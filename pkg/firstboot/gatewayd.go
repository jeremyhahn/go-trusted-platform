// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package firstboot

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// gatewaydOpenRCScript is the OpenRC init script for gatewayd on Alpine
// Linux. It is the script the fleet's gateway node already runs
// (hand-installed before #66), reproduced by the repo: gatewayd starts
// after platformd, which brings up the OVS bridge the datapath services
// program, and logs beside it. The constant stops inside start_pre;
// renderGatewaydInitScript closes it.
const gatewaydOpenRCScript = `#!/sbin/openrc-run
# OpenRC init script for the Trusted Platform gateway daemon (gatewayd).
# Written by platformd firstboot for gateway-role nodes (#66).

name="gatewayd"
description="Trusted Platform gateway daemon"

command="/usr/sbin/gatewayd"
command_args="serve --config /etc/gatewayd/config.yaml"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/trusted-platform/gatewayd.log"
error_log="/var/log/trusted-platform/gatewayd.log"

depend() {
    need localmount networking
    after platformd
    keyword -shutdown
}

start_pre() {
    checkpath --directory --owner root:root --mode 0755 /var/log/trusted-platform
    checkpath --directory --owner root:root --mode 0700 /etc/gatewayd
`

// gatewaydJoolModprobe loads the Jool NAT64 kernel module ahead of a gateway
// whose nat64: section is enabled (#603). The module comes from Alpine's
// jool-modules-lts and is built for one linux-lts version; a kernel upgrade
// that outruns the package leaves it unloadable. The failure is a warning, not
// a failed start: gatewayd still runs its other services and refuses the
// section with ErrNAT64ModuleUnavailable, so no traffic passes untranslated.
const gatewaydJoolModprobe = `    # nat64: is enabled. The module follows linux-lts (jool-modules-lts); if it
    # does not load, gatewayd refuses the section (ErrNAT64ModuleUnavailable).
    if ! modprobe jool; then
        ewarn "jool kernel module did not load; gatewayd will refuse the nat64 section"
    fi
`

// renderGatewaydInitScript returns the gatewayd OpenRC script, with the Jool
// module load in start_pre when loadJool is set.
func renderGatewaydInitScript(loadJool bool) string {
	script := gatewaydOpenRCScript
	if loadJool {
		script += gatewaydJoolModprobe
	}
	return script + "}\n"
}

// gatewaydNAT64Probe is the minimal shape of the gateway's nat64: section the
// init script decision needs. The rest belongs to gatewayd.
type gatewaydNAT64Probe struct {
	Gateway *struct {
		NAT64 *struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"nat64"`
	} `yaml:"gateway"`
}

// gatewaydNAT64Enabled reports whether a platform configuration enables the
// gateway's nat64: section — the one case gatewayd runs the Jool translator.
func gatewaydNAT64Enabled(platformConfig []byte) (bool, error) {
	var probe gatewaydNAT64Probe
	if err := yaml.Unmarshal(platformConfig, &probe); err != nil {
		return false, &tpconfig.ErrPlatformConfigUnreadable{Cause: err}
	}
	return probe.Gateway != nil && probe.Gateway.NAT64 != nil && probe.Gateway.NAT64.Enabled, nil
}

// Paths gatewayd is packaged at. They are variables so tests can point
// the install at a temporary root; production never changes them.
var (
	gatewaydConfigDir  = "/etc/gatewayd"
	gatewaydConfigFile = "config.yaml"
	gatewaydInitScript = "/etc/init.d/gatewayd"
)

// ErrGatewaydIdentityMissing reports that the control-plane reporter's
// mTLS client identity is not on disk. The repo cannot issue it yet: a
// gateway's client certificate is signed by the control plane's CA for the
// gateway id (CN), and neither the ACME enroll-01 IDevID (restricted key,
// no TLS client auth — #149) nor the control plane's ACME server (#431) can
// produce a client certificate for a node today. The service is still
// installed and enabled so the datapath runs; the reporter is rendered
// disabled until the operator delivers the identity and re-enables it.
type ErrGatewaydIdentityMissing struct {
	Missing []string
}

// Error implements the error interface.
func (e *ErrGatewaydIdentityMissing) Error() string {
	return fmt.Sprintf("gatewayd control-plane identity missing: %s — the control-plane reporter is rendered disabled; "+
		"deliver the client certificate (CN = gateway id, issued by the control plane's CA), key and CA bundle, "+
		"set control-plane.enabled: true in %s and restart gatewayd",
		strings.Join(e.Missing, ", "), filepath.Join(gatewaydConfigDir, gatewaydConfigFile))
}

// renderGatewaydConfig projects the gatewayd sections out of the platform
// configuration (tpconfig.GatewaydConfigSections). The gateway node keeps
// one source of truth — its platform config, which the seeder renders from
// the device template and overrides — and gatewayd reads exactly the
// sections it decodes. When the control-plane section is present but its
// identity files are absent, the section is rendered with enabled: false
// and ErrGatewaydIdentityMissing is returned alongside the config, so the
// caller can install the service and still surface the gap.
func renderGatewaydConfig(platformConfig []byte, identityPresent func(path string) bool) ([]byte, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(platformConfig, &doc); err != nil {
		return nil, &tpconfig.ErrPlatformConfigUnreadable{Cause: err}
	}
	out := map[string]any{}
	for _, section := range tpconfig.GatewaydConfigSections {
		if v, ok := doc[section]; ok && v != nil {
			out[section] = v
		}
	}

	var identityErr error
	if cp, ok := out["control-plane"].(map[string]any); ok {
		if missing := missingIdentity(cp, identityPresent); len(missing) > 0 {
			cp["enabled"] = false
			identityErr = &ErrGatewaydIdentityMissing{Missing: missing}
		}
	}

	var buf bytes.Buffer
	buf.WriteString("# gatewayd configuration rendered by platformd firstboot from the node's\n")
	buf.WriteString("# platform config (/etc/trusted-platform/config.yaml). Edit the platform\n")
	buf.WriteString("# config and re-render rather than this file; the sections below are the\n")
	buf.WriteString("# ones gatewayd decodes (#66).\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(out); err != nil {
		return nil, &WrappedError{Msg: "failed to render gatewayd config", Err: err}
	}
	if err := enc.Close(); err != nil {
		return nil, &WrappedError{Msg: "failed to render gatewayd config", Err: err}
	}
	return buf.Bytes(), identityErr
}

// missingIdentity lists the control-plane identity files the section names
// that are not present. A section with enabled: false is not checked — the
// operator has already said the reporter is off.
func missingIdentity(cp map[string]any, present func(string) bool) []string {
	if enabled, ok := cp["enabled"].(bool); ok && !enabled {
		return nil
	}
	var missing []string
	for _, key := range []string{"cert-file", "key-file", "ca-file"} {
		path, ok := cp[key].(string)
		if !ok || path == "" {
			missing = append(missing, key+" (not configured)")
			continue
		}
		if !present(path) {
			missing = append(missing, path)
		}
	}
	return missing
}

// commandRunner runs an OpenRC command and returns its combined output.
type commandRunner func(name string, args ...string) ([]byte, error)

func execRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// installGatewaydService packages gatewayd on a gateway-role node: the
// rendered config, the OpenRC script, enablement in the default runlevel,
// and a start. Nodes whose configuration does not enable the gateway role
// get nothing. A missing reporter identity is reported after the service
// is installed, never before — the datapath must not wait on paperwork.
func (e *Executor) installGatewaydService(platformConfig []byte) error {
	return installGatewaydServiceAt(platformConfig, gatewaydInstallPaths{
		configDir:  gatewaydConfigDir,
		initScript: gatewaydInitScript,
	}, fileExists, execRunner, e.logInfo, e.logWarn)
}

// gatewaydInstallPaths are the two locations the install writes.
type gatewaydInstallPaths struct {
	configDir  string
	initScript string
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// installGatewaydServiceAt is installGatewaydService with every host
// touchpoint injected, so the role gate, the rendering, the script and the
// OpenRC calls are testable against a temporary tree.
func installGatewaydServiceAt(platformConfig []byte, paths gatewaydInstallPaths, present func(string) bool,
	run commandRunner, info, warn func(msg string, kv ...any)) error {

	enabled, err := tpconfig.GatewayRoleEnabled(platformConfig)
	if err != nil {
		return err
	}
	if !enabled {
		info("Node is not a gateway; gatewayd not installed")
		return nil
	}
	if !present("/usr/sbin/gatewayd") && !present("/usr/bin/gatewayd") {
		return &ErrGatewaydBinaryAbsent{}
	}

	rendered, identityErr := renderGatewaydConfig(platformConfig, present)
	if identityErr != nil {
		var missing *ErrGatewaydIdentityMissing
		if !errors.As(identityErr, &missing) {
			return identityErr
		}
	}

	if err := os.MkdirAll(paths.configDir, 0700); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to create %s", paths.configDir), Err: err}
	}
	configPath := filepath.Join(paths.configDir, gatewaydConfigFile)
	if err := os.WriteFile(configPath, rendered, 0600); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to write %s", configPath), Err: err}
	}
	info("Rendered gatewayd config", "path", configPath)

	loadJool, err := gatewaydNAT64Enabled(platformConfig)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(paths.initScript), 0755); err != nil {
		return &WrappedError{Msg: "failed to create the init.d directory", Err: err}
	}
	if err := os.WriteFile(paths.initScript, []byte(renderGatewaydInitScript(loadJool)), 0755); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to write init script %s", paths.initScript), Err: err}
	}
	info("Created gatewayd OpenRC init script", "path", paths.initScript, "loads_jool", loadJool)

	if output, err := run("rc-update", "add", "gatewayd", "default"); err != nil {
		return &CommandOutputError{Msg: "failed to enable gatewayd service", Err: err, Detail: fmt.Sprintf(" (output: %s)", string(output))}
	}
	info("Enabled gatewayd service at default runlevel")

	if output, err := run("rc-service", "gatewayd", "start"); err != nil {
		warn("Failed to start gatewayd service", "error", err, "output", string(output))
	} else {
		info("Started gatewayd service")
	}

	if identityErr != nil {
		warn(identityErr.Error())
	}
	return identityErr
}

// ErrGatewaydBinaryAbsent reports a gateway-role node whose installer did
// not place gatewayd. The installer fails closed on that (#66), so reaching
// this at firstboot means the disk was not produced by the installer.
type ErrGatewaydBinaryAbsent struct{}

// Error implements the error interface.
func (e *ErrGatewaydBinaryAbsent) Error() string {
	return "gatewayd binary is absent from /usr/sbin and /usr/bin on a gateway-role node; the installer places it for the gateway role"
}

func (e *Executor) logInfo(msg string, kv ...any) { e.logger.Info(msg, kv...) }
func (e *Executor) logWarn(msg string, kv ...any) { e.logger.Warn(msg, kv...) }
