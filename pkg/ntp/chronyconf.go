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

package ntp

import (
	"strconv"
	"strings"
)

// ManagedHeader marks a chrony.conf as platform-owned. Operators editing the
// file by hand will have their changes overwritten on the next boot.
const ManagedHeader = "# Managed by go-trusted-platform (pkg/ntp). Do not edit by hand."

// firstBootStepUpdates is the number of initial updates during which chronyd
// may STEP the clock instead of slewing it. A node whose RTC is years wrong
// cannot be slewed back in any useful time, so the first corrections must be
// steps; afterwards a large jump is an anomaly, not a correction.
const firstBootStepUpdates = 3

// firstBootStepThresholdSeconds is the offset above which those initial
// updates step rather than slew.
const firstBootStepThresholdSeconds = "1.0"

// Paths are the filesystem locations chronyd is pointed at. They are not part
// of the YAML schema: they are platform layout constants, overridable only in
// tests via Service options.
type Paths struct {
	// ConfigFile is the rendered chrony.conf destination.
	ConfigFile string

	// DriftFile persists the measured oscillator drift across reboots.
	DriftFile string

	// NTSCertFile is where the resolved NTS server certificate is written.
	NTSCertFile string

	// NTSKeyFile is where the resolved NTS server private key is written.
	NTSKeyFile string

	// NTSDumpDir holds chronyd's NTS-KE server key cache.
	NTSDumpDir string

	// CommandSocket is chronyd's Unix control socket, which is how the
	// platform reads sync state.
	CommandSocket string
}

// DefaultPaths returns the Alpine/OpenRC filesystem layout chrony ships with.
func DefaultPaths() Paths {
	return Paths{
		ConfigFile:    "/etc/chrony/chrony.conf",
		DriftFile:     "/var/lib/chrony/chrony.drift",
		NTSCertFile:   "/etc/chrony/nts-server.crt",
		NTSKeyFile:    "/etc/chrony/nts-server.key",
		NTSDumpDir:    "/var/lib/chrony",
		CommandSocket: "/run/chrony/chronyd.sock",
	}
}

// Render produces the chrony.conf body for cfg. It never emits an
// unrestricted `allow` directive: the allow-list comes straight from the
// validated serve.listen-networks entries.
func Render(cfg *Config, paths Paths) (string, error) {
	if cfg == nil {
		return "", ErrRenderFailed{Cause: ErrNilConfig{}}
	}
	if err := cfg.Validate(); err != nil {
		return "", ErrRenderFailed{Cause: err}
	}
	if !cfg.Enabled {
		return "", ErrRenderFailed{Cause: ErrDisabled{}}
	}

	var b strings.Builder
	b.WriteString(ManagedHeader)
	b.WriteString("\n# mode: ")
	b.WriteString(string(cfg.Mode))
	b.WriteString("\n\n")

	renderUpstream(&b, cfg)
	renderDiscipline(&b, cfg, paths)
	renderServer(&b, cfg, paths)
	renderControl(&b, paths)

	return b.String(), nil
}

// renderUpstream writes the server/pool directives.
func renderUpstream(b *strings.Builder, cfg *Config) {
	if !cfg.Mode.Consumes() || cfg.Consume == nil || len(cfg.Consume.Upstream) == 0 {
		return
	}

	b.WriteString("# Upstream time sources, in configuration order.\n")
	for _, src := range cfg.Consume.Upstream {
		directive := "server"
		if src.Pool {
			directive = "pool"
		}
		b.WriteString(directive)
		b.WriteByte(' ')
		b.WriteString(strings.TrimSpace(src.Address))
		if src.IBurst {
			b.WriteString(" iburst")
		}
		if src.Prefer {
			b.WriteString(" prefer")
		}
		if src.NTS {
			b.WriteString(" nts")
		}
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
}

// renderDiscipline writes the clock-discipline directives shared by every
// role.
func renderDiscipline(b *strings.Builder, cfg *Config, paths Paths) {
	b.WriteString("# Clock discipline. The first ")
	b.WriteString(strconv.Itoa(firstBootStepUpdates))
	b.WriteString(" updates may STEP the clock so a node whose RTC is years\n")
	b.WriteString("# wrong converges immediately; later corrections slew and a large one is an anomaly.\n")
	b.WriteString("driftfile ")
	b.WriteString(paths.DriftFile)
	b.WriteString("\nmakestep ")
	b.WriteString(firstBootStepThresholdSeconds)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(firstBootStepUpdates))
	b.WriteByte('\n')

	if cfg.RTCWriteBack() {
		b.WriteString("rtcsync\n")
	}
	b.WriteByte('\n')
}

// renderServer writes the server-side directives: the explicit allow-list,
// orphan-mode stratum, and NTS-KE material. Consume-only nodes get `port 0`
// so they never listen on 123 at all.
func renderServer(b *strings.Builder, cfg *Config, paths Paths) {
	if !cfg.Mode.Serves() {
		b.WriteString("# Consume-only node: do not listen on the NTP port.\nport 0\n\n")
		return
	}

	b.WriteString("# Explicit CIDR allow-list. Never 0.0.0.0/0 — an open NTP server is a\n")
	b.WriteString("# reflection-amplification source.\n")
	for _, network := range cfg.Serve.ListenNetworks {
		b.WriteString("allow ")
		b.WriteString(strings.TrimSpace(network))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')

	if cfg.Consume != nil && cfg.Consume.OrphanFallback {
		b.WriteString("# Orphan fallback: keep serving from the local clock when no upstream is\n")
		b.WriteString("# reachable, at a stratum low enough that any real chain wins.\n")
		b.WriteString("local stratum ")
		b.WriteString(strconv.Itoa(cfg.LocalStratum()))
		b.WriteString("\n\n")
	}

	if cfg.NTSServing() {
		b.WriteString("# RFC 8915 Network Time Security, keyed by the platform CA.\n")
		b.WriteString("ntsservercert ")
		b.WriteString(paths.NTSCertFile)
		b.WriteString("\nntsserverkey ")
		b.WriteString(paths.NTSKeyFile)
		b.WriteString("\nntsdumpdir ")
		b.WriteString(paths.NTSDumpDir)
		b.WriteString("\n\n")
	}
}

// renderControl writes the control-socket directives. The UDP command port is
// disabled outright: the platform reads state over the local Unix socket.
func renderControl(b *strings.Builder, paths Paths) {
	b.WriteString("# Control surface: local Unix socket only, no UDP command port.\n")
	b.WriteString("bindcmdaddress ")
	b.WriteString(paths.CommandSocket)
	b.WriteString("\ncmdport 0\n")
}
