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
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"gopkg.in/yaml.v3"
)

// templateDir is the shipped device-template tree, relative to this package.
const templateDir = "../../configs/platform/templates"

// decodeTemplateNTP extracts and decodes the `ntp:` section of a device
// template exactly the way platformd does at runtime: YAML into a generic
// map, then mapstructure with the duration hook viper installs. Decoding it
// any other way would let a template that platformd rejects pass the test.
func decodeTemplateNTP(t *testing.T, path string) (*Config, bool) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	section, ok := document["ntp"]
	if !ok {
		return nil, false
	}

	var config Config
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
		Result:     &config,
	})
	if err != nil {
		t.Fatalf("build decoder: %v", err)
	}
	if err := decoder.Decode(section); err != nil {
		t.Fatalf("decode ntp section of %s: %v", path, err)
	}
	return &config, true
}

// gatewaydTemplates are configurations for the EDGE daemon rather than device
// templates for platformd. gatewayd reads only `gateway:`, `sdn:`,
// `control-plane:`, `proxy:` and `trust:`
// (pkg/sdn/gateway/commands.LoadServeConfig) and starts no time daemon, so an
// `ntp:` section here would be configuration the daemon accepts and silently
// drops rather than time synchronization anyone gets.
//
// The node itself is still covered: a gateway-role node runs platformd for its
// worker duties from the device template beside this file, and that template is
// checked like every other. This exemption removes a file, not a machine.
//
// Named explicitly, and confirmed by isGatewaydTemplate below, so a file
// exempting itself from these guards has to be added here deliberately.
var gatewaydTemplates = map[string]bool{
	"gatewayd.yaml": true,
}

// isGatewaydTemplate confirms the file at path really is an edge-daemon
// configuration: it carries gatewayd's own root section and none of the
// platformd keys the device templates are built around. A file that stops
// matching has become a device template that would otherwise skip the checks
// these tests exist to enforce.
func isGatewaydTemplate(t *testing.T, path string) bool {
	t.Helper()
	if !gatewaydTemplates[filepath.Base(path)] {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if _, ok := doc["gateway"]; !ok {
		t.Fatalf("%s is exempted as a gatewayd configuration but has no top-level `gateway:` key; "+
			"if it is now a device template, remove it from gatewaydTemplates so it is checked", path)
	}
	if _, ok := doc["platform"]; ok {
		t.Fatalf("%s is exempted as a gatewayd configuration but declares platformd's `platform:` section; "+
			"remove it from gatewaydTemplates", path)
	}
	return true
}

// overrideExamples are the --overrides files shipped beside the templates,
// relative to templateDir. An override is merged onto its template, not
// loaded on its own, so it carries no `ntp:` section and no package list of
// its own: the template's are the node's. Named explicitly, and confirmed by
// isOverrideExample below.
var overrideExamples = map[string]bool{
	"dedicated/raspberrypi/cm4/desk-overrides.yaml": true,
}

// isOverrideExample confirms the file at path is an override example that
// leaves the template's time synchronization alone: an override that set
// `ntp:` or `os:` would change what these tests check on the template, so it
// must not skip them.
func isOverrideExample(t *testing.T, path string) bool {
	t.Helper()
	rel, err := filepath.Rel(templateDir, path)
	if err != nil {
		t.Fatalf("%s is outside %s: %v", path, templateDir, err)
	}
	if !overrideExamples[filepath.ToSlash(rel)] {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, key := range []string{"ntp", "os"} {
		if _, ok := doc[key]; ok {
			t.Fatalf("%s is exempted as an override example but sets `%s:`; "+
				"remove it from overrideExamples so it is checked", path, key)
		}
	}
	return true
}

// templatePaths returns every shipped platformd device template, excluding the
// edge-daemon configurations and the override examples that live alongside
// them.
func templatePaths(t *testing.T) []string {
	t.Helper()

	var paths []string
	seenGatewayd, seenOverrides := 0, 0
	walkErr := filepath.WalkDir(templateDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		if isGatewaydTemplate(t, path) {
			seenGatewayd++
			return nil
		}
		if isOverrideExample(t, path) {
			seenOverrides++
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if seenGatewayd != len(gatewaydTemplates) {
		t.Errorf("expected to see %d exempted gatewayd configurations, saw %d — the exempt list names a file that no longer exists",
			len(gatewaydTemplates), seenGatewayd)
	}
	if seenOverrides != len(overrideExamples) {
		t.Errorf("expected to see %d exempted override examples, saw %d — the exempt list names a file that no longer exists",
			len(overrideExamples), seenOverrides)
	}
	if walkErr != nil {
		t.Fatalf("walk %s: %v", templateDir, walkErr)
	}
	if len(paths) == 0 {
		t.Fatalf("no templates found under %s", templateDir)
	}
	return paths
}

// TestShippedTemplatesCarryAValidNTPSection is a regression guard against the
// node-02 incident: a node that ships without time synchronization boots on
// whatever its RTC says. Every shipped template must configure `ntp:`, and
// that section must satisfy the same validation platformd applies at startup.
func TestShippedTemplatesCarryAValidNTPSection(t *testing.T) {
	for _, path := range templatePaths(t) {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			config, present := decodeTemplateNTP(t, path)
			if !present {
				t.Fatalf("%s has no ntp: section; the node would boot with no time daemon", path)
			}
			if !config.Enabled {
				t.Fatalf("%s disables time synchronization", path)
			}
			if err := config.Validate(); err != nil {
				t.Fatalf("%s ntp section is invalid: %v", path, err)
			}
			if !config.GateEnabled() {
				t.Fatalf("%s does not block startup until the clock is trustworthy", path)
			}
			if !config.RTCWriteBack() {
				t.Fatalf("%s does not write the corrected time back to the RTC", path)
			}
			// The rendered chrony.conf must be producible from the
			// shipped section, otherwise the node fails at bring-up.
			if _, err := Render(config, DefaultPaths()); err != nil {
				t.Fatalf("%s ntp section does not render: %v", path, err)
			}
		})
	}
}

// TestShippedTemplatesNeverServeTimeToTheInternet guards the security
// invariant that an NTP server is only ever exposed to an explicit CIDR
// allow-list. An open server is a reflection-amplification source.
func TestShippedTemplatesNeverServeTimeToTheInternet(t *testing.T) {
	for _, path := range templatePaths(t) {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			config, present := decodeTemplateNTP(t, path)
			if !present || !config.Mode.Serves() {
				return
			}
			if config.Serve == nil || len(config.Serve.ListenNetworks) == 0 {
				t.Fatalf("%s serves time with no allow-list", path)
			}
			for _, network := range config.Serve.ListenNetworks {
				trimmed := strings.TrimSpace(network)
				if _, unrestricted := unrestrictedNetworks[trimmed]; unrestricted {
					t.Fatalf("%s serves time to %s", path, network)
				}
			}
		})
	}
}

// TestShippedTemplatesInstallChrony guards the install path: platformd
// configures chrony but does not install it, so the package must be in every
// template's os.packages alongside its OpenRC init script.
func TestShippedTemplatesInstallChrony(t *testing.T) {
	for _, path := range templatePaths(t) {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			var document struct {
				OS struct {
					Packages []string `yaml:"packages"`
				} `yaml:"os"`
			}
			if err := yaml.Unmarshal(data, &document); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}

			present := make(map[string]struct{}, len(document.OS.Packages))
			for _, pkg := range document.OS.Packages {
				present[pkg] = struct{}{}
			}
			for _, required := range []string{"chrony", "chrony-openrc"} {
				if _, ok := present[required]; !ok {
					t.Fatalf("%s os.packages is missing %q", path, required)
				}
			}
		})
	}
}

// TestShippedTemplatesNameTheirNTSUpstream is the #509 regression guard.
//
// RFC 8915 key establishment is a TLS handshake and chronyd verifies the
// NTS-KE certificate against the string in its own `server` directive.
// Platform certificates carry DNS SANs only, so an IP address with
// `nts: true` can never validate: the node never synchronises and burns the
// whole startup gate at every boot, while the template reads as if
// authenticated time were in force. Both node templates shipped exactly that
// for months.
func TestShippedTemplatesNameTheirNTSUpstream(t *testing.T) {
	for _, path := range templatePaths(t) {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			config, present := decodeTemplateNTP(t, path)
			if !present || config.Consume == nil {
				return
			}
			for _, source := range config.Consume.Upstream {
				if !source.NTS {
					continue
				}
				address := strings.TrimSpace(source.Address)
				if _, err := netip.ParseAddr(address); err == nil {
					t.Fatalf("%s consumes NTS from the address %s; the NTS-KE handshake "+
						"validates the served certificate against this string and platform "+
						"certificates are DNS-only, so it can never succeed. Use the name "+
						"that resolves to it (#509)", path, address)
				}
			}
		})
	}
}

// TestShippedControlPlanesServeEveryNTSNameTheirNodesDial closes the loop
// across files: a node template that dials the control plane over NTS is
// only usable if the control-plane template in the same profile is issued a
// certificate carrying that exact name. Getting one half right and the other
// wrong produces a fleet that never synchronises, which is the state #509
// measured.
func TestShippedControlPlanesServeEveryNTSNameTheirNodesDial(t *testing.T) {
	// Group the templates by board directory: a board's node templates are
	// served by that board's control-plane template. A board directory with
	// no time server of its own (none ships one now: rpi5 gained its own
	// control-plane template in #1701) is served by any control plane of its
	// profile, so every one of them must list the names its nodes dial.
	hasServer := map[string]bool{}
	served := map[string]map[string]struct{}{}
	dialed := map[string][]struct{ path, name string }{}
	for _, path := range templatePaths(t) {
		dir := filepath.Dir(path)
		config, present := decodeTemplateNTP(t, path)
		if !present {
			continue
		}
		if config.Serve != nil {
			hasServer[dir] = true
		}
		for _, name := range config.NTSServerNames() {
			if served[dir] == nil {
				served[dir] = map[string]struct{}{}
			}
			served[dir][name] = struct{}{}
		}
		if config.Consume == nil {
			continue
		}
		for _, source := range config.Consume.Upstream {
			if source.NTS {
				dialed[dir] = append(dialed[dir], struct{ path, name string }{path, strings.TrimSpace(source.Address)})
			}
		}
	}

	for dir, nodes := range dialed {
		t.Run(filepath.Base(filepath.Dir(dir))+"/"+filepath.Base(dir), func(t *testing.T) {
			servers := []string{dir}
			if !hasServer[dir] {
				servers = profileServers(t, dir, hasServer)
			}
			for _, d := range nodes {
				for _, server := range servers {
					if _, ok := served[server][d.name]; !ok {
						t.Fatalf("%s dials %s over NTS, but no template in %s lists that name in "+
							"ntp.serve.nts.server-names; the certificate the control plane serves "+
							"would not carry it and every handshake would fail (#509)",
							d.path, d.name, server)
					}
				}
			}
		})
	}
}

// profileServers returns the board directories of dir's deployment profile
// (dedicated/, single-node/, ...) that carry a time server.
func profileServers(t *testing.T, dir string, hasServer map[string]bool) []string {
	t.Helper()
	profile := func(d string) string {
		rel, err := filepath.Rel(templateDir, d)
		if err != nil {
			t.Fatalf("%s is outside %s: %v", d, templateDir, err)
		}
		return strings.Split(filepath.ToSlash(rel), "/")[0]
	}
	var servers []string
	for server := range hasServer {
		if profile(server) == profile(dir) {
			servers = append(servers, server)
		}
	}
	if len(servers) == 0 {
		t.Fatalf("%s: its nodes dial NTS, but no template in its profile serves time", dir)
	}
	return servers
}
