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

// templatePaths returns every shipped device template.
func templatePaths(t *testing.T) []string {
	t.Helper()

	var paths []string
	walkErr := filepath.WalkDir(templateDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", templateDir, walkErr)
	}
	if len(paths) == 0 {
		t.Fatalf("no templates found under %s", templateDir)
	}
	return paths
}

// TestShippedTemplatesCarryAValidNTPSection is a regression guard against the
// lab-node-2 incident: a node that ships without time synchronization boots on
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
