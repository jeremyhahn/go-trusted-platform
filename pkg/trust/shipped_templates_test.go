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

package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestShippedTemplatesUseAllowedStrategies validates the `trust:` block of
// every shipped platform template against the class allowlist.
//
// This exists because #83 narrowed the bmc class and the templates were not
// caught by any test: every shipped template still carried
// `strategies: [dane, spki, ca-file, tofu]`, so a deployment rendered from a
// supported template would have failed trust-resolver construction at
// startup. A strategy allowlist and a set of shipped configurations that use
// it must be checked against each other, or they drift silently and the
// drift is only discovered on real hardware.
func TestShippedTemplatesUseAllowedStrategies(t *testing.T) {
	root := filepath.Join("..", "..", "configs", "platform", "templates")

	// The subset of the platform config this test cares about.
	type templateConfig struct {
		Trust struct {
			Default  *ScopeConfig `yaml:"default"`
			BMC      *ScopeConfig `yaml:"bmc"`
			Internal *ScopeConfig `yaml:"internal"`
		} `yaml:"trust"`
	}

	var templates []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			templates = append(templates, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if len(templates) == 0 {
		t.Fatalf("no templates found under %s — the test would pass vacuously", root)
	}

	checked := 0
	for _, path := range templates {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}

		var cfg templateConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			// Templates carry sections this struct does not model; only a
			// malformed trust block should ever fail here.
			t.Fatalf("parsing %s: %v", path, err)
		}

		for _, scope := range []struct {
			class Class
			cfg   *ScopeConfig
		}{
			{ClassDefault, cfg.Trust.Default},
			{ClassBMC, cfg.Trust.BMC},
			{ClassInternal, cfg.Trust.Internal},
		} {
			if scope.cfg == nil {
				continue
			}
			checked++
			for _, strategy := range scope.cfg.Strategies {
				if !StrategyAllowedForClass(scope.class, strategy) {
					t.Errorf("%s: class %q lists strategy %q, which the allowlist does not permit",
						path, scope.class, strategy)
				}
			}
		}
	}

	if checked == 0 {
		t.Fatal("no trust scopes found in any shipped template — the test would pass vacuously")
	}
	t.Logf("validated %d trust scopes across %d templates", checked, len(templates))
}
