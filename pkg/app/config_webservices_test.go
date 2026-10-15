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

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// configRoot is the tree of shipped platform configurations, relative to this
// package.
const configRoot = "../../configs"

// composeManifests are the YAML files under configs/ that are NOT platform
// configurations — Docker Compose manifests that happen to live alongside them.
// They are listed explicitly rather than pattern-matched so that a new file
// exempting itself from the check below has to be added here deliberately.
var composeManifests = map[string]bool{
	"platform/cluster/docker-compose.yaml":    true,
	"platform/standalone/docker-compose.yaml": true,
}

// gatewaydConfigs are configurations for the EDGE daemon, not for platformd.
// gatewayd reads only `gateway:`, `sdn:`, `control-plane:`, `proxy:` and
// `trust:` (pkg/sdn/gateway/commands.LoadServeConfig); it has no webservice of
// its own and never takes the runDaemonOnly path this test guards, so the key
// would be configuration the daemon accepts and silently drops — the defect
// class the gateway work has already had to fix four times.
//
// Listed explicitly, and confirmed below to still be a gatewayd config, for
// the same reason as the Compose manifests: a file that exempts itself from
// this check has to be added here deliberately.
var gatewaydConfigs = map[string]bool{
	"platform/templates/dedicated/supermicro/x10/gatewayd.yaml": true,
}

// bootstrapConfigs are the bootstrap orchestrator's files, not platformd
// configurations. A bootstrap config (top-level `nodes:`) is read only by
// `platformctl bootstrap`. A per-node overrides file is a fragment that a
// bootstrap config's nodes[].overrides_file merges over a role template; the
// template, checked here in its own right, carries the webservice key that
// platformd reads.
//
// Listed explicitly, and confirmed below to still be what they claim: a
// bootstrap config has `nodes:`, and every other entry is named by an
// exempted bootstrap config's overrides_file.
var bootstrapConfigs = map[string]bool{
	"bootstrap/tgw01-vlan405.example.yaml":      true,
	"bootstrap/tgw01-vlan405-pi.overrides.yaml": true,
}

// overrideExamples are the --overrides files shipped beside the templates,
// each mapped to the template it merges onto. An override is not a
// configuration on its own: the template walks skip it, and the webservice
// check below runs on the merged result, so an override cannot delete the
// key it guards. pkg/cli/commands/diskimage loads each merged result through
// the host-network check platformd runs.
var overrideExamples = map[string]string{
	"platform/templates/dedicated/raspberrypi/cm4/desk-overrides.yaml": "platform/templates/dedicated/raspberrypi/cm4/control-plane.yaml",
}

// TestEveryPlatformConfigDeclaresAWebServiceKey guards a security property that
// currently holds by accident.
//
// App.WebServices decides which of two mutually exclusive run paths platformd
// takes (pkg/daemon/commands/serve.go, dispatching on len(App.WebServices) > 0):
//
//	non-empty -> runWithWebservices, which hardcodes EnableREST = false
//	empty     -> runDaemonOnly,      which sets EnableREST from --enable-rest,
//	                                 a flag that defaults to TRUE
//
// The daemon REST server that second path starts applies CORS, compression,
// request logging and request IDs — and no authentication. It carries twenty
// BMC routes, including power control, virtual-media mounting, BMC user
// creation and BMC user password and privilege changes (#312).
//
// Nothing defaults the field. NewApp returns new(App), so App.WebServices starts
// empty and is populated ONLY by configuration: either the plural `webservices:`
// key directly, or the singular `webservice:` key promoted to it by initConfig
// (app.go:1447-1448). A platform configuration declaring neither key therefore
// selects the unauthenticated path, silently — InitWebServer logs "web services
// disabled" (app.go:3262), which describes the half of the consequence that
// sounds safer.
//
// Every shipped configuration declares one key or the other today, which is why
// the exposure is latent rather than live. That is a property of thirty files
// and nothing enforces it. This test does.
//
// It is deliberately a property of the CONFIGURATIONS rather than a test of
// initConfig: the promotion yields a non-empty App.WebServices exactly when at
// least one of the two keys is present, so checking the keys checks the outcome
// without re-implementing viper's loading — and it keeps working if the
// promotion is refactored.
func TestEveryPlatformConfigDeclaresAWebServiceKey(t *testing.T) {
	var checked, compose, gatewayd, overrides, bootstrap int
	// overridesNamed holds the overrides files exempted bootstrap configs
	// name; overridesFiles the exempted entries that are not bootstrap
	// configs, each of which must be among them.
	overridesNamed := map[string]bool{}
	var overridesFiles []string

	err := filepath.WalkDir(configRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}

		rel, relErr := filepath.Rel(configRoot, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("%s: cannot read: %v", rel, readErr)
			return nil
		}

		// An override example is checked as the configuration it produces:
		// merged onto its template, the way --overrides applies it.
		if template, isOverride := overrideExamples[rel]; isOverride {
			overrides++
			merged, mergeErr := config.DeepMergeYAMLFiles(filepath.Join(configRoot, filepath.FromSlash(template)), path)
			if mergeErr != nil {
				t.Errorf("%s: cannot merge onto %s: %v", rel, template, mergeErr)
				return nil
			}
			raw = merged
		}

		var doc map[string]any
		if unmarshalErr := yaml.Unmarshal(raw, &doc); unmarshalErr != nil {
			t.Errorf("%s: cannot parse as YAML: %v", rel, unmarshalErr)
			return nil
		}

		_, hasSingular := doc["webservice"]
		plural, hasPlural := doc["webservices"]

		// A Compose manifest is not a platform configuration and cannot declare
		// either key. Confirm it still looks like one: if a file on the exempt
		// list stops being a Compose manifest it has become a platform config
		// that silently skips the check, which is the failure this test exists
		// to prevent.
		if composeManifests[rel] {
			compose++
			if _, isCompose := doc["services"]; !isCompose {
				t.Errorf("%s is exempted as a Docker Compose manifest but has no top-level `services:` key; "+
					"if it is now a platform configuration, remove it from composeManifests so it is checked", rel)
			}
			if hasSingular || hasPlural {
				t.Errorf("%s is exempted as a Docker Compose manifest but declares a webservice key; "+
					"remove it from composeManifests", rel)
			}
			return nil
		}

		if gatewaydConfigs[rel] {
			gatewayd++
			// The same reasoning as the Compose exemption: confirm the file
			// is still what the exemption claims. A gatewayd config has the
			// edge daemon's own root section and none of platformd's.
			if _, isGateway := doc["gateway"]; !isGateway {
				t.Errorf("%s is exempted as a gatewayd configuration but has no top-level `gateway:` key; "+
					"if it is now a platform configuration, remove it from gatewaydConfigs so it is checked", rel)
			}
			if _, isPlatformd := doc["platform"]; isPlatformd {
				t.Errorf("%s is exempted as a gatewayd configuration but declares platformd's `platform:` section; "+
					"remove it from gatewaydConfigs", rel)
			}
			if hasSingular || hasPlural {
				t.Errorf("%s is exempted as a gatewayd configuration but declares a webservice key; "+
					"gatewayd does not read one — remove it from gatewaydConfigs or drop the key", rel)
			}
			return nil
		}

		if bootstrapConfigs[rel] {
			bootstrap++
			nodes, isBootstrap := doc["nodes"].([]any)
			if !isBootstrap {
				overridesFiles = append(overridesFiles, rel)
				return nil
			}
			for _, node := range nodes {
				entry, ok := node.(map[string]any)
				if !ok {
					continue
				}
				if file, ok := entry["overrides_file"].(string); ok {
					overridesNamed[filepath.ToSlash(filepath.Join(filepath.Dir(rel), file))] = true
				}
			}
			return nil
		}

		checked++

		// An empty `webservices: []` does not populate the field, and the
		// singular promotion only fires when the plural is empty AND the
		// singular is non-nil — so an empty list with no singular key selects
		// the unauthenticated path just as a missing key does.
		if hasPlural {
			if list, ok := plural.([]any); ok && len(list) == 0 {
				hasPlural = false
			}
		}

		if !hasSingular && !hasPlural {
			t.Errorf("%s declares neither `webservice:` nor `webservices:`.\n"+
				"  A platform config with neither leaves App.WebServices empty, which sends `platformd serve` down\n"+
				"  runDaemonOnly and starts the unauthenticated daemon REST server (--enable-rest defaults true),\n"+
				"  exposing twenty BMC routes including power control and BMC user management. See #312.", rel)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", configRoot, err)
	}

	// A rename or a moved directory that makes the walk find nothing must fail
	// loudly rather than pass as a vacuous success.
	if checked == 0 {
		t.Fatalf("no platform configurations found under %s — the check verified nothing", configRoot)
	}
	if compose != len(composeManifests) {
		t.Errorf("expected to see %d exempted Compose manifests, saw %d — the exempt list names a file that no longer exists",
			len(composeManifests), compose)
	}
	if gatewayd != len(gatewaydConfigs) {
		t.Errorf("expected to see %d exempted gatewayd configurations, saw %d — the exempt list names a file that no longer exists",
			len(gatewaydConfigs), gatewayd)
	}
	if overrides != len(overrideExamples) {
		t.Errorf("expected to merge %d override examples, merged %d — the list names a file that no longer exists",
			len(overrideExamples), overrides)
	}

	if bootstrap != len(bootstrapConfigs) {
		t.Errorf("expected to see %d exempted bootstrap files, saw %d — the exempt list names a file that no longer exists",
			len(bootstrapConfigs), bootstrap)
	}
	for _, rel := range overridesFiles {
		if !overridesNamed[rel] {
			t.Errorf("%s is exempted as a bootstrap file but has no `nodes:` and no exempted bootstrap config names it "+
				"as an overrides_file; if it is now a platform configuration, remove it from bootstrapConfigs", rel)
		}
	}

	t.Logf("checked %d platform configurations (%d of them override examples merged onto their templates), skipped %d Compose manifests, %d gatewayd configurations and %d bootstrap files",
		checked, overrides, compose, gatewayd, bootstrap)
}

// TestComposeExemptionsAreMinimal asserts the exempt list contains only files
// that exist. An entry for a deleted file is a hole waiting for a new file to
// be created at that path.
func TestComposeExemptionsAreMinimal(t *testing.T) {
	for rel := range composeManifests {
		path := filepath.Join(configRoot, filepath.FromSlash(rel))
		if _, err := os.Stat(path); err != nil {
			t.Errorf("composeManifests names %s, which does not exist: %v", rel, err)
		}
		if !strings.HasSuffix(rel, "docker-compose.yaml") && !strings.HasSuffix(rel, "docker-compose.yml") {
			t.Errorf("composeManifests names %s, which is not a docker-compose file; exemptions are for Compose manifests only", rel)
		}
	}
}

// TestGatewaydExemptionsAreMinimal is the counterpart for the edge-daemon
// exemptions: an entry for a deleted file is a hole waiting for a new file to
// be created at that path.
func TestGatewaydExemptionsAreMinimal(t *testing.T) {
	for rel := range gatewaydConfigs {
		path := filepath.Join(configRoot, filepath.FromSlash(rel))
		if _, err := os.Stat(path); err != nil {
			t.Errorf("gatewaydConfigs names %s, which does not exist: %v", rel, err)
		}
		if !strings.HasSuffix(rel, "gatewayd.yaml") {
			t.Errorf("gatewaydConfigs names %s, which is not a gatewayd.yaml; exemptions are for edge-daemon configurations only", rel)
		}
	}
}
