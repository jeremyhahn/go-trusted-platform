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

// Package zone — architecture guard tests.
//
// These tests walk the source tree and assert structural invariants that
// cannot be expressed in the type system:
//
//   - No forbidden OID arc (1.3.6.1.4.1.99999) appears in production pkg/ code.
//   - The stale identifiers VLANFlowManager, FirewallZone, and
//     NetworkPhaseProduction do not appear in production (non-test) pkg/ code.
//   - Shipped template YAML files in configs/platform/templates/**/*.yaml
//     contain no network/pool entry named "production".
//
// All checks use filepath.WalkDir for speed; no shell-outs.
package zone_test

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repoRoot resolves the repository root by walking up from this file's
// location until a go.mod is found.
func repoRoot(t *testing.T) string {
	t.Helper()
	// This file lives at pkg/sdn/zone/guards_test.go; the root is three
	// directories up.
	dir, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("cannot resolve repo root: %v", err)
	}
	// Sanity check: go.mod must exist there.
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatalf("repo root %s has no go.mod: %v", dir, err)
	}
	return dir
}

// isPkgTestFile reports whether the file path refers to a test file inside
// pkg/ (_test.go suffix or .disabled suffix used for disabled tests).
func isPkgTestFile(path string) bool {
	return strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".disabled")
}

// TestGuard_NoForbiddenOIDArcs asserts that the bare forbidden OID arc string
// "1.3.6.1.4.1.99999" does not appear anywhere in non-test Go source files
// under pkg/. Bare numeric literals like 99999 are permitted (test fixtures).
func TestGuard_NoForbiddenOIDArcs(t *testing.T) {
	root := repoRoot(t)
	pkgDir := filepath.Join(root, "pkg")

	const forbidden = "1.3.6.1.4.1.99999"

	var violations []string

	err := filepath.WalkDir(pkgDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if isPkgTestFile(path) {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if bytes.Contains(data, []byte(forbidden)) {
			rel, _ := filepath.Rel(root, path)
			violations = append(violations, rel)
		}
		return nil
	})

	assert.NoError(t, err)
	assert.Empty(t, violations,
		"forbidden OID arc %q found in production pkg/ files: %v", forbidden, violations)
}

// TestGuard_NoStaleNetworkIdentifiers asserts that the renamed/removed
// identifiers VLANFlowManager, FirewallZone, and NetworkPhaseProduction do not
// appear in production (non-test) Go source files under pkg/.
//
// VLANFlowManager was replaced by ZoneFlowManager in the Z3-Z9 refactor.
// FirewallZone and NetworkPhaseProduction never shipped but are forbidden to
// prevent accidental re-introduction.
func TestGuard_NoStaleNetworkIdentifiers(t *testing.T) {
	root := repoRoot(t)
	pkgDir := filepath.Join(root, "pkg")

	forbidden := []string{
		"VLANFlowManager",
		"FirewallZone",
		"NetworkPhaseProduction",
		// The trusted zone and the fixed VLAN/VNI constants were retired
		// by the reference network (#708); numbering comes from netplan.
		"ZoneTrusted",
		"ZoneTenant",
		"ZonePublic",
		"DefaultTrustedVLAN",
		"TenantBase",
		"VNIBase",
	}

	violations := make(map[string][]string) // identifier → []file paths

	err := filepath.WalkDir(pkgDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if isPkgTestFile(path) {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, id := range forbidden {
			if regexp.MustCompile(`\b` + id + `\b`).Match(data) {
				rel, _ := filepath.Rel(root, path)
				violations[id] = append(violations[id], rel)
			}
		}
		return nil
	})

	assert.NoError(t, err)
	for _, id := range forbidden {
		assert.Empty(t, violations[id],
			"stale identifier %q found in production pkg/ files: %v", id, violations[id])
	}
}

// TestGuard_NoProductionNetworkNameInTemplates asserts that deployed template
// YAML files under configs/platform/templates/**/*.yaml contain no network or
// pool entry with name: production. The zone model uses descriptive zone names
// (trusted, provisioning, etc.); "production" is a pre-zone legacy identifier.
func TestGuard_NoProductionNetworkNameInTemplates(t *testing.T) {
	root := repoRoot(t)
	templatesDir := filepath.Join(root, "configs", "platform", "templates")

	_, statErr := os.Stat(templatesDir)
	require.NoError(t, statErr, "the shipped templates must be present")

	var violations []string

	err := filepath.WalkDir(templatesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		f, openErr := os.Open(path)
		if openErr != nil {
			return openErr
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			// Match YAML entries: "name: production" (with optional
			// surrounding whitespace). Must be an exact name value, not a
			// substring inside a longer name like "production-db".
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "name:") {
				value := strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
				// Strip optional YAML quotes.
				value = strings.Trim(value, `"'`)
				if value == "production" {
					rel, _ := filepath.Rel(root, path)
					violations = append(violations, rel+":"+strconv.Itoa(lineNum))
				}
			}
		}
		return scanner.Err()
	})

	assert.NoError(t, err)
	assert.Empty(t, violations,
		"template YAML files must not use 'name: production' for networks/pools "+
			"(use zone-named segments instead): %v", violations)
}
