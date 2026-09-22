// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package arch — layer-boundary guard tests.
//
// go-trusted-platform is Layer 5 of the trusted-computing stack and is a
// pure consumer of the go-quicbaas SDK (Layer 4). Every crypto, key, auth,
// ceremony, and trust-bootstrap capability is reached through
// github.com/jeremyhahn/go-quicbaas/sdk/go/... — including the
// sdk/go/xkms/* type-alias re-exports of the go-xkms surface.
//
// The same rule governs protected memory: locked, zeroized regions are
// allocated by the stack through sdk/go/xkms/secure, so no file in this
// module imports awnumar/memguard directly — pkg/memguard.MemoryEnclave is
// the platform-side API and it holds an SDK secure.Buffer.
//
// The layer boundary cannot be expressed in the type system, so this guard
// walks every .go file in the module (production AND _test.go) and fails
// with a file:line listing when a forbidden upstream module is imported
// directly. Parsing is import-only, so the sweep costs milliseconds and
// never builds a package.
//
// When the SDK is missing a symbol, add the alias to the appropriate
// go-quicbaas/sdk/go/xkms package upstream — never bypass this guard.
package arch_test

import (
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ForbiddenImportError reports a single layer-boundary violation: a Go file
// in this module importing a module the platform is not allowed to reach
// directly.
type ForbiddenImportError struct {
	// File is the module-relative path of the offending file.
	File string

	// Line is the 1-based line of the import spec.
	Line int

	// Import is the offending import path.
	Import string

	// Rule is the name of the guard rule that matched.
	Rule string

	// Remedy states the sanctioned SDK path to use instead.
	Remedy string
}

// Error implements the error interface.
func (e ForbiddenImportError) Error() string {
	return e.File + ":" + strconv.Itoa(e.Line) + ": " + e.Rule +
		" imports " + strconv.Quote(e.Import) + "; use " + e.Remedy
}

// layerRule declares one forbidden module prefix and the SDK path that
// replaces it.
type layerRule struct {
	// name identifies the rule in failure output.
	name string

	// prefix is the module path prefix that may not be imported.
	prefix string

	// remedy is the sanctioned replacement, quoted in failure output.
	remedy string
}

// layerRules is the authoritative list of upstream modules the platform may
// not import directly. See CLAUDE.md §"SDK Consumption Invariant" and
// docs/02-dependency-graph.md in the architecture repo.
var layerRules = []layerRule{
	{
		name:   "go-xkms",
		prefix: "github.com/jeremyhahn/go-xkms",
		remedy: "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/...",
	},
	{
		name:   "go-qrdb",
		prefix: "github.com/jeremyhahn/go-qrdb",
		remedy: "github.com/jeremyhahn/go-quicbaas/sdk/go/... (e.g. sdk/go/secret)",
	},
	{
		name:   "go-quicraft",
		prefix: "github.com/jeremyhahn/go-quicraft",
		remedy: "github.com/jeremyhahn/go-quicbaas/sdk/go/...",
	},
	{
		name:   "go-truststrap",
		prefix: "github.com/jeremyhahn/go-truststrap",
		remedy: "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/...",
	},
	{
		// Locked memory is allocated by the stack, not by the platform.
		// pkg/memguard is the platform's MemoryEnclave API and it holds a
		// secure.Buffer from the SDK re-export; nothing in this module
		// reaches the underlying library directly.
		name:   "awnumar/memguard",
		prefix: "github.com/awnumar/memguard",
		remedy: "github.com/jeremyhahn/go-trusted-platform/pkg/memguard (MemoryEnclave), backed by github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure",
	},
}

// allowedPrefix is the single sanctioned upstream path. Any import beneath
// it is legal even when the alias chain resolves into a forbidden module.
const allowedPrefix = "github.com/jeremyhahn/go-quicbaas/"

// skipDirs are directories excluded from the sweep: VCS metadata, vendored
// third-party code, and JavaScript dependency trees.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
}

// moduleRoot resolves the module root from this file's location
// (pkg/arch/layerguard_test.go) and verifies go.mod is present.
func moduleRoot(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %s has no go.mod: %v", root, err)
	}
	return root
}

// collectImports parses every .go file under root (imports only) and returns
// the module-relative file path, line, and import path of each import spec.
func collectImports(t *testing.T, root string) []ForbiddenImportError {
	t.Helper()

	fset := token.NewFileSet()
	var imports []ForbiddenImportError

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A directory this user cannot open holds nothing this module
			// compiles, so it cannot hide an import. The devcontainer TPM
			// suite's platformd leaves a root-owned tpm2-keys/ under the
			// checkout (gitignored; go-xkms's node barrier derives it from
			// an empty storage path); without this the guard failed on
			// every checkout that had run that suite.
			if d != nil && d.IsDir() && errors.Is(err, fs.ErrPermission) {
				t.Logf("skipping unreadable directory %s: %v", path, err)
				return filepath.SkipDir
			}
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			// A file that does not parse cannot import anything; report it
			// so a syntax error never silently hides a violation.
			t.Errorf("parse %s: %v", path, err)
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		for _, spec := range file.Imports {
			value, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				continue
			}
			imports = append(imports, ForbiddenImportError{
				File:   rel,
				Line:   fset.Position(spec.Path.Pos()).Line,
				Import: value,
			})
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", root, walkErr)
	}
	return imports
}

// TestLayerBoundary_NoForbiddenUpstreamImports asserts that no Go file in the
// module — production or test — imports go-xkms, go-qrdb, go-quicraft,
// go-truststrap, or awnumar/memguard directly. The go-quicbaas SDK
// (including its sdk/go/xkms/* re-exports) is the only sanctioned upstream
// path, and locked memory is reached through pkg/memguard.MemoryEnclave,
// which is itself backed by that SDK.
func TestLayerBoundary_NoForbiddenUpstreamImports(t *testing.T) {
	root := moduleRoot(t)
	imports := collectImports(t, root)
	if len(imports) == 0 {
		t.Fatal("no imports collected; the guard is not scanning the module")
	}

	for _, rule := range layerRules {
		t.Run(rule.name, func(t *testing.T) {
			var violations []ForbiddenImportError
			for _, imp := range imports {
				if strings.HasPrefix(imp.Import, allowedPrefix) {
					continue
				}
				if !strings.HasPrefix(imp.Import, rule.prefix) {
					continue
				}
				imp.Rule = rule.name
				imp.Remedy = rule.remedy
				violations = append(violations, imp)
			}
			if len(violations) == 0 {
				return
			}
			t.Errorf("%d forbidden %s import(s) found:", len(violations), rule.name)
			for _, v := range violations {
				t.Errorf("  %v", v)
			}
		})
	}
}

// TestLayerBoundary_RulesAreWellFormed guards the guard: every rule must
// carry a name, a module prefix, and a remedy, and no rule may forbid the
// sanctioned go-quicbaas path.
func TestLayerBoundary_RulesAreWellFormed(t *testing.T) {
	seen := make(map[string]bool, len(layerRules))
	for _, rule := range layerRules {
		t.Run(rule.name, func(t *testing.T) {
			if rule.name == "" || rule.prefix == "" || rule.remedy == "" {
				t.Fatalf("incomplete rule: %+v", rule)
			}
			if strings.HasPrefix(allowedPrefix, rule.prefix) {
				t.Fatalf("rule %q forbids the sanctioned SDK path %q", rule.name, allowedPrefix)
			}
			if seen[rule.prefix] {
				t.Fatalf("duplicate rule prefix %q", rule.prefix)
			}
			seen[rule.prefix] = true
		})
	}
}

// TestLayerBoundary_DetectsSyntheticViolations exercises the matcher itself
// with inputs that must and must not trip each rule, so a regression in the
// prefix/allow-list logic cannot silently disable the sweep.
func TestLayerBoundary_DetectsSyntheticViolations(t *testing.T) {
	testCases := []struct {
		name       string
		importPath string
		forbidden  bool
	}{
		{"xkms internal package", "github.com/jeremyhahn/go-xkms/pkg/ca", true},
		{"xkms sdk", "github.com/jeremyhahn/go-xkms/sdk/go", true},
		{"qrdb sdk", "github.com/jeremyhahn/go-qrdb/sdk/go/secret", true},
		{"quicraft", "github.com/jeremyhahn/go-quicraft/pkg/raft", true},
		{"truststrap", "github.com/jeremyhahn/go-truststrap/pkg/dane", true},
		{"raw memguard", "github.com/awnumar/memguard", true},
		{"platform enclave", "github.com/jeremyhahn/go-trusted-platform/pkg/memguard", false},
		{"quicbaas xkms re-export", "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca", false},
		{"quicbaas sdk root", "github.com/jeremyhahn/go-quicbaas/sdk/go", false},
		{"platform package", "github.com/jeremyhahn/go-trusted-platform/pkg/app", false},
		{"stdlib", "crypto/x509", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var matched bool
			for _, rule := range layerRules {
				if strings.HasPrefix(tc.importPath, allowedPrefix) {
					continue
				}
				if strings.HasPrefix(tc.importPath, rule.prefix) {
					matched = true
				}
			}
			if matched != tc.forbidden {
				t.Fatalf("import %q: forbidden=%v, want %v", tc.importPath, matched, tc.forbidden)
			}
		})
	}
}
