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

// integration_daemon_guard_test.go — integration suites test the runner's
// daemon, never a QuicBaaS of their own.
//
// The devcontainer runner starts one platformd, with one backing store, and
// hands every suite its endpoints (PLATFORM_* env) and the mTLS trio. A suite
// that constructs its own QuicBaaS server inside that container collides with
// the daemon it is meant to test: the tenant harness bound 127.0.0.1:50100,
// the port the runner's daemon already holds, and failed on every run (#541).
//
// The guard parses every Go file under test/integration (build tags do not
// matter to the parser) and fails on any reference to the SDK's server
// constructor, with the file:line and the remedy.
package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	// integrationRoot is the module-relative root of the integration tree.
	integrationRoot = "test/integration"

	// quicbaasSDKImport is the SDK root package that re-exports the
	// QuicBaaS server constructor.
	quicbaasSDKImport = "github.com/jeremyhahn/go-quicbaas/sdk/go"

	// quicbaasSDKPackageName is the SDK root's declared package name, the
	// identifier an unaliased import binds.
	quicbaasSDKPackageName = "quicbaas"

	// quicbaasServerConstructor is the SDK root's server constructor.
	quicbaasServerConstructor = "NewServer"
)

// SelfHostedQuicBaaSError reports an integration test file that constructs
// its own QuicBaaS server instead of using the runner's daemon.
type SelfHostedQuicBaaSError struct {
	// File is the module-relative path of the offending file.
	File string

	// Line is the 1-based line of the offending reference.
	Line int
}

// Error implements error.
func (e SelfHostedQuicBaaSError) Error() string {
	return e.File + ":" + strconv.Itoa(e.Line) + ": integration test constructs its own QuicBaaS server (" +
		quicbaasSDKPackageName + "." + quicbaasServerConstructor + "); dial the runner's platformd " +
		"through the PLATFORM_* endpoints and the mTLS trio (test/integration/helpers) instead"
}

// selfHostedQuicBaaS parses src as the Go file named name and returns every
// reference it makes to the SDK's server constructor. A dot import of the
// SDK root is reported at the import, because it hides the constructor's
// qualifier.
func selfHostedQuicBaaS(fset *token.FileSet, name string, src any) ([]SelfHostedQuicBaaSError, error) {
	file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}

	var findings []SelfHostedQuicBaaSError
	localName := ""
	for _, spec := range file.Imports {
		path, unquoteErr := strconv.Unquote(spec.Path.Value)
		if unquoteErr != nil || path != quicbaasSDKImport {
			continue
		}
		localName = quicbaasSDKPackageName
		if spec.Name != nil {
			localName = spec.Name.Name
		}
		if localName == "." {
			findings = append(findings, SelfHostedQuicBaaSError{
				File: name,
				Line: fset.Position(spec.Pos()).Line,
			})
		}
	}
	if localName == "" || localName == "_" || localName == "." {
		return findings, nil
	}

	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != quicbaasServerConstructor {
			return true
		}
		qualifier, ok := selector.X.(*ast.Ident)
		if ok && qualifier.Name == localName {
			findings = append(findings, SelfHostedQuicBaaSError{
				File: name,
				Line: fset.Position(selector.Pos()).Line,
			})
		}
		return true
	})
	return findings, nil
}

// TestIntegrationSuites_UseTheRunnerDaemon fails when any file under
// test/integration constructs its own QuicBaaS server.
func TestIntegrationSuites_UseTheRunnerDaemon(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()

	walkErr := filepath.WalkDir(filepath.Join(root, integrationRoot), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		findings, parseErr := selfHostedQuicBaaS(fset, rel, src)
		if parseErr != nil {
			// A file that does not parse cannot be checked; report it so a
			// syntax error never silently hides a violation.
			t.Errorf("parse %s: %v", rel, parseErr)
			return nil
		}
		for _, finding := range findings {
			t.Error(finding.Error())
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", integrationRoot, walkErr)
	}
}

// TestSelfHostedQuicBaaS_DetectsSyntheticSources proves the detector on
// sources that do and do not construct a QuicBaaS server.
func TestSelfHostedQuicBaaS_DetectsSyntheticSources(t *testing.T) {
	testCases := []struct {
		name      string
		src       string
		wantLines []int
	}{
		{
			name: "unaliased import calls the constructor",
			src: "package p\n\nimport \"github.com/jeremyhahn/go-quicbaas/sdk/go\"\n\n" +
				"func f() { _, _ = quicbaas.NewServer(nil) }\n",
			wantLines: []int{5},
		},
		{
			name: "aliased import calls the constructor",
			src: "package p\n\nimport baas \"github.com/jeremyhahn/go-quicbaas/sdk/go\"\n\n" +
				"func f() { _, _ = baas.NewServer(nil) }\n",
			wantLines: []int{5},
		},
		{
			name: "constructor taken as a value",
			src: "package p\n\nimport \"github.com/jeremyhahn/go-quicbaas/sdk/go\"\n\n" +
				"var newServer = quicbaas.NewServer\n",
			wantLines: []int{5},
		},
		{
			name:      "dot import hides the qualifier",
			src:       "package p\n\nimport . \"github.com/jeremyhahn/go-quicbaas/sdk/go\"\n",
			wantLines: []int{3},
		},
		{
			name: "SDK client use is allowed",
			src: "package p\n\nimport \"github.com/jeremyhahn/go-quicbaas/sdk/go\"\n\n" +
				"var opt = quicbaas.WithEmbedded\n",
		},
		{
			name: "another package's NewServer is allowed",
			src: "package p\n\nimport \"google.golang.org/grpc\"\n\n" +
				"var s = grpc.NewServer()\n",
		},
		{
			name: "aliased SDK leaves the default name free",
			src: "package p\n\nimport (\n\tbaas \"github.com/jeremyhahn/go-quicbaas/sdk/go\"\n\tquicbaas \"example.com/other\"\n)\n\n" +
				"var _ = baas.WithEmbedded\nvar s = quicbaas.NewServer()\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := selfHostedQuicBaaS(token.NewFileSet(), "synthetic.go", tc.src)
			if err != nil {
				t.Fatalf("selfHostedQuicBaaS: %v", err)
			}
			var gotLines []int
			for _, finding := range findings {
				gotLines = append(gotLines, finding.Line)
			}
			if len(gotLines) != len(tc.wantLines) {
				t.Fatalf("findings at lines %v, want %v", gotLines, tc.wantLines)
			}
			for i := range gotLines {
				if gotLines[i] != tc.wantLines[i] {
					t.Fatalf("findings at lines %v, want %v", gotLines, tc.wantLines)
				}
			}
		})
	}
}

// TestSelfHostedQuicBaaS_RejectsInvalidSource proves a source that does not
// parse is an error, not a clean result.
func TestSelfHostedQuicBaaS_RejectsInvalidSource(t *testing.T) {
	findings, err := selfHostedQuicBaaS(token.NewFileSet(), "broken.go", "package p\n\nfunc {\n")
	if err == nil {
		t.Fatalf("selfHostedQuicBaaS returned %v and no error for an unparseable source", findings)
	}
}
