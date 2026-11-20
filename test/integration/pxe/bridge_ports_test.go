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

//go:build integration

package pxe

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterOptionsOnBridgeCreatesThePort requires RegisterOptionsOnBridge
// to add its port to the integration bridge and remove it when the test
// that made it ends (#1896 F47). No t.Parallel: it swaps ovsVsctl.
func TestRegisterOptionsOnBridgeCreatesThePort(t *testing.T) {
	var calls [][]string
	orig := ovsVsctl
	ovsVsctl = func(args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	}
	t.Cleanup(func() { ovsVsctl = orig })
	t.Setenv(EnvPXETestBridge, "br-rf1896b")

	var opts RegisterDeviceOptions
	t.Run("register", func(t *testing.T) {
		opts = RegisterOptionsOnBridge(t, "rf1896b-port")
		assert.Equal(t, OVSTestPortName("rf1896b-port"), opts.PortID)
		assert.NotEmpty(t, opts.MACAddress)
		require.Len(t, calls, 1)
		assert.Equal(t, []string{"--may-exist", "add-port", "br-rf1896b", opts.PortID,
			"--", "set", "interface", opts.PortID, "type=internal"}, calls[0])
	})
	require.NotEmpty(t, calls)
	assert.Equal(t, []string{"--if-exists", "del-port", "br-rf1896b", opts.PortID}, calls[len(calls)-1],
		"the port is removed when the test that made it ends")
}

// TestPXESuiteRegistersOnBridgePorts requires every registration in the PXE
// suite that must reach the daemon to be on a real port of the integration
// bridge: registration applies quarantine flows, which refuse a port the
// bridge does not have (#1896 F47). testPXECLI keeps one
// DefaultRegisterOptions call: the CLI refuses RegisterDevice before any
// daemon call, so no port is needed.
func TestPXESuiteRegistersOnBridgePorts(t *testing.T) {
	var bad []string
	for _, name := range []string{"pxe_test.go", "rest_adapter_test.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				line := fset.Position(call.Pos()).Line
				switch {
				case id.Name == "GenerateTestPortID":
					bad = append(bad, fmt.Sprintf("%s:%d GenerateTestPortID", name, line))
				case id.Name == "DefaultRegisterOptions" && fn.Name.Name != "testPXECLI":
					bad = append(bad, fmt.Sprintf("%s:%d DefaultRegisterOptions", name, line))
				}
				return true
			})
		}
	}
	require.Empty(t, bad, strings.Join(bad, "\n"))
}
