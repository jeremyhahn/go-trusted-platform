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

package commands

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// TestServeCommand_ListenerFlagsAreRegistered pins the flag surface of
// the serve command: a bind-host and a port flag per transport, defaulting
// to loopback on the canonical ports.
func TestServeCommand_ListenerFlagsAreRegistered(t *testing.T) {
	for flag, def := range map[string]string{
		"rest-bind-host": tpconfig.LoopbackBindHost, "rest-port": "8443",
		"grpc-bind-host": tpconfig.LoopbackBindHost, "grpc-port": "10443",
		"quic-bind-host": tpconfig.LoopbackBindHost, "quic-port": "9444",
		"mcp-bind-host": tpconfig.LoopbackBindHost, "mcp-port": "9445",
	} {
		f := serveCmd.Flags().Lookup(flag)
		require.NotNil(t, f, flag)
		assert.Equal(t, def, f.DefValue, flag)
	}
}

// TestResolveDaemonListeners_DefaultsAndEnv proves the serve command
// resolves through the global viper the root and serve inits wired: the
// defaults are loopback, and the PLATFORMD_ environment layer is live.
func TestResolveDaemonListeners_DefaultsAndEnv(t *testing.T) {
	got, err := resolveDaemonListeners(serveCmd)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:10443", got.GRPC.Address())

	t.Setenv("PLATFORMD_DAEMON_GRPC_BIND_HOST", "0.0.0.0")
	t.Setenv("PLATFORMD_DAEMON_GRPC_PORT", "20443")
	got, err = resolveDaemonListeners(serveCmd)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:20443", got.GRPC.Address())
	assert.Equal(t, "127.0.0.1:9444", got.QUIC.Address(), "other transports keep their defaults")
}

// TestResolveDaemonListeners_InvalidValueIsAStartupError proves a bad
// value stops startup with the serve command's typed error, naming the
// listener phase, and is printed for the operator.
func TestResolveDaemonListeners_InvalidValueIsAStartupError(t *testing.T) {
	t.Setenv("PLATFORMD_DAEMON_REST_PORT", "99999")
	var stderr bytes.Buffer
	serveCmd.SetErr(&stderr)
	defer serveCmd.SetErr(nil)

	_, err := resolveDaemonListeners(serveCmd)
	var startup ErrServeStartup
	require.True(t, errors.As(err, &startup), "got %v", err)
	assert.Equal(t, "daemon listener configuration", startup.Phase)
	var port *tpconfig.ErrInvalidListenerPort
	assert.True(t, errors.As(startup.Cause, &port))
	assert.Contains(t, stderr.String(), "daemon.rest.port")
}

// TestApplyDaemonListeners_WritesEveryTransport proves the resolved
// `daemon:` section reaches every daemon listener field, including the
// QUIC server's own address and an MCP config the defaults left nil.
func TestApplyDaemonListeners_WritesEveryTransport(t *testing.T) {
	t.Setenv("PLATFORMD_DAEMON_REST_BIND_HOST", "10.0.0.1")
	t.Setenv("PLATFORMD_DAEMON_GRPC_BIND_HOST", "10.0.0.2")
	t.Setenv("PLATFORMD_DAEMON_QUIC_BIND_HOST", "::1")
	t.Setenv("PLATFORMD_DAEMON_MCP_PORT", "29445")
	listeners, err := resolveDaemonListeners(serveCmd)
	require.NoError(t, err)

	cfg := daemon.DefaultConfig()
	cfg.EnableREST = true
	cfg.QUICConfig = &quic.ServerConfig{ListenAddr: "0.0.0.0:9444"}
	cfg.MCPConfig = nil
	applyDaemonListeners(cfg, listeners)

	assert.Equal(t, "10.0.0.1:8443", cfg.RESTListenAddr)
	assert.Equal(t, "10.0.0.2:10443", cfg.GRPCListenAddr)
	assert.Equal(t, "[::1]:9444", cfg.QUICListenAddr)
	assert.Equal(t, "[::1]:9444", cfg.QUICConfig.ListenAddr)
	require.NotNil(t, cfg.MCPConfig)
	assert.Equal(t, "127.0.0.1:29445", cfg.MCPConfig.HTTPAddr)
}

// TestApplyDaemonListeners_LeavesRESTToTheWebservice proves a daemon that
// does not serve REST keeps its REST address untouched (the webservice owns
// REST and its bind host in that mode), and that a missing QUIC config is
// not invented.
func TestApplyDaemonListeners_LeavesRESTToTheWebservice(t *testing.T) {
	t.Setenv("PLATFORMD_DAEMON_REST_BIND_HOST", "10.0.0.1")
	listeners, err := resolveDaemonListeners(serveCmd)
	require.NoError(t, err)

	cfg := daemon.DefaultConfig()
	cfg.EnableREST = false
	cfg.RESTListenAddr = "unchanged"
	cfg.QUICConfig = nil
	applyDaemonListeners(cfg, listeners)

	assert.Equal(t, "unchanged", cfg.RESTListenAddr)
	assert.Nil(t, cfg.QUICConfig)
	assert.Equal(t, "127.0.0.1:10443", cfg.GRPCListenAddr)
}

// daemonListenAddrFields are the daemon config fields that carry a
// transport bind address.
var daemonListenAddrFields = map[string]bool{
	"RESTListenAddr": true,
	"GRPCListenAddr": true,
	"QUICListenAddr": true,
	"ListenAddr":     true,
	"HTTPAddr":       true,
}

// TestServeCommands_NoListenAddressOutsideApplyDaemonListeners guards the
// #93 ruling at the source: in this package, a transport bind address is
// written only by applyDaemonListeners, and never as a string literal or a
// fmt.Sprintf. Reintroducing `cfg.GRPCListenAddr = "0.0.0.0:..."` on either
// serve path fails here with its file:line.
func TestServeCommands_NoListenAddressOutsideApplyDaemonListeners(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var violations []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, parseErr, name)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Name.Name == "applyDaemonListeners" {
				continue
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.AssignStmt:
					for _, lhs := range node.Lhs {
						sel, isSel := lhs.(*ast.SelectorExpr)
						if isSel && daemonListenAddrFields[sel.Sel.Name] {
							violations = append(violations, fset.Position(node.Pos()).String()+": assigns "+sel.Sel.Name)
						}
					}
				case *ast.KeyValueExpr:
					key, isIdent := node.Key.(*ast.Ident)
					if isIdent && daemonListenAddrFields[key.Name] && isLiteralAddress(node.Value) {
						violations = append(violations, fset.Position(node.Pos()).String()+": literal "+key.Name)
					}
				}
				return true
			})
		}
	}
	assert.Empty(t, violations, "set listen addresses only in applyDaemonListeners, from the `daemon:` section")
}

// isLiteralAddress reports a string literal or a fmt.Sprintf call.
func isLiteralAddress(expr ast.Expr) bool {
	switch value := expr.(type) {
	case *ast.BasicLit:
		return value.Kind == token.STRING
	case *ast.CallExpr:
		sel, ok := value.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "fmt" && sel.Sel.Name == "Sprintf"
	}
	return false
}

// TestIsLiteralAddress pins the guard's classifier: literals and Sprintf
// are caught, a value copied from config is not.
func TestIsLiteralAddress(t *testing.T) {
	for src, want := range map[string]bool{
		`"0.0.0.0:8443"`:                  true,
		`fmt.Sprintf("0.0.0.0:%d", port)`: true,
		`listeners.REST.Address()`:        false,
		`cfg.RESTListenAddr`:              false,
		`8443`:                            false,
		`strings.Join(parts, ":")`:        false,
	} {
		expr, err := parser.ParseExpr(src)
		require.NoError(t, err, src)
		assert.Equal(t, want, isLiteralAddress(expr), src)
	}
}
