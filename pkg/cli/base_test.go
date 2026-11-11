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

package cli

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// startTestGRPCServer starts a gRPC server on a Unix socket for testing
func startTestGRPCServer(t *testing.T, socketPath string) (*grpc.Server, func()) {
	t.Helper()

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	server := grpc.NewServer()

	go func() {
		if err := server.Serve(listener); err != nil && err != grpc.ErrServerStopped {
			t.Logf("gRPC server error: %v", err)
		}
	}()

	// The listener is already bound: a dial queues in its backlog until
	// Serve accepts it, so no start-up wait is needed.
	cleanup := func() {
		server.GracefulStop()
		listener.Close()
	}

	return server, cleanup
}

func TestNewBaseCommand_GetContextError(t *testing.T) {
	flags := &CommonFlags{
		ConfigPath:   "",
		ContextName:  "nonexistent",
		OutputFormat: OutputFormatTable,
		GetConfig: func() (*Config, error) {
			return DefaultConfig(), nil
		},
		GetContext: func() (*Context, error) {
			return nil, ErrContextNotFound{Context: "nonexistent"}
		},
	}

	baseCmd, err := NewBaseCommand(flags)

	require.Error(t, err)
	assert.Nil(t, baseCmd)
	assert.Contains(t, err.Error(), "failed to get context")
}

func TestNewBaseCommand_ConnectionFailed(t *testing.T) {
	// Context with invalid socket path
	testCtx := &Context{
		Name: "invalid",
		Type: ContextTypeLocal,
		Local: &LocalContext{
			SocketPath: "/nonexistent/socket.sock",
		},
	}

	flags := &CommonFlags{
		ConfigPath:   "",
		ContextName:  "invalid",
		OutputFormat: OutputFormatTable,
		GetConfig: func() (*Config, error) {
			return DefaultConfig(), nil
		},
		GetContext: func() (*Context, error) {
			return testCtx, nil
		},
	}

	baseCmd, err := NewBaseCommand(flags)

	// Connection may succeed (lazy) or fail immediately
	if err != nil {
		assert.IsType(t, ErrConnectionFailed{}, err)
		assert.Nil(t, baseCmd)
	} else {
		// Lazy connection succeeded, clean up
		assert.NotNil(t, baseCmd)
		baseCmd.Close()
	}
}

func TestBaseCommand_Close_NilClient(t *testing.T) {
	baseCmd := &BaseCommand{
		client: nil,
	}

	err := baseCmd.Close()

	// Should not error when client is nil
	require.NoError(t, err)
}

func TestBaseCommand_AllOutputFormats(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	server, cleanup := startTestGRPCServer(t, socketPath)
	defer cleanup()
	_ = server

	testCtx := &Context{
		Name: "test",
		Type: ContextTypeLocal,
		Local: &LocalContext{
			SocketPath: socketPath,
		},
	}

	formats := []OutputFormat{
		OutputFormatTable,
		OutputFormatJSON,
		OutputFormatYAML,
	}

	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			flags := &CommonFlags{
				OutputFormat: format,
				GetConfig: func() (*Config, error) {
					return DefaultConfig(), nil
				},
				GetContext: func() (*Context, error) {
					return testCtx, nil
				},
			}

			baseCmd, err := NewBaseCommand(flags)
			require.NoError(t, err)
			defer baseCmd.Close()

			printer := baseCmd.Printer()
			assert.Equal(t, format, printer.format)
		})
	}
}

func TestBaseCommand_FullWorkflow(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "workflow.sock")

	server, cleanup := startTestGRPCServer(t, socketPath)
	defer cleanup()
	_ = server

	testCtx := &Context{
		Name: "workflow-test",
		Type: ContextTypeLocal,
		Local: &LocalContext{
			SocketPath: socketPath,
		},
	}

	flags := &CommonFlags{
		ConfigPath:   "/etc/platformctl/config.yaml",
		ContextName:  "workflow-test",
		OutputFormat: OutputFormatTable,
		Verbose:      true,
		NoColor:      true,
		GetConfig: func() (*Config, error) {
			return DefaultConfig(), nil
		},
		GetContext: func() (*Context, error) {
			return testCtx, nil
		},
	}

	// Create base command
	baseCmd, err := NewBaseCommand(flags)
	require.NoError(t, err)

	// Verify all components are accessible
	assert.NotNil(t, baseCmd.Client())
	assert.NotNil(t, baseCmd.Printer())
	assert.IsType(t, context.Background(), baseCmd.Context())
	assert.Equal(t, flags, baseCmd.Flags())
	assert.True(t, baseCmd.flags.Verbose)

	// Verify client is connected
	assert.True(t, baseCmd.Client().IsConnected())

	// Test printer functionality
	printer := baseCmd.Printer()
	assert.Equal(t, OutputFormatTable, printer.format)
	assert.True(t, printer.noColor)

	// Clean up
	err = baseCmd.Close()
	require.NoError(t, err)
	assert.False(t, baseCmd.Client().IsConnected())
}

// contextToSDKOptions tests

func TestContextToSDKOptions_LocalUnix(t *testing.T) {
	ctx := &Context{
		Name: "local-test",
		Type: ContextTypeLocal,
		Local: &LocalContext{
			SocketPath: "/run/platformd.sock",
		},
	}

	opts, err := contextToSDKOptions(ctx)

	require.NoError(t, err)
	require.NotNil(t, opts)
	assert.Equal(t, platform.ProtocolUnix, opts.OnlyProtocol)
	assert.Equal(t, "/run/platformd.sock", opts.UnixSocket)
}

func TestContextToSDKOptions_LocalUnixWithGRPCAddr(t *testing.T) {
	ctx := &Context{
		Name: "local-grpc",
		Type: ContextTypeLocal,
		Local: &LocalContext{
			SocketPath: "/run/platformd.sock",
			GRPCAddr:   "localhost:10443",
		},
	}

	opts, err := contextToSDKOptions(ctx)

	require.NoError(t, err)
	require.NotNil(t, opts)
	assert.Equal(t, platform.ProtocolUnix, opts.OnlyProtocol)
	assert.Equal(t, "/run/platformd.sock", opts.UnixSocket)
	assert.Equal(t, "localhost:10443", opts.GRPCAddr)
}

func TestContextToSDKOptions_RemoteGRPC(t *testing.T) {
	ctx := &Context{
		Name: "remote-grpc",
		Type: ContextTypeRemote,
		Remote: &RemoteContext{
			Server: "platform.example.com:10443",
		},
	}

	opts, err := contextToSDKOptions(ctx)

	require.NoError(t, err)
	require.NotNil(t, opts)
	assert.Equal(t, platform.ProtocolGRPC, opts.OnlyProtocol)
	assert.Equal(t, "platform.example.com:10443", opts.GRPCAddr)
}

func TestContextToSDKOptions_RemoteREST(t *testing.T) {
	ctx := &Context{
		Name:     "remote-rest",
		Type:     ContextTypeRemote,
		Protocol: "rest",
		Remote: &RemoteContext{
			Server: "https://platform.example.com:8443",
		},
	}

	opts, err := contextToSDKOptions(ctx)

	require.NoError(t, err)
	require.NotNil(t, opts)
	assert.Equal(t, platform.ProtocolREST, opts.OnlyProtocol)
	assert.Equal(t, "https://platform.example.com:8443", opts.RESTAddr)
}

func TestContextToSDKOptions_RemoteQUIC(t *testing.T) {
	ctx := &Context{
		Name:     "remote-quic",
		Type:     ContextTypeRemote,
		Protocol: "quic",
		Remote: &RemoteContext{
			Server: "platform.example.com:9444",
		},
	}

	opts, err := contextToSDKOptions(ctx)

	require.NoError(t, err)
	require.NotNil(t, opts)
	assert.Equal(t, platform.ProtocolQUIC, opts.OnlyProtocol)
	assert.Equal(t, "platform.example.com:9444", opts.QUICAddr)
}

func TestContextToSDKOptions_RemoteMCP(t *testing.T) {
	ctx := &Context{
		Name:     "remote-mcp",
		Type:     ContextTypeRemote,
		Protocol: "mcp",
		Remote: &RemoteContext{
			Server: "http://platform.example.com:9445",
		},
	}

	opts, err := contextToSDKOptions(ctx)

	require.NoError(t, err)
	require.NotNil(t, opts)
	assert.Equal(t, platform.ProtocolMCP, opts.OnlyProtocol)
	assert.Equal(t, "http://platform.example.com:9445", opts.MCPAddr)
}

func TestContextToSDKOptions_Embedded(t *testing.T) {
	ctx := &Context{
		Name: "embedded-ctx",
		Type: ContextTypeEmbedded,
	}

	opts, err := contextToSDKOptions(ctx)

	require.NoError(t, err)
	require.NotNil(t, opts)
	assert.Equal(t, platform.ProtocolEmbedded, opts.OnlyProtocol)
}

func TestContextToSDKOptions_NilContext(t *testing.T) {
	opts, err := contextToSDKOptions(nil)

	require.Error(t, err)
	assert.Nil(t, opts)
	assert.Contains(t, err.Error(), "context cannot be nil")
}

func TestContextToSDKOptions_InvalidProtocol(t *testing.T) {
	ctx := &Context{
		Name:     "invalid-proto",
		Type:     ContextTypeRemote,
		Protocol: "bogus",
		Remote: &RemoteContext{
			Server: "example.com:1234",
		},
	}

	opts, err := contextToSDKOptions(ctx)

	require.Error(t, err)
	assert.Nil(t, opts)
	assert.IsType(t, ErrInvalidContext{}, err)
	assert.Contains(t, err.Error(), "unsupported protocol")
	assert.Contains(t, err.Error(), "bogus")
}

func TestContextToSDKOptions_MissingLocalConfig(t *testing.T) {
	ctx := &Context{
		Name:  "local-missing",
		Type:  ContextTypeLocal,
		Local: nil,
	}

	opts, err := contextToSDKOptions(ctx)

	require.Error(t, err)
	assert.Nil(t, opts)
	assert.Contains(t, err.Error(), "local context configuration is missing")
}

func TestContextToSDKOptions_MissingRemoteConfig(t *testing.T) {
	ctx := &Context{
		Name:   "remote-missing",
		Type:   ContextTypeRemote,
		Remote: nil,
	}

	opts, err := contextToSDKOptions(ctx)

	require.Error(t, err)
	assert.Nil(t, opts)
	assert.Contains(t, err.Error(), "remote context configuration is missing")
}

func TestContextToSDKOptions_InvalidContextType(t *testing.T) {
	ctx := &Context{
		Name: "bad-type",
		Type: ContextType("unknown-type"),
	}

	opts, err := contextToSDKOptions(ctx)

	require.Error(t, err)
	assert.Nil(t, opts)
	assert.IsType(t, ErrInvalidContext{}, err)
}

func TestContextToSDKOptions_RemoteNoCerts(t *testing.T) {
	// Remote with no certs should produce nil TLS config
	ctx := &Context{
		Name: "remote-no-certs",
		Type: ContextTypeRemote,
		Remote: &RemoteContext{
			Server: "platform.example.com:10443",
		},
	}

	opts, err := contextToSDKOptions(ctx)

	require.NoError(t, err)
	require.NotNil(t, opts)
	assert.Equal(t, platform.ProtocolGRPC, opts.OnlyProtocol)
	// TLS config is nil when no certs provided
	assert.Nil(t, opts.TLSConfig)
}

func TestContextToSDKOptions_RemoteProtocolOverrideFallback(t *testing.T) {
	// RemoteContext.Protocol used when Context.Protocol is empty
	ctx := &Context{
		Name: "remote-fallback",
		Type: ContextTypeRemote,
		Remote: &RemoteContext{
			Server:   "platform.example.com:9444",
			Protocol: "quic",
		},
	}

	opts, err := contextToSDKOptions(ctx)

	require.NoError(t, err)
	require.NotNil(t, opts)
	assert.Equal(t, platform.ProtocolQUIC, opts.OnlyProtocol)
	assert.Equal(t, "platform.example.com:9444", opts.QUICAddr)
}

// protocolAddress tests

func TestProtocolAddress_SetsTheProtocolField(t *testing.T) {
	tests := []struct {
		protocol platform.Protocol
		addr     string
		field    func(*platform.Options) string
	}{
		{platform.ProtocolREST, "https://example.com:8443", func(o *platform.Options) string { return o.RESTAddr }},
		{platform.ProtocolGRPC, "example.com:10443", func(o *platform.Options) string { return o.GRPCAddr }},
		{platform.ProtocolQUIC, "example.com:9444", func(o *platform.Options) string { return o.QUICAddr }},
		{platform.ProtocolMCP, "http://example.com:9445", func(o *platform.Options) string { return o.MCPAddr }},
		{platform.ProtocolUnix, "/run/platformd.sock", func(o *platform.Options) string { return o.UnixSocket }},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			result := protocolAddress(tt.protocol, tt.addr)
			require.Len(t, result, 1)

			opts := platform.NewOptions(result...)
			assert.Equal(t, tt.addr, tt.field(opts))
		})
	}
}

func TestProtocolAddress_Embedded(t *testing.T) {
	// Embedded protocol has no address, returns nil
	result := protocolAddress(platform.ProtocolEmbedded, "anything")

	assert.Nil(t, result)
}

func TestProtocolAddress_Unknown(t *testing.T) {
	// Unknown protocol returns nil
	result := protocolAddress(platform.ProtocolUnknown, "anything")

	assert.Nil(t, result)
}

// protocolMap tests

func TestProtocolMap_AllProtocolsMapped(t *testing.T) {
	expected := map[string]platform.Protocol{
		"unix":     platform.ProtocolUnix,
		"grpc":     platform.ProtocolGRPC,
		"rest":     platform.ProtocolREST,
		"quic":     platform.ProtocolQUIC,
		"mcp":      platform.ProtocolMCP,
		"embedded": platform.ProtocolEmbedded,
	}

	assert.Len(t, protocolMap, len(expected))

	for key, wantProto := range expected {
		gotProto, ok := protocolMap[key]
		assert.True(t, ok, "expected key %q in protocolMap", key)
		assert.Equal(t, wantProto, gotProto, "protocol mismatch for key %q", key)
	}
}

func TestNewBaseCommand_NilFlags(t *testing.T) {
	baseCmd, err := NewBaseCommand(nil)

	require.Error(t, err)
	assert.Nil(t, baseCmd)
	assert.IsType(t, ErrNoContextSet{}, err)
}

func TestNewBaseCommand_NilGetContext(t *testing.T) {
	flags := &CommonFlags{
		GetContext: nil,
	}

	baseCmd, err := NewBaseCommand(flags)

	require.Error(t, err)
	assert.Nil(t, baseCmd)
	assert.IsType(t, ErrNoContextSet{}, err)
}

// ---------------------------------------------------------------------------
// QuicBaaS option resolver tests
// ---------------------------------------------------------------------------

func TestResolveContextQuicBaaSOptions_NilContextReturnsNil(t *testing.T) {
	if got := resolveContextQuicBaaSOptions(nil); got != nil {
		t.Errorf("expected nil for nil context, got %v", got)
	}
}

func TestResolveContextQuicBaaSOptions_LocalDefaults(t *testing.T) {
	ctx := &Context{Type: ContextTypeLocal, Local: &LocalContext{SocketPath: "/run/platformd.sock"}}
	got := resolveContextQuicBaaSOptions(ctx)
	if len(got) == 0 {
		t.Fatal("expected options for local context")
	}
	// Apply the options to an Options struct and verify the addr.
	o := platformNewOptionsForTest(got...)
	if o.QuicBaaSAddr != DefaultQuicBaaSSocketPath {
		t.Errorf("expected default quicbaas socket, got %q", o.QuicBaaSAddr)
	}
	if o.QuicBaaSTransport != "unix" {
		t.Errorf("expected unix transport, got %q", o.QuicBaaSTransport)
	}
}

func TestResolveContextQuicBaaSOptions_EnvOverridesContext(t *testing.T) {
	t.Setenv(EnvPlatformQuicBaaSAddr, "/tmp/from-env.sock")
	t.Setenv(EnvPlatformQuicBaaSTransport, "rest")

	ctx := &Context{Type: ContextTypeLocal, Local: &LocalContext{
		QuicBaaSAddr:      "/run/quicbaas.sock",
		QuicBaaSTransport: "unix",
	}}
	o := platformNewOptionsForTest(resolveContextQuicBaaSOptions(ctx)...)
	if o.QuicBaaSAddr != "/tmp/from-env.sock" {
		t.Errorf("env addr must win, got %q", o.QuicBaaSAddr)
	}
	if o.QuicBaaSTransport != "rest" {
		t.Errorf("env transport must win, got %q", o.QuicBaaSTransport)
	}
}

func TestResolveContextQuicBaaSOptions_EmbeddedReturnsNil(t *testing.T) {
	ctx := &Context{Type: ContextTypeEmbedded}
	if got := resolveContextQuicBaaSOptions(ctx); got != nil {
		t.Errorf("expected nil for embedded context (no addr), got %v", got)
	}
}

// platformNewOptionsForTest applies a slice of platform.Option to a
// fresh Options struct and returns it. Used by the QuicBaaS resolver
// tests to inspect the values written into Options.
func platformNewOptionsForTest(opts ...platform.Option) *platform.Options {
	return platform.NewOptions(opts...)
}
