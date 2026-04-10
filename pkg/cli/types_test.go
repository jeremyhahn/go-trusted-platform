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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOutputFormat_IsValid_ValidFormats(t *testing.T) {
	tests := []struct {
		name   string
		format OutputFormat
		want   bool
	}{
		{
			name:   "table format is valid",
			format: OutputFormatTable,
			want:   true,
		},
		{
			name:   "json format is valid",
			format: OutputFormatJSON,
			want:   true,
		},
		{
			name:   "yaml format is valid",
			format: OutputFormatYAML,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.format.IsValid()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestOutputFormat_IsValid_InvalidFormats(t *testing.T) {
	tests := []struct {
		name   string
		format OutputFormat
		want   bool
	}{
		{
			name:   "xml format is invalid",
			format: OutputFormat("xml"),
			want:   false,
		},
		{
			name:   "csv format is invalid",
			format: OutputFormat("csv"),
			want:   false,
		},
		{
			name:   "empty format is invalid",
			format: OutputFormat(""),
			want:   false,
		},
		{
			name:   "random string is invalid",
			format: OutputFormat("random"),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.format.IsValid()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestContextType_Constants(t *testing.T) {
	assert.Equal(t, ContextType("local"), ContextTypeLocal)
	assert.Equal(t, ContextType("remote"), ContextTypeRemote)
}

func TestContextTypeEmbedded_Value(t *testing.T) {
	assert.Equal(t, ContextType("embedded"), ContextTypeEmbedded)
	assert.Equal(t, "embedded", string(ContextTypeEmbedded))
}

func TestContext_Structure(t *testing.T) {
	ctx := &Context{
		Name: "test-context",
		Type: ContextTypeLocal,
		Local: &LocalContext{
			SocketPath: "/var/run/test.sock",
		},
	}

	assert.Equal(t, "test-context", ctx.Name)
	assert.Equal(t, ContextTypeLocal, ctx.Type)
	assert.NotNil(t, ctx.Local)
	assert.Equal(t, "/var/run/test.sock", ctx.Local.SocketPath)
	assert.Nil(t, ctx.Remote)
}

func TestContext_LocalContext(t *testing.T) {
	local := &LocalContext{
		SocketPath: "/run/platformd.sock",
	}

	assert.Equal(t, "/run/platformd.sock", local.SocketPath)
}

func TestContext_RemoteContext(t *testing.T) {
	remote := &RemoteContext{
		Server:     "https://platform.example.com:8443",
		CACert:     "/path/to/ca.crt",
		ClientCert: "/path/to/client.crt",
		ClientKey:  "/path/to/client.key",
	}

	assert.Equal(t, "https://platform.example.com:8443", remote.Server)
	assert.Equal(t, "/path/to/ca.crt", remote.CACert)
	assert.Equal(t, "/path/to/client.crt", remote.ClientCert)
	assert.Equal(t, "/path/to/client.key", remote.ClientKey)
}

func TestContext_BothContextsNil(t *testing.T) {
	ctx := &Context{
		Name:   "empty-context",
		Type:   ContextTypeLocal,
		Local:  nil,
		Remote: nil,
	}

	assert.Nil(t, ctx.Local)
	assert.Nil(t, ctx.Remote)
}

func TestContext_BothContextsPopulated(t *testing.T) {
	// This is a degenerate case but should be allowed by the type system
	ctx := &Context{
		Name: "dual-context",
		Type: ContextTypeLocal,
		Local: &LocalContext{
			SocketPath: "/run/test.sock",
		},
		Remote: &RemoteContext{
			Server: "https://test.com:8443",
		},
	}

	assert.NotNil(t, ctx.Local)
	assert.NotNil(t, ctx.Remote)
}

func TestResolveProtocol_LocalDefault(t *testing.T) {
	ctx := &Context{
		Name: "local-ctx",
		Type: ContextTypeLocal,
		Local: &LocalContext{
			SocketPath: "/run/platformd.sock",
		},
	}

	result := ctx.ResolveProtocol()
	assert.Equal(t, "unix", result)
}

func TestResolveProtocol_RemoteDefault(t *testing.T) {
	ctx := &Context{
		Name: "remote-ctx",
		Type: ContextTypeRemote,
		Remote: &RemoteContext{
			Server: "https://platform.example.com:10443",
		},
	}

	result := ctx.ResolveProtocol()
	assert.Equal(t, "grpc", result)
}

func TestResolveProtocol_EmbeddedDefault(t *testing.T) {
	ctx := &Context{
		Name: "embedded-ctx",
		Type: ContextTypeEmbedded,
	}

	result := ctx.ResolveProtocol()
	assert.Equal(t, "embedded", result)
}

func TestResolveProtocol_ExplicitProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		ctxType  ContextType
	}{
		{name: "explicit rest on local", protocol: "rest", ctxType: ContextTypeLocal},
		{name: "explicit quic on remote", protocol: "quic", ctxType: ContextTypeRemote},
		{name: "explicit mcp on remote", protocol: "mcp", ctxType: ContextTypeRemote},
		{name: "explicit grpc on local", protocol: "grpc", ctxType: ContextTypeLocal},
		{name: "explicit unix on remote", protocol: "unix", ctxType: ContextTypeRemote},
		{name: "explicit embedded on local", protocol: "embedded", ctxType: ContextTypeLocal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &Context{
				Name:     "test",
				Type:     tt.ctxType,
				Protocol: tt.protocol,
			}

			result := ctx.ResolveProtocol()
			assert.Equal(t, tt.protocol, result)
		})
	}
}

func TestResolveProtocol_RemoteProtocolOverride(t *testing.T) {
	// When Context.Protocol is empty but RemoteContext.Protocol is set,
	// RemoteContext.Protocol is used.
	ctx := &Context{
		Name: "remote-override",
		Type: ContextTypeRemote,
		Remote: &RemoteContext{
			Server:   "https://platform.example.com:8443",
			Protocol: "rest",
		},
	}

	result := ctx.ResolveProtocol()
	assert.Equal(t, "rest", result)
}

func TestResolveProtocol_ContextProtocolPriority(t *testing.T) {
	// Context.Protocol takes priority over RemoteContext.Protocol
	ctx := &Context{
		Name:     "priority-test",
		Type:     ContextTypeRemote,
		Protocol: "quic",
		Remote: &RemoteContext{
			Server:   "https://platform.example.com:9444",
			Protocol: "rest",
		},
	}

	result := ctx.ResolveProtocol()
	assert.Equal(t, "quic", result)
}

func TestResolveProtocol_RemoteNilRemoteContext(t *testing.T) {
	// Remote type with nil Remote field falls back to default "grpc"
	ctx := &Context{
		Name: "remote-nil",
		Type: ContextTypeRemote,
	}

	result := ctx.ResolveProtocol()
	assert.Equal(t, "grpc", result)
}

func TestResolveProtocol_UnknownTypeFallback(t *testing.T) {
	// Unknown context type falls back to "grpc"
	ctx := &Context{
		Name: "unknown",
		Type: ContextType("something-else"),
	}

	result := ctx.ResolveProtocol()
	assert.Equal(t, "grpc", result)
}

func TestValidProtocols_AllSupported(t *testing.T) {
	expected := []string{"unix", "grpc", "rest", "quic", "mcp", "embedded"}

	assert.Len(t, ValidProtocols, len(expected))

	for _, proto := range expected {
		_, ok := ValidProtocols[proto]
		assert.True(t, ok, "expected protocol %q to be in ValidProtocols", proto)
	}
}

func TestValidProtocols_InvalidNotPresent(t *testing.T) {
	invalidProtocols := []string{"bogus", "http", "tcp", "websocket", "", "GRPC", "Unix"}

	for _, proto := range invalidProtocols {
		t.Run(proto, func(t *testing.T) {
			_, ok := ValidProtocols[proto]
			assert.False(t, ok, "protocol %q should not be in ValidProtocols", proto)
		})
	}
}

func TestRemoteContext_ProtocolField(t *testing.T) {
	remote := &RemoteContext{
		Server:   "https://example.com:8443",
		Protocol: "quic",
	}

	assert.Equal(t, "quic", remote.Protocol)
}

func TestRemoteContext_TokenField(t *testing.T) {
	remote := &RemoteContext{
		Server: "https://example.com:8443",
		Token:  "bearer-token-value",
	}

	assert.Equal(t, "bearer-token-value", remote.Token)
}

func TestLocalContext_GRPCAddrField(t *testing.T) {
	local := &LocalContext{
		SocketPath: "/run/platformd.sock",
		GRPCAddr:   "localhost:10443",
	}

	assert.Equal(t, "localhost:10443", local.GRPCAddr)
}

func TestContext_ProtocolField(t *testing.T) {
	ctx := &Context{
		Name:     "proto-ctx",
		Type:     ContextTypeRemote,
		Protocol: "mcp",
		Remote: &RemoteContext{
			Server: "https://example.com:9445",
		},
	}

	assert.Equal(t, "mcp", ctx.Protocol)
}
