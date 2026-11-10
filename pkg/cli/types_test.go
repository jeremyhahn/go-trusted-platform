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

// ---------------------------------------------------------------------------
// QuicBaaS context resolver tests
// ---------------------------------------------------------------------------

func TestResolveQuicBaaSAddr_LocalDefault(t *testing.T) {
	ctx := &Context{
		Name: "local",
		Type: ContextTypeLocal,
		Local: &LocalContext{
			SocketPath: "/run/platformd.sock",
		},
	}
	if got := ctx.ResolveQuicBaaSAddr(); got != DefaultQuicBaaSSocketPath {
		t.Errorf("expected default quicbaas socket, got %q", got)
	}
}

func TestResolveQuicBaaSAddr_LocalOverride(t *testing.T) {
	ctx := &Context{
		Type: ContextTypeLocal,
		Local: &LocalContext{
			SocketPath:   "/run/platformd.sock",
			QuicBaaSAddr: "/tmp/custom.sock",
		},
	}
	if got := ctx.ResolveQuicBaaSAddr(); got != "/tmp/custom.sock" {
		t.Errorf("expected custom socket, got %q", got)
	}
}

func TestResolveQuicBaaSAddr_RemoteFallsBackToServer(t *testing.T) {
	ctx := &Context{
		Type: ContextTypeRemote,
		Remote: &RemoteContext{
			Server: "https://example.com:8443",
		},
	}
	if got := ctx.ResolveQuicBaaSAddr(); got != "https://example.com:8443" {
		t.Errorf("expected server URL, got %q", got)
	}
}

func TestResolveQuicBaaSAddr_RemoteOverride(t *testing.T) {
	ctx := &Context{
		Type: ContextTypeRemote,
		Remote: &RemoteContext{
			Server:       "https://example.com:8443",
			QuicBaaSAddr: "https://quicbaasd.example.com:9000",
		},
	}
	if got := ctx.ResolveQuicBaaSAddr(); got != "https://quicbaasd.example.com:9000" {
		t.Errorf("expected override, got %q", got)
	}
}

func TestResolveQuicBaaSAddr_RemoteNil(t *testing.T) {
	ctx := &Context{Type: ContextTypeRemote}
	if got := ctx.ResolveQuicBaaSAddr(); got != "" {
		t.Errorf("expected empty for nil remote, got %q", got)
	}
}

func TestResolveQuicBaaSAddr_EmbeddedReturnsEmpty(t *testing.T) {
	ctx := &Context{Type: ContextTypeEmbedded}
	if got := ctx.ResolveQuicBaaSAddr(); got != "" {
		t.Errorf("expected empty for embedded, got %q", got)
	}
}

func TestResolveQuicBaaSTransport_LocalDefault(t *testing.T) {
	ctx := &Context{Type: ContextTypeLocal, Local: &LocalContext{}}
	if got := ctx.ResolveQuicBaaSTransport(); got != "unix" {
		t.Errorf("expected unix default, got %q", got)
	}
}

func TestResolveQuicBaaSTransport_LocalOverride(t *testing.T) {
	ctx := &Context{Type: ContextTypeLocal, Local: &LocalContext{QuicBaaSTransport: "rest"}}
	if got := ctx.ResolveQuicBaaSTransport(); got != "rest" {
		t.Errorf("expected rest, got %q", got)
	}
}

func TestResolveQuicBaaSTransport_RemoteMirrorsProtocol(t *testing.T) {
	ctx := &Context{
		Type:     ContextTypeRemote,
		Protocol: "quic",
		Remote:   &RemoteContext{Server: "x"},
	}
	if got := ctx.ResolveQuicBaaSTransport(); got != "quic" {
		t.Errorf("expected quic (mirror), got %q", got)
	}
}

func TestResolveQuicBaaSTransport_RemoteOverride(t *testing.T) {
	ctx := &Context{
		Type:   ContextTypeRemote,
		Remote: &RemoteContext{Server: "x", QuicBaaSTransport: "mcp"},
	}
	if got := ctx.ResolveQuicBaaSTransport(); got != "mcp" {
		t.Errorf("expected mcp, got %q", got)
	}
}

func TestResolveQuicBaaSTransport_RemoteNil(t *testing.T) {
	ctx := &Context{Type: ContextTypeRemote}
	if got := ctx.ResolveQuicBaaSTransport(); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestResolveQuicBaaSTransport_EmbeddedReturnsEmpty(t *testing.T) {
	ctx := &Context{Type: ContextTypeEmbedded}
	if got := ctx.ResolveQuicBaaSTransport(); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}
