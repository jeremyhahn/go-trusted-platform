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

package platform

import (
	"testing"
)

func TestProtocol_String(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		want     string
	}{
		{
			name:     "unix protocol",
			protocol: ProtocolUnix,
			want:     "unix",
		},
		{
			name:     "grpc protocol",
			protocol: ProtocolGRPC,
			want:     "grpc",
		},
		{
			name:     "rest protocol",
			protocol: ProtocolREST,
			want:     "rest",
		},
		{
			name:     "quic protocol",
			protocol: ProtocolQUIC,
			want:     "quic",
		},
		{
			name:     "mcp protocol",
			protocol: ProtocolMCP,
			want:     "mcp",
		},
		{
			name:     "embedded protocol",
			protocol: ProtocolEmbedded,
			want:     "embedded",
		},
		{
			name:     "unknown protocol",
			protocol: ProtocolUnknown,
			want:     "unknown",
		},
		{
			name:     "invalid protocol value",
			protocol: Protocol(99),
			want:     "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.protocol.String()
			if got != tt.want {
				t.Errorf("Protocol.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProtocol_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		want     bool
	}{
		{
			name:     "unix is valid",
			protocol: ProtocolUnix,
			want:     true,
		},
		{
			name:     "grpc is valid",
			protocol: ProtocolGRPC,
			want:     true,
		},
		{
			name:     "rest is valid",
			protocol: ProtocolREST,
			want:     true,
		},
		{
			name:     "quic is valid",
			protocol: ProtocolQUIC,
			want:     true,
		},
		{
			name:     "mcp is valid",
			protocol: ProtocolMCP,
			want:     true,
		},
		{
			name:     "embedded is valid",
			protocol: ProtocolEmbedded,
			want:     true,
		},
		{
			name:     "unknown is not valid",
			protocol: ProtocolUnknown,
			want:     false,
		},
		{
			name:     "invalid value is not valid",
			protocol: Protocol(99),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.protocol.IsValid()
			if got != tt.want {
				t.Errorf("Protocol.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseProtocol(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Protocol
	}{
		{
			name:  "parse unix",
			input: "unix",
			want:  ProtocolUnix,
		},
		{
			name:  "parse grpc",
			input: "grpc",
			want:  ProtocolGRPC,
		},
		{
			name:  "parse rest",
			input: "rest",
			want:  ProtocolREST,
		},
		{
			name:  "parse quic",
			input: "quic",
			want:  ProtocolQUIC,
		},
		{
			name:  "parse mcp",
			input: "mcp",
			want:  ProtocolMCP,
		},
		{
			name:  "parse embedded",
			input: "embedded",
			want:  ProtocolEmbedded,
		},
		{
			name:  "parse unknown",
			input: "unknown",
			want:  ProtocolUnknown,
		},
		{
			name:  "parse invalid string returns unknown",
			input: "bogus",
			want:  ProtocolUnknown,
		},
		{
			name:  "parse empty string",
			input: "",
			want:  ProtocolUnknown,
		},
		{
			name:  "parse uppercase (not supported)",
			input: "GRPC",
			want:  ProtocolUnknown,
		},
		{
			name:  "parse uppercase embedded (not supported)",
			input: "EMBEDDED",
			want:  ProtocolUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseProtocol(tt.input)
			if got != tt.want {
				t.Errorf("ParseProtocol(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestProtocol_DefaultPort(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		want     string
	}{
		{
			name:     "unix has no port",
			protocol: ProtocolUnix,
			want:     "",
		},
		{
			name:     "grpc default port",
			protocol: ProtocolGRPC,
			want:     DefaultGRPCPort,
		},
		{
			name:     "rest default port",
			protocol: ProtocolREST,
			want:     DefaultRESTPort,
		},
		{
			name:     "quic default port",
			protocol: ProtocolQUIC,
			want:     DefaultQUICPort,
		},
		{
			name:     "mcp default port",
			protocol: ProtocolMCP,
			want:     DefaultMCPPort,
		},
		{
			name:     "embedded has no port",
			protocol: ProtocolEmbedded,
			want:     "",
		},
		{
			name:     "unknown has no port",
			protocol: ProtocolUnknown,
			want:     "",
		},
		{
			name:     "invalid protocol has no port",
			protocol: Protocol(99),
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.protocol.DefaultPort()
			if got != tt.want {
				t.Errorf("Protocol.DefaultPort() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProtocol_Constants(t *testing.T) {
	// Verify that protocol constants have expected iota values
	if ProtocolUnknown != 0 {
		t.Error("ProtocolUnknown should be 0")
	}
	if ProtocolUnix != 1 {
		t.Error("ProtocolUnix should be 1")
	}
	if ProtocolGRPC != 2 {
		t.Error("ProtocolGRPC should be 2")
	}
	if ProtocolREST != 3 {
		t.Error("ProtocolREST should be 3")
	}
	if ProtocolQUIC != 4 {
		t.Error("ProtocolQUIC should be 4")
	}
	if ProtocolMCP != 5 {
		t.Error("ProtocolMCP should be 5")
	}
	if ProtocolEmbedded != 6 {
		t.Error("ProtocolEmbedded should be 6")
	}
}

func TestProtocol_MapConsistency(t *testing.T) {
	// Verify that all valid protocols are in the maps consistently
	validProtos := []Protocol{
		ProtocolUnix, ProtocolGRPC, ProtocolREST,
		ProtocolQUIC, ProtocolMCP, ProtocolEmbedded,
	}

	for _, p := range validProtos {
		// Should have a name
		name := p.String()
		if name == "unknown" {
			t.Errorf("Protocol %d should have a non-unknown name", p)
		}

		// ParseProtocol should round-trip
		parsed := ParseProtocol(name)
		if parsed != p {
			t.Errorf("ParseProtocol(%q) = %v, want %v", name, parsed, p)
		}

		// IsValid should return true
		if !p.IsValid() {
			t.Errorf("Protocol %v should be valid", p)
		}
	}
}

func TestProtocolEmbedded_RoundTrip(t *testing.T) {
	// Verify the full round-trip: constant -> string -> parse -> constant
	t.Run("string to parse round trip", func(t *testing.T) {
		str := ProtocolEmbedded.String()
		if str != "embedded" {
			t.Errorf("ProtocolEmbedded.String() = %q, want %q", str, "embedded")
		}

		parsed := ParseProtocol(str)
		if parsed != ProtocolEmbedded {
			t.Errorf("ParseProtocol(%q) = %v, want ProtocolEmbedded", str, parsed)
		}
	})

	// Verify embedded is in both name and fromString maps
	t.Run("present in protocolNames map", func(t *testing.T) {
		name, ok := protocolNames[ProtocolEmbedded]
		if !ok {
			t.Error("ProtocolEmbedded should be in protocolNames map")
		}
		if name != "embedded" {
			t.Errorf("protocolNames[ProtocolEmbedded] = %q, want %q", name, "embedded")
		}
	})

	t.Run("present in protocolFromString map", func(t *testing.T) {
		proto, ok := protocolFromString["embedded"]
		if !ok {
			t.Error("\"embedded\" should be in protocolFromString map")
		}
		if proto != ProtocolEmbedded {
			t.Errorf("protocolFromString[\"embedded\"] = %v, want ProtocolEmbedded", proto)
		}
	})

	t.Run("present in validProtocols map", func(t *testing.T) {
		_, ok := validProtocols[ProtocolEmbedded]
		if !ok {
			t.Error("ProtocolEmbedded should be in validProtocols map")
		}
	})
}
