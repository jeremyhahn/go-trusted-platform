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

// Package platform provides the Go SDK for go-trusted-platform.
// It offers a unified client abstraction for connecting to the platform daemon
// via multiple protocols including Unix socket, gRPC, REST, QUIC, and MCP.
package platform

// Protocol represents the communication protocol used to connect to the daemon.
type Protocol uint8

const (
	// ProtocolUnknown represents an unknown or invalid protocol.
	ProtocolUnknown Protocol = iota

	// ProtocolUnix connects via gRPC over Unix Domain Socket.
	// Default path: /run/platformd.sock
	// Requires root privileges on the host.
	ProtocolUnix

	// ProtocolGRPC connects via gRPC over TCP.
	// Default port: 10443
	ProtocolGRPC

	// ProtocolREST connects via REST over HTTP/HTTPS.
	// Default port: 8443
	ProtocolREST

	// ProtocolQUIC connects via QUIC over UDP.
	// Default port: 9444
	ProtocolQUIC

	// ProtocolMCP connects via MCP (Model Context Protocol) over stdio/HTTP.
	// Default port: 9445
	// Used for AI/LLM integration.
	ProtocolMCP

	// ProtocolEmbedded connects via in-process direct service calls.
	// No network transport is used. Used for desktop embedded mode.
	ProtocolEmbedded
)

// protocolNames provides O(1) lookup for protocol string representations.
var protocolNames = map[Protocol]string{
	ProtocolUnknown:  "unknown",
	ProtocolUnix:     "unix",
	ProtocolGRPC:     "grpc",
	ProtocolREST:     "rest",
	ProtocolQUIC:     "quic",
	ProtocolMCP:      "mcp",
	ProtocolEmbedded: "embedded",
}

// protocolFromString provides O(1) lookup for parsing protocol strings.
var protocolFromString = map[string]Protocol{
	"unknown":  ProtocolUnknown,
	"unix":     ProtocolUnix,
	"grpc":     ProtocolGRPC,
	"rest":     ProtocolREST,
	"quic":     ProtocolQUIC,
	"mcp":      ProtocolMCP,
	"embedded": ProtocolEmbedded,
}

// validProtocols contains all supported protocols for O(1) validation.
var validProtocols = map[Protocol]struct{}{
	ProtocolUnix:     {},
	ProtocolGRPC:     {},
	ProtocolREST:     {},
	ProtocolQUIC:     {},
	ProtocolMCP:      {},
	ProtocolEmbedded: {},
}

// String returns the string representation of the protocol.
func (p Protocol) String() string {
	if name, ok := protocolNames[p]; ok {
		return name
	}
	return protocolNames[ProtocolUnknown]
}

// IsValid checks if the protocol is a valid, supported protocol.
func (p Protocol) IsValid() bool {
	_, ok := validProtocols[p]
	return ok
}

// ParseProtocol converts a string to a Protocol.
// Returns ProtocolUnknown if the string does not match a known protocol.
func ParseProtocol(s string) Protocol {
	if proto, ok := protocolFromString[s]; ok {
		return proto
	}
	return ProtocolUnknown
}

// DefaultPort returns the default port for the protocol.
func (p Protocol) DefaultPort() string {
	switch p {
	case ProtocolUnix:
		return "" // Unix socket uses a path, not a port
	case ProtocolGRPC:
		return DefaultGRPCPort
	case ProtocolREST:
		return DefaultRESTPort
	case ProtocolQUIC:
		return DefaultQUICPort
	case ProtocolMCP:
		return DefaultMCPPort
	case ProtocolEmbedded:
		return "" // Embedded uses in-process calls, no port
	default:
		return ""
	}
}
