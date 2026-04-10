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

// Package transport provides transport layer abstractions for the platform SDK.
// It defines the Adapter interface that all protocol implementations must satisfy.
package transport

import (
	"google.golang.org/grpc"
)

// Adapter defines the interface for protocol-specific transport implementations.
// Each protocol (gRPC, Unix, REST, QUIC, MCP) implements this interface to provide
// a consistent connection abstraction to the platform package.
type Adapter interface {
	// Connection returns the underlying gRPC client connection.
	// For non-gRPC protocols, this may return a wrapped connection that
	// implements the gRPC interface.
	Connection() grpc.ClientConnInterface

	// Close closes the transport connection and releases resources.
	Close() error

	// IsConnected returns true if the transport is currently connected.
	IsConnected() bool

	// Target returns the connection target (address, socket path, etc.).
	Target() string
}
