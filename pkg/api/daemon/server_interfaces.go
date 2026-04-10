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

package daemon

import (
	"context"
	"net"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
)

// GRPCServerInterface defines the interface for gRPC server operations.
// This allows injection of mock servers for testing.
type GRPCServerInterface interface {
	// RegisterService registers a service and its implementation to the gRPC server
	RegisterService(desc *grpc.ServiceDesc, impl interface{})

	// Serve starts the gRPC server using the provided listener
	Serve(lis net.Listener) error

	// GracefulStop gracefully stops the server
	GracefulStop()

	// Stop immediately stops the server
	Stop()
}

// QUICServerInterface defines the interface for QUIC server operations.
// This allows injection of mock servers for testing.
type QUICServerInterface interface {
	// Start starts the QUIC server
	Start() error

	// Stop gracefully stops the QUIC server
	Stop() error

	// IsRunning returns true if the server is running
	IsRunning() bool

	// ListenAddr returns the configured listen address
	ListenAddr() string

	// GetMetrics returns current server metrics
	GetMetrics() map[string]interface{}

	// Stats returns current server statistics
	Stats() *quic.ServerStats
}

// RESTServerInterface defines the interface for REST server operations.
// This allows injection of mock servers for testing.
type RESTServerInterface interface {
	// Start starts the REST server
	Start() error

	// Stop gracefully stops the REST server
	Stop(ctx context.Context) error

	// ForceStop immediately stops the REST server
	ForceStop() error

	// IsRunning returns whether the REST server is running
	IsRunning() bool
}

// MCPServerInterface defines the interface for MCP server operations.
// This allows injection of mock servers for testing.
type MCPServerInterface interface {
	// Start starts the MCP server with the configured transport
	Start() error

	// Stop gracefully shuts down the MCP server
	Stop() error

	// IsRunning returns true if the server is running
	IsRunning() bool
}

// Compile-time interface assertions to ensure concrete types implement the interfaces.
// These will cause compilation errors if the concrete types don't implement the interfaces.
var (
	_ QUICServerInterface = (*quic.Server)(nil)
	_ RESTServerInterface = (*RESTServer)(nil)
	_ MCPServerInterface  = (*mcp.Server)(nil)
	_ GRPCServerInterface = (*grpc.Server)(nil)
)
