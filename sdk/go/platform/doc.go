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
//
// The SDK offers a unified client abstraction for connecting to the platform daemon
// via multiple protocols:
//
//   - Unix Domain Socket (ProtocolUnix) - gRPC over /run/platformd.sock
//   - gRPC over TCP (ProtocolGRPC) - port 10443
//   - REST over HTTP/HTTPS (ProtocolREST) - port 8443
//   - QUIC over UDP (ProtocolQUIC) - port 9444
//   - MCP over stdio/HTTP (ProtocolMCP) - port 9445
//
// # Basic Usage
//
// The simplest way to connect is using NewClient with functional options:
//
//	client, err := platform.NewClient(ctx,
//	    platform.WithGRPCAddr("localhost:10443"),
//	    platform.WithTLSConfig(tlsConfig),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Use service clients
//	resp, err := client.Daemon().GetVersion(ctx, &platformv1.GetVersionRequest{})
//
// # Protocol Selection
//
// By default, the client tries protocols in this order: Unix > gRPC > REST > QUIC > MCP.
// Unix socket requires root privileges.
//
// To force a specific protocol:
//
//	client, err := platform.NewClient(ctx,
//	    platform.WithGRPCAddr("localhost:10443"),
//	    platform.WithOnlyProtocol(platform.ProtocolGRPC),
//	)
//
// To set a preferred protocol (tried first, falls back to others):
//
//	client, err := platform.NewClient(ctx,
//	    platform.WithGRPCAddr("localhost:10443"),
//	    platform.WithUnixSocket("/run/platformd.sock"),
//	    platform.WithPreferredProtocol(platform.ProtocolGRPC),
//	)
//
// # Transport Registration
//
// Transport adapters register themselves during package initialization.
// Import the transport packages to enable their protocols:
//
//	import (
//	    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
//	    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
//	)
//
// # Error Handling
//
// All errors returned by the SDK are typed for easy inspection:
//
//	var connErr platform.ErrConnectionFailed
//	if errors.As(err, &connErr) {
//	    log.Printf("Failed to connect via %s to %s: %v",
//	        connErr.Protocol, connErr.Target, connErr.Err)
//	}
package platform
