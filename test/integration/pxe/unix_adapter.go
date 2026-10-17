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

// This file implements the PXECommands interface over the SDK's Unix transport.

//go:build integration

package pxe

import (
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

// NewUnixAdapter drives the PXE service over gRPC on the daemon's Unix
// socket, the CLI default. The socket serves gRPC, not HTTP, and
// authenticates the local peer, so no TLS configuration is passed.
func NewUnixAdapter() *SDKAdapter {
	socketPath := GetServiceEndpoints().PlatformdSocket
	return &SDKAdapter{
		name:     "Unix",
		endpoint: socketPath,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolUnix),
				platform.WithUnixSocket(socketPath),
			)
		},
	}
}
