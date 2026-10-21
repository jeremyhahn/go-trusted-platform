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

// Package pxe provides integration test adapters for PXE provisioning services.
// This file implements the PXECommands interface over the SDK's Unix transport.

//go:build integration

package pxe

import (
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

// NewUnixAdapter drives the PXE service over the platformd Unix socket. The
// socket serves gRPC (the daemon registers PXEService on its UDS gRPC server),
// so this is the SDK's Unix transport: gRPC over the socket, authenticated by
// peer credentials, with no TLS options.
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
