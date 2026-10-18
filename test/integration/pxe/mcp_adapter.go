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

// This file implements the PXECommands interface over the SDK's MCP transport.

//go:build integration

package pxe

import (
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// NewMCPAdapter drives the PXE service over MCP: every PXEService method
// travels as its pxe_* tool.
func NewMCPAdapter() *SDKAdapter {
	endpoint := GetServiceEndpoints().PlatformMCP
	return &SDKAdapter{
		name:     "MCP",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolMCP),
				platform.WithMCPAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}
