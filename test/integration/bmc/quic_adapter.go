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

// This file implements the BMCCommands interface over the SDK's QUIC transport.

//go:build integration

package bmc_integration

import (
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// NewQUICAdapter drives the BMC service over QUIC: every BMCService method
// travels as an OpBMCCategory sub-opcode.
func NewQUICAdapter() *SDKAdapter {
	endpoint := GetServiceEndpoints().PlatformQUIC
	return &SDKAdapter{
		name:     "QUIC",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolQUIC),
				platform.WithQUICAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}
