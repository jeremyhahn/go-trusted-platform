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

// This file implements the PXECommands interface over the SDK's REST transport.

//go:build integration

package pxe

import (
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// NewRESTAdapter drives the PXE service over HTTPS REST: the SDK's REST
// route map carries every PXEService method to the /api/v1/pxe routes. The
// endpoint already carries its https:// scheme, and REST is served over TLS
// only, so the adapter presents the suite's mTLS client certificate.
func NewRESTAdapter() *SDKAdapter {
	endpoint := GetServiceEndpoints().PlatformAPI
	return &SDKAdapter{
		name:     "REST",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolREST),
				platform.WithRESTAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}
