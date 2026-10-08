//go:build fips

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

package gateway

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
)

// TestGatewayConfig_Validate_WireGuardRefusedUnderFIPS: the gateway section
// reaches the tunnel package's own validation, so a wireguard tunnel is
// refused when the configuration loads, with the typed error that names the
// ipsec transport as the FIPS alternative.
func TestGatewayConfig_Validate_WireGuardRefusedUnderFIPS(t *testing.T) {
	cfg := baseGatewayConfig("fips-wg")
	cfg.Tunnels = []TunnelConfig{{
		Name: "wg-a", Transport: tunnel.TransportWireGuard,
		Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.1.1/30",
		WireGuard: &tunnel.WireGuardConfig{KeyRef: "kms://k", PeerPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", RemotePort: 51820},
	}}

	err := cfg.Validate()

	var unavailable *tunnel.ErrTransportUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Contains(t, err.Error(), "ipsec")
}
