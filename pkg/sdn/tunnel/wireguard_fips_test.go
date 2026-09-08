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

package tunnel

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWireGuard_RefusedUnderFIPS pins the FIPS rule: the transport is
// compiled out and refused at configuration time with a typed error that
// points at the ipsec transport.
func TestWireGuard_RefusedUnderFIPS(t *testing.T) {
	assert.False(t, wireGuardAvailable)
	cfg := TunnelConfig{Name: "wg", Transport: TransportWireGuard, Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.1.1/30",
		WireGuard: &WireGuardConfig{KeyRef: "kms://k", PeerPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", RemotePort: 51820}}
	err := cfg.Validate()
	var unavailable *ErrTransportUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Contains(t, err.Error(), "ipsec")

	m := newManagerWithOps(testLogger(), newMockNetlinkOps(), WithKeyProvider(&mockKeys{}))
	require.True(t, errors.As(m.createWireGuard(context.Background(), cfg), &unavailable))
	require.True(t, errors.As(m.rekeyWireGuard(context.Background(), cfg), &unavailable))
}
