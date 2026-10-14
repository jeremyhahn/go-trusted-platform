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

package vpn

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWireGuardIsAbsentUnderFIPS: the kind is not Known, so a configuration
// naming it is refused at load — there is no WireGuard symbol to reach.
func TestWireGuardIsAbsentUnderFIPS(t *testing.T) {
	assert.False(t, DataPlaneKind("wireguard").Known())
	cfg := testConfig()
	cfg.DataPlanes = []DataPlaneKind{"wireguard"}
	err := cfg.WithDefaults().Validate()
	var invalid *ErrInvalidConfig
	require.True(t, errors.As(err, &invalid))
	assert.Equal(t, "data-planes", invalid.Field)
}

// TestMASQUEPlaneIsTheFIPSPlane: the MASQUE plane is present and offered in
// a FIPS build, so a FIPS deployment still has remote access.
func TestMASQUEPlaneIsTheFIPSPlane(t *testing.T) {
	assert.True(t, DataPlaneMASQUE.Known())
	cfg := testConfig()
	cfg.DataPlanes = []DataPlaneKind{DataPlaneMASQUE}
	require.NoError(t, cfg.WithDefaults().Validate())

	pki := newTestPKI(t)
	plane, err := NewMASQUEPlane(MASQUEConfig{
		Template: "https://localhost:4433/.well-known/masque/ip/",
		TLS:      pki.serverTLS(),
		Routes:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}, newFakeDevice(), nil)
	require.NoError(t, err)
	assert.Equal(t, DataPlaneMASQUE, plane.Kind())
}

// TestRestore_DropsAWireGuardLeaseUnderFIPS: a lease recorded by a non-FIPS
// gateway names "wireguard"; a FIPS build has no plane of that kind, so
// Restore drops it rather than reinstating it (restore.go:58-59).
func TestRestore_DropsAWireGuardLeaseUnderFIPS(t *testing.T) {
	requireRestoreDrops(t, func(t *testing.T, h *restoreHarness, l *Lease) {
		l.DataPlane = DataPlaneKind("wireguard")
		require.NoError(t, h.store.Put(context.Background(), l))
	}, "data plane not offered")
}
