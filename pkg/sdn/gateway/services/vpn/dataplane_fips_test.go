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

	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
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

func TestPlaneHost_CannotHostWireGuardUnderFIPS(t *testing.T) {
	var log []string
	_, err := NewPlaneHost(newManagedFakePlane("wireguard", &log))
	var invalid *ErrInvalidConfig
	require.True(t, errors.As(err, &invalid), "err = %v", err)
	assert.Contains(t, invalid.Reason, "not offered by this build")

	// A MASQUE-only host refuses a WireGuard peer as a plane it does not host.
	host, err := NewPlaneHost(newManagedFakePlane(DataPlaneMASQUE, &log))
	require.NoError(t, err)
	peer := masquePeer("l1")
	peer.DataPlane = "wireguard"
	peer.WireguardPublicKey = bytesOf(0x01, 32)
	refusal := host.InstallVPNPeer(context.Background(), &ipcv1.InstallVPNPeerRequest{Peer: peer}).GetRefusal()
	assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE, refusal.GetClass())
}

func TestNewDatapathPlane_RefusesWireGuardUnderFIPS(t *testing.T) {
	_, err := NewDatapathPlane("wireguard", &refusingPeers{})
	var unavailable *ErrDataPlaneUnavailable
	require.True(t, errors.As(err, &unavailable), "err = %v", err)
	assert.Equal(t, DataPlaneKind("wireguard"), unavailable.Kind)

	p, err := NewDatapathPlane(DataPlaneMASQUE, &refusingPeers{})
	require.NoError(t, err)
	assert.Equal(t, DataPlaneMASQUE, p.Kind())
}

// TestConfig_WireGuardKeysRefusedUnderFIPS: a FIPS build cannot offer
// WireGuard, so a configuration carrying `wireguard.*` keys is refused by
// name rather than silently ignored.
func TestConfig_WireGuardKeysRefusedUnderFIPS(t *testing.T) {
	cfg := parseVPNConfig(t, `
pool: vpn-clients
allow-to: [management]
masque:
  template: https://gw.example:4433/.well-known/masque/ip/
  routes: [10.0.0.0/8]
wireguard:
  listen-port: 51820
`)
	assertInvalidField(t, cfg.Validate(), "wireguard.listen-port")

	cfg.WireGuard = WireGuardSettings{KeyRef: "secret://vpn/hub-key"}
	assertInvalidField(t, cfg.Validate(), "wireguard.key-ref")

	cfg.WireGuard = WireGuardSettings{Address: netip.MustParsePrefix("10.99.0.1/24")}
	assertInvalidField(t, cfg.Validate(), "wireguard.address")

	cfg.WireGuard = WireGuardSettings{}
	require.NoError(t, cfg.Validate())
	assert.Zero(t, cfg.WithDefaults().WireGuard.ListenPort, "no WireGuard default in a FIPS build")
}
