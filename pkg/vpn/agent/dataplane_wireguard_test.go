//go:build !fips

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

package agent

import (
	"bytes"
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
)

// fakeWireGuard records what the plane asks of the kernel. The key it was
// keyed with is copied, because the plane zeroizes the original.
type fakeWireGuard struct {
	upErr   error
	downErr error
	ups     []tunnel.WireGuardClientConfig
	keys    [][]byte
	downs   []string
}

func (d *fakeWireGuard) Up(cfg tunnel.WireGuardClientConfig) error {
	d.ups = append(d.ups, cfg)
	d.keys = append(d.keys, bytes.Clone(cfg.PrivateKey))
	return d.upErr
}

func (d *fakeWireGuard) Down(name string) error {
	d.downs = append(d.downs, name)
	return d.downErr
}

// fakeResolver answers gw.example and fails every other name.
func fakeResolver(_ context.Context, host string) ([]netip.Addr, error) {
	switch host {
	case "gw.example":
		return []netip.Addr{netip.MustParseAddr("::ffff:198.51.100.7"), netip.MustParseAddr("198.51.100.8")}, nil
	case "empty.example":
		return nil, nil
	}
	return nil, &errFake{"lookup " + host}
}

func newTestWireGuardPlane() (*wireGuardPlane, *fakeWireGuard) {
	device := &fakeWireGuard{}
	return newWireGuardPlane(device, fakeResolver, tunnel.GenerateWireGuardKey), device
}

func gatewayKey(t *testing.T) []byte {
	t.Helper()
	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	pub := priv.PublicKey()
	return pub[:]
}

func wireGuardLease(t *testing.T) *gwvpn.LeaseWire {
	return &gwvpn.LeaseWire{
		ID:        "l-1",
		Address:   "10.8.0.2/32",
		DataPlane: gwvpn.DataPlaneWireGuard,
		Endpoint: gwvpn.EndpointWire{WireGuard: &gwvpn.WireGuardEndpointWire{
			PublicKey: gatewayKey(t),
			Endpoint:  "198.51.100.7:51820",
			Routes:    []string{"10.20.0.0/16", "fd00:20::1/48"},
		}},
	}
}

// preparedKey returns the private key Prepare left pending, so a test can
// see it zeroized.
func preparedKey(t *testing.T, p *wireGuardPlane) []byte {
	t.Helper()
	pending := p.pending.Load()
	require.NotNil(t, pending)
	return *pending
}

func TestWireGuardPlane_UpKeysTheInterfaceFromTheLease(t *testing.T) {
	plane, device := newTestWireGuardPlane()
	lease := wireGuardLease(t)

	peer, err := plane.Prepare(context.Background())
	require.NoError(t, err)
	key := preparedKey(t, plane)
	session, err := plane.Up(context.Background(), lease)

	require.NoError(t, err)
	assert.Equal(t, gwvpn.DataPlaneWireGuard, plane.Kind())
	assert.Equal(t, Session{Interface: "vpn-wg0"}, session)
	require.Len(t, device.ups, 1)
	cfg := device.ups[0]
	assert.Equal(t, "vpn-wg0", cfg.Name)
	derived := wgtypes.Key(device.keys[0]).PublicKey()
	assert.Equal(t, peer.WireGuardPublicKey, derived[:], "keyed with the private half of the key the admission carried")
	assert.Equal(t, lease.Endpoint.WireGuard.PublicKey, cfg.PeerPublicKey)
	assert.Equal(t, netip.MustParseAddrPort("198.51.100.7:51820"), cfg.PeerEndpoint)
	assert.Equal(t, netip.MustParsePrefix("10.8.0.2/32"), cfg.Address)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd00:20::/48")}, cfg.Routes)
	assert.Equal(t, make([]byte, 32), key, "the private key is zeroized once the interface is keyed")
	assert.Nil(t, plane.pending.Load())
}

func TestWireGuardPlane_UpResolvesAHostNameEndpoint(t *testing.T) {
	plane, device := newTestWireGuardPlane()
	lease := wireGuardLease(t)
	lease.Endpoint.WireGuard.Endpoint = "gw.example:51820"

	_, err := plane.Prepare(context.Background())
	require.NoError(t, err)
	_, err = plane.Up(context.Background(), lease)

	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddrPort("198.51.100.7:51820"), device.ups[0].PeerEndpoint, "the first address, unmapped")
}

func TestWireGuardPlane_UpRefusesALeaseItCannotUse(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(l *gwvpn.LeaseWire)
	}{
		{"no endpoint", func(l *gwvpn.LeaseWire) { l.Endpoint.WireGuard = nil }},
		{"short gateway key", func(l *gwvpn.LeaseWire) { l.Endpoint.WireGuard.PublicKey = []byte("short") }},
		{"endpoint without a port", func(l *gwvpn.LeaseWire) { l.Endpoint.WireGuard.Endpoint = "198.51.100.7" }},
		{"endpoint port zero", func(l *gwvpn.LeaseWire) { l.Endpoint.WireGuard.Endpoint = "198.51.100.7:0" }},
		{"endpoint port not a number", func(l *gwvpn.LeaseWire) { l.Endpoint.WireGuard.Endpoint = "198.51.100.7:wg" }},
		{"endpoint host unresolvable", func(l *gwvpn.LeaseWire) { l.Endpoint.WireGuard.Endpoint = "nx.example:51820" }},
		{"endpoint host without addresses", func(l *gwvpn.LeaseWire) { l.Endpoint.WireGuard.Endpoint = "empty.example:51820" }},
		{"address not a prefix", func(l *gwvpn.LeaseWire) { l.Address = "10.8.0.2" }},
		{"no routes", func(l *gwvpn.LeaseWire) { l.Endpoint.WireGuard.Routes = nil }},
		{"route not a prefix", func(l *gwvpn.LeaseWire) { l.Endpoint.WireGuard.Routes = []string{"10.20.0.0/16", "zone-b"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plane, device := newTestWireGuardPlane()
			lease := wireGuardLease(t)
			tt.mutate(lease)

			_, err := plane.Prepare(context.Background())
			require.NoError(t, err)
			key := preparedKey(t, plane)
			_, err = plane.Up(context.Background(), lease)

			var unusable *ErrLeaseUnusable
			require.ErrorAs(t, err, &unusable)
			assert.Equal(t, gwvpn.DataPlaneWireGuard, unusable.Kind)
			assert.Empty(t, device.ups, "nothing reaches the kernel")
			assert.Equal(t, make([]byte, 32), key, "the refused key is zeroized")
		})
	}
}

func TestWireGuardPlane_UpWithoutAPreparedKeyIsRefused(t *testing.T) {
	plane, device := newTestWireGuardPlane()

	_, err := plane.Up(context.Background(), wireGuardLease(t))

	var notPrepared *ErrNotPrepared
	require.ErrorAs(t, err, &notPrepared)
	assert.Equal(t, "data plane wireguard: no client key was prepared for this lease", err.Error())
	assert.Empty(t, device.ups)
}

func TestWireGuardPlane_AFailedBringUpConsumesTheKey(t *testing.T) {
	plane, device := newTestWireGuardPlane()
	device.upErr = &tunnel.ErrTunnelCreateFailed{Name: "vpn-wg0", Cause: &errFake{"link add"}}

	_, err := plane.Prepare(context.Background())
	require.NoError(t, err)
	key := preparedKey(t, plane)
	_, err = plane.Up(context.Background(), wireGuardLease(t))

	assert.ErrorIs(t, err, device.upErr)
	assert.Equal(t, make([]byte, 32), key)
	_, err = plane.Up(context.Background(), wireGuardLease(t))
	var notPrepared *ErrNotPrepared
	assert.ErrorAs(t, err, &notPrepared, "a key is never used twice")
}

func TestWireGuardPlane_PrepareReplacesAnUnusedKey(t *testing.T) {
	plane, _ := newTestWireGuardPlane()

	first, err := plane.Prepare(context.Background())
	require.NoError(t, err)
	stale := preparedKey(t, plane)
	second, err := plane.Prepare(context.Background())
	require.NoError(t, err)

	assert.Len(t, second.WireGuardPublicKey, 32)
	assert.NotEqual(t, first.WireGuardPublicKey, second.WireGuardPublicKey)
	assert.Equal(t, make([]byte, 32), stale, "the unused key is zeroized")
}

func TestWireGuardPlane_PrepareReportsAKeyThatCannotBeMade(t *testing.T) {
	keygen := &tunnel.ErrKeyMaterial{Name: "client", Reason: "no entropy"}
	plane := newWireGuardPlane(&fakeWireGuard{}, fakeResolver, func() ([]byte, []byte, error) { return nil, nil, keygen })

	_, err := plane.Prepare(context.Background())

	assert.ErrorIs(t, err, keygen)
	assert.Nil(t, plane.pending.Load())
}

func TestWireGuardPlane_DownRemovesTheSessionsInterface(t *testing.T) {
	plane, device := newTestWireGuardPlane()

	require.NoError(t, plane.Down(context.Background(), Session{Interface: "vpn-wg0"}))
	assert.Equal(t, []string{"vpn-wg0"}, device.downs)

	device.downErr = &tunnel.ErrTunnelRemoveFailed{Name: "vpn-wg0", Cause: &errFake{"route del"}}
	assert.ErrorIs(t, plane.Down(context.Background(), Session{Interface: "vpn-wg0"}), device.downErr)
}

func TestNewWireGuardPlane_IsTheWireGuardPlane(t *testing.T) {
	plane := NewWireGuardPlane(nil)

	assert.Equal(t, gwvpn.DataPlaneWireGuard, plane.Kind())
	peer, err := plane.Prepare(context.Background())
	require.NoError(t, err)
	assert.Len(t, peer.WireGuardPublicKey, 32)
}
