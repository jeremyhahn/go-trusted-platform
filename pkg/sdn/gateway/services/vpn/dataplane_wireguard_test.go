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

package vpn

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWireGuardIsOfferedOutsideFIPS(t *testing.T) {
	assert.True(t, DataPlaneWireGuard.Known())
	cfg := testConfig()
	cfg.DataPlanes = []DataPlaneKind{DataPlaneWireGuard, DataPlaneMASQUE}
	require.NoError(t, cfg.WithDefaults().Validate())
}

// fakeHub records what the plane asks the kernel for.
type fakeHub struct {
	mu        sync.Mutex
	up        int
	down      int
	upErr     error
	downErr   error
	setErr    error
	removeErr error
	peers     map[string][]netip.Prefix
	removed   []string
	pub       []byte
}

func newFakeHub() *fakeHub {
	return &fakeHub{peers: map[string][]netip.Prefix{}, pub: bytes.Repeat([]byte{7}, 32)}
}

func (h *fakeHub) Up(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.up++
	return h.upErr
}

func (h *fakeHub) Down() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.down++
	return h.downErr
}

func (h *fakeHub) SetPeer(_ context.Context, publicKey []byte, allowed []netip.Prefix) error {
	if h.setErr != nil {
		return h.setErr
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.peers[string(publicKey)] = allowed
	return nil
}

func (h *fakeHub) RemovePeer(_ context.Context, publicKey []byte) error {
	if h.removeErr != nil {
		return h.removeErr
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.peers, string(publicKey))
	h.removed = append(h.removed, string(publicKey))
	return nil
}

func (h *fakeHub) PublicKey() []byte { return h.pub }
func (h *fakeHub) ListenPort() int   { return 51820 }

func wgClientKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func wgLease(id LeaseID, addr string, key []byte) *Lease {
	return &Lease{ID: id, DeviceID: "mini-99", TenantID: "t1", Address: netip.MustParsePrefix(addr), DataPlane: DataPlaneWireGuard, Keys: PeerKeys{WireGuardPublicKey: key}}
}

func newWireGuardPlaneForTest(t *testing.T) (*wireguardPlane, *fakeHub) {
	t.Helper()
	hub := newFakeHub()
	plane, err := NewWireGuardPlane(hub, slog.Default())
	require.NoError(t, err)
	require.NoError(t, plane.Start(context.Background()))
	return plane.(*wireguardPlane), hub
}

func TestWireGuardPlane_InstallAndRemove(t *testing.T) {
	plane, hub := newWireGuardPlaneForTest(t)
	assert.Equal(t, DataPlaneWireGuard, plane.Kind())
	key := wgClientKey(1)
	require.NoError(t, plane.InstallPeer(context.Background(), wgLease("l1", "10.9.0.23/32", key)))
	allowed, ok := hub.peers[string(key)]
	require.True(t, ok, "peer not programmed")
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.9.0.23/32")}, allowed,
		"a client may source packets only from its lease address")

	require.NoError(t, plane.RemovePeer(context.Background(), "l1"))
	_, ok = hub.peers[string(key)]
	assert.False(t, ok, "peer not removed")
	// Removing again, and removing a lease this plane never saw, are both
	// no-ops: the peer is gone either way.
	require.NoError(t, plane.RemovePeer(context.Background(), "l1"))
	require.NoError(t, plane.RemovePeer(context.Background(), "never"))
	assert.Len(t, hub.removed, 1)
}

// TestWireGuardPlane_ReconcileRemovesPeersOutsideKeep covers the hosted
// plane's half of a vpn child's restart: a peer whose lease the restarted
// child no longer stores is removed from the hub; a kept one stays.
func TestWireGuardPlane_ReconcileRemovesPeersOutsideKeep(t *testing.T) {
	plane, hub := newWireGuardPlaneForTest(t)
	kept, revoked := wgClientKey(1), wgClientKey(2)
	require.NoError(t, plane.InstallPeer(context.Background(), wgLease("l1", "10.9.0.23/32", kept)))
	require.NoError(t, plane.InstallPeer(context.Background(), wgLease("l2", "10.9.0.24/32", revoked)))

	var r PeerReconciler = plane
	require.NoError(t, r.ReconcilePeers(context.Background(), []LeaseID{"l1"}))
	_, ok := hub.peers[string(kept)]
	assert.True(t, ok, "the kept peer was removed")
	_, ok = hub.peers[string(revoked)]
	assert.False(t, ok, "the revoked peer is still on the hub")
}

func TestWireGuardPlane_RefusesBadLeases(t *testing.T) {
	plane, hub := newWireGuardPlaneForTest(t)
	ctx := context.Background()
	var keyErr *ErrPeerKeyInvalid
	var reqErr *ErrInvalidRequest

	assert.True(t, errors.As(plane.InstallPeer(ctx, nil), &reqErr))
	assert.True(t, errors.As(plane.InstallPeer(ctx, wgLease("l1", "10.9.0.23/32", []byte("short"))), &keyErr))
	assert.True(t, errors.As(plane.InstallPeer(ctx, wgLease("l1", "10.9.0.0/24", wgClientKey(1))), &keyErr),
		"a lease covering more than one address must be refused")
	assert.True(t, errors.As(plane.InstallPeer(ctx, &Lease{ID: "l1", Keys: PeerKeys{WireGuardPublicKey: wgClientKey(1)}}), &keyErr))
	assert.Empty(t, hub.peers)
}

func TestWireGuardPlane_KernelRefusalIsReported(t *testing.T) {
	plane, hub := newWireGuardPlaneForTest(t)
	boom := errors.New("kernel says no")
	hub.setErr = boom
	err := plane.InstallPeer(context.Background(), wgLease("l1", "10.9.0.23/32", wgClientKey(1)))
	require.ErrorIs(t, err, boom)

	hub.setErr = nil
	require.NoError(t, plane.InstallPeer(context.Background(), wgLease("l1", "10.9.0.23/32", wgClientKey(1))))
	hub.removeErr = boom
	require.ErrorIs(t, plane.RemovePeer(context.Background(), "l1"), boom)
	assert.Contains(t, plane.peers, LeaseID("l1"), "the lease must stay mapped when the kernel refused the removal")
}

func TestWireGuardPlane_Lifecycle(t *testing.T) {
	hub := newFakeHub()
	plane, err := NewWireGuardPlane(hub, nil)
	require.NoError(t, err)
	ctx := context.Background()

	var notStarted *ErrDataPlaneNotStarted
	assert.True(t, errors.As(plane.InstallPeer(ctx, wgLease("l1", "10.9.0.23/32", wgClientKey(1))), &notStarted))

	require.NoError(t, plane.Start(ctx))
	require.NoError(t, plane.Start(ctx), "Start is idempotent")
	assert.Equal(t, 1, hub.up)
	require.NoError(t, plane.InstallPeer(ctx, wgLease("l1", "10.9.0.23/32", wgClientKey(1))))

	require.NoError(t, plane.Stop(ctx))
	require.NoError(t, plane.Stop(ctx), "Stop is idempotent")
	assert.Equal(t, 1, hub.down)
	// The device is gone, so the lease table is empty and a removal has
	// nothing left to do.
	require.NoError(t, plane.RemovePeer(ctx, "l1"))
	assert.Empty(t, hub.removed)
}

func TestWireGuardPlane_StartFailureAndMissingHub(t *testing.T) {
	boom := errors.New("no device")
	hub := newFakeHub()
	hub.upErr = boom
	plane, err := NewWireGuardPlane(hub, nil)
	require.NoError(t, err)
	require.ErrorIs(t, plane.Start(context.Background()), boom)

	var missing *ErrDepsMissing
	_, err = NewWireGuardPlane(nil, nil)
	assert.True(t, errors.As(err, &missing))
}

// TestRestore_DropsAWireGuardLeaseTheGatewayDoesNotOffer: a recorded
// WireGuard lease on a gateway that offers only MASQUE is dropped
// (restore.go:58-59).
func TestRestore_DropsAWireGuardLeaseTheGatewayDoesNotOffer(t *testing.T) {
	requireRestoreDrops(t, func(t *testing.T, h *restoreHarness, l *Lease) {
		l.DataPlane = DataPlaneWireGuard
		require.NoError(t, h.store.Put(context.Background(), l))
	}, "data plane not offered")
}

func TestPlaneHost_HostsBothPlanesAndUnwindsAFailedStart(t *testing.T) {
	var log []string
	wg := newManagedFakePlane(DataPlaneWireGuard, &log)
	masque := newManagedFakePlane(DataPlaneMASQUE, &log)
	host, err := NewPlaneHost(wg, masque)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, host.Start(ctx))
	require.NoError(t, host.Stop(ctx))
	assert.Equal(t, []string{"start wireguard", "start masque", "stop masque", "stop wireguard"}, log)

	log = nil
	masque.startErr = errors.New("bind: address in use")
	err = host.Start(ctx)
	assert.ErrorIs(t, err, masque.startErr)
	assert.Equal(t, []string{"start wireguard", "start masque", "stop wireguard"}, log,
		"the plane that started is stopped again; the one that failed is not")
}

func TestDatapathPlane_ForwardsAWireGuardPeer(t *testing.T) {
	var log []string
	plane := newManagedFakePlane(DataPlaneWireGuard, &log)
	host, err := NewPlaneHost(plane)
	require.NoError(t, err)
	p, err := NewDatapathPlane(DataPlaneWireGuard, &hostPeers{host: host})
	require.NoError(t, err)

	lease := &Lease{ID: "l1", DataPlane: DataPlaneWireGuard, Address: netip.MustParsePrefix("100.64.0.9/32"),
		Keys: PeerKeys{WireGuardPublicKey: bytesOf(0x01, 32)}}
	require.NoError(t, p.InstallPeer(context.Background(), lease))
	require.NotNil(t, plane.installed["l1"])
	assert.Equal(t, bytesOf(0x01, 32), plane.installed["l1"].Keys.WireGuardPublicKey)

	// A refusal from the child's WireGuard plane comes back typed.
	plane.installErr = &ErrPeerKeyInvalid{Kind: DataPlaneWireGuard, Reason: "the public key is not 32 bytes"}
	assert.Equal(t, plane.installErr, p.InstallPeer(context.Background(), lease))
}

// TestConfig_WireGuardKeysOutsideFIPS pins the `wireguard.*` keys where the
// plane exists: read from YAML, defaulted only when wireguard is offered,
// range-checked, and the `masque.*` keys refused when masque is not offered.
func TestConfig_WireGuardKeysOutsideFIPS(t *testing.T) {
	t.Run("the listen port defaults for an offered plane", func(t *testing.T) {
		cfg := parseVPNConfig(t, `
pool: vpn-clients
allow-to: [management]
data-planes: [wireguard]
`)
		require.NoError(t, cfg.Validate())
		assert.Equal(t, DefaultWireGuardListenPort, cfg.WireGuard.ListenPort)
	})
	t.Run("the listen port is read", func(t *testing.T) {
		cfg := parseVPNConfig(t, `
pool: vpn-clients
allow-to: [management]
data-planes: [wireguard]
wireguard:
  listen-port: 51821
`)
		require.NoError(t, cfg.Validate())
		assert.Equal(t, 51821, cfg.WireGuard.ListenPort)
	})
	t.Run("a listen port out of range is refused", func(t *testing.T) {
		cfg := testConfig()
		cfg.DataPlanes = []DataPlaneKind{DataPlaneWireGuard}
		cfg.MASQUE = MASQUESettings{}
		cfg.WireGuard.ListenPort = 65536
		assertInvalidField(t, cfg.WithDefaults().Validate(), "wireguard.listen-port")
		cfg.WireGuard.ListenPort = -1
		assertInvalidField(t, cfg.WithDefaults().Validate(), "wireguard.listen-port")
	})
	t.Run("masque keys without the masque plane are refused", func(t *testing.T) {
		for name, set := range map[string]func(*MASQUESettings){
			"template": func(m *MASQUESettings) { m.Routes = nil },
			"routes":   func(m *MASQUESettings) { m.Template = "" },
		} {
			t.Run(name, func(t *testing.T) {
				cfg := testConfig()
				cfg.DataPlanes = []DataPlaneKind{DataPlaneWireGuard}
				set(&cfg.MASQUE)
				assertInvalidField(t, cfg.WithDefaults().Validate(), "masque")
			})
		}
	})
	t.Run("both planes need both key groups", func(t *testing.T) {
		cfg := testConfig()
		cfg.DataPlanes = []DataPlaneKind{DataPlaneMASQUE, DataPlaneWireGuard}
		cfg = cfg.WithDefaults()
		require.NoError(t, cfg.Validate())
		assert.Equal(t, DefaultWireGuardListenPort, cfg.WireGuard.ListenPort)
		cfg.MASQUE.Routes = nil
		assertInvalidField(t, cfg.Validate(), "masque.routes")
	})
}
