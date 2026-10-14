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
	"net/http"
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

// TestWireGuardPlaneIsAbsentUnderFIPS is the non-FIPS half of the pair: the
// plane constructor exists here. The fips twin asserts the kind is not even
// Known there.
func TestWireGuardPlaneExistsOutsideFIPS(t *testing.T) {
	plane, err := NewWireGuardPlane(newFakeHub(), nil)
	require.NoError(t, err)
	assert.Equal(t, DataPlaneWireGuard, plane.Kind())
}

// TestWireGuardPlane_BadKeyIsAnInvalidRequest: the plane's refusal of a
// malformed client key reaches the caller as an invalid request, not as an
// unavailable data plane.
func TestWireGuardPlane_BadKeyIsAnInvalidRequest(t *testing.T) {
	plane, _ := newWireGuardPlaneForTest(t)
	err := plane.InstallPeer(context.Background(), wgLease("l1", "10.9.0.23/32", []byte("short")))

	refusal, status := RefusalOf(err)
	assert.Equal(t, RefusalInvalidRequest, refusal.Reason)
	assert.Equal(t, http.StatusBadRequest, status)
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
