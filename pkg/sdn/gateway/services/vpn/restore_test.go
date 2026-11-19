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
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
)

// restoreHarness is a service over a real in-memory IPAM, so Restore's
// address handling runs against the allocator semantics it relies on.
type restoreHarness struct {
	svc   *Service
	clock *fakeClock
	ipam  *backends.MemoryBackend
	pool  *ipam.Pool
	plane *fakePlane
	store *seededStore
}

// seededStore is a memory lease store whose List and Delete can fail.
type seededStore struct {
	*MemoryLeaseStore
	listErr   error
	deleteErr error
}

func (s *seededStore) List(ctx context.Context) ([]*Lease, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.MemoryLeaseStore.List(ctx)
}

func (s *seededStore) Delete(ctx context.Context, id LeaseID) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.MemoryLeaseStore.Delete(ctx, id)
}

func newRestoreHarness(t *testing.T) *restoreHarness {
	t.Helper()
	ctx := context.Background()
	h := &restoreHarness{
		clock: newFakeClock(),
		ipam:  backends.NewMemoryBackend(),
		pool:  &ipam.Pool{ID: "vpn-pool", Name: "vpn-clients", CIDR: netip.MustParsePrefix("100.64.0.0/24")},
		plane: newFakePlane(DataPlaneMASQUE),
		store: &seededStore{MemoryLeaseStore: NewMemoryLeaseStore()},
	}
	require.NoError(t, h.ipam.CreatePool(ctx, h.pool))
	h.svc = h.newService(t)
	return h
}

// newService builds a Service over the harness's IPAM, plane, store and
// clock.
func (h *restoreHarness) newService(t *testing.T) *Service {
	t.Helper()
	return h.newServiceFor(t, testConfig(), h.plane, h.store)
}

// newServiceFor builds a Service over the harness's IPAM pool with its own
// config, plane and lease store: a second gateway sharing the pool.
func (h *restoreHarness) newServiceFor(t *testing.T, cfg Config, plane *fakePlane, store LeaseStore) *Service {
	t.Helper()
	svc, err := New(Deps{
		Identity:   &fakeIdentity{},
		Verifier:   &fakeVerifier{},
		Posture:    &fakePosture{},
		Factors:    &fakeFactors{},
		IPAM:       h.ipam,
		DataPlanes: map[DataPlaneKind]DataPlane{DataPlaneMASQUE: plane},
		Leases:     store,
		Audit:      &fakeAudit{},
		Clock:      h.clock,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, cfg)
	require.NoError(t, err)
	return svc
}

// restart replaces the service with a new one over the same IPAM backend,
// plane, store and clock, as a restarted VPN child would see them, and
// starts it. What the old service held only in memory is gone.
func (h *restoreHarness) restart(t *testing.T) {
	t.Helper()
	h.svc = h.newService(t)
	h.start(t)
}

// allocateVPN holds addr for device the way an admission does: a
// vpn-tagged allocation in the lease pool.
func (h *restoreHarness) allocateVPN(t *testing.T, device string, addr netip.Prefix) {
	t.Helper()
	h.allocateTagged(t, device, addr, "vpn", "tenant:tenant-a", "gateway:gw-a")
}

// allocateTagged allocates addr to device in the lease pool with tags.
func (h *restoreHarness) allocateTagged(t *testing.T, device string, addr netip.Prefix, tags ...string) {
	t.Helper()
	_, err := h.ipam.AllocateSpecific(context.Background(), &ipam.AllocationRequest{
		PoolID: h.pool.ID, DeviceID: device, RequestedIP: addr.Addr(),
		Description: "vpn lease", Tags: tags,
	})
	require.NoError(t, err)
}

// start starts the service and stops it when the test ends.
func (h *restoreHarness) start(t *testing.T) {
	t.Helper()
	svc := h.svc
	require.NoError(t, svc.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, svc.Stop(context.Background())) })
}

// seed records a live lease for device at address.
func (h *restoreHarness) seed(t *testing.T, id LeaseID, device, address string) *Lease {
	t.Helper()
	now := h.clock.Now()
	lease := &Lease{
		ID:        id,
		DeviceID:  device,
		TenantID:  "tenant-a",
		Address:   netip.MustParsePrefix(address),
		Zones:     []string{"management"},
		DataPlane: DataPlaneMASQUE,
		Keys:      PeerKeys{ClientCertificateSHA256: make([]byte, 32)},
		IssuedAt:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
		Verdict:   VerdictSummary{Passed: true, Cryptographic: true, ProfileID: 7},
	}
	require.NoError(t, h.store.Put(context.Background(), lease))
	return lease
}

// holder is the device holding addr in the IPAM, or "" when none does.
func (h *restoreHarness) holder(t *testing.T, addr netip.Prefix) string {
	t.Helper()
	alloc, err := h.ipam.GetAllocation(context.Background(), addr.Addr())
	if errors.Is(err, ipam.ErrAllocationNotFound) {
		return ""
	}
	require.NoError(t, err)
	if alloc.Status != ipam.AllocationStatusActive {
		return ""
	}
	return alloc.DeviceID
}

func (h *restoreHarness) allocate(t *testing.T, device string, addr netip.Prefix) {
	t.Helper()
	_, err := h.ipam.AllocateSpecific(context.Background(), &ipam.AllocationRequest{
		PoolID: h.pool.ID, DeviceID: device, RequestedIP: addr.Addr(),
	})
	require.NoError(t, err)
}

func TestRestore_ReinstatesRecordedLeases(t *testing.T) {
	h := newRestoreHarness(t)
	first := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	second := h.seed(t, "lease-2", "mini-2", "100.64.0.3/32")
	// A persistent IPAM may still hold the address for the device: Restore
	// keeps that allocation rather than tripping over it.
	h.allocate(t, "mini-2", second.Address)
	h.start(t)

	require.NoError(t, h.svc.Restore(context.Background()))

	assert.Equal(t, 2, h.plane.count(), "both peers are back in the data plane")
	assert.Equal(t, "mini-1", h.holder(t, first.Address))
	assert.Equal(t, "mini-2", h.holder(t, second.Address))
	stored, err := h.store.Get(context.Background(), first.ID)
	require.NoError(t, err)
	assert.Equal(t, first.Keys, stored.Keys, "the restored lease keeps its peer keys")
}

// TestRestore_RemovesAHostedPeerWhoseLeaseIsGone covers a vpn child that
// dies after a revoke deleted the lease record but before it removed the
// peer: the datapath's plane outlives the child and still hosts the peer.
// The replacement child's Restore reconciles the plane's peers against the
// stored leases, so the revoked key stops passing traffic.
func TestRestore_RemovesAHostedPeerWhoseLeaseIsGone(t *testing.T) {
	h := newRestoreHarness(t)
	kept := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.plane.installed[kept.ID] = kept
	h.plane.installed["lease-revoked"] = &Lease{ID: "lease-revoked", DataPlane: DataPlaneMASQUE}
	h.start(t)

	require.NoError(t, h.svc.Restore(context.Background()))

	h.plane.mu.Lock()
	defer h.plane.mu.Unlock()
	assert.NotContains(t, h.plane.installed, LeaseID("lease-revoked"), "the revoked lease's peer is removed")
	assert.Contains(t, h.plane.installed, kept.ID, "the stored lease's peer stays")
}

// TestReconcileHostedPeers_AnEmptyStoreWithdrawsEveryHostedPeer pins the
// memory-only restart: a replacement child whose store is empty withdraws
// every peer its predecessor left in the surviving hosted planes.
func TestReconcileHostedPeers_AnEmptyStoreWithdrawsEveryHostedPeer(t *testing.T) {
	h := newRestoreHarness(t)
	h.plane.installed["lease-orphan"] = &Lease{ID: "lease-orphan", DataPlane: DataPlaneMASQUE}
	h.start(t)

	require.NoError(t, h.svc.ReconcileHostedPeers(context.Background()))

	h.plane.mu.Lock()
	defer h.plane.mu.Unlock()
	assert.NotContains(t, h.plane.installed, LeaseID("lease-orphan"), "the orphaned peer is withdrawn")
}

func TestReconcileHostedPeers_RefusesBeforeStart(t *testing.T) {
	h := newRestoreHarness(t)
	var notStarted *ErrNotStarted
	assert.True(t, errors.As(h.svc.ReconcileHostedPeers(context.Background()), &notStarted))
}

func TestRestore_DropsLeasesItCannotReinstate(t *testing.T) {
	cases := map[string]struct {
		prepare func(*testing.T, *restoreHarness, *Lease)
		reason  string
	}{
		"expired": {func(t *testing.T, h *restoreHarness, l *Lease) {
			l.ExpiresAt = h.clock.Now()
			require.NoError(t, h.store.Put(context.Background(), l))
		}, "expired"},
		"data plane not offered": {func(t *testing.T, h *restoreHarness, l *Lease) {
			l.DataPlane = DataPlaneKind("carrier-pigeon")
			require.NoError(t, h.store.Put(context.Background(), l))
		}, "data plane not offered"},
		"zone withdrawn from the gateway": {func(t *testing.T, h *restoreHarness, l *Lease) {
			l.Zones = []string{"fabric"}
			require.NoError(t, h.store.Put(context.Background(), l))
		}, "zones not allowed"},
		"address taken by another device": {func(t *testing.T, h *restoreHarness, l *Lease) {
			h.allocate(t, "mini-other", l.Address)
		}, "address unavailable"},
		"data plane refuses the peer": {func(t *testing.T, h *restoreHarness, _ *Lease) {
			h.plane.installErr = errors.New("netlink: operation not permitted")
		}, "data plane refused the peer"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			requireRestoreDrops(t, c.prepare, c.reason)
		})
	}
}

// requireRestoreDrops seeds one lease, lets prepare make it unrestorable,
// and asserts Restore drops it for reason: no peer, no stored lease, no
// address held.
func requireRestoreDrops(t *testing.T, prepare func(*testing.T, *restoreHarness, *Lease), reason string) {
	t.Helper()
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	prepare(t, h, lease)
	h.start(t)

	err := h.svc.Restore(context.Background())

	var dropped *ErrLeaseNotRestored
	require.True(t, errors.As(err, &dropped), "got %v", err)
	assert.Equal(t, lease.ID, dropped.LeaseID)
	assert.Equal(t, reason, dropped.Reason)
	assert.Zero(t, h.plane.count(), "a dropped lease has no peer")
	_, err = h.store.Get(context.Background(), lease.ID)
	var nf *ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf), "a dropped lease leaves the store, got %v", err)
	assert.NotEqual(t, "mini-1", h.holder(t, lease.Address), "a dropped lease holds no address")
}

// A datapath that survived the vpn child's restart still hosts the peer of
// a recorded lease Restore now rejects: the peer is removed with the lease.
func TestRestore_RemovesTheHostedPeerOfALeaseItRejects(t *testing.T) {
	cases := map[string]func(*testing.T, *restoreHarness, *Lease){
		"expired": func(t *testing.T, h *restoreHarness, l *Lease) {
			l.ExpiresAt = h.clock.Now()
			require.NoError(t, h.store.Put(context.Background(), l))
		},
		"zone withdrawn from the gateway": func(t *testing.T, h *restoreHarness, l *Lease) {
			l.Zones = []string{"fabric"}
			require.NoError(t, h.store.Put(context.Background(), l))
		},
		"address taken by another device": func(t *testing.T, h *restoreHarness, l *Lease) {
			h.allocate(t, "mini-other", l.Address)
		},
	}
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRestoreHarness(t)
			lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
			prepare(t, h, lease)
			h.plane.installed[lease.ID] = lease
			h.start(t)

			err := h.svc.Restore(context.Background())

			var dropped *ErrLeaseNotRestored
			require.True(t, errors.As(err, &dropped), "got %v", err)
			assert.False(t, h.plane.hosts(lease.ID), "the rejected lease's hosted peer is removed")
		})
	}
}

// A revoked lease's peer the datapath could not remove at Restore stays an
// obligation: Sweep retries the reconciliation until it succeeds.
func TestRestore_AFailedPeerReconciliationIsRetried(t *testing.T) {
	h := newRestoreHarness(t)
	h.plane.installed["lease-revoked"] = &Lease{ID: "lease-revoked", DataPlane: DataPlaneMASQUE}
	h.plane.failRemovals(errors.New("datapath unreachable"))
	h.start(t)

	err := h.svc.Restore(context.Background())
	var unavailable *ErrDataPlaneUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	require.True(t, h.plane.hosts("lease-revoked"))

	h.svc.Sweep(context.Background())
	require.True(t, h.plane.hosts("lease-revoked"), "the datapath is still unreachable")

	h.plane.failRemovals(nil)
	h.svc.Sweep(context.Background())
	assert.False(t, h.plane.hosts("lease-revoked"), "the retried reconciliation removes the revoked peer")
}

// A rejected lease whose hosted peer the datapath could not remove keeps
// its address until a retried removal succeeds.
func TestRestore_AFailedRejectedPeerRemovalIsRetried(t *testing.T) {
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	lease.Zones = []string{"fabric"}
	require.NoError(t, h.store.Put(context.Background(), lease))
	h.plane.installed[lease.ID] = lease
	// The persistent IPAM still holds the address for the device.
	h.allocate(t, "mini-1", lease.Address)
	h.start(t)
	h.plane.failRemovals(errors.New("datapath unreachable"))

	err := h.svc.Restore(context.Background())
	var dropped *ErrLeaseNotRestored
	require.True(t, errors.As(err, &dropped), "got %v", err)
	require.True(t, h.plane.hosts(lease.ID))
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "the address stays held while the peer may route it")

	h.plane.failRemovals(nil)
	h.svc.Sweep(context.Background())
	assert.False(t, h.plane.hosts(lease.ID), "the retried removal takes the peer down")
	assert.NotEqual(t, "mini-1", h.holder(t, lease.Address), "then the address is released")
}

// A rejected lease whose record the store could not delete is still listed
// when the reconciliation is retried: the retry must not keep its peer.
func TestRestore_ARetriedReconciliationRemovesARejectedLeaseStillStored(t *testing.T) {
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	lease.Zones = []string{"fabric"}
	require.NoError(t, h.store.Put(context.Background(), lease))
	h.plane.installed[lease.ID] = lease
	h.allocate(t, "mini-1", lease.Address)
	h.store.deleteErr = errors.New("control plane unreachable")
	h.start(t)
	h.plane.failRemovals(errors.New("datapath unreachable"))

	err := h.svc.Restore(context.Background())
	var dropped *ErrLeaseNotRestored
	require.True(t, errors.As(err, &dropped), "got %v", err)
	require.True(t, h.plane.hosts(lease.ID))
	stored, err := h.store.List(context.Background())
	require.NoError(t, err)
	require.Len(t, stored, 1, "the rejected lease's record is still stored")

	h.plane.failRemovals(nil)
	h.svc.Sweep(context.Background())
	assert.False(t, h.plane.hosts(lease.ID), "the retried reconciliation takes the rejected lease's peer down")
}

func TestRestore_LeavesAnotherDevicesAddressAlone(t *testing.T) {
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.allocate(t, "mini-other", lease.Address)
	h.start(t)

	require.Error(t, h.svc.Restore(context.Background()))
	assert.Equal(t, "mini-other", h.holder(t, lease.Address), "dropping a lease must not free an address it never held")
}

func TestRestore_LeavesAnUntaggedAllocationAlone(t *testing.T) {
	// Only a vpn-tagged allocation records a VPN address; another holder
	// of the pool keeps its address with no lease.
	h := newRestoreHarness(t)
	addr := netip.MustParsePrefix("100.64.0.9/32")
	h.allocate(t, "mini-other", addr)
	h.start(t)

	require.NoError(t, h.svc.Restore(context.Background()))
	assert.Equal(t, "mini-other", h.holder(t, addr), "an untagged allocation is not a VPN lease's address")
}

func TestRestore_ASweepReclaimsTheAddressAfterAFailedRestoreReconcile(t *testing.T) {
	// An expired lease whose peer removal failed is deleted from the
	// store and its address kept until the retry removes the peer. A
	// restart forgets that retry, and the replacement's first
	// reconciliation fails too: the reclaim is still owed, and the Sweep
	// that recovers the reconciliation pays it.
	ctx := context.Background()
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.allocateVPN(t, "mini-1", lease.Address)
	h.start(t)
	require.NoError(t, h.svc.Restore(ctx))

	h.forgetAFailedRemoval(t, lease)

	h.restart(t)
	var unavailable *ErrDataPlaneUnavailable
	require.ErrorAs(t, h.svc.Restore(ctx), &unavailable)
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "an orphan peer still installed keeps its address")

	h.plane.failRemovals(nil)
	h.svc.Sweep(ctx)
	assert.False(t, h.plane.hosts(lease.ID), "the orphan peer is removed")
	assert.Equal(t, "", h.holder(t, lease.Address), "and its forgotten address reclaimed")
}

// forgetAFailedRemoval expires lease with peer removals failing: the lease
// is deleted, its peer stays installed and its address is kept.
func (h *restoreHarness) forgetAFailedRemoval(t *testing.T, lease *Lease) {
	t.Helper()
	ctx := context.Background()
	h.plane.failRemovals(errors.New("datapath unreachable"))
	h.clock.Advance(2 * time.Hour)
	h.svc.Sweep(ctx)

	stored, err := h.store.List(ctx)
	require.NoError(t, err)
	require.Empty(t, stored, "the expired lease is deleted")
	require.True(t, h.plane.hosts(lease.ID), "its peer removal failed")
	require.Equal(t, "mini-1", h.holder(t, lease.Address), "so its address is kept")
}

func TestRestore_ReclaimSkipsAnAddressAnOwedRemovalStillHolds(t *testing.T) {
	ctx := context.Background()
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.allocateVPN(t, "mini-1", lease.Address)
	h.start(t)
	require.NoError(t, h.svc.Restore(ctx))

	h.forgetAFailedRemoval(t, lease)

	require.NoError(t, h.svc.reclaimOrphanAddresses(ctx))
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "an owed peer removal still holds its address")
}

// revokeInFlight starts a revocation of lease and returns once the
// revocation has deleted the lease and is held in RemovePeer, with the
// channel its result arrives on.
func (h *restoreHarness) revokeInFlight(t *testing.T, lease *Lease) (*pause, <-chan error) {
	t.Helper()
	ctx := context.Background()
	p := newPause()
	h.plane.mu.Lock()
	h.plane.removePause = p
	h.plane.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- h.svc.Revoke(ctx, lease.ID, RevokeClient) }()
	select {
	case <-p.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("Revoke never reached RemovePeer")
	}
	h.plane.mu.Lock()
	h.plane.removePause = nil
	h.plane.mu.Unlock()
	stored, err := h.store.List(ctx)
	require.NoError(t, err)
	require.Empty(t, stored, "the lease is deleted before its peer removal")
	return p, done
}

func TestReclaimOrphans_RevokeInFlightKeepsAddress(t *testing.T) {
	ctx := context.Background()
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.allocateVPN(t, "mini-1", lease.Address)
	h.start(t)
	require.NoError(t, h.svc.Restore(ctx))

	p, done := h.revokeInFlight(t, lease)
	require.NoError(t, h.svc.reclaimOrphanAddresses(ctx))
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "a revocation in flight still holds its address")

	close(p.release)
	require.NoError(t, <-done)
	assert.Empty(t, h.holder(t, lease.Address), "the settled revocation releases its address")

	// The address goes to a replacement; neither a late release nor a
	// reclaim may take it from it.
	h.allocateVPN(t, "mini-2", lease.Address)
	h.seed(t, "lease-2", "mini-2", "100.64.0.2/32")
	require.NoError(t, h.svc.reclaimOrphanAddresses(ctx))
	assert.Equal(t, "mini-2", h.holder(t, lease.Address), "the address was released exactly once")
}

func TestReclaimOrphans_RevokeInFlightFailedRemovalKeepsAddress(t *testing.T) {
	ctx := context.Background()
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.allocateVPN(t, "mini-1", lease.Address)
	h.start(t)
	require.NoError(t, h.svc.Restore(ctx))

	p, done := h.revokeInFlight(t, lease)
	h.plane.failRemovals(errors.New("datapath unreachable"))
	require.NoError(t, h.svc.reclaimOrphanAddresses(ctx))
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "a revocation in flight still holds its address")

	close(p.release)
	require.Error(t, <-done, "the peer removal failed")
	require.True(t, h.plane.hosts(lease.ID), "the revoked peer is still installed")
	require.NoError(t, h.svc.reclaimOrphanAddresses(ctx))
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "the owed removal holds the address through peerRetry")
}

func TestRestore_ReclaimLeavesAnotherGatewaysAllocationAlone(t *testing.T) {
	ctx := context.Background()
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.allocateVPN(t, "mini-1", lease.Address)

	cfgB := testConfig()
	cfgB.GatewayID = "gw-b"
	gwB := h.newServiceFor(t, cfgB, newFakePlane(DataPlaneMASQUE), NewMemoryLeaseStore())
	require.NoError(t, gwB.Start(ctx))
	t.Cleanup(func() { require.NoError(t, gwB.Stop(context.Background())) })
	other := netip.MustParsePrefix("100.64.0.3/32")
	h.allocateTagged(t, "mini-b", other, "vpn", "tenant:tenant-a", gwB.ownerTag())

	h.start(t)
	require.NoError(t, h.svc.Restore(ctx))
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "this gateway's leased address is kept")
	assert.Equal(t, "mini-b", h.holder(t, other), "another gateway's live allocation in the shared pool is not reclaimed")
}

func TestRestore_ReclaimLeavesAnUnownedVPNAllocationAlone(t *testing.T) {
	ctx := context.Background()
	h := newRestoreHarness(t)
	legacy := netip.MustParsePrefix("100.64.0.4/32")
	h.allocateTagged(t, "mini-legacy", legacy, "vpn", "tenant:tenant-a")
	h.start(t)

	require.NoError(t, h.svc.Restore(ctx))
	assert.Equal(t, "mini-legacy", h.holder(t, legacy), "an allocation with no owner tag is never reclaimed")
}

func TestRestore_ReportsADropTheStoreCouldNotRecord(t *testing.T) {
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	lease.ExpiresAt = h.clock.Now()
	require.NoError(t, h.store.Put(context.Background(), lease))
	storeDown := errors.New("control plane unreachable")
	h.store.deleteErr = storeDown
	h.start(t)

	err := h.svc.Restore(context.Background())

	var dropped *ErrLeaseNotRestored
	assert.True(t, errors.As(err, &dropped), "got %v", err)
	assert.ErrorIs(t, err, storeDown, "the failed delete is reported with the drop")
}

func TestRestore_ADropRecordedNowhereKeepsTheAddress(t *testing.T) {
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	lease.ExpiresAt = h.clock.Now()
	require.NoError(t, h.store.Put(context.Background(), lease))
	h.allocate(t, "mini-1", lease.Address)
	h.store.deleteErr = &ErrRevocationNotRecorded{LeaseID: lease.ID, Cause: errors.New("disk full")}
	h.start(t)

	err := h.svc.Restore(context.Background())

	var unrecorded *ErrRevocationNotRecorded
	require.True(t, errors.As(err, &unrecorded), "got %v", err)
	alloc, err := h.ipam.GetAllocation(context.Background(), lease.Address.Addr())
	require.NoError(t, err)
	assert.Equal(t, ipam.AllocationStatusActive, alloc.Status, "the kept lease keeps its address")
	assert.Equal(t, "mini-1", alloc.DeviceID)
}

// An expired lease is dead whether or not its deletion was recorded, and a
// later restart drops it again before anything else: its hosted peer goes
// at once, while the kept record keeps its address until the deletion is
// recorded.
func TestRestore_AnUnrecordedExpiredDropRemovesTheHostedPeer(t *testing.T) {
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	lease.ExpiresAt = h.clock.Now()
	require.NoError(t, h.store.Put(context.Background(), lease))
	h.plane.installed[lease.ID] = lease
	h.allocate(t, "mini-1", lease.Address)
	h.store.deleteErr = &ErrRevocationNotRecorded{LeaseID: lease.ID, Cause: errors.New("disk full")}
	h.start(t)

	err := h.svc.Restore(context.Background())

	var unrecorded *ErrRevocationNotRecorded
	require.True(t, errors.As(err, &unrecorded), "got %v", err)
	assert.False(t, h.plane.hosts(lease.ID), "the expired lease's hosted peer is removed")
	stored, err := h.store.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, stored, 1, "the lease whose drop was not recorded is still stored")
	alloc, err := h.ipam.GetAllocation(context.Background(), lease.Address.Addr())
	require.NoError(t, err)
	assert.Equal(t, ipam.AllocationStatusActive, alloc.Status, "the kept record keeps its address")
	assert.Equal(t, "mini-1", alloc.DeviceID)
}

// A lease that expires while the store cannot record its deletion loses its
// peer at the first Sweep; its address stays held until a later Sweep
// records the deletion, and only then goes back to the pool.
func TestSweep_AnUnrecordedExpiryRemovesThePeerAndKeepsTheAddress(t *testing.T) {
	ctx := context.Background()
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.allocate(t, "mini-1", lease.Address)
	h.start(t)
	require.NoError(t, h.svc.Restore(ctx))
	require.True(t, h.plane.hosts(lease.ID))
	h.store.deleteErr = &ErrRevocationNotRecorded{LeaseID: lease.ID, Cause: errors.New("disk full")}
	h.clock.Advance(2 * time.Hour)

	h.svc.Sweep(ctx)

	assert.False(t, h.plane.hosts(lease.ID), "the expired lease's peer is removed")
	alloc, err := h.ipam.GetAllocation(ctx, lease.Address.Addr())
	require.NoError(t, err)
	assert.Equal(t, ipam.AllocationStatusActive, alloc.Status, "the kept record keeps its address")

	h.store.deleteErr = nil
	h.svc.Sweep(ctx)

	stored, err := h.store.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, stored, "the recorded deletion removes the lease")
	assert.NotEqual(t, "mini-1", h.holder(t, lease.Address), "then the address is released")
}

func TestRevoke_ARevocationRecordedNowhereTearsNothingDown(t *testing.T) {
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.start(t)
	require.NoError(t, h.svc.Restore(context.Background()))
	h.store.deleteErr = &ErrRevocationNotRecorded{LeaseID: lease.ID, Cause: errors.New("disk full")}

	err := h.svc.Revoke(context.Background(), lease.ID, RevokeOperator)

	var unrecorded *ErrRevocationNotRecorded
	require.True(t, errors.As(err, &unrecorded), "got %v", err)
	assert.Empty(t, h.plane.removed, "the peer stays with the kept lease")
	alloc, err := h.ipam.GetAllocation(context.Background(), lease.Address.Addr())
	require.NoError(t, err)
	assert.Equal(t, ipam.AllocationStatusActive, alloc.Status, "the address stays with the kept lease")
}

func TestErrRevocationNotRecorded_Message(t *testing.T) {
	cause := errors.New("disk full")
	err := &ErrRevocationNotRecorded{LeaseID: "lease-1", Cause: cause}
	assert.Equal(t, "vpn: revocation of lease lease-1 not recorded: disk full", err.Error())
	assert.ErrorIs(t, err, cause)
}

func TestRestore_Refusals(t *testing.T) {
	t.Run("not started", func(t *testing.T) {
		h := newRestoreHarness(t)
		var notStarted *ErrNotStarted
		assert.True(t, errors.As(h.svc.Restore(context.Background()), &notStarted))
	})
	t.Run("lease store unreadable", func(t *testing.T) {
		h := newRestoreHarness(t)
		h.store.listErr = errors.New("disk gone")
		h.start(t)
		var unavailable *ErrLeaseStoreUnavailable
		assert.True(t, errors.As(h.svc.Restore(context.Background()), &unavailable))
	})
}

func TestErrLeaseNotRestored_Message(t *testing.T) {
	cause := errors.New("pool gone")
	withCause := &ErrLeaseNotRestored{LeaseID: "lease-1", Reason: "address unavailable", Cause: cause}
	assert.Equal(t, "vpn: lease lease-1 not restored: address unavailable: pool gone", withCause.Error())
	assert.ErrorIs(t, withCause, cause)
	bare := &ErrLeaseNotRestored{LeaseID: "lease-1", Reason: "expired"}
	assert.Equal(t, "vpn: lease lease-1 not restored: expired", bare.Error())
	assert.NoError(t, bare.Unwrap())
}
