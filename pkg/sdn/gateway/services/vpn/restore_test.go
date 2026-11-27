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
	"sync"
	"sync/atomic"
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

	// Reclaim started during the revocation runs after it, so it never
	// sees the address between the lease deletion and its release.
	p, done := h.revokeInFlight(t, lease)
	require.NoError(t, h.reclaimAfterRevoke(t, p, done))
	assert.Empty(t, h.holder(t, lease.Address), "the settled revocation releases its address")

	// The address goes to a replacement; neither a late release nor a
	// reclaim may take it from it.
	h.allocateVPN(t, "mini-2", lease.Address)
	h.seed(t, "lease-2", "mini-2", "100.64.0.2/32")
	require.NoError(t, h.svc.reclaimOrphanAddresses(ctx))
	assert.Equal(t, "mini-2", h.holder(t, lease.Address), "the address was released exactly once")
}

// pausingAllocator is the shared pool seen through one gateway: once
// armed, its next GetAllocationsByPool returns its snapshot and then
// blocks until resume is closed, and it records every Release of watch
// made after the address was reassigned.
type pausingAllocator struct {
	ipam.Allocator
	armed      atomic.Bool
	paused     chan struct{}
	resume     chan struct{}
	once       sync.Once
	watch      netip.Addr
	reassigned atomic.Bool
	mu         sync.Mutex
	stolen     int
}

func (p *pausingAllocator) GetAllocationsByPool(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	allocs, err := p.Allocator.GetAllocationsByPool(ctx, poolID)
	if p.armed.Load() {
		p.once.Do(func() {
			close(p.paused)
			<-p.resume
		})
	}
	return allocs, err
}

func (p *pausingAllocator) Release(ctx context.Context, ip netip.Addr) error {
	if ip == p.watch && p.reassigned.Load() {
		p.mu.Lock()
		p.stolen++
		p.mu.Unlock()
	}
	return p.Allocator.Release(ctx, ip)
}

func TestService_OrphanReclaimNeverReleasesAReassignedAddress(t *testing.T) {
	ctx := context.Background()
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.allocateVPN(t, "mini-1", lease.Address)
	shared := &pausingAllocator{
		Allocator: h.ipam,
		paused:    make(chan struct{}),
		resume:    make(chan struct{}),
		watch:     lease.Address.Addr(),
	}
	svc, err := New(Deps{
		Identity:   &fakeIdentity{},
		Verifier:   &fakeVerifier{},
		Posture:    &fakePosture{},
		Factors:    &fakeFactors{},
		IPAM:       shared,
		DataPlanes: map[DataPlaneKind]DataPlane{DataPlaneMASQUE: h.plane},
		Leases:     h.store,
		Audit:      &fakeAudit{},
		Clock:      h.clock,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, testConfig())
	require.NoError(t, err)
	h.svc = svc
	h.start(t)
	require.NoError(t, h.svc.Restore(ctx))
	require.Equal(t, "mini-1", h.holder(t, lease.Address))

	// A revocation is in flight: its lease is deleted and its peer
	// removal is paused.
	p, revoked := h.revokeInFlight(t, lease)

	// Reclaim starts now. It waits behind the revocation (the two are
	// serialized by enrolGate), so it must not reach GetAllocationsByPool
	// until the revocation has finished; there it pauses after taking its
	// snapshot.
	shared.armed.Store(true)
	reclaimed := make(chan error, 1)
	go func() { reclaimed <- h.svc.reclaimOrphanAddresses(ctx) }()
	select {
	case <-shared.paused:
		assert.Fail(t, "reclaim took its snapshot while a revocation was in flight")
	case <-time.After(200 * time.Millisecond):
	}

	// The revocation settles and releases the address.
	close(p.release)
	select {
	case err := <-revoked:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("revocation never finished")
	}
	select {
	case <-shared.paused:
	case <-time.After(10 * time.Second):
		t.Fatal("reclaim never reached GetAllocationsByPool")
	}

	// While reclaim is paused, another gateway on the shared pool takes
	// the freed address with the same tags.
	h.allocateVPN(t, "mini-b", lease.Address)
	shared.reassigned.Store(true)

	close(shared.resume)
	select {
	case err := <-reclaimed:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("reclaim never finished")
	}

	shared.mu.Lock()
	stolen := shared.stolen
	shared.mu.Unlock()
	assert.Zero(t, stolen, "reclaim never releases the reassigned allocation")
	assert.Equal(t, "mini-b", h.holder(t, lease.Address), "the other gateway's allocation is still active")
}

func TestReclaimOrphans_RevokeInFlightFailedRemovalKeepsAddress(t *testing.T) {
	ctx := context.Background()
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.allocateVPN(t, "mini-1", lease.Address)
	h.start(t)
	require.NoError(t, h.svc.Restore(ctx))

	// Reclaim started during the revocation runs after it: the failed
	// removal is owed through peerRetry by then and holds the address.
	p, done := h.revokeInFlight(t, lease)
	h.plane.failRemovals(errors.New("datapath unreachable"))
	require.Error(t, h.reclaimAfterRevoke(t, p, done), "the peer removal failed")
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "a reclaim behind the revocation keeps its address")
	require.True(t, h.plane.hosts(lease.ID), "the revoked peer is still installed")

	require.NoError(t, h.svc.reclaimOrphanAddresses(ctx))
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "the owed removal holds the address through peerRetry")
}

// lostReleaseAllocator commits a Release and, when armed, loses its
// response: the caller sees an error although the address was freed.
type lostReleaseAllocator struct {
	ipam.Allocator
	lose atomic.Bool
}

func (a *lostReleaseAllocator) Release(ctx context.Context, ip netip.Addr) error {
	if err := a.Allocator.Release(ctx, ip); err != nil {
		return err
	}
	if a.lose.CompareAndSwap(true, false) {
		return errors.New("response lost")
	}
	return nil
}

func TestRetry_ALostReleaseResponseNeverFreesAReadmittedLease(t *testing.T) {
	ctx := context.Background()
	h := newRestoreHarness(t)
	lossy := &lostReleaseAllocator{Allocator: h.ipam}
	svc, err := New(Deps{
		Identity:   &fakeIdentity{},
		Verifier:   &fakeVerifier{},
		Posture:    &fakePosture{},
		Factors:    &fakeFactors{},
		IPAM:       lossy,
		DataPlanes: map[DataPlaneKind]DataPlane{DataPlaneMASQUE: h.plane},
		Leases:     h.store,
		Audit:      &fakeAudit{},
		Clock:      h.clock,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, testConfig())
	require.NoError(t, err)
	h.svc = svc

	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	lease.Zones = []string{"fabric"}
	require.NoError(t, h.store.Put(ctx, lease))
	h.plane.installed[lease.ID] = lease
	h.allocate(t, "mini-1", lease.Address)
	h.start(t)
	h.plane.failRemovals(errors.New("datapath unreachable"))
	err = h.svc.Restore(ctx)
	var dropped *ErrLeaseNotRestored
	require.True(t, errors.As(err, &dropped), "got %v", err)

	// The retried removal succeeds; the release commits but its response
	// is lost, so lease-1 is owed again.
	h.plane.failRemovals(nil)
	lossy.lose.Store(true)
	h.svc.Sweep(ctx)
	require.False(t, h.plane.hosts(lease.ID))
	require.Equal(t, "", h.holder(t, lease.Address), "the release committed")

	// The same device is readmitted at the freed address.
	h.allocate(t, "mini-1", lease.Address)
	lease2 := h.seed(t, "lease-2", "mini-1", lease.Address.String())
	h.plane.mu.Lock()
	h.plane.installed[lease2.ID] = lease2
	h.plane.mu.Unlock()

	h.svc.Sweep(ctx)
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "the owed cleanup never frees the readmitted lease's address")
	assert.True(t, h.plane.hosts("lease-2"))

	h.svc.Sweep(ctx)
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "the obligation was dropped, not owed again")
	assert.True(t, h.plane.hosts("lease-2"))
}

// A lost release response leaves the release owed; if the device is then
// readmitted at the freed address through another gateway sharing the pool,
// this gateway's store cannot see that lease, and the retried release must
// not free the other gateway's live allocation.
func TestRetry_ALostReleaseResponseNeverFreesAnotherGatewaysReadmission(t *testing.T) {
	ctx := context.Background()
	h := newRestoreHarness(t)
	lossy := &lostReleaseAllocator{Allocator: h.ipam}
	svc, err := New(Deps{
		Identity:   &fakeIdentity{},
		Verifier:   &fakeVerifier{},
		Posture:    &fakePosture{},
		Factors:    &fakeFactors{},
		IPAM:       lossy,
		DataPlanes: map[DataPlaneKind]DataPlane{DataPlaneMASQUE: h.plane},
		Leases:     h.store,
		Audit:      &fakeAudit{},
		Clock:      h.clock,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, testConfig())
	require.NoError(t, err)
	h.svc = svc

	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	lease.Zones = []string{"fabric"}
	require.NoError(t, h.store.Put(ctx, lease))
	h.plane.installed[lease.ID] = lease
	h.allocateVPN(t, "mini-1", lease.Address)
	h.start(t)
	h.plane.failRemovals(errors.New("datapath unreachable"))
	err = h.svc.Restore(ctx)
	var dropped *ErrLeaseNotRestored
	require.True(t, errors.As(err, &dropped), "got %v", err)

	// The retried removal succeeds; the release commits but its response
	// is lost, so lease-1 is owed again.
	h.plane.failRemovals(nil)
	lossy.lose.Store(true)
	h.svc.Sweep(ctx)
	require.False(t, h.plane.hosts(lease.ID))
	require.Equal(t, "", h.holder(t, lease.Address), "the release committed")

	// gw-b readmits the same device at the freed address; gw-a's store
	// holds no lease for it.
	h.allocateTagged(t, "mini-1", lease.Address, "vpn", "tenant:tenant-a", "gateway:gw-b")

	h.svc.Sweep(ctx)
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "the owed release never frees gw-b's allocation")
	alloc, err := h.ipam.GetAllocation(ctx, lease.Address.Addr())
	require.NoError(t, err)
	assert.Contains(t, alloc.Tags, "gateway:gw-b")

	h.svc.Sweep(ctx)
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "the obligation was dropped, not owed again")
}

func TestRetry_ReclaimDuringAWaitingRetryKeepsTheOwedAddress(t *testing.T) {
	ctx := context.Background()
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.allocateVPN(t, "mini-1", lease.Address)
	h.start(t)
	require.NoError(t, h.svc.Restore(ctx))
	h.forgetAFailedRemoval(t, lease)

	// A retry waits for the gate while another holder of it reclaims.
	h.svc.enrolGate.RLock()
	done := make(chan struct{})
	go func() {
		h.svc.retryPeerReconcile(ctx)
		close(done)
	}()
	<-time.After(200 * time.Millisecond)
	err := h.svc.reclaimOrphanAddressesLocked(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "a waiting retry still owes the peer removal")
	assert.True(t, h.plane.hosts(lease.ID))
	h.svc.enrolGate.RUnlock()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry never finished")
	}
	assert.Equal(t, "mini-1", h.holder(t, lease.Address), "the retry failed again, so the obligation is kept")
}

func TestSweep_AnOverlappingSweepNeverReclaimsAnAddressWhosePeerRemovalIsPending(t *testing.T) {
	// After a restart whose reconciliation failed, the reclaim is owed and
	// a reconciliation pending. Sweep A is parked just before it takes the
	// enrolment gate; an overlapping Sweep B (Sweep is exported and can
	// overlap sweepLoop) runs to the end meanwhile. No address may be
	// reclaimed while the orphan peer that holds it is still installed: A
	// must not have detached the pending reconciliation where B cannot see
	// it (#2029 Codex).
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
	h.plane.failRemovals(nil)

	parked := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	h.svc.sweepGateHook = func() {
		first := false
		once.Do(func() { first = true })
		if first {
			close(parked)
			<-release
		}
	}
	sweepA := make(chan struct{})
	go func() {
		h.svc.Sweep(ctx)
		close(sweepA)
	}()
	select {
	case <-parked:
	case <-time.After(10 * time.Second):
		t.Fatal("sweep A never reached the enrolment gate")
	}

	h.svc.Sweep(ctx)
	if h.holder(t, lease.Address) == "" {
		assert.False(t, h.plane.hosts(lease.ID), "an address was reclaimed while its orphan peer is still installed")
	}

	close(release)
	select {
	case <-sweepA:
	case <-time.After(10 * time.Second):
		t.Fatal("sweep A never finished")
	}
	assert.False(t, h.plane.hosts(lease.ID), "the orphan peer is removed")
	assert.Equal(t, "", h.holder(t, lease.Address), "and its address reclaimed")
}

// reclaimAfterRevoke starts orphan reclaim while the revocation paused at
// p is in flight, checks that reclaim waits behind it (the two are
// serialized by enrolGate), lets the revocation finish and waits for
// reclaim. It returns the revocation's error.
func (h *restoreHarness) reclaimAfterRevoke(t *testing.T, p *pause, revoked <-chan error) error {
	t.Helper()
	reclaimed := make(chan error, 1)
	go func() { reclaimed <- h.svc.reclaimOrphanAddresses(context.Background()) }()
	select {
	case err := <-reclaimed:
		close(p.release)
		<-revoked
		t.Fatalf("reclaim returned (%v) while a revocation was in flight", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(p.release)
	var revokeErr error
	select {
	case revokeErr = <-revoked:
	case <-time.After(10 * time.Second):
		t.Fatal("revocation never finished")
	}
	select {
	case err := <-reclaimed:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("reclaim never finished after the revocation")
	}
	return revokeErr
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

// restartWith replaces svc with a new Service over the same deps, as a
// restarted VPN child would see them, starts it and runs Restore. What
// the old service held only in memory is gone.
func restartWith(t *testing.T, h *harness, deps Deps) error {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, h.svc.Stop(ctx))
	svc, err := New(deps, testConfig())
	require.NoError(t, err)
	require.NoError(t, svc.SetEnrolments(ctx, []Enrolment{{TenantID: "tenant-a", DeviceID: "mini-99"}}))
	require.NoError(t, svc.Start(ctx))
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	h.svc = svc
	return svc.Restore(ctx)
}

// A lease the host already expired is dead: when the store cannot record
// its revocation, the deletion stays owed, a restart does not reinstall
// the peer, and a later Sweep records the deletion once the store heals.
func TestRestore_ALostLeaseWithAnUnrecordedRevocationStaysOwed(t *testing.T) {
	ctx := context.Background()
	plane := &extendingPlane{fakePlane: newFakePlane(DataPlaneMASQUE)}
	var store *seededStore
	var deps Deps
	h := newHarnessWith(t, testConfig(), func(d *Deps) {
		store = &seededStore{MemoryLeaseStore: d.Leases.(*MemoryLeaseStore)}
		d.Leases = store
		d.DataPlanes = map[DataPlaneKind]DataPlane{DataPlaneMASQUE: plane}
		deps = *d
	})
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	plane.steps = []extendStep{
		{err: errors.New("datapath unreachable")},
		{err: &ErrLeaseNotFound{LeaseID: lease.ID}},
	}
	_, err = h.svc.Renew(ctx, lease.ID, h.evidence(t))
	var unavailable *ErrDataPlaneUnavailable
	require.ErrorAs(t, err, &unavailable)

	store.deleteErr = &ErrRevocationNotRecorded{LeaseID: lease.ID, Cause: errors.New("disk full")}
	h.svc.Sweep(ctx)
	require.Equal(t, 2, plane.calls, "Sweep re-sent the owed extension")
	assert.False(t, plane.hosts(lease.ID), "the host's peer is gone")
	_, err = store.Get(ctx, lease.ID)
	require.NoError(t, err, "the store kept the record it could not delete")

	var notRestored *ErrLeaseNotRestored
	require.ErrorAs(t, restartWith(t, h, deps), &notRestored, "the dead lease is dropped, not restored")
	assert.False(t, plane.hosts(lease.ID), "a restart must not reinstall a lease the host expired")

	store.deleteErr = nil
	h.svc.Sweep(ctx)
	_, err = store.Get(ctx, lease.ID)
	var nf *ErrLeaseNotFound
	require.ErrorAs(t, err, &nf, "the owed deletion is recorded once the store heals")
	assert.False(t, plane.hosts(lease.ID))
}

// A client refused a renewal after its new deadline was stored still holds
// its old expiry: a restart keeps its retry outside the renew window.
func TestRestore_KeepsTheRenewBypassAfterAFailedExtension(t *testing.T) {
	ctx := context.Background()
	plane := &extendingPlane{fakePlane: newFakePlane(DataPlaneMASQUE)}
	var deps Deps
	h := newHarnessWith(t, testConfig(), func(d *Deps) {
		d.DataPlanes = map[DataPlaneKind]DataPlane{DataPlaneMASQUE: plane}
		deps = *d
	})
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	plane.steps = []extendStep{{err: errors.New("datapath unreachable")}}
	_, err = h.svc.Renew(ctx, lease.ID, h.evidence(t))
	var unavailable *ErrDataPlaneUnavailable
	require.ErrorAs(t, err, &unavailable)

	require.NoError(t, restartWith(t, h, deps))
	require.True(t, plane.hosts(lease.ID), "the live lease is restored")

	renewed, err := h.svc.Renew(ctx, lease.ID, h.evidence(t))
	require.NoError(t, err, "the client's retry is not held to the window of the deadline it was refused")
	assert.Equal(t, 2, renewed.Renewals)

	// Once the client holds the new deadline, the window applies again.
	require.NoError(t, restartWith(t, h, deps))
	_, err = h.svc.Renew(ctx, lease.ID, h.evidence(t))
	var notOpen *ErrRenewalNotOpen
	require.ErrorAs(t, err, &notOpen)
}
