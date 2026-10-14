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
	svc, err := New(Deps{
		Identity:   &fakeIdentity{},
		Verifier:   &fakeVerifier{},
		Posture:    &fakePosture{},
		Factors:    &fakeFactors{},
		IPAM:       h.ipam,
		DataPlanes: map[DataPlaneKind]DataPlane{DataPlaneMASQUE: h.plane},
		Leases:     h.store,
		Audit:      &fakeAudit{},
		Clock:      h.clock,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, testConfig())
	require.NoError(t, err)
	h.svc = svc
	return h
}

// start starts the service and stops it when the test ends.
func (h *restoreHarness) start(t *testing.T) {
	t.Helper()
	require.NoError(t, h.svc.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, h.svc.Stop(context.Background())) })
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
			l.DataPlane = DataPlaneWireGuard
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
			h := newRestoreHarness(t)
			lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
			c.prepare(t, h, lease)
			h.start(t)

			err := h.svc.Restore(context.Background())

			var dropped *ErrLeaseNotRestored
			require.True(t, errors.As(err, &dropped), "got %v", err)
			assert.Equal(t, lease.ID, dropped.LeaseID)
			assert.Equal(t, c.reason, dropped.Reason)
			assert.Zero(t, h.plane.count(), "a dropped lease has no peer")
			_, err = h.store.Get(context.Background(), lease.ID)
			var nf *ErrLeaseNotFound
			assert.True(t, errors.As(err, &nf), "a dropped lease leaves the store, got %v", err)
			assert.NotEqual(t, "mini-1", h.holder(t, lease.Address), "a dropped lease holds no address")
		})
	}
}

func TestRestore_LeavesAnotherDevicesAddressAlone(t *testing.T) {
	h := newRestoreHarness(t)
	lease := h.seed(t, "lease-1", "mini-1", "100.64.0.2/32")
	h.allocate(t, "mini-other", lease.Address)
	h.start(t)

	require.Error(t, h.svc.Restore(context.Background()))
	assert.Equal(t, "mini-other", h.holder(t, lease.Address), "dropping a lease must not free an address it never held")
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
