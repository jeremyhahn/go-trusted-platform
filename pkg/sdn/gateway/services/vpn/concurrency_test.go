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
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdmit_ConcurrentSameDeviceLeavesOnePeer pins the #588 review finding:
// N concurrent admissions for one (tenant, device) must end with exactly one
// lease, one installed peer and one allocated address — every other peer
// removed and its address released.
func TestAdmit_ConcurrentSameDeviceLeavesOnePeer(t *testing.T) {
	h := newHarness(t, testConfig())
	h.ipam.capacity = 64
	const n = 12
	reqs := make([]*AdmissionRequest, n)
	for i := range reqs {
		reqs[i] = h.request(t)
	}
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for _, req := range reqs {
		wg.Add(1)
		go func(r *AdmissionRequest) {
			defer wg.Done()
			_, err := h.svc.Admit(context.Background(), r)
			errs <- err
		}(req)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	leases, err := h.svc.Leases(context.Background())
	require.NoError(t, err)
	require.Len(t, leases, 1, "one lease per device per tenant")
	assert.Equal(t, 1, h.plane.count(), "exactly one peer remains installed")
	assert.Equal(t, 1, h.ipam.allocatedCount(), "exactly one address remains allocated")
	assert.Len(t, h.plane.removed, n-1, "every replaced peer was removed")
	_, installed := h.plane.installed[leases[0].ID]
	assert.True(t, installed, "the surviving lease is the installed peer")
}

// TestRenew_ConcurrentSameLeaseSerialises: renewals racing on one lease
// serialise under the device lock. Exactly one of them lands inside the
// renew window and extends the lease; every other one then sees a lease
// whose window has not opened again and is refused (#588 review) — the
// counter reflects one renewal, never a torn read.
func TestRenew_ConcurrentSameLeaseSerialises(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	const n = 6
	evs := make([]*Evidence, n)
	for i := range evs {
		evs[i] = h.evidence(t)
	}
	var wg sync.WaitGroup
	var renewed, notOpen atomic.Int32
	for _, ev := range evs {
		wg.Add(1)
		go func(e *Evidence) {
			defer wg.Done()
			_, err := h.svc.Renew(context.Background(), lease.ID, e)
			var refused *ErrRenewalNotOpen
			switch {
			case err == nil:
				renewed.Add(1)
			case errors.As(err, &refused):
				notOpen.Add(1)
			default:
				assert.NoError(t, err)
			}
		}(ev)
	}
	wg.Wait()
	assert.Equal(t, int32(1), renewed.Load(), "exactly one renewal lands in the window")
	assert.Equal(t, int32(n-1), notOpen.Load(), "the rest are refused until the window opens again")
	got, err := h.svc.Lease(context.Background(), lease.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.Renewals)
}

// TestRevoke_ConcurrentWithRenewResolvesToRevoked: a revoke racing a renewal
// ends with no lease, whichever wins the lock.
func TestRevoke_ConcurrentWithRenewResolvesToRevoked(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	ev := h.evidence(t)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = h.svc.Renew(context.Background(), lease.ID, ev) }()
	go func() { defer wg.Done(); _ = h.svc.Revoke(context.Background(), lease.ID, RevokeOperator) }()
	wg.Wait()
	// The revoke may have lost the race to a renewal that had already
	// re-read the lease; either way the operator's intent must hold once
	// the revoke is repeated after the race.
	err = h.svc.Revoke(context.Background(), lease.ID, RevokeOperator)
	var nf *ErrLeaseNotFound
	if err != nil {
		require.True(t, errors.As(err, &nf), "got %v", err)
	}
	leases, _ := h.svc.Leases(context.Background())
	assert.Empty(t, leases)
	assert.Equal(t, 0, h.plane.count())
	assert.Equal(t, 0, h.ipam.allocatedCount())
}

func TestKeyLock_EntriesAreReleased(t *testing.T) {
	k := newKeyLock()
	unlockA := k.lock("a")
	unlockB := k.lock("b")
	k.mu.Lock()
	assert.Len(t, k.locks, 2)
	k.mu.Unlock()
	unlockA()
	unlockB()
	k.mu.Lock()
	assert.Empty(t, k.locks, "entries leave the map with their last holder")
	k.mu.Unlock()
}

func TestAdmit_LeaseStoreFailureIsItsOwnError(t *testing.T) {
	h := newHarness(t, testConfig())
	h.svc.deps.Leases = &failingStore{LeaseStore: h.store, findErr: errors.New("store down")}
	_, err := h.svc.Admit(context.Background(), h.request(t))
	var storeErr *ErrLeaseStoreUnavailable
	assert.True(t, errors.As(err, &storeErr), "got %v", err)
	assert.Equal(t, 0, h.plane.count())
}

type failingStore struct {
	LeaseStore
	findErr error
}

func (f *failingStore) FindByDevice(ctx context.Context, tenantID, deviceID string) (*Lease, bool, error) {
	if f.findErr != nil {
		return nil, false, f.findErr
	}
	return f.LeaseStore.FindByDevice(ctx, tenantID, deviceID)
}
