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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdmit_RefusesAPeerWithNoEnrolment(t *testing.T) {
	h := newHarness(t, testConfig())
	require.NoError(t, h.svc.SetEnrolments(context.Background(), []Enrolment{{TenantID: "tenant-a", DeviceID: "someone-else"}}))

	_, err := h.svc.Admit(context.Background(), h.request(t))
	var notEnrolled *ErrPeerNotEnrolled
	require.True(t, errors.As(err, &notEnrolled), "got %v", err)
	assert.Equal(t, "mini-99", notEnrolled.DeviceID)
	assert.Equal(t, 0, h.verifier.callCount(), "an unenrolled peer is refused before attestation")
}

// TestAdmit_RefusesBeforeAnyEnrolmentIsDelivered: a gateway that has not yet
// heard from the control plane admits nobody.
func TestAdmit_RefusesBeforeAnyEnrolmentIsDelivered(t *testing.T) {
	h := newHarness(t, testConfig())
	h.svc.enrolments.Store(nil)

	_, err := h.svc.Admit(context.Background(), h.request(t))
	var notEnrolled *ErrPeerNotEnrolled
	assert.True(t, errors.As(err, &notEnrolled), "got %v", err)
	assert.Empty(t, h.svc.Enrolments())
}

func TestAdmit_EnrolmentZonesNarrowTheRequest(t *testing.T) {
	cfg := testConfig()
	cfg.AllowTo = []string{"management", "storage"}
	h := newHarness(t, cfg)
	require.NoError(t, h.svc.SetEnrolments(context.Background(), []Enrolment{{TenantID: "tenant-a", DeviceID: "mini-99", Zones: []string{"storage"}}}))

	_, err := h.svc.Admit(context.Background(), h.request(t))
	var zone *ErrZoneNotAllowed
	require.True(t, errors.As(err, &zone), "got %v", err)
	assert.Equal(t, "management", zone.Zone)

	req := h.request(t)
	req.RequestedZones = []string{"storage"}
	lease, err := h.svc.Admit(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, []string{"storage"}, lease.Zones)
}

func TestSetEnrolments_RevokesLeasesTheNewSetNoLongerCovers(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)

	require.NoError(t, h.svc.SetEnrolments(context.Background(), nil))
	_, err = h.store.Get(context.Background(), lease.ID)
	var nf *ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf), "the removed peer's lease must be revoked")
	assert.Equal(t, 1, h.ipam.releaseCount(), "the address goes back to the pool")
}

func TestSetEnrolments_ZoneWithdrawalRevokesTheLease(t *testing.T) {
	cfg := testConfig()
	cfg.AllowTo = []string{"management", "storage"}
	h := newHarness(t, cfg)
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)

	require.NoError(t, h.svc.SetEnrolments(context.Background(), []Enrolment{{TenantID: "tenant-a", DeviceID: "mini-99", Zones: []string{"storage"}}}))
	_, err = h.store.Get(context.Background(), lease.ID)
	var nf *ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf), "a lease holding a withdrawn zone must be revoked")
}

func TestSetEnrolments_RefusesAMalformedSetAndKeepsThePrevious(t *testing.T) {
	h := newHarness(t, testConfig())
	cases := map[string][]Enrolment{
		"no tenant": {{DeviceID: "d"}},
		"no device": {{TenantID: "t"}},
		"duplicate": {{TenantID: "t", DeviceID: "d"}, {TenantID: "t", DeviceID: "d"}},
		"refused then duplicate": {
			{TenantID: "t", DeviceID: "d", Zones: []string{"storage"}},
			{TenantID: "t", DeviceID: "d"},
		},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			err := h.svc.SetEnrolments(context.Background(), set)
			var invalid *ErrInvalidEnrolment
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Equal(t, []Enrolment{{TenantID: "tenant-a", DeviceID: "mini-99"}}, h.svc.Enrolments())
		})
	}
}

// One peer asking for a zone this gateway does not serve is refused alone:
// the rest of the set is enrolled, the refused peer loses its lease, and the
// rejection is reported until a later set no longer carries it.
func TestSetEnrolments_RefusesOnlyThePeerAskingForAnUnservedZone(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)

	err = h.svc.SetEnrolments(context.Background(), []Enrolment{
		{TenantID: "tenant-b", DeviceID: "laptop-2"},
		{TenantID: "tenant-a", DeviceID: "mini-99", Zones: []string{"storage"}},
		{TenantID: "tenant-a", DeviceID: "laptop-1", Zones: []string{"management"}},
	})

	require.NoError(t, err, "a refused peer must not fail the delivery")
	assert.ElementsMatch(t, []Enrolment{
		{TenantID: "tenant-b", DeviceID: "laptop-2"},
		{TenantID: "tenant-a", DeviceID: "laptop-1", Zones: []string{"management"}},
	}, h.svc.Enrolments())
	assert.Equal(t, []EnrolmentRejection{{
		TenantID: "tenant-a",
		DeviceID: "mini-99",
		Reason:   (&ErrZoneNotAllowed{Zone: "storage"}).Error(),
	}}, h.svc.RejectedEnrolments())
	_, err = h.store.Get(context.Background(), lease.ID)
	var nf *ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf), "the refused peer's lease must be revoked")

	require.NoError(t, h.svc.SetEnrolments(context.Background(), []Enrolment{{TenantID: "tenant-a", DeviceID: "mini-99"}}))
	assert.Empty(t, h.svc.RejectedEnrolments())
}

func TestRejectedEnrolments_NilBeforeAnyDelivery(t *testing.T) {
	svc := &Service{}
	assert.Nil(t, svc.RejectedEnrolments())
}

func TestRenew_RefusesAndRevokesAnUnenrolledLease(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	// Withdraw the enrolment without the revocation sweep, as a renewal
	// racing the delivery would see it.
	empty := enrolmentSet{}
	h.svc.enrolments.Store(&empty)

	h.clock.Advance(DefaultLeaseTTL - DefaultRenewWindow + time.Minute)
	_, err = h.svc.Renew(context.Background(), lease.ID, h.evidence(t))
	var notEnrolled *ErrPeerNotEnrolled
	require.True(t, errors.As(err, &notEnrolled), "got %v", err)
	_, err = h.store.Get(context.Background(), lease.ID)
	var nf *ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf))
}

// admitInBackground starts an admission and returns the channel its error
// arrives on.
func admitInBackground(h *harness, req *AdmissionRequest) <-chan error {
	result := make(chan error, 1)
	go func() {
		_, err := h.svc.Admit(context.Background(), req)
		result <- err
	}()
	return result
}

func TestAdmit_EnrolmentWithdrawnDuringVerificationIsRefused(t *testing.T) {
	h := newHarness(t, testConfig())
	h.verifier.pause = newPause()
	result := admitInBackground(h, h.request(t))

	// The admission passed the enrolment check and is parked in attestation
	// while the control plane withdraws the peer and the sweep finds no lease.
	<-h.verifier.pause.entered
	require.NoError(t, h.svc.SetEnrolments(context.Background(), nil))
	close(h.verifier.pause.release)

	var notEnrolled *ErrPeerNotEnrolled
	err := <-result
	require.True(t, errors.As(err, &notEnrolled), "got %v", err)
	leases, err := h.svc.Leases(context.Background())
	require.NoError(t, err)
	assert.Empty(t, leases, "a withdrawn peer holds no lease")
	assert.Equal(t, 0, h.plane.count(), "no peer is installed")
	assert.Equal(t, 0, h.ipam.allocatedCount(), "no address is allocated")
}

func TestAdmit_EnrolmentKeptDuringVerificationIsAdmitted(t *testing.T) {
	h := newHarness(t, testConfig())
	h.verifier.pause = newPause()
	result := admitInBackground(h, h.request(t))

	<-h.verifier.pause.entered
	require.NoError(t, h.svc.SetEnrolments(context.Background(), []Enrolment{
		{TenantID: "tenant-a", DeviceID: "mini-99"},
		{TenantID: "tenant-a", DeviceID: "mini-100"},
	}))
	close(h.verifier.pause.release)

	require.NoError(t, <-result)
	leases, err := h.svc.Leases(context.Background())
	require.NoError(t, err)
	assert.Len(t, leases, 1, "an update that keeps the peer does not refuse it")
}

func TestSetEnrolments_SweepsALeaseCommittedDuringTheUpdate(t *testing.T) {
	h := newHarness(t, testConfig())
	h.plane.pause = newPause()
	result := admitInBackground(h, h.request(t))

	// The admission is past its final enrolment check and installing the
	// peer. The withdrawal must wait for its lease write and then sweep it.
	<-h.plane.pause.entered
	updated := make(chan error, 1)
	go func() { updated <- h.svc.SetEnrolments(context.Background(), nil) }()
	close(h.plane.pause.release)

	require.NoError(t, <-result)
	require.NoError(t, <-updated)
	leases, err := h.svc.Leases(context.Background())
	require.NoError(t, err)
	assert.Empty(t, leases, "the sweep revokes the lease committed under the old set")
	assert.Equal(t, 0, h.plane.count(), "the peer is removed")
}

func TestSetEnrolments_SeparatorInAnIDDoesNotCollide(t *testing.T) {
	h := newHarness(t, testConfig())
	both := []Enrolment{{TenantID: "a/b", DeviceID: "c"}, {TenantID: "a", DeviceID: "b/c"}}
	require.NoError(t, h.svc.SetEnrolments(context.Background(), both),
		"two distinct peers are not duplicates")
	assert.Len(t, h.svc.Enrolments(), 2)
}

func TestSetEnrolments_RefusesADuplicatePeer(t *testing.T) {
	h := newHarness(t, testConfig())
	dup := []Enrolment{{TenantID: "a", DeviceID: "b/c"}, {TenantID: "a", DeviceID: "b/c"}}
	var invalid *ErrInvalidEnrolment
	err := h.svc.SetEnrolments(context.Background(), dup)
	require.True(t, errors.As(err, &invalid), "got %v", err)
	assert.Equal(t, 1, invalid.Index)
}

func TestEnrolled_SeparatorInAnIDDoesNotGrantAnotherPeer(t *testing.T) {
	cases := map[string]struct {
		enrolled Enrolment
		asking   Enrolment
	}{
		"slash in the tenant": {Enrolment{TenantID: "a/b", DeviceID: "c"}, Enrolment{TenantID: "a", DeviceID: "b/c"}},
		"slash in the device": {Enrolment{TenantID: "a", DeviceID: "b/c"}, Enrolment{TenantID: "a/b", DeviceID: "c"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, testConfig())
			require.NoError(t, h.svc.SetEnrolments(context.Background(), []Enrolment{tc.enrolled}))

			var notEnrolled *ErrPeerNotEnrolled
			err := h.svc.enrolled(tc.asking.TenantID, tc.asking.DeviceID, nil)
			require.True(t, errors.As(err, &notEnrolled), "got %v", err)
			require.NoError(t, h.svc.enrolled(tc.enrolled.TenantID, tc.enrolled.DeviceID, nil))

			set := enrolmentSet{deviceKey(tc.enrolled.TenantID, tc.enrolled.DeviceID): tc.enrolled}
			assert.False(t, covered(set, &Lease{TenantID: tc.asking.TenantID, DeviceID: tc.asking.DeviceID}),
				"the other peer's lease is not covered")
		})
	}
}

func TestPeerKey_CompareOrdersByTenantThenDevice(t *testing.T) {
	assert.Negative(t, deviceKey("a", "z").compare(deviceKey("b", "a")), "tenant decides first")
	assert.Negative(t, deviceKey("a", "a").compare(deviceKey("a", "b")), "device breaks a tenant tie")
	assert.Zero(t, deviceKey("a", "b").compare(deviceKey("a", "b")))
	assert.NotZero(t, deviceKey("a/b", "c").compare(deviceKey("a", "b/c")), "the separator does not merge keys")
}
