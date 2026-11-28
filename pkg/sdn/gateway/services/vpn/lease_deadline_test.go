// Copyright (c) 2026 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package vpn

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
)

var leaseDeadlineT0 = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

// deadlinePeer is masquePeer with the lease deadline set.
func deadlinePeer(id string, deadline time.Time) *ipcv1.VPNPeer {
	peer := masquePeer(id)
	peer.ExpiresAtUnixNano = deadline.UnixNano()
	return peer
}

func installHosted(t *testing.T, host *PlaneHost, peer *ipcv1.VPNPeer) *ipcv1.VPNPeerRefusal {
	t.Helper()
	return host.InstallVPNPeer(context.Background(), &ipcv1.InstallVPNPeerRequest{Peer: peer}).GetRefusal()
}

func TestLeaseDeadline_PeerOfCarriesItOverTheWire(t *testing.T) {
	t0 := leaseDeadlineT0
	roundTrip := func(t *testing.T, lease *Lease) (*ipcv1.VPNPeer, *Lease) {
		t.Helper()
		b, err := proto.Marshal(peerOf(DataPlaneMASQUE, lease))
		require.NoError(t, err)
		var got ipcv1.VPNPeer
		require.NoError(t, proto.Unmarshal(b, &got))
		back, err := leaseFromPeer(&got)
		require.NoError(t, err)
		return &got, back
	}

	t.Run("deadline", func(t *testing.T) {
		lease := clientLease("l1")
		lease.ExpiresAt = t0.Add(time.Hour + 123)
		got, back := roundTrip(t, lease)
		assert.Equal(t, lease.ExpiresAt.UnixNano(), got.GetExpiresAtUnixNano())
		assert.True(t, back.ExpiresAt.Equal(lease.ExpiresAt), "got %v want %v", back.ExpiresAt, lease.ExpiresAt)
	})

	t.Run("no deadline", func(t *testing.T) {
		lease := clientLease("l1")
		got, back := roundTrip(t, lease)
		assert.Zero(t, got.GetExpiresAtUnixNano())
		assert.True(t, back.ExpiresAt.IsZero())
	})
}

func TestLeaseDeadline_HostRemovesAPeerPastItsDeadline(t *testing.T) {
	t0 := leaseDeadlineT0
	ctx := context.Background()
	plane := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, plane)

	require.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(time.Hour))))

	require.NoError(t, host.ExpirePeers(ctx, t0.Add(30*time.Minute)))
	assert.Equal(t, 1, plane.count())
	assert.Empty(t, plane.removed)

	require.NoError(t, host.ExpirePeers(ctx, t0.Add(time.Hour)))
	assert.Equal(t, []LeaseID{"l1"}, plane.removed)
	assert.Equal(t, 0, plane.count())

	require.NoError(t, host.ExpirePeers(ctx, t0.Add(2*time.Hour)))
	assert.Equal(t, []LeaseID{"l1"}, plane.removed)
}

func TestLeaseDeadline_AFailedExpiryIsRetried(t *testing.T) {
	t0 := leaseDeadlineT0
	ctx := context.Background()
	plane := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, plane)
	require.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(time.Hour))))

	plane.failRemovals(errors.New("netlink refused"))
	require.Error(t, host.ExpirePeers(ctx, t0.Add(time.Hour)))
	assert.Equal(t, 1, plane.count())

	plane.failRemovals(nil)
	require.NoError(t, host.ExpirePeers(ctx, t0.Add(time.Hour+time.Second)))
	assert.Equal(t, 0, plane.count())
}

func TestLeaseDeadline_ReinstallOfTheSamePeerOnlyMovesTheDeadline(t *testing.T) {
	t0 := leaseDeadlineT0
	ctx := context.Background()
	plane := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, plane)
	require.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(time.Hour))))

	plane.installErr = errors.New("plane reached")
	assert.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(2*time.Hour))),
		"an identical peer only moves its deadline and never reaches the plane")

	require.NoError(t, host.ExpirePeers(ctx, t0.Add(90*time.Minute)))
	assert.Equal(t, 1, plane.count())
	require.NoError(t, host.ExpirePeers(ctx, t0.Add(2*time.Hour)))
	assert.Equal(t, 0, plane.count())

	changed := deadlinePeer("l1", t0.Add(3*time.Hour))
	changed.ClientCertificateSha256 = bytesOf(0xcd, 32)
	assert.NotNil(t, installHosted(t, host, changed), "a changed peer reaches the plane")
}

func TestLeaseDeadline_RemoveAndReconcileForgetTheDeadline(t *testing.T) {
	t0 := leaseDeadlineT0
	ctx := context.Background()
	plane := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, plane)
	require.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(time.Hour))))
	l2 := deadlinePeer("l2", t0.Add(time.Hour))
	l2.Address = "100.64.0.8/32"
	require.Nil(t, installHosted(t, host, l2))

	require.Nil(t, host.RemoveVPNPeer(ctx, &ipcv1.RemoveVPNPeerRequest{
		LeaseId: "l1", DataPlane: string(DataPlaneMASQUE),
	}).GetRefusal())
	require.Nil(t, host.ReconcileVPNPeers(ctx, &ipcv1.ReconcileVPNPeersRequest{
		DataPlane: string(DataPlaneMASQUE),
	}).GetRefusal())
	removed := len(plane.removed)

	require.NoError(t, host.ExpirePeers(ctx, t0.Add(2*time.Hour)))
	assert.Len(t, plane.removed, removed, "a withdrawn peer is not expired again")
}

func TestLeaseDeadline_AStartedHostExpiresPeersOnItsOwn(t *testing.T) {
	tick := planeHostExpiryTick
	planeHostExpiryTick = 10 * time.Millisecond
	t.Cleanup(func() { planeHostExpiryTick = tick })

	ctx := context.Background()
	plane := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, plane)
	require.Nil(t, installHosted(t, host, deadlinePeer("l1", time.Now())))

	require.NoError(t, host.Start(ctx))
	require.Eventually(t, func() bool { return plane.count() == 0 }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, host.Stop(ctx))

	require.NoError(t, host.Start(ctx))
	require.NoError(t, host.Stop(ctx))
}

// hostedHarness admits through a DatapathPlane whose PlaneHost holds the
// managed fake, as the gateway runs it: admission in one process, the plane
// in the datapath.
func hostedHarness(t *testing.T) (*harness, *PlaneHost, *managedFakePlane, *hostPeers) {
	t.Helper()
	managed := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, managed)
	peers := &hostPeers{host: host}
	dp, err := NewDatapathPlane(DataPlaneMASQUE, peers)
	require.NoError(t, err)
	h := newHarnessWith(t, testConfig(), func(d *Deps) {
		d.DataPlanes[DataPlaneMASQUE] = dp
	})
	host.now = h.clock.Now
	return h, host, managed, peers
}

// renewalEvidence is the renewal evidence admission_test.go uses: no person
// factor, which renewal does not require by default.
func renewalEvidence(t *testing.T, h *harness) *Evidence {
	t.Helper()
	ev := h.evidence(t)
	ev.PersonFactor = nil
	return ev
}

func TestLeaseDeadline_ExpiresAnAdmittedPeerWithoutTheAdmissionService(t *testing.T) {
	ctx := context.Background()
	h, host, managed, _ := hostedHarness(t)
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	require.Equal(t, 1, managed.count())

	require.NoError(t, host.ExpirePeers(ctx, lease.ExpiresAt.Add(-time.Second)))
	assert.Equal(t, 1, managed.count())
	require.NoError(t, host.ExpirePeers(ctx, lease.ExpiresAt))
	assert.Equal(t, 0, managed.count())
}

func TestLeaseDeadline_RenewalMovesTheHostedDeadline(t *testing.T) {
	ctx := context.Background()
	h, host, managed, _ := hostedHarness(t)
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	oldDeadline := lease.ExpiresAt

	managed.installErr = errors.New("renewal reinstalled the peer")
	h.clock.Advance(DefaultLeaseTTL - DefaultRenewWindow + time.Minute)
	renewed, err := h.svc.Renew(ctx, lease.ID, renewalEvidence(t, h))
	require.NoError(t, err)
	require.True(t, renewed.ExpiresAt.After(oldDeadline))

	require.NoError(t, host.ExpirePeers(ctx, oldDeadline))
	assert.Equal(t, 1, managed.count())
	require.NoError(t, host.ExpirePeers(ctx, renewed.ExpiresAt))
	assert.Equal(t, 0, managed.count())
}

func TestLeaseDeadline_RenewalRefusedWhenTheHostIsUnreachable(t *testing.T) {
	ctx := context.Background()
	h, _, _, peers := hostedHarness(t)
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)

	peers.err = errors.New("child gone")
	h.clock.Advance(DefaultLeaseTTL - DefaultRenewWindow + time.Minute)
	_, err = h.svc.Renew(ctx, lease.ID, renewalEvidence(t, h))
	var unavailable *ErrDataPlaneUnavailable
	require.ErrorAs(t, err, &unavailable)
}

func TestLeaseDeadline_RenewalAfterExpiryIsRefusedAndInstallsNothing(t *testing.T) {
	t0 := leaseDeadlineT0
	ctx := context.Background()

	t.Run("expired and removed", func(t *testing.T) {
		managed := newManagedFakePlane(DataPlaneMASQUE, new([]string))
		host := hostOf(t, managed)
		dp, err := NewDatapathPlane(DataPlaneMASQUE, &hostPeers{host: host})
		require.NoError(t, err)
		require.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(time.Hour))))
		require.NoError(t, host.ExpirePeers(ctx, t0.Add(time.Hour)))
		require.Equal(t, 0, managed.count())

		lease, err := leaseFromPeer(deadlinePeer("l1", t0.Add(2*time.Hour)))
		require.NoError(t, err)
		var notFound *ErrLeaseNotFound
		require.ErrorAs(t, dp.ExtendPeer(ctx, lease), &notFound)
		assert.Equal(t, 0, managed.count(), "a renewal after expiry installs nothing")
	})

	t.Run("deadline passed before expiry ran", func(t *testing.T) {
		managed := newManagedFakePlane(DataPlaneMASQUE, new([]string))
		host := hostOf(t, managed)
		host.now = func() time.Time { return t0.Add(time.Hour) }
		require.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(time.Hour))))

		resp := host.RenewVPNPeer(ctx, &ipcv1.RenewVPNPeerRequest{
			DataPlane: string(DataPlaneMASQUE), LeaseId: "l1",
			PublicKey:         bytesOf(0xab, 32),
			ExpiresAtUnixNano: t0.Add(2 * time.Hour).UnixNano(),
		})
		require.NotNil(t, resp.GetRefusal())
		assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_LEASE_NOT_FOUND, resp.GetRefusal().GetClass())

		require.NoError(t, host.ExpirePeers(ctx, t0.Add(time.Hour)))
		assert.Equal(t, 0, managed.count(), "the old deadline stands")
	})

	t.Run("held and unexpired moves only the deadline", func(t *testing.T) {
		managed := newManagedFakePlane(DataPlaneMASQUE, new([]string))
		host := hostOf(t, managed)
		host.now = func() time.Time { return t0.Add(30 * time.Minute) }
		require.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(time.Hour))))
		managed.installErr = errors.New("renewal reached the plane")

		require.Nil(t, host.RenewVPNPeer(ctx, &ipcv1.RenewVPNPeerRequest{
			DataPlane: string(DataPlaneMASQUE), LeaseId: "l1",
			PublicKey:         bytesOf(0xab, 32),
			ExpiresAtUnixNano: t0.Add(2 * time.Hour).UnixNano(),
		}).GetRefusal())
		require.NoError(t, host.ExpirePeers(ctx, t0.Add(time.Hour)))
		assert.Equal(t, 1, managed.count())
		require.NoError(t, host.ExpirePeers(ctx, t0.Add(2*time.Hour)))
		assert.Equal(t, 0, managed.count())
	})
}

// A renewal request that arrives after a later one (reordered or delayed
// delivery) must not shorten the deadline the host holds: the host deadline
// only moves forward.
func TestLeaseDeadline_DelayedLowerRenewalCannotRollBackTheHostDeadline(t *testing.T) {
	t0 := leaseDeadlineT0
	ctx := context.Background()
	managed := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, managed)
	host.now = func() time.Time { return t0.Add(30 * time.Minute) }
	require.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(time.Hour))))

	require.Nil(t, host.RenewVPNPeer(ctx, &ipcv1.RenewVPNPeerRequest{
		DataPlane: string(DataPlaneMASQUE), LeaseId: "l1",
		PublicKey:         bytesOf(0xab, 32),
		ExpiresAtUnixNano: t0.Add(3 * time.Hour).UnixNano(),
	}).GetRefusal())
	require.Nil(t, host.RenewVPNPeer(ctx, &ipcv1.RenewVPNPeerRequest{
		DataPlane: string(DataPlaneMASQUE), LeaseId: "l1",
		PublicKey:         bytesOf(0xab, 32),
		ExpiresAtUnixNano: t0.Add(2 * time.Hour).UnixNano(),
	}).GetRefusal(), "a lower deadline is accepted as a no-op")

	require.NoError(t, host.ExpirePeers(ctx, t0.Add(2*time.Hour)))
	assert.Equal(t, 1, managed.count(), "the delayed lower deadline did not roll the host back")
	require.NoError(t, host.ExpirePeers(ctx, t0.Add(3*time.Hour)))
	assert.Equal(t, 0, managed.count())
}

// A renewal whose host extension failed told the client 503, so the client
// still holds its old expiry. A Sweep that later pays the host extension
// must not close the renewal window the client's retry relies on: the retry
// is accepted though the new stored deadline's window has not opened.
func TestLeaseDeadline_ClientRetryAfterASweepRecoveredTheHostIsStillAccepted(t *testing.T) {
	ctx := context.Background()
	h, plane, lease := renewHarness(t)
	plane.steps = []extendStep{{err: errors.New("datapath unreachable")}}
	_, err := h.svc.Renew(ctx, lease.ID, h.evidence(t))
	var unavailable *ErrDataPlaneUnavailable
	require.ErrorAs(t, err, &unavailable, "the client is told the renewal failed")
	stored, err := h.svc.Lease(ctx, lease.ID)
	require.NoError(t, err)

	h.svc.Sweep(ctx)
	require.Equal(t, 2, plane.calls, "Sweep pays the host extension")
	assert.Equal(t, stored.ExpiresAt, plane.hostDeadline(lease.ExpiresAt))

	h.clock.Advance(time.Minute)
	require.True(t, h.clock.Now().Before(stored.ExpiresAt.Add(-DefaultRenewWindow)),
		"the ordinary window of the new stored deadline would refuse")
	renewed, err := h.svc.Renew(ctx, lease.ID, h.evidence(t))
	require.NoError(t, err, "the client never learned its new deadline: its retry is still owed")
	assert.Equal(t, 2, renewed.Renewals)

	_, err = h.svc.Renew(ctx, lease.ID, h.evidence(t))
	var notOpen *ErrRenewalNotOpen
	require.ErrorAs(t, err, &notOpen, "a successful renewal clears the client's bypass")
}

// A non-expired revocation whose deletion was not recorded leaves the lease
// served: the owed extension it still needs stays owed, so a following
// Sweep re-sends it.
func TestLeaseDeadline_AnUnrecordedRevocationKeepsTheOwedExtension(t *testing.T) {
	ctx := context.Background()
	plane := &extendingPlane{fakePlane: newFakePlane(DataPlaneMASQUE)}
	var store *seededStore
	h := newHarnessWith(t, testConfig(), func(d *Deps) {
		store = &seededStore{MemoryLeaseStore: d.Leases.(*MemoryLeaseStore)}
		d.Leases = store
		d.DataPlanes = map[DataPlaneKind]DataPlane{DataPlaneMASQUE: plane}
	})
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	plane.steps = []extendStep{{err: errors.New("datapath unreachable")}}
	_, err = h.svc.Renew(ctx, lease.ID, h.evidence(t))
	var unavailable *ErrDataPlaneUnavailable
	require.ErrorAs(t, err, &unavailable)
	require.Equal(t, 1, plane.calls)

	store.deleteErr = &ErrRevocationNotRecorded{LeaseID: lease.ID, Cause: errors.New("disk full")}
	err = h.svc.Revoke(ctx, lease.ID, RevokeOperator)
	var unrecorded *ErrRevocationNotRecorded
	require.ErrorAs(t, err, &unrecorded)
	_, err = h.svc.Lease(ctx, lease.ID)
	require.NoError(t, err, "the lease is still served")

	h.svc.Sweep(ctx)
	assert.Equal(t, 2, plane.calls, "Sweep still re-sends the owed extension")
}

// renewFailingPeers is a datapath whose renewal RPC alone goes unanswered:
// installs and reconciles still reach the host.
type renewFailingPeers struct {
	*hostPeers
	renewErr error
}

func (p *renewFailingPeers) RenewVPNPeer(ctx context.Context, req *ipcv1.RenewVPNPeerRequest) (*ipcv1.RenewVPNPeerResponse, error) {
	if p.renewErr != nil {
		return nil, p.renewErr
	}
	return p.hostPeers.RenewVPNPeer(ctx, req)
}

// restartableHostedHarness is hostedHarness with the deps a restart reuses
// and a datapath whose renewal RPC can fail on its own.
func restartableHostedHarness(t *testing.T) (*harness, Deps, *PlaneHost, *managedFakePlane, *renewFailingPeers) {
	t.Helper()
	managed := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, managed)
	peers := &renewFailingPeers{hostPeers: &hostPeers{host: host}}
	dp, err := NewDatapathPlane(DataPlaneMASQUE, peers)
	require.NoError(t, err)
	var deps Deps
	h := newHarnessWith(t, testConfig(), func(d *Deps) {
		d.DataPlanes[DataPlaneMASQUE] = dp
		deps = *d
	})
	host.now = h.clock.Now
	return h, deps, host, managed, peers
}

// A renewal RPC that failed left the host at the client's deadline. After
// the host expired the peer there, a restart whose renewal check fails again
// while installs succeed must not recreate the peer with the later stored
// deadline.
func TestRestore_AFailedHostCheckNeverReinstallsAPeerTheHostExpired(t *testing.T) {
	ctx := context.Background()
	h, deps, host, managed, peers := restartableHostedHarness(t)
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	peers.renewErr = errors.New("datapath unreachable")
	_, err = h.svc.Renew(ctx, lease.ID, renewalEvidence(t, h))
	var unavailable *ErrDataPlaneUnavailable
	require.ErrorAs(t, err, &unavailable)
	stored, err := h.svc.Lease(ctx, lease.ID)
	require.NoError(t, err)
	require.True(t, stored.ExpiresAt.After(lease.ExpiresAt))

	h.clock.Advance(DefaultRenewWindow)
	require.NoError(t, host.ExpirePeers(ctx, h.clock.Now()))
	require.Equal(t, 0, managed.count(), "the host expired the peer at the client's deadline")

	require.NoError(t, restartWith(t, h, deps))
	assert.Equal(t, 0, managed.count(), "an inconclusive host check must not reinstall a peer the host expired")

	peers.renewErr = nil
	h.svc.Sweep(ctx)
	assert.Equal(t, 0, managed.count())
	_, err = h.svc.Lease(ctx, lease.ID)
	var nf *ErrLeaseNotFound
	assert.ErrorAs(t, err, &nf, "the Sweep's host check finds the peer expired and revokes the lease")
}

// A pending renewal's lease survives a restart of both the datapath (an
// empty replacement host) and the vpn service before the client's deadline:
// the peer is replayed with the client's deadline, and the client's retry
// extends it.
func TestRestore_AReplacementHostGetsAPendingRenewalsPeerReplayed(t *testing.T) {
	ctx := context.Background()
	h, deps, _, _, peers := restartableHostedHarness(t)
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	peers.renewErr = errors.New("datapath unreachable")
	_, err = h.svc.Renew(ctx, lease.ID, renewalEvidence(t, h))
	var unavailable *ErrDataPlaneUnavailable
	require.ErrorAs(t, err, &unavailable)

	managed2 := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host2 := hostOf(t, managed2)
	host2.now = h.clock.Now
	peers.host = host2
	peers.renewErr = nil
	require.True(t, h.clock.Now().Before(lease.ExpiresAt))

	require.NoError(t, restartWith(t, h, deps), "a lease before its client's deadline is not dropped")
	require.Equal(t, 1, managed2.count(), "the replacement host gets the peer replayed")
	_, err = h.svc.Lease(ctx, lease.ID)
	require.NoError(t, err)
	require.NoError(t, host2.ExpirePeers(ctx, lease.ExpiresAt.Add(-time.Second)))
	require.Equal(t, 1, managed2.count())

	renewed, err := h.svc.Renew(ctx, lease.ID, renewalEvidence(t, h))
	require.NoError(t, err, "the client's retry keeps the renew bypass")
	require.NoError(t, host2.ExpirePeers(ctx, lease.ExpiresAt))
	assert.Equal(t, 1, managed2.count(), "the retry moved the replayed peer's deadline")
	require.NoError(t, host2.ExpirePeers(ctx, renewed.ExpiresAt))
	assert.Equal(t, 0, managed2.count())
}

// markerClearFailStore fails only the write that clears a renewal's
// recovery marker (a lease with a zero ClientExpiresAt); the renewal's
// first write, which stores the marker, succeeds.
type markerClearFailStore struct {
	LeaseStore
	fail atomic.Bool
}

func (s *markerClearFailStore) Put(ctx context.Context, lease *Lease) error {
	if s.fail.Load() && lease.ClientExpiresAt.IsZero() {
		return errors.New("disk full")
	}
	return s.LeaseStore.Put(ctx, lease)
}

// A renewal whose marker clear could not be stored is refused, so the
// client keeps its older deadline and retries; after the retry clears the
// marker, a restart of both the datapath (an empty replacement host) and
// the vpn service past the original deadline replays the lease instead of
// deleting it.
func TestRenew_AFailedMarkerClearRefusesTheRenewalAndKeepsTheLeaseAcrossARestart(t *testing.T) {
	ctx := context.Background()
	managed := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, managed)
	peers := &renewFailingPeers{hostPeers: &hostPeers{host: host}}
	dp, err := NewDatapathPlane(DataPlaneMASQUE, peers)
	require.NoError(t, err)
	var deps Deps
	var store *markerClearFailStore
	h := newHarnessWith(t, testConfig(), func(d *Deps) {
		d.DataPlanes[DataPlaneMASQUE] = dp
		store = &markerClearFailStore{LeaseStore: d.Leases}
		d.Leases = store
		deps = *d
	})
	host.now = h.clock.Now

	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	store.fail.Store(true)
	_, err = h.svc.Renew(ctx, lease.ID, renewalEvidence(t, h))
	var unavailable *ErrLeaseStoreUnavailable
	require.ErrorAs(t, err, &unavailable, "a renewal whose recovery marker could not be cleared is not reported as done")
	stored, err := store.Get(ctx, lease.ID)
	require.NoError(t, err)
	require.True(t, stored.ClientExpiresAt.Equal(lease.ExpiresAt), "the marker still names the deadline the client holds")

	store.fail.Store(false)
	renewed, err := h.svc.Renew(ctx, lease.ID, renewalEvidence(t, h))
	require.NoError(t, err, "the client's retry keeps the renew bypass")
	stored, err = store.Get(ctx, lease.ID)
	require.NoError(t, err)
	require.True(t, stored.ClientExpiresAt.IsZero())

	managed2 := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host2 := hostOf(t, managed2)
	host2.now = h.clock.Now
	peers.host = host2
	h.clock.Advance(DefaultRenewWindow)
	require.True(t, h.clock.Now().After(lease.ExpiresAt))
	require.True(t, h.clock.Now().Before(renewed.ExpiresAt))

	require.NoError(t, restartWith(t, h, deps), "a confirmed renewal is restored past the original deadline")
	assert.Equal(t, 1, managed2.count(), "the replacement host gets the peer replayed")
	_, err = h.svc.Lease(ctx, lease.ID)
	require.NoError(t, err)
}

// lostMarkerClearStore is a lease store whose marker-clearing Put (a lease
// with a zero ClientExpiresAt) commits and then fails, as an HTTP PUT whose
// response is lost. With failRemark set, a later marker-storing Put fails
// without committing.
type lostMarkerClearStore struct {
	LeaseStore
	lose       atomic.Bool
	failRemark atomic.Bool
	lost       atomic.Bool
}

func (s *lostMarkerClearStore) Put(ctx context.Context, lease *Lease) error {
	if lease.ClientExpiresAt.IsZero() && s.lose.Load() {
		if err := s.LeaseStore.Put(ctx, lease); err != nil {
			return err
		}
		s.lost.Store(true)
		return errors.New("response lost")
	}
	if !lease.ClientExpiresAt.IsZero() && s.failRemark.Load() && s.lost.Load() {
		return errors.New("disk full")
	}
	return s.LeaseStore.Put(ctx, lease)
}

// lostClearHarness builds a MASQUE harness whose lease store is a
// lostMarkerClearStore and returns the deps a restart reuses.
func lostClearHarness(t *testing.T) (*harness, Deps, *lostMarkerClearStore) {
	t.Helper()
	managed := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, managed)
	peers := &renewFailingPeers{hostPeers: &hostPeers{host: host}}
	dp, err := NewDatapathPlane(DataPlaneMASQUE, peers)
	require.NoError(t, err)
	var deps Deps
	var store *lostMarkerClearStore
	h := newHarnessWith(t, testConfig(), func(d *Deps) {
		d.DataPlanes[DataPlaneMASQUE] = dp
		store = &lostMarkerClearStore{LeaseStore: d.Leases}
		d.Leases = store
		deps = *d
	})
	host.now = h.clock.Now
	return h, deps, store
}

// A marker-clearing write that committed before its response was lost must
// not leave the refused client without its stored marker: a restart restores
// the renew bypass and the client's retry is accepted (Codex #2336 round 19).
func TestRenew_ALostMarkerClearResponseKeepsTheRenewBypassAcrossARestart(t *testing.T) {
	ctx := context.Background()
	h, deps, store := lostClearHarness(t)
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	store.lose.Store(true)
	_, err = h.svc.Renew(ctx, lease.ID, renewalEvidence(t, h))
	var unavailable *ErrLeaseStoreUnavailable
	require.ErrorAs(t, err, &unavailable, "a renewal whose clear response was lost is refused")
	stored, err := store.Get(ctx, lease.ID)
	require.NoError(t, err)
	require.True(t, stored.ClientExpiresAt.Equal(lease.ExpiresAt), "the refusal's marker is stored again")

	store.lose.Store(false)
	require.NoError(t, restartWith(t, h, deps))
	renewed, err := h.svc.Renew(ctx, lease.ID, renewalEvidence(t, h))
	require.NoError(t, err, "the restored service keeps the client's renew bypass")
	require.True(t, renewed.ExpiresAt.After(lease.ExpiresAt))
	stored, err = store.Get(ctx, lease.ID)
	require.NoError(t, err)
	assert.True(t, stored.ClientExpiresAt.IsZero(), "the accepted retry clears the marker")
}

// When the marker cannot be stored again either, the renewal reads the store
// back and reports the renewal done when the store holds the clear, so the
// client's deadline matches the record (Codex #2336 round 19).
func TestRenew_AnUnknownMarkerClearIsResolvedByReadingTheStore(t *testing.T) {
	ctx := context.Background()
	h, _, store := lostClearHarness(t)
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	store.lose.Store(true)
	store.failRemark.Store(true)
	renewed, err := h.svc.Renew(ctx, lease.ID, renewalEvidence(t, h))
	require.NoError(t, err, "the store holds the clear: the renewal is done")
	require.True(t, renewed.ExpiresAt.After(lease.ExpiresAt))
	stored, err := store.Get(ctx, lease.ID)
	require.NoError(t, err)
	assert.True(t, stored.ClientExpiresAt.IsZero())
	assert.True(t, stored.ExpiresAt.Equal(renewed.ExpiresAt))
}

// TestPlaneHost_ADelayedRenewalOfARemovedLeaseDoesNotExtendItsReplacement:
// lease A's renewal, delayed past A's removal, must not extend replacement
// lease B, which reuses A's key; B keeps its own deadline (Codex #2336 round 17).
func TestPlaneHost_ADelayedRenewalOfARemovedLeaseDoesNotExtendItsReplacement(t *testing.T) {
	t0 := leaseDeadlineT0
	ctx := context.Background()
	managed := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, managed)
	host.now = func() time.Time { return t0.Add(30 * time.Minute) }
	require.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(time.Hour))))
	require.Nil(t, host.RemoveVPNPeer(ctx, &ipcv1.RemoveVPNPeerRequest{DataPlane: string(DataPlaneMASQUE), LeaseId: "l1"}).GetRefusal())
	require.Nil(t, installHosted(t, host, deadlinePeer("l2", t0.Add(time.Hour))), "the replacement reuses the key")

	resp := host.RenewVPNPeer(ctx, &ipcv1.RenewVPNPeerRequest{
		DataPlane: string(DataPlaneMASQUE), LeaseId: "l1",
		PublicKey:         bytesOf(0xab, 32),
		ExpiresAtUnixNano: t0.Add(3 * time.Hour).UnixNano(),
	})
	require.NotNil(t, resp.GetRefusal(), "the removed lease's renewal is refused")
	assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_LEASE_NOT_FOUND, resp.GetRefusal().GetClass())

	require.NoError(t, host.ExpirePeers(ctx, t0.Add(time.Hour)))
	assert.Equal(t, 0, managed.count(), "the replacement keeps its own deadline")
}

// TestPlaneHost_ACancelledRenewalLeavesTheDeadline: a renewal whose context is
// cancelled extends nothing (Codex #2336 round 17).
func TestPlaneHost_ACancelledRenewalLeavesTheDeadline(t *testing.T) {
	t0 := leaseDeadlineT0
	ctx := context.Background()
	managed := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, managed)
	host.now = func() time.Time { return t0.Add(30 * time.Minute) }
	require.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(time.Hour))))

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	resp := host.RenewVPNPeer(cctx, &ipcv1.RenewVPNPeerRequest{
		DataPlane: string(DataPlaneMASQUE), LeaseId: "l1",
		PublicKey:         bytesOf(0xab, 32),
		ExpiresAtUnixNano: t0.Add(2 * time.Hour).UnixNano(),
	})
	require.NotNil(t, resp.GetRefusal())
	assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE, resp.GetRefusal().GetClass())

	require.NoError(t, host.ExpirePeers(ctx, t0.Add(time.Hour)))
	assert.Equal(t, 0, managed.count(), "the old deadline stands")
}
