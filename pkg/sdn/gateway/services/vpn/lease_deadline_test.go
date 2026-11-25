// Copyright (c) 2026 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package vpn

import (
	"context"
	"errors"
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
			PublicKey:         bytesOf(0xab, 32),
			ExpiresAtUnixNano: t0.Add(2 * time.Hour).UnixNano(),
		}).GetRefusal())
		require.NoError(t, host.ExpirePeers(ctx, t0.Add(time.Hour)))
		assert.Equal(t, 1, managed.count())
		require.NoError(t, host.ExpirePeers(ctx, t0.Add(2*time.Hour)))
		assert.Equal(t, 0, managed.count())
	})
}
