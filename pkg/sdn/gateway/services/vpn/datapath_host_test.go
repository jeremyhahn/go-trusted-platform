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
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
)

// managedFakePlane is the fakePlane with a lifecycle, recording Start and
// Stop into a log shared by the planes of one host.
type managedFakePlane struct {
	*fakePlane
	log      *[]string
	startErr error
	stopErr  error
}

func newManagedFakePlane(kind DataPlaneKind, log *[]string) *managedFakePlane {
	return &managedFakePlane{fakePlane: newFakePlane(kind), log: log}
}

func (p *managedFakePlane) Start(context.Context) error {
	*p.log = append(*p.log, "start "+string(p.kind))
	return p.startErr
}

func (p *managedFakePlane) Stop(context.Context) error {
	*p.log = append(*p.log, "stop "+string(p.kind))
	return p.stopErr
}

func masquePeer(id string) *ipcv1.VPNPeer {
	return &ipcv1.VPNPeer{
		LeaseId:                 id,
		DataPlane:               string(DataPlaneMASQUE),
		Address:                 "100.64.0.7/32",
		ClientCertificateSha256: bytesOf(0xab, 32),
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func hostOf(t *testing.T, planes ...ManagedDataPlane) *PlaneHost {
	t.Helper()
	host, err := NewPlaneHost(planes...)
	require.NoError(t, err)
	return host
}

func TestPlaneHost_InstallAndRemoveReachThePlane(t *testing.T) {
	var log []string
	plane := newManagedFakePlane(DataPlaneMASQUE, &log)
	host := hostOf(t, plane)
	ctx := context.Background()

	peer := masquePeer("l1")
	peer.WireguardPublicKey = bytesOf(0x01, 32)
	resp := host.InstallVPNPeer(ctx, &ipcv1.InstallVPNPeerRequest{Peer: peer})
	require.Nil(t, resp.GetRefusal())

	installed := plane.installed["l1"]
	require.NotNil(t, installed)
	assert.Equal(t, DataPlaneMASQUE, installed.DataPlane)
	assert.Equal(t, netip.MustParsePrefix("100.64.0.7/32"), installed.Address)
	assert.Equal(t, bytesOf(0xab, 32), installed.Keys.ClientCertificateSHA256)
	assert.Equal(t, bytesOf(0x01, 32), installed.Keys.WireGuardPublicKey)

	removed := host.RemoveVPNPeer(ctx, &ipcv1.RemoveVPNPeerRequest{DataPlane: string(DataPlaneMASQUE), LeaseId: "l1"})
	require.Nil(t, removed.GetRefusal())
	assert.Equal(t, []LeaseID{"l1"}, plane.removed)
	assert.Zero(t, plane.count())
}

// TestPlaneHost_AnOlderDuplicateInstallKeepsTheRenewedDeadline: a replayed
// install of the same peer (Restore) carries an older deadline than a renewal
// the host already applied; the deadline must not move back.
func TestPlaneHost_AnOlderDuplicateInstallKeepsTheRenewedDeadline(t *testing.T) {
	t0 := leaseDeadlineT0
	ctx := context.Background()
	plane := newManagedFakePlane(DataPlaneMASQUE, new([]string))
	host := hostOf(t, plane)
	host.now = func() time.Time { return t0.Add(30 * time.Minute) }
	require.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(time.Hour))))

	require.Nil(t, host.RenewVPNPeer(ctx, &ipcv1.RenewVPNPeerRequest{
		DataPlane: string(DataPlaneMASQUE), LeaseId: "l1",
		PublicKey:         bytesOf(0xab, 32),
		ExpiresAtUnixNano: t0.Add(2 * time.Hour).UnixNano(),
	}).GetRefusal())
	require.Nil(t, installHosted(t, host, deadlinePeer("l1", t0.Add(time.Hour))),
		"the same peer again is accepted")

	require.NoError(t, host.ExpirePeers(ctx, t0.Add(90*time.Minute)))
	assert.Equal(t, 1, plane.count(), "the older duplicate install did not shorten the renewed deadline")
	assert.Empty(t, plane.removed)
	require.NoError(t, host.ExpirePeers(ctx, t0.Add(2*time.Hour)))
	assert.Equal(t, 0, plane.count())
}

func TestPlaneHost_RefusesBadInputAsInvalidRequest(t *testing.T) {
	var log []string
	plane := newManagedFakePlane(DataPlaneMASQUE, &log)
	host := hostOf(t, plane)
	ctx := context.Background()

	noID := masquePeer("")
	badAddress := masquePeer("l1")
	badAddress.Address = "not-a-prefix"
	cases := map[string]struct {
		refusal *ipcv1.VPNPeerRefusal
		field   string
	}{
		"no peer":      {host.InstallVPNPeer(ctx, &ipcv1.InstallVPNPeerRequest{}).GetRefusal(), "peer"},
		"no lease id":  {host.InstallVPNPeer(ctx, &ipcv1.InstallVPNPeerRequest{Peer: noID}).GetRefusal(), "lease_id"},
		"bad address":  {host.InstallVPNPeer(ctx, &ipcv1.InstallVPNPeerRequest{Peer: badAddress}).GetRefusal(), "address"},
		"remove no id": {host.RemoveVPNPeer(ctx, &ipcv1.RemoveVPNPeerRequest{DataPlane: string(DataPlaneMASQUE)}).GetRefusal(), "lease_id"},
		"reconcile no plane": {host.ReconcileVPNPeers(ctx,
			&ipcv1.ReconcileVPNPeersRequest{LeaseIds: []string{"l1"}}).GetRefusal(), "data_plane"},
		"reconcile empty id": {host.ReconcileVPNPeers(ctx,
			&ipcv1.ReconcileVPNPeersRequest{DataPlane: string(DataPlaneMASQUE), LeaseIds: []string{"l1", ""}}).GetRefusal(), "lease_ids"},
		"reconcile duplicate id": {host.ReconcileVPNPeers(ctx,
			&ipcv1.ReconcileVPNPeersRequest{DataPlane: string(DataPlaneMASQUE), LeaseIds: []string{"l1", "l1"}}).GetRefusal(), "lease_ids"},
	}
	for name, c := range cases {
		assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_INVALID_REQUEST, c.refusal.GetClass(), name)
		assert.Equal(t, c.field, c.refusal.GetField(), name)
		assert.NotEmpty(t, c.refusal.GetReason(), name)
	}
	assert.Zero(t, plane.count(), "a refused request must not reach the plane")
	assert.Empty(t, plane.removed)
	assert.Empty(t, plane.reconciles, "a refused reconciliation must not reach the plane")
}

func TestPlaneHost_RefusesAPlaneItDoesNotHost(t *testing.T) {
	var log []string
	host := hostOf(t, newManagedFakePlane(DataPlaneMASQUE, &log))
	ctx := context.Background()

	peer := masquePeer("l1")
	peer.DataPlane = "quic"
	install := host.InstallVPNPeer(ctx, &ipcv1.InstallVPNPeerRequest{Peer: peer}).GetRefusal()
	assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE, install.GetClass())
	assert.Contains(t, install.GetReason(), "does not host")

	remove := host.RemoveVPNPeer(ctx, &ipcv1.RemoveVPNPeerRequest{DataPlane: "quic", LeaseId: "l1"}).GetRefusal()
	assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE, remove.GetClass())
}

// TestPlaneHost_WithdrawingEveryPeerOfAPlaneItDoesNotHostSucceeds pins
// finding 2: a plane the host does not have holds no peer, so withdrawing all
// of them is already done; keeping a peer of it is still refused.
func TestPlaneHost_WithdrawingEveryPeerOfAPlaneItDoesNotHostSucceeds(t *testing.T) {
	var log []string
	host := hostOf(t, newManagedFakePlane(DataPlaneMASQUE, &log))
	ctx := context.Background()

	withdrawn := host.ReconcileVPNPeers(ctx, &ipcv1.ReconcileVPNPeersRequest{DataPlane: "quic"})
	assert.Nil(t, withdrawn.GetRefusal(), "withdrawing every peer of an unhosted plane succeeds")

	kept := host.ReconcileVPNPeers(ctx, &ipcv1.ReconcileVPNPeersRequest{DataPlane: "quic", LeaseIds: []string{"l1"}}).GetRefusal()
	assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE, kept.GetClass())
}

func TestPlaneHost_RefusesAnUnknownPeerAsLeaseNotFound(t *testing.T) {
	var log []string
	plane := newManagedFakePlane(DataPlaneMASQUE, &log)
	plane.removeErr = &ErrLeaseNotFound{LeaseID: "l9"}
	host := hostOf(t, plane)

	refusal := host.RemoveVPNPeer(context.Background(),
		&ipcv1.RemoveVPNPeerRequest{DataPlane: string(DataPlaneMASQUE), LeaseId: "l9"}).GetRefusal()
	assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_LEASE_NOT_FOUND, refusal.GetClass())
}

func TestPlaneHost_CarriesEveryPlaneErrorTyped(t *testing.T) {
	cases := map[string]struct {
		err  error
		want *ipcv1.VPNPeerRefusal
	}{
		"invalid request": {
			&ErrInvalidRequest{Field: "lease", Reason: "required"},
			&ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_INVALID_REQUEST, Field: "lease", Reason: "required"},
		},
		"peer key invalid": {
			&ErrPeerKeyInvalid{Kind: DataPlaneMASQUE, Reason: "no fingerprint"},
			&ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_PEER_KEY_INVALID, Reason: "no fingerprint"},
		},
		"peer conflict": {
			&ErrPeerConflict{Kind: DataPlaneMASQUE, LeaseID: "l1", Existing: "l0", Reason: "the address is already bound"},
			&ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_PEER_CONFLICT,
				ExistingLeaseId: "l0", Reason: "the address is already bound"},
		},
		"not started": {
			&ErrDataPlaneNotStarted{Kind: DataPlaneMASQUE},
			&ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_NOT_STARTED},
		},
		"lease not found": {
			&ErrLeaseNotFound{LeaseID: "l1"},
			&ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_LEASE_NOT_FOUND},
		},
		"unavailable with a cause": {
			&ErrDataPlaneUnavailable{Kind: DataPlaneMASQUE, Cause: errors.New("session close: broken pipe")},
			&ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE, Reason: "session close: broken pipe"},
		},
		"unavailable with a reason": {
			&ErrDataPlaneUnavailable{Kind: DataPlaneMASQUE, Reason: "draining"},
			&ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE, Reason: "draining"},
		},
		"untyped kernel error": {
			errors.New("netlink: operation not permitted"),
			&ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE, Reason: "netlink: operation not permitted"},
		},
	}
	for name, c := range cases {
		var log []string
		plane := newManagedFakePlane(DataPlaneMASQUE, &log)
		plane.installErr = c.err
		host := hostOf(t, plane)

		got := host.InstallVPNPeer(context.Background(), &ipcv1.InstallVPNPeerRequest{Peer: masquePeer("l1")}).GetRefusal()
		require.NotNil(t, got, name)
		assert.Equal(t, c.want.GetClass(), got.GetClass(), name)
		assert.Equal(t, c.want.GetField(), got.GetField(), name)
		assert.Equal(t, c.want.GetReason(), got.GetReason(), name)
		assert.Equal(t, c.want.GetExistingLeaseId(), got.GetExistingLeaseId(), name)
	}
}

func TestPlaneHost_CarriesARealPlanesRefusals(t *testing.T) {
	pki := newTestPKI(t)
	plane, err := NewMASQUEPlane(MASQUEConfig{
		Template: "https://localhost:4433/.well-known/masque/ip/",
		TLS:      pki.serverTLS(),
		Routes:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}, newFakeDevice(), nil)
	require.NoError(t, err)
	host := hostOf(t, plane)
	ctx := context.Background()

	noPrint := masquePeer("l1")
	noPrint.ClientCertificateSha256 = nil
	refusal := host.InstallVPNPeer(ctx, &ipcv1.InstallVPNPeerRequest{Peer: noPrint}).GetRefusal()
	assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_PEER_KEY_INVALID, refusal.GetClass())

	refusal = host.InstallVPNPeer(ctx, &ipcv1.InstallVPNPeerRequest{Peer: masquePeer("l1")}).GetRefusal()
	assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_NOT_STARTED, refusal.GetClass(),
		"a plane the child has not started refuses, it does not queue")

	removed := host.RemoveVPNPeer(ctx, &ipcv1.RemoveVPNPeerRequest{DataPlane: string(DataPlaneMASQUE), LeaseId: "l1"})
	assert.Nil(t, removed.GetRefusal(), "removing a peer the plane does not hold succeeds")
}

func TestNewPlaneHost_Refusals(t *testing.T) {
	var log []string
	var cfgErr *ErrInvalidConfig
	var deps *ErrDepsMissing

	_, err := NewPlaneHost()
	assert.True(t, errors.As(err, &cfgErr), "a host with no plane: %v", err)

	_, err = NewPlaneHost(nil)
	assert.True(t, errors.As(err, &deps), "a nil plane: %v", err)

	_, err = NewPlaneHost(newManagedFakePlane(DataPlaneMASQUE, &log), newManagedFakePlane(DataPlaneMASQUE, &log))
	require.True(t, errors.As(err, &cfgErr), "a kind hosted twice: %v", err)
	assert.Contains(t, cfgErr.Reason, "twice")

	_, err = NewPlaneHost(newManagedFakePlane("quic", &log))
	require.True(t, errors.As(err, &cfgErr), "an unknown kind: %v", err)
	assert.Contains(t, cfgErr.Reason, "not offered by this build")
}

func TestPlaneHost_StartAndStop(t *testing.T) {
	var log []string
	plane := newManagedFakePlane(DataPlaneMASQUE, &log)
	host := hostOf(t, plane)
	ctx := context.Background()

	require.NoError(t, host.Start(ctx))
	require.NoError(t, host.Stop(ctx))
	assert.Equal(t, []string{"start masque", "stop masque"}, log)

	plane.startErr = errors.New("bind: address in use")
	plane.stopErr = errors.New("device busy")
	assert.ErrorIs(t, host.Start(ctx), plane.startErr)
	assert.ErrorIs(t, host.Stop(ctx), plane.stopErr)
}
