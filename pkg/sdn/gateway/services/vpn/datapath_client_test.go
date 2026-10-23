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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
)

// hostPeers reaches a PlaneHost in-process, the way the IPC client reaches
// the datapath child's; err stands for an RPC that never got an answer.
type hostPeers struct {
	host *PlaneHost
	err  error
}

func (p *hostPeers) InstallVPNPeer(ctx context.Context, req *ipcv1.InstallVPNPeerRequest) (*ipcv1.InstallVPNPeerResponse, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.host.InstallVPNPeer(ctx, req), nil
}

func (p *hostPeers) RemoveVPNPeer(ctx context.Context, req *ipcv1.RemoveVPNPeerRequest) (*ipcv1.RemoveVPNPeerResponse, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.host.RemoveVPNPeer(ctx, req), nil
}

// refusingPeers answers every RPC with refusal.
type refusingPeers struct{ refusal *ipcv1.VPNPeerRefusal }

func (p *refusingPeers) InstallVPNPeer(context.Context, *ipcv1.InstallVPNPeerRequest) (*ipcv1.InstallVPNPeerResponse, error) {
	return &ipcv1.InstallVPNPeerResponse{Refusal: p.refusal}, nil
}

func (p *refusingPeers) RemoveVPNPeer(context.Context, *ipcv1.RemoveVPNPeerRequest) (*ipcv1.RemoveVPNPeerResponse, error) {
	return &ipcv1.RemoveVPNPeerResponse{Refusal: p.refusal}, nil
}

func clientLease(id LeaseID) *Lease {
	return &Lease{
		ID:        id,
		DataPlane: DataPlaneMASQUE,
		Address:   netip.MustParsePrefix("100.64.0.7/32"),
		Keys:      PeerKeys{ClientCertificateSHA256: bytesOf(0xab, 32)},
	}
}

// datapathOf is a MASQUE DatapathPlane forwarding to a host of plane.
func datapathOf(t *testing.T, plane *managedFakePlane) *DatapathPlane {
	t.Helper()
	p, err := NewDatapathPlane(DataPlaneMASQUE, &hostPeers{host: hostOf(t, plane)})
	require.NoError(t, err)
	return p
}

func TestDatapathPlane_InstallAndRemoveReachTheChildsPlane(t *testing.T) {
	var log []string
	plane := newManagedFakePlane(DataPlaneMASQUE, &log)
	p := datapathOf(t, plane)
	assert.Equal(t, DataPlaneMASQUE, p.Kind())

	require.NoError(t, p.InstallPeer(context.Background(), clientLease("l1")))
	got := plane.installed["l1"]
	require.NotNil(t, got)
	assert.Equal(t, DataPlaneMASQUE, got.DataPlane)
	assert.Equal(t, netip.MustParsePrefix("100.64.0.7/32"), got.Address)
	assert.Equal(t, bytesOf(0xab, 32), got.Keys.ClientCertificateSHA256)

	require.NoError(t, p.RemovePeer(context.Background(), "l1"))
	assert.Equal(t, []LeaseID{"l1"}, plane.removed)
}

func TestDatapathPlane_RefusesANilLeaseWithoutAnRPC(t *testing.T) {
	p, err := NewDatapathPlane(DataPlaneMASQUE, &hostPeers{err: errors.New("must not be called")})
	require.NoError(t, err)

	var invalid *ErrInvalidRequest
	require.ErrorAs(t, p.InstallPeer(context.Background(), nil), &invalid)
	assert.Equal(t, "lease", invalid.Field)
}

func TestDatapathPlane_UnreachableChildIsUnavailable(t *testing.T) {
	cause := errors.New("connection refused")
	p, err := NewDatapathPlane(DataPlaneMASQUE, &hostPeers{err: cause})
	require.NoError(t, err)

	for name, call := range map[string]func() error{
		"install": func() error { return p.InstallPeer(context.Background(), clientLease("l1")) },
		"remove":  func() error { return p.RemovePeer(context.Background(), "l1") },
	} {
		err := call()
		var unavailable *ErrDataPlaneUnavailable
		require.ErrorAs(t, err, &unavailable, name)
		assert.Equal(t, DataPlaneMASQUE, unavailable.Kind, name)
		assert.ErrorIs(t, err, cause, name)
	}
}

// Every plane error the child sends back is the same typed error here.
func TestDatapathPlane_RebuildsEveryPlaneErrorTyped(t *testing.T) {
	cases := map[string]struct {
		planeErr error
		want     error
	}{
		"invalid request": {
			&ErrInvalidRequest{Field: "address", Reason: "required"},
			&ErrInvalidRequest{Field: "address", Reason: "required"},
		},
		"peer key invalid": {
			&ErrPeerKeyInvalid{Kind: DataPlaneMASQUE, Reason: "no fingerprint"},
			&ErrPeerKeyInvalid{Kind: DataPlaneMASQUE, Reason: "no fingerprint"},
		},
		"peer conflict": {
			&ErrPeerConflict{Kind: DataPlaneMASQUE, LeaseID: "l1", Existing: "l0", Reason: "the address is already bound"},
			&ErrPeerConflict{Kind: DataPlaneMASQUE, LeaseID: "l1", Existing: "l0", Reason: "the address is already bound"},
		},
		"not started": {
			&ErrDataPlaneNotStarted{Kind: DataPlaneMASQUE},
			&ErrDataPlaneNotStarted{Kind: DataPlaneMASQUE},
		},
		"lease not found": {
			&ErrLeaseNotFound{LeaseID: "l1"},
			&ErrLeaseNotFound{LeaseID: "l1"},
		},
		"unavailable": {
			&ErrDataPlaneUnavailable{Kind: DataPlaneMASQUE, Reason: "draining"},
			&ErrDataPlaneUnavailable{Kind: DataPlaneMASQUE, Reason: "draining"},
		},
		"untyped kernel error": {
			errors.New("netlink: operation not permitted"),
			&ErrDataPlaneUnavailable{Kind: DataPlaneMASQUE, Reason: "netlink: operation not permitted"},
		},
	}
	for name, c := range cases {
		var log []string
		plane := newManagedFakePlane(DataPlaneMASQUE, &log)
		plane.installErr = c.planeErr
		plane.removeErr = c.planeErr
		p := datapathOf(t, plane)

		assert.Equal(t, c.want, p.InstallPeer(context.Background(), clientLease("l1")), name)
		assert.Equal(t, c.want, p.RemovePeer(context.Background(), "l1"), name)
	}
}

func TestDatapathPlane_UnknownRefusalClassFailsClosed(t *testing.T) {
	for _, class := range []ipcv1.VPNPeerRefusalClass{
		ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNSPECIFIED,
		ipcv1.VPNPeerRefusalClass(99),
	} {
		p, err := NewDatapathPlane(DataPlaneMASQUE, &refusingPeers{refusal: &ipcv1.VPNPeerRefusal{Class: class, Reason: "newer child"}})
		require.NoError(t, err)

		want := &ErrDataPlaneUnavailable{Kind: DataPlaneMASQUE, Reason: "newer child"}
		assert.Equal(t, want, p.InstallPeer(context.Background(), clientLease("l1")), class.String())
		assert.Equal(t, want, p.RemovePeer(context.Background(), "l1"), class.String())
	}
}

func TestNewDatapathPlane_Refusals(t *testing.T) {
	_, err := NewDatapathPlane("ipsec", &refusingPeers{})
	var unavailable *ErrDataPlaneUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, DataPlaneKind("ipsec"), unavailable.Kind)

	_, err = NewDatapathPlane(DataPlaneMASQUE, nil)
	var missing *ErrDepsMissing
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "DatapathPeers", missing.Dep)
}

func TestPeerOf_CarriesTheLease(t *testing.T) {
	lease := clientLease("l1")
	lease.Keys.WireGuardPublicKey = bytesOf(0x01, 32)
	peer := peerOf(DataPlaneMASQUE, lease)
	assert.Equal(t, "l1", peer.GetLeaseId())
	assert.Equal(t, "masque", peer.GetDataPlane())
	assert.Equal(t, "100.64.0.7/32", peer.GetAddress())
	assert.Equal(t, bytesOf(0x01, 32), peer.GetWireguardPublicKey())
	assert.Equal(t, bytesOf(0xab, 32), peer.GetClientCertificateSha256())
}

// A lease without an address goes out without one, for the plane to refuse.
func TestPeerOf_LeavesAnInvalidAddressEmpty(t *testing.T) {
	lease := clientLease("l1")
	lease.Address = netip.Prefix{}
	assert.Empty(t, peerOf(DataPlaneMASQUE, lease).GetAddress())
}

func TestErrorOfRefusal_NoRefusalIsSuccess(t *testing.T) {
	assert.NoError(t, errorOfRefusal(DataPlaneMASQUE, "l1", nil))
}
