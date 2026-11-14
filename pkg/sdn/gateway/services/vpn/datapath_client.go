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

	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
)

// DatapathPeers is the datapath child's VPN peer surface. The gateway IPC
// client (*ipc.Client) satisfies it over the supervisor's socket.
type DatapathPeers interface {
	InstallVPNPeer(ctx context.Context, req *ipcv1.InstallVPNPeerRequest) (*ipcv1.InstallVPNPeerResponse, error)
	RemoveVPNPeer(ctx context.Context, req *ipcv1.RemoveVPNPeerRequest) (*ipcv1.RemoveVPNPeerResponse, error)
	ReconcileVPNPeers(ctx context.Context, req *ipcv1.ReconcileVPNPeersRequest) (*ipcv1.ReconcileVPNPeersResponse, error)
}

// DatapathPlane is the DataPlane of a process that does not own the plane:
// each peer is forwarded to the datapath child that does (#557). It fails
// closed: a child that does not answer is ErrDataPlaneUnavailable, never an
// admit, and a refusal comes back as the plane's own typed error.
type DatapathPlane struct {
	kind  DataPlaneKind
	peers DatapathPeers
}

// NewDatapathPlane is the plane of kind in the child peers reaches. A kind
// this build does not offer is refused: a FIPS build has no WireGuard.
func NewDatapathPlane(kind DataPlaneKind, peers DatapathPeers) (*DatapathPlane, error) {
	if !kind.Known() {
		return nil, &ErrDataPlaneUnavailable{Kind: kind, Reason: "not offered by this build"}
	}
	if peers == nil {
		return nil, &ErrDepsMissing{Dep: "DatapathPeers"}
	}
	return &DatapathPlane{kind: kind, peers: peers}, nil
}

// Kind implements DataPlane.
func (p *DatapathPlane) Kind() DataPlaneKind { return p.kind }

// InstallPeer implements DataPlane through the datapath child.
func (p *DatapathPlane) InstallPeer(ctx context.Context, lease *Lease) error {
	if lease == nil {
		return &ErrInvalidRequest{Field: "lease", Reason: "required"}
	}
	resp, err := p.peers.InstallVPNPeer(ctx, &ipcv1.InstallVPNPeerRequest{Peer: peerOf(p.kind, lease)})
	if err != nil {
		return &ErrDataPlaneUnavailable{Kind: p.kind, Cause: err}
	}
	return errorOfRefusal(p.kind, lease.ID, resp.GetRefusal())
}

// RemovePeer implements DataPlane through the datapath child.
func (p *DatapathPlane) RemovePeer(ctx context.Context, leaseID LeaseID) error {
	resp, err := p.peers.RemoveVPNPeer(ctx, &ipcv1.RemoveVPNPeerRequest{DataPlane: string(p.kind), LeaseId: string(leaseID)})
	if err != nil {
		return &ErrDataPlaneUnavailable{Kind: p.kind, Cause: err}
	}
	return errorOfRefusal(p.kind, leaseID, resp.GetRefusal())
}

// ReconcilePeers asks the datapath child to remove every peer of the plane
// whose lease is not in keep.
func (p *DatapathPlane) ReconcilePeers(ctx context.Context, keep []LeaseID) error {
	ids := make([]string, 0, len(keep))
	for _, id := range keep {
		ids = append(ids, string(id))
	}
	resp, err := p.peers.ReconcileVPNPeers(ctx, &ipcv1.ReconcileVPNPeersRequest{DataPlane: string(p.kind), LeaseIds: ids})
	if err != nil {
		return &ErrDataPlaneUnavailable{Kind: p.kind, Cause: err}
	}
	return errorOfRefusal(p.kind, "", resp.GetRefusal())
}

// peerOf is the wire form of lease for the plane of kind.
func peerOf(kind DataPlaneKind, lease *Lease) *ipcv1.VPNPeer {
	peer := &ipcv1.VPNPeer{
		LeaseId:                 string(lease.ID),
		DataPlane:               string(kind),
		WireguardPublicKey:      lease.Keys.WireGuardPublicKey,
		ClientCertificateSha256: lease.Keys.ClientCertificateSHA256,
	}
	if lease.Address.IsValid() {
		peer.Address = lease.Address.String()
	}
	return peer
}

// refusalDecoder rebuilds the typed error of one refusal class.
type refusalDecoder func(kind DataPlaneKind, leaseID LeaseID, r *ipcv1.VPNPeerRefusal) error

var refusalDecoders = map[ipcv1.VPNPeerRefusalClass]refusalDecoder{
	ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_INVALID_REQUEST: func(_ DataPlaneKind, _ LeaseID, r *ipcv1.VPNPeerRefusal) error {
		return &ErrInvalidRequest{Field: r.GetField(), Reason: r.GetReason()}
	},
	ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_PEER_KEY_INVALID: func(kind DataPlaneKind, _ LeaseID, r *ipcv1.VPNPeerRefusal) error {
		return &ErrPeerKeyInvalid{Kind: kind, Reason: r.GetReason()}
	},
	ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_PEER_CONFLICT: func(kind DataPlaneKind, leaseID LeaseID, r *ipcv1.VPNPeerRefusal) error {
		return &ErrPeerConflict{Kind: kind, LeaseID: leaseID, Existing: LeaseID(r.GetExistingLeaseId()), Reason: r.GetReason()}
	},
	ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_NOT_STARTED: func(kind DataPlaneKind, _ LeaseID, _ *ipcv1.VPNPeerRefusal) error {
		return &ErrDataPlaneNotStarted{Kind: kind}
	},
	ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_LEASE_NOT_FOUND: func(_ DataPlaneKind, leaseID LeaseID, _ *ipcv1.VPNPeerRefusal) error {
		return &ErrLeaseNotFound{LeaseID: leaseID}
	},
	ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE: unavailableRefusal,
}

func unavailableRefusal(kind DataPlaneKind, _ LeaseID, r *ipcv1.VPNPeerRefusal) error {
	return &ErrDataPlaneUnavailable{Kind: kind, Reason: r.GetReason()}
}

// errorOfRefusal is the typed error a refusal stands for; nil for none. A
// class this binary does not know is unavailable, so a newer child's
// refusal is never read as success.
func errorOfRefusal(kind DataPlaneKind, leaseID LeaseID, r *ipcv1.VPNPeerRefusal) error {
	if r == nil {
		return nil
	}
	decode, ok := refusalDecoders[r.GetClass()]
	if !ok {
		decode = unavailableRefusal
	}
	return decode(kind, leaseID, r)
}
