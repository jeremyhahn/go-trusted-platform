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

	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
)

// PlaneHost is the datapath child's side of the DataPlane seam (#557): it
// owns the planes this build offers and applies the DatapathService peer
// RPCs to them. A plane's refusal is returned in the response as a typed
// VPNPeerRefusal, so the caller rebuilds the same error.
type PlaneHost struct {
	planes map[DataPlaneKind]ManagedDataPlane
	order  []ManagedDataPlane
}

// NewPlaneHost hosts planes, at most one per kind, each a kind this build
// offers: a FIPS build cannot host WireGuard.
func NewPlaneHost(planes ...ManagedDataPlane) (*PlaneHost, error) {
	if len(planes) == 0 {
		return nil, &ErrInvalidConfig{Field: "data-planes", Reason: "the datapath hosts no data plane"}
	}
	h := &PlaneHost{planes: make(map[DataPlaneKind]ManagedDataPlane, len(planes))}
	for _, plane := range planes {
		if plane == nil {
			return nil, &ErrDepsMissing{Dep: "DataPlane"}
		}
		kind := plane.Kind()
		if !kind.Known() {
			return nil, &ErrInvalidConfig{Field: "data-planes", Reason: "data plane " + string(kind) + " is not offered by this build"}
		}
		if _, dup := h.planes[kind]; dup {
			return nil, &ErrInvalidConfig{Field: "data-planes", Reason: "data plane " + string(kind) + " is hosted twice"}
		}
		h.planes[kind] = plane
		h.order = append(h.order, plane)
	}
	return h, nil
}

// Start starts the planes in order. When one fails, the planes already
// started are stopped again and both errors are returned.
func (h *PlaneHost) Start(ctx context.Context) error {
	for i, plane := range h.order {
		if err := plane.Start(ctx); err != nil {
			return errors.Join(err, stopHostedPlanes(ctx, h.order[:i]))
		}
	}
	return nil
}

// Stop stops the planes in reverse order and joins their errors.
func (h *PlaneHost) Stop(ctx context.Context) error {
	return stopHostedPlanes(ctx, h.order)
}

// InstallVPNPeer installs the request's peer on the plane it names.
func (h *PlaneHost) InstallVPNPeer(ctx context.Context, req *ipcv1.InstallVPNPeerRequest) *ipcv1.InstallVPNPeerResponse {
	return &ipcv1.InstallVPNPeerResponse{Refusal: refusalOf(h.install(ctx, req.GetPeer()))}
}

// RemoveVPNPeer removes the request's lease from the plane it names.
func (h *PlaneHost) RemoveVPNPeer(ctx context.Context, req *ipcv1.RemoveVPNPeerRequest) *ipcv1.RemoveVPNPeerResponse {
	return &ipcv1.RemoveVPNPeerResponse{Refusal: refusalOf(h.remove(ctx, req))}
}

func (h *PlaneHost) install(ctx context.Context, peer *ipcv1.VPNPeer) error {
	lease, err := leaseFromPeer(peer)
	if err != nil {
		return err
	}
	plane, err := h.plane(lease.DataPlane)
	if err != nil {
		return err
	}
	return plane.InstallPeer(ctx, lease)
}

func (h *PlaneHost) remove(ctx context.Context, req *ipcv1.RemoveVPNPeerRequest) error {
	if req.GetLeaseId() == "" {
		return &ErrInvalidRequest{Field: "lease_id", Reason: "required"}
	}
	plane, err := h.plane(DataPlaneKind(req.GetDataPlane()))
	if err != nil {
		return err
	}
	return plane.RemovePeer(ctx, LeaseID(req.GetLeaseId()))
}

func (h *PlaneHost) plane(kind DataPlaneKind) (ManagedDataPlane, error) {
	plane, ok := h.planes[kind]
	if !ok {
		return nil, &ErrDataPlaneUnavailable{Kind: kind, Reason: "the datapath process does not host this data plane"}
	}
	return plane, nil
}

func stopHostedPlanes(ctx context.Context, planes []ManagedDataPlane) error {
	var errs []error
	for i := len(planes) - 1; i >= 0; i-- {
		if err := planes[i].Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// leaseFromPeer rebuilds the lease fields a plane binds a peer with. An
// absent address stays the zero prefix for the plane to refuse.
func leaseFromPeer(peer *ipcv1.VPNPeer) (*Lease, error) {
	if peer == nil {
		return nil, &ErrInvalidRequest{Field: "peer", Reason: "required"}
	}
	if peer.GetLeaseId() == "" {
		return nil, &ErrInvalidRequest{Field: "lease_id", Reason: "required"}
	}
	lease := &Lease{
		ID:        LeaseID(peer.GetLeaseId()),
		DataPlane: DataPlaneKind(peer.GetDataPlane()),
		Keys: PeerKeys{
			WireGuardPublicKey:      peer.GetWireguardPublicKey(),
			ClientCertificateSHA256: peer.GetClientCertificateSha256(),
		},
	}
	if peer.GetAddress() != "" {
		address, err := netip.ParsePrefix(peer.GetAddress())
		if err != nil {
			return nil, &ErrInvalidRequest{Field: "address", Reason: err.Error()}
		}
		lease.Address = address
	}
	return lease, nil
}

// refusalOf is the wire form of a plane error; nil for success. An error
// outside the vocabulary is UNAVAILABLE carrying its text.
// ErrDataPlaneUnavailable is matched first because it is the one type that
// wraps a cause.
func refusalOf(err error) *ipcv1.VPNPeerRefusal {
	if err == nil {
		return nil
	}
	var (
		unavailable *ErrDataPlaneUnavailable
		invalid     *ErrInvalidRequest
		badKey      *ErrPeerKeyInvalid
		conflict    *ErrPeerConflict
		notStarted  *ErrDataPlaneNotStarted
		notFound    *ErrLeaseNotFound
	)
	switch {
	case errors.As(err, &unavailable):
		reason := unavailable.Reason
		if unavailable.Cause != nil {
			reason = unavailable.Cause.Error()
		}
		return &ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE, Reason: reason}
	case errors.As(err, &invalid):
		return &ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_INVALID_REQUEST, Field: invalid.Field, Reason: invalid.Reason}
	case errors.As(err, &badKey):
		return &ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_PEER_KEY_INVALID, Reason: badKey.Reason}
	case errors.As(err, &conflict):
		return &ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_PEER_CONFLICT,
			ExistingLeaseId: string(conflict.Existing), Reason: conflict.Reason}
	case errors.As(err, &notStarted):
		return &ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_NOT_STARTED}
	case errors.As(err, &notFound):
		return &ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_LEASE_NOT_FOUND}
	default:
		return &ipcv1.VPNPeerRefusal{Class: ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE, Reason: err.Error()}
	}
}
