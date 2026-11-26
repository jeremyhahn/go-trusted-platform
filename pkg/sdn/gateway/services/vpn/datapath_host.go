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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
)

// planeHostExpiryTick is how often a started PlaneHost removes the peers
// whose lease deadline has passed. A variable so tests can shorten it.
var planeHostExpiryTick = time.Second

// hostedPeer is a peer the host installed with a lease deadline.
type hostedPeer struct {
	kind DataPlaneKind
	// peer is the installed peer with its deadline zeroed, so a re-install
	// that differs only in the deadline is recognised as a deadline move.
	peer     *ipcv1.VPNPeer
	deadline time.Time
}

// PlaneHost is the datapath child's side of the DataPlane seam (#557): it
// owns the planes this build offers and applies the DatapathService peer
// RPCs to them. A plane's refusal is returned in the response as a typed
// VPNPeerRefusal, so the caller rebuilds the same error.
type PlaneHost struct {
	planes map[DataPlaneKind]ManagedDataPlane
	order  []ManagedDataPlane

	// mu guards held and the expiry loop. The host removes a peer once its
	// lease deadline passes, also while the admission service or its lease
	// store is unavailable (docs/vpn/architecture.md, lease expiry).
	mu     sync.Mutex
	held   map[LeaseID]hostedPeer
	now    func() time.Time
	cancel context.CancelFunc
	done   chan struct{}
}

// NewPlaneHost hosts planes, at most one per kind, each a kind this build
// offers: a FIPS build cannot host WireGuard.
func NewPlaneHost(planes ...ManagedDataPlane) (*PlaneHost, error) {
	if len(planes) == 0 {
		return nil, &ErrInvalidConfig{Field: "data-planes", Reason: "the datapath hosts no data plane"}
	}
	h := &PlaneHost{
		planes: make(map[DataPlaneKind]ManagedDataPlane, len(planes)),
		held:   make(map[LeaseID]hostedPeer),
		now:    time.Now,
	}
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
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cancel != nil {
		return nil
	}
	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	h.cancel, h.done = cancel, done
	go h.expireLoop(loopCtx, done)
	return nil
}

// expireLoop removes, every planeHostExpiryTick, each held peer whose lease
// deadline has passed, until ctx is cancelled.
func (h *PlaneHost) expireLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(planeHostExpiryTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := h.ExpirePeers(ctx, time.Now()); err != nil {
				slog.Default().Warn("vpn.plane.peer.expire.failed", "error", err)
			}
		}
	}
}

// ExpirePeers removes every held peer whose lease deadline is not after now,
// through its plane's RemovePeer, so a plane's own state (the hub's
// forwarding accepts) goes with the peer. It needs neither the admission
// service nor its lease store. A peer whose removal fails stays held and is
// retried by the next call.
func (h *PlaneHost) ExpirePeers(ctx context.Context, now time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var errs []error
	for id, held := range h.held {
		if now.Before(held.deadline) {
			continue
		}
		plane, err := h.plane(held.kind)
		if err == nil {
			err = plane.RemovePeer(ctx, id)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		delete(h.held, id)
		slog.Default().Info("vpn.plane.peer.expire", "lease_id", string(id), "data_plane", string(held.kind))
	}
	return errors.Join(errs...)
}

// Stop stops the planes in reverse order and joins their errors.
func (h *PlaneHost) Stop(ctx context.Context) error {
	h.mu.Lock()
	cancel, done := h.cancel, h.done
	h.cancel, h.done = nil, nil
	h.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	err := stopHostedPlanes(ctx, h.order)
	h.mu.Lock()
	clear(h.held)
	h.mu.Unlock()
	return err
}

// InstallVPNPeer installs the request's peer on the plane it names.
func (h *PlaneHost) InstallVPNPeer(ctx context.Context, req *ipcv1.InstallVPNPeerRequest) *ipcv1.InstallVPNPeerResponse {
	return &ipcv1.InstallVPNPeerResponse{Refusal: refusalOf(h.install(ctx, req.GetPeer()))}
}

// RemoveVPNPeer removes the request's lease from the plane it names.
func (h *PlaneHost) RemoveVPNPeer(ctx context.Context, req *ipcv1.RemoveVPNPeerRequest) *ipcv1.RemoveVPNPeerResponse {
	return &ipcv1.RemoveVPNPeerResponse{Refusal: refusalOf(h.remove(ctx, req))}
}

// RenewVPNPeer moves the deadline of the held peer whose key is the
// request's public key (its WireGuard key, or its client certificate
// SHA-256 for a plane without one). It never installs: a peer the host no
// longer holds, or whose deadline has passed, is LEASE_NOT_FOUND, so a
// renewal that arrives after expiry cannot bring the peer back. The deadline
// only moves forward: a deadline earlier than the held one is accepted and
// ignored, so a delayed or reordered request cannot shorten it.
func (h *PlaneHost) RenewVPNPeer(_ context.Context, req *ipcv1.RenewVPNPeerRequest) *ipcv1.RenewVPNPeerResponse {
	return &ipcv1.RenewVPNPeerResponse{Refusal: refusalOf(h.renew(req))}
}

// renew moves the held deadline forward to the request's, and accepts a
// lower deadline as a no-op (see RenewVPNPeer).
func (h *PlaneHost) renew(req *ipcv1.RenewVPNPeerRequest) error {
	if len(req.GetPublicKey()) == 0 {
		return &ErrInvalidRequest{Field: "public_key", Reason: "required"}
	}
	if req.GetExpiresAtUnixNano() <= 0 {
		return &ErrInvalidRequest{Field: "expires_at_unix_nano", Reason: "required"}
	}
	deadline := time.Unix(0, req.GetExpiresAtUnixNano())

	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	var (
		match LeaseID
		found int
	)
	for id, held := range h.held {
		if bytes.Equal(held.peer.GetWireguardPublicKey(), req.GetPublicKey()) ||
			(len(held.peer.GetWireguardPublicKey()) == 0 && bytes.Equal(held.peer.GetClientCertificateSha256(), req.GetPublicKey())) {
			match = id
			found++
		}
	}
	if found != 1 {
		// None held, or a key that names more than one peer: the old
		// deadline stands (fail closed).
		return &ErrLeaseNotFound{LeaseID: match}
	}
	held := h.held[match]
	if !now.Before(held.deadline) {
		return &ErrLeaseNotFound{LeaseID: match}
	}
	if deadline.After(held.deadline) {
		held.deadline = deadline
		h.held[match] = held
	}
	return nil
}

// ReconcileVPNPeers removes from the plane the request names every peer
// whose lease is not in the request: the plane outlives a vpn child that
// died between a revoke's record deletion and its peer removal. The vpn
// child sends it at Restore, with its stored leases, and again from Sweep
// while a failed reconciliation is owed. It is the bulk form of
// RemoveVPNPeer, under the same admission, and touches only the one plane
// it names. A request with no data plane, or with an empty or repeated
// lease id, is refused as INVALID_REQUEST before any plane is reached.
func (h *PlaneHost) ReconcileVPNPeers(ctx context.Context, req *ipcv1.ReconcileVPNPeersRequest) *ipcv1.ReconcileVPNPeersResponse {
	return &ipcv1.ReconcileVPNPeersResponse{Refusal: refusalOf(h.reconcile(ctx, req))}
}

func (h *PlaneHost) reconcile(ctx context.Context, req *ipcv1.ReconcileVPNPeersRequest) error {
	kind := DataPlaneKind(req.GetDataPlane())
	if kind == "" {
		return &ErrInvalidRequest{Field: "data_plane", Reason: "required"}
	}
	keep := make([]LeaseID, 0, len(req.GetLeaseIds()))
	seen := make(map[string]bool, len(req.GetLeaseIds()))
	for _, id := range req.GetLeaseIds() {
		if id == "" {
			return &ErrInvalidRequest{Field: "lease_ids", Reason: "a lease id is empty"}
		}
		if seen[id] {
			return &ErrInvalidRequest{Field: "lease_ids", Reason: "lease id " + id + " is repeated"}
		}
		seen[id] = true
		keep = append(keep, LeaseID(id))
	}
	plane, err := h.plane(kind)
	if err != nil {
		// A plane this process does not host holds no peer, so withdrawing
		// every peer of it is already done. Keeping a peer still refuses.
		if len(keep) == 0 {
			return nil
		}
		return err
	}
	r, ok := plane.(PeerReconciler)
	if !ok {
		return &ErrDataPlaneUnavailable{Kind: kind, Cause: errors.New("the plane cannot reconcile its peers")}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := r.ReconcilePeers(ctx, keep); err != nil {
		// The held deadlines stay, so expiry still removes those peers.
		return err
	}
	for id, held := range h.held {
		if held.kind == kind && !seen[string(id)] {
			delete(h.held, id)
		}
	}
	return nil
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
	bare := proto.Clone(peer).(*ipcv1.VPNPeer)
	bare.ExpiresAtUnixNano = 0

	h.mu.Lock()
	defer h.mu.Unlock()
	if held, ok := h.held[lease.ID]; ok && held.kind == lease.DataPlane && proto.Equal(held.peer, bare) {
		// The same peer again is a renewal: only its deadline moves, and
		// the plane is not touched, so a live session is kept.
		if !lease.ExpiresAt.IsZero() {
			held.deadline = lease.ExpiresAt
			h.held[lease.ID] = held
		}
		return nil
	}
	if err := plane.InstallPeer(ctx, lease); err != nil {
		return err
	}
	if lease.ExpiresAt.IsZero() {
		// A peer without a deadline is not tracked; the hub plane refuses
		// one outright.
		delete(h.held, lease.ID)
		return nil
	}
	h.held[lease.ID] = hostedPeer{kind: lease.DataPlane, peer: bare, deadline: lease.ExpiresAt}
	return nil
}

func (h *PlaneHost) remove(ctx context.Context, req *ipcv1.RemoveVPNPeerRequest) error {
	if req.GetLeaseId() == "" {
		return &ErrInvalidRequest{Field: "lease_id", Reason: "required"}
	}
	plane, err := h.plane(DataPlaneKind(req.GetDataPlane()))
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := plane.RemovePeer(ctx, LeaseID(req.GetLeaseId())); err != nil {
		return err
	}
	delete(h.held, LeaseID(req.GetLeaseId()))
	return nil
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
	if zones := peer.GetZones(); len(zones) > 0 {
		lease.Zones = append([]string(nil), zones...)
	}
	if n := peer.GetExpiresAtUnixNano(); n > 0 {
		lease.ExpiresAt = time.Unix(0, n).UTC()
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
