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
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// Restore reinstates the leases the lease store holds after a restart: each
// takes its address back and has its peer programmed into its data plane, so
// a client admitted before the restart keeps its session. A lease that has
// expired, or whose data plane, zones or address this gateway can no longer
// give it, is dropped from the store instead and reported as an
// ErrLeaseNotRestored; the errors of every dropped lease are joined. A
// lease the host expired whose revocation the store could not record was
// re-stored with an elapsed deadline (see oweDeletion), so it is dropped,
// not reinstalled. A restored lease whose client was refused its stored
// deadline (Lease.ClientExpiresAt) gets its renew bypass back; the host is
// asked first whether it still holds such a lease, since the renewal never
// reached it and its expiry marker may be lost, and one it expired is dropped.
//
// Call Restore after Start and before applying the enrolment set: that
// set's sweep then revokes the restored leases of peers the control plane
// withdrew while the gateway was down.
func (s *Service) Restore(ctx context.Context) error {
	if !s.Active() {
		return &ErrNotStarted{}
	}
	leases, err := s.deps.Leases.List(ctx)
	if err != nil {
		return &ErrLeaseStoreUnavailable{Cause: err}
	}
	var errs []error
	if err := s.reconcilePeers(ctx, leases); err != nil {
		// An orphan peer may still hold its address: the reclaim waits
		// for the retry that reconciles it (see retryPeerReconcile).
		s.oweReclaim()
		errs = append(errs, err)
	} else if err := s.reclaimOrphanAddresses(ctx); err != nil {
		s.logger.Warn("vpn.restore: orphan address reclaim incomplete; a sweep retries it", slog.Any("error", err))
		s.oweReclaim()
	}
	for _, l := range leases {
		if err := s.restore(ctx, l); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ReconcileHostedPeers withdraws from every hosted plane each peer whose lease
// the store does not hold. It is the restart step of a vpn child without a
// lease control plane: its memory store starts empty, so the peers its
// predecessor left in the surviving datapath planes would otherwise stay up
// with no expiry authority. Unlike Restore it neither holds addresses nor
// drops leases; a plane that fails is owed to the Sweep, as in Restore.
func (s *Service) ReconcileHostedPeers(ctx context.Context) error {
	if !s.Active() {
		return &ErrNotStarted{}
	}
	leases, err := s.deps.Leases.List(ctx)
	if err != nil {
		return &ErrLeaseStoreUnavailable{Cause: err}
	}
	return s.reconcilePeers(ctx, leases)
}

// reconcilePeers removes from every plane that outlives the service each
// peer whose lease is not among the stored leases: a revoke that deleted the
// record and died before it removed the peer leaves that peer behind.
func (s *Service) reconcilePeers(ctx context.Context, leases []*Lease) error {
	var errs []error
	for kind, plane := range s.deps.DataPlanes {
		r, ok := plane.(PeerReconciler)
		if !ok {
			continue
		}
		if err := reconcilePlane(ctx, kind, r, leases, nil); err != nil {
			// An orphan peer may still be installed with its lease gone from
			// the store, where no sweep finds it: keep the obligation.
			s.owePeerRetry(kind, nil)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// reclaimOrphanAddresses releases every vpn-tagged allocation in the lease
// pool whose address no stored lease holds. The vpn-tagged allocation is the
// durable record of an address whose cleanup peerRetry held, and peerRetry
// does not survive a restart; once every hosted plane matches the stored
// leases (reconcilePeers succeeded), its peer is gone and the address is free
// to go back. A pool, list or release failure is logged and the allocation
// stays held for the next restart.
func (s *Service) reclaimOrphanAddresses(ctx context.Context) error {
	s.enrolGate.Lock()
	defer s.enrolGate.Unlock()
	return s.reclaimOrphanAddressesLocked(ctx)
}

// ErrOrphanReclaimFailed reports that the orphan addresses of this
// gateway's lease pool could not all be listed or released; the reclaim
// stays owed and a later Sweep retries it.
type ErrOrphanReclaimFailed struct {
	// Address is the allocation whose release failed; invalid when the
	// pool or its allocations could not be read.
	Address netip.Addr
	Cause   error
}

func (e *ErrOrphanReclaimFailed) Error() string {
	if e.Address.IsValid() {
		return fmt.Sprintf("vpn: orphan address %s not reclaimed: %v", e.Address, e.Cause)
	}
	return fmt.Sprintf("vpn: orphan addresses not reclaimed: %v", e.Cause)
}

func (e *ErrOrphanReclaimFailed) Unwrap() error { return e.Cause }

// reclaimOrphanAddressesLocked releases each active allocation in the
// lease pool that this gateway provably wrote (tagged vpn and with its
// exact owner tag) and that neither a stored lease nor an owed peer
// removal holds. A gateway with no owner tag reclaims nothing; an
// allocation without one is never reclaimed. The caller holds enrolGate.
func (s *Service) reclaimOrphanAddressesLocked(ctx context.Context) error {
	owner := s.ownerTag()
	if owner == "" {
		return nil
	}
	leases, err := s.deps.Leases.List(ctx)
	if err != nil {
		return &ErrLeaseStoreUnavailable{Cause: err}
	}
	pool, err := s.deps.IPAM.GetPoolByName(ctx, s.cfg.Pool)
	if err != nil {
		return &ErrOrphanReclaimFailed{Cause: err}
	}
	allocs, err := s.deps.IPAM.GetAllocationsByPool(ctx, pool.ID)
	if err != nil {
		return &ErrOrphanReclaimFailed{Cause: err}
	}
	held := make(map[netip.Addr]bool, len(leases))
	for _, l := range leases {
		if l.Address.IsValid() {
			held[l.Address.Addr()] = true
		}
	}
	s.mu.Lock()
	for _, owed := range s.peerRetry {
		for _, l := range owed {
			if l.Address.IsValid() {
				held[l.Address.Addr()] = true
			}
		}
	}
	for addr := range s.tearingDown {
		held[addr] = true
	}
	s.mu.Unlock()
	var first error
	for _, alloc := range allocs {
		if alloc.Status != ipam.AllocationStatusActive || held[alloc.IP] ||
			!slices.Contains(alloc.Tags, "vpn") || !slices.Contains(alloc.Tags, owner) {
			continue
		}
		if err := s.deps.IPAM.Release(ctx, alloc.IP); err != nil {
			s.logger.Warn("vpn.restore: orphan address release failed",
				slog.String("ip", alloc.IP.String()), slog.String("device", alloc.DeviceID), slog.Any("error", err))
			if first == nil {
				first = &ErrOrphanReclaimFailed{Address: alloc.IP, Cause: err}
			}
			continue
		}
		s.logger.Info("vpn.restore.address.reclaim",
			slog.String("ip", alloc.IP.String()), slog.String("device", alloc.DeviceID))
	}
	return first
}

// reconcilePlane removes every peer of one hosted plane whose lease is not
// among leases.
func reconcilePlane(ctx context.Context, kind DataPlaneKind, r PeerReconciler, leases []*Lease, except map[LeaseID]bool) error {
	keep := make([]LeaseID, 0, len(leases))
	for _, l := range leases {
		if l.DataPlane == kind && !except[l.ID] {
			keep = append(keep, l.ID)
		}
	}
	if err := r.ReconcilePeers(ctx, keep); err != nil {
		return &ErrDataPlaneUnavailable{Kind: kind, Cause: err}
	}
	return nil
}

// owePeerRetry records that a hosted plane's peers must be reconciled
// again, and, with held non-nil, that held's address is released only once
// that succeeds.
func (s *Service) owePeerRetry(kind DataPlaneKind, held ...*Lease) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peerRetry == nil {
		s.peerRetry = map[DataPlaneKind][]*Lease{}
	}
	owed := s.peerRetry[kind]
	for _, l := range held {
		if l != nil {
			owed = append(owed, l)
		}
	}
	s.peerRetry[kind] = owed
}

// retryPeerReconcile retries each owed reconciliation against the stored
// leases, under the enrolment gate so no admission is between installing
// a peer and storing its lease. Once a plane's reconciliation succeeds, the
// addresses of the rejected leases that waited on it are released; a
// failure keeps the obligation for the next sweep. Obligations are
// detached only under the gate: until then the owed addresses stay in
// peerRetry, where a concurrent orphan reclaim sees them as held.
func (s *Service) retryPeerReconcile(ctx context.Context) {
	s.mu.Lock()
	pending := len(s.peerRetry) > 0 || s.reclaimOwed
	s.mu.Unlock()
	if !pending {
		return
	}
	if s.sweepGateHook != nil {
		s.sweepGateHook()
	}
	s.enrolGate.Lock()
	defer s.enrolGate.Unlock()
	s.mu.Lock()
	due := s.peerRetry
	s.peerRetry = nil
	owed := s.reclaimOwed
	s.mu.Unlock()
	if len(due) == 0 && !owed {
		return
	}
	leases, err := s.deps.Leases.List(ctx)
	if err != nil {
		s.logger.Warn("vpn: peer reconciliation retry could not list leases", slog.Any("error", err))
		for kind, held := range due {
			s.owePeerRetry(kind, held...)
		}
		return
	}
	stored := make(map[LeaseID]bool, len(leases))
	for _, l := range leases {
		stored[l.ID] = true
	}
	// An address a stored lease holds belongs to that lease, whatever
	// owed cleanup still names it.
	inUse := make(map[netip.Addr]bool, len(leases))
	for _, l := range leases {
		if l.Address.IsValid() {
			inUse[l.Address.Addr()] = true
		}
	}
	reconciled := true
	for kind, held := range due {
		plane, ok := s.deps.DataPlanes[kind]
		if !ok {
			continue
		}
		r, ok := plane.(PeerReconciler)
		if !ok {
			s.retryPeerRemovals(ctx, kind, plane, held, stored, inUse)
			continue
		}
		// A held lease was rejected: its record may still be stored when
		// its delete failed, but its peer must not be kept.
		except := make(map[LeaseID]bool, len(held))
		for _, l := range held {
			except[l.ID] = true
		}
		if err := reconcilePlane(ctx, kind, r, leases, except); err != nil {
			s.logger.Warn("vpn: peer reconciliation failed again", slog.String("data_plane", string(kind)), slog.Any("error", err))
			s.owePeerRetry(kind, held...)
			reconciled = false
			continue
		}
		for _, l := range held {
			if stored[l.ID] {
				continue
			}
			s.releaseOwedAddress(ctx, kind, l, inUse)
		}
	}
	// The reclaim waits until every plane reconciles: an orphan peer of a
	// plane still owed may hold an address no lease records.
	if !owed || !reconciled {
		return
	}
	if err := s.reclaimOrphanAddressesLocked(ctx); err != nil {
		s.logger.Warn("vpn: orphan address reclaim failed again", slog.Any("error", err))
		return
	}
	s.mu.Lock()
	s.reclaimOwed = false
	s.mu.Unlock()
}

// oweReclaim records that orphan addresses still wait to be reclaimed.
func (s *Service) oweReclaim() {
	s.mu.Lock()
	s.reclaimOwed = true
	s.mu.Unlock()
}

// releaseOwedAddress releases the address of an owed lease whose peer is
// gone and whose record is no longer stored. The retry set is the only
// place that still knows the allocation, so a failed lookup or release
// puts the lease back on it for a later sweep. The caller holds enrolGate,
// so no admission is in flight: a stored lease is the only way a newer
// admission holds the address, and then the obligation is dropped (a
// release whose response was lost may already have freed it once).
func (s *Service) releaseOwedAddress(ctx context.Context, kind DataPlaneKind, l *Lease, inUse map[netip.Addr]bool) {
	if l.Address.IsValid() && inUse[l.Address.Addr()] {
		s.logger.Info("vpn: owed address is held by a stored lease; nothing to release",
			slog.String("data_plane", string(kind)), slog.String("lease", string(l.ID)))
		return
	}
	h, err := s.ownsOwedAllocation(ctx, l)
	if err == nil && h {
		err = s.deps.IPAM.Release(ctx, l.Address.Addr())
	}
	if err != nil {
		s.logger.Warn("vpn: owed address release failed",
			slog.String("data_plane", string(kind)), slog.String("lease", string(l.ID)), slog.Any("error", err))
		s.owePeerRetry(kind, l)
	}
}

// retryPeerRemovals retries, on a plane that cannot reconcile, the removal
// of each owed peer; a peer removed (or already gone) releases its address
// unless its lease is still stored, and a failure stays owed.
func (s *Service) retryPeerRemovals(ctx context.Context, kind DataPlaneKind, plane DataPlane, held []*Lease, stored map[LeaseID]bool, inUse map[netip.Addr]bool) {
	for _, l := range held {
		err := plane.RemovePeer(ctx, l.ID)
		var nf *ErrLeaseNotFound
		if err != nil && !errors.As(err, &nf) {
			s.logger.Warn("vpn: owed peer removal failed again",
				slog.String("data_plane", string(kind)), slog.String("lease", string(l.ID)), slog.Any("error", err))
			s.owePeerRetry(kind, l)
			continue
		}
		if stored[l.ID] {
			continue
		}
		s.releaseOwedAddress(ctx, kind, l, inUse)
	}
}

// restore reinstates one lease, or drops it.
func (s *Service) restore(ctx context.Context, l *Lease) error {
	unlock := s.devices.lock(deviceKey(l.TenantID, l.DeviceID))
	defer unlock()
	plane, ok := s.deps.DataPlanes[l.DataPlane]
	if l.Expired(s.deps.Clock.Now()) {
		return s.dropLease(ctx, l, plane, "expired", nil)
	}
	if !ok || !s.cfg.Offers(l.DataPlane) {
		return s.dropLease(ctx, l, plane, "data plane not offered", &ErrDataPlaneUnavailable{Kind: l.DataPlane})
	}
	if !s.ZonesAllowed(l.Zones) {
		return s.dropLease(ctx, l, plane, "zones not allowed", nil)
	}
	// The renewal stored before the restart never reached the host: the
	// host may have expired the peer at the client's deadline while the
	// record kept the later one, and an expiry marker that could not be
	// written is lost with the restart. Restore asks the host first and
	// fails closed on a lease it expired.
	if !l.ClientExpiresAt.IsZero() {
		if ext, ok := plane.(PeerDeadlineExtender); ok {
			if err := ext.ExtendPeer(ctx, l); err != nil {
				var nf *ErrLeaseNotFound
				if errors.As(err, &nf) {
					dErr := s.dropLease(ctx, l, plane, "host expired an unresolved renewal", err)
					var unrecorded *ErrRevocationNotRecorded
					if errors.As(dErr, &unrecorded) {
						s.oweDeletion(ctx, l)
					}
					return dErr
				}
				s.oweExtension(l)
			}
		}
	}
	if err := s.holdAddress(ctx, l); err != nil {
		return s.dropLease(ctx, l, plane, "address unavailable", err)
	}
	if err := plane.InstallPeer(ctx, l); err != nil {
		return s.dropLease(ctx, l, plane, "data plane refused the peer", &ErrDataPlaneUnavailable{Kind: l.DataPlane, Cause: err})
	}
	// A client refused a renewal before the restart still holds the
	// deadline stored with the lease: its retry keeps the renew bypass.
	if !l.ClientExpiresAt.IsZero() && l.ClientExpiresAt.Before(l.ExpiresAt) {
		s.bypassRenewal(l.ID)
	}
	s.logger.Info("vpn.restore",
		slog.String("lease", string(l.ID)),
		slog.String("device", l.DeviceID),
		slog.String("tenant", l.TenantID),
		slog.Time("expires_at", l.ExpiresAt))
	return nil
}

// holdAddress gives the lease its recorded address back. An allocation the
// device still holds (a persistent IPAM) is kept as it is.
func (s *Service) holdAddress(ctx context.Context, l *Lease) error {
	held, err := s.holdsAddress(ctx, l)
	if err != nil || held {
		return err
	}
	req, err := s.allocationRequest(ctx, l.TenantID, l.DeviceID)
	if err != nil {
		return err
	}
	req.RequestedIP = l.Address.Addr()
	_, err = s.deps.IPAM.AllocateSpecific(ctx, req)
	return err
}

// holdsAddress reports whether the lease's device holds the lease's address.
func (s *Service) holdsAddress(ctx context.Context, l *Lease) (bool, error) {
	if !l.Address.IsValid() {
		return false, nil
	}
	alloc, err := s.deps.IPAM.GetAllocation(ctx, l.Address.Addr())
	if errors.Is(err, ipam.ErrAllocationNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return alloc.Status == ipam.AllocationStatusActive && alloc.DeviceID == l.DeviceID, nil
}

// ownsOwedAllocation reports whether the active allocation at l's address
// is still the one this gateway allocated for l, so an owed release may
// free it. The IPAM has no conditional release, so the retry is fenced on
// what the allocation records: the device, the vpn and tenant tags of a
// lease allocation, and no owner tag but this gateway's. A release whose
// response was lost may already have committed; the device can then hold
// the address again through another gateway sharing the pool, whose lease
// this gateway's store cannot see, and that allocation carries the other
// gateway's owner tag. An untagged allocation (one made before owner tags)
// is still released.
func (s *Service) ownsOwedAllocation(ctx context.Context, l *Lease) (bool, error) {
	if !l.Address.IsValid() {
		return false, nil
	}
	alloc, err := s.deps.IPAM.GetAllocation(ctx, l.Address.Addr())
	if errors.Is(err, ipam.ErrAllocationNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if alloc.Status != ipam.AllocationStatusActive || alloc.DeviceID != l.DeviceID {
		return false, nil
	}
	owner := s.ownerTag()
	for _, tag := range alloc.Tags {
		switch {
		case strings.HasPrefix(tag, "gateway:") && tag != owner:
			return false, nil
		case strings.HasPrefix(tag, "tenant:") && tag != "tenant:"+l.TenantID:
			return false, nil
		}
	}
	return true, nil
}

// dropLease removes a lease Restore will not reinstate: the record is deleted
// so the control plane forgets it too, and the address goes back to the pool
// when the device holds it. A store that could not record the drop
// (ErrRevocationNotRecorded) keeps the lease and its address. A lease that
// is not expired keeps its hosted peer too: the deletion is recorded before
// the peer is removed. An expired lease's peer is removed anyway (a removal
// that fails is owed to Sweep); only its address waits for the deletion.
func (s *Service) dropLease(ctx context.Context, l *Lease, plane DataPlane, reason string, cause error) error {
	expired := l.Expired(s.deps.Clock.Now())
	dropped := &ErrLeaseNotRestored{LeaseID: l.ID, Reason: reason, Cause: cause}
	s.logger.Warn("vpn.restore: lease dropped",
		slog.String("lease", string(l.ID)), slog.String("device", l.DeviceID), slog.String("reason", reason))
	// Record the deletion first: a lease the store keeps is reinstated by
	// the next restart, so its peer must not go before the drop is recorded.
	var storeErr error
	if err := s.deps.Leases.Delete(ctx, l.ID); err != nil {
		var nf *ErrLeaseNotFound
		var unrecorded *ErrRevocationNotRecorded
		if errors.As(err, &unrecorded) {
			if !expired {
				return errors.Join(dropped, err)
			}
			// An expired lease is dead whether or not its deletion was
			// recorded, and a restart drops it again before anything
			// else: its peer goes now. The kept record keeps the
			// address; an owed removal is retried by Sweep, which
			// releases the address only once the record is gone.
			removeErr := s.removeRejectedPeer(ctx, l, plane)
			if removeErr != nil {
				s.owePeerRetry(l.DataPlane, l)
			}
			return errors.Join(dropped, err, removeErr)
		}
		if !errors.As(err, &nf) {
			storeErr = err
		}
	}
	// A hosted plane may still carry the lease's peer from before the vpn
	// child restarted: remove it before the address can go to another device.
	removeErr := s.removeRejectedPeer(ctx, l, plane)
	if removeErr != nil {
		// The peer may still route the address: keep it held until a
		// retried reconciliation (Sweep) removes the peer.
		s.owePeerRetry(l.DataPlane, l)
		return errors.Join(dropped, removeErr, storeErr)
	}
	if held, err := s.holdsAddress(ctx, l); err != nil {
		s.logger.Warn("vpn.restore: could not tell who holds a dropped lease's address",
			slog.String("lease", string(l.ID)), slog.Any("error", err))
	} else if held {
		s.releaseAddress(ctx, l.Address)
	}
	if storeErr != nil {
		return errors.Join(dropped, storeErr)
	}
	return dropped
}

// removeRejectedPeer removes the peer a hosted plane (a PeerReconciler,
// whose peers outlive the vpn child) may still carry for a lease Restore
// rejects. Other planes start empty with the child and hold no such peer.
func (s *Service) removeRejectedPeer(ctx context.Context, l *Lease, plane DataPlane) error {
	if _, hosted := plane.(PeerReconciler); !hosted {
		return nil
	}
	err := plane.RemovePeer(ctx, l.ID)
	var nf *ErrLeaseNotFound
	if err == nil || errors.As(err, &nf) {
		return nil
	}
	var unavailable *ErrDataPlaneUnavailable
	if errors.As(err, &unavailable) {
		return err
	}
	return &ErrDataPlaneUnavailable{Kind: l.DataPlane, Cause: err}
}
