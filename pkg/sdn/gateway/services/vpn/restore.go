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
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// Restore reinstates the leases the lease store holds after a restart: each
// takes its address back and has its peer programmed into its data plane, so
// a client admitted before the restart keeps its session. A lease that has
// expired, or whose data plane, zones or address this gateway can no longer
// give it, is dropped from the store instead and reported as an
// ErrLeaseNotRestored; the errors of every dropped lease are joined.
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
	for _, l := range leases {
		if err := s.restore(ctx, l); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// restore reinstates one lease, or drops it.
func (s *Service) restore(ctx context.Context, l *Lease) error {
	unlock := s.devices.lock(deviceKey(l.TenantID, l.DeviceID))
	defer unlock()
	if l.Expired(s.deps.Clock.Now()) {
		return s.dropLease(ctx, l, "expired", nil)
	}
	plane, ok := s.deps.DataPlanes[l.DataPlane]
	if !ok || !s.cfg.Offers(l.DataPlane) {
		return s.dropLease(ctx, l, "data plane not offered", &ErrDataPlaneUnavailable{Kind: l.DataPlane})
	}
	if !s.ZonesAllowed(l.Zones) {
		return s.dropLease(ctx, l, "zones not allowed", nil)
	}
	if err := s.holdAddress(ctx, l); err != nil {
		return s.dropLease(ctx, l, "address unavailable", err)
	}
	if err := plane.InstallPeer(ctx, l); err != nil {
		return s.dropLease(ctx, l, "data plane refused the peer", &ErrDataPlaneUnavailable{Kind: l.DataPlane, Cause: err})
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

// dropLease removes a lease Restore will not reinstate: the record is deleted
// so the control plane forgets it too, and the address goes back to the pool
// when the device holds it. A store that could not record the drop
// (ErrRevocationNotRecorded) keeps the lease, and its address with it.
func (s *Service) dropLease(ctx context.Context, l *Lease, reason string, cause error) error {
	dropped := &ErrLeaseNotRestored{LeaseID: l.ID, Reason: reason, Cause: cause}
	s.logger.Warn("vpn.restore: lease dropped",
		slog.String("lease", string(l.ID)), slog.String("device", l.DeviceID), slog.String("reason", reason))
	var storeErr error
	if err := s.deps.Leases.Delete(ctx, l.ID); err != nil {
		var nf *ErrLeaseNotFound
		var unrecorded *ErrRevocationNotRecorded
		if errors.As(err, &unrecorded) {
			return errors.Join(dropped, err)
		}
		if !errors.As(err, &nf) {
			storeErr = err
		}
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
