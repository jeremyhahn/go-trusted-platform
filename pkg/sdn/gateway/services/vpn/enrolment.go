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
	"slices"
)

// Enrolment makes a device a VPN peer of a tenant. The control plane owns
// the enrolment set and delivers it in the gateway's desired configuration;
// a device that passes identity, attestation and posture but has no
// enrolment is refused.
type Enrolment struct {
	TenantID string `json:"tenant_id" yaml:"tenant-id"`
	DeviceID string `json:"device_id" yaml:"device-id"`
	// Zones, when set, narrows the zones the peer may request below the
	// service's allow-to set. Empty means every allow-to zone.
	Zones []string `json:"zones,omitempty" yaml:"zones,omitempty"`
}

// enrolmentSet indexes enrolments by tenant/device key.
type enrolmentSet map[peerKey]Enrolment

// EnrolmentRejection is a peer the delivered set named that this gateway
// refused to enrol, with the reason. The rest of the set still applies.
type EnrolmentRejection struct {
	TenantID string
	DeviceID string
	Reason   string
}

// SetEnrolments replaces the enrolment set and revokes every lease the new
// set no longer covers — a device removed from the set, or a lease holding a
// zone its enrolment no longer grants. A malformed set (a missing tenant or
// device, a device listed twice) is refused whole and the previous set stays
// in force. A peer asking for a zone this gateway does not serve is refused
// alone: it is not enrolled, so it is refused admission and any lease it holds
// is revoked, while the rest of the set applies; RejectedEnrolments reports
// it. Revocation failures are returned after the new set is in force, so a
// removed peer cannot be re-admitted meanwhile.
func (s *Service) SetEnrolments(ctx context.Context, enrolments []Enrolment) error {
	set := make(enrolmentSet, len(enrolments))
	seen := make(map[peerKey]struct{}, len(enrolments))
	var rejected []EnrolmentRejection
	for i, e := range enrolments {
		switch {
		case e.TenantID == "":
			return &ErrInvalidEnrolment{Index: i, Reason: "tenant_id is required"}
		case e.DeviceID == "":
			return &ErrInvalidEnrolment{Index: i, Reason: "device_id is required"}
		}
		key := deviceKey(e.TenantID, e.DeviceID)
		if _, dup := seen[key]; dup {
			return &ErrInvalidEnrolment{Index: i, Reason: fmt.Sprintf("duplicate enrolment for device %q of tenant %q", e.DeviceID, e.TenantID)}
		}
		seen[key] = struct{}{}
		if bad := slices.IndexFunc(e.Zones, func(z string) bool { return !s.cfg.allows(z) }); bad >= 0 {
			rejected = append(rejected, EnrolmentRejection{
				TenantID: e.TenantID,
				DeviceID: e.DeviceID,
				Reason:   (&ErrZoneNotAllowed{Zone: e.Zones[bad]}).Error(),
			})
			continue
		}
		set[key] = Enrolment{TenantID: e.TenantID, DeviceID: e.DeviceID, Zones: slices.Clone(e.Zones)}
	}
	slices.SortFunc(rejected, func(a, b EnrolmentRejection) int {
		return deviceKey(a.TenantID, a.DeviceID).compare(deviceKey(b.TenantID, b.DeviceID))
	})
	for _, r := range rejected {
		s.logger.Warn("vpn.enrolment: peer refused",
			slog.String("tenant", r.TenantID), slog.String("device", r.DeviceID), slog.String("reason", r.Reason))
	}
	// The gate holds admissions at their final authorization while the new
	// set is published and swept, so none can write a lease the sweep misses.
	s.enrolGate.Lock()
	defer s.enrolGate.Unlock()
	s.enrolments.Store(&set)
	s.rejectedEnrolments.Store(&rejected)
	return s.revokeUnenrolled(ctx, set)
}

// RejectedEnrolments returns the peers the last delivered set named but this
// gateway refused, sorted by tenant and device. Nil before the first delivery.
func (s *Service) RejectedEnrolments() []EnrolmentRejection {
	p := s.rejectedEnrolments.Load()
	if p == nil {
		return nil
	}
	return slices.Clone(*p)
}

// Enrolments returns the enrolment set in force.
func (s *Service) Enrolments() []Enrolment {
	p := s.enrolments.Load()
	if p == nil {
		return nil
	}
	out := make([]Enrolment, 0, len(*p))
	for _, e := range *p {
		out = append(out, Enrolment{TenantID: e.TenantID, DeviceID: e.DeviceID, Zones: slices.Clone(e.Zones)})
	}
	return out
}

// enrolled checks the device is an enrolled peer allowed every requested
// zone. Before any set is delivered nothing is enrolled: the gate fails
// closed.
func (s *Service) enrolled(tenantID, deviceID string, zones []string) error {
	p := s.enrolments.Load()
	if p == nil {
		return &ErrPeerNotEnrolled{TenantID: tenantID, DeviceID: deviceID}
	}
	e, ok := (*p)[deviceKey(tenantID, deviceID)]
	if !ok {
		return &ErrPeerNotEnrolled{TenantID: tenantID, DeviceID: deviceID}
	}
	if len(e.Zones) == 0 {
		return nil
	}
	for _, z := range zones {
		if !slices.Contains(e.Zones, z) {
			return &ErrZoneNotAllowed{Zone: z}
		}
	}
	return nil
}

// revokeUnenrolled revokes, with RevokeOperator, every lease the set does
// not cover.
func (s *Service) revokeUnenrolled(ctx context.Context, set enrolmentSet) error {
	leases, err := s.deps.Leases.List(ctx)
	if err != nil {
		return &ErrLeaseStoreUnavailable{Cause: err}
	}
	var errs []error
	for _, l := range leases {
		if covered(set, l) {
			continue
		}
		if err := s.revokeLocked(ctx, l, RevokeOperator); err != nil {
			s.logger.Warn("vpn.enrolment: revoking an unenrolled lease failed",
				slog.String("lease", string(l.ID)), slog.Any("error", err))
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// revokeLocked re-reads the lease under its device lock and revokes it; a
// lease already gone is not an error.
func (s *Service) revokeLocked(ctx context.Context, l *Lease, reason RevokeReason) error {
	unlock := s.devices.lock(deviceKey(l.TenantID, l.DeviceID))
	defer unlock()
	current, err := s.deps.Leases.Get(ctx, l.ID)
	if err != nil {
		var nf *ErrLeaseNotFound
		if errors.As(err, &nf) {
			return nil
		}
		return err
	}
	return s.revoke(ctx, current, reason)
}

// covered reports whether the set still grants the lease's device and every
// zone the lease holds.
func covered(set enrolmentSet, l *Lease) bool {
	e, ok := set[deviceKey(l.TenantID, l.DeviceID)]
	if !ok {
		return false
	}
	if len(e.Zones) == 0 {
		return true
	}
	for _, z := range l.Zones {
		if !slices.Contains(e.Zones, z) {
			return false
		}
	}
	return true
}
