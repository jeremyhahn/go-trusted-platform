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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// Admit runs the five steps for a fresh session and returns the lease. Every
// step fails closed; the order is fixed: identity, attestation, posture,
// person factor, address, peer. A device that already holds a lease in the
// tenant has that lease revoked (RevokeReplaced) before the new one is
// issued — a lost laptop coming back cannot keep a session open beside its
// replacement. A failed peer install releases the address.
func (s *Service) Admit(ctx context.Context, req *AdmissionRequest) (*Lease, error) {
	if !s.Active() {
		return nil, &ErrNotStarted{}
	}
	if err := s.validateRequest(req); err != nil {
		s.recordRefusal(err.Error())
		return nil, err
	}
	if !s.consumeNonce(req.Nonce) {
		return nil, s.refuse(ctx, req.DeviceID, &ErrNonceUnknown{})
	}

	// 1. Device identity.
	decision := s.deps.Identity.Evaluate(ctx, req.Peer)
	if err := s.deps.Audit.RecordAdmission(ctx, decision); err != nil {
		s.logger.Warn("vpn audit record failed", slog.Any("error", err))
	}
	if !decision.Admitted {
		return nil, s.refuse(ctx, req.DeviceID, &ErrPeerRefused{Reason: decision.Reason})
	}
	// An admitted identity is a peer only when the control plane enrolled
	// it, and only for the zones the enrolment grants.
	if err := s.enrolled(req.TenantID, req.DeviceID, req.RequestedZones); err != nil {
		return nil, s.refuse(ctx, req.DeviceID, err)
	}

	// 2. Attestation.
	summary, err := s.attest(ctx, req.DeviceID, req.Nonce, req.Attestation)
	if err != nil {
		return nil, s.refuse(ctx, req.DeviceID, err)
	}

	// 3. Posture.
	if err := s.posture(ctx, req.TenantID, req.Posture, summary); err != nil {
		return nil, s.refuse(ctx, req.DeviceID, err)
	}

	// 4. Person factor.
	if err := s.personFactor(ctx, req.TenantID, req.DeviceID, req.Nonce, req.PersonFactor, s.cfg.RequirePersonFactor.OnAdmit); err != nil {
		return nil, s.refuse(ctx, req.DeviceID, err)
	}

	// The control plane may have withdrawn the peer while attestation and
	// the factor check ran. Authorize again under the enrolment gate and
	// keep it to the lease write: the commit then lands either before
	// SetEnrolments publishes a set, so its sweep sees the lease, or after
	// the sweep, where this check sees the withdrawal.
	s.enrolGate.RLock()
	defer s.enrolGate.RUnlock()
	if err := s.enrolled(req.TenantID, req.DeviceID, req.RequestedZones); err != nil {
		return nil, s.refuse(ctx, req.DeviceID, err)
	}

	// One lease per device per tenant. From here to the record write the
	// device is locked, so two concurrent admissions cannot both see "no
	// lease" and leave a peer and an address orphaned.
	unlock := s.devices.lock(deviceKey(req.TenantID, req.DeviceID))
	defer unlock()
	if prev, held, err := s.deps.Leases.FindByDevice(ctx, req.TenantID, req.DeviceID); err != nil {
		return nil, s.refuse(ctx, req.DeviceID, &ErrLeaseStoreUnavailable{Cause: err})
	} else if held {
		if err := s.revoke(ctx, prev, RevokeReplaced); err != nil {
			return nil, s.refuse(ctx, req.DeviceID, err)
		}
	}

	// 5. Address, then peer.
	now := s.deps.Clock.Now()
	id, err := newLeaseID()
	if err != nil {
		return nil, s.refuse(ctx, req.DeviceID, err)
	}
	addr, err := s.allocate(ctx, req)
	if err != nil {
		return nil, s.refuse(ctx, req.DeviceID, err)
	}
	lease := &Lease{
		ID:        id,
		DeviceID:  req.DeviceID,
		TenantID:  req.TenantID,
		Address:   addr,
		Zones:     append([]string(nil), req.RequestedZones...),
		DataPlane: req.DataPlane,
		Keys:      bindPeerKeys(req),
		IssuedAt:  now,
		ExpiresAt: now.Add(s.cfg.LeaseTTL),
		Verdict:   *summary,
	}
	plane := s.deps.DataPlanes[req.DataPlane]
	if err := plane.InstallPeer(ctx, lease); err != nil {
		s.releaseAddress(ctx, addr)
		return nil, s.refuse(ctx, req.DeviceID, &ErrDataPlaneUnavailable{Kind: req.DataPlane, Cause: err})
	}
	if err := s.deps.Leases.Put(ctx, lease); err != nil {
		if rmErr := plane.RemovePeer(ctx, lease.ID); rmErr != nil {
			// Both the store and the datapath failed: the peer may be live
			// with no lease behind it, and the operator must be told.
			s.logger.Warn("vpn.admit: peer left in the datapath after a lease-store failure",
				slog.String("lease", string(lease.ID)), slog.Any("error", rmErr))
		}
		s.releaseAddress(ctx, addr)
		return nil, s.refuse(ctx, req.DeviceID, &ErrLeaseStoreUnavailable{Cause: err})
	}
	s.admissions.Add(1)
	s.logger.Info("vpn.admit",
		slog.String("lease", string(lease.ID)),
		slog.String("device", lease.DeviceID),
		slog.String("tenant", lease.TenantID),
		slog.String("data_plane", string(lease.DataPlane)),
		slog.Time("expires_at", lease.ExpiresAt))
	cp := *lease
	return &cp, nil
}

// Renew extends a lease inside its renew window on fresh evidence:
// attestation and posture always, the person factor when the policy asks
// for it on renewal. A failed renewal revokes the lease; a renewal after
// expiry is ErrLeaseExpired.
func (s *Service) Renew(ctx context.Context, id LeaseID, ev *Evidence) (*Lease, error) {
	if !s.Active() {
		return nil, &ErrNotStarted{}
	}
	if ev == nil {
		return nil, &ErrInvalidRequest{Field: "evidence", Reason: "required"}
	}
	probe, err := s.deps.Leases.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	unlock := s.devices.lock(deviceKey(probe.TenantID, probe.DeviceID))
	defer unlock()
	// Re-read under the lock: a concurrent renewal or revoke may have
	// changed the record between the probe and here.
	lease, err := s.deps.Leases.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	now := s.deps.Clock.Now()
	if lease.Expired(now) {
		_ = s.revoke(ctx, lease, RevokeExpired)
		return nil, &ErrLeaseExpired{LeaseID: id}
	}
	// Renewal opens RenewWindow before expiry and not earlier: a client
	// that re-attests every minute would otherwise keep a lease alive with
	// evidence that was never allowed to age, and the window is what the
	// operator configured (Config.Validate binds it below LeaseTTL).
	if opensAt := lease.ExpiresAt.Add(-s.cfg.RenewWindow); now.Before(opensAt) {
		return nil, s.refuse(ctx, lease.DeviceID, &ErrRenewalNotOpen{LeaseID: id, OpensAt: opensAt})
	}
	if err := s.enrolled(lease.TenantID, lease.DeviceID, lease.Zones); err != nil {
		if rErr := s.revoke(ctx, lease, RevokeOperator); rErr != nil {
			s.logger.Warn("vpn.renew: revoking an unenrolled lease failed",
				slog.String("lease", string(lease.ID)), slog.Any("error", rErr))
		}
		return nil, s.refuse(ctx, lease.DeviceID, err)
	}
	if !s.consumeNonce(ev.Nonce) {
		return nil, s.refuse(ctx, lease.DeviceID, &ErrNonceUnknown{})
	}
	summary, err := s.attest(ctx, lease.DeviceID, ev.Nonce, ev.Attestation)
	if err != nil {
		_ = s.revoke(ctx, lease, RevokeAttestation)
		return nil, s.refuse(ctx, lease.DeviceID, err)
	}
	if err := s.posture(ctx, lease.TenantID, ev.Posture, summary); err != nil {
		_ = s.revoke(ctx, lease, RevokePosture)
		return nil, s.refuse(ctx, lease.DeviceID, err)
	}
	if err := s.personFactor(ctx, lease.TenantID, lease.DeviceID, ev.Nonce, ev.PersonFactor, s.cfg.RequirePersonFactor.OnRenew); err != nil {
		return nil, s.refuse(ctx, lease.DeviceID, err)
	}
	if err := s.deps.IPAM.Renew(ctx, lease.Address.Addr()); err != nil {
		return nil, s.refuse(ctx, lease.DeviceID, &ErrPoolExhausted{Pool: s.cfg.Pool, Cause: err})
	}
	lease.ExpiresAt = now.Add(s.cfg.LeaseTTL)
	lease.Renewals++
	lease.Verdict = *summary
	if err := s.deps.Leases.Put(ctx, lease); err != nil {
		return nil, s.refuse(ctx, lease.DeviceID, &ErrLeaseStoreUnavailable{Cause: err})
	}
	s.logger.Info("vpn.renew", slog.String("lease", string(lease.ID)), slog.Int("renewals", lease.Renewals), slog.Time("expires_at", lease.ExpiresAt))
	cp := *lease
	return &cp, nil
}

// Revoke ends a lease: the peer is removed, then the address released, then
// the lease deleted. It is idempotent: an unknown lease is ErrLeaseNotFound
// and nothing else happens.
func (s *Service) Revoke(ctx context.Context, id LeaseID, reason RevokeReason) error {
	if !s.Active() {
		return &ErrNotStarted{}
	}
	probe, err := s.deps.Leases.Get(ctx, id)
	if err != nil {
		return err
	}
	unlock := s.devices.lock(deviceKey(probe.TenantID, probe.DeviceID))
	defer unlock()
	lease, err := s.deps.Leases.Get(ctx, id)
	if err != nil {
		return err
	}
	return s.revoke(ctx, lease, reason)
}

// Leases lists the leases the service knows.
func (s *Service) Leases(ctx context.Context) ([]*Lease, error) {
	return s.deps.Leases.List(ctx)
}

// Lease returns one lease.
func (s *Service) Lease(ctx context.Context, id LeaseID) (*Lease, error) {
	return s.deps.Leases.Get(ctx, id)
}

// revoke tears a lease down in order: peer, address, record. The record is
// deleted even when the peer removal failed, because a lease past its
// authority is dead whether or not the datapath answered; the removal error
// is returned so the caller retries the peer.
func (s *Service) revoke(ctx context.Context, lease *Lease, reason RevokeReason) error {
	var planeErr error
	if plane, ok := s.deps.DataPlanes[lease.DataPlane]; ok {
		if err := plane.RemovePeer(ctx, lease.ID); err != nil {
			planeErr = &ErrDataPlaneUnavailable{Kind: lease.DataPlane, Cause: err}
		}
	}
	s.releaseAddress(ctx, lease.Address)
	if err := s.deps.Leases.Delete(ctx, lease.ID); err != nil {
		var nf *ErrLeaseNotFound
		if !errors.As(err, &nf) {
			return err
		}
	}
	s.logger.Info("vpn.revoke", slog.String("lease", string(lease.ID)), slog.String("device", lease.DeviceID), slog.String("reason", string(reason)))
	return planeErr
}

func (s *Service) releaseAddress(ctx context.Context, addr netip.Prefix) {
	if !addr.IsValid() {
		return
	}
	if err := s.deps.IPAM.Release(ctx, addr.Addr()); err != nil {
		s.logger.Warn("vpn address release failed", slog.String("address", addr.String()), slog.Any("error", err))
	}
}

func (s *Service) refuse(ctx context.Context, deviceID string, err error) error {
	s.recordRefusal(err.Error())
	s.logger.Warn("vpn.refuse", slog.String("device", deviceID), slog.String("reason", err.Error()))
	return err
}

func (s *Service) validateRequest(req *AdmissionRequest) error {
	switch {
	case req == nil:
		return &ErrInvalidRequest{Field: "request", Reason: "required"}
	case req.Peer == nil || req.Peer.Leaf == nil:
		return &ErrInvalidRequest{Field: "peer", Reason: "no mTLS peer"}
	case req.DeviceID == "":
		return &ErrInvalidRequest{Field: "device_id", Reason: "required"}
	case req.TenantID == "":
		return &ErrInvalidRequest{Field: "tenant_id", Reason: "required"}
	case len(req.Nonce) == 0:
		return &ErrInvalidRequest{Field: "nonce", Reason: "required"}
	case req.Attestation == nil:
		return &ErrInvalidRequest{Field: "attestation", Reason: "required"}
	case req.Posture == nil:
		return &ErrInvalidRequest{Field: "posture", Reason: "required"}
	case !req.DataPlane.Known():
		return &ErrDataPlaneUnavailable{Kind: req.DataPlane}
	case !s.cfg.Offers(req.DataPlane):
		return &ErrDataPlaneUnavailable{Kind: req.DataPlane}
	case len(req.RequestedZones) == 0:
		return &ErrInvalidRequest{Field: "zones", Reason: "at least one zone is required"}
	}
	for _, z := range req.RequestedZones {
		if !s.cfg.allows(z) {
			return &ErrZoneNotAllowed{Zone: z}
		}
	}
	return nil
}

func (s *Service) attest(ctx context.Context, deviceID string, nonce []byte, att *manifest.HostAttestation) (*VerdictSummary, error) {
	if att == nil {
		return nil, &ErrAttestationFailed{DeviceID: deviceID, Reason: "no attestation presented"}
	}
	v, err := s.deps.Verifier.Verify(ctx, deviceID, nonce, att)
	if err != nil {
		return nil, &ErrAttestationFailed{DeviceID: deviceID, Reason: "verifier error", Cause: err}
	}
	if v == nil {
		return nil, &ErrAttestationFailed{DeviceID: deviceID, Reason: "verifier returned no verdict"}
	}
	if !v.Passed || !v.Cryptographic {
		reason := v.Reason
		if reason == "" {
			reason = "verdict did not pass"
		}
		return nil, &ErrAttestationFailed{DeviceID: deviceID, Reason: reason}
	}
	return &VerdictSummary{Passed: v.Passed, Cryptographic: v.Cryptographic, ProfileID: v.ProfileID}, nil
}

// postureInput is the OPA input: the report plus the verdict summary.
func postureInput(report *PostureReport, v *VerdictSummary) (map[string]interface{}, error) {
	raw, err := json.Marshal(struct {
		Posture *PostureReport  `json:"posture"`
		Verdict *VerdictSummary `json:"verdict"`
	}{report, v})
	if err != nil {
		return nil, err
	}
	var input map[string]interface{}
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, err
	}
	return input, nil
}

func (s *Service) posture(ctx context.Context, tenantID string, report *PostureReport, v *VerdictSummary) error {
	if report == nil {
		return &ErrPostureViolation{Violations: []string{"posture-missing"}}
	}
	input, err := postureInput(report, v)
	if err != nil {
		return &ErrPostureUnavailable{Cause: err}
	}
	evaluator, policyName, err := s.postureFor(tenantID)
	if err != nil {
		// A tenant policy that failed to compile refuses; it never falls
		// back to the default.
		return &ErrPostureUnavailable{Cause: err}
	}
	result, err := evaluator.Evaluate(ctx, policyName, input)
	if err != nil {
		// Every engine failure is a refusal: no policy never means allow.
		return &ErrPostureUnavailable{Cause: err}
	}
	if result == nil {
		return &ErrPostureUnavailable{Cause: &opa.ErrEvaluationFailed{PolicyName: policyName, Reason: "no result"}}
	}
	if len(result.Violations) > 0 || !result.Allowed {
		names := make([]string, 0, len(result.Violations))
		for _, viol := range result.Violations {
			names = append(names, viol.Rule)
		}
		if len(names) == 0 {
			names = append(names, "denied")
		}
		return &ErrPostureViolation{Violations: names}
	}
	return nil
}

func (s *Service) personFactor(ctx context.Context, tenantID, deviceID string, nonce []byte, factor *PersonFactor, required bool) error {
	if factor == nil {
		if required {
			return &ErrPersonFactorRequired{}
		}
		return nil
	}
	if factor.Kind != PersonFactorFIDO2 && factor.Kind != PersonFactorPIV {
		return &ErrPersonFactorInvalid{FactorName: string(factor.Kind)}
	}
	if len(factor.Assertion) == 0 {
		return &ErrPersonFactorInvalid{FactorName: string(factor.Kind)}
	}
	if err := s.deps.Factors.Verify(ctx, tenantID, deviceID, nonce, factor); err != nil {
		return &ErrPersonFactorInvalid{FactorName: string(factor.Kind), Cause: err}
	}
	return nil
}

func (s *Service) allocate(ctx context.Context, req *AdmissionRequest) (netip.Prefix, error) {
	pool, err := s.deps.IPAM.GetPoolByName(ctx, s.cfg.Pool)
	if err != nil {
		return netip.Prefix{}, &ErrPoolExhausted{Pool: s.cfg.Pool, Cause: err}
	}
	alloc, err := s.deps.IPAM.Allocate(ctx, &ipam.AllocationRequest{
		PoolID:        pool.ID,
		DeviceID:      req.DeviceID,
		Description:   "vpn lease",
		Tags:          []string{"vpn", "tenant:" + req.TenantID},
		LeaseDuration: s.cfg.LeaseTTL,
	})
	if err != nil {
		return netip.Prefix{}, &ErrPoolExhausted{Pool: s.cfg.Pool, Cause: err}
	}
	if alloc == nil || !alloc.IP.IsValid() {
		return netip.Prefix{}, &ErrPoolExhausted{Pool: s.cfg.Pool}
	}
	return netip.PrefixFrom(alloc.IP, alloc.IP.BitLen()), nil
}

// zonesAllowed is exported for the daemon's authorization layer: the lease's
// zones must also be within the person's IAM entitlement, which the control
// plane checks; the service only knows its own allow-to set.
func (s *Service) ZonesAllowed(zones []string) bool {
	for _, z := range zones {
		if !s.cfg.allows(z) {
			return false
		}
	}
	return len(zones) > 0
}

// bindPeerKeys copies the request's data-plane material into the lease and
// adds the fingerprint of the mTLS client certificate the admission ran
// under, so a data plane can bind a later data-plane session to this lease
// by certificate rather than by anything the client asserts.
func bindPeerKeys(req *AdmissionRequest) PeerKeys {
	sum := sha256.Sum256(req.Peer.Leaf.Raw)
	return PeerKeys{
		WireGuardPublicKey:      append([]byte(nil), req.Keys.WireGuardPublicKey...),
		ClientCertificateSHA256: sum[:],
	}
}
