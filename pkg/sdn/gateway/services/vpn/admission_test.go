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
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
)

func TestAdmit_FiveStepsIssueALease(t *testing.T) {
	h := newHarness(t, testConfig())
	req := h.request(t)

	lease, err := h.svc.Admit(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, lease.ID)
	assert.Equal(t, "mini-99", lease.DeviceID)
	assert.Equal(t, "tenant-a", lease.TenantID)
	assert.Equal(t, "10.200.0.10/32", lease.Address.String())
	assert.Equal(t, []string{"management"}, lease.Zones)
	assert.Equal(t, DataPlaneMASQUE, lease.DataPlane)
	assert.Equal(t, h.clock.Now().Add(DefaultLeaseTTL), lease.ExpiresAt)
	assert.True(t, lease.Verdict.Passed && lease.Verdict.Cryptographic)
	assert.Equal(t, uint64(7), lease.Verdict.ProfileID)

	assert.Equal(t, 1, h.plane.count(), "the peer is installed")
	assert.Equal(t, 1, h.verifier.callCount())
	assert.Equal(t, 1, h.factors.callCount())
	require.Len(t, h.audit.decisions, 1, "the identity decision is audited")
	require.Len(t, h.posture.inputs, 1)
	assert.Contains(t, h.posture.inputs[0], "posture")
	assert.Contains(t, h.posture.inputs[0], "verdict")

	stored, err := h.svc.Lease(context.Background(), lease.ID)
	require.NoError(t, err)
	assert.Equal(t, lease.Address, stored.Address)
	health := h.svc.Health()
	assert.Equal(t, 1, health.ActiveLeases)
	assert.Equal(t, uint64(1), health.Admissions)
	assert.Equal(t, 1, health.LeasesByDataPlane[DataPlaneMASQUE])
}

func TestAdmit_RefusalMatrix(t *testing.T) {
	cases := map[string]struct {
		arrange func(h *harness, req *AdmissionRequest)
		want    interface{}
	}{
		"identity refused": {func(h *harness, _ *AdmissionRequest) {
			h.identity.decision = calleradmission.Decision{Admitted: false, Reason: calleradmission.ReasonUntrustedIssuer}
		}, &ErrPeerRefused{}},
		"verdict failed": {func(h *harness, _ *AdmissionRequest) {
			h.verifier.verdict = &verdict.DeviceVerdict{Passed: false, Cryptographic: true, Reason: "pcr mismatch"}
		}, &ErrAttestationFailed{}},
		"verdict not cryptographic": {func(h *harness, _ *AdmissionRequest) {
			h.verifier.verdict = &verdict.DeviceVerdict{Passed: true, Cryptographic: false}
		}, &ErrAttestationFailed{}},
		"verifier error": {func(h *harness, _ *AdmissionRequest) {
			h.verifier.err = errors.New("tpm unreachable")
		}, &ErrAttestationFailed{}},
		"verifier returns nothing": {func(h *harness, _ *AdmissionRequest) {
			h.verifier.verdict = nil
		}, &ErrAttestationFailed{}},
		"posture violation": {func(h *harness, _ *AdmissionRequest) {
			h.posture.result = &opa.EvaluationResult{Allowed: false, Violations: []opa.Violation{{Rule: "secure-boot-enabled"}}}
		}, &ErrPostureViolation{}},
		"posture denied without violations": {func(h *harness, _ *AdmissionRequest) {
			h.posture.result = &opa.EvaluationResult{Allowed: false}
		}, &ErrPostureViolation{}},
		"posture engine unavailable": {func(h *harness, _ *AdmissionRequest) {
			h.posture.err = opa.ErrPolicyNotFound{Name: "vpn_posture"}
		}, &ErrPostureUnavailable{}},
		"posture engine returns nothing": {func(h *harness, _ *AdmissionRequest) {
			h.posture.result = nil
		}, &ErrPostureUnavailable{}},
		"factor missing": {func(_ *harness, req *AdmissionRequest) {
			req.PersonFactor = nil
		}, &ErrPersonFactorRequired{}},
		"factor invalid": {func(h *harness, _ *AdmissionRequest) {
			h.factors.err = errors.New("assertion did not verify")
		}, &ErrPersonFactorInvalid{}},
		"factor unknown kind": {func(_ *harness, req *AdmissionRequest) {
			req.PersonFactor.Kind = "otp"
		}, &ErrPersonFactorInvalid{}},
		"factor empty assertion": {func(_ *harness, req *AdmissionRequest) {
			req.PersonFactor.Assertion = nil
		}, &ErrPersonFactorInvalid{}},
		"pool exhausted": {func(h *harness, _ *AdmissionRequest) {
			h.ipam.capacity = 0
		}, &ErrPoolExhausted{}},
		"pool unknown": {func(h *harness, _ *AdmissionRequest) {
			h.ipam.poolErr = errors.New("no such pool")
		}, &ErrPoolExhausted{}},
		"data plane refuses": {func(h *harness, _ *AdmissionRequest) {
			h.plane.installErr = errors.New("datapath down")
		}, &ErrDataPlaneUnavailable{}},
		"data plane not offered": {func(_ *harness, req *AdmissionRequest) {
			req.DataPlane = DataPlaneKind("carrier-pigeon")
		}, &ErrDataPlaneUnavailable{}},
		"zone not allowed": {func(_ *harness, req *AdmissionRequest) {
			req.RequestedZones = []string{"control-plane"}
		}, &ErrZoneNotAllowed{}},
		"no zones": {func(_ *harness, req *AdmissionRequest) {
			req.RequestedZones = nil
		}, &ErrInvalidRequest{}},
		"no peer": {func(_ *harness, req *AdmissionRequest) {
			req.Peer = nil
		}, &ErrInvalidRequest{}},
		"no attestation": {func(_ *harness, req *AdmissionRequest) {
			req.Attestation = nil
		}, &ErrInvalidRequest{}},
		"no posture": {func(_ *harness, req *AdmissionRequest) {
			req.Posture = nil
		}, &ErrInvalidRequest{}},
		"unknown nonce": {func(_ *harness, req *AdmissionRequest) {
			req.Nonce = []byte("never-issued")
		}, &ErrNonceUnknown{}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, testConfig())
			req := h.request(t)
			c.arrange(h, req)
			lease, err := h.svc.Admit(context.Background(), req)
			require.Error(t, err)
			assert.Nil(t, lease)
			assert.True(t, errorsAsType(err, c.want), "want %T, got %T (%v)", c.want, err, err)
			assert.Equal(t, 0, h.plane.count(), "no peer is installed on refusal")
			assert.Equal(t, 0, h.ipam.allocatedCount(), "no address stays allocated on refusal")
			leases, _ := h.svc.Leases(context.Background())
			assert.Empty(t, leases)
			assert.Equal(t, uint64(1), h.svc.Health().Refusals)
			assert.NotEmpty(t, h.svc.Health().LastRefusal)
		})
	}
}

// errorsAsType reports whether err's chain contains an error of want's type.
func errorsAsType(err error, want interface{}) bool {
	switch want.(type) {
	case *ErrPeerRefused:
		var e *ErrPeerRefused
		return errors.As(err, &e)
	case *ErrAttestationFailed:
		var e *ErrAttestationFailed
		return errors.As(err, &e)
	case *ErrPostureViolation:
		var e *ErrPostureViolation
		return errors.As(err, &e)
	case *ErrPostureUnavailable:
		var e *ErrPostureUnavailable
		return errors.As(err, &e)
	case *ErrPersonFactorRequired:
		var e *ErrPersonFactorRequired
		return errors.As(err, &e)
	case *ErrPersonFactorInvalid:
		var e *ErrPersonFactorInvalid
		return errors.As(err, &e)
	case *ErrPoolExhausted:
		var e *ErrPoolExhausted
		return errors.As(err, &e)
	case *ErrDataPlaneUnavailable:
		var e *ErrDataPlaneUnavailable
		return errors.As(err, &e)
	case *ErrZoneNotAllowed:
		var e *ErrZoneNotAllowed
		return errors.As(err, &e)
	case *ErrInvalidRequest:
		var e *ErrInvalidRequest
		return errors.As(err, &e)
	case *ErrNonceUnknown:
		var e *ErrNonceUnknown
		return errors.As(err, &e)
	case *ErrLeaseExpired:
		var e *ErrLeaseExpired
		return errors.As(err, &e)
	case *ErrLeaseNotFound:
		var e *ErrLeaseNotFound
		return errors.As(err, &e)
	}
	return false
}

func TestAdmit_FailedPeerInstallReleasesTheAddress(t *testing.T) {
	h := newHarness(t, testConfig())
	h.plane.installErr = errors.New("datapath down")
	_, err := h.svc.Admit(context.Background(), h.request(t))
	var unavailable *ErrDataPlaneUnavailable
	require.True(t, errors.As(err, &unavailable))
	assert.Equal(t, 1, h.ipam.releaseCount(), "the address allocated before the install is released")
	assert.Equal(t, 0, h.ipam.allocatedCount())
}

func TestAdmit_SecondAdmissionReplacesTheFirst(t *testing.T) {
	h := newHarness(t, testConfig())
	first, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	second, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	assert.NotEqual(t, first.ID, second.ID)

	leases, err := h.svc.Leases(context.Background())
	require.NoError(t, err)
	require.Len(t, leases, 1, "one lease per device per tenant")
	assert.Equal(t, second.ID, leases[0].ID)
	assert.Contains(t, h.plane.removed, first.ID, "the replaced peer is removed")
	assert.Equal(t, 1, h.plane.count())
	_, err = h.svc.Lease(context.Background(), first.ID)
	var nf *ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf))
}

func TestAdmit_NonceIsSingleUse(t *testing.T) {
	h := newHarness(t, testConfig())
	req := h.request(t)
	_, err := h.svc.Admit(context.Background(), req)
	require.NoError(t, err)
	replay := h.request(t)
	replay.Nonce = req.Nonce
	_, err = h.svc.Admit(context.Background(), replay)
	var unknown *ErrNonceUnknown
	assert.True(t, errors.As(err, &unknown), "a consumed nonce is refused: %v", err)
}

func TestAdmit_ExpiredNonceIsRefused(t *testing.T) {
	h := newHarness(t, testConfig())
	req := h.request(t)
	h.clock.Advance(DefaultNonceTTL + time.Second)
	_, err := h.svc.Admit(context.Background(), req)
	var unknown *ErrNonceUnknown
	assert.True(t, errors.As(err, &unknown), "got %v", err)
}

func TestAdmit_PersonFactorOptionalWhenPolicySaysSo(t *testing.T) {
	cfg := testConfig()
	cfg.RequirePersonFactor = PersonFactorPolicy{OnAdmit: false, OnRenew: true}
	h := newHarness(t, cfg)
	req := h.request(t)
	req.PersonFactor = nil
	_, err := h.svc.Admit(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, 0, h.factors.callCount())
}

func TestAdmit_AuditFailureDoesNotAdmitOrRefuseOnItsOwn(t *testing.T) {
	h := newHarness(t, testConfig())
	h.audit.err = errors.New("audit sink down")
	_, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err, "the audit sink is best-effort for the record; the decision itself was admitted")
}

func TestRenew_ExtendsInsideTheLease(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)

	h.clock.Advance(DefaultLeaseTTL - DefaultRenewWindow + time.Minute)
	ev := h.evidence(t)
	ev.PersonFactor = nil // not required on renewal by default
	renewed, err := h.svc.Renew(context.Background(), lease.ID, ev)
	require.NoError(t, err)
	assert.Equal(t, 1, renewed.Renewals)
	assert.Equal(t, h.clock.Now().Add(DefaultLeaseTTL), renewed.ExpiresAt)
	assert.Equal(t, lease.Address, renewed.Address, "the address is kept")
	assert.Equal(t, 2, h.verifier.callCount(), "renewal re-attests")
	assert.Equal(t, 2, h.posture.inputCount(), "renewal re-evaluates posture")
	assert.Equal(t, 1, h.factors.callCount(), "the person factor is not required on renewal by default")
}

// TestRenew_RefusedBeforeTheWindowOpens pins the review finding on #588:
// RenewWindow is enforced at runtime, not only validated at config time. A
// renewal an hour into an eight-hour lease is refused with the opening
// time; one inside the last thirty minutes succeeds.
func TestRenew_RefusedBeforeTheWindowOpens(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)

	h.clock.Advance(time.Hour)
	ev := h.evidence(t)
	ev.PersonFactor = nil
	_, err = h.svc.Renew(context.Background(), lease.ID, ev)
	var notOpen *ErrRenewalNotOpen
	require.True(t, errors.As(err, &notOpen), "got %v", err)
	assert.Equal(t, lease.ExpiresAt.Add(-DefaultRenewWindow), notOpen.OpensAt)
	assert.Equal(t, 1, h.verifier.callCount(), "no re-attestation is spent on a refused renewal")

	// The lease itself is untouched and renews once the window opens.
	h.clock.Advance(DefaultLeaseTTL - DefaultRenewWindow - time.Hour + time.Minute)
	renewed, err := h.svc.Renew(context.Background(), lease.ID, h.evidence(t))
	require.NoError(t, err)
	assert.Equal(t, 1, renewed.Renewals)
}

// TestRenew_PresentedFactorIsAlwaysVerified: a factor the client chose to
// present is verified even when the policy would not have asked for it — a
// presented credential that does not verify is never ignored.
func TestRenew_PresentedFactorIsAlwaysVerified(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	h.factors.err = errors.New("assertion did not verify")
	_, err = h.svc.Renew(context.Background(), lease.ID, h.evidence(t))
	var invalid *ErrPersonFactorInvalid
	assert.True(t, errors.As(err, &invalid), "got %v", err)
	assert.Equal(t, 2, h.factors.callCount())
}

func TestRenew_RequiresThePersonFactorWhenConfigured(t *testing.T) {
	cfg := testConfig()
	cfg.RequirePersonFactor = PersonFactorPolicy{OnAdmit: true, OnRenew: true}
	h := newHarness(t, cfg)
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	ev := h.evidence(t)
	ev.PersonFactor = nil
	_, err = h.svc.Renew(context.Background(), lease.ID, ev)
	var required *ErrPersonFactorRequired
	assert.True(t, errors.As(err, &required), "got %v", err)
	_, err = h.svc.Lease(context.Background(), lease.ID)
	assert.NoError(t, err, "a missing factor on renewal refuses the renewal but does not tear the lease down before expiry")
}

func TestRenew_FailedAttestationRevokes(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	h.verifier.verdict = &verdict.DeviceVerdict{Passed: false, Cryptographic: true, Reason: "drift"}
	_, err = h.svc.Renew(context.Background(), lease.ID, h.evidence(t))
	var failed *ErrAttestationFailed
	require.True(t, errors.As(err, &failed))
	assert.Contains(t, h.plane.removed, lease.ID)
	assert.Equal(t, 0, h.ipam.allocatedCount())
	_, err = h.svc.Lease(context.Background(), lease.ID)
	var nf *ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf))
}

func TestRenew_PostureDriftRevokes(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	h.posture.result = &opa.EvaluationResult{Allowed: false, Violations: []opa.Violation{{Rule: "fde-root-encrypted"}}}
	_, err = h.svc.Renew(context.Background(), lease.ID, h.evidence(t))
	var viol *ErrPostureViolation
	require.True(t, errors.As(err, &viol))
	assert.Equal(t, []string{"fde-root-encrypted"}, viol.Violations)
	assert.Contains(t, h.plane.removed, lease.ID)
}

func TestRenew_AfterExpiryIsExpiredAndRevoked(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	h.clock.Advance(DefaultLeaseTTL + time.Second)
	_, err = h.svc.Renew(context.Background(), lease.ID, h.evidence(t))
	var expired *ErrLeaseExpired
	require.True(t, errors.As(err, &expired))
	assert.Contains(t, h.plane.removed, lease.ID)
	assert.Equal(t, 0, h.ipam.allocatedCount())
}

func TestRenew_UnknownLease(t *testing.T) {
	h := newHarness(t, testConfig())
	_, err := h.svc.Renew(context.Background(), LeaseID("nope"), h.evidence(t))
	var nf *ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf))
	_, err = h.svc.Renew(context.Background(), LeaseID("nope"), nil)
	var invalid *ErrInvalidRequest
	assert.True(t, errors.As(err, &invalid))
}

func TestRenew_IPAMRenewFailureRefuses(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	h.ipam.renewErr = errors.New("lease table read-only")
	_, err = h.svc.Renew(context.Background(), lease.ID, h.evidence(t))
	var exhausted *ErrPoolExhausted
	assert.True(t, errors.As(err, &exhausted), "got %v", err)
}

func TestRevoke_OrderAndIdempotence(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)

	require.NoError(t, h.svc.Revoke(context.Background(), lease.ID, RevokeOperator))
	assert.Equal(t, []LeaseID{lease.ID}, h.plane.removed, "peer removed first")
	assert.Equal(t, 0, h.ipam.allocatedCount(), "then the address released")
	leases, _ := h.svc.Leases(context.Background())
	assert.Empty(t, leases, "then the record deleted")

	err = h.svc.Revoke(context.Background(), lease.ID, RevokeOperator)
	var nf *ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf), "a second revoke finds nothing")
	assert.Len(t, h.plane.removed, 1, "and touches nothing")
}

func TestRevoke_DataPlaneFailureStillKillsTheLease(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	h.plane.removeErr = errors.New("datapath unreachable")
	err = h.svc.Revoke(context.Background(), lease.ID, RevokeOperator)
	var unavailable *ErrDataPlaneUnavailable
	require.True(t, errors.As(err, &unavailable), "the caller is told to retry the peer")
	leases, _ := h.svc.Leases(context.Background())
	assert.Empty(t, leases, "the lease is dead regardless")
	assert.Equal(t, 0, h.ipam.allocatedCount())
}

func TestSweep_ExpiredLeasesAreRevoked(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)

	h.clock.Advance(DefaultLeaseTTL - time.Minute)
	h.svc.Sweep(context.Background())
	leases, _ := h.svc.Leases(context.Background())
	require.Len(t, leases, 1, "not yet expired")

	h.clock.Advance(2 * time.Minute)
	h.svc.Sweep(context.Background())
	leases, _ = h.svc.Leases(context.Background())
	assert.Empty(t, leases)
	assert.Contains(t, h.plane.removed, lease.ID)
	assert.Equal(t, 0, h.ipam.allocatedCount())
}

// pendingStore is a PendingDeleteStore that counts the sweep's retries.
type pendingStore struct {
	LeaseStore
	retryErr error
	retries  int
}

func (p *pendingStore) RetryPendingDeletes(context.Context) error {
	p.retries++
	return p.retryErr
}

func TestSweep_RetriesPendingDeletes(t *testing.T) {
	h := newHarness(t, testConfig())
	store := &pendingStore{LeaseStore: h.store}
	h.svc.deps.Leases = store

	h.svc.Sweep(context.Background())
	h.svc.Sweep(context.Background())
	assert.Equal(t, 2, store.retries, "every pass retries")
}

func TestSweep_AFailedRetryStillSweeps(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	store := &pendingStore{LeaseStore: h.store, retryErr: &ErrLeaseStoreUnavailable{Cause: errors.New("store down")}}
	h.svc.deps.Leases = store

	h.clock.Advance(DefaultLeaseTTL + time.Minute)
	h.svc.Sweep(context.Background())
	assert.Equal(t, 1, store.retries)
	leases, err := h.svc.Leases(context.Background())
	require.NoError(t, err)
	assert.Empty(t, leases, "a failed retry does not stop the expiry sweep")
	assert.Contains(t, h.plane.removed, lease.ID)
}

func TestSweep_RunsFromTheTicker(t *testing.T) {
	h := newHarness(t, testConfig())
	lease, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	h.clock.Advance(DefaultLeaseTTL + time.Second)
	h.clock.tick <- h.clock.Now()
	// The sweep runs on the service goroutine; wait for its effect through
	// the data plane rather than sleeping. The record goes before the peer,
	// so an emptied store does not yet mean the peer is gone.
	deadline := time.After(5 * time.Second)
	for h.plane.count() != 0 {
		select {
		case <-deadline:
			t.Fatalf("lease %s was not swept by the ticker", lease.ID)
		default:
		}
	}
	assert.Contains(t, h.plane.removed, lease.ID)
	leases, err := h.svc.Leases(context.Background())
	require.NoError(t, err)
	assert.Empty(t, leases)
}

func TestZonesAllowed(t *testing.T) {
	h := newHarness(t, testConfig())
	assert.True(t, h.svc.ZonesAllowed([]string{"management"}))
	assert.False(t, h.svc.ZonesAllowed([]string{"management", "control-plane"}))
	assert.False(t, h.svc.ZonesAllowed(nil))
}

func TestOwnLease(t *testing.T) {
	h := newHarness(t, testConfig())
	req := h.request(t)
	req.Peer.Leaf = &x509.Certificate{Raw: []byte("device certificate")}
	lease, err := h.svc.Admit(context.Background(), req)
	require.NoError(t, err)

	t.Run("the admitting certificate owns the lease", func(t *testing.T) {
		got, err := h.svc.OwnLease(context.Background(), lease.ID, &calleradmission.Peer{Leaf: &x509.Certificate{Raw: []byte("device certificate")}})
		require.NoError(t, err)
		assert.Equal(t, lease.ID, got.ID)
	})

	t.Run("refusals", func(t *testing.T) {
		cases := map[string]struct {
			id   LeaseID
			peer *calleradmission.Peer
			want any
		}{
			"no peer":             {lease.ID, nil, &ErrPeerRefused{}},
			"no leaf":             {lease.ID, &calleradmission.Peer{}, &ErrPeerRefused{}},
			"another certificate": {lease.ID, &calleradmission.Peer{Leaf: &x509.Certificate{Raw: []byte("other device")}}, &ErrLeaseNotFound{}},
			"unknown lease":       {"lease-unknown", &calleradmission.Peer{Leaf: &x509.Certificate{Raw: []byte("device certificate")}}, &ErrLeaseNotFound{}},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				_, err := h.svc.OwnLease(context.Background(), tc.id, tc.peer)
				require.Error(t, err)
				assert.IsType(t, tc.want, err)
			})
		}
	})
}

// intoRenewWindow advances the harness clock to one minute inside the
// lease's renew window, where a renewal is allowed (#588 review).
func (h *harness) intoRenewWindow() {
	h.clock.Advance(DefaultLeaseTTL - DefaultRenewWindow + time.Minute)
}
