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
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
)

func TestLeasePaths_EscapeTheID(t *testing.T) {
	assert.Equal(t, "/api/v1/vpn/leases/l-1", LeasePath("l-1"))
	assert.Equal(t, "/api/v1/vpn/leases/l-1/renew", LeaseRenewPath("l-1"))
	assert.Equal(t, "/api/v1/vpn/leases/a%2Fb", LeasePath("a/b"), "an id must not add a path segment")
}

func wireTestAttestation() *manifest.HostAttestation {
	return &manifest.HostAttestation{
		QuoteData:          []byte("quoted"),
		Signature:          []byte("sig"),
		SignatureAlgorithm: "ECDSA-SHA256",
		PCRs: []manifest.PCRValue{
			{Index: 0, Value: []byte{0xde, 0xad}, Algorithm: "sha256"},
			{Index: 7, Value: []byte{0xbe, 0xef}, Algorithm: "sha256"},
		},
		PCRDigest:         []byte("digest"),
		Nonce:             []byte("nonce-1"),
		Timestamp:         time.Unix(1760300000, 0).UTC(),
		AKPublicKey:       []byte("ak"),
		IDevIDCertificate: []byte("cert"),
		HashAlgorithm:     "sha256",
		FirmwareVersion:   "1.2",
	}
}

func TestAttestationWire_RoundTripsThroughJSON(t *testing.T) {
	att := wireTestAttestation()

	raw, err := json.Marshal(AttestationFromHost(att))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"value":"dead"`, "PCR values travel as hex")

	var decoded AttestationWire
	require.NoError(t, json.Unmarshal(raw, &decoded))
	got, err := decoded.HostAttestation(att.Nonce)
	require.NoError(t, err)
	assert.Equal(t, att, got)
}

func TestAttestationWire_NilStaysNil(t *testing.T) {
	assert.Nil(t, AttestationFromHost(nil))
	var w *AttestationWire
	got, err := w.HostAttestation([]byte("n"))
	require.NoError(t, err)
	assert.Nil(t, got, "a missing attestation is the verifier's refusal, not a decode error")
}

func TestAttestationWire_RejectsANonHexPCR(t *testing.T) {
	w := &AttestationWire{PCRs: []PCRWire{{Index: 7, Value: "zz"}}}
	_, err := w.HostAttestation([]byte("n"))
	var invalid *ErrInvalidRequest
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "attestation.pcrs[7].value", invalid.Field)
}

func TestPersonFactorWire_RoundTrips(t *testing.T) {
	f := &PersonFactor{Kind: PersonFactorFIDO2, CredentialID: "cred-1", Assertion: []byte("assertion")}
	assert.Equal(t, f, PersonFactorToWire(f).PersonFactor())
}

func TestPersonFactorWire_NilStaysNil(t *testing.T) {
	assert.Nil(t, PersonFactorToWire(nil))
	var w *PersonFactorWire
	assert.Nil(t, w.PersonFactor())
}

func TestLeaseToWire_RenewAtOpensTheWindowBeforeExpiry(t *testing.T) {
	issued := time.Unix(1760300000, 0)
	lease := &Lease{
		ID: "l-1", DeviceID: "laptop-1", TenantID: "acme",
		Address: netip.MustParsePrefix("10.8.0.2/32"), Zones: []string{"management"},
		DataPlane: DataPlaneMASQUE, IssuedAt: issued, ExpiresAt: issued.Add(8 * time.Hour),
		Renewals: 2, Verdict: VerdictSummary{Passed: true, Cryptographic: true, ProfileID: 9},
	}
	ep := EndpointWire{MASQUE: &MASQUEEndpointWire{Template: "https://gw/masque", Routes: []string{"10.0.0.0/8"}}}

	w := LeaseToWire(lease, time.Hour, ep)

	assert.Equal(t, "10.8.0.2/32", w.Address)
	assert.Equal(t, issued.Unix(), w.IssuedAtUnix)
	assert.Equal(t, issued.Add(8*time.Hour).Unix(), w.ExpiresAtUnix)
	assert.Equal(t, issued.Add(7*time.Hour).Unix(), w.RenewAtUnix)
	assert.Equal(t, ep, w.Endpoint)
	assert.Equal(t, lease.Verdict, w.Verdict)
	assert.Equal(t, 2, w.Renewals)
}

func TestRefusalOf_MapsEveryErrorToItsClassAndStatus(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		class  RefusalClass
		status int
		rules  []string
	}{
		{"untrusted issuer", &ErrPeerRefused{Reason: calleradmission.ReasonUntrustedIssuer}, "untrusted-issuer", http.StatusUnauthorized, nil},
		{"no identity", &ErrPeerRefused{Reason: calleradmission.ReasonNoIdentity}, "no-identity", http.StatusUnauthorized, nil},
		{"not listed", &ErrPeerRefused{Reason: calleradmission.ReasonNotListed}, "not-listed", http.StatusForbidden, nil},
		{"attestation", &ErrAttestationFailed{DeviceID: "d", Reason: "pcr 7 mismatch"}, RefusalAttestationFailed, http.StatusForbidden, nil},
		{"posture", &ErrPostureViolation{Violations: []string{"secure_boot", "fde"}}, RefusalPostureViolation, http.StatusForbidden, []string{"secure_boot", "fde"}},
		{"not enrolled", &ErrPeerNotEnrolled{TenantID: "t", DeviceID: "d"}, RefusalPeerNotEnrolled, http.StatusForbidden, nil},
		{"zone", &ErrZoneNotAllowed{Zone: "storage"}, RefusalZoneNotAllowed, http.StatusForbidden, nil},
		{"factor required", &ErrPersonFactorRequired{}, RefusalPersonFactorRequired, http.StatusUnauthorized, nil},
		{"factor invalid", &ErrPersonFactorInvalid{FactorName: "fido2"}, RefusalPersonFactorInvalid, http.StatusUnauthorized, nil},
		{"nonce", &ErrNonceUnknown{}, RefusalNonceUnknown, http.StatusUnauthorized, nil},
		{"posture unavailable", &ErrPostureUnavailable{Cause: &ErrPosturePolicyInvalid{Name: "corp"}}, RefusalPostureUnavailable, http.StatusServiceUnavailable, nil},
		{"pool", &ErrPoolExhausted{Pool: "acme"}, RefusalPoolExhausted, http.StatusServiceUnavailable, nil},
		{"data plane", &ErrDataPlaneUnavailable{Kind: DataPlaneMASQUE, Cause: &ErrPeerKeyInvalid{Kind: DataPlaneMASQUE}}, RefusalDataPlaneUnavailable, http.StatusServiceUnavailable, nil},
		{"lease store", &ErrLeaseStoreUnavailable{Cause: &ErrNotStarted{}}, RefusalLeaseStoreUnavailable, http.StatusServiceUnavailable, nil},
		{"not started", &ErrNotStarted{}, RefusalNotStarted, http.StatusServiceUnavailable, nil},
		{"expired", &ErrLeaseExpired{LeaseID: "l"}, RefusalLeaseExpired, http.StatusGone, nil},
		{"not found", &ErrLeaseNotFound{LeaseID: "l"}, RefusalLeaseNotFound, http.StatusNotFound, nil},
		{"renewal early", &ErrRenewalNotOpen{LeaseID: "l"}, RefusalRenewalNotOpen, http.StatusConflict, nil},
		{"invalid", &ErrInvalidRequest{Field: "nonce", Reason: "empty"}, RefusalInvalidRequest, http.StatusBadRequest, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refusal, status := RefusalOf(tt.err)
			assert.Equal(t, tt.class, refusal.Reason)
			assert.Equal(t, tt.status, status)
			assert.Equal(t, tt.rules, refusal.Rules)
		})
	}
}

func TestRefusalOf_UnknownErrorIsInternalWithoutDetail(t *testing.T) {
	refusal, status := RefusalOf(&ErrDepsMissing{Dep: "Verifier"})
	assert.Equal(t, RefusalWire{Reason: RefusalInternal}, refusal)
	assert.Equal(t, http.StatusInternalServerError, status)
}

func TestRefusalWire_PostureRulesOnlyWhenPresent(t *testing.T) {
	raw, err := json.Marshal(RefusalWire{Reason: RefusalPoolExhausted})
	require.NoError(t, err)
	assert.JSONEq(t, `{"reason":"pool-exhausted"}`, string(raw))
}
