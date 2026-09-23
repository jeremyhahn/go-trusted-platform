// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	bmcattestation "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
)

// livePolicy is the smallest policy this backend accepts: an explicit age
// bound and a nonce echo requirement.
func livePolicy() *bmcattestation.Policy {
	return &bmcattestation.Policy{
		AllowedVendors:   []bmcattestation.Vendor{Vendor},
		RequireNonceEcho: true,
		MaxAgeSeconds:    300,
	}
}

// newTestVerifier builds a verifier over a device that answers the given
// evidence frame, and returns the evidence it collected.
func newTestVerifier(t *testing.T, raw []byte, nonce []byte) (*Verifier, *bmcattestation.Evidence) {
	t.Helper()
	b := newTestBackend(t, secureElementLink().answerAttest(raw))
	v, err := NewVerifier(b)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ev, err := b.Dump(context.Background(), nonce)
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	return v, ev
}

func TestNewVerifier_RefusesANilProvider(t *testing.T) {
	if _, err := NewVerifier(nil); err == nil {
		t.Fatal("NewVerifier accepted a nil provider")
	}
}

func TestVerify_PassesFreshEvidenceFromTheRightDevice(t *testing.T) {
	nonce := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)

	got, err := v.Verify(context.Background(), ev, livePolicy())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !got.Passed {
		t.Fatalf("Passed = false, reasons = %v", got.Reasons)
	}
}

func TestVerify_RefusesAPolicyWithNoAgeBound(t *testing.T) {
	// A stale posture must never read as a good one. The vendor-neutral
	// contract treats zero as "no age check"; this backend refuses it, so a
	// caller cannot disable the rule by leaving a field at its zero value.
	nonce := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)

	for _, maxAge := range []int64{0, -1} {
		pol := livePolicy()
		pol.MaxAgeSeconds = maxAge
		_, err := v.Verify(context.Background(), ev, pol)
		var want ErrPolicyMaxAgeUnset
		if !errors.As(err, &want) {
			t.Fatalf("MaxAgeSeconds=%d: err = %T (%v), want ErrPolicyMaxAgeUnset", maxAge, err, err)
		}
	}
}

func TestVerify_RefusesMissingArguments(t *testing.T) {
	nonce := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)

	if _, err := v.Verify(context.Background(), nil, livePolicy()); err == nil {
		t.Fatal("Verify accepted nil evidence")
	}
	_, err := v.Verify(context.Background(), ev, nil)
	var want ErrNilPolicy
	if !errors.As(err, &want) {
		t.Fatalf("err = %T (%v), want ErrNilPolicy", err, err)
	}
}

func TestVerify_RefusesAnotherTenantsEvidence(t *testing.T) {
	// Cross-tenant evidence is never scored: a refusal, not a failed
	// appraisal that a caller might log and move past.
	nonce := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)
	ev.Metadata[MetadataTenantID] = "globex"

	_, err := v.Verify(context.Background(), ev, livePolicy())
	var want ErrTenantMismatch
	if !errors.As(err, &want) {
		t.Fatalf("err = %T (%v), want ErrTenantMismatch", err, err)
	}
	if want.Want != testTenant || want.Got != "globex" {
		t.Fatalf("error does not name both tenants: %+v", want)
	}
}

func TestVerify_FailsAReplayedRecording(t *testing.T) {
	// The device echoed a nonce that is not the one this host issued, which
	// on a device with no clock is the only thing separating a live answer
	// from a replay.
	issued := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(attestNonce(0x99)), issued)

	got, err := v.Verify(context.Background(), ev, livePolicy())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Passed {
		t.Fatal("Passed = true for evidence bound to a different challenge")
	}
	assertReason(t, got, RuleNonceEcho)
}

func TestVerify_FailsWhenTheChallengeWasNotRecorded(t *testing.T) {
	nonce := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)
	ev.Nonce = nil

	got, err := v.Verify(context.Background(), ev, livePolicy())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Passed {
		t.Fatal("Passed = true with no recorded challenge to compare against")
	}
	assertReason(t, got, RuleNonceEcho)
}

func TestVerify_WillNotClaimANonceCheckItCannotPerform(t *testing.T) {
	// The challenge in an alias certificate lives inside the UCCS claims
	// set, which this package does not decode. A policy that asked for a
	// nonce check must not be told it succeeded.
	der := aliasCertificate(t, true)
	b := newTestBackend(t, secureElementLink().answerAttestCert(der))
	v, err := NewVerifier(b)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ev, err := b.AttestCert(context.Background(), aliasNonce(3))
	if err != nil {
		t.Fatalf("AttestCert: %v", err)
	}

	got, err := v.Verify(context.Background(), ev, livePolicy())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Passed {
		t.Fatal("Passed = true for a check this package does not perform")
	}
	assertReason(t, got, RuleNonceEcho)
	if !strings.Contains(strings.Join(got.Reasons, " "), "go-xkms") {
		t.Fatalf("the reason does not say who does perform it: %v", got.Reasons)
	}
}

func TestVerify_FailsStaleEvidence(t *testing.T) {
	nonce := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)
	pol := livePolicy()
	pol.MaxAgeSeconds = 60
	ev.CreatedAt = frozenNow.Add(-2 * time.Minute)

	got, err := v.Verify(context.Background(), ev, pol)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Passed {
		t.Fatal("Passed = true for evidence older than the policy allows")
	}
	assertReason(t, got, RuleMaxAge)
}

func TestVerify_FailsEvidenceWithNoRelayStamp(t *testing.T) {
	// A zero time would otherwise compute as impossibly old, or worse be
	// special-cased into passing.
	nonce := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)
	ev.CreatedAt = time.Time{}

	got, err := v.Verify(context.Background(), ev, livePolicy())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Passed {
		t.Fatal("Passed = true for unstamped evidence")
	}
	assertReason(t, got, RuleRelayStamp)
}

func TestVerify_FailsEvidenceStampedInTheFuture(t *testing.T) {
	nonce := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)
	ev.CreatedAt = frozenNow.Add(time.Hour)

	got, err := v.Verify(context.Background(), ev, livePolicy())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Passed {
		t.Fatal("Passed = true for evidence stamped in the future")
	}
	assertReason(t, got, RuleRelayStamp)
}

func TestVerify_FailsAVendorThePolicyDoesNotAllow(t *testing.T) {
	nonce := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)
	pol := livePolicy()
	pol.AllowedVendors = []bmcattestation.Vendor{bmcattestation.VendorDell}

	got, err := v.Verify(context.Background(), ev, pol)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Passed {
		t.Fatal("Passed = true for a vendor the policy excludes")
	}
	assertReason(t, got, RuleVendor)
}

func TestVerify_AnEmptyVendorListMeansAnyKnownVendor(t *testing.T) {
	nonce := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)
	pol := livePolicy()
	pol.AllowedVendors = nil

	got, err := v.Verify(context.Background(), ev, pol)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !got.Passed {
		t.Fatalf("Passed = false, reasons = %v", got.Reasons)
	}
}

func TestVerify_PassesAGoldenBuildAndFailsADriftedOne(t *testing.T) {
	nonce := attestNonce(0x42)
	golden := evidenceFor(buildFrame(frameOpts{
		version: frameVersion, nonce: attestNonce(9), deviceID: testDeviceID,
		fwHash: goldenFWHash, algorithm: 1,
	}))

	t.Run("golden", func(t *testing.T) {
		v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)
		pol := livePolicy()
		pol.Reference = golden

		got, err := v.Verify(context.Background(), ev, pol)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !got.Passed {
			t.Fatalf("Passed = false, reasons = %v", got.Reasons)
		}
	})

	t.Run("drifted", func(t *testing.T) {
		drifted := buildFrame(frameOpts{
			version: frameVersion, nonce: nonce, deviceID: testDeviceID,
			fwHash: make([]byte, lenFrameFWHash), algorithm: 1,
		})
		v, ev := newTestVerifier(t, drifted, nonce)
		pol := livePolicy()
		pol.Reference = golden

		got, err := v.Verify(context.Background(), ev, pol)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if got.Passed {
			t.Fatal("Passed = true for a device running something other than the golden build")
		}
		assertReason(t, got, RuleReference)
	})
}

func TestVerify_ReportsAReferenceItCannotCompare(t *testing.T) {
	nonce := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)
	pol := livePolicy()
	bad := evidenceFor(defaultFrame(nonce))
	bad.Raw = bad.Raw[:10]
	pol.Reference = bad

	got, err := v.Verify(context.Background(), ev, pol)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Passed {
		t.Fatal("Passed = true against a reference that could not be parsed")
	}
	assertReason(t, got, RuleReference)
}

func TestVerify_ChecksTheCertificateIssuer(t *testing.T) {
	der := aliasCertificate(t, true)
	b := newTestBackend(t, secureElementLink().answerAttestCert(der))
	v, err := NewVerifier(b)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ev, err := b.AttestCert(context.Background(), aliasNonce(4))
	if err != nil {
		t.Fatalf("AttestCert: %v", err)
	}

	t.Run("trusted", func(t *testing.T) {
		pol := livePolicy()
		pol.RequireNonceEcho = false
		pol.TrustedIssuers = []string{"CN=ag DeviceID"}

		got, err := v.Verify(context.Background(), ev, pol)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !got.Passed {
			t.Fatalf("Passed = false, reasons = %v", got.Reasons)
		}
	})

	t.Run("untrusted", func(t *testing.T) {
		pol := livePolicy()
		pol.RequireNonceEcho = false
		pol.TrustedIssuers = []string{"CN=somebody else"}

		got, err := v.Verify(context.Background(), ev, pol)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if got.Passed {
			t.Fatal("Passed = true for a leaf from an issuer the policy does not trust")
		}
		assertReason(t, got, RuleIssuer)
	})
}

func TestVerify_FailsAnIssuerRuleWithNoCertificate(t *testing.T) {
	nonce := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(nonce), nonce)
	pol := livePolicy()
	pol.TrustedIssuers = []string{"CN=ag DeviceID"}

	got, err := v.Verify(context.Background(), ev, pol)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Passed {
		t.Fatal("Passed = true for an issuer rule against evidence with no certificate")
	}
	assertReason(t, got, RuleIssuer)
}

func TestVerify_ReportsEveryFailedRuleNotJustTheFirst(t *testing.T) {
	// One collection should answer "what is wrong with this device", so no
	// rule short-circuits the rest.
	issued := attestNonce(0x42)
	v, ev := newTestVerifier(t, defaultFrame(attestNonce(0x99)), issued)
	ev.CreatedAt = frozenNow.Add(-time.Hour)
	pol := livePolicy()
	pol.AllowedVendors = []bmcattestation.Vendor{bmcattestation.VendorHPE}

	got, err := v.Verify(context.Background(), ev, pol)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Passed {
		t.Fatal("Passed = true")
	}
	for _, rule := range []string{RuleVendor, RuleNonceEcho, RuleMaxAge} {
		assertReason(t, got, rule)
	}
}

// assertReason fails the test unless the result names the given rule.
func assertReason(t *testing.T, got *bmcattestation.VerifyResult, rule string) {
	t.Helper()
	for _, r := range got.Reasons {
		if strings.Contains(r, rule) {
			return
		}
	}
	t.Fatalf("reasons do not name rule %q: %v", rule, got.Reasons)
}
