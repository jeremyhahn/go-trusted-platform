// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"context"
	"crypto/subtle"
	"strconv"
	"time"

	bmcattestation "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
)

// Compile-time contract check.
var _ bmcattestation.Verifier = (*Verifier)(nil)

// Policy rule names, used in [bmcattestation.VerifyResult.Reasons] and in
// [bmcattestation.ErrPolicyViolation.Rule] so an audit trail names the rule
// rather than describing it differently at each call site.
const (
	RuleVendor     = "allowed_vendors"
	RuleNonceEcho  = "require_nonce_echo"
	RuleIssuer     = "trusted_issuers"
	RuleReference  = "reference"
	RuleMaxAge     = "max_age_seconds"
	RuleRelayStamp = "relay_stamp"
)

// Verifier appraises evidence against a policy.
//
// It parses through [Backend.GetInfo] rather than reading Raw, so the single
// parse point holds. It is a distinct type from the provider because the
// contract separates appraisal from collection — an appraisal service that
// never touches a device is the intended deployment — but this
// implementation does hold a provider, because the wire layout a Measurement
// comes from is the provider's knowledge and duplicating it here would put
// two parsers in one package.
type Verifier struct {
	provider *Backend
}

// NewVerifier builds a verifier that appraises through the supplied provider.
func NewVerifier(provider *Backend) (*Verifier, error) {
	if provider == nil {
		return nil, ErrNilDevice{}
	}
	return &Verifier{provider: provider}, nil
}

// Verify appraises evidence against a policy.
//
// The split between the error return and the result is deliberate:
//
//   - An ERROR means the appraisal could not be performed or must not be:
//     a nil argument, a policy that does not state an age bound, evidence
//     that does not parse, evidence belonging to another tenant. None of
//     these produce a score, because a score is a statement about a device
//     and there is nothing here to make a statement about.
//   - A RESULT with Passed false means the appraisal ran and the device
//     failed it. Reasons lists every rule that failed, not just the first,
//     so one collection answers "what is wrong with this device".
//
// Rules are evaluated in a fixed order and none of them short-circuits.
func (v *Verifier) Verify(ctx context.Context, ev *bmcattestation.Evidence, pol *bmcattestation.Policy) (*bmcattestation.VerifyResult, error) {
	if ev == nil {
		return nil, bmcattestation.ErrInvalidEvidence{Reason: "nil evidence"}
	}
	if pol == nil {
		return nil, ErrNilPolicy{}
	}
	// MaxAgeSeconds is REQUIRED and is not defaulted. The contract treats
	// zero as "no age check"; here a zero would mean an unbounded posture
	// silently reading as a current one, which is the exact failure this
	// subsystem exists to prevent.
	if pol.MaxAgeSeconds <= 0 {
		return nil, ErrPolicyMaxAgeUnset{}
	}

	info, err := v.provider.GetInfo(ctx, ev)
	if err != nil {
		return nil, err
	}

	result := &bmcattestation.VerifyResult{Passed: true}
	fail := func(rule, detail string) {
		result.Passed = false
		result.Reasons = append(result.Reasons,
			bmcattestation.ErrPolicyViolation{Rule: rule, Detail: detail}.Error())
	}

	if !vendorAllowed(pol.AllowedVendors, ev.Vendor) {
		fail(RuleVendor, "vendor "+strconv.Quote(string(ev.Vendor))+" is not in the allowed set")
	}

	if pol.RequireNonceEcho {
		v.checkNonceEcho(ev, info, fail)
	}

	if len(pol.TrustedIssuers) > 0 {
		v.checkIssuer(pol.TrustedIssuers, info, fail)
	}

	if pol.Reference != nil {
		v.checkReference(ctx, ev, pol.Reference, fail)
	}

	v.checkAge(ev, pol.MaxAgeSeconds, fail)

	return result, nil
}

// checkNonceEcho compares what the device echoed against what this host
// asked for, in constant time.
//
// A device with no clock has nothing but this nonce separating a live answer
// from a replayed recording, so the comparison is against Evidence.Nonce —
// the challenge the provider issued — and never against anything read back
// out of Raw.
//
// On alias certificate evidence there is no echo to compare: the challenge
// lives in the UCCS claims set, which this package does not decode. That
// FAILS rather than passing. A policy that asked for a nonce check and got
// silence must not be told the check succeeded.
func (v *Verifier) checkNonceEcho(ev *bmcattestation.Evidence, info *bmcattestation.Measurement, fail func(rule, detail string)) {
	if len(info.NonceEcho) == 0 {
		fail(RuleNonceEcho, "this evidence carries no readable nonce echo; the challenge in an "+
			"alias certificate is inside tcg-dice-UCCS-evidence and is verified by go-xkms, not here")
		return
	}
	if len(ev.Nonce) == 0 {
		fail(RuleNonceEcho, "evidence records no challenge to compare the echo against")
		return
	}
	if subtle.ConstantTimeCompare(info.NonceEcho, ev.Nonce) != 1 {
		fail(RuleNonceEcho, "the nonce the device echoed is not the challenge that was issued")
	}
}

// checkIssuer requires the leaf's issuer to be one the policy trusts.
//
// This is a NAME check and not a chain verification. Building a DICE chain
// and verifying the signatures over it is go-xkms's dice.Verify; a name match
// here narrows which certificates are worth forwarding and claims nothing
// more than that.
func (v *Verifier) checkIssuer(trusted []string, info *bmcattestation.Measurement, fail func(rule, detail string)) {
	if len(info.CertChain) == 0 {
		fail(RuleIssuer, "policy names trusted issuers but this evidence carries no certificate")
		return
	}
	issuer := info.CertChain[0].Issuer.String()
	for _, want := range trusted {
		if issuer == want {
			return
		}
	}
	fail(RuleIssuer, "leaf issuer "+strconv.Quote(issuer)+" is not a trusted issuer")
}

// checkReference runs the golden-build comparison. This is where
// trusted-firmware's reproducible FWHash lands.
func (v *Verifier) checkReference(ctx context.Context, live, ref *bmcattestation.Evidence, fail func(rule, detail string)) {
	cmp, err := v.provider.Compare(ctx, live, ref)
	if err != nil {
		fail(RuleReference, "comparison against the reference could not be performed: "+err.Error())
		return
	}
	if cmp.Match {
		return
	}
	for _, d := range cmp.Differences {
		fail(RuleReference, d.Field+" is "+strconv.Quote(d.Live)+
			", reference is "+strconv.Quote(d.Ref))
	}
}

// checkAge bounds how long ago this gateway relayed the evidence.
//
// CreatedAt is the GATEWAY's stamp. Nothing device-supplied is compared
// against the clock: the frame's uptime is not a timestamp and is not used
// here. Unstamped evidence fails — a zero time would otherwise compute as
// impossibly old or, worse, be special-cased into passing.
func (v *Verifier) checkAge(ev *bmcattestation.Evidence, maxAgeSeconds int64, fail func(rule, detail string)) {
	if ev.CreatedAt.IsZero() {
		fail(RuleRelayStamp, "evidence carries no relay timestamp, so its age cannot be bounded")
		return
	}
	age := v.provider.now().Sub(ev.CreatedAt)
	if age < 0 {
		fail(RuleRelayStamp, "evidence is stamped "+
			strconv.FormatInt(int64(-age/time.Second), 10)+"s in the future")
		return
	}
	if age > time.Duration(maxAgeSeconds)*time.Second {
		fail(RuleMaxAge, "evidence is "+strconv.FormatInt(int64(age/time.Second), 10)+
			"s old, policy allows "+strconv.FormatInt(maxAgeSeconds, 10)+"s")
	}
}

// vendorAllowed reports whether a vendor satisfies the policy's allow list.
// An empty list means any known vendor, per the contract.
func vendorAllowed(allowed []bmcattestation.Vendor, got bmcattestation.Vendor) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, want := range allowed {
		if want == got {
			return true
		}
	}
	return false
}
