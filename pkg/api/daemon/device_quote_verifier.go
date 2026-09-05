// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// DeviceQuoteEvidence is the TPM quote evidence a device submits for
// verification. It is the same shape on every transport: gRPC and Unix carry
// it as the AttestDeviceRequest.evidence bytes, QUIC and the live REST stack
// pass those bytes through, and MCP carries it as the tool's evidence
// argument.
//
// PCRs are the values the device READ from its TPM for the quoted selection.
// They are not trusted as-is: the verifier proves they hash to the digest the
// TPM signed, then compares them against the baseline recorded on the
// device's profile. The attester never supplies the expected state (#373).
type DeviceQuoteEvidence struct {
	// Quote is the marshaled TPMS_ATTEST structure the TPM produced.
	Quote []byte `json:"quote"`
	// Signature is the attestation-key signature over Quote.
	Signature []byte `json:"signature"`
	// Nonce is the verifier-issued anti-replay value that must appear in
	// the quote's extraData.
	Nonce []byte `json:"nonce"`
	// PCRs maps PCR index to the SHA-256 value the device read for it. The
	// index set must exactly match the quote's PCR selection.
	PCRs map[int][]byte `json:"pcrs"`
}

// DeviceAttestationResult reports what was verified, check by check, so a
// caller can tell a bad signature from a PCR mismatch from a device that has
// simply never enrolled an attestation certificate.
type DeviceAttestationResult struct {
	DeviceID uint64 `json:"device_id,string"`
	Serial   string `json:"serial,omitempty"`
	Model    string `json:"model,omitempty"`
	// Verified is the overall verdict: true only when every check passed.
	Verified bool `json:"verified"`
	// AKCertificateVerified is true when the device's enrolled attestation
	// certificate chains to the platform CA and carries
	// tcg-cap-verifiedTPMRestricted (TCG DevID v1 r12 §8.2).
	AKCertificateVerified bool `json:"ak_certificate_verified"`
	SignatureValid        bool `json:"signature_valid"`
	NonceValid            bool `json:"nonce_valid"`
	// PCRsValid is true when the reported PCR values hash to the signed
	// digest AND match the profile baseline.
	PCRsValid bool `json:"pcrs_valid"`
	// PCRBaselineSource is where the baseline the quote was compared against
	// came from: "signed" or "tofu". Empty when no baseline was evaluated.
	PCRBaselineSource string `json:"pcr_baseline_source,omitempty"`
	// PCRBaselineRecordedAt is when that baseline was recorded, so an
	// operator can see how old the expected state is.
	PCRBaselineRecordedAt time.Time `json:"pcr_baseline_recorded_at,omitempty"`
	// PCRBaselineCaptured is true when THIS verification recorded the
	// profile's trust-on-first-use baseline from the device's reported
	// values. It is a security event and is logged as one.
	PCRBaselineCaptured bool `json:"pcr_baseline_captured"`
	// CryptographicFailure is true when a negative verdict came from a check
	// that RAN and failed — bad certificate chain, bad signature, wrong
	// nonce, PCR divergence from a known baseline — as opposed to a check
	// that could not run (no certificate, no profile, no baseline). Only the
	// former is grounds for quarantine; the reporting collector carries the
	// distinction onto the cached report.
	CryptographicFailure bool      `json:"cryptographic_failure"`
	Status               string    `json:"status"`
	Message              string    `json:"message,omitempty"`
	AttestedAt           time.Time `json:"attested_at"`
}

// AKTrustAnchor is the slice of the platform CA the verifier needs to chain
// an attestation certificate: the root and, when the issuing CA is
// subordinate, the intermediate. The quicbaas CACertificateAuthority
// satisfies it.
type AKTrustAnchor interface {
	TrustedRoot() (*x509.Certificate, error)
	TrustedIntermediate() (*x509.Certificate, error)
}

// DeviceQuoteVerifier is the single implementation of device quote
// verification, shared by every transport that exposes it (gRPC, Unix, QUIC,
// the live REST stack and MCP). One implementation is what lets the
// transports answer identically; a copy per transport is how two of them
// come to disagree about whether a device attested.
//
// It fails closed throughout: every check runs against real crypto, and a
// check that cannot run is not treated as a check that passed.
type DeviceQuoteVerifier struct {
	devices  device.DeviceService
	profiles device.DeviceProfileService
	trust    AKTrustAnchor
	verdicts verdict.Sink
	now      func() time.Time
	logger   *slog.Logger
}

// NewDeviceQuoteVerifier constructs a verifier. trust and verdicts may be nil
// in a deployment that has no CA or no attestation service: quotes then fail
// closed (no trust anchor) and verdicts are only logged.
func NewDeviceQuoteVerifier(
	devices device.DeviceService,
	profiles device.DeviceProfileService,
	trust AKTrustAnchor,
	verdicts verdict.Sink,
	logger *slog.Logger,
) *DeviceQuoteVerifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &DeviceQuoteVerifier{
		devices:  devices,
		profiles: profiles,
		trust:    trust,
		verdicts: verdicts,
		now:      func() time.Time { return time.Now().UTC() },
		logger:   logger,
	}
}

// quoteChecks accumulates the outcome of the individual checks so the
// verdict's failure class can be derived in one place.
type quoteChecks struct {
	failures      []string
	cryptographic bool
}

// fail records a cryptographic failure: the evidence was present and did not
// verify.
func (c *quoteChecks) fail(reason string) {
	c.failures = append(c.failures, reason)
	c.cryptographic = true
}

// absent records an absence of evidence: a check that could not run. The
// device is denied service but not quarantined.
func (c *quoteChecks) absent(reason string) {
	c.failures = append(c.failures, reason)
}

// Verify evaluates one quote for one device. It returns an error only when
// the request itself is unusable (unknown device, malformed evidence, a
// dependency missing); a quote that fails verification is a successful call
// whose result says Verified=false.
func (v *DeviceQuoteVerifier) Verify(ctx context.Context, deviceID string, evidence []byte) (*DeviceAttestationResult, error) {
	if v == nil || v.devices == nil {
		return nil, ErrServiceNotAvailable{Service: "device"}
	}
	if v.profiles == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	if deviceID == "" {
		return nil, ErrAttestationFailed{Reason: "device ID is required"}
	}
	if len(evidence) == 0 {
		return nil, ErrAttestationFailed{Reason: "attestation evidence is required"}
	}

	id, err := parseDeviceID(deviceID)
	if err != nil {
		return nil, err
	}

	var quote DeviceQuoteEvidence
	if err := json.Unmarshal(evidence, &quote); err != nil {
		return nil, ErrInvalidAttestationEvidence{Reason: "evidence must be JSON-encoded device quote evidence"}
	}
	if len(quote.Quote) == 0 {
		return nil, ErrInvalidAttestationEvidence{Reason: "quote is required"}
	}
	if len(quote.Signature) == 0 {
		return nil, ErrInvalidAttestationEvidence{Reason: "signature is required"}
	}
	if len(quote.Nonce) == 0 {
		return nil, ErrInvalidAttestationEvidence{Reason: "nonce is required"}
	}
	if len(quote.PCRs) == 0 {
		return nil, ErrInvalidAttestationEvidence{Reason: "pcrs are required: the device must report the values it quoted"}
	}

	dev, err := v.devices.Get(ctx, id)
	if err != nil {
		return nil, ErrDeviceNotFound{DeviceID: deviceID}
	}

	now := v.now()
	result := &DeviceAttestationResult{
		DeviceID:   dev.ID,
		Serial:     dev.Serial,
		Model:      dev.Model,
		AttestedAt: now,
	}
	checks := &quoteChecks{}
	dv := verdict.DeviceVerdict{DeviceID: dev.ID, HostID: dev.Hostname, Serial: dev.Serial}

	akPublicKey := v.verifyAKCertificate(dev, now, result, checks)

	quoteVerified := false
	if akPublicKey != nil {
		quoteVerified = v.verifyQuote(akPublicKey, &quote, result, checks)
	} else {
		checks.absent("quote not evaluated: no verified attestation key")
	}

	if quoteVerified {
		v.evaluateBaseline(ctx, dev, quote.PCRs, now, result, checks, &dv)
	} else {
		checks.absent("PCR baseline not evaluated: quote did not verify")
	}

	result.Verified = result.AKCertificateVerified && result.SignatureValid && result.NonceValid && result.PCRsValid
	if result.Verified {
		result.Status = "verified"
		result.Message = "device attestation verified"
	} else {
		result.Status = "failed"
		result.Message = strings.Join(checks.failures, "; ")
	}

	result.CryptographicFailure = !result.Verified && checks.cryptographic
	dv.Passed = result.Verified
	dv.Cryptographic = checks.cryptographic
	if !result.Verified {
		dv.Reason = result.Message
	}
	v.record(ctx, dv)

	return result, nil
}

// verifyAKCertificate resolves the trust anchor for the quote signature: the
// device's enrolled attestation certificate, chained to the platform CA and
// carrying tcg-cap-verifiedTPMRestricted. It returns the certified public key
// in PKIX DER, or nil when no key can be trusted.
//
// A bare AttestPub is deliberately not accepted as an anchor: without the
// certificate the Restricted attribute cannot be checked, and DevID §8.2
// makes that check a MUST for a relying party. A device enrolled before
// certificates were recorded is denied service, not quarantined.
func (v *DeviceQuoteVerifier) verifyAKCertificate(dev *deviceentities.Device, now time.Time, result *DeviceAttestationResult, checks *quoteChecks) []byte {
	if strings.TrimSpace(dev.AttestCert) == "" {
		checks.absent("no attestation certificate enrolled for device; tcg-cap-verifiedTPMRestricted cannot be checked (TCG DevID §8.2)")
		return nil
	}
	if v.trust == nil {
		checks.absent("no CA trust anchor configured; attestation certificate cannot be chained")
		return nil
	}

	roots := x509.NewCertPool()
	root, err := v.trust.TrustedRoot()
	if err != nil || root == nil {
		checks.absent("CA trust anchor unavailable; attestation certificate cannot be chained")
		return nil
	}
	roots.AddCert(root)

	var intermediates *x509.CertPool
	if intermediate, err := v.trust.TrustedIntermediate(); err == nil && intermediate != nil {
		intermediates = x509.NewCertPool()
		intermediates.AddCert(intermediate)
	}

	pub, err := vm.VerifyAKCertificate([]byte(dev.AttestCert), roots, intermediates, now)
	if err != nil {
		checks.fail(err.Error())
		return nil
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		checks.fail("attestation certificate carries an unsupported public key: " + err.Error())
		return nil
	}
	result.AKCertificateVerified = true
	return der
}

// verifyQuote checks the signature, the nonce and that the reported PCR
// values are the ones the TPM signed. It returns true only when all three
// hold, which is the precondition for reading the PCR values as evidence.
func (v *DeviceQuoteVerifier) verifyQuote(akPublicKey []byte, quote *DeviceQuoteEvidence, result *DeviceAttestationResult, checks *quoteChecks) bool {
	if err := vm.VerifyQuoteSignature(akPublicKey, quote.Quote, quote.Signature); err != nil {
		checks.fail(err.Error())
	} else {
		result.SignatureValid = true
	}

	if err := vm.VerifyQuoteNonce(quote.Quote, quote.Nonce); err != nil {
		checks.fail(err.Error())
	} else {
		result.NonceValid = true
	}

	digestValid := false
	if err := vm.VerifyQuotePCRDigest(quote.Quote, quote.PCRs); err != nil {
		checks.fail("reported PCR values do not match the signed digest: " + err.Error())
	} else {
		digestValid = true
	}

	return result.SignatureValid && result.NonceValid && digestValid
}

// evaluateBaseline compares the (now proven) reported PCR values against the
// baseline on the device's profile. A profile with no baseline captures one
// on first use — a trust-on-first-use event that is recorded as such — and
// the quote passes against the baseline it just set.
func (v *DeviceQuoteVerifier) evaluateBaseline(
	ctx context.Context,
	dev *deviceentities.Device,
	reported map[int][]byte,
	now time.Time,
	result *DeviceAttestationResult,
	checks *quoteChecks,
	dv *verdict.DeviceVerdict,
) {
	// The one device -> profile resolver the collector also uses (#463):
	// the profile bound to this device's EK identity first, else the match
	// rules. Both consumers therefore always land on the same profile.
	profile, err := v.profiles.FindProfileForDevice(ctx, dev)
	if err != nil || profile == nil {
		checks.absent("no device profile is bound to or matches this device; nothing holds its PCR baseline")
		return
	}
	dv.ProfileID = profile.ID

	if profile.PCRBaseline == nil {
		baseline := &deviceentities.PCRBaseline{
			Values:               copyPCRValues(reported),
			Source:               deviceentities.BaselineSourceTOFU,
			RecordedAt:           now,
			RecordedFromDeviceID: dev.ID,
		}
		if err := baseline.Validate(); err != nil {
			checks.absent("PCR baseline could not be captured: " + err.Error())
			return
		}
		profile.PCRBaseline = baseline
		if err := v.profiles.Update(ctx, profile); err != nil {
			checks.absent("PCR baseline could not be recorded on profile: " + err.Error())
			return
		}
		v.logger.Warn("PCR baseline captured on first use",
			"profile_id", profile.ID,
			"profile_name", profile.Name,
			"device_id", dev.ID,
			"serial", dev.Serial,
			"pcr_count", len(baseline.Values),
		)
		result.PCRsValid = true
		result.PCRBaselineCaptured = true
		result.PCRBaselineSource = string(baseline.Source)
		result.PCRBaselineRecordedAt = baseline.RecordedAt
		dv.BaselineCaptured = true
		dv.BaselineSource = string(baseline.Source)
		return
	}

	result.PCRBaselineSource = string(profile.PCRBaseline.Source)
	result.PCRBaselineRecordedAt = profile.PCRBaseline.RecordedAt
	dv.BaselineSource = string(profile.PCRBaseline.Source)
	if err := vm.ComparePCRBaseline(reported, profile.PCRBaseline.Values); err != nil {
		checks.fail(err.Error())
		return
	}
	result.PCRsValid = true
}

// record hands the verdict to the sink. A sink failure is logged, not
// returned: the verdict has been reached and the caller must see it.
func (v *DeviceQuoteVerifier) record(ctx context.Context, dv verdict.DeviceVerdict) {
	if v.verdicts == nil {
		return
	}
	if err := v.verdicts.RecordDeviceVerdict(ctx, dv); err != nil {
		v.logger.Error("device verdict could not be recorded",
			"device_id", dv.DeviceID,
			"passed", dv.Passed,
			"error", err,
		)
	}
}

// copyPCRValues deep-copies a PCR map so a baseline never aliases the
// request's buffers.
func copyPCRValues(in map[int][]byte) map[int][]byte {
	out := make(map[int][]byte, len(in))
	for idx, val := range in {
		cp := make([]byte, len(val))
		copy(cp, val)
		out[idx] = cp
	}
	return out
}
