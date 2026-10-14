// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// DeviceQuoteEvidence is the TPM quote evidence a device submits for
// verification. It is the same shape on every transport: gRPC and Unix carry
// it as the AttestDeviceRequest.evidence bytes, QUIC and the live REST stack
// pass those bytes through, and MCP carries it as the tool's evidence
// argument. The type lives in pkg/attestation/vm so the attester side — a
// diskless node's platformd (#690) — builds the same shape this verifier
// reads.
type DeviceQuoteEvidence = vm.QuoteEvidence

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
	// requireChannelBinding holds the verifier the reporting collector
	// feeds: its evidence must carry the TLS channel binding the quote was
	// collected over, and the quote must be bound to it. Off, the binding
	// field is ignored, so a caller-submitted binding is never honoured.
	requireChannelBinding bool
}

// boundQuoteEvidence is DeviceQuoteEvidence plus the channel binding the
// collector derived from the connection the quote was collected over.
type boundQuoteEvidence struct {
	DeviceQuoteEvidence
	ChannelBinding []byte `json:"channel_binding,omitempty"`
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

// Verify evaluates one quote for one device. It returns an error only when
// the request itself is unusable (unknown device, malformed evidence, a
// dependency missing, the context done); a quote that fails verification is
// a successful call whose result says Verified=false.
//
// The checks themselves — the attestation certificate's chain and
// tcg-cap-verifiedTPMRestricted, the quote signature, the nonce, the PCR
// digest and the baseline — are the upstream attested-peer verifier's. What
// stays here is what only the platform knows: which profile holds the
// baseline, trust-on-first-use capture into it, and the verdict sink.
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

	var quote boundQuoteEvidence
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
	var channelBinding []byte
	if v.requireChannelBinding {
		if len(quote.ChannelBinding) == 0 {
			return nil, ErrInvalidAttestationEvidence{Reason: "channel binding is required: the quote must be bound to the TLS session it was collected over"}
		}
		channelBinding = quote.ChannelBinding
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
	dv := verdict.DeviceVerdict{DeviceID: dev.ID, TenantID: dev.TenantID, HostID: dev.Hostname, Serial: dev.Serial, AttestedAt: now}

	// The one device -> profile resolver the collector also uses (#463):
	// the profile bound to this device's EK identity first, else the match
	// rules. Both consumers therefore always land on the same profile.
	// No profile is a verdict; a store that could not answer is not, so it
	// fails closed instead of reading as "no profile".
	profile, err := v.profiles.FindProfileForDevice(ctx, dev)
	if err != nil {
		var unbound device.ErrNoProfileForDevice
		if !errors.As(err, &unbound) {
			return nil, ErrDeviceProfileLookupFailed{DeviceID: deviceID, Cause: err}
		}
		profile = nil
	}
	var baseline map[int][]byte
	if profile != nil {
		dv.ProfileID = profile.ID
		if profile.PCRBaseline != nil {
			baseline = profile.PCRBaseline.Values
			result.PCRBaselineSource = string(profile.PCRBaseline.Source)
			result.PCRBaselineRecordedAt = profile.PCRBaseline.RecordedAt
			dv.BaselineSource = string(profile.PCRBaseline.Source)
		}
	}

	peer, err := xkms.NewPeerAttestationVerifier(xkms.WithPeerVerifierClock(func() time.Time { return now })).Verify(ctx,
		xkms.PeerEvidence{
			Quote:            quote.Quote,
			Signature:        quote.Signature,
			Nonce:            quote.Nonce,
			PCRs:             quote.PCRs,
			AKCertificatePEM: []byte(dev.AttestCert),
		},
		v.policy(baseline, channelBinding))
	if err != nil {
		var policyErr *xkms.PeerPolicyError
		if !errors.As(err, &policyErr) {
			return nil, ErrAttestationFailed{Reason: "peer verification did not complete", Err: err}
		}
		// A stored baseline the verifier refuses is a check that could not
		// run: the device is denied, not quarantined.
		peer = xkms.PeerVerdict{Failure: xkms.PeerFailureAbsence, Reason: "profile PCR baseline is unusable: " + err.Error()}
	}

	result.AKCertificateVerified = peer.Checks.AKCertificate
	result.SignatureValid = peer.Checks.Signature
	result.NonceValid = peer.Checks.Nonce && peer.Checks.ChannelBinding
	result.PCRsValid = peer.Checks.Baseline
	result.Verified = peer.Passed
	cryptographic := peer.Failure == xkms.PeerFailureCryptographic
	var failures []string
	if !peer.Passed {
		failures = append(failures, peer.Reason)
	}

	switch {
	case profile == nil:
		failures = append(failures, "no device profile is bound to or matches this device; nothing holds its PCR baseline")
	case profile.PCRBaseline == nil && provenExceptBaseline(peer.Checks):
		// The only failed check is the baseline the profile does not have
		// yet: the proven values become it.
		captured, reason := v.captureBaseline(ctx, dev, profile, peer.PCRs, now)
		if captured == nil {
			failures = []string{reason}
			break
		}
		failures = nil
		result.Verified = true
		result.PCRsValid = true
		result.PCRBaselineCaptured = true
		result.PCRBaselineSource = string(captured.Source)
		result.PCRBaselineRecordedAt = captured.RecordedAt
		dv.BaselineCaptured = true
		dv.BaselineSource = string(captured.Source)
	}

	if result.Verified {
		result.Status = "verified"
		result.Message = "device attestation verified"
	} else {
		result.Status = "failed"
		result.Message = strings.Join(failures, "; ")
	}

	result.CryptographicFailure = !result.Verified && cryptographic
	dv.Passed = result.Verified
	dv.Cryptographic = result.CryptographicFailure
	if !result.Verified {
		dv.Reason = result.Message
	}
	v.record(ctx, dv)

	return result, nil
}

// policy assembles what a device is judged against: the platform CA as the
// anchor for its attestation certificate, and the profile baseline.
//
// A bare AttestPub is deliberately never an anchor: without the certificate
// the Restricted attribute cannot be checked, and DevID §8.2 makes that check
// a MUST for a relying party. A CA that cannot be read leaves Anchors nil,
// which the verifier reports as an absence — denied service, not quarantine.
func (v *DeviceQuoteVerifier) policy(baseline map[int][]byte, channelBinding []byte) xkms.PeerPolicy {
	policy := xkms.PeerPolicy{Baseline: baseline, ChannelBinding: channelBinding}
	if v.trust == nil {
		return policy
	}
	root, err := v.trust.TrustedRoot()
	if err != nil || root == nil {
		v.logger.Warn("CA trust anchor unavailable; attestation certificates cannot be chained", "error", err)
		return policy
	}
	policy.Anchors = x509.NewCertPool()
	policy.Anchors.AddCert(root)
	if intermediate, err := v.trust.TrustedIntermediate(); err == nil && intermediate != nil {
		policy.Intermediates = x509.NewCertPool()
		policy.Intermediates.AddCert(intermediate)
	}
	return policy
}

// provenExceptBaseline reports whether every check but the baseline held:
// the quoted PCR values are proven genuine and fresh, so they may seed a
// profile that has no baseline yet. Nothing unproven ever becomes one.
func provenExceptBaseline(c xkms.PeerChecks) bool {
	return c.AKCertificate && c.Signature && c.Nonce && c.ChannelBinding &&
		c.PCRDigest && c.RequiredPCRs && c.Freshness
}

// captureBaseline records the proven PCR values as the profile's
// trust-on-first-use baseline — a security event, logged as one. It returns
// the recorded baseline, or nil and the reason it could not be recorded; a
// capture that fails leaves the device denied, never verified.
func (v *DeviceQuoteVerifier) captureBaseline(
	ctx context.Context,
	dev *deviceentities.Device,
	profile *deviceentities.DeviceProfile,
	proven map[int][]byte,
	now time.Time,
) (*deviceentities.PCRBaseline, string) {
	baseline := &deviceentities.PCRBaseline{
		Values:               copyPCRValues(proven),
		Source:               deviceentities.BaselineSourceTOFU,
		RecordedAt:           now,
		RecordedFromDeviceID: dev.ID,
	}
	if err := baseline.Validate(); err != nil {
		return nil, "PCR baseline could not be captured: " + err.Error()
	}
	profile.PCRBaseline = baseline
	if err := v.profiles.Update(ctx, profile); err != nil {
		profile.PCRBaseline = nil
		return nil, "PCR baseline could not be recorded on profile: " + err.Error()
	}
	v.logger.Warn("PCR baseline captured on first use",
		"profile_id", profile.ID,
		"profile_name", profile.Name,
		"device_id", dev.ID,
		"serial", dev.Serial,
		"pcr_count", len(baseline.Values),
	)
	return baseline, ""
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

// parseDeviceID reads the numeric device ID the device store keys on.
func parseDeviceID(id string) (uint64, error) {
	var deviceID uint64
	_, err := fmt.Sscanf(id, "%d", &deviceID)
	if err != nil {
		return 0, &MessageError{Msg: fmt.Sprintf("invalid device ID: %s", id)}
	}
	return deviceID, nil
}
