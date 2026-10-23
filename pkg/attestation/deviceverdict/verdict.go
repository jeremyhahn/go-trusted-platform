// Package deviceverdict contains the leaf device-attestation verdict DTOs.
package deviceverdict

import "time"

// DeviceVerdict is the result of verifying one quote from one device.
//
// Passed is the overall verdict. When it is false, Cryptographic says what
// kind of failure it was, and that distinction is load-bearing: a
// cryptographic failure (bad signature, wrong nonce, PCR values that differ
// from the profile baseline, an attestation certificate that does not chain
// or lacks tcg-cap-verifiedTPMRestricted) is evidence of a compromised or
// impersonated device and is denied service AND quarantined; an absence of
// evidence (no attestation certificate enrolled, no profile to hold a
// baseline, no CA trust anchor) is denied service but never quarantined,
// because absence of evidence is not evidence of compromise.
type DeviceVerdict struct {
	// DeviceID is the platform device record the quote was verified for.
	DeviceID uint64
	// TenantID is the tenant that owns the device record; empty for a device
	// the platform itself owns. It decides which tenants may see the verdict.
	TenantID string
	// HostID is the device's enrolled hostname (IDevID CN) when known.
	HostID string
	// Serial is the device serial number when known.
	Serial string
	// Passed is true only when every check ran and passed.
	Passed bool
	// Cryptographic is true when a failed verdict was a cryptographic
	// failure rather than an absence of evidence. Meaningless when Passed.
	Cryptographic bool
	// Reason is the human-readable failure detail; empty when Passed.
	Reason string
	// BaselineCaptured is true when this verification recorded a
	// trust-on-first-use PCR baseline on the device's profile.
	BaselineCaptured bool
	// BaselineSource names where the PCR baseline the quote was compared
	// against came from ("signed" or "tofu"); empty when no baseline was
	// evaluated.
	BaselineSource string
	// ProfileID is the device profile whose baseline was evaluated or
	// captured; zero when none was.
	ProfileID uint64
	// AttestedAt is the verifier's timestamp for the evaluation; zero when
	// the producer did not stamp one. A consumer that keeps only the latest
	// verdict per device orders verifications by it.
	AttestedAt time.Time
}

// RecordedDeviceVerdict is a device verdict with the event-log timestamp that
// made it durable.
type RecordedDeviceVerdict struct {
	Verdict    DeviceVerdict
	EventID    string
	RecordedAt time.Time
}

// Validate reports whether the verdict is internally consistent: a passed
// verdict carries no reason, and a failed one must carry one.
func (v DeviceVerdict) Validate() error {
	if v.DeviceID == 0 {
		return ErrInvalidVerdict{Reason: "device ID is required"}
	}
	if v.Passed && v.Reason != "" {
		return ErrInvalidVerdict{Reason: "a passed verdict must not carry a failure reason"}
	}
	if !v.Passed && v.Reason == "" {
		return ErrInvalidVerdict{Reason: "a failed verdict must carry a reason"}
	}
	return nil
}

// ErrInvalidVerdict reports a verdict that violates its own invariants.
type ErrInvalidVerdict struct {
	Reason string
}

func (e ErrInvalidVerdict) Error() string {
	return "verdict: invalid device verdict: " + e.Reason
}
