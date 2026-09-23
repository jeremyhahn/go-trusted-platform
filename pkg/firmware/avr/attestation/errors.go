// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"strconv"

	bmcattestation "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
)

// Errors in this package are types, never formatted strings, so a caller can
// switch on the condition instead of matching text. The vendor-neutral
// contract's own error set is reused wherever it already says the right
// thing — notably [bmcattestation.ErrAttestationUnsupported] for the verbs a
// microcontroller cannot implement, and [bmcattestation.ErrInvalidEvidence]
// for structural refusals that carry no further detail worth a type.

// ErrInvalidConfig reports a [Config] field that cannot be used.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return "avr attestation: invalid config field " + strconv.Quote(e.Field) + ": " + e.Reason
}

// ErrNilConfig is returned when [New] is called without a configuration.
// Construction does not invent one: the tenant a device belongs to has no
// defensible default.
type ErrNilConfig struct{}

func (ErrNilConfig) Error() string { return "avr attestation: nil config" }

// ErrNilDevice is returned when [New] is called without an open device. The
// link belongs to whoever opened it; this provider does not create one.
type ErrNilDevice struct{}

func (ErrNilDevice) Error() string { return "avr attestation: nil device" }

// ErrInvalidTenant reports a tenant identifier that is empty or contains a
// character that would corrupt a tenant key path. It wraps the tenant
// package's own validation so there is one definition of a legal tenant id.
type ErrInvalidTenant struct {
	TenantID string
	Cause    error
}

func (e ErrInvalidTenant) Error() string {
	msg := "avr attestation: invalid tenant " + strconv.Quote(e.TenantID)
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e ErrInvalidTenant) Unwrap() error { return e.Cause }

// ErrTenantMismatch reports evidence presented to a provider that belongs to
// a different tenant, or evidence carrying no tenant at all. It is a refusal
// rather than a failed appraisal: cross-tenant evidence is never scored.
type ErrTenantMismatch struct {
	Want string
	Got  string
}

func (e ErrTenantMismatch) Error() string {
	got := e.Got
	if got == "" {
		got = "(none)"
	} else {
		got = strconv.Quote(got)
	}
	return "avr attestation: evidence belongs to tenant " + got +
		", provider is bound to " + strconv.Quote(e.Want)
}

// ErrAttestationNotCompiledIn reports a device whose CAPS reply does not set
// the attestation feature bit. The bitmap describes what the firmware HAS,
// not what the part could do, so this is a build that shipped without the
// command — retrying will not change it.
type ErrAttestationNotCompiledIn struct {
	BoardID    uint8
	CryptoTier string
}

func (e ErrAttestationNotCompiledIn) Error() string {
	return "avr attestation: device (board " + strconv.Itoa(int(e.BoardID)) +
		", crypto tier " + e.CryptoTier + ") reports no attestation feature bit"
}

// ErrNonceLength reports a challenge of the wrong width. The two widths are
// deliberately different and are refused before a frame is built, because a
// device handed the shorter one cannot tell it was truncated.
type ErrNonceLength struct {
	// Flow names which challenge was expected: "runtime" or "enrolment".
	Flow string
	Got  int
	Want int
}

func (e ErrNonceLength) Error() string {
	return "avr attestation: " + e.Flow + " nonce must be " + strconv.Itoa(e.Want) +
		" bytes, got " + strconv.Itoa(e.Got)
}

// ErrEvidenceLength reports an evidence frame that is not the fixed wire
// length. Every deployed host parses this frame at fixed offsets, so a short
// or long frame is a protocol break and not something to parse partially.
type ErrEvidenceLength struct {
	Got  int
	Want int
}

func (e ErrEvidenceLength) Error() string {
	return "avr attestation: evidence frame must be " + strconv.Itoa(e.Want) +
		" bytes, got " + strconv.Itoa(e.Got)
}

// ErrEvidenceVersion reports a frame whose version byte this host does not
// know how to parse. Versions extend and never renumber, so an unknown
// version is refused rather than read as the one version this host knows.
type ErrEvidenceVersion struct {
	Got  uint8
	Want uint8
}

func (e ErrEvidenceVersion) Error() string {
	return "avr attestation: evidence frame version " + strconv.Itoa(int(e.Got)) +
		" is not version " + strconv.Itoa(int(e.Want))
}

// ErrUnsupportedAction reports an [bmcattestation.Action] this backend has no
// meaning for. Actions extend, so an unrecognised one is refused rather than
// treated as the default.
type ErrUnsupportedAction struct {
	Action bmcattestation.Action
}

func (e ErrUnsupportedAction) Error() string {
	return "avr attestation: unsupported action " + strconv.Quote(string(e.Action))
}

// ErrUnsupportedCompare reports a Compare between evidence this backend
// cannot compare. Only the evidence frame has a golden-build form: an alias
// certificate's comparable content is its UCCS claims set, and decoding that
// belongs to go-xkms rather than here.
type ErrUnsupportedCompare struct {
	Live bmcattestation.Action
	Ref  bmcattestation.Action
}

func (e ErrUnsupportedCompare) Error() string {
	return "avr attestation: cannot compare " + strconv.Quote(string(e.Live)) +
		" evidence against " + strconv.Quote(string(e.Ref)) +
		"; only the evidence frame has a golden-build form"
}

// ErrPolicyMaxAgeUnset reports a [bmcattestation.Policy] whose MaxAgeSeconds
// is not positive.
//
// The vendor-neutral contract treats zero as "disable the age check". This
// backend refuses it instead, because a stale posture read as a good one is
// the failure this whole subsystem exists to prevent, and a caller who wants
// no age bound must say so by setting one large enough to be visible in an
// audit rather than by leaving a field at its zero value.
type ErrPolicyMaxAgeUnset struct{}

func (ErrPolicyMaxAgeUnset) Error() string {
	return "avr attestation: policy MaxAgeSeconds must be set explicitly and positive"
}

// ErrNilPolicy reports a Verify call with no policy. A nil policy accepts
// nothing; it is not an empty policy that accepts everything.
type ErrNilPolicy struct{}

func (ErrNilPolicy) Error() string { return "avr attestation: nil policy" }
