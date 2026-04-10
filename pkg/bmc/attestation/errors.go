// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

// ErrUnsupportedVendor is returned when the detected BMC manufacturer
// does not have an attestation backend compiled in.
type ErrUnsupportedVendor struct {
	Manufacturer string
}

func (e ErrUnsupportedVendor) Error() string {
	if e.Manufacturer == "" {
		return "bmc attestation: unsupported vendor: (unknown manufacturer)"
	}
	return "bmc attestation: unsupported vendor: " + e.Manufacturer
}

// ErrAttestationUnsupported is returned by a vendor backend when the
// target hardware does not support any form of BMC-level remote
// attestation. This is a terminal, non-recoverable condition for that
// specific BMC: the caller should not retry and should not attempt to
// work around it — the silicon simply lacks the root-of-trust features
// needed to produce signed measurement evidence.
//
// Known cases on 2026-04-08 hardware survey:
//
//   - Supermicro X10 generation (e.g. X10SDV-TP8F): pre-dates the
//     Silicon Root of Trust silicon; SUM itself reports
//     "Remote Attestation is not supported on this platform"
//     (error 609.100) even with SFT-DCMS-SINGLE + SFT-SDDC-SINGLE
//     activated.
//   - Dell 14G (e.g. PowerEdge R640) running iDRAC9 7.00.00.183:
//     has SRoT silicon but no Redfish ComponentIntegrity endpoint,
//     no DellAttestationService, and no attestation actions on
//     DellLCService. Dell shipped real attestation surface starting
//     15G and completed the schema in 16G.
//
// See docs/architecture/bmc-attestation.md for the full hardware
// compatibility matrix and the phasing plan for real implementations
// once RoT-capable hardware is available.
type ErrAttestationUnsupported struct {
	Vendor       Vendor
	Manufacturer string
	Platform     string
	Reason       string
}

func (e ErrAttestationUnsupported) Error() string {
	msg := "bmc attestation: unsupported"
	if e.Vendor != "" {
		msg += " on " + string(e.Vendor)
	}
	if e.Platform != "" {
		msg += " (" + e.Platform + ")"
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

// ErrAttestationFailed wraps a vendor-side failure reported during an
// attestation operation.
type ErrAttestationFailed struct {
	Vendor Vendor
	Action Action
	Reason string
	Cause  error
}

func (e ErrAttestationFailed) Error() string {
	msg := "bmc attestation: "
	if e.Vendor != "" {
		msg += string(e.Vendor) + " "
	}
	if e.Action != "" {
		msg += string(e.Action) + " "
	}
	msg += "failed"
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e ErrAttestationFailed) Unwrap() error { return e.Cause }

// ErrPolicyViolation is returned by a [Verifier] when a policy rule is
// not satisfied by a supplied [Evidence].
type ErrPolicyViolation struct {
	Rule   string
	Detail string
}

func (e ErrPolicyViolation) Error() string {
	msg := "bmc attestation: policy violation"
	if e.Rule != "" {
		msg += " [" + e.Rule + "]"
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// ErrInvalidEvidence indicates that an Evidence blob is malformed or
// fails structural sanity checks.
type ErrInvalidEvidence struct {
	Reason string
}

func (e ErrInvalidEvidence) Error() string {
	if e.Reason == "" {
		return "bmc attestation: invalid evidence"
	}
	return "bmc attestation: invalid evidence: " + e.Reason
}

// ErrNotImplemented is returned by stub backends and by methods whose
// vendor implementation is deferred to a later phase.
type ErrNotImplemented struct {
	Vendor Vendor
	Action Action
}

func (e ErrNotImplemented) Error() string {
	msg := "bmc attestation: not implemented"
	if e.Vendor != "" {
		msg += " for " + string(e.Vendor)
	}
	if e.Action != "" {
		msg += " (" + string(e.Action) + ")"
	}
	return msg
}
