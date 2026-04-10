// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

// Package supermicro is the stub Supermicro BMC attestation backend.
//
// # Current status: DEFERRED (2026-04-08)
//
// No Supermicro hardware the project can test against supports remote
// BMC attestation. The X10 generation (our current fleet) pre-dates
// the Silicon Root of Trust silicon; Supermicro Update Manager itself
// refuses to run the Attestation command against X10 with the message
// "Remote Attestation is not supported on this platform" (error
// 609.100), even when both SFT-DCMS-SINGLE and SFT-SDDC-SINGLE product
// keys are activated on the BMC.
//
// Per strings extracted from sum 2.14.0:
//
//	Support only on RoT system of X12 and later platforms.
//
// Consequently this package is intentionally a thin stub: every
// [attestation.AttestationProvider] method returns
// [attestation.ErrAttestationUnsupported] with an actionable error
// message pointing at the hardware requirement. No shell-out, no
// wire-protocol reverse engineering, no dead code.
//
// # Reviving this backend
//
// This package will be brought back online when the project has
// regular access to X12+ Supermicro hardware with a Silicon Root of
// Trust chip. At that time the intended implementation path is pure
// Go against the SUM Attestation wire protocol, reverse-engineered
// from packet captures against a live RoT-capable BMC — no shell-out
// wrapper. See docs/architecture/bmc-attestation.md for the phasing
// plan.
package supermicro
