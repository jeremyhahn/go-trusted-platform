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

// Workload verdicts: turning VM and container attestation EVIDENCE into a
// verdict about it.
//
// An attestor produces evidence; a verifier judges it. Before #483 the VM and
// container response builders on both transports set `Verified: true` from a
// literal, so the field reported the same value whether the evidence had been
// checked, had been checked and passed, or could not be checked at all. This
// file exists so that judgement happens in ONE place and both transports
// report what it returned.

package verdict

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	attestvm "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
)

// Status is the outcome of attempting to verify a piece of attestation
// evidence. It has three values, not two, because "I could not look" is a
// different answer from "it passed" and reporting the first as the second is
// the defect this package was written to remove.
type Status string

const (
	// StatusVerified means every check that applies to this evidence ran and
	// passed.
	StatusVerified Status = "verified"

	// StatusFailed means a check ran and rejected the evidence. Reason says
	// which.
	StatusFailed Status = "failed"

	// StatusNotEvaluated means no verdict was reached: the evidence, or the
	// material needed to judge it, was absent. Reason says what was missing.
	// It is NOT a pass.
	StatusNotEvaluated Status = "not_evaluated"
)

// WorkloadVerdict is the result of judging one piece of evidence.
type WorkloadVerdict struct {
	// Status is the outcome. Prefer it to Verified when a caller can act on
	// the difference between a rejection and an unattempted check.
	Status Status

	// Verified is true only for StatusVerified. It exists so a response can
	// carry a plain boolean without that boolean lying: both StatusFailed and
	// StatusNotEvaluated leave it false.
	Verified bool

	// Reason names the failing check, or what was missing. Empty when the
	// verdict is StatusVerified.
	Reason string
}

func verified() WorkloadVerdict { return WorkloadVerdict{Status: StatusVerified, Verified: true} }

func failed(reason string) WorkloadVerdict {
	return WorkloadVerdict{Status: StatusFailed, Reason: reason}
}

func notEvaluated(reason string) WorkloadVerdict {
	return WorkloadVerdict{Status: StatusNotEvaluated, Reason: reason}
}

// VerifyVMAttestation judges a VM attestation against the nonce the caller
// asked for.
//
// This is the same pair of checks the TPM verify_quote handlers already run —
// VerifyQuoteNonce then VerifyQuoteSignatureWithAlgorithm, under the scheme the
// evidence declares (#482) — which is the shape #483 named
// as the reference. The difference from those handlers is the third outcome:
// they are given a quote, a key and a nonce by the caller, whereas here any of
// the three may be absent from collected evidence, and an absent input must
// not read as a pass.
func VerifyVMAttestation(a *manifest.VMAttestation, expectedNonce []byte) WorkloadVerdict {
	if a == nil {
		return notEvaluated("no attestation evidence")
	}
	if len(a.QuoteData) == 0 {
		return notEvaluated("attestation carries no quote")
	}
	if len(a.AIKPublicKey) == 0 {
		return notEvaluated("attestation carries no AIK public key to verify the signature against")
	}
	if len(a.Signature) == 0 {
		return notEvaluated("attestation carries no signature")
	}
	if a.SignatureAlgorithm == "" {
		return notEvaluated("attestation carries no signature scheme to verify the signature under")
	}
	if len(expectedNonce) == 0 {
		return notEvaluated("no expected nonce supplied, so freshness cannot be established")
	}

	if err := attestvm.VerifyQuoteNonce(a.QuoteData, expectedNonce); err != nil {
		return failed("quote nonce does not match the nonce requested: " + err.Error())
	}
	if err := attestvm.VerifyQuoteSignatureWithAlgorithm(a.AIKPublicKey, a.QuoteData, a.Signature, a.SignatureAlgorithm); err != nil {
		return failed("quote signature is not valid for the AIK public key under " + a.SignatureAlgorithm + ": " + err.Error())
	}

	return verified()
}

// VerifyContainerAttestation judges a container attestation.
//
// manifest.ContainerAttestation carries a digest and a PCR value and NO
// signature, so there is nothing to verify cryptographically: any function
// claiming otherwise would be a second literal wearing a verifier's name.
// manifest's own VerifyContainerAttestations only calls Validate(), which is a
// presence check on fields, not a judgement about authenticity.
//
// So this reports StatusNotEvaluated with the reason, which is the honest
// answer for this evidence shape. It returns StatusFailed for evidence that is
// structurally unusable, because that much CAN be decided here.
//
// When container quote verification lands — pkg/compute/podman has a
// ContainerQuote with a real VerifyQuote — this is where it plugs in, and
// every caller starts getting real verdicts without changing.
func VerifyContainerAttestation(a *manifest.ContainerAttestation) WorkloadVerdict {
	if a == nil {
		return notEvaluated("no attestation evidence")
	}
	if len(a.Digest) == 0 {
		return failed("attestation carries no digest")
	}
	if len(a.PCRValue) == 0 {
		return failed("attestation carries no PCR value")
	}
	return notEvaluated("container attestation carries no signature; no cryptographic verification is defined for this evidence")
}
