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

package verdict

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict/verdicttest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// These are POSITIVE CONTROLS. #483's defect was a literal `Verified: true`,
// which reports the same value whether a check ran, ran and passed, or could
// not run — so a test that merely exercises the path passes over it. Every
// case here constructs evidence that MUST NOT produce a pass and asserts it
// does not. Each one fails if the literal is restored.

// TestVMEvidenceThatCannotVerifyIsNotAPass is the acceptance criterion.
//
// Not one of these inputs can be verified, and none of them may report
// verified. The third state matters: absent evidence is not_evaluated, present
// but wrong evidence is failed, and neither is a pass.
func TestVMEvidenceThatCannotVerifyIsNotAPass(t *testing.T) {
	good := []byte("quote-bytes")

	cases := map[string]struct {
		att   *manifest.VMAttestation
		nonce []byte
		want  Status
	}{
		"no evidence at all": {nil, []byte("n"), StatusNotEvaluated},
		"no quote": {
			&manifest.VMAttestation{VMID: "vm-1", AIKPublicKey: []byte("k"), Signature: []byte("s")},
			[]byte("n"), StatusNotEvaluated,
		},
		"no AIK to check the signature against": {
			&manifest.VMAttestation{VMID: "vm-1", QuoteData: good, Signature: []byte("s")},
			[]byte("n"), StatusNotEvaluated,
		},
		"no signature": {
			&manifest.VMAttestation{VMID: "vm-1", QuoteData: good, AIKPublicKey: []byte("k")},
			[]byte("n"), StatusNotEvaluated,
		},
		"no signature scheme to verify the signature under": {
			&manifest.VMAttestation{VMID: "vm-1", QuoteData: good, AIKPublicKey: []byte("k"), Signature: []byte("s")},
			[]byte("n"), StatusNotEvaluated,
		},
		"no nonce, so freshness cannot be established": {
			&manifest.VMAttestation{VMID: "vm-1", QuoteData: good, AIKPublicKey: []byte("k"), Signature: []byte("s"), SignatureAlgorithm: testutil.PSSQuoteScheme},
			nil, StatusNotEvaluated,
		},
		"complete evidence that does not actually verify": {
			&manifest.VMAttestation{VMID: "vm-1", QuoteData: good, AIKPublicKey: []byte("not-a-key"), Signature: []byte("not-a-signature"), SignatureAlgorithm: testutil.PSSQuoteScheme},
			[]byte("nonce-the-quote-does-not-carry"), StatusFailed,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := VerifyVMAttestation(tc.att, tc.nonce)

			assert.False(t, got.Verified,
				"evidence that cannot verify reported verified=true — this is #483's defect")
			assert.Equal(t, tc.want, got.Status)
			assert.NotEmpty(t, got.Reason, "a non-pass must say why, or the caller cannot act on it")
		})
	}
}

// TestNotEvaluatedIsDistinguishableFromFailed is the third state, asserted
// directly. If these two collapse into one value, the response cannot tell a
// caller "your evidence was rejected" from "I never looked" — which is the
// same information loss as the literal, one step smaller.
func TestNotEvaluatedIsDistinguishableFromFailed(t *testing.T) {
	couldNotLook := VerifyVMAttestation(&manifest.VMAttestation{VMID: "vm-1"}, []byte("n"))
	looked := VerifyVMAttestation(&manifest.VMAttestation{
		VMID: "vm-1", QuoteData: []byte("q"), AIKPublicKey: []byte("k"), Signature: []byte("s"),
		SignatureAlgorithm: testutil.PSSQuoteScheme,
	}, []byte("n"))

	require.False(t, couldNotLook.Verified)
	require.False(t, looked.Verified)
	assert.Equal(t, StatusNotEvaluated, couldNotLook.Status)
	assert.Equal(t, StatusFailed, looked.Status)
	assert.NotEqual(t, couldNotLook.Status, looked.Status,
		"an unattempted check and a rejection must not report the same status")
}

// TestContainerEvidenceCarriesNoSignatureSoItIsNeverAPass.
//
// manifest.ContainerAttestation has a digest and a PCR value and no signature,
// so there is nothing to verify cryptographically. Reporting a pass here would
// be the literal again, and reporting one from manifest's own
// VerifyContainerAttestations would be no better: that function calls
// Validate(), which is a presence check on fields.
func TestContainerEvidenceCarriesNoSignatureSoItIsNeverAPass(t *testing.T) {
	full := &manifest.ContainerAttestation{
		ContainerID: "ctr-1",
		Digest:      []byte("digest"),
		PCRValue:    []byte("pcr"),
	}

	got := VerifyContainerAttestation(full)
	assert.False(t, got.Verified,
		"a container attestation with no signature cannot be verified, so it must not report a pass")
	assert.Equal(t, StatusNotEvaluated, got.Status)
	assert.Contains(t, got.Reason, "no signature")

	// Structurally unusable evidence CAN be judged here, and is.
	for name, bad := range map[string]*manifest.ContainerAttestation{
		"no digest":    {ContainerID: "ctr-1", PCRValue: []byte("pcr")},
		"no PCR value": {ContainerID: "ctr-1", Digest: []byte("d")},
	} {
		t.Run(name, func(t *testing.T) {
			v := VerifyContainerAttestation(bad)
			assert.False(t, v.Verified)
			assert.Equal(t, StatusFailed, v.Status)
		})
	}

	assert.Equal(t, StatusNotEvaluated, VerifyContainerAttestation(nil).Status)
}

// TestVerifiedIsReachable is the control for every assertion above.
//
// Without it, a VerifyVMAttestation that returned not_evaluated
// unconditionally would satisfy this whole file — the inert-test failure, in
// which a green suite is named for the right function and its inputs cannot
// reach the behaviour. It uses the real signing path rather than a stub,
// because the point is that the good answer is reachable through the same code
// the bad answers went through.
func TestVerifiedIsReachable(t *testing.T) {
	evidence, nonce := verdicttest.SignedVMAttestation(t, "vm-1")

	got := VerifyVMAttestation(evidence, nonce)

	require.Equal(t, StatusVerified, got.Status,
		"the passing verdict must be reachable, or the negative cases above prove nothing: %s", got.Reason)
	assert.True(t, got.Verified)
	assert.Empty(t, got.Reason)
}

// TestVMVerdictJudgesTheDeclaredScheme pins #482: the signature is checked
// under the scheme the evidence declares, so an RSA-PSS quote verifies and a
// scheme the signature was not made under fails rather than being guessed.
func TestVMVerdictJudgesTheDeclaredScheme(t *testing.T) {
	t.Run("an RSA-PSS quote verifies", func(t *testing.T) {
		evidence, nonce := verdicttest.SignedVMAttestation(t, "vm-1")
		evidence.Signature, evidence.AIKPublicKey = testutil.SignPSSQuote(t, evidence.QuoteData)
		evidence.SignatureAlgorithm = testutil.PSSQuoteScheme

		got := VerifyVMAttestation(evidence, nonce)

		require.Equal(t, StatusVerified, got.Status, got.Reason)
		assert.True(t, got.Verified)
	})

	t.Run("a scheme the signature was not made under fails", func(t *testing.T) {
		evidence, nonce := verdicttest.SignedVMAttestation(t, "vm-1")
		evidence.SignatureAlgorithm = testutil.PSSQuoteScheme

		got := VerifyVMAttestation(evidence, nonce)

		assert.Equal(t, StatusFailed, got.Status)
		assert.False(t, got.Verified)
		assert.Contains(t, got.Reason, testutil.PSSQuoteScheme)
	})
}
