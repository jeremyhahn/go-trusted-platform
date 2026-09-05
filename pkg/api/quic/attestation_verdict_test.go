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

//go:build codec_msgpack

package quic

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict/verdicttest"
)

// #483: handleAttestVM and handleAttestContainer set `Verified: true` from a
// literal, so every attestation the QUIC transport ever returned reported as
// verified regardless of the evidence. These exercise the handler over the
// wire encoding, which is where the literal lived.

// attestVMOverWire runs a real AttestVM request through the handler and
// decodes the response, so the assertions see what a client would see rather
// than a function return the transport might not carry.
func attestVMOverWire(t *testing.T, service *mockAttestationService, handler *AttestationHandler, vmID string, nonce []byte) AttestVMResponse {
	t.Helper()

	payload, err := EncodePayload(&AttestVMRequest{
		VMID:          vmID,
		Nonce:         nonce,
		PCRIndices:    []int{0},
		HashAlgorithm: "sha256",
	})
	require.NoError(t, err)

	resp := handler.HandleRequest(context.Background(), &Request{
		Opcode:  OpAttestVMWorkload,
		Payload: payload,
	})
	require.Equal(t, StatusOK, resp.Status)

	var decoded AttestVMResponse
	require.NoError(t, DecodePayload(resp.Payload, &decoded))
	return decoded
}

// TestAttestVMOverWireReportsAPassOnlyForEvidenceThatVerifies is the pair the
// issue asks for: the same handler, the same wire path, two pieces of
// evidence, two different verdicts. Either half alone is satisfied by a
// constant — only the pair shows the handler is reading the evidence.
func TestAttestVMOverWireReportsAPassOnlyForEvidenceThatVerifies(t *testing.T) {
	t.Run("evidence that verifies is reported verified", func(t *testing.T) {
		handler, service := createTestAttestationHandler()

		signed, nonce := verdicttest.SignedVMAttestation(t, "vm-signed")
		service.vmAttestation = signed

		got := attestVMOverWire(t, service, handler, "vm-signed", nonce)

		require.True(t, got.Verified,
			"the passing verdict must survive the wire, or the failing case below proves nothing: %s",
			got.VerificationError)
		assert.Equal(t, string(verdict.StatusVerified), got.VerificationStatus)
		assert.Empty(t, got.VerificationError)
	})

	t.Run("a tampered quote is reported failed", func(t *testing.T) {
		handler, service := createTestAttestationHandler()

		signed, nonce := verdicttest.SignedVMAttestation(t, "vm-tampered")
		// Flip one byte of the signature. Everything else is identical to the
		// case above, so nothing but the cryptography distinguishes them.
		signed.Signature[len(signed.Signature)-1] ^= 0xFF
		service.vmAttestation = signed

		got := attestVMOverWire(t, service, handler, "vm-tampered", nonce)

		assert.False(t, got.Verified,
			"a quote whose signature does not check out was reported verified (#483)")
		assert.Equal(t, string(verdict.StatusFailed), got.VerificationStatus)
		assert.NotEmpty(t, got.VerificationError)
	})

	t.Run("a quote for a different nonce is reported failed", func(t *testing.T) {
		handler, service := createTestAttestationHandler()

		signed, _ := verdicttest.SignedVMAttestation(t, "vm-replayed")
		service.vmAttestation = signed

		// The evidence is genuinely signed; it just answers a challenge the
		// caller did not issue. Replay must not read as freshness.
		got := attestVMOverWire(t, service, handler, "vm-replayed", []byte("a-different-nonce-16b"))

		assert.False(t, got.Verified,
			"a replayed quote was reported verified (#483)")
		assert.Equal(t, string(verdict.StatusFailed), got.VerificationStatus)
		assert.NotEmpty(t, got.VerificationError)
	})

	t.Run("evidence with no quote is not_evaluated, not failed", func(t *testing.T) {
		handler, service := createTestAttestationHandler()

		service.vmAttestation = &manifest.VMAttestation{VMID: "vm-empty"}

		got := attestVMOverWire(t, service, handler, "vm-empty", []byte("a-nonce-16-bytes-long"))

		assert.False(t, got.Verified)
		assert.Equal(t, string(verdict.StatusNotEvaluated), got.VerificationStatus,
			"a check that could not run must not be reported as a check that ran and failed")
		assert.NotEmpty(t, got.VerificationError)
	})
}
