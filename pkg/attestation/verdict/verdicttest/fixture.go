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

// Package verdicttest builds attestation evidence that genuinely verifies, so
// tests across the transports can prove the passing verdict is still reachable
// through the real code path.
//
// A negative test only means something if the positive answer is reachable —
// otherwise a verifier hardcoded to reject everything would satisfy it. The
// fixture therefore signs a real marshalled TPMS_ATTEST rather than returning
// a stub: it goes through the same nonce and signature checks the failing
// evidence went through.
package verdicttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
)

// SignedVMAttestation returns VM attestation evidence that verifies against
// the returned nonce, along with that nonce.
//
// The quote is a marshalled TPMS_ATTEST carrying the nonce as ExtraData; the
// signature is over its SHA-256 digest, made with a freshly generated ECDSA
// P-256 key whose public half is returned as the AIK in PKIX DER — the shapes
// attestvm.VerifyQuoteNonce and attestvm.VerifyQuoteSignatureWithAlgorithm
// expect, with the ECDSA-SHA256 scheme declared beside them.
func SignedVMAttestation(t *testing.T, vmID string) (*manifest.VMAttestation, []byte) {
	t.Helper()

	nonce := []byte("a-known-nonce-16bytes")

	attest := tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: []byte("test-ak")},
		ExtraData:       tpm2.TPM2BData{Buffer: nonce},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(0),
				}},
			},
			PCRDigest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)},
		}),
	}

	quote := tpm2.Marshal(attest)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	aik, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	digest := sha256.Sum256(quote)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)

	return &manifest.VMAttestation{
		VMID:               vmID,
		HostID:             "test-host-id",
		QuoteData:          quote,
		AIKPublicKey:       aik,
		Signature:          signature,
		SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		Nonce:              nonce,
	}, nonce
}
