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

package vm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"sort"

	"github.com/google/go-tpm/tpm2"
)

// VerifyQuoteSignature verifies the AK signature over a marshaled TPMS_ATTEST
// quote structure. The AK public key may be DER (PKIX or PKCS#1) or PEM
// encoded. RSA signatures are verified as RSASSA-PKCS1-v1_5 over SHA-256 and
// ECDSA signatures as ASN.1 DER over SHA-256, matching the signature formats
// produced by the platform's TPM quote path.
func VerifyQuoteSignature(akPublicKey, quoteData, signature []byte) error {
	if len(akPublicKey) == 0 {
		return ErrSignatureInvalid{Reason: "AK public key is empty"}
	}
	if len(quoteData) == 0 {
		return ErrSignatureInvalid{Reason: "quote data is empty"}
	}
	if len(signature) == 0 {
		return ErrSignatureInvalid{Reason: "signature is empty"}
	}

	pubKey, err := parsePublicKey(akPublicKey)
	if err != nil {
		return ErrSignatureInvalid{Reason: "failed to parse AK public key", Cause: err}
	}

	hashed := sha256.Sum256(quoteData)

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], signature); err != nil {
			return ErrSignatureInvalid{Reason: "RSA signature verification failed", Cause: err}
		}
		return nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, hashed[:], signature) {
			return ErrSignatureInvalid{Reason: "ECDSA signature verification failed"}
		}
		return nil
	default:
		return ErrSignatureInvalid{Reason: "unsupported AK key type"}
	}
}

// ParseQuoteNonce extracts the anti-replay nonce (TPMS_ATTEST extraData /
// qualifying data) from a marshaled TPMS_ATTEST quote structure.
func ParseQuoteNonce(quoteData []byte) ([]byte, error) {
	attest, err := parseQuoteAttest(quoteData)
	if err != nil {
		return nil, err
	}
	return attest.ExtraData.Buffer, nil
}

// VerifyQuoteNonce verifies that the nonce embedded in a marshaled
// TPMS_ATTEST quote matches the expected nonce.
func VerifyQuoteNonce(quoteData, expectedNonce []byte) error {
	if len(expectedNonce) == 0 {
		return ErrQuoteVerificationFailed{Reason: "expected nonce is empty"}
	}
	nonce, err := ParseQuoteNonce(quoteData)
	if err != nil {
		return err
	}
	if !bytes.Equal(nonce, expectedNonce) {
		return ErrNonceMismatch{Expected: expectedNonce, Actual: nonce}
	}
	return nil
}

// VerifyQuotePCRDigest verifies that the PCR digest embedded in a marshaled
// TPMS_ATTEST quote matches the digest computed from the expected PCR
// values. The expected PCR index set must exactly match the quote's PCR
// selection, and the digest is computed as SHA-256 over the expected PCR
// values concatenated in ascending index order — the same construction the
// TPM uses when producing the quote (single SHA-256 bank selections only).
func VerifyQuotePCRDigest(quoteData []byte, expectedPCRs map[int][]byte) error {
	if len(expectedPCRs) == 0 {
		return ErrQuoteVerificationFailed{Reason: "expected PCR values are empty"}
	}

	attest, err := parseQuoteAttest(quoteData)
	if err != nil {
		return err
	}

	quoteInfo, err := attest.Attested.Quote()
	if err != nil {
		return ErrQuoteVerificationFailed{Reason: "attest structure does not contain quote info", Cause: err}
	}

	selected, err := selectedPCRIndices(quoteInfo.PCRSelect)
	if err != nil {
		return err
	}

	// The expected PCR index set must exactly match the quote's selection;
	// anything else silently verifies the wrong state.
	if len(selected) != len(expectedPCRs) {
		return ErrQuoteVerificationFailed{Reason: "expected PCR set does not match quote PCR selection"}
	}
	for _, idx := range selected {
		if _, ok := expectedPCRs[idx]; !ok {
			return ErrQuoteVerificationFailed{Reason: "expected PCR set does not match quote PCR selection"}
		}
	}

	// Compute the PCR digest: SHA-256 over the selected PCR values in
	// ascending index order.
	indices := make([]int, 0, len(expectedPCRs))
	for idx := range expectedPCRs {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	hasher := sha256.New()
	for _, idx := range indices {
		hasher.Write(expectedPCRs[idx])
	}
	digest := hasher.Sum(nil)

	if !bytes.Equal(digest, quoteInfo.PCRDigest.Buffer) {
		return ErrQuoteVerificationFailed{Reason: "PCR digest mismatch"}
	}

	return nil
}

// QuotePCRDigest returns the PCR digest a marshaled TPMS_ATTEST quote
// attests to, together with the PCR indices it covers, in ascending order.
//
// It is the read-only counterpart of VerifyQuotePCRDigest: a producer uses
// it to confirm the PCR values it is about to report actually hash to the
// digest its TPM signed, so it never emits evidence a verifier will reject.
func QuotePCRDigest(quoteData []byte) (digest []byte, indices []int, err error) {
	attest, err := parseQuoteAttest(quoteData)
	if err != nil {
		return nil, nil, err
	}
	quoteInfo, err := attest.Attested.Quote()
	if err != nil {
		return nil, nil, ErrQuoteVerificationFailed{Reason: "attest structure does not contain quote info", Cause: err}
	}
	indices, err = selectedPCRIndices(quoteInfo.PCRSelect)
	if err != nil {
		return nil, nil, err
	}
	return quoteInfo.PCRDigest.Buffer, indices, nil
}

// parseQuoteAttest unmarshals and validates a marshaled TPMS_ATTEST quote
// structure.
func parseQuoteAttest(quoteData []byte) (*tpm2.TPMSAttest, error) {
	if len(quoteData) == 0 {
		return nil, ErrQuoteVerificationFailed{Reason: "quote data is empty"}
	}

	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](quoteData)
	if err != nil {
		return nil, ErrQuoteVerificationFailed{Reason: "failed to parse TPMS_ATTEST structure", Cause: err}
	}

	if attest.Type != tpm2.TPMSTAttestQuote {
		return nil, ErrQuoteVerificationFailed{Reason: "attest structure is not a quote"}
	}

	return attest, nil
}

// selectedPCRIndices decodes the PCR indices selected by a TPML_PCR_SELECTION.
// Only single-bank SHA-256 selections are supported, matching the quotes the
// platform generates.
func selectedPCRIndices(selection tpm2.TPMLPCRSelection) ([]int, error) {
	var indices []int
	banks := 0
	for _, sel := range selection.PCRSelections {
		empty := true
		for _, b := range sel.PCRSelect {
			if b != 0 {
				empty = false
				break
			}
		}
		if empty {
			continue
		}
		banks++
		if sel.Hash != tpm2.TPMAlgSHA256 {
			return nil, ErrQuoteVerificationFailed{Reason: "unsupported PCR bank in quote selection: only SHA-256 is supported"}
		}
		for byteIdx, b := range sel.PCRSelect {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<uint(bit)) != 0 {
					indices = append(indices, byteIdx*8+bit)
				}
			}
		}
	}
	if banks == 0 {
		return nil, ErrQuoteVerificationFailed{Reason: "quote PCR selection is empty"}
	}
	if banks > 1 {
		return nil, ErrQuoteVerificationFailed{Reason: "multi-bank quote PCR selections are not supported"}
	}
	sort.Ints(indices)
	return indices, nil
}
