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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"sort"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestQuote marshals a synthetic TPMS_ATTEST quote structure with the
// given nonce and SHA-256 PCR values.
func buildTestQuote(t *testing.T, nonce []byte, pcrValues map[int][]byte) []byte {
	t.Helper()

	indices := make([]int, 0, len(pcrValues))
	for idx := range pcrValues {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	hasher := sha256.New()
	pcrs := make([]uint, 0, len(indices))
	for _, idx := range indices {
		hasher.Write(pcrValues[idx])
		pcrs = append(pcrs, uint(idx))
	}
	digest := hasher.Sum(nil)

	attest := tpm2.TPMSAttest{
		Magic: tpm2.TPMGeneratedValue,
		Type:  tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{
			Buffer: []byte("test-ak"),
		},
		ExtraData: tpm2.TPM2BData{
			Buffer: nonce,
		},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
					},
				},
			},
			PCRDigest: tpm2.TPM2BDigest{
				Buffer: digest,
			},
		}),
	}

	return tpm2.Marshal(attest)
}

// signTestQuote signs quote data with an RSA test key and returns the DER
// AK public key and the signature.
func signTestQuote(t *testing.T, quoteData []byte) ([]byte, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	hashed := sha256.Sum256(quoteData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	require.NoError(t, err)

	akPub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	return akPub, signature
}

func TestVerifyQuoteSignature_RSA(t *testing.T) {
	nonce := []byte("test-nonce-value")
	quote := buildTestQuote(t, nonce, map[int][]byte{0: make([]byte, 32)})
	akPub, signature := signTestQuote(t, quote)

	require.NoError(t, VerifyQuoteSignature(akPub, quote, signature))
}

func TestVerifyQuoteSignature_ECDSA(t *testing.T) {
	quote := buildTestQuote(t, []byte("nonce"), map[int][]byte{7: make([]byte, 32)})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	hashed := sha256.Sum256(quote)
	signature, err := ecdsa.SignASN1(rand.Reader, key, hashed[:])
	require.NoError(t, err)

	akPub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	require.NoError(t, VerifyQuoteSignature(akPub, quote, signature))
}

func TestVerifyQuoteSignature_TamperedQuote(t *testing.T) {
	quote := buildTestQuote(t, []byte("nonce"), map[int][]byte{0: make([]byte, 32)})
	akPub, signature := signTestQuote(t, quote)

	tampered := append([]byte(nil), quote...)
	tampered[len(tampered)-1] ^= 0xFF

	err := VerifyQuoteSignature(akPub, tampered, signature)
	require.Error(t, err)
	var sigErr ErrSignatureInvalid
	assert.True(t, errors.As(err, &sigErr))
}

func TestVerifyQuoteSignature_InvalidInputs(t *testing.T) {
	quote := buildTestQuote(t, []byte("nonce"), map[int][]byte{0: make([]byte, 32)})
	akPub, signature := signTestQuote(t, quote)

	tests := []struct {
		name      string
		akPub     []byte
		quote     []byte
		signature []byte
	}{
		{"empty key", nil, quote, signature},
		{"empty quote", akPub, nil, signature},
		{"empty signature", akPub, quote, nil},
		{"garbage key", []byte("not-a-key"), quote, signature},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyQuoteSignature(tt.akPub, tt.quote, tt.signature)
			require.Error(t, err)
			var sigErr ErrSignatureInvalid
			assert.True(t, errors.As(err, &sigErr))
		})
	}
}

// signQuote signs quote the way a TPM AK under opts would, returning the PKIX
// encoded AK public key and the raw signature.
func signQuote(t *testing.T, signer crypto.Signer, quote []byte, opts crypto.SignerOpts) ([]byte, []byte) {
	t.Helper()

	h := opts.HashFunc().New()
	h.Write(quote)
	signature, err := signer.Sign(rand.Reader, h.Sum(nil), opts)
	require.NoError(t, err)

	akPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	require.NoError(t, err)
	return akPub, signature
}

func TestVerifyQuoteSignatureWithAlgorithm_RoundTrips(t *testing.T) {
	quote := buildTestQuote(t, []byte("nonce"), map[int][]byte{7: make([]byte, 32)})

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		signer    crypto.Signer
		opts      crypto.SignerOpts
		algorithm x509.SignatureAlgorithm
	}{
		{"RSASSA SHA-256", rsaKey, crypto.SHA256, x509.SHA256WithRSA},
		{"RSASSA SHA-384", rsaKey, crypto.SHA384, x509.SHA384WithRSA},
		{"RSA-PSS salt equals hash", rsaKey,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}, x509.SHA256WithRSAPSS},
		{"RSA-PSS maximum salt", rsaKey,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}, x509.SHA256WithRSAPSS},
		{"RSA-PSS SHA-512", rsaKey,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512}, x509.SHA512WithRSAPSS},
		{"ECDSA P-256", p256, crypto.SHA256, x509.ECDSAWithSHA256},
		{"ECDSA P-384", p384, crypto.SHA384, x509.ECDSAWithSHA384},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			akPub, signature := signQuote(t, tt.signer, quote, tt.opts)
			require.NoError(t, VerifyQuoteSignatureWithAlgorithm(akPub, quote, signature, tt.algorithm.String()))

			tampered := append([]byte(nil), quote...)
			tampered[len(tampered)-1] ^= 0xFF
			err := VerifyQuoteSignatureWithAlgorithm(akPub, tampered, signature, tt.algorithm.String())
			var sigErr ErrSignatureInvalid
			require.True(t, errors.As(err, &sigErr), "tampered quote must fail verification, got %v", err)
		})
	}
}

// TestVerifyQuoteSignatureWithAlgorithm_DeclaredSchemeIsTheOneChecked proves
// the declared scheme is used and no other: an RSA-PSS quote does not pass as
// RSASSA, nor RSASSA as RSA-PSS, under the same key.
func TestVerifyQuoteSignatureWithAlgorithm_DeclaredSchemeIsTheOneChecked(t *testing.T) {
	quote := buildTestQuote(t, []byte("nonce"), map[int][]byte{7: make([]byte, 32)})
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	akPub, pssSig := signQuote(t, rsaKey, quote, pssOpts)
	_, pkcs1Sig := signQuote(t, rsaKey, quote, crypto.SHA256)

	var sigErr ErrSignatureInvalid
	err = VerifyQuoteSignatureWithAlgorithm(akPub, quote, pssSig, x509.SHA256WithRSA.String())
	assert.True(t, errors.As(err, &sigErr), "RSA-PSS signature declared as RSASSA: %v", err)
	err = VerifyQuoteSignatureWithAlgorithm(akPub, quote, pkcs1Sig, x509.SHA256WithRSAPSS.String())
	assert.True(t, errors.As(err, &sigErr), "RSASSA signature declared as RSA-PSS: %v", err)
	err = VerifyQuoteSignature(akPub, quote, pssSig)
	assert.True(t, errors.As(err, &sigErr), "VerifyQuoteSignature checks RSASSA only: %v", err)
}

func TestVerifyQuoteSignatureWithAlgorithm_SchemeKeyMismatch(t *testing.T) {
	quote := buildTestQuote(t, []byte("nonce"), map[int][]byte{7: make([]byte, 32)})
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rsaPub, rsaSig := signQuote(t, rsaKey, quote, crypto.SHA256)
	ecPub, ecSig := signQuote(t, ecKey, quote, crypto.SHA256)

	tests := []struct {
		name       string
		akPub      []byte
		signature  []byte
		algorithm  x509.SignatureAlgorithm
		wantScheme string
	}{
		{"RSA-PSS declared with an ECDSA key", ecPub, ecSig, x509.SHA256WithRSAPSS, "RSASSA-PSS"},
		{"RSASSA declared with an ECDSA key", ecPub, ecSig, x509.SHA256WithRSA, "RSASSA-PKCS1-v1_5"},
		{"ECDSA declared with an RSA key", rsaPub, rsaSig, x509.ECDSAWithSHA256, "ECDSA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyQuoteSignatureWithAlgorithm(tt.akPub, quote, tt.signature, tt.algorithm.String())
			var mismatch ErrSignatureSchemeMismatch
			require.True(t, errors.As(err, &mismatch), "want ErrSignatureSchemeMismatch, got %v", err)
			assert.Equal(t, tt.wantScheme, mismatch.Scheme)
		})
	}
}

func TestVerifyQuoteSignatureWithAlgorithm_FailsClosed(t *testing.T) {
	quote := buildTestQuote(t, []byte("nonce"), map[int][]byte{7: make([]byte, 32)})
	akPub, signature := signTestQuote(t, quote)

	for _, algorithm := range []string{"", "SHA1-RSA", "Ed25519", "sha256-rsa"} {
		t.Run("algorithm "+algorithm, func(t *testing.T) {
			err := VerifyQuoteSignatureWithAlgorithm(akPub, quote, signature, algorithm)
			var unsupported ErrUnsupportedSignatureAlgorithm
			require.True(t, errors.As(err, &unsupported), "want ErrUnsupportedSignatureAlgorithm, got %v", err)
			assert.Equal(t, algorithm, unsupported.Algorithm)
		})
	}

	inputs := []struct {
		name      string
		akPub     []byte
		quote     []byte
		signature []byte
	}{
		{"empty key", nil, quote, signature},
		{"empty quote", akPub, nil, signature},
		{"empty signature", akPub, quote, nil},
		{"garbage key", []byte("not-a-key"), quote, signature},
	}
	for _, tt := range inputs {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyQuoteSignatureWithAlgorithm(tt.akPub, tt.quote, tt.signature, x509.SHA256WithRSA.String())
			var sigErr ErrSignatureInvalid
			assert.True(t, errors.As(err, &sigErr), "want ErrSignatureInvalid, got %v", err)
		})
	}
}

func TestVerifyQuoteSignature_UnsupportedKeyType(t *testing.T) {
	quote := buildTestQuote(t, []byte("nonce"), map[int][]byte{7: make([]byte, 32)})
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	akPub, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)

	err = VerifyQuoteSignature(akPub, quote, []byte("signature"))
	var sigErr ErrSignatureInvalid
	require.True(t, errors.As(err, &sigErr))
	assert.Equal(t, "unsupported AK key type", sigErr.Reason)
}

func TestParseQuoteNonce(t *testing.T) {
	nonce := []byte("anti-replay-nonce")
	quote := buildTestQuote(t, nonce, map[int][]byte{0: make([]byte, 32)})

	parsed, err := ParseQuoteNonce(quote)
	require.NoError(t, err)
	assert.Equal(t, nonce, parsed)
}

func TestParseQuoteNonce_InvalidData(t *testing.T) {
	_, err := ParseQuoteNonce([]byte("garbage"))
	require.Error(t, err)
	var verifyErr ErrQuoteVerificationFailed
	assert.True(t, errors.As(err, &verifyErr))

	_, err = ParseQuoteNonce(nil)
	require.Error(t, err)
	assert.True(t, errors.As(err, &verifyErr))
}

func TestVerifyQuoteNonce(t *testing.T) {
	nonce := []byte("expected-nonce")
	quote := buildTestQuote(t, nonce, map[int][]byte{0: make([]byte, 32)})

	require.NoError(t, VerifyQuoteNonce(quote, nonce))

	err := VerifyQuoteNonce(quote, []byte("wrong-nonce"))
	require.Error(t, err)
	var nonceErr ErrNonceMismatch
	assert.True(t, errors.As(err, &nonceErr))

	err = VerifyQuoteNonce(quote, nil)
	require.Error(t, err)
}

func TestVerifyQuotePCRDigest(t *testing.T) {
	pcrValues := map[int][]byte{
		0: bytesOf(0xAA, 32),
		7: bytesOf(0xBB, 32),
	}
	quote := buildTestQuote(t, []byte("nonce"), pcrValues)

	require.NoError(t, VerifyQuotePCRDigest(quote, pcrValues))
}

func TestVerifyQuotePCRDigest_Mismatch(t *testing.T) {
	pcrValues := map[int][]byte{
		0: bytesOf(0xAA, 32),
		7: bytesOf(0xBB, 32),
	}
	quote := buildTestQuote(t, []byte("nonce"), pcrValues)

	// Wrong value for a selected PCR.
	wrong := map[int][]byte{
		0: bytesOf(0xAA, 32),
		7: bytesOf(0xCC, 32),
	}
	err := VerifyQuotePCRDigest(quote, wrong)
	require.Error(t, err)
	var verifyErr ErrQuoteVerificationFailed
	assert.True(t, errors.As(err, &verifyErr))

	// Index set does not match the quote selection.
	err = VerifyQuotePCRDigest(quote, map[int][]byte{0: bytesOf(0xAA, 32)})
	require.Error(t, err)
	assert.True(t, errors.As(err, &verifyErr))

	err = VerifyQuotePCRDigest(quote, map[int][]byte{
		0: bytesOf(0xAA, 32),
		1: bytesOf(0xBB, 32),
	})
	require.Error(t, err)
	assert.True(t, errors.As(err, &verifyErr))

	// Empty expected PCRs.
	err = VerifyQuotePCRDigest(quote, nil)
	require.Error(t, err)
	assert.True(t, errors.As(err, &verifyErr))
}

func TestVerifyQuotePCRDigest_UnsupportedBank(t *testing.T) {
	attest := tpm2.TPMSAttest{
		Magic: tpm2.TPMGeneratedValue,
		Type:  tpm2.TPMSTAttestQuote,
		ExtraData: tpm2.TPM2BData{
			Buffer: []byte("nonce"),
		},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA1,
						PCRSelect: tpm2.PCClientCompatible.PCRs(0),
					},
				},
			},
			PCRDigest: tpm2.TPM2BDigest{Buffer: make([]byte, 20)},
		}),
	}
	quote := tpm2.Marshal(attest)

	err := VerifyQuotePCRDigest(quote, map[int][]byte{0: make([]byte, 20)})
	require.Error(t, err)
	var verifyErr ErrQuoteVerificationFailed
	assert.True(t, errors.As(err, &verifyErr))
	assert.Contains(t, err.Error(), "SHA-256")
}

func TestParseQuoteAttest_WrongType(t *testing.T) {
	attest := tpm2.TPMSAttest{
		Magic: tpm2.TPMGeneratedValue,
		Type:  tpm2.TPMSTAttestCertify,
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify, &tpm2.TPMSCertifyInfo{
			Name:          tpm2.TPM2BName{Buffer: []byte("n")},
			QualifiedName: tpm2.TPM2BName{Buffer: []byte("q")},
		}),
	}
	data := tpm2.Marshal(attest)

	_, err := ParseQuoteNonce(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a quote")
}

// bytesOf returns a slice of n bytes all set to b.
func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestQuotePCRDigest_ReturnsTheSignedDigestAndSelection(t *testing.T) {
	values := map[int][]byte{0: bytes.Repeat([]byte{1}, 32), 7: bytes.Repeat([]byte{7}, 32), 14: bytes.Repeat([]byte{14}, 32)}
	quote := buildTestQuote(t, []byte("nonce"), values)

	digest, indices, err := QuotePCRDigest(quote)
	require.NoError(t, err)
	assert.Equal(t, []int{0, 7, 14}, indices, "selection must come back in ascending order")

	// The digest must be exactly what VerifyQuotePCRDigest would accept.
	require.NoError(t, VerifyQuotePCRDigest(quote, values))
	h := sha256.New()
	for _, idx := range []int{0, 7, 14} {
		h.Write(values[idx])
	}
	assert.Equal(t, h.Sum(nil), digest)
}

func TestQuotePCRDigest_RejectsGarbage(t *testing.T) {
	for name, in := range map[string][]byte{"empty": nil, "not an attest": []byte("hello")} {
		t.Run(name, func(t *testing.T) {
			_, _, err := QuotePCRDigest(in)
			var qerr ErrQuoteVerificationFailed
			require.ErrorAs(t, err, &qerr)
		})
	}
}
