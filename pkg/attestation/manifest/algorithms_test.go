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

package manifest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

// hashAlgorithmCase pairs a manifest hash algorithm with the crypto.Hash and
// signature algorithm name the signer must use for it.
type hashAlgorithmCase struct {
	algorithm     HashAlgorithm
	cryptoHash    crypto.Hash
	signatureName string
}

var hashAlgorithmCases = []hashAlgorithmCase{
	{HashAlgorithmSHA256, crypto.SHA256, "RSASSA-PKCS1-v1_5-SHA256"},
	{HashAlgorithmSHA384, crypto.SHA384, "RSASSA-PKCS1-v1_5-SHA384"},
	{HashAlgorithmSHA512, crypto.SHA512, "RSASSA-PKCS1-v1_5-SHA512"},
}

// buildTestManifest builds a manifest with one host, one VM and one container
// attestation using the given Merkle tree hash algorithm.
func buildTestManifest(t *testing.T, algorithm HashAlgorithm) *HostManifest {
	t.Helper()
	ctx := context.Background()

	builder := NewManifestBuilder()
	config := &BuilderConfig{HostID: "host-1", HashAlgorithm: algorithm, NonceSize: 32}
	if err := builder.Initialize(ctx, config); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if err := builder.SetHostAttestation(ctx, createValidHostAttestation()); err != nil {
		t.Fatalf("SetHostAttestation failed: %v", err)
	}
	if err := builder.AddVMAttestation(ctx, createValidVMAttestation("vm-1")); err != nil {
		t.Fatalf("AddVMAttestation failed: %v", err)
	}
	if err := builder.AddContainerAttestation(ctx, createValidContainerAttestation("container-1")); err != nil {
		t.Fatalf("AddContainerAttestation failed: %v", err)
	}

	manifest, err := builder.Build(ctx)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	return manifest
}

// newInitializedSigner returns a signer configured for the given algorithm.
func newInitializedSigner(t *testing.T, tpm TPMDevice, algorithm HashAlgorithm) ManifestSigner {
	t.Helper()
	signer := NewManifestSigner(WithSignerTPMDevice(tpm))
	config := &SignerConfig{TPMDevicePath: "/dev/tpm0", HashAlgorithm: algorithm}
	if err := signer.Initialize(context.Background(), config); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	return signer
}

// TestHashAlgorithmRoundTrip builds, signs and verifies a manifest with each
// supported algorithm, so the builder, signer and verifier must agree on the
// digest for SHA-384 and SHA-512 as well as SHA-256.
func TestHashAlgorithmRoundTrip(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	for _, tc := range hashAlgorithmCases {
		t.Run(tc.algorithm.String(), func(t *testing.T) {
			ctx := context.Background()
			manifest := buildTestManifest(t, tc.algorithm)

			if len(manifest.MerkleRoot) != tc.algorithm.DigestSize() {
				t.Fatalf("Merkle root is %d bytes, want %d", len(manifest.MerkleRoot), tc.algorithm.DigestSize())
			}

			signer := newInitializedSigner(t, &mockTPMDevice{}, tc.algorithm)
			if err := signer.SignWithKey(ctx, manifest, privateKey); err != nil {
				t.Fatalf("SignWithKey failed: %v", err)
			}
			if manifest.SignatureAlgorithm != tc.signatureName {
				t.Errorf("SignatureAlgorithm = %q, want %q", manifest.SignatureAlgorithm, tc.signatureName)
			}

			valid, err := signer.VerifySignature(ctx, manifest, &privateKey.PublicKey)
			if err != nil || !valid {
				t.Fatalf("signer.VerifySignature = %v, %v; want true, nil", valid, err)
			}

			valid, err = VerifyManifestSignature(manifest, &privateKey.PublicKey, tc.algorithm)
			if err != nil || !valid {
				t.Fatalf("VerifyManifestSignature = %v, %v; want true, nil", valid, err)
			}

			verifier := NewManifestVerifier()
			verifierConfig := &VerifierConfig{
				PlatformCACert:   createTestCACert(),
				HashAlgorithm:    tc.algorithm,
				VerifyMerkleRoot: true,
			}
			if err := verifier.Initialize(ctx, verifierConfig); err != nil {
				t.Fatalf("verifier Initialize failed: %v", err)
			}
			result, err := verifier.Verify(ctx, manifest, &privateKey.PublicKey, manifest.Nonce)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}
			if result.Status != VerificationStatusVerified {
				t.Errorf("Status = %s, want %s (errors: %v)", result.Status, VerificationStatusVerified, result.Errors)
			}
		})
	}
}

// TestHashAlgorithmMismatchRejected checks that a signature made with one
// algorithm does not verify under another.
func TestHashAlgorithmMismatchRejected(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	manifest := buildTestManifest(t, HashAlgorithmSHA384)
	signer := newInitializedSigner(t, &mockTPMDevice{}, HashAlgorithmSHA384)
	if err := signer.SignWithKey(context.Background(), manifest, privateKey); err != nil {
		t.Fatalf("SignWithKey failed: %v", err)
	}

	for _, algorithm := range []HashAlgorithm{HashAlgorithmSHA256, HashAlgorithmSHA512} {
		t.Run(algorithm.String(), func(t *testing.T) {
			valid, err := VerifyManifestSignature(manifest, &privateKey.PublicKey, algorithm)
			if valid {
				t.Fatal("expected signature to be rejected")
			}
			var sigErr ErrSignatureInvalid
			if !errors.As(err, &sigErr) {
				t.Fatalf("expected ErrSignatureInvalid, got %T: %v", err, err)
			}
			if sigErr.Cause == nil {
				t.Error("expected the RSA verification error as the cause")
			}
		})
	}
}

// TestManifestSignerSignTPMHashAlgorithms checks that the TPM is asked to
// sign a digest of the configured size with the configured algorithm, and
// that the resulting signature verifies.
func TestManifestSignerSignTPMHashAlgorithms(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	for _, tc := range hashAlgorithmCases {
		t.Run(tc.algorithm.String(), func(t *testing.T) {
			var gotDigestLen int
			var gotAlgorithm HashAlgorithm
			tpm := &mockTPMDevice{
				signFunc: func(ctx context.Context, data []byte, algorithm HashAlgorithm) ([]byte, error) {
					gotDigestLen = len(data)
					gotAlgorithm = algorithm
					return rsa.SignPKCS1v15(rand.Reader, privateKey, tc.cryptoHash, data)
				},
			}
			signer := newInitializedSigner(t, tpm, tc.algorithm)

			manifest := createTestManifest()
			if err := signer.Sign(context.Background(), manifest); err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			if gotDigestLen != tc.algorithm.DigestSize() {
				t.Errorf("TPM signed a %d-byte digest, want %d", gotDigestLen, tc.algorithm.DigestSize())
			}
			if gotAlgorithm != tc.algorithm {
				t.Errorf("TPM algorithm = %s, want %s", gotAlgorithm, tc.algorithm)
			}
			if manifest.SignatureAlgorithm != tc.signatureName {
				t.Errorf("SignatureAlgorithm = %q, want %q", manifest.SignatureAlgorithm, tc.signatureName)
			}

			valid, err := VerifyManifestSignature(manifest, &privateKey.PublicKey, tc.algorithm)
			if err != nil || !valid {
				t.Fatalf("VerifyManifestSignature = %v, %v; want true, nil", valid, err)
			}
		})
	}
}

// TestVerifyManifestSignatureRejections covers the rejection paths of
// VerifyManifestSignature beyond nil inputs.
func TestVerifyManifestSignatureRejections(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tests := []struct {
		name      string
		signature []byte
		publicKey crypto.PublicKey
		reason    string
	}{
		{"NoSignature", nil, &rsaKey.PublicKey, "manifest has no signature"},
		{"UnsupportedKeyType", []byte("signature"), &ecKey.PublicKey, "unsupported key type"},
		{"BadRSASignature", []byte("signature"), &rsaKey.PublicKey, "RSA signature verification failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := createTestManifest()
			manifest.Signature = tt.signature

			valid, err := VerifyManifestSignature(manifest, tt.publicKey, HashAlgorithmSHA256)
			if valid {
				t.Fatal("expected signature to be rejected")
			}
			var sigErr ErrSignatureInvalid
			if !errors.As(err, &sigErr) {
				t.Fatalf("expected ErrSignatureInvalid, got %T: %v", err, err)
			}
			if sigErr.Reason != tt.reason {
				t.Errorf("Reason = %q, want %q", sigErr.Reason, tt.reason)
			}
		})
	}
}

// TestManifestSignerVerifySignatureUnsupportedKey checks that the signer
// rejects a non-RSA key instead of reporting the signature as valid.
func TestManifestSignerVerifySignatureUnsupportedKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer := newInitializedSigner(t, &mockTPMDevice{}, HashAlgorithmSHA256)

	manifest := createTestManifest()
	manifest.Signature = []byte("signature")

	valid, err := signer.VerifySignature(context.Background(), manifest, &ecKey.PublicKey)
	if valid {
		t.Fatal("expected signature to be rejected")
	}
	var sigErr ErrSignatureInvalid
	if !errors.As(err, &sigErr) || sigErr.Reason != "unsupported key type" {
		t.Fatalf("expected ErrSignatureInvalid{unsupported key type}, got %T: %v", err, err)
	}
}

// TestParsePublicKeyPEM covers the PEM-encoded PKIX path and a PEM block
// that does not hold a public key.
func TestParsePublicKeyPEM(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	derBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	t.Run("PKIX", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})

		pubKey, err := ParsePublicKey(pemBytes)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("expected *rsa.PublicKey, got %T", pubKey)
		}
		if !rsaKey.Equal(&privateKey.PublicKey) {
			t.Error("parsed public key does not match")
		}
	})

	t.Run("NotAPublicKey", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a key")})

		_, err := ParsePublicKey(pemBytes)
		var sigErr ErrSignatureInvalid
		if !errors.As(err, &sigErr) {
			t.Fatalf("expected ErrSignatureInvalid, got %T: %v", err, err)
		}
	})
}
