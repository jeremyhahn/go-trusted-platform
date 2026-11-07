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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"sync"
	"testing"
	"time"
)

func createTestCACert() *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	return template
}

// cachedRSAKey returns a generator that makes one RSA-2048 key on first use
// and returns it after that. Key generation is the bulk of this package's test
// time; no test needs a fresh key, only a second key that differs.
func cachedRSAKey() func() (*rsa.PrivateKey, error) {
	return sync.OnceValues(func() (*rsa.PrivateKey, error) {
		return rsa.GenerateKey(rand.Reader, 2048)
	})
}

var (
	// testRSAKey is the key the tests sign manifests with.
	testRSAKey = cachedRSAKey()
	// testOtherRSAKey is a different key, for wrong-key verification.
	testOtherRSAKey = cachedRSAKey()
)

func createSignedTestManifest(t *testing.T) (*HostManifest, *rsa.PrivateKey) {
	privateKey, err := testRSAKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	manifest := createTestManifest()

	// Set correct Merkle root
	root, err := RecomputeMerkleRoot(manifest, HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("failed to compute Merkle root: %v", err)
	}
	manifest.MerkleRoot = root

	// Sign the manifest
	digest, err := ComputeManifestDigest(manifest, HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("failed to compute digest: %v", err)
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("failed to sign manifest: %v", err)
	}
	manifest.Signature = signature
	manifest.SignatureAlgorithm = "RSASSA-PKCS1-v1_5-SHA256"

	return manifest, privateKey
}

func TestNewManifestVerifier(t *testing.T) {
	t.Run("DefaultLogger", func(t *testing.T) {
		verifier := NewManifestVerifier()
		if verifier == nil {
			t.Fatal("expected non-nil verifier")
		}
	})

	t.Run("WithLogger", func(t *testing.T) {
		logger := slog.Default()
		verifier := NewManifestVerifier(WithVerifierLogger(logger))
		if verifier == nil {
			t.Fatal("expected non-nil verifier")
		}
	})
}

func TestManifestVerifierInitialize(t *testing.T) {
	caCert := createTestCACert()

	t.Run("Success", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}

		err := verifier.Initialize(context.Background(), config)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
	})

	t.Run("WithTrustedRoots", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			TrustedRoots:   []*x509.Certificate{caCert},
			HashAlgorithm:  HashAlgorithmSHA256,
		}

		err := verifier.Initialize(context.Background(), config)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
	})

	t.Run("NilConfig", func(t *testing.T) {
		verifier := NewManifestVerifier()
		err := verifier.Initialize(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
	})

	t.Run("InvalidConfig", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := verifier.Initialize(context.Background(), config)
		if err == nil {
			t.Fatal("expected error for invalid config")
		}
	})

	t.Run("AlreadyInitialized", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}

		err := verifier.Initialize(context.Background(), config)
		if err != nil {
			t.Fatalf("first initialization should succeed: %v", err)
		}

		err = verifier.Initialize(context.Background(), config)
		if err == nil {
			t.Fatal("expected error for double initialization")
		}
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := verifier.Initialize(ctx, config)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
	})
}

func TestManifestVerifierVerify(t *testing.T) {
	caCert := createTestCACert()

	t.Run("Success", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert:   caCert,
			HashAlgorithm:    HashAlgorithmSHA256,
			VerifyMerkleRoot: true,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest, privateKey := createSignedTestManifest(t)

		result, err := verifier.Verify(context.Background(), manifest, &privateKey.PublicKey, manifest.Nonce)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		if result.Status != VerificationStatusVerified {
			t.Errorf("expected Verified status, got %s", result.Status)
		}
		if !result.SignatureValid {
			t.Error("expected signature to be valid")
		}
		if !result.MerkleRootValid {
			t.Error("expected Merkle root to be valid")
		}
		if !result.NonceValid {
			t.Error("expected nonce to be valid")
		}
	})

	t.Run("WithHostAttestationRequired", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert:         caCert,
			HashAlgorithm:          HashAlgorithmSHA256,
			VerifyMerkleRoot:       true,
			RequireHostAttestation: true,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest, privateKey := createSignedTestManifest(t)

		result, err := verifier.Verify(context.Background(), manifest, &privateKey.PublicKey, manifest.Nonce)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		if result.Status != VerificationStatusVerified {
			t.Errorf("expected Verified status, got %s", result.Status)
		}
		if !result.HostAttestationValid {
			t.Error("expected host attestation to be valid")
		}
	})

	t.Run("NotInitialized", func(t *testing.T) {
		verifier := NewManifestVerifier()
		manifest, privateKey := createSignedTestManifest(t)

		_, err := verifier.Verify(context.Background(), manifest, &privateKey.PublicKey, manifest.Nonce)
		if err == nil {
			t.Fatal("expected error for uninitialized verifier")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		privateKey, _ := testRSAKey()

		_, err := verifier.Verify(context.Background(), nil, &privateKey.PublicKey, []byte("nonce"))
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert:   caCert,
			HashAlgorithm:    HashAlgorithmSHA256,
			VerifyMerkleRoot: true,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest, _ := createSignedTestManifest(t)
		manifest.Signature = []byte("invalid-signature")

		// Use a different key for verification
		otherKey, _ := testOtherRSAKey()

		result, err := verifier.Verify(context.Background(), manifest, &otherKey.PublicKey, manifest.Nonce)
		if err != nil {
			t.Fatalf("expected no error from Verify, got: %v", err)
		}

		if result.Status != VerificationStatusFailed {
			t.Errorf("expected Failed status, got %s", result.Status)
		}
		if result.SignatureValid {
			t.Error("expected signature to be invalid")
		}
	})

	t.Run("InvalidNonce", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert:   caCert,
			HashAlgorithm:    HashAlgorithmSHA256,
			VerifyMerkleRoot: true,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest, privateKey := createSignedTestManifest(t)

		result, err := verifier.Verify(context.Background(), manifest, &privateKey.PublicKey, []byte("wrong-nonce"))
		if err != nil {
			t.Fatalf("expected no error from Verify, got: %v", err)
		}

		if result.Status != VerificationStatusFailed {
			t.Errorf("expected Failed status, got %s", result.Status)
		}
		if result.NonceValid {
			t.Error("expected nonce to be invalid")
		}
	})

	t.Run("ExpiredManifest", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
			MaxManifestAge: 1, // 1 second
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest, privateKey := createSignedTestManifest(t)
		manifest.Timestamp = time.Now().Add(-10 * time.Second) // 10 seconds ago

		// Re-sign with updated timestamp
		root, _ := RecomputeMerkleRoot(manifest, HashAlgorithmSHA256)
		manifest.MerkleRoot = root
		digest, _ := ComputeManifestDigest(manifest, HashAlgorithmSHA256)
		signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
		manifest.Signature = signature

		result, err := verifier.Verify(context.Background(), manifest, &privateKey.PublicKey, manifest.Nonce)
		if err != nil {
			t.Fatalf("expected no error from Verify, got: %v", err)
		}

		if result.Status != VerificationStatusFailed {
			t.Errorf("expected Failed status, got %s", result.Status)
		}
		if result.TimestampValid {
			t.Error("expected timestamp to be invalid")
		}
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		manifest, privateKey := createSignedTestManifest(t)
		_, err := verifier.Verify(ctx, manifest, &privateKey.PublicKey, manifest.Nonce)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
	})

	t.Run("ClosedVerifier", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		if err := verifier.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		manifest, privateKey := createSignedTestManifest(t)
		_, err := verifier.Verify(context.Background(), manifest, &privateKey.PublicKey, manifest.Nonce)
		if err == nil {
			t.Fatal("expected error for closed verifier")
		}
	})
}

func TestManifestVerifierVerifySignature(t *testing.T) {
	caCert := createTestCACert()

	t.Run("Valid", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest, privateKey := createSignedTestManifest(t)

		valid, err := verifier.VerifySignature(context.Background(), manifest, &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if !valid {
			t.Error("expected signature to be valid")
		}
	})

	t.Run("ValidSHA384", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA384,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		privateKey, _ := testRSAKey()
		manifest := createTestManifest()
		root, _ := RecomputeMerkleRoot(manifest, HashAlgorithmSHA384)
		manifest.MerkleRoot = root
		digest, _ := ComputeManifestDigest(manifest, HashAlgorithmSHA384)
		signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, digest)
		manifest.Signature = signature

		valid, err := verifier.VerifySignature(context.Background(), manifest, &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if !valid {
			t.Error("expected signature to be valid")
		}
	})

	t.Run("ValidSHA512", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA512,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		privateKey, _ := testRSAKey()
		manifest := createTestManifest()
		root, _ := RecomputeMerkleRoot(manifest, HashAlgorithmSHA512)
		manifest.MerkleRoot = root
		digest, _ := ComputeManifestDigest(manifest, HashAlgorithmSHA512)
		signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, digest)
		manifest.Signature = signature

		valid, err := verifier.VerifySignature(context.Background(), manifest, &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if !valid {
			t.Error("expected signature to be valid")
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest, _ := createSignedTestManifest(t)
		manifest.Signature = []byte("invalid")

		otherKey, _ := testOtherRSAKey()

		valid, err := verifier.VerifySignature(context.Background(), manifest, &otherKey.PublicKey)
		if err == nil {
			t.Fatal("expected error for invalid signature")
		}
		if valid {
			t.Error("expected signature to be invalid")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		privateKey, _ := testRSAKey()

		_, err := verifier.VerifySignature(context.Background(), nil, &privateKey.PublicKey)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("NilPublicKey", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest, _ := createSignedTestManifest(t)

		_, err := verifier.VerifySignature(context.Background(), manifest, nil)
		if err == nil {
			t.Fatal("expected error for nil public key")
		}
	})

	t.Run("EmptySignature", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		manifest.Signature = nil

		privateKey, _ := testRSAKey()

		_, err := verifier.VerifySignature(context.Background(), manifest, &privateKey.PublicKey)
		if err == nil {
			t.Fatal("expected error for empty signature")
		}
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		manifest, privateKey := createSignedTestManifest(t)
		_, err := verifier.VerifySignature(ctx, manifest, &privateKey.PublicKey)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
	})
}

func TestManifestVerifierVerifyMerkleRoot(t *testing.T) {
	caCert := createTestCACert()

	t.Run("Valid", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest, _ := createSignedTestManifest(t)

		valid, err := verifier.VerifyMerkleRoot(context.Background(), manifest)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if !valid {
			t.Error("expected Merkle root to be valid")
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		manifest.MerkleRoot = []byte("wrong-merkle-root")

		valid, err := verifier.VerifyMerkleRoot(context.Background(), manifest)
		if err == nil {
			t.Fatal("expected error for invalid Merkle root")
		}
		if valid {
			t.Error("expected Merkle root to be invalid")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		_, err := verifier.VerifyMerkleRoot(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("EmptyMerkleRoot", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		manifest.MerkleRoot = nil

		_, err := verifier.VerifyMerkleRoot(context.Background(), manifest)
		if err == nil {
			t.Fatal("expected error for empty Merkle root")
		}
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		manifest, _ := createSignedTestManifest(t)
		_, err := verifier.VerifyMerkleRoot(ctx, manifest)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
	})
}

func TestManifestVerifierVerifyNonce(t *testing.T) {
	caCert := createTestCACert()

	t.Run("Valid", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		valid := verifier.VerifyNonce(manifest, manifest.Nonce)
		if !valid {
			t.Error("expected nonce to be valid")
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		valid := verifier.VerifyNonce(manifest, []byte("wrong-nonce"))
		if valid {
			t.Error("expected nonce to be invalid")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		verifier := NewManifestVerifier()
		valid := verifier.VerifyNonce(nil, []byte("nonce"))
		if valid {
			t.Error("expected false for nil manifest")
		}
	})

	t.Run("EmptyExpectedNonce", func(t *testing.T) {
		verifier := NewManifestVerifier()
		manifest := createTestManifest()
		valid := verifier.VerifyNonce(manifest, []byte{})
		if valid {
			t.Error("expected false for empty expected nonce")
		}
	})
}

func TestManifestVerifierVerifyFreshness(t *testing.T) {
	caCert := createTestCACert()

	t.Run("Fresh", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
			MaxManifestAge: 300, // 5 minutes
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		manifest.Timestamp = time.Now()

		valid, err := verifier.VerifyFreshness(manifest)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if !valid {
			t.Error("expected manifest to be fresh")
		}
	})

	t.Run("Expired", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
			MaxManifestAge: 1, // 1 second
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		manifest.Timestamp = time.Now().Add(-10 * time.Second)

		valid, err := verifier.VerifyFreshness(manifest)
		if err == nil {
			t.Fatal("expected error for expired manifest")
		}
		if valid {
			t.Error("expected manifest to be expired")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
			MaxManifestAge: 300,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		_, err := verifier.VerifyFreshness(nil)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("ZeroTimestamp", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
			MaxManifestAge: 300,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		manifest.Timestamp = time.Time{}

		_, err := verifier.VerifyFreshness(manifest)
		if err == nil {
			t.Fatal("expected error for zero timestamp")
		}
	})
}

func TestManifestVerifierVerifyHostAttestation(t *testing.T) {
	caCert := createTestCACert()

	t.Run("Valid", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest, _ := createSignedTestManifest(t)

		valid, err := verifier.VerifyHostAttestation(context.Background(), manifest, nil)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if !valid {
			t.Error("expected host attestation to be valid")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		_, err := verifier.VerifyHostAttestation(context.Background(), nil, nil)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("NilHostAttestation", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		manifest.Host = nil

		_, err := verifier.VerifyHostAttestation(context.Background(), manifest, nil)
		if err == nil {
			t.Fatal("expected error for nil host attestation")
		}
	})

	t.Run("WithExpectedPCRs", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		expectedPCRs := map[int][]byte{
			0: make([]byte, 32),
		}

		valid, err := verifier.VerifyHostAttestation(context.Background(), manifest, expectedPCRs)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if !valid {
			t.Error("expected host attestation to be valid")
		}
	})

	t.Run("PCRMismatch", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		expectedPCRs := map[int][]byte{
			0: bytes.Repeat([]byte{0xFF}, 32),
		}

		valid, err := verifier.VerifyHostAttestation(context.Background(), manifest, expectedPCRs)
		if err == nil {
			t.Fatal("expected error for PCR mismatch")
		}
		if valid {
			t.Error("expected host attestation to be invalid")
		}
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		manifest, _ := createSignedTestManifest(t)
		_, err := verifier.VerifyHostAttestation(ctx, manifest, nil)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
	})
}

func TestManifestVerifierVerifyVMAttestations(t *testing.T) {
	caCert := createTestCACert()

	t.Run("AllValid", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest, _ := createSignedTestManifest(t)

		valid, errors := verifier.VerifyVMAttestations(context.Background(), manifest)
		if !valid {
			t.Errorf("expected all VM attestations to be valid: %v", errors)
		}
		if len(errors) > 0 {
			t.Errorf("expected no errors: %v", errors)
		}
	})

	t.Run("InvalidVM", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		manifest.VMs = append(manifest.VMs, VMAttestation{
			VMID: "invalid-vm",
			// Missing required fields
		})

		valid, errors := verifier.VerifyVMAttestations(context.Background(), manifest)
		if valid {
			t.Error("expected some VM attestations to be invalid")
		}
		if len(errors) == 0 {
			t.Error("expected some errors")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		valid, _ := verifier.VerifyVMAttestations(context.Background(), nil)
		if valid {
			t.Error("expected false for nil manifest")
		}
	})
}

func TestManifestVerifierVerifyContainerAttestations(t *testing.T) {
	caCert := createTestCACert()

	t.Run("AllValid", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest, _ := createSignedTestManifest(t)

		valid, errors := verifier.VerifyContainerAttestations(context.Background(), manifest)
		if !valid {
			t.Errorf("expected all container attestations to be valid: %v", errors)
		}
		if len(errors) > 0 {
			t.Errorf("expected no errors: %v", errors)
		}
	})

	t.Run("InvalidContainer", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		manifest.Containers = append(manifest.Containers, ContainerAttestation{
			ContainerID: "invalid-container",
			// Missing required fields
		})

		valid, errors := verifier.VerifyContainerAttestations(context.Background(), manifest)
		if valid {
			t.Error("expected some container attestations to be invalid")
		}
		if len(errors) == 0 {
			t.Error("expected some errors")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		valid, _ := verifier.VerifyContainerAttestations(context.Background(), nil)
		if valid {
			t.Error("expected false for nil manifest")
		}
	})
}

func TestManifestVerifierClose(t *testing.T) {
	caCert := createTestCACert()

	t.Run("Success", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := verifier.Close()
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
	})

	t.Run("DoubleClose", func(t *testing.T) {
		verifier := NewManifestVerifier()
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}
		if err := verifier.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := verifier.Close()
		if err != nil {
			t.Fatalf("first close should succeed: %v", err)
		}

		err = verifier.Close()
		if err != nil {
			t.Fatalf("second close should also succeed: %v", err)
		}
	})
}

func TestQuickVerify(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		manifest, privateKey := createSignedTestManifest(t)

		valid, err := QuickVerify(manifest, &privateKey.PublicKey, manifest.Nonce, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if !valid {
			t.Error("expected valid")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		privateKey, _ := testRSAKey()
		_, err := QuickVerify(nil, &privateKey.PublicKey, []byte("nonce"), HashAlgorithmSHA256)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("InvalidManifest", func(t *testing.T) {
		manifest := &HostManifest{} // Missing required fields
		privateKey, _ := testRSAKey()

		_, err := QuickVerify(manifest, &privateKey.PublicKey, []byte("nonce"), HashAlgorithmSHA256)
		if err == nil {
			t.Fatal("expected error for invalid manifest")
		}
	})

	t.Run("WrongNonce", func(t *testing.T) {
		manifest, privateKey := createSignedTestManifest(t)

		_, err := QuickVerify(manifest, &privateKey.PublicKey, []byte("wrong-nonce"), HashAlgorithmSHA256)
		if err == nil {
			t.Fatal("expected error for wrong nonce")
		}
	})

	t.Run("InvalidMerkleRoot", func(t *testing.T) {
		manifest, privateKey := createSignedTestManifest(t)
		manifest.MerkleRoot = []byte("wrong-merkle-root")

		_, err := QuickVerify(manifest, &privateKey.PublicKey, manifest.Nonce, HashAlgorithmSHA256)
		if err == nil {
			t.Fatal("expected error for invalid Merkle root")
		}
	})
}

func TestExtractPublicKeyFromManifest(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		// Generate a key pair and encode the public key
		privateKey, _ := testRSAKey()
		pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)

		manifest := createTestManifest()
		manifest.Host.AKPublicKey = pubKeyBytes

		pubKey, err := ExtractPublicKeyFromManifest(manifest)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			t.Fatal("expected RSA public key")
		}
		if rsaKey.N.Cmp(privateKey.N) != 0 {
			t.Error("extracted key does not match")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		_, err := ExtractPublicKeyFromManifest(nil)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("NilHost", func(t *testing.T) {
		manifest := &HostManifest{}
		_, err := ExtractPublicKeyFromManifest(manifest)
		if err == nil {
			t.Fatal("expected error for nil host")
		}
	})

	t.Run("EmptyAKPublicKey", func(t *testing.T) {
		manifest := createTestManifest()
		manifest.Host.AKPublicKey = nil

		_, err := ExtractPublicKeyFromManifest(manifest)
		if err == nil {
			t.Fatal("expected error for empty AK public key")
		}
	})
}
