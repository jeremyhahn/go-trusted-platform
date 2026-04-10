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
	"errors"
	"testing"
	"time"
)

func createTestManifest() *HostManifest {
	return &HostManifest{
		ID:        "manifest-1",
		HostID:    "host-1",
		Timestamp: time.Now(),
		Nonce:     []byte("nonce123456789012345678901234567"),
		Host: &HostAttestation{
			QuoteData:          []byte("host-quote-data"),
			Signature:          []byte("host-signature"),
			SignatureAlgorithm: "RSASSA-PKCS1-v1_5-SHA256",
			PCRs: []PCRValue{
				{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256},
			},
			PCRDigest:     make([]byte, 32),
			Nonce:         []byte("host-nonce12345678901234"),
			Timestamp:     time.Now(),
			AKPublicKey:   []byte("ak-public-key"),
			HashAlgorithm: HashAlgorithmSHA256,
		},
		VMs: []VMAttestation{
			{
				VMID:          "vm-1",
				HostID:        "host-1",
				QuoteData:     []byte("vm-quote-data"),
				Signature:     []byte("vm-signature"),
				PCRs:          []PCRValue{{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256}},
				PCRDigest:     make([]byte, 32),
				Nonce:         []byte("vm-nonce1234567890123456"),
				HashAlgorithm: HashAlgorithmSHA256,
			},
		},
		Containers: []ContainerAttestation{
			{
				ContainerID: "container-1",
				Digest:      make([]byte, 32),
				PCRValue:    make([]byte, 32),
			},
		},
		MerkleRoot: make([]byte, 32),
		Version:    "1.0",
		Metadata:   make(map[string]string),
	}
}

func TestNewManifestSigner(t *testing.T) {
	t.Run("DefaultLogger", func(t *testing.T) {
		signer := NewManifestSigner()
		if signer == nil {
			t.Fatal("expected non-nil signer")
		}
	})

	t.Run("WithOptions", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(
			WithSignerTPMDevice(tpm),
		)
		if signer == nil {
			t.Fatal("expected non-nil signer")
		}
	})
}

func TestManifestSignerInitialize(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := signer.Initialize(context.Background(), config)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
	})

	t.Run("NilConfig", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		err := signer.Initialize(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
	})

	t.Run("InvalidConfig", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := signer.Initialize(context.Background(), config)
		if err == nil {
			t.Fatal("expected error for invalid config")
		}
	})

	t.Run("NoTPMDevice", func(t *testing.T) {
		signer := NewManifestSigner()

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := signer.Initialize(context.Background(), config)
		if err == nil {
			t.Fatal("expected error for missing TPM device")
		}
	})

	t.Run("TPMError", func(t *testing.T) {
		tpm := &mockTPMDevice{
			getAKPublicKeyFunc: func(ctx context.Context) ([]byte, error) {
				return nil, errors.New("TPM error")
			},
		}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := signer.Initialize(context.Background(), config)
		if err == nil {
			t.Fatal("expected error for TPM failure")
		}
	})

	t.Run("AlreadyInitialized", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := signer.Initialize(context.Background(), config)
		if err != nil {
			t.Fatalf("first initialization should succeed: %v", err)
		}

		err = signer.Initialize(context.Background(), config)
		if err == nil {
			t.Fatal("expected error for double initialization")
		}
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := signer.Initialize(ctx, config)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
	})
}

func TestManifestSignerSign(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tpm := &mockTPMDevice{
			signFunc: func(ctx context.Context, data []byte, algorithm HashAlgorithm) ([]byte, error) {
				return []byte("tpm-signature"), nil
			},
		}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}
		if err := signer.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		err := signer.Sign(context.Background(), manifest)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		if len(manifest.Signature) == 0 {
			t.Error("expected signature to be set")
		}
		if manifest.SignatureAlgorithm == "" {
			t.Error("expected signature algorithm to be set")
		}
	})

	t.Run("NotInitialized", func(t *testing.T) {
		signer := NewManifestSigner()
		manifest := createTestManifest()
		err := signer.Sign(context.Background(), manifest)
		if err == nil {
			t.Fatal("expected error for uninitialized signer")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}
		if err := signer.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := signer.Sign(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("TPMSignError", func(t *testing.T) {
		tpm := &mockTPMDevice{
			signFunc: func(ctx context.Context, data []byte, algorithm HashAlgorithm) ([]byte, error) {
				return nil, errors.New("sign error")
			},
		}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}
		if err := signer.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		err := signer.Sign(context.Background(), manifest)
		if err == nil {
			t.Fatal("expected error for TPM sign failure")
		}
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}
		if err := signer.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		manifest := createTestManifest()
		err := signer.Sign(ctx, manifest)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
	})
}

func TestManifestSignerSignWithKey(t *testing.T) {
	// Generate test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	t.Run("Success", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}
		if err := signer.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		err := signer.SignWithKey(context.Background(), manifest, privateKey)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		if len(manifest.Signature) == 0 {
			t.Error("expected signature to be set")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		signer := NewManifestSigner()
		err := signer.SignWithKey(context.Background(), nil, privateKey)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("NilKey", func(t *testing.T) {
		signer := NewManifestSigner()
		manifest := createTestManifest()
		err := signer.SignWithKey(context.Background(), manifest, nil)
		if err == nil {
			t.Fatal("expected error for nil key")
		}
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		signer := NewManifestSigner()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		manifest := createTestManifest()
		err := signer.SignWithKey(ctx, manifest, privateKey)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
	})
}

func TestManifestSignerVerifySignature(t *testing.T) {
	// Generate test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	t.Run("Success", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}
		if err := signer.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		err := signer.SignWithKey(context.Background(), manifest, privateKey)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		valid, err := signer.VerifySignature(context.Background(), manifest, &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if !valid {
			t.Error("expected signature to be valid")
		}
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}
		if err := signer.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		manifest.Signature = []byte("invalid-signature")

		valid, err := signer.VerifySignature(context.Background(), manifest, &privateKey.PublicKey)
		if err == nil {
			t.Fatal("expected error for invalid signature")
		}
		if valid {
			t.Error("expected signature to be invalid")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}
		if err := signer.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		_, err := signer.VerifySignature(context.Background(), nil, &privateKey.PublicKey)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("NilPublicKey", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}
		if err := signer.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		_, err := signer.VerifySignature(context.Background(), manifest, nil)
		if err == nil {
			t.Fatal("expected error for nil public key")
		}
	})

	t.Run("EmptySignature", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}
		if err := signer.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		manifest := createTestManifest()
		manifest.Signature = nil

		_, err := signer.VerifySignature(context.Background(), manifest, &privateKey.PublicKey)
		if err == nil {
			t.Fatal("expected error for empty signature")
		}
	})
}

func TestManifestSignerClose(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}
		if err := signer.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := signer.Close()
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
	})

	t.Run("DoubleClose", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		signer := NewManifestSigner(WithSignerTPMDevice(tpm))

		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}
		if err := signer.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := signer.Close()
		if err != nil {
			t.Fatalf("first close should succeed: %v", err)
		}

		err = signer.Close()
		if err != nil {
			t.Fatalf("second close should also succeed: %v", err)
		}
	})
}

func TestParsePublicKey(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	t.Run("DERFormat", func(t *testing.T) {
		derBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to marshal public key: %v", err)
		}

		pubKey, err := ParsePublicKey(derBytes)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			t.Fatal("expected RSA public key")
		}
		if rsaKey.N.Cmp(privateKey.N) != 0 {
			t.Error("public key N does not match")
		}
	})

	t.Run("PKCS1Format", func(t *testing.T) {
		pkcs1Bytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)

		pubKey, err := ParsePublicKey(pkcs1Bytes)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			t.Fatal("expected RSA public key")
		}
		if rsaKey.N.Cmp(privateKey.N) != 0 {
			t.Error("public key N does not match")
		}
	})

	t.Run("InvalidData", func(t *testing.T) {
		_, err := ParsePublicKey([]byte("invalid"))
		if err == nil {
			t.Fatal("expected error for invalid data")
		}
	})
}

func TestComputeManifestDigest(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		manifest := createTestManifest()
		digest, err := ComputeManifestDigest(manifest, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if len(digest) != 32 {
			t.Errorf("expected 32-byte digest, got %d", len(digest))
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		_, err := ComputeManifestDigest(nil, HashAlgorithmSHA256)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("Deterministic", func(t *testing.T) {
		manifest := createTestManifest()
		digest1, _ := ComputeManifestDigest(manifest, HashAlgorithmSHA256)
		digest2, _ := ComputeManifestDigest(manifest, HashAlgorithmSHA256)
		if !bytes.Equal(digest1, digest2) {
			t.Error("expected deterministic digest")
		}
	})

	t.Run("SHA384", func(t *testing.T) {
		manifest := createTestManifest()
		digest, err := ComputeManifestDigest(manifest, HashAlgorithmSHA384)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if len(digest) != 48 {
			t.Errorf("expected 48-byte digest for SHA384, got %d", len(digest))
		}
	})

	t.Run("SHA512", func(t *testing.T) {
		manifest := createTestManifest()
		digest, err := ComputeManifestDigest(manifest, HashAlgorithmSHA512)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if len(digest) != 64 {
			t.Errorf("expected 64-byte digest for SHA512, got %d", len(digest))
		}
	})
}

func TestVerifyManifestSignature(t *testing.T) {
	// Generate test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	t.Run("Success", func(t *testing.T) {
		manifest := createTestManifest()

		// Compute digest and sign
		digest, _ := ComputeManifestDigest(manifest, HashAlgorithmSHA256)
		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}
		manifest.Signature = signature

		valid, err := VerifyManifestSignature(manifest, &privateKey.PublicKey, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if !valid {
			t.Error("expected valid signature")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		_, err := VerifyManifestSignature(nil, &privateKey.PublicKey, HashAlgorithmSHA256)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("NilPublicKey", func(t *testing.T) {
		manifest := createTestManifest()
		manifest.Signature = []byte("signature")
		_, err := VerifyManifestSignature(manifest, nil, HashAlgorithmSHA256)
		if err == nil {
			t.Fatal("expected error for nil public key")
		}
	})
}

func TestRecomputeMerkleRoot(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		manifest := createTestManifest()
		root, err := RecomputeMerkleRoot(manifest, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if len(root) != 32 {
			t.Errorf("expected 32-byte root, got %d", len(root))
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		_, err := RecomputeMerkleRoot(nil, HashAlgorithmSHA256)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})

	t.Run("EmptyManifest", func(t *testing.T) {
		manifest := &HostManifest{}
		_, err := RecomputeMerkleRoot(manifest, HashAlgorithmSHA256)
		if err == nil {
			t.Fatal("expected error for empty manifest")
		}
	})

	t.Run("Deterministic", func(t *testing.T) {
		manifest := createTestManifest()
		root1, _ := RecomputeMerkleRoot(manifest, HashAlgorithmSHA256)
		root2, _ := RecomputeMerkleRoot(manifest, HashAlgorithmSHA256)
		if !bytes.Equal(root1, root2) {
			t.Error("expected deterministic Merkle root")
		}
	})
}

func TestValidateMerkleRoot(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		manifest := createTestManifest()
		// Set the correct Merkle root
		root, _ := RecomputeMerkleRoot(manifest, HashAlgorithmSHA256)
		manifest.MerkleRoot = root

		valid, err := ValidateMerkleRoot(manifest, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if !valid {
			t.Error("expected valid Merkle root")
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		manifest := createTestManifest()
		manifest.MerkleRoot = []byte("wrong-merkle-root-value-here")

		valid, err := ValidateMerkleRoot(manifest, HashAlgorithmSHA256)
		if err == nil {
			t.Fatal("expected error for invalid Merkle root")
		}
		if valid {
			t.Error("expected invalid Merkle root")
		}
	})

	t.Run("NilManifest", func(t *testing.T) {
		_, err := ValidateMerkleRoot(nil, HashAlgorithmSHA256)
		if err == nil {
			t.Fatal("expected error for nil manifest")
		}
	})
}
