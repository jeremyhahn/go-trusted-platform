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
	"crypto/x509"
	"testing"
	"time"
)

func TestHashAlgorithm(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		tests := []struct {
			alg      HashAlgorithm
			expected string
		}{
			{HashAlgorithmSHA1, "sha1"},
			{HashAlgorithmSHA256, "sha256"},
			{HashAlgorithmSHA384, "sha384"},
			{HashAlgorithmSHA512, "sha512"},
		}

		for _, tc := range tests {
			if tc.alg.String() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, tc.alg.String())
			}
		}
	})

	t.Run("IsValid", func(t *testing.T) {
		validAlgs := []HashAlgorithm{
			HashAlgorithmSHA1,
			HashAlgorithmSHA256,
			HashAlgorithmSHA384,
			HashAlgorithmSHA512,
		}

		for _, alg := range validAlgs {
			if !alg.IsValid() {
				t.Errorf("expected %q to be valid", alg)
			}
		}

		invalidAlgs := []HashAlgorithm{"md5", "sha3", ""}
		for _, alg := range invalidAlgs {
			if alg.IsValid() {
				t.Errorf("expected %q to be invalid", alg)
			}
		}
	})

	t.Run("DigestSize", func(t *testing.T) {
		tests := []struct {
			alg      HashAlgorithm
			expected int
		}{
			{HashAlgorithmSHA1, 20},
			{HashAlgorithmSHA256, 32},
			{HashAlgorithmSHA384, 48},
			{HashAlgorithmSHA512, 64},
			{"invalid", 0},
		}

		for _, tc := range tests {
			if tc.alg.DigestSize() != tc.expected {
				t.Errorf("expected %d for %q, got %d", tc.expected, tc.alg, tc.alg.DigestSize())
			}
		}
	})
}

func TestVerificationStatus(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		tests := []struct {
			status   VerificationStatus
			expected string
		}{
			{VerificationStatusUnknown, "unknown"},
			{VerificationStatusPending, "pending"},
			{VerificationStatusVerified, "verified"},
			{VerificationStatusFailed, "failed"},
		}

		for _, tc := range tests {
			if tc.status.String() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, tc.status.String())
			}
		}
	})

	t.Run("IsValid", func(t *testing.T) {
		validStatuses := []VerificationStatus{
			VerificationStatusUnknown,
			VerificationStatusPending,
			VerificationStatusVerified,
			VerificationStatusFailed,
		}

		for _, status := range validStatuses {
			if !status.IsValid() {
				t.Errorf("expected %q to be valid", status)
			}
		}

		invalidStatuses := []VerificationStatus{"invalid", ""}
		for _, status := range invalidStatuses {
			if status.IsValid() {
				t.Errorf("expected %q to be invalid", status)
			}
		}
	})
}

func TestHostManifestValidate(t *testing.T) {
	validHost := &HostAttestation{
		QuoteData:     []byte("quote"),
		Signature:     []byte("sig"),
		PCRs:          []PCRValue{{Index: 0, Value: []byte("value")}},
		Nonce:         []byte("nonce"),
		HashAlgorithm: HashAlgorithmSHA256,
	}

	t.Run("Valid", func(t *testing.T) {
		manifest := &HostManifest{
			ID:         "manifest-1",
			HostID:     "host-1",
			Timestamp:  time.Now(),
			Nonce:      []byte("nonce123456789012"),
			Host:       validHost,
			MerkleRoot: []byte("merkle"),
		}

		if err := manifest.Validate(); err != nil {
			t.Errorf("expected valid manifest, got error: %v", err)
		}
	})

	t.Run("EmptyID", func(t *testing.T) {
		manifest := &HostManifest{
			HostID:     "host-1",
			Timestamp:  time.Now(),
			Nonce:      []byte("nonce"),
			Host:       validHost,
			MerkleRoot: []byte("merkle"),
		}

		err := manifest.Validate()
		if err == nil {
			t.Error("expected error for empty ID")
		}
	})

	t.Run("EmptyHostID", func(t *testing.T) {
		manifest := &HostManifest{
			ID:         "manifest-1",
			Timestamp:  time.Now(),
			Nonce:      []byte("nonce"),
			Host:       validHost,
			MerkleRoot: []byte("merkle"),
		}

		err := manifest.Validate()
		if err == nil {
			t.Error("expected error for empty HostID")
		}
	})

	t.Run("ZeroTimestamp", func(t *testing.T) {
		manifest := &HostManifest{
			ID:         "manifest-1",
			HostID:     "host-1",
			Nonce:      []byte("nonce"),
			Host:       validHost,
			MerkleRoot: []byte("merkle"),
		}

		err := manifest.Validate()
		if err == nil {
			t.Error("expected error for zero timestamp")
		}
	})

	t.Run("EmptyNonce", func(t *testing.T) {
		manifest := &HostManifest{
			ID:         "manifest-1",
			HostID:     "host-1",
			Timestamp:  time.Now(),
			Host:       validHost,
			MerkleRoot: []byte("merkle"),
		}

		err := manifest.Validate()
		if err == nil {
			t.Error("expected error for empty nonce")
		}
	})

	t.Run("NilHost", func(t *testing.T) {
		manifest := &HostManifest{
			ID:         "manifest-1",
			HostID:     "host-1",
			Timestamp:  time.Now(),
			Nonce:      []byte("nonce"),
			MerkleRoot: []byte("merkle"),
		}

		err := manifest.Validate()
		if err == nil {
			t.Error("expected error for nil host")
		}
	})

	t.Run("EmptyMerkleRoot", func(t *testing.T) {
		manifest := &HostManifest{
			ID:        "manifest-1",
			HostID:    "host-1",
			Timestamp: time.Now(),
			Nonce:     []byte("nonce"),
			Host:      validHost,
		}

		err := manifest.Validate()
		if err == nil {
			t.Error("expected error for empty Merkle root")
		}
	})
}

func TestVMManifestValidate(t *testing.T) {
	validAttestation := &VMAttestation{
		VMID:          "vm-1",
		HostID:        "host-1",
		QuoteData:     []byte("quote"),
		Signature:     []byte("sig"),
		PCRs:          []PCRValue{{Index: 0, Value: []byte("value")}},
		Nonce:         []byte("nonce"),
		HashAlgorithm: HashAlgorithmSHA256,
	}

	t.Run("Valid", func(t *testing.T) {
		manifest := &VMManifest{
			VMID:        "vm-1",
			HostID:      "host-1",
			Attestation: validAttestation,
			Timestamp:   time.Now(),
		}

		if err := manifest.Validate(); err != nil {
			t.Errorf("expected valid manifest, got error: %v", err)
		}
	})

	t.Run("EmptyVMID", func(t *testing.T) {
		manifest := &VMManifest{
			HostID:      "host-1",
			Attestation: validAttestation,
		}

		err := manifest.Validate()
		if err == nil {
			t.Error("expected error for empty VMID")
		}
	})

	t.Run("EmptyHostID", func(t *testing.T) {
		manifest := &VMManifest{
			VMID:        "vm-1",
			Attestation: validAttestation,
		}

		err := manifest.Validate()
		if err == nil {
			t.Error("expected error for empty HostID")
		}
	})

	t.Run("NilAttestation", func(t *testing.T) {
		manifest := &VMManifest{
			VMID:   "vm-1",
			HostID: "host-1",
		}

		err := manifest.Validate()
		if err == nil {
			t.Error("expected error for nil attestation")
		}
	})
}

func TestContainerManifestValidate(t *testing.T) {
	validAttestation := &ContainerAttestation{
		ContainerID: "container-1",
		Digest:      []byte("digest"),
		PCRValue:    []byte("pcr"),
	}

	t.Run("Valid", func(t *testing.T) {
		manifest := &ContainerManifest{
			ContainerID: "container-1",
			ImageDigest: "sha256:abc123",
			Attestation: validAttestation,
			Timestamp:   time.Now(),
		}

		if err := manifest.Validate(); err != nil {
			t.Errorf("expected valid manifest, got error: %v", err)
		}
	})

	t.Run("EmptyContainerID", func(t *testing.T) {
		manifest := &ContainerManifest{
			Attestation: validAttestation,
		}

		err := manifest.Validate()
		if err == nil {
			t.Error("expected error for empty ContainerID")
		}
	})

	t.Run("NilAttestation", func(t *testing.T) {
		manifest := &ContainerManifest{
			ContainerID: "container-1",
		}

		err := manifest.Validate()
		if err == nil {
			t.Error("expected error for nil attestation")
		}
	})
}

func TestHostAttestationValidate(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		attestation := &HostAttestation{
			QuoteData:     []byte("quote"),
			Signature:     []byte("sig"),
			PCRs:          []PCRValue{{Index: 0, Value: []byte("value")}},
			Nonce:         []byte("nonce"),
			HashAlgorithm: HashAlgorithmSHA256,
		}

		if err := attestation.Validate(); err != nil {
			t.Errorf("expected valid attestation, got error: %v", err)
		}
	})

	t.Run("EmptyQuoteData", func(t *testing.T) {
		attestation := &HostAttestation{
			Signature:     []byte("sig"),
			PCRs:          []PCRValue{{Index: 0, Value: []byte("value")}},
			Nonce:         []byte("nonce"),
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := attestation.Validate()
		if err == nil {
			t.Error("expected error for empty quote data")
		}
	})

	t.Run("EmptySignature", func(t *testing.T) {
		attestation := &HostAttestation{
			QuoteData:     []byte("quote"),
			PCRs:          []PCRValue{{Index: 0, Value: []byte("value")}},
			Nonce:         []byte("nonce"),
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := attestation.Validate()
		if err == nil {
			t.Error("expected error for empty signature")
		}
	})

	t.Run("EmptyPCRs", func(t *testing.T) {
		attestation := &HostAttestation{
			QuoteData:     []byte("quote"),
			Signature:     []byte("sig"),
			Nonce:         []byte("nonce"),
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := attestation.Validate()
		if err == nil {
			t.Error("expected error for empty PCRs")
		}
	})

	t.Run("EmptyNonce", func(t *testing.T) {
		attestation := &HostAttestation{
			QuoteData:     []byte("quote"),
			Signature:     []byte("sig"),
			PCRs:          []PCRValue{{Index: 0, Value: []byte("value")}},
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := attestation.Validate()
		if err == nil {
			t.Error("expected error for empty nonce")
		}
	})

	t.Run("InvalidHashAlgorithm", func(t *testing.T) {
		attestation := &HostAttestation{
			QuoteData:     []byte("quote"),
			Signature:     []byte("sig"),
			PCRs:          []PCRValue{{Index: 0, Value: []byte("value")}},
			Nonce:         []byte("nonce"),
			HashAlgorithm: "invalid",
		}

		err := attestation.Validate()
		if err == nil {
			t.Error("expected error for invalid hash algorithm")
		}
	})
}

func TestVMAttestationValidate(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		attestation := &VMAttestation{
			VMID:          "vm-1",
			HostID:        "host-1",
			QuoteData:     []byte("quote"),
			Signature:     []byte("sig"),
			PCRs:          []PCRValue{{Index: 0, Value: []byte("value")}},
			Nonce:         []byte("nonce"),
			HashAlgorithm: HashAlgorithmSHA256,
		}

		if err := attestation.Validate(); err != nil {
			t.Errorf("expected valid attestation, got error: %v", err)
		}
	})

	t.Run("EmptyVMID", func(t *testing.T) {
		attestation := &VMAttestation{
			HostID:        "host-1",
			QuoteData:     []byte("quote"),
			Signature:     []byte("sig"),
			PCRs:          []PCRValue{{Index: 0, Value: []byte("value")}},
			Nonce:         []byte("nonce"),
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := attestation.Validate()
		if err == nil {
			t.Error("expected error for empty VMID")
		}
	})

	t.Run("EmptyHostID", func(t *testing.T) {
		attestation := &VMAttestation{
			VMID:          "vm-1",
			QuoteData:     []byte("quote"),
			Signature:     []byte("sig"),
			PCRs:          []PCRValue{{Index: 0, Value: []byte("value")}},
			Nonce:         []byte("nonce"),
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := attestation.Validate()
		if err == nil {
			t.Error("expected error for empty HostID")
		}
	})
}

func TestContainerAttestationValidate(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		attestation := &ContainerAttestation{
			ContainerID: "container-1",
			Digest:      []byte("digest"),
			PCRValue:    []byte("pcr"),
		}

		if err := attestation.Validate(); err != nil {
			t.Errorf("expected valid attestation, got error: %v", err)
		}
	})

	t.Run("EmptyContainerID", func(t *testing.T) {
		attestation := &ContainerAttestation{
			Digest:   []byte("digest"),
			PCRValue: []byte("pcr"),
		}

		err := attestation.Validate()
		if err == nil {
			t.Error("expected error for empty ContainerID")
		}
	})

	t.Run("EmptyDigest", func(t *testing.T) {
		attestation := &ContainerAttestation{
			ContainerID: "container-1",
			PCRValue:    []byte("pcr"),
		}

		err := attestation.Validate()
		if err == nil {
			t.Error("expected error for empty Digest")
		}
	})

	t.Run("EmptyPCRValue", func(t *testing.T) {
		attestation := &ContainerAttestation{
			ContainerID: "container-1",
			Digest:      []byte("digest"),
		}

		err := attestation.Validate()
		if err == nil {
			t.Error("expected error for empty PCRValue")
		}
	})
}

func TestManifestConfigValidate(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		config := &ManifestConfig{
			TPMDevicePath:        "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
			NonceSize:            32,
		}

		if err := config.Validate(); err != nil {
			t.Errorf("expected valid config, got error: %v", err)
		}
	})

	t.Run("EmptyTPMDevicePath", func(t *testing.T) {
		config := &ManifestConfig{
			DefaultHashAlgorithm: HashAlgorithmSHA256,
			NonceSize:            32,
		}

		err := config.Validate()
		if err == nil {
			t.Error("expected error for empty TPM device path")
		}
	})

	t.Run("InvalidHashAlgorithm", func(t *testing.T) {
		config := &ManifestConfig{
			TPMDevicePath:        "/dev/tpm0",
			DefaultHashAlgorithm: "invalid",
			NonceSize:            32,
		}

		err := config.Validate()
		if err == nil {
			t.Error("expected error for invalid hash algorithm")
		}
	})

	t.Run("NegativeMaxAge", func(t *testing.T) {
		config := &ManifestConfig{
			TPMDevicePath:        "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
			MaxManifestAge:       -1,
			NonceSize:            32,
		}

		err := config.Validate()
		if err == nil {
			t.Error("expected error for negative max age")
		}
	})

	t.Run("SmallNonceSize", func(t *testing.T) {
		config := &ManifestConfig{
			TPMDevicePath:        "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
			NonceSize:            8,
		}

		err := config.Validate()
		if err == nil {
			t.Error("expected error for small nonce size")
		}
	})
}

func TestDefaultManifestConfig(t *testing.T) {
	config := DefaultManifestConfig()

	if config.DefaultHashAlgorithm != HashAlgorithmSHA256 {
		t.Errorf("expected SHA256, got %v", config.DefaultHashAlgorithm)
	}

	if config.MaxManifestAge != 300 {
		t.Errorf("expected 300, got %d", config.MaxManifestAge)
	}

	if config.NonceSize != 32 {
		t.Errorf("expected 32, got %d", config.NonceSize)
	}

	if !config.IncludeWorkloadPCR {
		t.Error("expected IncludeWorkloadPCR to be true")
	}

	if config.Version != "1.0" {
		t.Errorf("expected 1.0, got %s", config.Version)
	}
}

func TestBuilderConfigValidate(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}

		if err := config.Validate(); err != nil {
			t.Errorf("expected valid config, got error: %v", err)
		}
	})

	t.Run("EmptyHostID", func(t *testing.T) {
		config := &BuilderConfig{
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}

		err := config.Validate()
		if err == nil {
			t.Error("expected error for empty HostID")
		}
	})

	t.Run("InvalidHashAlgorithm", func(t *testing.T) {
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: "invalid",
			NonceSize:     32,
		}

		err := config.Validate()
		if err == nil {
			t.Error("expected error for invalid hash algorithm")
		}
	})

	t.Run("SmallNonceSize", func(t *testing.T) {
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     8,
		}

		err := config.Validate()
		if err == nil {
			t.Error("expected error for small nonce size")
		}
	})
}

func TestSignerConfigValidate(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: HashAlgorithmSHA256,
		}

		if err := config.Validate(); err != nil {
			t.Errorf("expected valid config, got error: %v", err)
		}
	})

	t.Run("EmptyTPMDevicePath", func(t *testing.T) {
		config := &SignerConfig{
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := config.Validate()
		if err == nil {
			t.Error("expected error for empty TPM device path")
		}
	})

	t.Run("InvalidHashAlgorithm", func(t *testing.T) {
		config := &SignerConfig{
			TPMDevicePath: "/dev/tpm0",
			HashAlgorithm: "invalid",
		}

		err := config.Validate()
		if err == nil {
			t.Error("expected error for invalid hash algorithm")
		}
	})
}

func TestVerifierConfigValidate(t *testing.T) {
	// Create a test certificate
	caCert := &x509.Certificate{}

	t.Run("Valid", func(t *testing.T) {
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  HashAlgorithmSHA256,
		}

		if err := config.Validate(); err != nil {
			t.Errorf("expected valid config, got error: %v", err)
		}
	})

	t.Run("NilPlatformCACert", func(t *testing.T) {
		config := &VerifierConfig{
			HashAlgorithm: HashAlgorithmSHA256,
		}

		err := config.Validate()
		if err == nil {
			t.Error("expected error for nil Platform CA cert")
		}
	})

	t.Run("NegativeMaxAge", func(t *testing.T) {
		config := &VerifierConfig{
			PlatformCACert: caCert,
			MaxManifestAge: -1,
			HashAlgorithm:  HashAlgorithmSHA256,
		}

		err := config.Validate()
		if err == nil {
			t.Error("expected error for negative max age")
		}
	})

	t.Run("InvalidHashAlgorithm", func(t *testing.T) {
		config := &VerifierConfig{
			PlatformCACert: caCert,
			HashAlgorithm:  "invalid",
		}

		err := config.Validate()
		if err == nil {
			t.Error("expected error for invalid hash algorithm")
		}
	})
}

func TestVerificationResult(t *testing.T) {
	t.Run("AddError", func(t *testing.T) {
		result := &VerificationResult{}
		result.AddError("error 1")
		result.AddError("error 2")

		if len(result.Errors) != 2 {
			t.Errorf("expected 2 errors, got %d", len(result.Errors))
		}
	})

	t.Run("HasErrors", func(t *testing.T) {
		result := &VerificationResult{}
		if result.HasErrors() {
			t.Error("expected no errors initially")
		}

		result.AddError("error")
		if !result.HasErrors() {
			t.Error("expected HasErrors to return true")
		}
	})
}
