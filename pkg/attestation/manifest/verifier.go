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
	"crypto/rsa"
	"crypto/x509"
	"log/slog"
	"sync/atomic"
	"time"
)

// ManifestVerifier provides capabilities for verifying host manifests.
type ManifestVerifier interface {
	// Initialize sets up the verifier with the given configuration.
	Initialize(ctx context.Context, config *VerifierConfig) error

	// Verify verifies a manifest including signature and Merkle root.
	Verify(ctx context.Context, manifest *HostManifest, publicKey crypto.PublicKey, expectedNonce []byte) (*VerificationResult, error)

	// VerifySignature verifies only the manifest signature.
	VerifySignature(ctx context.Context, manifest *HostManifest, publicKey crypto.PublicKey) (bool, error)

	// VerifyMerkleRoot verifies the Merkle root integrity.
	VerifyMerkleRoot(ctx context.Context, manifest *HostManifest) (bool, error)

	// VerifyNonce verifies the nonce matches the expected value.
	VerifyNonce(manifest *HostManifest, expectedNonce []byte) bool

	// VerifyFreshness verifies the manifest has not expired.
	VerifyFreshness(manifest *HostManifest) (bool, error)

	// VerifyHostAttestation verifies the host attestation.
	VerifyHostAttestation(ctx context.Context, manifest *HostManifest, expectedPCRs map[int][]byte) (bool, error)

	// VerifyVMAttestations verifies all VM attestations.
	VerifyVMAttestations(ctx context.Context, manifest *HostManifest) (bool, map[string]string)

	// VerifyContainerAttestations verifies all container attestations.
	VerifyContainerAttestations(ctx context.Context, manifest *HostManifest) (bool, map[string]string)

	// Close releases resources held by the verifier.
	Close() error
}

// manifestVerifier is the concrete implementation of ManifestVerifier.
type manifestVerifier struct {
	initialized atomic.Bool
	closed      atomic.Bool
	config      *VerifierConfig
	certPool    *x509.CertPool
	logger      *slog.Logger
}

// ManifestVerifierOption configures a manifest verifier.
type ManifestVerifierOption func(*manifestVerifier)

// WithVerifierLogger sets the logger for the verifier.
func WithVerifierLogger(logger *slog.Logger) ManifestVerifierOption {
	return func(v *manifestVerifier) {
		v.logger = logger
	}
}

// NewManifestVerifier creates a new manifest verifier with the given options.
func NewManifestVerifier(opts ...ManifestVerifierOption) ManifestVerifier {
	v := &manifestVerifier{}

	for _, opt := range opts {
		opt(v)
	}

	if v.logger == nil {
		v.logger = slog.Default()
	}

	return v
}

// Initialize sets up the verifier with the given configuration.
func (v *manifestVerifier) Initialize(ctx context.Context, config *VerifierConfig) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "Initialize"}
	default:
	}

	if v.initialized.Load() {
		return ErrInvalidConfig{Reason: "verifier already initialized"}
	}

	if config == nil {
		return ErrInvalidConfig{Reason: "configuration cannot be nil"}
	}

	if err := config.Validate(); err != nil {
		return err
	}

	// Build certificate pool for chain validation
	certPool := x509.NewCertPool()
	certPool.AddCert(config.PlatformCACert)
	for _, cert := range config.TrustedRoots {
		certPool.AddCert(cert)
	}

	v.config = config
	v.certPool = certPool
	v.initialized.Store(true)

	v.logger.Info("manifest verifier initialized",
		"max_manifest_age", config.MaxManifestAge,
		"require_host_attestation", config.RequireHostAttestation,
		"verify_merkle_root", config.VerifyMerkleRoot,
	)

	return nil
}

// Verify verifies a manifest including signature and Merkle root.
func (v *manifestVerifier) Verify(ctx context.Context, manifest *HostManifest, publicKey crypto.PublicKey, expectedNonce []byte) (*VerificationResult, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "Verify"}
	default:
	}

	if !v.initialized.Load() {
		return nil, ErrVerifierNotInitialized{}
	}

	if v.closed.Load() {
		return nil, ErrVerifierNotInitialized{}
	}

	if manifest == nil {
		return nil, ErrInvalidManifest{Reason: "manifest cannot be nil"}
	}

	result := &VerificationResult{
		Status:          VerificationStatusPending,
		VerifiedAt:      time.Now().UTC(),
		VMErrors:        make(map[string]string),
		ContainerErrors: make(map[string]string),
	}

	// Verify signature
	sigValid, sigErr := v.VerifySignature(ctx, manifest, publicKey)
	result.SignatureValid = sigValid
	if !sigValid && sigErr != nil {
		result.AddError("signature verification failed: " + sigErr.Error())
	}

	// Verify Merkle root
	if v.config.VerifyMerkleRoot {
		merkleValid, merkleErr := v.VerifyMerkleRoot(ctx, manifest)
		result.MerkleRootValid = merkleValid
		if !merkleValid && merkleErr != nil {
			result.AddError("Merkle root verification failed: " + merkleErr.Error())
		}
	} else {
		result.MerkleRootValid = true
	}

	// Verify nonce
	result.NonceValid = v.VerifyNonce(manifest, expectedNonce)
	if !result.NonceValid {
		result.AddError("nonce mismatch")
	}

	// Verify freshness
	if v.config.MaxManifestAge > 0 {
		freshValid, freshErr := v.VerifyFreshness(manifest)
		result.TimestampValid = freshValid
		if !freshValid && freshErr != nil {
			result.AddError("freshness verification failed: " + freshErr.Error())
		}
	} else {
		result.TimestampValid = true
	}

	// Verify host attestation
	if v.config.RequireHostAttestation {
		hostValid, hostErr := v.VerifyHostAttestation(ctx, manifest, nil)
		result.HostAttestationValid = hostValid
		if !hostValid && hostErr != nil {
			result.AddError("host attestation verification failed: " + hostErr.Error())
		}
	} else {
		result.HostAttestationValid = true
	}

	// Verify VM attestations
	vmValid, vmErrors := v.VerifyVMAttestations(ctx, manifest)
	result.VMAttestationsValid = vmValid
	result.VMErrors = vmErrors
	if !vmValid {
		for vmID, vmErr := range vmErrors {
			result.AddError("VM " + vmID + ": " + vmErr)
		}
	}

	// Verify container attestations
	containerValid, containerErrors := v.VerifyContainerAttestations(ctx, manifest)
	result.ContainerAttestationsValid = containerValid
	result.ContainerErrors = containerErrors
	if !containerValid {
		for containerID, containerErr := range containerErrors {
			result.AddError("Container " + containerID + ": " + containerErr)
		}
	}

	// Determine overall status
	if result.SignatureValid && result.MerkleRootValid && result.NonceValid &&
		result.TimestampValid && result.HostAttestationValid &&
		result.VMAttestationsValid && result.ContainerAttestationsValid {
		result.Status = VerificationStatusVerified
	} else {
		result.Status = VerificationStatusFailed
	}

	v.logger.Info("manifest verified",
		"manifest_id", manifest.ID,
		"status", result.Status,
		"signature_valid", result.SignatureValid,
		"merkle_root_valid", result.MerkleRootValid,
		"nonce_valid", result.NonceValid,
		"timestamp_valid", result.TimestampValid,
		"host_attestation_valid", result.HostAttestationValid,
		"vm_attestations_valid", result.VMAttestationsValid,
		"container_attestations_valid", result.ContainerAttestationsValid,
	)

	return result, nil
}

// VerifySignature verifies only the manifest signature.
func (v *manifestVerifier) VerifySignature(ctx context.Context, manifest *HostManifest, publicKey crypto.PublicKey) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ErrContextCanceled{Operation: "VerifySignature"}
	default:
	}

	if manifest == nil {
		return false, ErrInvalidManifest{Reason: "manifest cannot be nil"}
	}

	if publicKey == nil {
		return false, ErrSignatureInvalid{Reason: "public key cannot be nil"}
	}

	if len(manifest.Signature) == 0 {
		return false, ErrSignatureInvalid{Reason: "manifest has no signature"}
	}

	// Compute the manifest digest
	digest, err := ComputeManifestDigest(manifest, v.config.HashAlgorithm)
	if err != nil {
		return false, err
	}

	// Get crypto hash
	cryptoHash := v.getCryptoHash()

	// Verify based on key type
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(key, cryptoHash, digest, manifest.Signature)
		if err != nil {
			return false, ErrSignatureInvalid{Reason: "RSA signature verification failed", Cause: err}
		}
		return true, nil
	default:
		return false, ErrSignatureInvalid{Reason: "unsupported key type"}
	}
}

// VerifyMerkleRoot verifies the Merkle root integrity.
func (v *manifestVerifier) VerifyMerkleRoot(ctx context.Context, manifest *HostManifest) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ErrContextCanceled{Operation: "VerifyMerkleRoot"}
	default:
	}

	if manifest == nil {
		return false, ErrInvalidManifest{Reason: "manifest cannot be nil"}
	}

	if len(manifest.MerkleRoot) == 0 {
		return false, ErrInvalidManifest{Field: "MerkleRoot", Reason: "Merkle root is empty"}
	}

	// Recompute the Merkle root
	computed, err := RecomputeMerkleRoot(manifest, v.config.HashAlgorithm)
	if err != nil {
		return false, err
	}

	if !bytes.Equal(computed, manifest.MerkleRoot) {
		return false, ErrMerkleRootMismatch{
			Expected: manifest.MerkleRoot,
			Actual:   computed,
		}
	}

	return true, nil
}

// VerifyNonce verifies the nonce matches the expected value.
func (v *manifestVerifier) VerifyNonce(manifest *HostManifest, expectedNonce []byte) bool {
	if manifest == nil || len(expectedNonce) == 0 {
		return false
	}
	return bytes.Equal(manifest.Nonce, expectedNonce)
}

// VerifyFreshness verifies the manifest has not expired.
func (v *manifestVerifier) VerifyFreshness(manifest *HostManifest) (bool, error) {
	if manifest == nil {
		return false, ErrInvalidManifest{Reason: "manifest cannot be nil"}
	}

	if manifest.Timestamp.IsZero() {
		return false, ErrInvalidManifest{Field: "Timestamp", Reason: "timestamp is zero"}
	}

	age := time.Since(manifest.Timestamp).Seconds()
	if int64(age) > v.config.MaxManifestAge {
		return false, ErrManifestExpired{
			Age:    int64(age),
			MaxAge: v.config.MaxManifestAge,
		}
	}

	return true, nil
}

// VerifyHostAttestation verifies the host attestation.
func (v *manifestVerifier) VerifyHostAttestation(ctx context.Context, manifest *HostManifest, expectedPCRs map[int][]byte) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ErrContextCanceled{Operation: "VerifyHostAttestation"}
	default:
	}

	if manifest == nil {
		return false, ErrInvalidManifest{Reason: "manifest cannot be nil"}
	}

	if manifest.Host == nil {
		return false, ErrHostNotAttested{}
	}

	if err := manifest.Host.Validate(); err != nil {
		return false, err
	}

	// Verify PCRs if expected values provided
	if expectedPCRs != nil {
		for _, pcr := range manifest.Host.PCRs {
			expected, ok := expectedPCRs[pcr.Index]
			if !ok {
				continue
			}
			if !bytes.Equal(pcr.Value, expected) {
				return false, ErrManifestVerifyFailed{
					Reason: "PCR mismatch for host attestation",
				}
			}
		}
	}

	return true, nil
}

// VerifyVMAttestations verifies all VM attestations.
func (v *manifestVerifier) VerifyVMAttestations(ctx context.Context, manifest *HostManifest) (bool, map[string]string) {
	errors := make(map[string]string)

	if manifest == nil {
		return false, errors
	}

	for _, vm := range manifest.VMs {
		if err := vm.Validate(); err != nil {
			errors[vm.VMID] = err.Error()
		}
	}

	return len(errors) == 0, errors
}

// VerifyContainerAttestations verifies all container attestations.
func (v *manifestVerifier) VerifyContainerAttestations(ctx context.Context, manifest *HostManifest) (bool, map[string]string) {
	errors := make(map[string]string)

	if manifest == nil {
		return false, errors
	}

	for _, container := range manifest.Containers {
		if err := container.Validate(); err != nil {
			errors[container.ContainerID] = err.Error()
		}
	}

	return len(errors) == 0, errors
}

// Close releases resources held by the verifier.
func (v *manifestVerifier) Close() error {
	if v.closed.Swap(true) {
		return nil
	}

	v.logger.Info("manifest verifier closed")
	return nil
}

// getCryptoHash returns the crypto.Hash for the configured algorithm.
func (v *manifestVerifier) getCryptoHash() crypto.Hash {
	switch v.config.HashAlgorithm {
	case HashAlgorithmSHA384:
		return crypto.SHA384
	case HashAlgorithmSHA512:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// QuickVerify performs a basic verification of a manifest without full initialization.
// This is useful for quick checks before a full verification.
func QuickVerify(manifest *HostManifest, publicKey crypto.PublicKey, expectedNonce []byte, algorithm HashAlgorithm) (bool, error) {
	if manifest == nil {
		return false, ErrInvalidManifest{Reason: "manifest cannot be nil"}
	}

	// Validate basic structure
	if err := manifest.Validate(); err != nil {
		return false, err
	}

	// Verify nonce
	if !bytes.Equal(manifest.Nonce, expectedNonce) {
		return false, ErrNonceMismatch{
			Expected: expectedNonce,
			Actual:   manifest.Nonce,
		}
	}

	// Verify Merkle root
	valid, err := ValidateMerkleRoot(manifest, algorithm)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, ErrMerkleRootMismatch{}
	}

	// Verify signature
	sigValid, err := VerifyManifestSignature(manifest, publicKey, algorithm)
	if err != nil {
		return false, err
	}

	return sigValid, nil
}

// ExtractPublicKeyFromManifest extracts the AK public key from the host attestation.
func ExtractPublicKeyFromManifest(manifest *HostManifest) (crypto.PublicKey, error) {
	if manifest == nil {
		return nil, ErrInvalidManifest{Reason: "manifest cannot be nil"}
	}

	if manifest.Host == nil {
		return nil, ErrHostNotAttested{}
	}

	if len(manifest.Host.AKPublicKey) == 0 {
		return nil, ErrAKNotFound{Reason: "AK public key not in manifest"}
	}

	return ParsePublicKey(manifest.Host.AKPublicKey)
}
