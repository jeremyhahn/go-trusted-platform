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
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"hash"
	"log/slog"
	"sync/atomic"
)

// ManifestSigner provides capabilities for signing host manifests.
type ManifestSigner interface {
	// Initialize sets up the signer with the given configuration.
	Initialize(ctx context.Context, config *SignerConfig) error

	// Sign signs a manifest using the TPM's AK.
	Sign(ctx context.Context, manifest *HostManifest) error

	// SignWithKey signs a manifest using a provided private key (for testing).
	SignWithKey(ctx context.Context, manifest *HostManifest, key crypto.Signer) error

	// VerifySignature verifies a manifest's signature using the provided public key.
	VerifySignature(ctx context.Context, manifest *HostManifest, publicKey crypto.PublicKey) (bool, error)

	// Close releases resources held by the signer.
	Close() error
}

// manifestSigner is the concrete implementation of ManifestSigner.
type manifestSigner struct {
	initialized atomic.Bool
	closed      atomic.Bool
	config      *SignerConfig
	tpm         TPMDevice
	logger      *slog.Logger
}

// ManifestSignerOption configures a manifest signer.
type ManifestSignerOption func(*manifestSigner)

// WithSignerTPMDevice sets the TPM device for the signer.
func WithSignerTPMDevice(tpm TPMDevice) ManifestSignerOption {
	return func(s *manifestSigner) {
		s.tpm = tpm
	}
}

// WithSignerLogger sets the logger for the signer.
func WithSignerLogger(logger *slog.Logger) ManifestSignerOption {
	return func(s *manifestSigner) {
		s.logger = logger
	}
}

// NewManifestSigner creates a new manifest signer with the given options.
func NewManifestSigner(opts ...ManifestSignerOption) ManifestSigner {
	s := &manifestSigner{}

	for _, opt := range opts {
		opt(s)
	}

	if s.logger == nil {
		s.logger = slog.Default()
	}

	return s
}

// Initialize sets up the signer with the given configuration.
func (s *manifestSigner) Initialize(ctx context.Context, config *SignerConfig) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "Initialize"}
	default:
	}

	if s.initialized.Load() {
		return ErrInvalidConfig{Reason: "signer already initialized"}
	}

	if config == nil {
		return ErrInvalidConfig{Reason: "configuration cannot be nil"}
	}

	if err := config.Validate(); err != nil {
		return err
	}

	if s.tpm == nil {
		return ErrTPMNotAvailable{Reason: "TPM device not configured"}
	}

	// Verify TPM is accessible by getting AK public key
	_, err := s.tpm.GetAKPublicKey(ctx)
	if err != nil {
		return ErrAKNotFound{Reason: err.Error()}
	}

	s.config = config
	s.initialized.Store(true)

	s.logger.Info("manifest signer initialized",
		"tpm_device", config.TPMDevicePath,
		"hash_algorithm", config.HashAlgorithm,
	)

	return nil
}

// Sign signs a manifest using the TPM's AK.
func (s *manifestSigner) Sign(ctx context.Context, manifest *HostManifest) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "Sign"}
	default:
	}

	if !s.initialized.Load() {
		return ErrSignerNotInitialized{}
	}

	if s.closed.Load() {
		return ErrSignerNotInitialized{}
	}

	if manifest == nil {
		return ErrInvalidManifest{Reason: "manifest cannot be nil"}
	}

	// Compute the manifest digest
	digest, err := s.computeManifestDigest(manifest)
	if err != nil {
		return err
	}

	// Sign with TPM AK
	signature, err := s.tpm.Sign(ctx, digest, s.config.HashAlgorithm)
	if err != nil {
		return ErrManifestSignFailed{Reason: "TPM signing failed", Cause: err}
	}

	manifest.Signature = signature
	manifest.SignatureAlgorithm = s.getSignatureAlgorithmName()

	s.logger.Info("manifest signed",
		"manifest_id", manifest.ID,
		"signature_algorithm", manifest.SignatureAlgorithm,
	)

	return nil
}

// SignWithKey signs a manifest using a provided private key (for testing).
func (s *manifestSigner) SignWithKey(ctx context.Context, manifest *HostManifest, key crypto.Signer) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "SignWithKey"}
	default:
	}

	if manifest == nil {
		return ErrInvalidManifest{Reason: "manifest cannot be nil"}
	}

	if key == nil {
		return ErrManifestSignFailed{Reason: "signing key cannot be nil"}
	}

	// Compute the manifest digest
	digest, err := s.computeManifestDigestWithAlgorithm(manifest, s.getHashAlgorithm())
	if err != nil {
		return err
	}

	// Sign with provided key
	signature, err := key.Sign(rand.Reader, digest, s.getCryptoHash())
	if err != nil {
		return ErrManifestSignFailed{Reason: "signing failed", Cause: err}
	}

	manifest.Signature = signature
	manifest.SignatureAlgorithm = s.getSignatureAlgorithmName()

	s.logger.Info("manifest signed with key",
		"manifest_id", manifest.ID,
		"signature_algorithm", manifest.SignatureAlgorithm,
	)

	return nil
}

// VerifySignature verifies a manifest's signature using the provided public key.
func (s *manifestSigner) VerifySignature(ctx context.Context, manifest *HostManifest, publicKey crypto.PublicKey) (bool, error) {
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
	digest, err := s.computeManifestDigestWithAlgorithm(manifest, s.getHashAlgorithm())
	if err != nil {
		return false, err
	}

	// Verify based on key type
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(key, s.getCryptoHash(), digest, manifest.Signature)
		if err != nil {
			return false, ErrSignatureInvalid{Reason: "RSA signature verification failed", Cause: err}
		}
		return true, nil
	default:
		return false, ErrSignatureInvalid{Reason: "unsupported key type"}
	}
}

// Close releases resources held by the signer.
func (s *manifestSigner) Close() error {
	if s.closed.Swap(true) {
		return nil
	}

	if s.tpm != nil {
		if err := s.tpm.Close(); err != nil {
			s.logger.Warn("failed to close TPM device", "error", err)
		}
	}

	s.logger.Info("manifest signer closed")
	return nil
}

// computeManifestDigest computes the digest of the manifest for signing.
func (s *manifestSigner) computeManifestDigest(manifest *HostManifest) ([]byte, error) {
	return s.computeManifestDigestWithAlgorithm(manifest, s.config.HashAlgorithm)
}

// computeManifestDigestWithAlgorithm computes the digest using the specified algorithm.
func (s *manifestSigner) computeManifestDigestWithAlgorithm(manifest *HostManifest, algorithm HashAlgorithm) ([]byte, error) {
	hasher := s.getHasherForAlgorithm(algorithm)

	// Hash the core manifest fields
	hasher.Write([]byte(manifest.ID))
	hasher.Write([]byte(manifest.HostID))
	hasher.Write([]byte(manifest.Timestamp.Format("2006-01-02T15:04:05.999999999Z07:00")))
	hasher.Write(manifest.Nonce)
	hasher.Write(manifest.MerkleRoot)

	// Hash host attestation
	if manifest.Host != nil {
		hasher.Write(manifest.Host.QuoteData)
		hasher.Write(manifest.Host.Signature)
		hasher.Write(manifest.Host.PCRDigest)
	}

	// Hash VM attestations
	for _, vm := range manifest.VMs {
		hasher.Write([]byte(vm.VMID))
		hasher.Write(vm.QuoteData)
		hasher.Write(vm.Signature)
		hasher.Write(vm.PCRDigest)
	}

	// Hash container attestations
	for _, container := range manifest.Containers {
		hasher.Write([]byte(container.ContainerID))
		hasher.Write(container.Digest)
		hasher.Write(container.PCRValue)
	}

	return hasher.Sum(nil), nil
}

// getHasherForAlgorithm returns a hash function for the specified algorithm.
func (s *manifestSigner) getHasherForAlgorithm(algorithm HashAlgorithm) hash.Hash {
	switch algorithm {
	case HashAlgorithmSHA384:
		return sha512.New384()
	case HashAlgorithmSHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

// getHashAlgorithm returns the configured hash algorithm or default.
func (s *manifestSigner) getHashAlgorithm() HashAlgorithm {
	if s.config != nil && s.config.HashAlgorithm.IsValid() {
		return s.config.HashAlgorithm
	}
	return HashAlgorithmSHA256
}

// getCryptoHash returns the crypto.Hash for the configured algorithm.
func (s *manifestSigner) getCryptoHash() crypto.Hash {
	switch s.getHashAlgorithm() {
	case HashAlgorithmSHA384:
		return crypto.SHA384
	case HashAlgorithmSHA512:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// getSignatureAlgorithmName returns the signature algorithm name.
func (s *manifestSigner) getSignatureAlgorithmName() string {
	switch s.getHashAlgorithm() {
	case HashAlgorithmSHA384:
		return "RSASSA-PKCS1-v1_5-SHA384"
	case HashAlgorithmSHA512:
		return "RSASSA-PKCS1-v1_5-SHA512"
	default:
		return "RSASSA-PKCS1-v1_5-SHA256"
	}
}

// ParsePublicKey parses a public key from DER or PEM encoded data.
func ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	// Try DER format first
	pubKey, err := x509.ParsePKIXPublicKey(data)
	if err == nil {
		return pubKey, nil
	}

	// Try PEM format
	block, _ := pem.Decode(data)
	if block != nil {
		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			return pubKey, nil
		}
	}

	// Try parsing as RSA public key directly
	rsaPubKey, err := x509.ParsePKCS1PublicKey(data)
	if err == nil {
		return rsaPubKey, nil
	}

	return nil, ErrSignatureInvalid{Reason: "failed to parse public key"}
}

// ComputeManifestDigest computes the digest of a manifest.
// This is exported for verification purposes.
func ComputeManifestDigest(manifest *HostManifest, algorithm HashAlgorithm) ([]byte, error) {
	if manifest == nil {
		return nil, ErrInvalidManifest{Reason: "manifest cannot be nil"}
	}

	var hasher hash.Hash
	switch algorithm {
	case HashAlgorithmSHA384:
		hasher = sha512.New384()
	case HashAlgorithmSHA512:
		hasher = sha512.New()
	default:
		hasher = sha256.New()
	}

	// Hash the core manifest fields
	hasher.Write([]byte(manifest.ID))
	hasher.Write([]byte(manifest.HostID))
	hasher.Write([]byte(manifest.Timestamp.Format("2006-01-02T15:04:05.999999999Z07:00")))
	hasher.Write(manifest.Nonce)
	hasher.Write(manifest.MerkleRoot)

	// Hash host attestation
	if manifest.Host != nil {
		hasher.Write(manifest.Host.QuoteData)
		hasher.Write(manifest.Host.Signature)
		hasher.Write(manifest.Host.PCRDigest)
	}

	// Hash VM attestations
	for _, vm := range manifest.VMs {
		hasher.Write([]byte(vm.VMID))
		hasher.Write(vm.QuoteData)
		hasher.Write(vm.Signature)
		hasher.Write(vm.PCRDigest)
	}

	// Hash container attestations
	for _, container := range manifest.Containers {
		hasher.Write([]byte(container.ContainerID))
		hasher.Write(container.Digest)
		hasher.Write(container.PCRValue)
	}

	return hasher.Sum(nil), nil
}

// VerifyManifestSignature verifies a manifest signature using a public key.
// This is exported as a utility function.
func VerifyManifestSignature(manifest *HostManifest, publicKey crypto.PublicKey, algorithm HashAlgorithm) (bool, error) {
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
	digest, err := ComputeManifestDigest(manifest, algorithm)
	if err != nil {
		return false, err
	}

	// Get crypto hash
	var cryptoHash crypto.Hash
	switch algorithm {
	case HashAlgorithmSHA384:
		cryptoHash = crypto.SHA384
	case HashAlgorithmSHA512:
		cryptoHash = crypto.SHA512
	default:
		cryptoHash = crypto.SHA256
	}

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

// RecomputeMerkleRoot recomputes the Merkle root from a manifest's attestations.
func RecomputeMerkleRoot(manifest *HostManifest, algorithm HashAlgorithm) ([]byte, error) {
	if manifest == nil {
		return nil, ErrInvalidManifest{Reason: "manifest cannot be nil"}
	}

	var leaves [][]byte

	// Add host attestation to leaves
	if manifest.Host != nil {
		hostHash := HashAttestation(manifest.Host.QuoteData, manifest.Host.PCRDigest, algorithm)
		leaves = append(leaves, hostHash)
	}

	// Add VM attestations to leaves
	for _, vm := range manifest.VMs {
		vmHash := HashAttestation(vm.QuoteData, vm.PCRDigest, algorithm)
		leaves = append(leaves, vmHash)
	}

	// Add container attestations to leaves
	for _, container := range manifest.Containers {
		containerHash := HashAttestation(container.Digest, container.PCRValue, algorithm)
		leaves = append(leaves, containerHash)
	}

	if len(leaves) == 0 {
		return nil, ErrEmptyManifest{}
	}

	return ComputeMerkleRoot(leaves, algorithm), nil
}

// ValidateMerkleRoot validates a manifest's Merkle root.
func ValidateMerkleRoot(manifest *HostManifest, algorithm HashAlgorithm) (bool, error) {
	computed, err := RecomputeMerkleRoot(manifest, algorithm)
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
