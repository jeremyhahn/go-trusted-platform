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
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"log/slog"
	"sync/atomic"
	"time"
)

// ManifestBuilder provides capabilities for building host manifests.
type ManifestBuilder interface {
	// Initialize sets up the builder with the given configuration.
	Initialize(ctx context.Context, config *BuilderConfig) error

	// SetHostAttestation sets the host attestation for the manifest.
	SetHostAttestation(ctx context.Context, attestation *HostAttestation) error

	// AddVMAttestation adds a VM attestation to the manifest.
	AddVMAttestation(ctx context.Context, attestation *VMAttestation) error

	// AddContainerAttestation adds a container attestation to the manifest.
	AddContainerAttestation(ctx context.Context, attestation *ContainerAttestation) error

	// Build constructs the manifest with all collected attestations.
	Build(ctx context.Context) (*HostManifest, error)

	// BuildWithNonce constructs the manifest using a provided nonce.
	BuildWithNonce(ctx context.Context, nonce []byte) (*HostManifest, error)

	// Reset clears all collected attestations for a fresh build.
	Reset()

	// GetVMCount returns the number of VM attestations added.
	GetVMCount() int

	// GetContainerCount returns the number of container attestations added.
	GetContainerCount() int

	// Close releases resources held by the builder.
	Close() error
}

// TPMDevice provides TPM operations for attestation.
type TPMDevice interface {
	// GenerateQuote generates a TPM quote signed by the AK.
	GenerateQuote(ctx context.Context, nonce []byte, pcrIndices []int, algorithm HashAlgorithm) (
		quoteData []byte, signature []byte, err error)

	// ReadPCR reads the current value of the specified PCR.
	ReadPCR(ctx context.Context, pcr int, algorithm HashAlgorithm) ([]byte, error)

	// GetAKPublicKey returns the public key of the AK.
	GetAKPublicKey(ctx context.Context) ([]byte, error)

	// Sign signs data using the AK.
	Sign(ctx context.Context, data []byte, algorithm HashAlgorithm) ([]byte, error)

	// Close releases TPM resources.
	Close() error
}

// manifestBuilder is the concrete implementation of ManifestBuilder.
type manifestBuilder struct {
	initialized atomic.Bool
	closed      atomic.Bool
	config      *BuilderConfig
	tpm         TPMDevice
	logger      *slog.Logger

	hostAttestation *HostAttestation
	vmAttestations  []VMAttestation
	containerAtts   []ContainerAttestation
}

// ManifestBuilderOption configures a manifest builder.
type ManifestBuilderOption func(*manifestBuilder)

// WithTPMDevice sets the TPM device for the builder.
func WithTPMDevice(tpm TPMDevice) ManifestBuilderOption {
	return func(b *manifestBuilder) {
		b.tpm = tpm
	}
}

// WithBuilderLogger sets the logger for the builder.
func WithBuilderLogger(logger *slog.Logger) ManifestBuilderOption {
	return func(b *manifestBuilder) {
		b.logger = logger
	}
}

// NewManifestBuilder creates a new manifest builder with the given options.
func NewManifestBuilder(opts ...ManifestBuilderOption) ManifestBuilder {
	b := &manifestBuilder{
		vmAttestations: make([]VMAttestation, 0),
		containerAtts:  make([]ContainerAttestation, 0),
	}

	for _, opt := range opts {
		opt(b)
	}

	if b.logger == nil {
		b.logger = slog.Default()
	}

	return b
}

// Initialize sets up the builder with the given configuration.
func (b *manifestBuilder) Initialize(ctx context.Context, config *BuilderConfig) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "Initialize"}
	default:
	}

	if b.initialized.Load() {
		return ErrInvalidConfig{Reason: "builder already initialized"}
	}

	if config == nil {
		return ErrInvalidConfig{Reason: "configuration cannot be nil"}
	}

	if err := config.Validate(); err != nil {
		return err
	}

	b.config = config
	b.initialized.Store(true)

	b.logger.Info("manifest builder initialized",
		"host_id", config.HostID,
		"hash_algorithm", config.HashAlgorithm,
		"nonce_size", config.NonceSize,
	)

	return nil
}

// SetHostAttestation sets the host attestation for the manifest.
func (b *manifestBuilder) SetHostAttestation(ctx context.Context, attestation *HostAttestation) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "SetHostAttestation"}
	default:
	}

	if !b.initialized.Load() {
		return ErrBuilderNotInitialized{}
	}

	if b.closed.Load() {
		return ErrBuilderNotInitialized{}
	}

	if attestation == nil {
		return ErrInvalidManifest{Field: "HostAttestation", Reason: "attestation cannot be nil"}
	}

	if err := attestation.Validate(); err != nil {
		return err
	}

	b.hostAttestation = attestation

	b.logger.Debug("host attestation set",
		"pcr_count", len(attestation.PCRs),
		"hash_algorithm", attestation.HashAlgorithm,
	)

	return nil
}

// AddVMAttestation adds a VM attestation to the manifest.
func (b *manifestBuilder) AddVMAttestation(ctx context.Context, attestation *VMAttestation) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "AddVMAttestation"}
	default:
	}

	if !b.initialized.Load() {
		return ErrBuilderNotInitialized{}
	}

	if b.closed.Load() {
		return ErrBuilderNotInitialized{}
	}

	if attestation == nil {
		return ErrInvalidManifest{Field: "VMAttestation", Reason: "attestation cannot be nil"}
	}

	if err := attestation.Validate(); err != nil {
		return err
	}

	b.vmAttestations = append(b.vmAttestations, *attestation)

	b.logger.Debug("VM attestation added",
		"vm_id", attestation.VMID,
		"host_id", attestation.HostID,
		"vm_count", len(b.vmAttestations),
	)

	return nil
}

// AddContainerAttestation adds a container attestation to the manifest.
func (b *manifestBuilder) AddContainerAttestation(ctx context.Context, attestation *ContainerAttestation) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "AddContainerAttestation"}
	default:
	}

	if !b.initialized.Load() {
		return ErrBuilderNotInitialized{}
	}

	if b.closed.Load() {
		return ErrBuilderNotInitialized{}
	}

	if attestation == nil {
		return ErrInvalidManifest{Field: "ContainerAttestation", Reason: "attestation cannot be nil"}
	}

	if err := attestation.Validate(); err != nil {
		return err
	}

	b.containerAtts = append(b.containerAtts, *attestation)

	b.logger.Debug("container attestation added",
		"container_id", attestation.ContainerID,
		"image_digest", attestation.ImageDigest,
		"container_count", len(b.containerAtts),
	)

	return nil
}

// Build constructs the manifest with all collected attestations.
func (b *manifestBuilder) Build(ctx context.Context) (*HostManifest, error) {
	// Check initialization before accessing config
	if !b.initialized.Load() {
		return nil, ErrBuilderNotInitialized{}
	}

	if b.closed.Load() {
		return nil, ErrBuilderNotInitialized{}
	}

	// Generate a fresh nonce
	nonce := make([]byte, b.config.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrManifestBuildFailed{Reason: "failed to generate nonce", Cause: err}
	}

	return b.BuildWithNonce(ctx, nonce)
}

// BuildWithNonce constructs the manifest using a provided nonce.
func (b *manifestBuilder) BuildWithNonce(ctx context.Context, nonce []byte) (*HostManifest, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "Build"}
	default:
	}

	if !b.initialized.Load() {
		return nil, ErrBuilderNotInitialized{}
	}

	if b.closed.Load() {
		return nil, ErrBuilderNotInitialized{}
	}

	if b.hostAttestation == nil {
		return nil, ErrHostNotAttested{}
	}

	if len(nonce) < 16 {
		return nil, ErrInvalidManifest{Field: "Nonce", Reason: "nonce must be at least 16 bytes"}
	}

	// Build Merkle tree from all attestation data
	merkleRoot, err := b.buildMerkleTree()
	if err != nil {
		return nil, err
	}

	// Generate manifest ID
	manifestID := b.generateManifestID(nonce)

	manifest := &HostManifest{
		ID:         manifestID,
		HostID:     b.config.HostID,
		Timestamp:  time.Now().UTC(),
		Nonce:      nonce,
		Host:       b.hostAttestation,
		VMs:        b.vmAttestations,
		Containers: b.containerAtts,
		MerkleRoot: merkleRoot,
		Version:    b.config.Version,
		Metadata:   make(map[string]string),
	}

	b.logger.Info("manifest built",
		"manifest_id", manifestID,
		"host_id", b.config.HostID,
		"vm_count", len(b.vmAttestations),
		"container_count", len(b.containerAtts),
		"merkle_root", hex.EncodeToString(merkleRoot),
	)

	return manifest, nil
}

// Reset clears all collected attestations for a fresh build.
func (b *manifestBuilder) Reset() {
	b.hostAttestation = nil
	b.vmAttestations = make([]VMAttestation, 0)
	b.containerAtts = make([]ContainerAttestation, 0)

	b.logger.Debug("builder reset")
}

// GetVMCount returns the number of VM attestations added.
func (b *manifestBuilder) GetVMCount() int {
	return len(b.vmAttestations)
}

// GetContainerCount returns the number of container attestations added.
func (b *manifestBuilder) GetContainerCount() int {
	return len(b.containerAtts)
}

// Close releases resources held by the builder.
func (b *manifestBuilder) Close() error {
	if b.closed.Swap(true) {
		return nil
	}

	if b.tpm != nil {
		if err := b.tpm.Close(); err != nil {
			b.logger.Warn("failed to close TPM device", "error", err)
		}
	}

	b.logger.Info("manifest builder closed")
	return nil
}

// buildMerkleTree constructs a Merkle tree from all attestation data.
func (b *manifestBuilder) buildMerkleTree() ([]byte, error) {
	var leaves [][]byte

	// Add host attestation to leaves
	if b.hostAttestation != nil {
		hostHash := b.hashAttestation(b.hostAttestation.QuoteData, b.hostAttestation.PCRDigest)
		leaves = append(leaves, hostHash)
	}

	// Add VM attestations to leaves
	for _, vm := range b.vmAttestations {
		vmHash := b.hashAttestation(vm.QuoteData, vm.PCRDigest)
		leaves = append(leaves, vmHash)
	}

	// Add container attestations to leaves
	for _, container := range b.containerAtts {
		containerHash := b.hashAttestation(container.Digest, container.PCRValue)
		leaves = append(leaves, containerHash)
	}

	if len(leaves) == 0 {
		return nil, ErrEmptyManifest{}
	}

	// Build Merkle tree and return root
	root := b.computeMerkleRoot(leaves)
	return root, nil
}

// hashAttestation creates a hash of attestation data.
func (b *manifestBuilder) hashAttestation(data1, data2 []byte) []byte {
	hasher := b.getHasher()
	hasher.Write(data1)
	hasher.Write(data2)
	return hasher.Sum(nil)
}

// computeMerkleRoot computes the Merkle root from leaf hashes.
func (b *manifestBuilder) computeMerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}

	if len(leaves) == 1 {
		return leaves[0]
	}

	// Pad to even number of leaves
	if len(leaves)%2 != 0 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}

	// Compute next level
	var nextLevel [][]byte
	for i := 0; i < len(leaves); i += 2 {
		hasher := b.getHasher()
		hasher.Write(leaves[i])
		hasher.Write(leaves[i+1])
		nextLevel = append(nextLevel, hasher.Sum(nil))
	}

	return b.computeMerkleRoot(nextLevel)
}

// getHasher returns a hash function based on the configured algorithm.
func (b *manifestBuilder) getHasher() hash.Hash {
	switch b.config.HashAlgorithm {
	case HashAlgorithmSHA384:
		return sha512.New384()
	case HashAlgorithmSHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

// generateManifestID generates a unique manifest ID.
func (b *manifestBuilder) generateManifestID(nonce []byte) string {
	data := append([]byte(b.config.HostID), nonce...)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	data = append(data, []byte(timestamp)...)

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:16])
}

// ComputeMerkleRoot computes a Merkle root from the given leaves.
// This is exported for use in verification.
func ComputeMerkleRoot(leaves [][]byte, algorithm HashAlgorithm) []byte {
	if len(leaves) == 0 {
		return nil
	}

	if len(leaves) == 1 {
		return leaves[0]
	}

	// Pad to even number of leaves
	if len(leaves)%2 != 0 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}

	getHasher := func() hash.Hash {
		switch algorithm {
		case HashAlgorithmSHA384:
			return sha512.New384()
		case HashAlgorithmSHA512:
			return sha512.New()
		default:
			return sha256.New()
		}
	}

	// Compute next level
	var nextLevel [][]byte
	for i := 0; i < len(leaves); i += 2 {
		hasher := getHasher()
		hasher.Write(leaves[i])
		hasher.Write(leaves[i+1])
		nextLevel = append(nextLevel, hasher.Sum(nil))
	}

	return ComputeMerkleRoot(nextLevel, algorithm)
}

// HashAttestation creates a hash of attestation data.
// This is exported for use in verification.
func HashAttestation(data1, data2 []byte, algorithm HashAlgorithm) []byte {
	var hasher hash.Hash
	switch algorithm {
	case HashAlgorithmSHA384:
		hasher = sha512.New384()
	case HashAlgorithmSHA512:
		hasher = sha512.New()
	default:
		hasher = sha256.New()
	}
	hasher.Write(data1)
	hasher.Write(data2)
	return hasher.Sum(nil)
}
