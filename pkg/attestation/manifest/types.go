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
	"time"
)

// HashAlgorithm represents a cryptographic hash algorithm.
type HashAlgorithm string

// Supported hash algorithms for TPM operations.
const (
	HashAlgorithmSHA1   HashAlgorithm = "sha1"
	HashAlgorithmSHA256 HashAlgorithm = "sha256"
	HashAlgorithmSHA384 HashAlgorithm = "sha384"
	HashAlgorithmSHA512 HashAlgorithm = "sha512"
)

// String returns the string representation of HashAlgorithm.
func (h HashAlgorithm) String() string {
	return string(h)
}

// IsValid returns true if the hash algorithm is supported.
func (h HashAlgorithm) IsValid() bool {
	switch h {
	case HashAlgorithmSHA1, HashAlgorithmSHA256, HashAlgorithmSHA384, HashAlgorithmSHA512:
		return true
	default:
		return false
	}
}

// DigestSize returns the digest size in bytes for the hash algorithm.
func (h HashAlgorithm) DigestSize() int {
	switch h {
	case HashAlgorithmSHA1:
		return 20
	case HashAlgorithmSHA256:
		return 32
	case HashAlgorithmSHA384:
		return 48
	case HashAlgorithmSHA512:
		return 64
	default:
		return 0
	}
}

// VerificationStatus represents the status of a verification operation.
type VerificationStatus string

// Verification status constants.
const (
	VerificationStatusUnknown  VerificationStatus = "unknown"
	VerificationStatusPending  VerificationStatus = "pending"
	VerificationStatusVerified VerificationStatus = "verified"
	VerificationStatusFailed   VerificationStatus = "failed"
)

// String returns the string representation of VerificationStatus.
func (v VerificationStatus) String() string {
	return string(v)
}

// IsValid returns true if the verification status is valid.
func (v VerificationStatus) IsValid() bool {
	switch v {
	case VerificationStatusUnknown, VerificationStatusPending,
		VerificationStatusVerified, VerificationStatusFailed:
		return true
	default:
		return false
	}
}

// PCRValue represents a single PCR index and its value.
type PCRValue struct {
	// Index is the PCR index (0-23).
	Index int

	// Value is the PCR digest value.
	Value []byte

	// Algorithm is the hash algorithm used for this PCR bank.
	Algorithm HashAlgorithm
}

// HostManifest represents a comprehensive attestation of a host and its workloads.
type HostManifest struct {
	// ID is a unique identifier for this manifest.
	ID string

	// HostID is the host identifier from the IDevID certificate.
	HostID string

	// Timestamp is when the manifest was generated.
	Timestamp time.Time

	// Nonce is the fresh nonce used for anti-replay protection.
	Nonce []byte

	// Host contains the physical TPM attestation.
	Host *HostAttestation

	// VMs contains attestations from all VMs on the host.
	VMs []VMAttestation

	// Containers contains attestations from all containers.
	Containers []ContainerAttestation

	// MerkleRoot is the root hash of the Merkle tree over all attestation data.
	MerkleRoot []byte

	// Signature is the AK signature over the manifest.
	Signature []byte

	// SignatureAlgorithm is the algorithm used for signing.
	SignatureAlgorithm string

	// Version is the manifest format version.
	Version string

	// Metadata contains additional manifest metadata.
	Metadata map[string]string
}

// Validate validates the HostManifest fields.
func (m *HostManifest) Validate() error {
	if m.ID == "" {
		return ErrInvalidManifest{Field: "ID", Reason: "manifest ID cannot be empty"}
	}

	if m.HostID == "" {
		return ErrInvalidManifest{Field: "HostID", Reason: "host ID cannot be empty"}
	}

	if m.Timestamp.IsZero() {
		return ErrInvalidManifest{Field: "Timestamp", Reason: "timestamp cannot be zero"}
	}

	if len(m.Nonce) == 0 {
		return ErrInvalidManifest{Field: "Nonce", Reason: "nonce cannot be empty"}
	}

	if m.Host == nil {
		return ErrInvalidManifest{Field: "Host", Reason: "host attestation cannot be nil"}
	}

	if err := m.Host.Validate(); err != nil {
		return err
	}

	if len(m.MerkleRoot) == 0 {
		return ErrInvalidManifest{Field: "MerkleRoot", Reason: "Merkle root cannot be empty"}
	}

	return nil
}

// VMManifest represents attestation data for a single VM.
type VMManifest struct {
	// VMID is the unique identifier for the virtual machine.
	VMID string

	// HostID is the host running this VM.
	HostID string

	// Attestation is the vTPM attestation for this VM.
	Attestation *VMAttestation

	// Timestamp is when the attestation was collected.
	Timestamp time.Time
}

// Validate validates the VMManifest fields.
func (m *VMManifest) Validate() error {
	if m.VMID == "" {
		return ErrInvalidManifest{Field: "VMID", Reason: "VM ID cannot be empty"}
	}

	if m.HostID == "" {
		return ErrInvalidManifest{Field: "HostID", Reason: "host ID cannot be empty"}
	}

	if m.Attestation == nil {
		return ErrInvalidManifest{Field: "Attestation", Reason: "attestation cannot be nil"}
	}

	return m.Attestation.Validate()
}

// ContainerManifest represents attestation data for a single container.
type ContainerManifest struct {
	// ContainerID is the unique identifier for the container.
	ContainerID string

	// ImageDigest is the digest of the container image.
	ImageDigest string

	// Attestation is the PCR 14 chain entry for this container.
	Attestation *ContainerAttestation

	// Timestamp is when the attestation was collected.
	Timestamp time.Time
}

// Validate validates the ContainerManifest fields.
func (m *ContainerManifest) Validate() error {
	if m.ContainerID == "" {
		return ErrInvalidManifest{Field: "ContainerID", Reason: "container ID cannot be empty"}
	}

	if m.Attestation == nil {
		return ErrInvalidManifest{Field: "Attestation", Reason: "attestation cannot be nil"}
	}

	return m.Attestation.Validate()
}

// HostAttestation represents the physical TPM attestation from the host.
type HostAttestation struct {
	// QuoteData is the raw TPM quote structure (TPMS_ATTEST).
	QuoteData []byte

	// Signature is the AK signature over the quote data.
	Signature []byte

	// SignatureAlgorithm is the algorithm used for signing.
	SignatureAlgorithm string

	// PCRs contains the PCR values included in the quote.
	PCRs []PCRValue

	// PCRDigest is the hash of the PCR values.
	PCRDigest []byte

	// Nonce is the anti-replay nonce included in the quote.
	Nonce []byte

	// Timestamp is when the quote was generated.
	Timestamp time.Time

	// AKPublicKey is the public key of the AK used for signing.
	AKPublicKey []byte

	// IDevIDCertificate is the host's IDevID certificate for identification.
	IDevIDCertificate []byte

	// HashAlgorithm is the hash algorithm used for the quote.
	HashAlgorithm HashAlgorithm

	// FirmwareVersion is the TPM firmware version.
	FirmwareVersion string
}

// Validate validates the HostAttestation fields.
func (a *HostAttestation) Validate() error {
	if len(a.QuoteData) == 0 {
		return ErrInvalidManifest{Field: "QuoteData", Reason: "quote data cannot be empty"}
	}

	if len(a.Signature) == 0 {
		return ErrInvalidManifest{Field: "Signature", Reason: "signature cannot be empty"}
	}

	if len(a.PCRs) == 0 {
		return ErrInvalidManifest{Field: "PCRs", Reason: "PCRs cannot be empty"}
	}

	if len(a.Nonce) == 0 {
		return ErrInvalidManifest{Field: "Nonce", Reason: "nonce cannot be empty"}
	}

	if !a.HashAlgorithm.IsValid() {
		return ErrInvalidHashAlgorithm{Algorithm: a.HashAlgorithm.String()}
	}

	return nil
}

// VMAttestation represents the vTPM attestation from a VM.
type VMAttestation struct {
	// VMID is the unique identifier for the virtual machine.
	VMID string

	// HostID is the host running this VM.
	HostID string

	// QuoteData is the raw TPM quote structure (TPMS_ATTEST).
	QuoteData []byte

	// Signature is the AIK/AK signature over the quote data.
	Signature []byte

	// SignatureAlgorithm is the algorithm used for signing.
	SignatureAlgorithm string

	// PCRs contains the PCR values included in the quote.
	PCRs []PCRValue

	// PCRDigest is the hash of the PCR values.
	PCRDigest []byte

	// Nonce is the anti-replay nonce included in the quote.
	Nonce []byte

	// Timestamp is when the quote was generated.
	Timestamp time.Time

	// AIKPublicKey is the public key of the AIK/AK used for signing.
	AIKPublicKey []byte

	// EKCertificate is the vTPM EK certificate.
	EKCertificate []byte

	// WorkloadPCR is the PCR 14 value (workload chain) from the vTPM.
	WorkloadPCR []byte

	// HashAlgorithm is the hash algorithm used for the quote.
	HashAlgorithm HashAlgorithm

	// Metadata contains additional VM-specific metadata.
	Metadata map[string]string
}

// Validate validates the VMAttestation fields.
func (a *VMAttestation) Validate() error {
	if a.VMID == "" {
		return ErrInvalidManifest{Field: "VMID", Reason: "VM ID cannot be empty"}
	}

	if a.HostID == "" {
		return ErrInvalidManifest{Field: "HostID", Reason: "host ID cannot be empty"}
	}

	if len(a.QuoteData) == 0 {
		return ErrInvalidManifest{Field: "QuoteData", Reason: "quote data cannot be empty"}
	}

	if len(a.Signature) == 0 {
		return ErrInvalidManifest{Field: "Signature", Reason: "signature cannot be empty"}
	}

	if len(a.PCRs) == 0 {
		return ErrInvalidManifest{Field: "PCRs", Reason: "PCRs cannot be empty"}
	}

	if len(a.Nonce) == 0 {
		return ErrInvalidManifest{Field: "Nonce", Reason: "nonce cannot be empty"}
	}

	if !a.HashAlgorithm.IsValid() {
		return ErrInvalidHashAlgorithm{Algorithm: a.HashAlgorithm.String()}
	}

	return nil
}

// ContainerAttestation represents the PCR 14 chain attestation for a container.
type ContainerAttestation struct {
	// ContainerID is the unique identifier for the container.
	ContainerID string

	// ImageID is the container image ID.
	ImageID string

	// ImageDigest is the digest of the container image.
	ImageDigest string

	// Digest is the measurement hash for this container.
	Digest []byte

	// PCRValue is the PCR 14 value after this container's extension.
	PCRValue []byte

	// Timestamp is when the container was measured.
	Timestamp time.Time

	// Metadata contains additional container-specific metadata.
	Metadata map[string]string
}

// Validate validates the ContainerAttestation fields.
func (a *ContainerAttestation) Validate() error {
	if a.ContainerID == "" {
		return ErrInvalidManifest{Field: "ContainerID", Reason: "container ID cannot be empty"}
	}

	if len(a.Digest) == 0 {
		return ErrInvalidManifest{Field: "Digest", Reason: "digest cannot be empty"}
	}

	if len(a.PCRValue) == 0 {
		return ErrInvalidManifest{Field: "PCRValue", Reason: "PCR value cannot be empty"}
	}

	return nil
}

// ManifestConfig contains configuration for manifest operations.
type ManifestConfig struct {
	// TPMDevicePath is the path to the TPM device.
	TPMDevicePath string

	// AKHandle is the TPM handle for the Attestation Key.
	AKHandle uint32

	// DefaultHashAlgorithm is the default hash algorithm for operations.
	DefaultHashAlgorithm HashAlgorithm

	// DefaultPCRIndices are the default PCRs to include in quotes.
	DefaultPCRIndices []int

	// MaxManifestAge is the maximum age of a manifest in seconds (0 = no limit).
	MaxManifestAge int64

	// NonceSize is the size of generated nonces in bytes.
	NonceSize int

	// IncludeWorkloadPCR includes PCR 14 (workload chain) in quotes.
	IncludeWorkloadPCR bool

	// Version is the manifest format version to use.
	Version string
}

// Validate validates the ManifestConfig fields.
func (c *ManifestConfig) Validate() error {
	if c.TPMDevicePath == "" {
		return ErrInvalidConfig{Field: "TPMDevicePath", Reason: "TPM device path cannot be empty"}
	}

	if !c.DefaultHashAlgorithm.IsValid() {
		return ErrInvalidHashAlgorithm{Algorithm: c.DefaultHashAlgorithm.String()}
	}

	if c.MaxManifestAge < 0 {
		return ErrInvalidConfig{Field: "MaxManifestAge", Reason: "max manifest age cannot be negative"}
	}

	if c.NonceSize < 16 {
		return ErrInvalidConfig{Field: "NonceSize", Reason: "nonce size must be at least 16 bytes"}
	}

	return nil
}

// DefaultManifestConfig returns a configuration with sensible defaults.
func DefaultManifestConfig() *ManifestConfig {
	return &ManifestConfig{
		DefaultHashAlgorithm: HashAlgorithmSHA256,
		DefaultPCRIndices:    []int{0, 1, 2, 3, 4, 5, 6, 7, 14},
		MaxManifestAge:       300, // 5 minutes
		NonceSize:            32,
		IncludeWorkloadPCR:   true,
		Version:              "1.0",
	}
}

// BuilderConfig contains configuration for the ManifestBuilder.
type BuilderConfig struct {
	// HostID is the host identifier for the manifest.
	HostID string

	// HashAlgorithm is the hash algorithm for Merkle tree construction.
	HashAlgorithm HashAlgorithm

	// PCRIndices are the PCR indices to include in host attestation.
	PCRIndices []int

	// NonceSize is the size of generated nonces in bytes.
	NonceSize int

	// Version is the manifest format version.
	Version string
}

// Validate validates the BuilderConfig fields.
func (c *BuilderConfig) Validate() error {
	if c.HostID == "" {
		return ErrInvalidConfig{Field: "HostID", Reason: "host ID cannot be empty"}
	}

	if !c.HashAlgorithm.IsValid() {
		return ErrInvalidHashAlgorithm{Algorithm: c.HashAlgorithm.String()}
	}

	if c.NonceSize < 16 {
		return ErrInvalidConfig{Field: "NonceSize", Reason: "nonce size must be at least 16 bytes"}
	}

	return nil
}

// SignerConfig contains configuration for the ManifestSigner.
type SignerConfig struct {
	// TPMDevicePath is the path to the TPM device.
	TPMDevicePath string

	// AKHandle is the TPM handle for the Attestation Key.
	AKHandle uint32

	// HashAlgorithm is the hash algorithm for signing.
	HashAlgorithm HashAlgorithm
}

// Validate validates the SignerConfig fields.
func (c *SignerConfig) Validate() error {
	if c.TPMDevicePath == "" {
		return ErrInvalidConfig{Field: "TPMDevicePath", Reason: "TPM device path cannot be empty"}
	}

	if !c.HashAlgorithm.IsValid() {
		return ErrInvalidHashAlgorithm{Algorithm: c.HashAlgorithm.String()}
	}

	return nil
}

// VerifierConfig contains configuration for the ManifestVerifier.
type VerifierConfig struct {
	// PlatformCACert is the Platform CA certificate for chain validation.
	PlatformCACert *x509.Certificate

	// TrustedRoots contains additional trusted root certificates.
	TrustedRoots []*x509.Certificate

	// MaxManifestAge is the maximum age of a manifest in seconds (0 = no limit).
	MaxManifestAge int64

	// RequireHostAttestation requires valid host attestation.
	RequireHostAttestation bool

	// VerifyMerkleRoot requires Merkle root verification.
	VerifyMerkleRoot bool

	// HashAlgorithm is the hash algorithm for Merkle tree verification.
	HashAlgorithm HashAlgorithm
}

// Validate validates the VerifierConfig fields.
func (c *VerifierConfig) Validate() error {
	if c.PlatformCACert == nil {
		return ErrInvalidConfig{Field: "PlatformCACert", Reason: "Platform CA certificate cannot be nil"}
	}

	if c.MaxManifestAge < 0 {
		return ErrInvalidConfig{Field: "MaxManifestAge", Reason: "max manifest age cannot be negative"}
	}

	if !c.HashAlgorithm.IsValid() {
		return ErrInvalidHashAlgorithm{Algorithm: c.HashAlgorithm.String()}
	}

	return nil
}

// VerificationResult represents the outcome of manifest verification.
type VerificationResult struct {
	// Status indicates the overall verification status.
	Status VerificationStatus

	// SignatureValid indicates if the manifest signature is valid.
	SignatureValid bool

	// MerkleRootValid indicates if the Merkle root is valid.
	MerkleRootValid bool

	// NonceValid indicates if the nonce matches expected value.
	NonceValid bool

	// TimestampValid indicates if the manifest is not expired.
	TimestampValid bool

	// HostAttestationValid indicates if host attestation is valid.
	HostAttestationValid bool

	// VMAttestationsValid indicates if all VM attestations are valid.
	VMAttestationsValid bool

	// ContainerAttestationsValid indicates if all container attestations are valid.
	ContainerAttestationsValid bool

	// VerifiedAt is when the verification was performed.
	VerifiedAt time.Time

	// Errors contains any errors encountered during verification.
	Errors []string

	// VMErrors contains errors for specific VM attestations.
	VMErrors map[string]string

	// ContainerErrors contains errors for specific container attestations.
	ContainerErrors map[string]string
}

// AddError adds an error message to the verification result.
func (v *VerificationResult) AddError(err string) {
	v.Errors = append(v.Errors, err)
}

// HasErrors returns true if there are any verification errors.
func (v *VerificationResult) HasErrors() bool {
	return len(v.Errors) > 0
}

// MerkleNode represents a node in the Merkle tree.
type MerkleNode struct {
	// Hash is the hash value of this node.
	Hash []byte

	// Left is the left child node (nil for leaf nodes).
	Left *MerkleNode

	// Right is the right child node (nil for leaf nodes).
	Right *MerkleNode

	// IsLeaf indicates if this is a leaf node.
	IsLeaf bool

	// Data is the original data for leaf nodes.
	Data []byte
}

// MerkleProof represents a proof of inclusion in the Merkle tree.
type MerkleProof struct {
	// LeafHash is the hash of the leaf being proven.
	LeafHash []byte

	// Path contains the sibling hashes needed to reconstruct the root.
	Path [][]byte

	// Directions indicates which side each hash should be on (true = right).
	Directions []bool
}
