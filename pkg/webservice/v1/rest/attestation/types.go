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

package attestation

import (
	"time"
)

// BuildManifestRequest is the request body for building a new manifest.
type BuildManifestRequest struct {
	// HostID is the identifier for the host (optional, defaults to IDevID CN).
	HostID string `json:"host_id,omitempty"`

	// Nonce is an optional base64-encoded nonce for anti-replay protection.
	// If not provided, a fresh nonce will be generated.
	Nonce string `json:"nonce,omitempty"`

	// PCRIndices are the PCR indices to include in the quote (optional).
	// Defaults to [0, 1, 2, 3, 4, 5, 6, 7, 14] if not specified.
	PCRIndices []int `json:"pcr_indices,omitempty"`

	// HashAlgorithm is the hash algorithm for the quote (sha256, sha384, sha512).
	// Defaults to sha256 if not specified.
	HashAlgorithm string `json:"hash_algorithm,omitempty"`

	// IncludeVMs indicates whether to include VM attestations.
	IncludeVMs bool `json:"include_vms,omitempty"`

	// IncludeContainers indicates whether to include container attestations.
	IncludeContainers bool `json:"include_containers,omitempty"`
}

// VerifyManifestRequest is the request body for verifying a manifest.
type VerifyManifestRequest struct {
	// Manifest is the host manifest to verify.
	Manifest *ManifestRequest `json:"manifest"`

	// ExpectedNonce is the base64-encoded expected nonce value.
	ExpectedNonce string `json:"expected_nonce,omitempty"`

	// PublicKeyPEM is the PEM-encoded public key for signature verification.
	// If not provided, the AK public key from the manifest is used.
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// ManifestRequest represents the manifest structure in API requests.
type ManifestRequest struct {
	// ID is the manifest identifier.
	ID string `json:"id"`

	// HostID is the host identifier.
	HostID string `json:"host_id"`

	// Timestamp is the manifest generation time.
	Timestamp time.Time `json:"timestamp"`

	// Nonce is the base64-encoded anti-replay nonce.
	Nonce string `json:"nonce"`

	// Host contains the host attestation data.
	Host *HostAttestationRequest `json:"host"`

	// VMs contains VM attestation data.
	VMs []VMAttestationRequest `json:"vms,omitempty"`

	// Containers contains container attestation data.
	Containers []ContainerAttestationRequest `json:"containers,omitempty"`

	// MerkleRoot is the base64-encoded Merkle root.
	MerkleRoot string `json:"merkle_root"`

	// Signature is the base64-encoded manifest signature.
	Signature string `json:"signature"`

	// SignatureAlgorithm is the signature algorithm used.
	SignatureAlgorithm string `json:"signature_algorithm"`

	// Version is the manifest format version.
	Version string `json:"version"`

	// Metadata contains additional metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// HostAttestationRequest represents host attestation in API requests.
type HostAttestationRequest struct {
	// QuoteData is the base64-encoded TPM quote data.
	QuoteData string `json:"quote_data"`

	// Signature is the base64-encoded quote signature.
	Signature string `json:"signature"`

	// SignatureAlgorithm is the signature algorithm.
	SignatureAlgorithm string `json:"signature_algorithm"`

	// PCRs contains the PCR values.
	PCRs []PCRValueRequest `json:"pcrs"`

	// PCRDigest is the base64-encoded PCR digest.
	PCRDigest string `json:"pcr_digest"`

	// Nonce is the base64-encoded nonce used in the quote.
	Nonce string `json:"nonce"`

	// Timestamp is when the quote was generated.
	Timestamp time.Time `json:"timestamp"`

	// AKPublicKey is the base64-encoded AK public key.
	AKPublicKey string `json:"ak_public_key"`

	// IDevIDCertificate is the base64-encoded IDevID certificate.
	IDevIDCertificate string `json:"idevid_certificate,omitempty"`

	// HashAlgorithm is the hash algorithm used.
	HashAlgorithm string `json:"hash_algorithm"`

	// FirmwareVersion is the TPM firmware version.
	FirmwareVersion string `json:"firmware_version,omitempty"`
}

// VMAttestationRequest represents VM attestation in API requests.
type VMAttestationRequest struct {
	// VMID is the VM identifier.
	VMID string `json:"vm_id"`

	// HostID is the host running this VM.
	HostID string `json:"host_id"`

	// QuoteData is the base64-encoded vTPM quote data.
	QuoteData string `json:"quote_data"`

	// Signature is the base64-encoded quote signature.
	Signature string `json:"signature"`

	// SignatureAlgorithm is the signature algorithm.
	SignatureAlgorithm string `json:"signature_algorithm"`

	// PCRs contains the PCR values.
	PCRs []PCRValueRequest `json:"pcrs"`

	// PCRDigest is the base64-encoded PCR digest.
	PCRDigest string `json:"pcr_digest"`

	// Nonce is the base64-encoded nonce used in the quote.
	Nonce string `json:"nonce"`

	// Timestamp is when the quote was generated.
	Timestamp time.Time `json:"timestamp"`

	// AIKPublicKey is the base64-encoded AIK public key.
	AIKPublicKey string `json:"aik_public_key"`

	// EKCertificate is the base64-encoded EK certificate.
	EKCertificate string `json:"ek_certificate,omitempty"`

	// WorkloadPCR is the base64-encoded PCR 14 value.
	WorkloadPCR string `json:"workload_pcr,omitempty"`

	// HashAlgorithm is the hash algorithm used.
	HashAlgorithm string `json:"hash_algorithm"`

	// Metadata contains additional metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ContainerAttestationRequest represents container attestation in API requests.
type ContainerAttestationRequest struct {
	// ContainerID is the container identifier.
	ContainerID string `json:"container_id"`

	// ImageID is the container image ID.
	ImageID string `json:"image_id,omitempty"`

	// ImageDigest is the container image digest.
	ImageDigest string `json:"image_digest,omitempty"`

	// Digest is the base64-encoded measurement hash.
	Digest string `json:"digest"`

	// PCRValue is the base64-encoded PCR 14 value.
	PCRValue string `json:"pcr_value"`

	// Timestamp is when the container was measured.
	Timestamp time.Time `json:"timestamp"`

	// Metadata contains additional metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// PCRValueRequest represents a PCR value in API requests.
type PCRValueRequest struct {
	// Index is the PCR index (0-23).
	Index int `json:"index"`

	// Value is the base64-encoded PCR value.
	Value string `json:"value"`

	// Algorithm is the hash algorithm for this PCR bank.
	Algorithm string `json:"algorithm"`
}

// GetQuoteRequest is the request body for generating a TPM quote.
type GetQuoteRequest struct {
	// Nonce is the base64-encoded nonce for anti-replay protection.
	// If not provided, a fresh nonce will be generated.
	Nonce string `json:"nonce,omitempty"`

	// PCRIndices are the PCR indices to include in the quote.
	// Defaults to [0, 1, 2, 3, 4, 5, 6, 7, 14] if not specified.
	PCRIndices []int `json:"pcr_indices,omitempty"`

	// HashAlgorithm is the hash algorithm (sha256, sha384, sha512).
	// Defaults to sha256 if not specified.
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
}

// VerifyQuoteRequest is the request body for verifying a TPM quote.
type VerifyQuoteRequest struct {
	// QuoteData is the base64-encoded TPM quote data.
	QuoteData string `json:"quote_data"`

	// Signature is the base64-encoded quote signature.
	Signature string `json:"signature"`

	// PublicKeyPEM is the PEM-encoded AK public key.
	PublicKeyPEM string `json:"public_key_pem"`

	// ExpectedNonce is the base64-encoded expected nonce.
	ExpectedNonce string `json:"expected_nonce"`

	// PCRs contains the expected PCR values.
	PCRs []PCRValueRequest `json:"pcrs,omitempty"`

	// HashAlgorithm is the hash algorithm used.
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
}

// ManifestResponse is the response for manifest operations.
type ManifestResponse struct {
	// ID is the manifest identifier.
	ID string `json:"id"`

	// HostID is the host identifier.
	HostID string `json:"host_id"`

	// Timestamp is the manifest generation time.
	Timestamp time.Time `json:"timestamp"`

	// Nonce is the base64-encoded anti-replay nonce.
	Nonce string `json:"nonce"`

	// Host contains the host attestation data.
	Host *HostAttestationResponse `json:"host"`

	// VMCount is the number of VMs attested.
	VMCount int `json:"vm_count"`

	// ContainerCount is the number of containers attested.
	ContainerCount int `json:"container_count"`

	// MerkleRoot is the base64-encoded Merkle root.
	MerkleRoot string `json:"merkle_root"`

	// Signature is the base64-encoded manifest signature.
	Signature string `json:"signature,omitempty"`

	// SignatureAlgorithm is the signature algorithm used.
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`

	// Version is the manifest format version.
	Version string `json:"version"`

	// Metadata contains additional metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// HostAttestationResponse represents host attestation in API responses.
type HostAttestationResponse struct {
	// QuoteData is the base64-encoded TPM quote data.
	QuoteData string `json:"quote_data"`

	// Signature is the base64-encoded quote signature.
	Signature string `json:"signature"`

	// SignatureAlgorithm is the signature algorithm.
	SignatureAlgorithm string `json:"signature_algorithm"`

	// PCRs contains the PCR values.
	PCRs []PCRValueResponse `json:"pcrs"`

	// PCRDigest is the base64-encoded PCR digest.
	PCRDigest string `json:"pcr_digest"`

	// Nonce is the base64-encoded nonce used in the quote.
	Nonce string `json:"nonce"`

	// Timestamp is when the quote was generated.
	Timestamp time.Time `json:"timestamp"`

	// AKPublicKeyPEM is the PEM-encoded AK public key.
	AKPublicKeyPEM string `json:"ak_public_key_pem,omitempty"`

	// HashAlgorithm is the hash algorithm used.
	HashAlgorithm string `json:"hash_algorithm"`

	// FirmwareVersion is the TPM firmware version.
	FirmwareVersion string `json:"firmware_version,omitempty"`
}

// PCRValueResponse represents a PCR value in API responses.
type PCRValueResponse struct {
	// Index is the PCR index (0-23).
	Index int `json:"index"`

	// Value is the base64-encoded PCR value.
	Value string `json:"value"`

	// Algorithm is the hash algorithm for this PCR bank.
	Algorithm string `json:"algorithm"`
}

// QuoteResponse is the response for quote generation.
type QuoteResponse struct {
	// QuoteData is the base64-encoded TPM quote data.
	QuoteData string `json:"quote_data"`

	// Signature is the base64-encoded quote signature.
	Signature string `json:"signature"`

	// SignatureAlgorithm is the signature algorithm used.
	SignatureAlgorithm string `json:"signature_algorithm"`

	// PCRs contains the PCR values included in the quote.
	PCRs []PCRValueResponse `json:"pcrs"`

	// PCRDigest is the base64-encoded PCR digest.
	PCRDigest string `json:"pcr_digest"`

	// Nonce is the base64-encoded nonce used.
	Nonce string `json:"nonce"`

	// Timestamp is when the quote was generated.
	Timestamp time.Time `json:"timestamp"`

	// AKPublicKeyPEM is the PEM-encoded AK public key.
	AKPublicKeyPEM string `json:"ak_public_key_pem"`

	// HashAlgorithm is the hash algorithm used.
	HashAlgorithm string `json:"hash_algorithm"`
}

// VerificationResponse is the response for verification operations.
type VerificationResponse struct {
	// Valid indicates if verification succeeded.
	Valid bool `json:"valid"`

	// Status is the verification status (verified, failed, pending).
	Status string `json:"status"`

	// SignatureValid indicates if the signature is valid.
	SignatureValid bool `json:"signature_valid"`

	// MerkleRootValid indicates if the Merkle root is valid.
	MerkleRootValid bool `json:"merkle_root_valid,omitempty"`

	// NonceValid indicates if the nonce matches.
	NonceValid bool `json:"nonce_valid,omitempty"`

	// TimestampValid indicates if the manifest is not expired.
	TimestampValid bool `json:"timestamp_valid,omitempty"`

	// HostAttestationValid indicates if host attestation is valid.
	HostAttestationValid bool `json:"host_attestation_valid,omitempty"`

	// VMAttestationsValid indicates if all VM attestations are valid.
	VMAttestationsValid bool `json:"vm_attestations_valid,omitempty"`

	// ContainerAttestationsValid indicates if all container attestations are valid.
	ContainerAttestationsValid bool `json:"container_attestations_valid,omitempty"`

	// VerifiedAt is when the verification was performed.
	VerifiedAt time.Time `json:"verified_at"`

	// Errors contains any verification errors.
	Errors []string `json:"errors,omitempty"`
}

// SuccessResponse is a generic success response.
type SuccessResponse struct {
	// Success indicates if the operation succeeded.
	Success bool `json:"success"`

	// Message provides additional information.
	Message string `json:"message,omitempty"`
}
