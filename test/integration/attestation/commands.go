//go:build integration

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

// Package attestation provides integration tests for attestation services
// including VM attestation, manifest building, push operations, and workload chain management.
package attestation

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
)

// AttestationCommands defines the interface for attestation operations across all protocols.
type AttestationCommands interface {
	// Setup prepares the adapter for testing
	Setup(ctx context.Context) error

	// Teardown cleans up after testing
	Teardown(ctx context.Context) error

	// Name returns the adapter name
	Name() string

	// VM Attestation Operations

	// GenerateVMQuote generates a TPM quote for a VM
	GenerateVMQuote(ctx context.Context, opts GenerateVMQuoteOptions) (*GenerateVMQuoteResult, error)

	// GetVMIdentity retrieves VM identity from vTPM EK certificate
	GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error)

	// GetVMAttestation generates a full VM attestation
	GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error)

	// VerifyVMAttestation verifies a VM attestation
	VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error)

	// Manifest Operations

	// BuildManifest builds a host manifest with attestations
	BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error)

	// SignManifest signs a manifest with the host TPM
	SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error)

	// VerifyManifest verifies a signed manifest
	VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error)

	// GetManifest retrieves a manifest by ID
	GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error)

	// Push Operations

	// PushAttestation pushes an attestation to a target
	PushAttestation(ctx context.Context, opts PushAttestationOptions) (*PushAttestationResult, error)

	// PushAttestationBatch pushes to multiple targets concurrently
	PushAttestationBatch(ctx context.Context, opts PushAttestationBatchOptions) (*PushAttestationBatchResult, error)

	// GetPushStatus retrieves the status of a push operation
	GetPushStatus(ctx context.Context, opts GetPushStatusOptions) (*GetPushStatusResult, error)

	// Workload Chain Operations

	// ExtendWorkloadChain extends the workload PCR with a measurement
	ExtendWorkloadChain(ctx context.Context, opts ExtendWorkloadChainOptions) (*ExtendWorkloadChainResult, error)

	// GetWorkloadChainHistory retrieves the chain history
	GetWorkloadChainHistory(ctx context.Context, opts GetWorkloadChainHistoryOptions) (*GetWorkloadChainHistoryResult, error)

	// VerifyWorkloadChain verifies the chain against expected PCR
	VerifyWorkloadChain(ctx context.Context, opts VerifyWorkloadChainOptions) (*VerifyWorkloadChainResult, error)

	// GetWorkloadChainStats retrieves chain statistics
	GetWorkloadChainStats(ctx context.Context, opts GetWorkloadChainStatsOptions) (*GetWorkloadChainStatsResult, error)

	// Device attestation reporting (#226, #429). The reads fail with
	// ErrReportingUnavailable on a node without a reporting service, and
	// GetDeviceReport with ErrReportNotCollected for a device the collector
	// has never reached.

	// ListDeviceReports reads every cached device report.
	ListDeviceReports(ctx context.Context) (*DeviceReportsResult, error)

	// GetDeviceReport reads one device's cached report.
	GetDeviceReport(ctx context.Context, opts DeviceReportOptions) (*DeviceReport, error)

	// RefreshDeviceReport asks the collector to re-collect one device.
	RefreshDeviceReport(ctx context.Context, opts DeviceReportOptions) (*RefreshDeviceReportResult, error)

	// DescribeCallerPolicy reads the node's compiled caller-admission policy.
	DescribeCallerPolicy(ctx context.Context) (*calleradmission.Description, error)
}

// =============================================================================
// VM Attestation Options and Results
// =============================================================================

// GenerateVMQuoteOptions contains options for generating a VM quote
type GenerateVMQuoteOptions struct {
	VMID          string `json:"vm_id"`
	Nonce         []byte `json:"nonce"`
	PCRIndices    []int  `json:"pcr_indices"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
}

// GenerateVMQuoteResult contains the result of VM quote generation
type GenerateVMQuoteResult struct {
	QuoteData     []byte    `json:"quote_data"`
	Signature     []byte    `json:"signature"`
	PCRDigest     []byte    `json:"pcr_digest"`
	AIKPublicKey  []byte    `json:"aik_public_key"`
	Timestamp     time.Time `json:"timestamp"`
	HashAlgorithm string    `json:"hash_algorithm"`
}

// GetVMIdentityOptions contains options for getting VM identity
type GetVMIdentityOptions struct {
	VMID string `json:"vm_id"`
}

// GetVMIdentityResult contains VM identity information
type GetVMIdentityResult struct {
	VMID         string `json:"vm_id"`
	HostID       string `json:"host_id"`
	EKCertPEM    string `json:"ek_cert_pem"`
	SerialNumber string `json:"serial_number"`
	Issuer       string `json:"issuer"`
}

// GetVMAttestationOptions contains options for getting VM attestation
type GetVMAttestationOptions struct {
	VMID          string `json:"vm_id"`
	Nonce         []byte `json:"nonce"`
	PCRIndices    []int  `json:"pcr_indices"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
}

// GetVMAttestationResult contains full VM attestation
type GetVMAttestationResult struct {
	AttestationID      string            `json:"attestation_id"`
	VMID               string            `json:"vm_id"`
	HostID             string            `json:"host_id"`
	QuoteData          []byte            `json:"quote_data"`
	Signature          []byte            `json:"signature"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	Nonce              []byte            `json:"nonce,omitempty"`
	PCRs               []PCRValueResult  `json:"pcrs"`
	PCRDigest          []byte            `json:"pcr_digest"`
	WorkloadPCR        []byte            `json:"workload_pcr,omitempty"`
	AIKPublicKey       []byte            `json:"aik_public_key"`
	EKCertPEM          string            `json:"ek_cert_pem"`
	Timestamp          time.Time         `json:"timestamp"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// VerifyOptions is the VerifyVMAttestation request for this attestation:
// its quote under its AIK, checked against expectedNonce.
func (r *GetVMAttestationResult) VerifyOptions(expectedNonce []byte) VerifyVMAttestationOptions {
	return VerifyVMAttestationOptions{
		AttestationID: r.AttestationID,
		Quote: &VMQuote{
			QuoteData:          r.QuoteData,
			Signature:          r.Signature,
			SignatureAlgorithm: r.SignatureAlgorithm,
			Nonce:              r.Nonce,
		},
		AkPublicKeyPem: r.AIKPublicKey,
		ExpectedNonce:  expectedNonce,
	}
}

// PCRValueResult represents a PCR value
type PCRValueResult struct {
	Index     int    `json:"index"`
	Value     []byte `json:"value"`
	Algorithm string `json:"algorithm"`
}

// VerifyVMAttestationOptions contains options for verifying VM attestation
type VerifyVMAttestationOptions struct {
	AttestationID string `json:"attestation_id"`
	// Quote is the quote to verify, as GetVMAttestation returned it. The
	// daemon refuses a verify request without one.
	Quote *VMQuote `json:"quote,omitempty"`
	// AkPublicKeyPem is the AK public key the signature is checked under.
	AkPublicKeyPem []byte   `json:"ak_public_key_pem,omitempty"`
	ExpectedNonce  []byte   `json:"expected_nonce"`
	ExpectedPCRs   [][]byte `json:"expected_pcrs,omitempty"`
	TrustedEKCerts []string `json:"trusted_ek_certs,omitempty"`
}

// VMQuote is the signed part of a VM attestation: the TPMS_ATTEST, the AK
// signature over it and the scheme it was signed under.
type VMQuote struct {
	QuoteData          []byte `json:"quote_data"`
	Signature          []byte `json:"signature"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Nonce              []byte `json:"nonce,omitempty"`
}

// VerifyVMAttestationResult contains verification result
type VerifyVMAttestationResult struct {
	Valid          bool              `json:"valid"`
	AttestationID  string            `json:"attestation_id"`
	VMID           string            `json:"vm_id"`
	NonceMatch     bool              `json:"nonce_match"`
	SignatureValid bool              `json:"signature_valid"`
	PCRsMatch      bool              `json:"pcrs_match"`
	EKTrusted      bool              `json:"ek_trusted"`
	Errors         []string          `json:"errors,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// =============================================================================
// Manifest Options and Results
// =============================================================================

// BuildManifestOptions contains options for building a manifest
type BuildManifestOptions struct {
	HostID                string                       `json:"host_id"`
	HostAttestation       *HostAttestationInput        `json:"host_attestation"`
	VMAttestations        []*VMAttestationInput        `json:"vm_attestations,omitempty"`
	ContainerAttestations []*ContainerAttestationInput `json:"container_attestations,omitempty"`
	HashAlgorithm         string                       `json:"hash_algorithm,omitempty"`
	Version               string                       `json:"version,omitempty"`
}

// HostAttestationInput represents host attestation data for manifest building
type HostAttestationInput struct {
	QuoteData []byte           `json:"quote_data"`
	Signature []byte           `json:"signature"`
	PCRs      []PCRValueResult `json:"pcrs"`
	PCRDigest []byte           `json:"pcr_digest"`
}

// VMAttestationInput represents VM attestation data for manifest building
type VMAttestationInput struct {
	VMID      string           `json:"vm_id"`
	HostID    string           `json:"host_id"`
	QuoteData []byte           `json:"quote_data"`
	Signature []byte           `json:"signature"`
	PCRs      []PCRValueResult `json:"pcrs"`
	PCRDigest []byte           `json:"pcr_digest"`
}

// ContainerAttestationInput represents container attestation data
type ContainerAttestationInput struct {
	ContainerID string `json:"container_id"`
	ImageDigest string `json:"image_digest"`
	Digest      []byte `json:"digest"`
	PCRValue    []byte `json:"pcr_value"`
}

// BuildManifestResult contains the built manifest
type BuildManifestResult struct {
	ManifestID     string            `json:"manifest_id"`
	HostID         string            `json:"host_id"`
	MerkleRoot     []byte            `json:"merkle_root"`
	VMCount        int               `json:"vm_count"`
	ContainerCount int               `json:"container_count"`
	Timestamp      time.Time         `json:"timestamp"`
	Version        string            `json:"version"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// SignManifestOptions contains options for signing a manifest
type SignManifestOptions struct {
	ManifestID    string `json:"manifest_id"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
}

// SignManifestResult contains the signed manifest
type SignManifestResult struct {
	ManifestID         string    `json:"manifest_id"`
	Signature          []byte    `json:"signature"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	SignerPublicKey    []byte    `json:"signer_public_key"`
	SignedAt           time.Time `json:"signed_at"`
}

// VerifyManifestOptions contains options for verifying a manifest
type VerifyManifestOptions struct {
	ManifestID     string   `json:"manifest_id"`
	TrustedSigners [][]byte `json:"trusted_signers,omitempty"`
	ExpectedHostID string   `json:"expected_host_id,omitempty"`
}

// VerifyManifestResult contains manifest verification result
type VerifyManifestResult struct {
	Valid           bool     `json:"valid"`
	ManifestID      string   `json:"manifest_id"`
	SignatureValid  bool     `json:"signature_valid"`
	MerkleRootValid bool     `json:"merkle_root_valid"`
	HostIDMatch     bool     `json:"host_id_match"`
	SignerTrusted   bool     `json:"signer_trusted"`
	Errors          []string `json:"errors,omitempty"`
}

// GetManifestOptions contains options for getting a manifest
type GetManifestOptions struct {
	ManifestID string `json:"manifest_id"`
}

// GetManifestResult contains the retrieved manifest
type GetManifestResult struct {
	ManifestID     string            `json:"manifest_id"`
	HostID         string            `json:"host_id"`
	MerkleRoot     []byte            `json:"merkle_root"`
	Signature      []byte            `json:"signature,omitempty"`
	VMCount        int               `json:"vm_count"`
	ContainerCount int               `json:"container_count"`
	Timestamp      time.Time         `json:"timestamp"`
	Version        string            `json:"version"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// =============================================================================
// Push Options and Results
// =============================================================================

// PushAttestationOptions contains options for pushing attestation
type PushAttestationOptions struct {
	ManifestID  string            `json:"manifest_id"`
	TargetID    string            `json:"target_id"`
	Endpoint    string            `json:"endpoint"`
	Transport   string            `json:"transport"` // http, grpc
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Timeout     time.Duration     `json:"timeout,omitempty"`
	AuthType    string            `json:"auth_type,omitempty"`
	AuthToken   string            `json:"auth_token,omitempty"`
}

// PushAttestationResult contains push result
type PushAttestationResult struct {
	PushID      string        `json:"push_id"`
	TargetID    string        `json:"target_id"`
	Endpoint    string        `json:"endpoint"`
	Status      string        `json:"status"` // success, failed, pending, canceled
	StatusCode  int           `json:"status_code,omitempty"`
	BytesSent   int64         `json:"bytes_sent"`
	Attempts    int           `json:"attempts"`
	Duration    time.Duration `json:"duration"`
	Error       string        `json:"error,omitempty"`
	Response    []byte        `json:"response,omitempty"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
}

// PushAttestationBatchOptions contains options for batch push
type PushAttestationBatchOptions struct {
	ManifestID string                    `json:"manifest_id"`
	Targets    []*PushAttestationOptions `json:"targets"`
}

// PushAttestationBatchResult contains batch push result
type PushAttestationBatchResult struct {
	ManifestID   string                   `json:"manifest_id"`
	Results      []*PushAttestationResult `json:"results"`
	TotalTargets int                      `json:"total_targets"`
	SuccessCount int                      `json:"success_count"`
	FailureCount int                      `json:"failure_count"`
	SkippedCount int                      `json:"skipped_count"`
	Duration     time.Duration            `json:"duration"`
	StartedAt    time.Time                `json:"started_at"`
	CompletedAt  time.Time                `json:"completed_at"`
}

// GetPushStatusOptions contains options for getting push status
type GetPushStatusOptions struct {
	PushID string `json:"push_id"`
}

// GetPushStatusResult contains push status
type GetPushStatusResult struct {
	PushID      string    `json:"push_id"`
	ManifestID  string    `json:"manifest_id"`
	TargetID    string    `json:"target_id"`
	Status      string    `json:"status"`
	Attempts    int       `json:"attempts"`
	LastAttempt time.Time `json:"last_attempt"`
	Error       string    `json:"error,omitempty"`
}

// =============================================================================
// Workload Chain Options and Results
// =============================================================================

// ExtendWorkloadChainOptions contains options for extending workload chain
type ExtendWorkloadChainOptions struct {
	WorkloadType string `json:"workload_type"` // vm, container
	WorkloadID   string `json:"workload_id"`
	ImageDigest  string `json:"image_digest"`
	ConfigHash   []byte `json:"config_hash,omitempty"`
	RuntimeHash  []byte `json:"runtime_hash,omitempty"`
}

// ExtendWorkloadChainResult contains extension result
type ExtendWorkloadChainResult struct {
	EntryID     string    `json:"entry_id"`
	WorkloadID  string    `json:"workload_id"`
	Digest      []byte    `json:"digest"`
	PCRValue    []byte    `json:"pcr_value"`
	Timestamp   time.Time `json:"timestamp"`
	ChainLength int       `json:"chain_length"`
}

// GetWorkloadChainHistoryOptions contains options for getting chain history
type GetWorkloadChainHistoryOptions struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// GetWorkloadChainHistoryResult contains chain history
type GetWorkloadChainHistoryResult struct {
	Entries []*ChainEntryResult `json:"entries"`
	Total   int                 `json:"total"`
}

// ChainEntryResult represents a chain entry
type ChainEntryResult struct {
	EntryID      string    `json:"entry_id"`
	WorkloadType string    `json:"workload_type"`
	WorkloadID   string    `json:"workload_id"`
	ImageDigest  string    `json:"image_digest"`
	Digest       []byte    `json:"digest"`
	PCRValue     []byte    `json:"pcr_value"`
	Timestamp    time.Time `json:"timestamp"`
}

// VerifyWorkloadChainOptions contains options for verifying chain
type VerifyWorkloadChainOptions struct {
	ExpectedPCRValue []byte `json:"expected_pcr_value"`
}

// VerifyWorkloadChainResult contains chain verification result
type VerifyWorkloadChainResult struct {
	Valid       bool     `json:"valid"`
	ComputedPCR []byte   `json:"computed_pcr"`
	ExpectedPCR []byte   `json:"expected_pcr"`
	ChainLength int      `json:"chain_length"`
	Errors      []string `json:"errors,omitempty"`
}

// GetWorkloadChainStatsOptions contains options for getting chain stats
type GetWorkloadChainStatsOptions struct{}

// GetWorkloadChainStatsResult contains chain statistics
type GetWorkloadChainStatsResult struct {
	TotalEntries    int       `json:"total_entries"`
	VMCount         int       `json:"vm_count"`
	ContainerCount  int       `json:"container_count"`
	CurrentPCRValue []byte    `json:"current_pcr_value"`
	FirstEntryTime  time.Time `json:"first_entry_time,omitempty"`
	LastEntryTime   time.Time `json:"last_entry_time,omitempty"`
}
