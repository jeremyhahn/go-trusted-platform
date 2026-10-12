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

package quic

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Attestation pagination defaults
const (
	attestationDefaultLimit int32 = 50
	attestationMaxLimit     int32 = 1000
)

// Attestation-specific sentinel errors
var (
	// ErrAttestationServiceNotAvailable is returned when the attestation service
	// is not configured or unavailable.
	ErrAttestationServiceNotAvailable = errors.New("attestation service not available")

	// ErrAttestationMissingManifestID is returned when a manifest ID is required but not provided.
	ErrAttestationMissingManifestID = errors.New("manifest ID is required")

	// ErrAttestationMissingReportID is returned when a report ID is required but not provided.
	ErrAttestationMissingReportID = errors.New("report ID is required")

	// ErrAttestationMissingVMID is returned when a VM ID is required but not provided.
	ErrAttestationMissingVMID = errors.New("VM ID is required")

	// ErrAttestationMissingContainerID is returned when a container ID is required but not provided.
	ErrAttestationMissingContainerID = errors.New("container ID is required")

	// ErrAttestationMissingDeviceID is returned when a device ID is required but not provided.
	ErrAttestationMissingDeviceID = errors.New("device ID is required")

	// ErrAttestationMissingPolicyName is returned when a policy name is required but not provided.
	ErrAttestationMissingPolicyName = errors.New("policy name is required")

	// ErrAttestationMissingManifest is returned when a manifest is required but not provided.
	ErrAttestationMissingManifest = errors.New("manifest is required")

	// ErrAttestationInvalidNonce is returned when a nonce is invalid.
	ErrAttestationInvalidNonce = errors.New("invalid nonce")

	// ErrAttestationInvalidHashAlgorithm is returned when a hash algorithm is invalid.
	ErrAttestationInvalidHashAlgorithm = errors.New("invalid hash algorithm")

	// ErrAttestationInvalidPCRIndex is returned when a PCR index is invalid.
	ErrAttestationInvalidPCRIndex = errors.New("invalid PCR index (valid: 0-23)")
)

// AttestationServiceInterface defines the interface for attestation operations.
type AttestationServiceInterface interface {
	// GetManifest retrieves an existing attestation manifest by ID or the current manifest.
	GetManifest(ctx context.Context, id string) (*manifest.HostManifest, error)

	// BuildManifest builds a new attestation manifest for the host and its workloads.
	BuildManifest(ctx context.Context, config *AttestationBuildManifestConfig) (*manifest.HostManifest, error)

	// VerifyManifest verifies an attestation manifest including signature and Merkle root.
	VerifyManifest(ctx context.Context, m *manifest.HostManifest, opts *AttestationVerifyManifestOptions) (*manifest.VerificationResult, error)

	// CollectHostAttestation collects attestation data from the host TPM.
	CollectHostAttestation(ctx context.Context, opts *AttestationCollectOptions) (*manifest.HostAttestation, error)

	// AttestVM performs attestation for a virtual machine.
	AttestVM(ctx context.Context, vmID string, opts *AttestationCollectOptions) (*manifest.VMAttestation, error)

	// AttestContainer performs attestation for a container.
	AttestContainer(ctx context.Context, containerID string, opts *AttestationCollectOptions) (*manifest.ContainerAttestation, error)

	// AttestDevice performs attestation for a device.
	AttestDevice(ctx context.Context, deviceID string, opts *AttestationCollectOptions) (*AttestationDeviceResult, error)

	// ListReports lists attestation reports with optional filtering.
	ListReports(ctx context.Context, filter *AttestationReportFilter) ([]*AttestationReport, int, error)

	// GetReport retrieves an attestation report by ID.
	GetReport(ctx context.Context, id string) (*AttestationReport, error)

	// CreatePolicy creates a new attestation policy.
	CreatePolicy(ctx context.Context, policy *AttestationPolicyCreateRequest) (*AttestationPolicy, error)

	// ListPolicies lists attestation policies with optional filtering.
	ListPolicies(ctx context.Context, filter *AttestationPolicyListFilter) ([]*AttestationPolicy, int, error)
}

// AttestationBuildManifestConfig contains configuration for building a manifest.
type AttestationBuildManifestConfig struct {
	HostID            string
	Nonce             []byte
	PCRIndices        []int
	HashAlgorithm     manifest.HashAlgorithm
	IncludeVMs        bool
	IncludeContainers bool
	VMIDs             []string
	ContainerIDs      []string
	Sign              bool
}

// AttestationVerifyManifestOptions contains options for manifest verification.
type AttestationVerifyManifestOptions struct {
	ExpectedNonce []byte
	PublicKeyPEM  []byte
	ExpectedPCRs  map[int][]byte
}

// AttestationCollectOptions contains options for attestation collection.
type AttestationCollectOptions struct {
	Nonce           []byte
	PCRIndices      []int
	HashAlgorithm   manifest.HashAlgorithm
	IncludeEventLog bool
	PolicyID        string
}

// AttestationReportFilter contains filters for listing attestation reports.
type AttestationReportFilter struct {
	HostID    string
	StartTime time.Time
	EndTime   time.Time
	Limit     int
	Offset    int
	Status    string
}

// AttestationPolicyListFilter contains filters for listing attestation policies.
type AttestationPolicyListFilter struct {
	Name   string
	Limit  int
	Offset int
	Active bool
}

// AttestationDeviceResult contains the result of a device attestation.
type AttestationDeviceResult struct {
	DeviceID     string
	DeviceType   string
	Verified     bool
	QuoteData    []byte
	Signature    []byte
	PCRValues    map[int][]byte
	Certificate  []byte
	Timestamp    time.Time
	Metadata     map[string]string
	PolicyResult *AttestationPolicyEvalResult
}

// AttestationPolicyEvalResult contains the result of policy evaluation.
type AttestationPolicyEvalResult struct {
	PolicyID    string
	PolicyName  string
	Passed      bool
	Details     []string
	EvaluatedAt time.Time
}

// AttestationReport represents an attestation report.
type AttestationReport struct {
	ID         string
	HostID     string
	Type       string
	WorkloadID string
	Status     string
	ManifestID string
	PolicyID   string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Metadata   map[string]string
}

// AttestationPolicy represents an attestation policy.
type AttestationPolicy struct {
	ID           string
	Name         string
	Description  string
	PCRPolicy    *AttestationPCRPolicyConfig
	GoldenValues map[int][]byte
	MaxAge       int64
	Active       bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Metadata     map[string]string
}

// AttestationPCRPolicyConfig defines expected PCR values for attestation.
type AttestationPCRPolicyConfig struct {
	RequiredPCRs    []int
	AllowedHashAlgs []string
	ExpectedValues  map[int][]byte
	AllowZeroValues bool
}

// AttestationPolicyCreateRequest represents a request to create an attestation policy.
type AttestationPolicyCreateRequest struct {
	Name         string
	Description  string
	PCRPolicy    *AttestationPCRPolicyConfig
	GoldenValues map[int][]byte
	MaxAge       int64
	Active       bool
	Metadata     map[string]string
}

// AttestationHandler handles attestation operations over QUIC
type AttestationHandler struct {
	service AttestationServiceInterface
	logger  *logging.Logger
}

// NewAttestationHandler creates a new attestation handler
func NewAttestationHandler(logger *logging.Logger, service AttestationServiceInterface) *AttestationHandler {
	return &AttestationHandler{
		service: service,
		logger:  logger,
	}
}

// HandleRequest processes an attestation request and returns a response
func (h *AttestationHandler) HandleRequest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if req == nil {
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte(quicwire.ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	case quicwire.OpAttestGetManifest:
		return h.handleGetManifest(ctx, req)
	case quicwire.OpAttestBuildManifest:
		return h.handleBuildManifest(ctx, req)
	case quicwire.OpAttestVerifyManifest:
		return h.handleVerifyManifest(ctx, req)
	case quicwire.OpAttestHost:
		return h.handleCollectHostAttestation(ctx, req)
	case quicwire.OpAttestVMWorkload:
		return h.handleAttestVM(ctx, req)
	case quicwire.OpAttestContainerWorkload:
		return h.handleAttestContainer(ctx, req)
	case quicwire.OpAttestDeviceWorkload:
		return h.handleAttestDevice(ctx, req)
	case quicwire.OpAttestListReports:
		return h.handleListReports(ctx, req)
	case quicwire.OpAttestGetReportByID:
		return h.handleGetReport(ctx, req)
	case quicwire.OpAttestCreatePolicy:
		return h.handleCreatePolicy(ctx, req)
	case quicwire.OpAttestListPolicies:
		return h.handleListPolicies(ctx, req)
	default:
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte("unknown attestation operation"),
		}
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// GetManifestRequest represents a request to get an attestation manifest
type GetManifestRequest struct {
	ID string `codec:"id"`
}

// GetManifestResponse represents a get manifest response
type GetManifestResponse struct {
	Manifest  *ManifestData `codec:"manifest"`
	Timestamp int64         `codec:"timestamp"`
}

// ManifestData represents attestation manifest data for QUIC transport
type ManifestData struct {
	ID                 string                `codec:"id"`
	HostID             string                `codec:"host_id"`
	Timestamp          int64                 `codec:"timestamp"`
	Nonce              []byte                `codec:"nonce"`
	Host               *HostAttestationData  `codec:"host"`
	VMs                []VMAttestationData   `codec:"vms"`
	Containers         []ContainerAttestData `codec:"containers"`
	MerkleRoot         []byte                `codec:"merkle_root"`
	Signature          []byte                `codec:"signature"`
	SignatureAlgorithm string                `codec:"signature_algorithm"`
	Version            string                `codec:"version"`
	Metadata           map[string]string     `codec:"metadata"`
}

// HostAttestationData represents host attestation data for QUIC transport
type HostAttestationData struct {
	QuoteData          []byte         `codec:"quote_data"`
	Signature          []byte         `codec:"signature"`
	SignatureAlgorithm string         `codec:"signature_algorithm"`
	PCRs               []PCRValueData `codec:"pcrs"`
	PCRDigest          []byte         `codec:"pcr_digest"`
	Nonce              []byte         `codec:"nonce"`
	Timestamp          int64          `codec:"timestamp"`
	AKPublicKey        []byte         `codec:"ak_public_key"`
	IDevIDCertificate  []byte         `codec:"idevid_certificate"`
	HashAlgorithm      string         `codec:"hash_algorithm"`
	FirmwareVersion    string         `codec:"firmware_version"`
}

// VMAttestationData represents VM attestation data for QUIC transport
type VMAttestationData struct {
	VMID               string            `codec:"vm_id"`
	HostID             string            `codec:"host_id"`
	QuoteData          []byte            `codec:"quote_data"`
	Signature          []byte            `codec:"signature"`
	SignatureAlgorithm string            `codec:"signature_algorithm"`
	PCRs               []PCRValueData    `codec:"pcrs"`
	PCRDigest          []byte            `codec:"pcr_digest"`
	Nonce              []byte            `codec:"nonce"`
	Timestamp          int64             `codec:"timestamp"`
	AIKPublicKey       []byte            `codec:"aik_public_key"`
	EKCertificate      []byte            `codec:"ek_certificate"`
	WorkloadPCR        []byte            `codec:"workload_pcr"`
	HashAlgorithm      string            `codec:"hash_algorithm"`
	Metadata           map[string]string `codec:"metadata"`
}

// ContainerAttestData represents container attestation data for QUIC transport
type ContainerAttestData struct {
	ContainerID string            `codec:"container_id"`
	ImageID     string            `codec:"image_id"`
	ImageDigest string            `codec:"image_digest"`
	Digest      []byte            `codec:"digest"`
	PCRValue    []byte            `codec:"pcr_value"`
	Timestamp   int64             `codec:"timestamp"`
	Metadata    map[string]string `codec:"metadata"`
}

// PCRValueData represents a PCR value for QUIC transport
type PCRValueData struct {
	Index     int    `codec:"index"`
	Value     []byte `codec:"value"`
	Algorithm string `codec:"algorithm"`
}

// BuildManifestRequest represents a request to build an attestation manifest
type BuildManifestRequest struct {
	HostID            string   `codec:"host_id"`
	Nonce             []byte   `codec:"nonce"`
	PCRIndices        []int    `codec:"pcr_indices"`
	HashAlgorithm     string   `codec:"hash_algorithm"`
	IncludeVMs        bool     `codec:"include_vms"`
	IncludeContainers bool     `codec:"include_containers"`
	VMIDs             []string `codec:"vm_ids"`
	ContainerIDs      []string `codec:"container_ids"`
	Sign              bool     `codec:"sign"`
}

// BuildManifestResponse represents a build manifest response
type BuildManifestResponse struct {
	Manifest  *ManifestData `codec:"manifest"`
	Timestamp int64         `codec:"timestamp"`
}

// VerifyManifestRequest represents a request to verify an attestation manifest
type VerifyManifestRequest struct {
	Manifest      *ManifestData  `codec:"manifest"`
	ExpectedNonce []byte         `codec:"expected_nonce"`
	PublicKeyPEM  []byte         `codec:"public_key_pem"`
	ExpectedPCRs  map[int][]byte `codec:"expected_pcrs"`
}

// VerifyManifestResponse represents a verify manifest response
type VerifyManifestResponse struct {
	Valid                      bool              `codec:"valid"`
	Status                     string            `codec:"status"`
	SignatureValid             bool              `codec:"signature_valid"`
	MerkleRootValid            bool              `codec:"merkle_root_valid"`
	NonceValid                 bool              `codec:"nonce_valid"`
	TimestampValid             bool              `codec:"timestamp_valid"`
	HostAttestationValid       bool              `codec:"host_attestation_valid"`
	VMAttestationsValid        bool              `codec:"vm_attestations_valid"`
	ContainerAttestationsValid bool              `codec:"container_attestations_valid"`
	VerifiedAt                 int64             `codec:"verified_at"`
	Errors                     []string          `codec:"errors"`
	VMErrors                   map[string]string `codec:"vm_errors"`
	ContainerErrors            map[string]string `codec:"container_errors"`
}

// CollectHostAttestationRequest represents a request to collect host attestation
type CollectHostAttestationRequest struct {
	Nonce           []byte `codec:"nonce"`
	PCRIndices      []int  `codec:"pcr_indices"`
	HashAlgorithm   string `codec:"hash_algorithm"`
	IncludeEventLog bool   `codec:"include_event_log"`
}

// CollectHostAttestationResponse represents a collect host attestation response
type CollectHostAttestationResponse struct {
	Attestation *HostAttestationData `codec:"attestation"`
	Timestamp   int64                `codec:"timestamp"`
}

// AttestVMRequest represents a request to attest a VM
type AttestVMRequest struct {
	VMID            string `codec:"vm_id"`
	Nonce           []byte `codec:"nonce"`
	PCRIndices      []int  `codec:"pcr_indices"`
	HashAlgorithm   string `codec:"hash_algorithm"`
	IncludeEventLog bool   `codec:"include_event_log"`
	PolicyID        string `codec:"policy_id"`
}

// AttestVMResponse represents an attest VM response
type AttestVMResponse struct {
	Attestation        *VMAttestationData `codec:"attestation"`
	Verified           bool               `codec:"verified"`
	VerificationStatus string             `codec:"verification_status"`
	VerificationError  string             `codec:"verification_error,omitempty"`
	Timestamp          int64              `codec:"timestamp"`
}

// AttestContainerRequest represents a request to attest a container
type AttestContainerRequest struct {
	ContainerID     string `codec:"container_id"`
	Nonce           []byte `codec:"nonce"`
	PCRIndices      []int  `codec:"pcr_indices"`
	HashAlgorithm   string `codec:"hash_algorithm"`
	IncludeEventLog bool   `codec:"include_event_log"`
	PolicyID        string `codec:"policy_id"`
}

// AttestContainerResponse represents an attest container response
type AttestContainerResponse struct {
	Attestation        *ContainerAttestData `codec:"attestation"`
	Verified           bool                 `codec:"verified"`
	VerificationStatus string               `codec:"verification_status"`
	VerificationError  string               `codec:"verification_error,omitempty"`
	Timestamp          int64                `codec:"timestamp"`
}

// AttestDeviceRequest represents a request to attest a device
type AttestDeviceRequest struct {
	DeviceID        string `codec:"device_id"`
	Nonce           []byte `codec:"nonce"`
	PCRIndices      []int  `codec:"pcr_indices"`
	HashAlgorithm   string `codec:"hash_algorithm"`
	IncludeEventLog bool   `codec:"include_event_log"`
	PolicyID        string `codec:"policy_id"`
}

// AttestDeviceResponse represents an attest device response
type AttestDeviceResponse struct {
	DeviceID     string                  `codec:"device_id"`
	DeviceType   string                  `codec:"device_type"`
	Verified     bool                    `codec:"verified"`
	QuoteData    []byte                  `codec:"quote_data"`
	Signature    []byte                  `codec:"signature"`
	PCRValues    map[int][]byte          `codec:"pcr_values"`
	Certificate  []byte                  `codec:"certificate"`
	Timestamp    int64                   `codec:"timestamp"`
	Metadata     map[string]string       `codec:"metadata"`
	PolicyResult *PolicyEvaluationResult `codec:"policy_result"`
}

// PolicyEvaluationResult represents a policy evaluation result for QUIC transport
type PolicyEvaluationResult struct {
	PolicyID    string   `codec:"policy_id"`
	PolicyName  string   `codec:"policy_name"`
	Passed      bool     `codec:"passed"`
	Details     []string `codec:"details"`
	EvaluatedAt int64    `codec:"evaluated_at"`
}

// ListReportsRequest represents a request to list attestation reports
type ListReportsRequest struct {
	HostID    string `codec:"host_id"`
	StartTime int64  `codec:"start_time"`
	EndTime   int64  `codec:"end_time"`
	Limit     int32  `codec:"limit"`
	Offset    int32  `codec:"offset"`
	Status    string `codec:"status"`
}

// ListReportsResponse represents a list reports response
type ListReportsResponse struct {
	Reports   []AttestationReportData `codec:"reports"`
	Count     int32                   `codec:"count"`
	Total     int32                   `codec:"total"`
	Timestamp int64                   `codec:"timestamp"`
}

// AttestationReportData represents an attestation report for QUIC transport
type AttestationReportData struct {
	ID         string            `codec:"id"`
	HostID     string            `codec:"host_id"`
	Type       string            `codec:"type"`
	WorkloadID string            `codec:"workload_id"`
	Status     string            `codec:"status"`
	ManifestID string            `codec:"manifest_id"`
	PolicyID   string            `codec:"policy_id"`
	CreatedAt  int64             `codec:"created_at"`
	ExpiresAt  int64             `codec:"expires_at"`
	Metadata   map[string]string `codec:"metadata"`
}

// GetReportRequest represents a request to get an attestation report
type GetReportRequest struct {
	ID string `codec:"id"`
}

// GetReportResponse represents a get report response
type GetReportResponse struct {
	Report    *AttestationReportData `codec:"report"`
	Timestamp int64                  `codec:"timestamp"`
}

// CreatePolicyRequest represents a request to create an attestation policy
type CreatePolicyRequest struct {
	Name         string            `codec:"name"`
	Description  string            `codec:"description"`
	PCRPolicy    *PCRPolicyData    `codec:"pcr_policy"`
	GoldenValues map[int][]byte    `codec:"golden_values"`
	MaxAge       int64             `codec:"max_age"`
	Active       bool              `codec:"active"`
	Metadata     map[string]string `codec:"metadata"`
}

// PCRPolicyData represents a PCR policy for QUIC transport
type PCRPolicyData struct {
	RequiredPCRs    []int          `codec:"required_pcrs"`
	AllowedHashAlgs []string       `codec:"allowed_hash_algs"`
	ExpectedValues  map[int][]byte `codec:"expected_values"`
	AllowZeroValues bool           `codec:"allow_zero_values"`
}

// CreatePolicyResponse represents a create policy response
type CreatePolicyResponse struct {
	Policy    *AttestationPolicyData `codec:"policy"`
	Timestamp int64                  `codec:"timestamp"`
}

// AttestationPolicyData represents an attestation policy for QUIC transport
type AttestationPolicyData struct {
	ID           string            `codec:"id"`
	Name         string            `codec:"name"`
	Description  string            `codec:"description"`
	PCRPolicy    *PCRPolicyData    `codec:"pcr_policy"`
	GoldenValues map[int][]byte    `codec:"golden_values"`
	MaxAge       int64             `codec:"max_age"`
	Active       bool              `codec:"active"`
	CreatedAt    int64             `codec:"created_at"`
	UpdatedAt    int64             `codec:"updated_at"`
	Metadata     map[string]string `codec:"metadata"`
}

// ListPoliciesRequest represents a request to list attestation policies
type ListPoliciesRequest struct {
	Name   string `codec:"name"`
	Limit  int32  `codec:"limit"`
	Offset int32  `codec:"offset"`
	Active bool   `codec:"active"`
}

// ListPoliciesResponse represents a list policies response
type ListPoliciesResponse struct {
	Policies  []AttestationPolicyData `codec:"policies"`
	Count     int32                   `codec:"count"`
	Total     int32                   `codec:"total"`
	Timestamp int64                   `codec:"timestamp"`
}

// =============================================================================
// Handler Methods
// =============================================================================

// handleGetManifest retrieves an attestation manifest
func (h *AttestationHandler) handleGetManifest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrAttestationServiceNotAvailable)
	}

	var getReq GetManifestRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrAttestationDecodingFailed{Cause: err})
	}

	m, err := h.service.GetManifest(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get manifest")
		return h.attestationErrorResponse(err)
	}

	if m == nil {
		return h.errorResponse(quicwire.StatusNotFound, ErrAttestationManifestNotFound(getReq))
	}

	resp := &GetManifestResponse{
		Manifest:  h.manifestToData(m),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrAttestationEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleBuildManifest builds a new attestation manifest
func (h *AttestationHandler) handleBuildManifest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrAttestationServiceNotAvailable)
	}

	var buildReq BuildManifestRequest
	if err := quicwire.DecodePayload(req.Payload, &buildReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrAttestationDecodingFailed{Cause: err})
	}

	// Validate and parse request
	config, err := h.parseBuildManifestRequest(&buildReq)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	m, err := h.service.BuildManifest(ctx, config)
	if err != nil {
		h.logger.Error(err, "failed to build manifest")
		return h.attestationErrorResponse(err)
	}

	resp := &BuildManifestResponse{
		Manifest:  h.manifestToData(m),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrAttestationEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVerifyManifest verifies an attestation manifest
func (h *AttestationHandler) handleVerifyManifest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrAttestationServiceNotAvailable)
	}

	var verifyReq VerifyManifestRequest
	if err := quicwire.DecodePayload(req.Payload, &verifyReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrAttestationDecodingFailed{Cause: err})
	}

	if verifyReq.Manifest == nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrAttestationMissingManifest)
	}

	// Convert request to manifest
	m, err := h.dataToManifest(verifyReq.Manifest)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	// Parse verify options
	opts := &AttestationVerifyManifestOptions{
		ExpectedNonce: verifyReq.ExpectedNonce,
		PublicKeyPEM:  verifyReq.PublicKeyPEM,
		ExpectedPCRs:  verifyReq.ExpectedPCRs,
	}

	result, err := h.service.VerifyManifest(ctx, m, opts)
	if err != nil {
		h.logger.Error(err, "failed to verify manifest")
		return h.attestationErrorResponse(err)
	}

	resp := h.verificationResultToResponse(result)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrAttestationEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleCollectHostAttestation collects host attestation
func (h *AttestationHandler) handleCollectHostAttestation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrAttestationServiceNotAvailable)
	}

	var collectReq CollectHostAttestationRequest
	if err := quicwire.DecodePayload(req.Payload, &collectReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrAttestationDecodingFailed{Cause: err})
	}

	opts, err := h.parseCollectOptions(&collectReq)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	attestation, err := h.service.CollectHostAttestation(ctx, opts)
	if err != nil {
		h.logger.Error(err, "failed to collect host attestation")
		return h.attestationErrorResponse(err)
	}

	resp := &CollectHostAttestationResponse{
		Attestation: h.hostAttestationToData(attestation),
		Timestamp:   time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrAttestationEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleAttestVM performs VM attestation
func (h *AttestationHandler) handleAttestVM(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrAttestationServiceNotAvailable)
	}

	var attestReq AttestVMRequest
	if err := quicwire.DecodePayload(req.Payload, &attestReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrAttestationDecodingFailed{Cause: err})
	}

	if attestReq.VMID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrAttestationMissingVMID)
	}

	opts, err := h.parseWorkloadAttestOptions(&attestReq.Nonce, attestReq.PCRIndices,
		attestReq.HashAlgorithm, attestReq.IncludeEventLog, attestReq.PolicyID)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	attestation, err := h.service.AttestVM(ctx, attestReq.VMID, opts)
	if err != nil {
		h.logger.Error(err, "failed to attest VM")
		return h.attestationErrorResponse(err)
	}

	v := verdict.VerifyVMAttestation(attestation, opts.Nonce)
	resp := &AttestVMResponse{
		Attestation:        h.vmAttestationToData(attestation),
		Verified:           v.Verified,
		VerificationStatus: string(v.Status),
		VerificationError:  v.Reason,
		Timestamp:          time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrAttestationEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleAttestContainer performs container attestation
func (h *AttestationHandler) handleAttestContainer(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrAttestationServiceNotAvailable)
	}

	var attestReq AttestContainerRequest
	if err := quicwire.DecodePayload(req.Payload, &attestReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrAttestationDecodingFailed{Cause: err})
	}

	if attestReq.ContainerID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrAttestationMissingContainerID)
	}

	opts, err := h.parseWorkloadAttestOptions(&attestReq.Nonce, attestReq.PCRIndices,
		attestReq.HashAlgorithm, attestReq.IncludeEventLog, attestReq.PolicyID)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	attestation, err := h.service.AttestContainer(ctx, attestReq.ContainerID, opts)
	if err != nil {
		h.logger.Error(err, "failed to attest container")
		return h.attestationErrorResponse(err)
	}

	v := verdict.VerifyContainerAttestation(attestation)
	resp := &AttestContainerResponse{
		Attestation:        h.containerAttestationToData(attestation),
		Verified:           v.Verified,
		VerificationStatus: string(v.Status),
		VerificationError:  v.Reason,
		Timestamp:          time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrAttestationEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleAttestDevice performs device attestation
func (h *AttestationHandler) handleAttestDevice(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrAttestationServiceNotAvailable)
	}

	var attestReq AttestDeviceRequest
	if err := quicwire.DecodePayload(req.Payload, &attestReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrAttestationDecodingFailed{Cause: err})
	}

	if attestReq.DeviceID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrAttestationMissingDeviceID)
	}

	opts, err := h.parseWorkloadAttestOptions(&attestReq.Nonce, attestReq.PCRIndices,
		attestReq.HashAlgorithm, attestReq.IncludeEventLog, attestReq.PolicyID)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	result, err := h.service.AttestDevice(ctx, attestReq.DeviceID, opts)
	if err != nil {
		h.logger.Error(err, "failed to attest device")
		return h.attestationErrorResponse(err)
	}

	resp := h.deviceResultToResponse(result)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrAttestationEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListReports lists attestation reports
func (h *AttestationHandler) handleListReports(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrAttestationServiceNotAvailable)
	}

	var listReq ListReportsRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrAttestationDecodingFailed{Cause: err})
	}

	filter := h.parseReportFilter(&listReq)

	reports, total, err := h.service.ListReports(ctx, filter)
	if err != nil {
		h.logger.Error(err, "failed to list reports")
		return h.attestationErrorResponse(err)
	}

	reportData := make([]AttestationReportData, 0, len(reports))
	for _, r := range reports {
		reportData = append(reportData, h.reportToData(r))
	}

	resp := &ListReportsResponse{
		Reports:   reportData,
		Count:     int32(len(reportData)),
		Total:     int32(total),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrAttestationEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetReport retrieves an attestation report by ID
func (h *AttestationHandler) handleGetReport(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrAttestationServiceNotAvailable)
	}

	var getReq GetReportRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrAttestationDecodingFailed{Cause: err})
	}

	if getReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrAttestationMissingReportID)
	}

	report, err := h.service.GetReport(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get report")
		return h.attestationErrorResponse(err)
	}

	if report == nil {
		return h.errorResponse(quicwire.StatusNotFound, ErrAttestationReportNotFound(getReq))
	}

	reportData := h.reportToData(report)
	resp := &GetReportResponse{
		Report:    &reportData,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrAttestationEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleCreatePolicy creates an attestation policy
func (h *AttestationHandler) handleCreatePolicy(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrAttestationServiceNotAvailable)
	}

	var createReq CreatePolicyRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrAttestationDecodingFailed{Cause: err})
	}

	if createReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrAttestationMissingPolicyName)
	}

	policyReq := h.dataToPolicyCreateRequest(&createReq)

	policy, err := h.service.CreatePolicy(ctx, policyReq)
	if err != nil {
		h.logger.Error(err, "failed to create policy")
		return h.attestationErrorResponse(err)
	}

	resp := &CreatePolicyResponse{
		Policy:    h.policyToData(policy),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrAttestationEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListPolicies lists attestation policies
func (h *AttestationHandler) handleListPolicies(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrAttestationServiceNotAvailable)
	}

	var listReq ListPoliciesRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrAttestationDecodingFailed{Cause: err})
	}

	filter := h.parsePolicyFilter(&listReq)

	policies, total, err := h.service.ListPolicies(ctx, filter)
	if err != nil {
		h.logger.Error(err, "failed to list policies")
		return h.attestationErrorResponse(err)
	}

	policyData := make([]AttestationPolicyData, 0, len(policies))
	for _, p := range policies {
		policyData = append(policyData, *h.policyToData(p))
	}

	resp := &ListPoliciesResponse{
		Policies:  policyData,
		Count:     int32(len(policyData)),
		Total:     int32(total),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrAttestationEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Helper Methods - Request Parsing
// =============================================================================

// parseBuildManifestRequest parses and validates a build manifest request
func (h *AttestationHandler) parseBuildManifestRequest(req *BuildManifestRequest) (*AttestationBuildManifestConfig, error) {
	config := &AttestationBuildManifestConfig{
		HostID:            req.HostID,
		Nonce:             req.Nonce,
		IncludeVMs:        req.IncludeVMs,
		IncludeContainers: req.IncludeContainers,
		VMIDs:             req.VMIDs,
		ContainerIDs:      req.ContainerIDs,
		Sign:              req.Sign,
	}

	// Validate nonce if provided
	if len(req.Nonce) > 0 && len(req.Nonce) < 16 {
		return nil, ErrAttestationInvalidNonce
	}

	// Parse hash algorithm
	if req.HashAlgorithm != "" {
		if !h.isValidHashAlgorithm(req.HashAlgorithm) {
			return nil, ErrAttestationInvalidHashAlgorithm
		}
		config.HashAlgorithm = h.parseHashAlgorithm(req.HashAlgorithm)
	} else {
		config.HashAlgorithm = manifest.HashAlgorithmSHA256
	}

	// Validate and parse PCR indices
	if len(req.PCRIndices) > 0 {
		if err := h.validatePCRIndices(req.PCRIndices); err != nil {
			return nil, err
		}
		config.PCRIndices = req.PCRIndices
	} else {
		config.PCRIndices = h.getDefaultPCRIndices()
	}

	return config, nil
}

// parseCollectOptions parses collect attestation options
func (h *AttestationHandler) parseCollectOptions(req *CollectHostAttestationRequest) (*AttestationCollectOptions, error) {
	opts := &AttestationCollectOptions{
		Nonce:           req.Nonce,
		IncludeEventLog: req.IncludeEventLog,
	}

	// Validate nonce if provided
	if len(req.Nonce) > 0 && len(req.Nonce) < 16 {
		return nil, ErrAttestationInvalidNonce
	}

	if req.HashAlgorithm != "" {
		if !h.isValidHashAlgorithm(req.HashAlgorithm) {
			return nil, ErrAttestationInvalidHashAlgorithm
		}
		opts.HashAlgorithm = h.parseHashAlgorithm(req.HashAlgorithm)
	} else {
		opts.HashAlgorithm = manifest.HashAlgorithmSHA256
	}

	if len(req.PCRIndices) > 0 {
		if err := h.validatePCRIndices(req.PCRIndices); err != nil {
			return nil, err
		}
		opts.PCRIndices = req.PCRIndices
	} else {
		opts.PCRIndices = h.getDefaultPCRIndices()
	}

	return opts, nil
}

// parseWorkloadAttestOptions parses workload attestation options
func (h *AttestationHandler) parseWorkloadAttestOptions(nonce *[]byte, pcrIndices []int,
	hashAlg string, includeEventLog bool, policyID string) (*AttestationCollectOptions, error) {

	opts := &AttestationCollectOptions{
		IncludeEventLog: includeEventLog,
		PolicyID:        policyID,
	}

	if nonce != nil {
		opts.Nonce = *nonce
		if len(*nonce) > 0 && len(*nonce) < 16 {
			return nil, ErrAttestationInvalidNonce
		}
	}

	if hashAlg != "" {
		if !h.isValidHashAlgorithm(hashAlg) {
			return nil, ErrAttestationInvalidHashAlgorithm
		}
		opts.HashAlgorithm = h.parseHashAlgorithm(hashAlg)
	} else {
		opts.HashAlgorithm = manifest.HashAlgorithmSHA256
	}

	if len(pcrIndices) > 0 {
		if err := h.validatePCRIndices(pcrIndices); err != nil {
			return nil, err
		}
		opts.PCRIndices = pcrIndices
	} else {
		opts.PCRIndices = h.getDefaultPCRIndices()
	}

	return opts, nil
}

// parseReportFilter parses report filter from request
func (h *AttestationHandler) parseReportFilter(req *ListReportsRequest) *AttestationReportFilter {
	filter := &AttestationReportFilter{
		HostID: req.HostID,
		Status: req.Status,
		Limit:  int(req.Limit),
		Offset: int(req.Offset),
	}

	if req.Limit <= 0 {
		filter.Limit = int(attestationDefaultLimit)
	} else if req.Limit > attestationMaxLimit {
		filter.Limit = int(attestationMaxLimit)
	}

	if req.StartTime > 0 {
		filter.StartTime = time.Unix(req.StartTime, 0)
	}

	if req.EndTime > 0 {
		filter.EndTime = time.Unix(req.EndTime, 0)
	}

	return filter
}

// parsePolicyFilter parses policy filter from request
func (h *AttestationHandler) parsePolicyFilter(req *ListPoliciesRequest) *AttestationPolicyListFilter {
	filter := &AttestationPolicyListFilter{
		Name:   req.Name,
		Limit:  int(req.Limit),
		Offset: int(req.Offset),
		Active: req.Active,
	}

	if req.Limit <= 0 {
		filter.Limit = int(attestationDefaultLimit)
	} else if req.Limit > attestationMaxLimit {
		filter.Limit = int(attestationMaxLimit)
	}

	return filter
}

// =============================================================================
// Helper Methods - Data Conversion
// =============================================================================

// manifestToData converts a HostManifest to ManifestData
func (h *AttestationHandler) manifestToData(m *manifest.HostManifest) *ManifestData {
	if m == nil {
		return nil
	}

	data := &ManifestData{
		ID:                 m.ID,
		HostID:             m.HostID,
		Timestamp:          m.Timestamp.Unix(),
		Nonce:              m.Nonce,
		MerkleRoot:         m.MerkleRoot,
		Signature:          m.Signature,
		SignatureAlgorithm: m.SignatureAlgorithm,
		Version:            m.Version,
		Metadata:           m.Metadata,
	}

	if m.Host != nil {
		data.Host = h.hostAttestationToData(m.Host)
	}

	if len(m.VMs) > 0 {
		data.VMs = make([]VMAttestationData, 0, len(m.VMs))
		for _, vm := range m.VMs {
			data.VMs = append(data.VMs, *h.vmAttestationToData(&vm))
		}
	}

	if len(m.Containers) > 0 {
		data.Containers = make([]ContainerAttestData, 0, len(m.Containers))
		for _, c := range m.Containers {
			data.Containers = append(data.Containers, *h.containerAttestationToData(&c))
		}
	}

	return data
}

// dataToManifest converts ManifestData to HostManifest
func (h *AttestationHandler) dataToManifest(data *ManifestData) (*manifest.HostManifest, error) {
	if data == nil {
		return nil, ErrAttestationMissingManifest
	}

	m := &manifest.HostManifest{
		ID:                 data.ID,
		HostID:             data.HostID,
		Timestamp:          time.Unix(data.Timestamp, 0),
		Nonce:              data.Nonce,
		MerkleRoot:         data.MerkleRoot,
		Signature:          data.Signature,
		SignatureAlgorithm: data.SignatureAlgorithm,
		Version:            data.Version,
		Metadata:           data.Metadata,
	}

	if data.Host != nil {
		m.Host = h.dataToHostAttestation(data.Host)
	}

	if len(data.VMs) > 0 {
		m.VMs = make([]manifest.VMAttestation, 0, len(data.VMs))
		for _, vm := range data.VMs {
			m.VMs = append(m.VMs, *h.dataToVMAttestation(&vm))
		}
	}

	if len(data.Containers) > 0 {
		m.Containers = make([]manifest.ContainerAttestation, 0, len(data.Containers))
		for _, c := range data.Containers {
			m.Containers = append(m.Containers, *h.dataToContainerAttestation(&c))
		}
	}

	return m, nil
}

// hostAttestationToData converts HostAttestation to HostAttestationData
func (h *AttestationHandler) hostAttestationToData(a *manifest.HostAttestation) *HostAttestationData {
	if a == nil {
		return nil
	}

	data := &HostAttestationData{
		QuoteData:          a.QuoteData,
		Signature:          a.Signature,
		SignatureAlgorithm: a.SignatureAlgorithm,
		PCRDigest:          a.PCRDigest,
		Nonce:              a.Nonce,
		Timestamp:          a.Timestamp.Unix(),
		AKPublicKey:        a.AKPublicKey,
		IDevIDCertificate:  a.IDevIDCertificate,
		HashAlgorithm:      a.HashAlgorithm.String(),
		FirmwareVersion:    a.FirmwareVersion,
	}

	if len(a.PCRs) > 0 {
		data.PCRs = make([]PCRValueData, 0, len(a.PCRs))
		for _, pcr := range a.PCRs {
			data.PCRs = append(data.PCRs, PCRValueData{
				Index:     pcr.Index,
				Value:     pcr.Value,
				Algorithm: pcr.Algorithm.String(),
			})
		}
	}

	return data
}

// dataToHostAttestation converts HostAttestationData to HostAttestation
func (h *AttestationHandler) dataToHostAttestation(data *HostAttestationData) *manifest.HostAttestation {
	if data == nil {
		return nil
	}

	a := &manifest.HostAttestation{
		QuoteData:          data.QuoteData,
		Signature:          data.Signature,
		SignatureAlgorithm: data.SignatureAlgorithm,
		PCRDigest:          data.PCRDigest,
		Nonce:              data.Nonce,
		Timestamp:          time.Unix(data.Timestamp, 0),
		AKPublicKey:        data.AKPublicKey,
		IDevIDCertificate:  data.IDevIDCertificate,
		HashAlgorithm:      h.parseHashAlgorithm(data.HashAlgorithm),
		FirmwareVersion:    data.FirmwareVersion,
	}

	if len(data.PCRs) > 0 {
		a.PCRs = make([]manifest.PCRValue, 0, len(data.PCRs))
		for _, pcr := range data.PCRs {
			a.PCRs = append(a.PCRs, manifest.PCRValue{
				Index:     pcr.Index,
				Value:     pcr.Value,
				Algorithm: h.parseHashAlgorithm(pcr.Algorithm),
			})
		}
	}

	return a
}

// vmAttestationToData converts VMAttestation to VMAttestationData
func (h *AttestationHandler) vmAttestationToData(a *manifest.VMAttestation) *VMAttestationData {
	if a == nil {
		return nil
	}

	data := &VMAttestationData{
		VMID:               a.VMID,
		HostID:             a.HostID,
		QuoteData:          a.QuoteData,
		Signature:          a.Signature,
		SignatureAlgorithm: a.SignatureAlgorithm,
		PCRDigest:          a.PCRDigest,
		Nonce:              a.Nonce,
		Timestamp:          a.Timestamp.Unix(),
		AIKPublicKey:       a.AIKPublicKey,
		EKCertificate:      a.EKCertificate,
		WorkloadPCR:        a.WorkloadPCR,
		HashAlgorithm:      a.HashAlgorithm.String(),
		Metadata:           a.Metadata,
	}

	if len(a.PCRs) > 0 {
		data.PCRs = make([]PCRValueData, 0, len(a.PCRs))
		for _, pcr := range a.PCRs {
			data.PCRs = append(data.PCRs, PCRValueData{
				Index:     pcr.Index,
				Value:     pcr.Value,
				Algorithm: pcr.Algorithm.String(),
			})
		}
	}

	return data
}

// dataToVMAttestation converts VMAttestationData to VMAttestation
func (h *AttestationHandler) dataToVMAttestation(data *VMAttestationData) *manifest.VMAttestation {
	if data == nil {
		return nil
	}

	a := &manifest.VMAttestation{
		VMID:               data.VMID,
		HostID:             data.HostID,
		QuoteData:          data.QuoteData,
		Signature:          data.Signature,
		SignatureAlgorithm: data.SignatureAlgorithm,
		PCRDigest:          data.PCRDigest,
		Nonce:              data.Nonce,
		Timestamp:          time.Unix(data.Timestamp, 0),
		AIKPublicKey:       data.AIKPublicKey,
		EKCertificate:      data.EKCertificate,
		WorkloadPCR:        data.WorkloadPCR,
		HashAlgorithm:      h.parseHashAlgorithm(data.HashAlgorithm),
		Metadata:           data.Metadata,
	}

	if len(data.PCRs) > 0 {
		a.PCRs = make([]manifest.PCRValue, 0, len(data.PCRs))
		for _, pcr := range data.PCRs {
			a.PCRs = append(a.PCRs, manifest.PCRValue{
				Index:     pcr.Index,
				Value:     pcr.Value,
				Algorithm: h.parseHashAlgorithm(pcr.Algorithm),
			})
		}
	}

	return a
}

// containerAttestationToData converts ContainerAttestation to ContainerAttestData
func (h *AttestationHandler) containerAttestationToData(a *manifest.ContainerAttestation) *ContainerAttestData {
	if a == nil {
		return nil
	}

	return &ContainerAttestData{
		ContainerID: a.ContainerID,
		ImageID:     a.ImageID,
		ImageDigest: a.ImageDigest,
		Digest:      a.Digest,
		PCRValue:    a.PCRValue,
		Timestamp:   a.Timestamp.Unix(),
		Metadata:    a.Metadata,
	}
}

// dataToContainerAttestation converts ContainerAttestData to ContainerAttestation
func (h *AttestationHandler) dataToContainerAttestation(data *ContainerAttestData) *manifest.ContainerAttestation {
	if data == nil {
		return nil
	}

	return &manifest.ContainerAttestation{
		ContainerID: data.ContainerID,
		ImageID:     data.ImageID,
		ImageDigest: data.ImageDigest,
		Digest:      data.Digest,
		PCRValue:    data.PCRValue,
		Timestamp:   time.Unix(data.Timestamp, 0),
		Metadata:    data.Metadata,
	}
}

// verificationResultToResponse converts VerificationResult to VerifyManifestResponse
func (h *AttestationHandler) verificationResultToResponse(r *manifest.VerificationResult) *VerifyManifestResponse {
	if r == nil {
		return nil
	}

	return &VerifyManifestResponse{
		Valid:                      r.Status == manifest.VerificationStatusVerified,
		Status:                     r.Status.String(),
		SignatureValid:             r.SignatureValid,
		MerkleRootValid:            r.MerkleRootValid,
		NonceValid:                 r.NonceValid,
		TimestampValid:             r.TimestampValid,
		HostAttestationValid:       r.HostAttestationValid,
		VMAttestationsValid:        r.VMAttestationsValid,
		ContainerAttestationsValid: r.ContainerAttestationsValid,
		VerifiedAt:                 r.VerifiedAt.Unix(),
		Errors:                     r.Errors,
		VMErrors:                   r.VMErrors,
		ContainerErrors:            r.ContainerErrors,
	}
}

// deviceResultToResponse converts AttestationDeviceResult to AttestDeviceResponse
func (h *AttestationHandler) deviceResultToResponse(r *AttestationDeviceResult) *AttestDeviceResponse {
	if r == nil {
		return nil
	}

	resp := &AttestDeviceResponse{
		DeviceID:    r.DeviceID,
		DeviceType:  r.DeviceType,
		Verified:    r.Verified,
		QuoteData:   r.QuoteData,
		Signature:   r.Signature,
		PCRValues:   r.PCRValues,
		Certificate: r.Certificate,
		Timestamp:   r.Timestamp.Unix(),
		Metadata:    r.Metadata,
	}

	if r.PolicyResult != nil {
		resp.PolicyResult = &PolicyEvaluationResult{
			PolicyID:    r.PolicyResult.PolicyID,
			PolicyName:  r.PolicyResult.PolicyName,
			Passed:      r.PolicyResult.Passed,
			Details:     r.PolicyResult.Details,
			EvaluatedAt: r.PolicyResult.EvaluatedAt.Unix(),
		}
	}

	return resp
}

// reportToData converts AttestationReport to AttestationReportData
func (h *AttestationHandler) reportToData(r *AttestationReport) AttestationReportData {
	data := AttestationReportData{
		ID:         r.ID,
		HostID:     r.HostID,
		Type:       r.Type,
		WorkloadID: r.WorkloadID,
		Status:     r.Status,
		ManifestID: r.ManifestID,
		PolicyID:   r.PolicyID,
		CreatedAt:  r.CreatedAt.Unix(),
		Metadata:   r.Metadata,
	}

	if !r.ExpiresAt.IsZero() {
		data.ExpiresAt = r.ExpiresAt.Unix()
	}

	return data
}

// policyToData converts AttestationPolicy to AttestationPolicyData
func (h *AttestationHandler) policyToData(p *AttestationPolicy) *AttestationPolicyData {
	if p == nil {
		return nil
	}

	data := &AttestationPolicyData{
		ID:           p.ID,
		Name:         p.Name,
		Description:  p.Description,
		GoldenValues: p.GoldenValues,
		MaxAge:       p.MaxAge,
		Active:       p.Active,
		CreatedAt:    p.CreatedAt.Unix(),
		UpdatedAt:    p.UpdatedAt.Unix(),
		Metadata:     p.Metadata,
	}

	if p.PCRPolicy != nil {
		data.PCRPolicy = &PCRPolicyData{
			RequiredPCRs:    p.PCRPolicy.RequiredPCRs,
			AllowedHashAlgs: p.PCRPolicy.AllowedHashAlgs,
			ExpectedValues:  p.PCRPolicy.ExpectedValues,
			AllowZeroValues: p.PCRPolicy.AllowZeroValues,
		}
	}

	return data
}

// dataToPolicyCreateRequest converts CreatePolicyRequest to AttestationPolicyCreateRequest
func (h *AttestationHandler) dataToPolicyCreateRequest(req *CreatePolicyRequest) *AttestationPolicyCreateRequest {
	policyReq := &AttestationPolicyCreateRequest{
		Name:         req.Name,
		Description:  req.Description,
		GoldenValues: req.GoldenValues,
		MaxAge:       req.MaxAge,
		Active:       req.Active,
		Metadata:     req.Metadata,
	}

	if req.PCRPolicy != nil {
		policyReq.PCRPolicy = &AttestationPCRPolicyConfig{
			RequiredPCRs:    req.PCRPolicy.RequiredPCRs,
			AllowedHashAlgs: req.PCRPolicy.AllowedHashAlgs,
			ExpectedValues:  req.PCRPolicy.ExpectedValues,
			AllowZeroValues: req.PCRPolicy.AllowZeroValues,
		}
	}

	return policyReq
}

// =============================================================================
// Helper Methods - Utilities
// =============================================================================

// isValidHashAlgorithm checks if the provided string is a valid hash algorithm
func (h *AttestationHandler) isValidHashAlgorithm(alg string) bool {
	switch strings.ToLower(alg) {
	case "sha256", "sha384", "sha512", "sha1":
		return true
	default:
		return false
	}
}

// parseHashAlgorithm parses a hash algorithm string
func (h *AttestationHandler) parseHashAlgorithm(alg string) manifest.HashAlgorithm {
	switch strings.ToLower(alg) {
	case "sha384":
		return manifest.HashAlgorithmSHA384
	case "sha512":
		return manifest.HashAlgorithmSHA512
	case "sha1":
		return manifest.HashAlgorithmSHA1
	default:
		return manifest.HashAlgorithmSHA256
	}
}

// validatePCRIndices validates PCR indices are in valid range
func (h *AttestationHandler) validatePCRIndices(indices []int) error {
	for _, idx := range indices {
		if idx < 0 || idx > 23 {
			return ErrAttestationInvalidPCRIndex
		}
	}
	return nil
}

// getDefaultPCRIndices returns the default PCR indices for attestation
func (h *AttestationHandler) getDefaultPCRIndices() []int {
	return []int{0, 1, 2, 3, 4, 5, 6, 7, 14}
}

// errorResponse creates an error response with the given status and error
func (h *AttestationHandler) errorResponse(status byte, err error) *quicwire.Response {
	return &quicwire.Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// attestationErrorResponse maps attestation errors to appropriate status codes
func (h *AttestationHandler) attestationErrorResponse(err error) *quicwire.Response {
	var status byte

	switch {
	case errors.Is(err, manifest.ErrBuilderNotInitialized{}):
		status = quicwire.StatusUnavailable
	case errors.Is(err, manifest.ErrVerifierNotInitialized{}):
		status = quicwire.StatusUnavailable
	case errors.Is(err, manifest.ErrSignerNotInitialized{}):
		status = quicwire.StatusUnavailable
	case errors.Is(err, manifest.ErrHostNotAttested{}):
		status = quicwire.StatusNotFound
	case errors.Is(err, manifest.ErrEmptyManifest{}):
		status = quicwire.StatusInvalidArgument
	default:
		errMsg := err.Error()
		lowerMsg := strings.ToLower(errMsg)
		switch {
		case containsAnyAttest(lowerMsg, "not found", "does not exist", "no such"):
			status = quicwire.StatusNotFound
		case containsAnyAttest(lowerMsg, "invalid", "required", "must be", "cannot be"):
			status = quicwire.StatusInvalidArgument
		case containsAnyAttest(lowerMsg, "expired"):
			status = quicwire.StatusTimeout
		case containsAnyAttest(lowerMsg, "not available", "unavailable", "not initialized"):
			status = quicwire.StatusUnavailable
		case containsAnyAttest(lowerMsg, "permission", "denied", "unauthorized"):
			status = quicwire.StatusPermissionDenied
		case containsAnyAttest(lowerMsg, "already exists", "duplicate"):
			status = quicwire.StatusAlreadyExists
		default:
			status = quicwire.StatusInternalError
		}
	}

	return h.errorResponse(status, err)
}

// containsAnyAttest checks if s contains any of the substrings
func containsAnyAttest(s string, substrings ...string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// =============================================================================
// Attestation Error Types
// =============================================================================

// ErrAttestationEncodingFailed represents an encoding failure error
type ErrAttestationEncodingFailed struct {
	Cause error
}

func (e ErrAttestationEncodingFailed) Error() string {
	return "failed to encode attestation payload: " + e.Cause.Error()
}

func (e ErrAttestationEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrAttestationDecodingFailed represents a decoding failure error
type ErrAttestationDecodingFailed struct {
	Cause error
}

func (e ErrAttestationDecodingFailed) Error() string {
	return "failed to decode attestation payload: " + e.Cause.Error()
}

func (e ErrAttestationDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrAttestationOperationFailed represents an attestation operation failure
type ErrAttestationOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrAttestationOperationFailed) Error() string {
	return "attestation operation " + e.Operation + " failed: " + e.Cause.Error()
}

func (e ErrAttestationOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrAttestationManifestNotFound represents a manifest not found error
type ErrAttestationManifestNotFound struct {
	ID string
}

func (e ErrAttestationManifestNotFound) Error() string {
	if e.ID != "" {
		return "manifest not found: " + e.ID
	}
	return "manifest not found"
}

// ErrAttestationReportNotFound represents a report not found error
type ErrAttestationReportNotFound struct {
	ID string
}

func (e ErrAttestationReportNotFound) Error() string {
	if e.ID != "" {
		return "attestation report not found: " + e.ID
	}
	return "attestation report not found"
}

// ErrAttestationPolicyNotFound represents a policy not found error
type ErrAttestationPolicyNotFound struct {
	ID string
}

func (e ErrAttestationPolicyNotFound) Error() string {
	if e.ID != "" {
		return "attestation policy not found: " + e.ID
	}
	return "attestation policy not found"
}
