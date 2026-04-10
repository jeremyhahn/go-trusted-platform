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

// Package rest provides REST API handlers for the trusted platform services.
package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
)

// =============================================================================
// Attestation REST Handler Errors
// =============================================================================

// ErrAttestationServiceNotAvailable is returned when the attestation service
// is not configured or unavailable.
type ErrAttestationServiceNotAvailable struct{}

func (e ErrAttestationServiceNotAvailable) Error() string {
	return "attestation service not available"
}

// ErrInvalidManifestID is returned when a manifest ID is invalid or empty.
type ErrInvalidManifestID struct {
	ID string
}

func (e ErrInvalidManifestID) Error() string {
	if e.ID == "" {
		return "manifest ID is required"
	}
	return fmt.Sprintf("invalid manifest ID: %s", e.ID)
}

// ErrInvalidReportID is returned when a report ID is invalid or empty.
type ErrInvalidReportID struct {
	ID string
}

func (e ErrInvalidReportID) Error() string {
	if e.ID == "" {
		return "report ID is required"
	}
	return fmt.Sprintf("invalid report ID: %s", e.ID)
}

// ErrAttestationFailed is returned when an attestation operation fails.
type ErrAttestationFailed struct {
	Operation string
	Cause     error
}

func (e ErrAttestationFailed) Error() string {
	return fmt.Sprintf("attestation operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrAttestationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidNonce is returned when a nonce is invalid.
type ErrInvalidNonce struct {
	Reason string
}

func (e ErrInvalidNonce) Error() string {
	return fmt.Sprintf("invalid nonce: %s", e.Reason)
}

// ErrInvalidHashAlgorithm is returned when a hash algorithm is invalid.
type ErrInvalidHashAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidHashAlgorithm) Error() string {
	return fmt.Sprintf("invalid hash algorithm: %s (valid: sha256, sha384, sha512)", e.Algorithm)
}

// ErrManifestNotFound is returned when a manifest is not found.
type ErrManifestNotFound struct {
	ID string
}

func (e ErrManifestNotFound) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("manifest not found: %s", e.ID)
	}
	return "manifest not found"
}

// ErrReportNotFound is returned when an attestation report is not found.
type ErrReportNotFound struct {
	ID string
}

func (e ErrReportNotFound) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("attestation report not found: %s", e.ID)
	}
	return "attestation report not found"
}

// ErrAttestationPolicyNotFound is returned when an attestation policy is not found.
type ErrAttestationPolicyNotFound struct {
	ID string
}

func (e ErrAttestationPolicyNotFound) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("attestation policy not found: %s", e.ID)
	}
	return "attestation policy not found"
}

// ErrInvalidVMID is returned when a VM ID is invalid or empty.
type ErrInvalidVMID struct {
	ID string
}

func (e ErrInvalidVMID) Error() string {
	if e.ID == "" {
		return "VM ID is required"
	}
	return fmt.Sprintf("invalid VM ID: %s", e.ID)
}

// ErrInvalidDeviceID is returned when a device ID is invalid or empty.
type ErrInvalidDeviceID struct {
	ID string
}

func (e ErrInvalidDeviceID) Error() string {
	if e.ID == "" {
		return "device ID is required"
	}
	return fmt.Sprintf("invalid device ID: %s", e.ID)
}

// ErrInvalidPCRIndex is returned when a PCR index is invalid.
type ErrInvalidPCRIndex struct {
	Index int
}

func (e ErrInvalidPCRIndex) Error() string {
	return fmt.Sprintf("invalid PCR index: %d (valid: 0-23)", e.Index)
}

// =============================================================================
// Attestation Service Interface
// =============================================================================

// AttestationServiceInterface defines the interface for attestation operations.
type AttestationServiceInterface interface {
	// GetManifest retrieves an existing attestation manifest by ID or the current manifest.
	GetManifest(ctx context.Context, id string) (*manifest.HostManifest, error)

	// BuildManifest builds a new attestation manifest for the host and its workloads.
	BuildManifest(ctx context.Context, config *BuildManifestConfig) (*manifest.HostManifest, error)

	// VerifyManifest verifies an attestation manifest including signature and Merkle root.
	VerifyManifest(ctx context.Context, m *manifest.HostManifest, opts *VerifyManifestOptions) (*manifest.VerificationResult, error)

	// CollectHostAttestation collects attestation data from the host TPM.
	CollectHostAttestation(ctx context.Context, opts *CollectAttestationOptions) (*manifest.HostAttestation, error)

	// AttestVM performs attestation for a virtual machine.
	AttestVM(ctx context.Context, vmID string, opts *CollectAttestationOptions) (*manifest.VMAttestation, error)

	// AttestContainer performs attestation for a container.
	AttestContainer(ctx context.Context, containerID string, opts *CollectAttestationOptions) (*manifest.ContainerAttestation, error)

	// AttestDevice performs attestation for a device.
	AttestDevice(ctx context.Context, deviceID string, opts *CollectAttestationOptions) (*DeviceAttestationResult, error)

	// ListReports lists attestation reports with optional filtering.
	ListReports(ctx context.Context, filter *ReportFilter) ([]*AttestationReportResponse, int, error)

	// GetReport retrieves an attestation report by ID.
	GetReport(ctx context.Context, id string) (*AttestationReportResponse, error)

	// CreatePolicy creates a new attestation policy.
	CreatePolicy(ctx context.Context, policy *AttestationPolicyRequest) (*AttestationPolicyResponse, error)

	// ListPolicies lists attestation policies with optional filtering.
	ListPolicies(ctx context.Context, filter *AttestationPolicyFilter) ([]*AttestationPolicyResponse, int, error)
}

// BuildManifestConfig contains configuration for building a manifest.
type BuildManifestConfig struct {
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

// VerifyManifestOptions contains options for manifest verification.
type VerifyManifestOptions struct {
	ExpectedNonce []byte
	PublicKeyPEM  []byte
	ExpectedPCRs  map[int][]byte
}

// CollectAttestationOptions contains options for attestation collection.
type CollectAttestationOptions struct {
	Nonce           []byte
	PCRIndices      []int
	HashAlgorithm   manifest.HashAlgorithm
	IncludeEventLog bool
}

// ReportFilter contains filters for listing attestation reports.
type ReportFilter struct {
	HostID    string
	StartTime time.Time
	EndTime   time.Time
	Limit     int
	Offset    int
	Status    string
}

// AttestationPolicyFilter contains filters for listing attestation policies.
type AttestationPolicyFilter struct {
	Name   string
	Limit  int
	Offset int
	Active bool
}

// DeviceAttestationResult contains the result of a device attestation.
type DeviceAttestationResult struct {
	DeviceID     string                       `json:"device_id"`
	DeviceType   string                       `json:"device_type"`
	Verified     bool                         `json:"verified"`
	QuoteData    []byte                       `json:"quote_data,omitempty"`
	Signature    []byte                       `json:"signature,omitempty"`
	PCRValues    map[int][]byte               `json:"pcr_values,omitempty"`
	Certificate  []byte                       `json:"certificate,omitempty"`
	Timestamp    time.Time                    `json:"timestamp"`
	Metadata     map[string]string            `json:"metadata,omitempty"`
	PolicyResult *AttestationPolicyEvaluation `json:"policy_result,omitempty"`
}

// AttestationPolicyEvaluation contains the result of policy evaluation.
type AttestationPolicyEvaluation struct {
	PolicyID    string    `json:"policy_id"`
	PolicyName  string    `json:"policy_name"`
	Passed      bool      `json:"passed"`
	Details     []string  `json:"details,omitempty"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// =============================================================================
// Request/Response Types
// =============================================================================

// BuildManifestRequest represents a request to build a new attestation manifest.
type BuildManifestRequest struct {
	HostID            string   `json:"host_id,omitempty"`
	Nonce             string   `json:"nonce,omitempty"`
	PCRIndices        []int    `json:"pcr_indices,omitempty"`
	HashAlgorithm     string   `json:"hash_algorithm,omitempty"`
	IncludeVMs        bool     `json:"include_vms,omitempty"`
	IncludeContainers bool     `json:"include_containers,omitempty"`
	VMIDs             []string `json:"vm_ids,omitempty"`
	ContainerIDs      []string `json:"container_ids,omitempty"`
	Sign              bool     `json:"sign,omitempty"`
}

// VerifyManifestRequest represents a request to verify an attestation manifest.
type VerifyManifestRequest struct {
	Manifest      *ManifestRequest `json:"manifest"`
	ExpectedNonce string           `json:"expected_nonce,omitempty"`
	PublicKeyPEM  string           `json:"public_key_pem,omitempty"`
	ExpectedPCRs  map[int]string   `json:"expected_pcrs,omitempty"`
}

// ManifestRequest represents a manifest in API requests.
type ManifestRequest struct {
	ID                 string                    `json:"id"`
	HostID             string                    `json:"host_id"`
	Timestamp          time.Time                 `json:"timestamp"`
	Nonce              string                    `json:"nonce"`
	Host               *HostAttestationRequest   `json:"host,omitempty"`
	VMs                []VMAttestationRequest    `json:"vms,omitempty"`
	Containers         []ContainerAttestationReq `json:"containers,omitempty"`
	MerkleRoot         string                    `json:"merkle_root"`
	Signature          string                    `json:"signature,omitempty"`
	SignatureAlgorithm string                    `json:"signature_algorithm,omitempty"`
	Version            string                    `json:"version"`
	Metadata           map[string]string         `json:"metadata,omitempty"`
}

// HostAttestationRequest represents host attestation data in API requests.
type HostAttestationRequest struct {
	QuoteData          string        `json:"quote_data"`
	Signature          string        `json:"signature"`
	SignatureAlgorithm string        `json:"signature_algorithm"`
	PCRs               []PCRValueReq `json:"pcrs"`
	PCRDigest          string        `json:"pcr_digest"`
	Nonce              string        `json:"nonce"`
	Timestamp          time.Time     `json:"timestamp"`
	AKPublicKey        string        `json:"ak_public_key,omitempty"`
	IDevIDCertificate  string        `json:"idevid_certificate,omitempty"`
	HashAlgorithm      string        `json:"hash_algorithm"`
	FirmwareVersion    string        `json:"firmware_version,omitempty"`
}

// VMAttestationRequest represents VM attestation data in API requests.
type VMAttestationRequest struct {
	VMID               string            `json:"vm_id"`
	HostID             string            `json:"host_id"`
	QuoteData          string            `json:"quote_data"`
	Signature          string            `json:"signature"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	PCRs               []PCRValueReq     `json:"pcrs"`
	PCRDigest          string            `json:"pcr_digest"`
	Nonce              string            `json:"nonce"`
	Timestamp          time.Time         `json:"timestamp"`
	AIKPublicKey       string            `json:"aik_public_key,omitempty"`
	EKCertificate      string            `json:"ek_certificate,omitempty"`
	WorkloadPCR        string            `json:"workload_pcr,omitempty"`
	HashAlgorithm      string            `json:"hash_algorithm"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// ContainerAttestationReq represents container attestation data in API requests.
type ContainerAttestationReq struct {
	ContainerID string            `json:"container_id"`
	ImageID     string            `json:"image_id,omitempty"`
	ImageDigest string            `json:"image_digest,omitempty"`
	Digest      string            `json:"digest"`
	PCRValue    string            `json:"pcr_value"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// PCRValueReq represents a PCR value in API requests.
type PCRValueReq struct {
	Index     int    `json:"index"`
	Value     string `json:"value"`
	Algorithm string `json:"algorithm"`
}

// CollectHostAttestationRequest represents a request to collect host attestation.
type CollectHostAttestationRequest struct {
	Nonce           string `json:"nonce,omitempty"`
	PCRIndices      []int  `json:"pcr_indices,omitempty"`
	HashAlgorithm   string `json:"hash_algorithm,omitempty"`
	IncludeEventLog bool   `json:"include_event_log,omitempty"`
}

// AttestWorkloadRequest represents a request to attest a workload (VM/container/device).
type AttestWorkloadRequest struct {
	Nonce           string `json:"nonce,omitempty"`
	PCRIndices      []int  `json:"pcr_indices,omitempty"`
	HashAlgorithm   string `json:"hash_algorithm,omitempty"`
	IncludeEventLog bool   `json:"include_event_log,omitempty"`
	PolicyID        string `json:"policy_id,omitempty"`
}

// AttestationPolicyRequest represents a request to create an attestation policy.
type AttestationPolicyRequest struct {
	Name         string                `json:"name"`
	Description  string                `json:"description,omitempty"`
	PCRPolicy    *AttestationPCRPolicy `json:"pcr_policy,omitempty"`
	GoldenValues map[int]string        `json:"golden_values,omitempty"`
	MaxAge       int64                 `json:"max_age,omitempty"`
	Active       bool                  `json:"active"`
	Metadata     map[string]string     `json:"metadata,omitempty"`
}

// AttestationPCRPolicy defines expected PCR values for attestation.
type AttestationPCRPolicy struct {
	RequiredPCRs    []int          `json:"required_pcrs"`
	AllowedHashAlgs []string       `json:"allowed_hash_algorithms,omitempty"`
	ExpectedValues  map[int]string `json:"expected_values,omitempty"`
	AllowZeroValues bool           `json:"allow_zero_values,omitempty"`
}

// ManifestResponse represents an attestation manifest in API responses.
type ManifestResponse struct {
	ID                 string               `json:"id"`
	HostID             string               `json:"host_id"`
	Timestamp          time.Time            `json:"timestamp"`
	Nonce              string               `json:"nonce"`
	Host               *HostAttestationResp `json:"host,omitempty"`
	VMCount            int                  `json:"vm_count"`
	ContainerCount     int                  `json:"container_count"`
	MerkleRoot         string               `json:"merkle_root"`
	Signature          string               `json:"signature,omitempty"`
	SignatureAlgorithm string               `json:"signature_algorithm,omitempty"`
	Version            string               `json:"version"`
	Metadata           map[string]string    `json:"metadata,omitempty"`
}

// HostAttestationResp represents host attestation data in API responses.
type HostAttestationResp struct {
	QuoteData          string         `json:"quote_data"`
	Signature          string         `json:"signature"`
	SignatureAlgorithm string         `json:"signature_algorithm"`
	PCRs               []PCRValueResp `json:"pcrs"`
	PCRDigest          string         `json:"pcr_digest"`
	Nonce              string         `json:"nonce"`
	Timestamp          time.Time      `json:"timestamp"`
	AKPublicKeyPEM     string         `json:"ak_public_key_pem,omitempty"`
	HashAlgorithm      string         `json:"hash_algorithm"`
	FirmwareVersion    string         `json:"firmware_version,omitempty"`
}

// PCRValueResp represents a PCR value in API responses.
type PCRValueResp struct {
	Index     int    `json:"index"`
	Value     string `json:"value"`
	Algorithm string `json:"algorithm"`
}

// VerificationResponse represents the result of manifest verification.
type VerificationResponse struct {
	Valid                      bool              `json:"valid"`
	Status                     string            `json:"status"`
	SignatureValid             bool              `json:"signature_valid"`
	MerkleRootValid            bool              `json:"merkle_root_valid"`
	NonceValid                 bool              `json:"nonce_valid"`
	TimestampValid             bool              `json:"timestamp_valid"`
	HostAttestationValid       bool              `json:"host_attestation_valid"`
	VMAttestationsValid        bool              `json:"vm_attestations_valid"`
	ContainerAttestationsValid bool              `json:"container_attestations_valid"`
	VerifiedAt                 time.Time         `json:"verified_at"`
	Errors                     []string          `json:"errors,omitempty"`
	VMErrors                   map[string]string `json:"vm_errors,omitempty"`
	ContainerErrors            map[string]string `json:"container_errors,omitempty"`
}

// VMAttestationResponse represents a VM attestation in API responses.
type VMAttestationResponse struct {
	VMID               string            `json:"vm_id"`
	HostID             string            `json:"host_id"`
	Verified           bool              `json:"verified"`
	QuoteData          string            `json:"quote_data"`
	Signature          string            `json:"signature"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	PCRs               []PCRValueResp    `json:"pcrs"`
	PCRDigest          string            `json:"pcr_digest"`
	Nonce              string            `json:"nonce"`
	Timestamp          time.Time         `json:"timestamp"`
	AIKPublicKeyPEM    string            `json:"aik_public_key_pem,omitempty"`
	HashAlgorithm      string            `json:"hash_algorithm"`
	WorkloadPCR        string            `json:"workload_pcr,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// ContainerAttestationResp represents a container attestation in API responses.
type ContainerAttestationResp struct {
	ContainerID string            `json:"container_id"`
	ImageID     string            `json:"image_id,omitempty"`
	ImageDigest string            `json:"image_digest,omitempty"`
	Verified    bool              `json:"verified"`
	Digest      string            `json:"digest"`
	PCRValue    string            `json:"pcr_value"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// DeviceAttestationResponse represents a device attestation in API responses.
type DeviceAttestationResponse struct {
	DeviceID     string                           `json:"device_id"`
	DeviceType   string                           `json:"device_type"`
	Verified     bool                             `json:"verified"`
	QuoteData    string                           `json:"quote_data,omitempty"`
	Signature    string                           `json:"signature,omitempty"`
	PCRValues    map[int]string                   `json:"pcr_values,omitempty"`
	Certificate  string                           `json:"certificate,omitempty"`
	Timestamp    time.Time                        `json:"timestamp"`
	Metadata     map[string]string                `json:"metadata,omitempty"`
	PolicyResult *AttestationPolicyEvaluationResp `json:"policy_result,omitempty"`
}

// AttestationPolicyEvaluationResp represents policy evaluation in API responses.
type AttestationPolicyEvaluationResp struct {
	PolicyID    string    `json:"policy_id"`
	PolicyName  string    `json:"policy_name"`
	Passed      bool      `json:"passed"`
	Details     []string  `json:"details,omitempty"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// AttestationReportResponse represents an attestation report in API responses.
type AttestationReportResponse struct {
	ID         string            `json:"id"`
	HostID     string            `json:"host_id"`
	Type       string            `json:"type"`
	WorkloadID string            `json:"workload_id,omitempty"`
	Status     string            `json:"status"`
	ManifestID string            `json:"manifest_id,omitempty"`
	PolicyID   string            `json:"policy_id,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// AttestationPolicyResponse represents an attestation policy in API responses.
type AttestationPolicyResponse struct {
	ID           string                `json:"id"`
	Name         string                `json:"name"`
	Description  string                `json:"description,omitempty"`
	PCRPolicy    *AttestationPCRPolicy `json:"pcr_policy,omitempty"`
	GoldenValues map[int]string        `json:"golden_values,omitempty"`
	MaxAge       int64                 `json:"max_age,omitempty"`
	Active       bool                  `json:"active"`
	CreatedAt    time.Time             `json:"created_at"`
	UpdatedAt    time.Time             `json:"updated_at"`
	Metadata     map[string]string     `json:"metadata,omitempty"`
}

// ReportListResponse represents a list of attestation reports.
type ReportListResponse struct {
	Reports   []AttestationReportResponse `json:"reports"`
	Count     int                         `json:"count"`
	Total     int                         `json:"total"`
	Timestamp time.Time                   `json:"timestamp"`
}

// AttestationPolicyListResponse represents a list of attestation policies.
type AttestationPolicyListResponse struct {
	Policies  []AttestationPolicyResponse `json:"policies"`
	Count     int                         `json:"count"`
	Total     int                         `json:"total"`
	Timestamp time.Time                   `json:"timestamp"`
}

// =============================================================================
// Attestation Handlers
// =============================================================================

// AttestationHandlers provides REST API handlers for attestation operations.
type AttestationHandlers struct {
	service AttestationServiceInterface
	logger  *slog.Logger
}

// NewAttestationHandlers creates a new AttestationHandlers instance.
func NewAttestationHandlers(service AttestationServiceInterface, logger *slog.Logger) *AttestationHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &AttestationHandlers{
		service: service,
		logger:  logger,
	}
}

// RegisterAttestationRoutes registers all attestation routes on the provided router.
func (h *AttestationHandlers) RegisterAttestationRoutes(router *mux.Router) {
	// Manifest operations
	router.HandleFunc("/api/v1/attestation/manifest", h.handleGetManifest).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/attestation/manifest", h.handleBuildManifest).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/attestation/manifest/verify", h.handleVerifyManifest).Methods(http.MethodPost)

	// Host attestation
	router.HandleFunc("/api/v1/attestation/host", h.handleCollectHostAttestation).Methods(http.MethodPost)

	// Workload attestation
	router.HandleFunc("/api/v1/attestation/vm/{id}", h.handleAttestVM).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/attestation/container/{id}", h.handleAttestContainer).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/attestation/device/{id}", h.handleAttestDevice).Methods(http.MethodPost)

	// Reports
	router.HandleFunc("/api/v1/attestation/reports", h.handleListReports).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/attestation/reports/{id}", h.handleGetReport).Methods(http.MethodGet)

	// Policies
	router.HandleFunc("/api/v1/attestation/policies", h.handleCreatePolicy).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/attestation/policies", h.handleListPolicies).Methods(http.MethodGet)

	h.logger.Info("Attestation REST routes registered")
}

// =============================================================================
// Manifest Handlers
// =============================================================================

// handleGetManifest handles GET /api/v1/attestation/manifest
func (h *AttestationHandlers) handleGetManifest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrAttestationServiceNotAvailable{})
		return
	}

	// Get optional manifest ID from query parameter
	manifestID := r.URL.Query().Get("id")

	m, err := h.service.GetManifest(ctx, manifestID)
	if err != nil {
		h.logger.Error("Failed to get manifest", "error", err, "id", manifestID)
		h.writeAttestationError(w, "get_manifest", err)
		return
	}

	if m == nil {
		h.writeError(w, http.StatusNotFound, ErrManifestNotFound{ID: manifestID})
		return
	}

	resp := h.manifestToResponse(m)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleBuildManifest handles POST /api/v1/attestation/manifest
func (h *AttestationHandlers) handleBuildManifest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrAttestationServiceNotAvailable{})
		return
	}

	var req BuildManifestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Parse and validate request
	config, err := h.parseBuildManifestRequest(&req)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	m, err := h.service.BuildManifest(ctx, config)
	if err != nil {
		h.logger.Error("Failed to build manifest", "error", err)
		h.writeAttestationError(w, "build_manifest", err)
		return
	}

	resp := h.manifestToResponse(m)
	h.logger.Info("Manifest built", "id", m.ID, "host_id", m.HostID)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleVerifyManifest handles POST /api/v1/attestation/manifest/verify
func (h *AttestationHandlers) handleVerifyManifest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrAttestationServiceNotAvailable{})
		return
	}

	var req VerifyManifestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Manifest == nil {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "manifest"})
		return
	}

	// Convert request to manifest
	m, err := h.requestToManifest(req.Manifest)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	// Parse verify options
	opts, err := h.parseVerifyOptions(&req)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := h.service.VerifyManifest(ctx, m, opts)
	if err != nil {
		h.logger.Error("Failed to verify manifest", "error", err, "id", m.ID)
		h.writeAttestationError(w, "verify_manifest", err)
		return
	}

	resp := h.verificationResultToResponse(result)
	h.logger.Info("Manifest verified", "id", m.ID, "status", result.Status)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Host Attestation Handler
// =============================================================================

// handleCollectHostAttestation handles POST /api/v1/attestation/host
func (h *AttestationHandlers) handleCollectHostAttestation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrAttestationServiceNotAvailable{})
		return
	}

	var req CollectHostAttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	opts, err := h.parseCollectAttestationOptions(&req)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	attestation, err := h.service.CollectHostAttestation(ctx, opts)
	if err != nil {
		h.logger.Error("Failed to collect host attestation", "error", err)
		h.writeAttestationError(w, "collect_host_attestation", err)
		return
	}

	resp := h.hostAttestationToResponse(attestation)
	h.logger.Info("Host attestation collected")
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Workload Attestation Handlers
// =============================================================================

// handleAttestVM handles POST /api/v1/attestation/vm/{id}
func (h *AttestationHandlers) handleAttestVM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrAttestationServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vmID := vars["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidVMID{})
		return
	}

	var req AttestWorkloadRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	opts, err := h.parseWorkloadAttestationOptions(&req)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	attestation, err := h.service.AttestVM(ctx, vmID, opts)
	if err != nil {
		h.logger.Error("Failed to attest VM", "error", err, "vm_id", vmID)
		h.writeAttestationError(w, "attest_vm", err)
		return
	}

	resp := h.vmAttestationToResponse(attestation)
	h.logger.Info("VM attested", "vm_id", vmID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleAttestContainer handles POST /api/v1/attestation/container/{id}
func (h *AttestationHandlers) handleAttestContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrAttestationServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	var req AttestWorkloadRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	opts, err := h.parseWorkloadAttestationOptions(&req)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	attestation, err := h.service.AttestContainer(ctx, containerID, opts)
	if err != nil {
		h.logger.Error("Failed to attest container", "error", err, "container_id", containerID)
		h.writeAttestationError(w, "attest_container", err)
		return
	}

	resp := h.containerAttestationToResponse(attestation)
	h.logger.Info("Container attested", "container_id", containerID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleAttestDevice handles POST /api/v1/attestation/device/{id}
func (h *AttestationHandlers) handleAttestDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrAttestationServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	deviceID := vars["id"]
	if deviceID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidDeviceID{})
		return
	}

	var req AttestWorkloadRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	opts, err := h.parseWorkloadAttestationOptions(&req)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := h.service.AttestDevice(ctx, deviceID, opts)
	if err != nil {
		h.logger.Error("Failed to attest device", "error", err, "device_id", deviceID)
		h.writeAttestationError(w, "attest_device", err)
		return
	}

	resp := h.deviceAttestationToResponse(result)
	h.logger.Info("Device attested", "device_id", deviceID, "verified", result.Verified)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Report Handlers
// =============================================================================

// handleListReports handles GET /api/v1/attestation/reports
func (h *AttestationHandlers) handleListReports(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrAttestationServiceNotAvailable{})
		return
	}

	filter := h.parseReportFilter(r)

	reports, total, err := h.service.ListReports(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to list reports", "error", err)
		h.writeAttestationError(w, "list_reports", err)
		return
	}

	resp := ReportListResponse{
		Reports:   make([]AttestationReportResponse, 0, len(reports)),
		Count:     len(reports),
		Total:     total,
		Timestamp: time.Now().UTC(),
	}
	for _, report := range reports {
		resp.Reports = append(resp.Reports, *report)
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetReport handles GET /api/v1/attestation/reports/{id}
func (h *AttestationHandlers) handleGetReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrAttestationServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	reportID := vars["id"]
	if reportID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidReportID{})
		return
	}

	report, err := h.service.GetReport(ctx, reportID)
	if err != nil {
		h.logger.Error("Failed to get report", "error", err, "id", reportID)
		h.writeAttestationError(w, "get_report", err)
		return
	}

	if report == nil {
		h.writeError(w, http.StatusNotFound, ErrReportNotFound{ID: reportID})
		return
	}

	h.writeJSON(w, http.StatusOK, report)
}

// =============================================================================
// Policy Handlers
// =============================================================================

// handleCreatePolicy handles POST /api/v1/attestation/policies
func (h *AttestationHandlers) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrAttestationServiceNotAvailable{})
		return
	}

	var req AttestationPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Validate required fields
	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "name"})
		return
	}

	policy, err := h.service.CreatePolicy(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to create policy", "error", err, "name", req.Name)
		h.writeAttestationError(w, "create_policy", err)
		return
	}

	h.logger.Info("Policy created", "id", policy.ID, "name", policy.Name)
	h.writeJSON(w, http.StatusCreated, policy)
}

// handleListPolicies handles GET /api/v1/attestation/policies
func (h *AttestationHandlers) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrAttestationServiceNotAvailable{})
		return
	}

	filter := h.parsePolicyFilter(r)

	policies, total, err := h.service.ListPolicies(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to list policies", "error", err)
		h.writeAttestationError(w, "list_policies", err)
		return
	}

	resp := AttestationPolicyListResponse{
		Policies:  make([]AttestationPolicyResponse, 0, len(policies)),
		Count:     len(policies),
		Total:     total,
		Timestamp: time.Now().UTC(),
	}
	for _, policy := range policies {
		resp.Policies = append(resp.Policies, *policy)
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Helper Methods - Request Parsing
// =============================================================================

// parseBuildManifestRequest parses and validates a build manifest request.
func (h *AttestationHandlers) parseBuildManifestRequest(req *BuildManifestRequest) (*BuildManifestConfig, error) {
	config := &BuildManifestConfig{
		HostID:            req.HostID,
		IncludeVMs:        req.IncludeVMs,
		IncludeContainers: req.IncludeContainers,
		VMIDs:             req.VMIDs,
		ContainerIDs:      req.ContainerIDs,
		Sign:              req.Sign,
	}

	// Parse nonce
	if req.Nonce != "" {
		nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			return nil, ErrInvalidNonce{Reason: "invalid base64 encoding"}
		}
		if len(nonce) < 16 {
			return nil, ErrInvalidNonce{Reason: "nonce must be at least 16 bytes"}
		}
		config.Nonce = nonce
	}

	// Parse hash algorithm - validate input before parsing
	if req.HashAlgorithm != "" {
		if !h.isValidHashAlgorithmString(req.HashAlgorithm) {
			return nil, ErrInvalidHashAlgorithm{Algorithm: req.HashAlgorithm}
		}
		config.HashAlgorithm = h.parseHashAlgorithm(req.HashAlgorithm)
	} else {
		config.HashAlgorithm = manifest.HashAlgorithmSHA256
	}

	// Parse PCR indices
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

// parseVerifyOptions parses verify manifest options from a request.
func (h *AttestationHandlers) parseVerifyOptions(req *VerifyManifestRequest) (*VerifyManifestOptions, error) {
	opts := &VerifyManifestOptions{}

	if req.ExpectedNonce != "" {
		nonce, err := base64.StdEncoding.DecodeString(req.ExpectedNonce)
		if err != nil {
			return nil, ErrInvalidNonce{Reason: "invalid base64 encoding for expected_nonce"}
		}
		opts.ExpectedNonce = nonce
	}

	if req.PublicKeyPEM != "" {
		opts.PublicKeyPEM = []byte(req.PublicKeyPEM)
	}

	if len(req.ExpectedPCRs) > 0 {
		opts.ExpectedPCRs = make(map[int][]byte)
		for idx, valueB64 := range req.ExpectedPCRs {
			if idx < 0 || idx > 23 {
				return nil, ErrInvalidPCRIndex{Index: idx}
			}
			value, err := base64.StdEncoding.DecodeString(valueB64)
			if err != nil {
				return nil, ErrInvalidRequestBody{Reason: fmt.Sprintf("invalid base64 for PCR %d", idx)}
			}
			opts.ExpectedPCRs[idx] = value
		}
	}

	return opts, nil
}

// parseCollectAttestationOptions parses collect attestation options from a request.
func (h *AttestationHandlers) parseCollectAttestationOptions(req *CollectHostAttestationRequest) (*CollectAttestationOptions, error) {
	opts := &CollectAttestationOptions{
		IncludeEventLog: req.IncludeEventLog,
	}

	if req.Nonce != "" {
		nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			return nil, ErrInvalidNonce{Reason: "invalid base64 encoding"}
		}
		opts.Nonce = nonce
	}

	if req.HashAlgorithm != "" {
		if !h.isValidHashAlgorithmString(req.HashAlgorithm) {
			return nil, ErrInvalidHashAlgorithm{Algorithm: req.HashAlgorithm}
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

// parseWorkloadAttestationOptions parses workload attestation options from a request.
func (h *AttestationHandlers) parseWorkloadAttestationOptions(req *AttestWorkloadRequest) (*CollectAttestationOptions, error) {
	opts := &CollectAttestationOptions{
		IncludeEventLog: req.IncludeEventLog,
	}

	if req.Nonce != "" {
		nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			return nil, ErrInvalidNonce{Reason: "invalid base64 encoding"}
		}
		opts.Nonce = nonce
	}

	if req.HashAlgorithm != "" {
		if !h.isValidHashAlgorithmString(req.HashAlgorithm) {
			return nil, ErrInvalidHashAlgorithm{Algorithm: req.HashAlgorithm}
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

// parseReportFilter parses report filter from query parameters.
func (h *AttestationHandlers) parseReportFilter(r *http.Request) *ReportFilter {
	query := r.URL.Query()

	filter := &ReportFilter{
		HostID: query.Get("host_id"),
		Status: query.Get("status"),
		Limit:  ParseIntParam(r, "limit", 50),
		Offset: ParseIntParam(r, "offset", 0),
	}

	if startTimeStr := query.Get("start_time"); startTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filter.StartTime = t
		}
	}

	if endTimeStr := query.Get("end_time"); endTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filter.EndTime = t
		}
	}

	return filter
}

// parsePolicyFilter parses policy filter from query parameters.
func (h *AttestationHandlers) parsePolicyFilter(r *http.Request) *AttestationPolicyFilter {
	query := r.URL.Query()

	filter := &AttestationPolicyFilter{
		Name:   query.Get("name"),
		Limit:  ParseIntParam(r, "limit", 50),
		Offset: ParseIntParam(r, "offset", 0),
		Active: ParseBoolParam(r, "active", false),
	}

	return filter
}

// =============================================================================
// Helper Methods - Response Conversion
// =============================================================================

// manifestToResponse converts a HostManifest to ManifestResponse.
func (h *AttestationHandlers) manifestToResponse(m *manifest.HostManifest) *ManifestResponse {
	if m == nil {
		return nil
	}

	resp := &ManifestResponse{
		ID:             m.ID,
		HostID:         m.HostID,
		Timestamp:      m.Timestamp,
		Nonce:          base64.StdEncoding.EncodeToString(m.Nonce),
		VMCount:        len(m.VMs),
		ContainerCount: len(m.Containers),
		MerkleRoot:     base64.StdEncoding.EncodeToString(m.MerkleRoot),
		Version:        m.Version,
		Metadata:       m.Metadata,
	}

	if len(m.Signature) > 0 {
		resp.Signature = base64.StdEncoding.EncodeToString(m.Signature)
		resp.SignatureAlgorithm = m.SignatureAlgorithm
	}

	if m.Host != nil {
		resp.Host = h.hostAttestationToResponse(m.Host)
	}

	return resp
}

// hostAttestationToResponse converts a HostAttestation to HostAttestationResp.
func (h *AttestationHandlers) hostAttestationToResponse(a *manifest.HostAttestation) *HostAttestationResp {
	if a == nil {
		return nil
	}

	resp := &HostAttestationResp{
		QuoteData:          base64.StdEncoding.EncodeToString(a.QuoteData),
		Signature:          base64.StdEncoding.EncodeToString(a.Signature),
		SignatureAlgorithm: a.SignatureAlgorithm,
		PCRDigest:          base64.StdEncoding.EncodeToString(a.PCRDigest),
		Nonce:              base64.StdEncoding.EncodeToString(a.Nonce),
		Timestamp:          a.Timestamp,
		HashAlgorithm:      a.HashAlgorithm.String(),
		FirmwareVersion:    a.FirmwareVersion,
	}

	if len(a.AKPublicKey) > 0 {
		resp.AKPublicKeyPEM = string(a.AKPublicKey)
	}

	resp.PCRs = make([]PCRValueResp, 0, len(a.PCRs))
	for _, pcr := range a.PCRs {
		resp.PCRs = append(resp.PCRs, PCRValueResp{
			Index:     pcr.Index,
			Value:     base64.StdEncoding.EncodeToString(pcr.Value),
			Algorithm: pcr.Algorithm.String(),
		})
	}

	return resp
}

// vmAttestationToResponse converts a VMAttestation to VMAttestationResponse.
func (h *AttestationHandlers) vmAttestationToResponse(a *manifest.VMAttestation) *VMAttestationResponse {
	if a == nil {
		return nil
	}

	resp := &VMAttestationResponse{
		VMID:               a.VMID,
		HostID:             a.HostID,
		Verified:           true,
		QuoteData:          base64.StdEncoding.EncodeToString(a.QuoteData),
		Signature:          base64.StdEncoding.EncodeToString(a.Signature),
		SignatureAlgorithm: a.SignatureAlgorithm,
		PCRDigest:          base64.StdEncoding.EncodeToString(a.PCRDigest),
		Nonce:              base64.StdEncoding.EncodeToString(a.Nonce),
		Timestamp:          a.Timestamp,
		HashAlgorithm:      a.HashAlgorithm.String(),
		Metadata:           a.Metadata,
	}

	if len(a.AIKPublicKey) > 0 {
		resp.AIKPublicKeyPEM = string(a.AIKPublicKey)
	}

	if len(a.WorkloadPCR) > 0 {
		resp.WorkloadPCR = base64.StdEncoding.EncodeToString(a.WorkloadPCR)
	}

	resp.PCRs = make([]PCRValueResp, 0, len(a.PCRs))
	for _, pcr := range a.PCRs {
		resp.PCRs = append(resp.PCRs, PCRValueResp{
			Index:     pcr.Index,
			Value:     base64.StdEncoding.EncodeToString(pcr.Value),
			Algorithm: pcr.Algorithm.String(),
		})
	}

	return resp
}

// containerAttestationToResponse converts a ContainerAttestation to ContainerAttestationResp.
func (h *AttestationHandlers) containerAttestationToResponse(a *manifest.ContainerAttestation) *ContainerAttestationResp {
	if a == nil {
		return nil
	}

	return &ContainerAttestationResp{
		ContainerID: a.ContainerID,
		ImageID:     a.ImageID,
		ImageDigest: a.ImageDigest,
		Verified:    true,
		Digest:      base64.StdEncoding.EncodeToString(a.Digest),
		PCRValue:    base64.StdEncoding.EncodeToString(a.PCRValue),
		Timestamp:   a.Timestamp,
		Metadata:    a.Metadata,
	}
}

// deviceAttestationToResponse converts a DeviceAttestationResult to DeviceAttestationResponse.
func (h *AttestationHandlers) deviceAttestationToResponse(r *DeviceAttestationResult) *DeviceAttestationResponse {
	if r == nil {
		return nil
	}

	resp := &DeviceAttestationResponse{
		DeviceID:   r.DeviceID,
		DeviceType: r.DeviceType,
		Verified:   r.Verified,
		Timestamp:  r.Timestamp,
		Metadata:   r.Metadata,
	}

	if len(r.QuoteData) > 0 {
		resp.QuoteData = base64.StdEncoding.EncodeToString(r.QuoteData)
	}

	if len(r.Signature) > 0 {
		resp.Signature = base64.StdEncoding.EncodeToString(r.Signature)
	}

	if len(r.Certificate) > 0 {
		resp.Certificate = base64.StdEncoding.EncodeToString(r.Certificate)
	}

	if len(r.PCRValues) > 0 {
		resp.PCRValues = make(map[int]string)
		for idx, value := range r.PCRValues {
			resp.PCRValues[idx] = base64.StdEncoding.EncodeToString(value)
		}
	}

	if r.PolicyResult != nil {
		resp.PolicyResult = &AttestationPolicyEvaluationResp{
			PolicyID:    r.PolicyResult.PolicyID,
			PolicyName:  r.PolicyResult.PolicyName,
			Passed:      r.PolicyResult.Passed,
			Details:     r.PolicyResult.Details,
			EvaluatedAt: r.PolicyResult.EvaluatedAt,
		}
	}

	return resp
}

// verificationResultToResponse converts a VerificationResult to VerificationResponse.
func (h *AttestationHandlers) verificationResultToResponse(r *manifest.VerificationResult) *VerificationResponse {
	if r == nil {
		return nil
	}

	return &VerificationResponse{
		Valid:                      r.Status == manifest.VerificationStatusVerified,
		Status:                     r.Status.String(),
		SignatureValid:             r.SignatureValid,
		MerkleRootValid:            r.MerkleRootValid,
		NonceValid:                 r.NonceValid,
		TimestampValid:             r.TimestampValid,
		HostAttestationValid:       r.HostAttestationValid,
		VMAttestationsValid:        r.VMAttestationsValid,
		ContainerAttestationsValid: r.ContainerAttestationsValid,
		VerifiedAt:                 r.VerifiedAt,
		Errors:                     r.Errors,
		VMErrors:                   r.VMErrors,
		ContainerErrors:            r.ContainerErrors,
	}
}

// =============================================================================
// Helper Methods - Request Conversion
// =============================================================================

// requestToManifest converts a ManifestRequest to HostManifest.
func (h *AttestationHandlers) requestToManifest(req *ManifestRequest) (*manifest.HostManifest, error) {
	if req == nil {
		return nil, ErrMissingRequiredField{Field: "manifest"}
	}

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		return nil, ErrInvalidRequestBody{Reason: "invalid base64 for nonce"}
	}

	merkleRoot, err := base64.StdEncoding.DecodeString(req.MerkleRoot)
	if err != nil {
		return nil, ErrInvalidRequestBody{Reason: "invalid base64 for merkle_root"}
	}

	var signature []byte
	if req.Signature != "" {
		signature, err = base64.StdEncoding.DecodeString(req.Signature)
		if err != nil {
			return nil, ErrInvalidRequestBody{Reason: "invalid base64 for signature"}
		}
	}

	m := &manifest.HostManifest{
		ID:                 req.ID,
		HostID:             req.HostID,
		Timestamp:          req.Timestamp,
		Nonce:              nonce,
		MerkleRoot:         merkleRoot,
		Signature:          signature,
		SignatureAlgorithm: req.SignatureAlgorithm,
		Version:            req.Version,
		Metadata:           req.Metadata,
	}

	if req.Host != nil {
		host, err := h.requestToHostAttestation(req.Host)
		if err != nil {
			return nil, err
		}
		m.Host = host
	}

	for _, vmReq := range req.VMs {
		vm, err := h.requestToVMAttestation(&vmReq)
		if err != nil {
			return nil, err
		}
		m.VMs = append(m.VMs, *vm)
	}

	for _, containerReq := range req.Containers {
		container, err := h.requestToContainerAttestation(&containerReq)
		if err != nil {
			return nil, err
		}
		m.Containers = append(m.Containers, *container)
	}

	return m, nil
}

// requestToHostAttestation converts a HostAttestationRequest to HostAttestation.
func (h *AttestationHandlers) requestToHostAttestation(req *HostAttestationRequest) (*manifest.HostAttestation, error) {
	if req == nil {
		return nil, nil
	}

	quoteData, err := base64.StdEncoding.DecodeString(req.QuoteData)
	if err != nil {
		return nil, ErrInvalidRequestBody{Reason: "invalid base64 for quote_data"}
	}

	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return nil, ErrInvalidRequestBody{Reason: "invalid base64 for signature"}
	}

	pcrDigest, err := base64.StdEncoding.DecodeString(req.PCRDigest)
	if err != nil {
		return nil, ErrInvalidRequestBody{Reason: "invalid base64 for pcr_digest"}
	}

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		return nil, ErrInvalidRequestBody{Reason: "invalid base64 for nonce"}
	}

	var akPublicKey []byte
	if req.AKPublicKey != "" {
		akPublicKey, err = base64.StdEncoding.DecodeString(req.AKPublicKey)
		if err != nil {
			return nil, ErrInvalidRequestBody{Reason: "invalid base64 for ak_public_key"}
		}
	}

	var idevidCert []byte
	if req.IDevIDCertificate != "" {
		idevidCert, err = base64.StdEncoding.DecodeString(req.IDevIDCertificate)
		if err != nil {
			return nil, ErrInvalidRequestBody{Reason: "invalid base64 for idevid_certificate"}
		}
	}

	host := &manifest.HostAttestation{
		QuoteData:          quoteData,
		Signature:          signature,
		SignatureAlgorithm: req.SignatureAlgorithm,
		PCRDigest:          pcrDigest,
		Nonce:              nonce,
		Timestamp:          req.Timestamp,
		AKPublicKey:        akPublicKey,
		IDevIDCertificate:  idevidCert,
		HashAlgorithm:      h.parseHashAlgorithm(req.HashAlgorithm),
		FirmwareVersion:    req.FirmwareVersion,
	}

	for _, pcrReq := range req.PCRs {
		value, err := base64.StdEncoding.DecodeString(pcrReq.Value)
		if err != nil {
			return nil, ErrInvalidRequestBody{Reason: fmt.Sprintf("invalid base64 for PCR %d", pcrReq.Index)}
		}
		host.PCRs = append(host.PCRs, manifest.PCRValue{
			Index:     pcrReq.Index,
			Value:     value,
			Algorithm: h.parseHashAlgorithm(pcrReq.Algorithm),
		})
	}

	return host, nil
}

// requestToVMAttestation converts a VMAttestationRequest to VMAttestation.
func (h *AttestationHandlers) requestToVMAttestation(req *VMAttestationRequest) (*manifest.VMAttestation, error) {
	if req == nil {
		return nil, nil
	}

	quoteData, err := base64.StdEncoding.DecodeString(req.QuoteData)
	if err != nil {
		return nil, ErrInvalidRequestBody{Reason: "invalid base64 for quote_data"}
	}

	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return nil, ErrInvalidRequestBody{Reason: "invalid base64 for signature"}
	}

	pcrDigest, err := base64.StdEncoding.DecodeString(req.PCRDigest)
	if err != nil {
		return nil, ErrInvalidRequestBody{Reason: "invalid base64 for pcr_digest"}
	}

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		return nil, ErrInvalidRequestBody{Reason: "invalid base64 for nonce"}
	}

	var aikPublicKey []byte
	if req.AIKPublicKey != "" {
		aikPublicKey, err = base64.StdEncoding.DecodeString(req.AIKPublicKey)
		if err != nil {
			return nil, ErrInvalidRequestBody{Reason: "invalid base64 for aik_public_key"}
		}
	}

	var ekCert []byte
	if req.EKCertificate != "" {
		ekCert, err = base64.StdEncoding.DecodeString(req.EKCertificate)
		if err != nil {
			return nil, ErrInvalidRequestBody{Reason: "invalid base64 for ek_certificate"}
		}
	}

	var workloadPCR []byte
	if req.WorkloadPCR != "" {
		workloadPCR, err = base64.StdEncoding.DecodeString(req.WorkloadPCR)
		if err != nil {
			return nil, ErrInvalidRequestBody{Reason: "invalid base64 for workload_pcr"}
		}
	}

	vm := &manifest.VMAttestation{
		VMID:               req.VMID,
		HostID:             req.HostID,
		QuoteData:          quoteData,
		Signature:          signature,
		SignatureAlgorithm: req.SignatureAlgorithm,
		PCRDigest:          pcrDigest,
		Nonce:              nonce,
		Timestamp:          req.Timestamp,
		AIKPublicKey:       aikPublicKey,
		EKCertificate:      ekCert,
		WorkloadPCR:        workloadPCR,
		HashAlgorithm:      h.parseHashAlgorithm(req.HashAlgorithm),
		Metadata:           req.Metadata,
	}

	for _, pcrReq := range req.PCRs {
		value, err := base64.StdEncoding.DecodeString(pcrReq.Value)
		if err != nil {
			return nil, ErrInvalidRequestBody{Reason: fmt.Sprintf("invalid base64 for PCR %d", pcrReq.Index)}
		}
		vm.PCRs = append(vm.PCRs, manifest.PCRValue{
			Index:     pcrReq.Index,
			Value:     value,
			Algorithm: h.parseHashAlgorithm(pcrReq.Algorithm),
		})
	}

	return vm, nil
}

// requestToContainerAttestation converts a ContainerAttestationReq to ContainerAttestation.
func (h *AttestationHandlers) requestToContainerAttestation(req *ContainerAttestationReq) (*manifest.ContainerAttestation, error) {
	if req == nil {
		return nil, nil
	}

	digest, err := base64.StdEncoding.DecodeString(req.Digest)
	if err != nil {
		return nil, ErrInvalidRequestBody{Reason: "invalid base64 for digest"}
	}

	pcrValue, err := base64.StdEncoding.DecodeString(req.PCRValue)
	if err != nil {
		return nil, ErrInvalidRequestBody{Reason: "invalid base64 for pcr_value"}
	}

	return &manifest.ContainerAttestation{
		ContainerID: req.ContainerID,
		ImageID:     req.ImageID,
		ImageDigest: req.ImageDigest,
		Digest:      digest,
		PCRValue:    pcrValue,
		Timestamp:   req.Timestamp,
		Metadata:    req.Metadata,
	}, nil
}

// =============================================================================
// Helper Methods - Utilities
// =============================================================================

// isValidHashAlgorithmString checks if the provided string is a valid hash algorithm.
func (h *AttestationHandlers) isValidHashAlgorithmString(alg string) bool {
	switch strings.ToLower(alg) {
	case "sha256", "sha384", "sha512", "sha1":
		return true
	default:
		return false
	}
}

// parseHashAlgorithm parses a hash algorithm string.
func (h *AttestationHandlers) parseHashAlgorithm(alg string) manifest.HashAlgorithm {
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

// validatePCRIndices validates PCR indices are in valid range.
func (h *AttestationHandlers) validatePCRIndices(indices []int) error {
	for _, idx := range indices {
		if idx < 0 || idx > 23 {
			return ErrInvalidPCRIndex{Index: idx}
		}
	}
	return nil
}

// getDefaultPCRIndices returns the default PCR indices for attestation.
func (h *AttestationHandlers) getDefaultPCRIndices() []int {
	return []int{0, 1, 2, 3, 4, 5, 6, 7, 14}
}

// writeJSON writes a JSON response.
func (h *AttestationHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *AttestationHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// writeAttestationError maps attestation errors to appropriate HTTP status codes.
func (h *AttestationHandlers) writeAttestationError(w http.ResponseWriter, operation string, err error) {
	var status int

	switch {
	case errors.Is(err, manifest.ErrBuilderNotInitialized{}):
		status = http.StatusServiceUnavailable
	case errors.Is(err, manifest.ErrVerifierNotInitialized{}):
		status = http.StatusServiceUnavailable
	case errors.Is(err, manifest.ErrHostNotAttested{}):
		status = http.StatusNotFound
	case errors.Is(err, manifest.ErrEmptyManifest{}):
		status = http.StatusBadRequest
	default:
		errMsg := err.Error()
		lowerMsg := strings.ToLower(errMsg)
		switch {
		case containsAny(lowerMsg, "not found", "does not exist", "no such"):
			status = http.StatusNotFound
		case containsAny(lowerMsg, "invalid", "required", "must be", "cannot be"):
			status = http.StatusBadRequest
		case containsAny(lowerMsg, "expired"):
			status = http.StatusGone
		case containsAny(lowerMsg, "not available", "unavailable", "not initialized"):
			status = http.StatusServiceUnavailable
		case containsAny(lowerMsg, "permission", "denied", "unauthorized"):
			status = http.StatusForbidden
		default:
			status = http.StatusInternalServerError
		}
	}

	h.writeError(w, status, ErrAttestationFailed{
		Operation: operation,
		Cause:     err,
	})
}

// containsAny checks if s contains any of the substrings.
func containsAny(s string, substrings ...string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ParseIntParamWithDefault parses an integer query parameter with a default value.
func ParseIntParamWithDefault(r *http.Request, param string, defaultVal int) int {
	val := r.URL.Query().Get(param)
	if val == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return defaultVal
	}
	return i
}
