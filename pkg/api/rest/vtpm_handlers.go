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

package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// =============================================================================
// vTPM REST Handler Errors
// =============================================================================

// ErrVTPMServiceNotAvailable is returned when the vTPM service is not configured.
type ErrVTPMServiceNotAvailable struct{}

func (e ErrVTPMServiceNotAvailable) Error() string {
	return "vTPM service not available"
}

// ErrInvalidBundleID is returned when a bundle ID is invalid or empty.
type ErrInvalidBundleID struct {
	ID string
}

func (e ErrInvalidBundleID) Error() string {
	if e.ID == "" {
		return "bundle ID is required"
	}
	return fmt.Sprintf("invalid bundle ID: %s", e.ID)
}

// ErrVTPMInvalidPCRIndex is returned when a PCR index is out of range.
type ErrVTPMInvalidPCRIndex struct {
	Index int
}

func (e ErrVTPMInvalidPCRIndex) Error() string {
	return fmt.Sprintf("invalid PCR index: %d (must be 0-23)", e.Index)
}

// ErrInvalidTemplateID is returned when a template ID is invalid or empty.
type ErrInvalidTemplateID struct {
	ID string
}

func (e ErrInvalidTemplateID) Error() string {
	if e.ID == "" {
		return "template ID is required"
	}
	return fmt.Sprintf("invalid template ID: %s", e.ID)
}

// ErrVTPMOperationFailed is returned when a vTPM operation fails.
type ErrVTPMOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrVTPMOperationFailed) Error() string {
	return fmt.Sprintf("vTPM operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrVTPMOperationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Request/Response Types
// =============================================================================

// CreateBundleRequest represents a vTPM bundle creation request.
type CreateBundleRequest struct {
	Hostname          string            `json:"hostname"`
	EKAlgorithm       string            `json:"ek_algorithm,omitempty"`
	SecureBootEnabled bool              `json:"secure_boot_enabled,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
}

// BundleResponse represents a vTPM bundle in API responses.
type BundleResponse struct {
	ID                string                  `json:"id"`
	Mode              string                  `json:"mode"`
	Hostname          string                  `json:"hostname,omitempty"`
	EKAlgorithm       string                  `json:"ek_algorithm"`
	SecureBootEnabled bool                    `json:"secure_boot_enabled"`
	Running           bool                    `json:"running"`
	CreatedAt         time.Time               `json:"created_at"`
	ClonedFrom        string                  `json:"cloned_from,omitempty"`
	Labels            map[string]string       `json:"labels,omitempty"`
	SocketPath        string                  `json:"socket_path,omitempty"`
	EKCertificate     *EKCertificateResponse  `json:"ek_certificate,omitempty"`
	SecureBootKeys    *SecureBootKeysResponse `json:"secure_boot_keys,omitempty"`
}

// EKCertificateResponse represents EK certificate info in API responses.
type EKCertificateResponse struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Fingerprint  string    `json:"fingerprint"`
}

// SecureBootKeysResponse represents Secure Boot key info in API responses.
type SecureBootKeysResponse struct {
	PKFingerprint  string `json:"pk_fingerprint"`
	KEKFingerprint string `json:"kek_fingerprint"`
	DBFingerprint  string `json:"db_fingerprint"`
}

// BundleListResponse represents a list of vTPM bundles.
type BundleListResponse struct {
	Bundles   []BundleResponse `json:"bundles"`
	Count     int              `json:"count"`
	Timestamp time.Time        `json:"timestamp"`
}

// BundleStateResponse represents the state of a vTPM bundle.
type BundleStateResponse struct {
	ID         string    `json:"id"`
	Running    bool      `json:"running"`
	SocketPath string    `json:"socket_path"`
	Timestamp  time.Time `json:"timestamp"`
}

// BundleActionResponse represents a bundle action result.
type BundleActionResponse struct {
	BundleID string `json:"bundle_id"`
	Action   string `json:"action"`
	Success  bool   `json:"success"`
	Message  string `json:"message,omitempty"`
}

// StartBundleResponse is the start reply: the action result plus the running
// state and the swtpm socket a guest VM attaches to.
type StartBundleResponse struct {
	BundleActionResponse
	Running    bool   `json:"running"`
	SocketPath string `json:"socket_path"`
}

// QuoteRequest represents a TPM quote request.
type QuoteRequest struct {
	Nonce string `json:"nonce"`
	PCRs  []int  `json:"pcrs,omitempty"`
}

// QuoteResponse represents a TPM quote response.
type QuoteResponse struct {
	BundleID      string         `json:"bundle_id"`
	Quote         string         `json:"quote"`
	Signature     string         `json:"signature"`
	PCRValues     map[int]string `json:"pcr_values"`
	HashAlgorithm string         `json:"hash_algorithm"`
	Timestamp     time.Time      `json:"timestamp"`
}

// PCRReadResponse represents a PCR read response.
type PCRReadResponse struct {
	BundleID  string    `json:"bundle_id"`
	PCRIndex  int       `json:"pcr_index"`
	Value     string    `json:"value"`
	Timestamp time.Time `json:"timestamp"`
}

// PCRExtendRequest represents a PCR extend request.
type PCRExtendRequest struct {
	Data string `json:"data"`
}

// SealRequest represents a TPM seal request.
type SealRequest struct {
	Data      string `json:"data"`
	PCRs      []int  `json:"pcrs,omitempty"`
	AuthValue string `json:"auth_value,omitempty"`
}

// SealResponse represents a TPM seal response.
type SealResponse struct {
	BundleID   string    `json:"bundle_id"`
	SealedData string    `json:"sealed_data"`
	Timestamp  time.Time `json:"timestamp"`
}

// UnsealRequest represents a TPM unseal request.
type UnsealRequest struct {
	SealedData string `json:"sealed_data"`
	AuthValue  string `json:"auth_value,omitempty"`
}

// UnsealResponse represents a TPM unseal response.
type UnsealResponse struct {
	BundleID  string    `json:"bundle_id"`
	Data      string    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// CreateTemplateRequest represents a vTPM template creation request.
type CreateTemplateRequest struct {
	ID                string `json:"id"`
	Description       string `json:"description,omitempty"`
	EKAlgorithm       string `json:"ek_algorithm,omitempty"`
	SecureBootEnabled bool   `json:"secure_boot_enabled,omitempty"`
}

// TemplateResponse represents a vTPM template in API responses.
type TemplateResponse struct {
	ID                string    `json:"id"`
	Description       string    `json:"description,omitempty"`
	EKAlgorithm       string    `json:"ek_algorithm"`
	SecureBootEnabled bool      `json:"secure_boot_enabled"`
	CreatedAt         time.Time `json:"created_at"`
}

// TemplateListResponse represents a list of vTPM templates.
type TemplateListResponse struct {
	Templates []TemplateResponse `json:"templates"`
	Timestamp time.Time          `json:"timestamp"`
}

// CloneTemplateRequest represents a template clone request.
type CloneTemplateRequest struct {
	Hostname string            `json:"hostname"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// ImportBundleResponse represents an imported bundle response.
type ImportBundleResponse struct {
	Bundle    BundleResponse `json:"bundle"`
	Timestamp time.Time      `json:"timestamp"`
}

// ValidateBundleResponse represents a bundle validation result.
type ValidateBundleResponse struct {
	Valid     bool      `json:"valid"`
	Errors    []string  `json:"errors,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// PathResponse represents a path query result.
type PathResponse struct {
	Path string `json:"path"`
}

// =============================================================================
// vTPM Service Interface
// =============================================================================

// VTPMServiceInterface defines the interface for vTPM operations.
// This abstracts the actual vtpm.Service implementation for testability.
type VTPMServiceInterface interface {
	// Bundle operations
	CreateBundle(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error)
	GetBundle(ctx context.Context, id string) (*vtpm.Bundle, error)
	DeleteBundle(ctx context.Context, id string) error
	ListBundles(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error)

	// Template operations
	CreateTemplate(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error)
	GetTemplate(ctx context.Context, id string) (*vtpm.Template, error)
	DeleteTemplate(ctx context.Context, id string) error
	ListTemplates(ctx context.Context) ([]*vtpm.Template, error)
	CloneTemplate(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error)

	// Validation operations
	ValidateBundle(ctx context.Context, id string) error

	// Runtime operations
	Start(ctx context.Context, bundleID string) error
	Stop(ctx context.Context, bundleID string) error
	IsRunning(bundleID string) bool

	// TPM operations
	Quote(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error)
	ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error)
	ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error
	Seal(ctx context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error)
	Unseal(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error)

	// Export/Import operations
	ExportBundle(ctx context.Context, id string, w io.Writer) error
	ImportBundle(ctx context.Context, r io.Reader) (*vtpm.Bundle, error)

	// Path operations
	GetBundlePath(id string) string
	GetTPMSocketPath(id string) string
	GetNVRAMPath(id string) string
}

// =============================================================================
// vTPM Handlers
// =============================================================================

// VTPMHandlers provides REST API handlers for vTPM operations.
type VTPMHandlers struct {
	service VTPMServiceInterface
	logger  *slog.Logger
}

// NewVTPMHandlers creates a new VTPMHandlers instance.
func NewVTPMHandlers(service VTPMServiceInterface, logger *slog.Logger) *VTPMHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &VTPMHandlers{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers all vTPM routes on the provided router.
func (h *VTPMHandlers) RegisterRoutes(router *mux.Router) {
	// Bundle CRUD operations
	router.HandleFunc("/api/v1/vtpm/bundles", h.handleCreateBundle).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/vtpm/bundles", h.handleListBundles).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/vtpm/bundles/{id}", h.handleGetBundle).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/vtpm/bundles/{id}", h.handleDeleteBundle).Methods(http.MethodDelete)

	// Bundle lifecycle operations
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/start", h.handleStartBundle).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/stop", h.handleStopBundle).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/state", h.handleGetBundleState).Methods(http.MethodGet)

	// Bundle validation
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/validate", h.handleValidateBundle).Methods(http.MethodPost)

	// Bundle path operations
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/path", h.handleGetBundlePath).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/tpm-socket", h.handleGetTPMSocketPath).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/nvram", h.handleGetNVRAMPath).Methods(http.MethodGet)

	// TPM operations
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/quote", h.handleQuote).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/pcr/{index}", h.handleReadPCR).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/pcr/{index}/extend", h.handleExtendPCR).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/seal", h.handleSeal).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/unseal", h.handleUnseal).Methods(http.MethodPost)

	// Export/Import operations
	router.HandleFunc("/api/v1/vtpm/bundles/{id}/export", h.handleExportBundle).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/vtpm/bundles/import", h.handleImportBundle).Methods(http.MethodPost)

	// Template operations
	router.HandleFunc("/api/v1/vtpm/templates", h.handleCreateTemplate).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/vtpm/templates", h.handleListTemplates).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/vtpm/templates/{id}", h.handleGetTemplate).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/vtpm/templates/{id}", h.handleDeleteTemplate).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/vtpm/templates/{id}/clone", h.handleCloneTemplate).Methods(http.MethodPost)

	h.logger.Info("vTPM REST routes registered")
}

// =============================================================================
// Bundle CRUD Handlers
// =============================================================================

// handleCreateBundle handles POST /api/v1/vtpm/bundles
func (h *VTPMHandlers) handleCreateBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	var req CreateBundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Hostname == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "hostname"})
		return
	}

	ekAlg, err := vtpm.ParseEKAlgorithm(req.EKAlgorithm)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	opts := &vtpm.CreateBundleOptions{
		Hostname:          req.Hostname,
		EKAlgorithm:       ekAlg,
		SecureBootEnabled: req.SecureBootEnabled,
		Labels:            req.Labels,
	}

	bundle, err := h.service.CreateBundle(ctx, opts)
	if err != nil {
		h.logger.Error("Failed to create vTPM bundle", "error", err, "hostname", req.Hostname)
		h.writeVTPMError(w, "create", err)
		return
	}

	resp := h.bundleToResponse(bundle)
	h.logger.Info("vTPM bundle created", "id", bundle.ID, "hostname", req.Hostname)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListBundles handles GET /api/v1/vtpm/bundles
func (h *VTPMHandlers) handleListBundles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	opts := h.parseListOptions(r)

	bundles, err := h.service.ListBundles(ctx, opts)
	if err != nil {
		h.logger.Error("Failed to list vTPM bundles", "error", err)
		h.writeVTPMError(w, "list", err)
		return
	}

	responses := make([]BundleResponse, 0, len(bundles))
	for _, bundle := range bundles {
		responses = append(responses, h.bundleToResponse(bundle))
	}

	resp := BundleListResponse{
		Bundles:   responses,
		Count:     len(responses),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetBundle handles GET /api/v1/vtpm/bundles/{id}
func (h *VTPMHandlers) handleGetBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	bundle, err := h.service.GetBundle(ctx, bundleID)
	if err != nil {
		h.logger.Error("Failed to get vTPM bundle", "error", err, "id", bundleID)
		h.writeVTPMError(w, "get", err)
		return
	}

	resp := h.bundleToResponse(bundle)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteBundle handles DELETE /api/v1/vtpm/bundles/{id}
func (h *VTPMHandlers) handleDeleteBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	if err := h.service.DeleteBundle(ctx, bundleID); err != nil {
		h.logger.Error("Failed to delete vTPM bundle", "error", err, "id", bundleID)
		h.writeVTPMError(w, "delete", err)
		return
	}

	resp := BundleActionResponse{
		BundleID: bundleID,
		Action:   "delete",
		Success:  true,
		Message:  "bundle deleted successfully",
	}

	h.logger.Info("vTPM bundle deleted", "id", bundleID)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Bundle Lifecycle Handlers
// =============================================================================

// handleStartBundle handles POST /api/v1/vtpm/bundles/{id}/start
func (h *VTPMHandlers) handleStartBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	if err := h.service.Start(ctx, bundleID); err != nil {
		h.logger.Error("Failed to start vTPM", "error", err, "id", bundleID)
		h.writeVTPMError(w, "start", err)
		return
	}

	resp := StartBundleResponse{
		BundleActionResponse: BundleActionResponse{
			BundleID: bundleID,
			Action:   "start",
			Success:  true,
			Message:  "vTPM started successfully",
		},
		Running:    h.service.IsRunning(bundleID),
		SocketPath: h.service.GetTPMSocketPath(bundleID),
	}

	h.logger.Info("vTPM started", "id", bundleID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleStopBundle handles POST /api/v1/vtpm/bundles/{id}/stop
func (h *VTPMHandlers) handleStopBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	if err := h.service.Stop(ctx, bundleID); err != nil {
		h.logger.Error("Failed to stop vTPM", "error", err, "id", bundleID)
		h.writeVTPMError(w, "stop", err)
		return
	}

	resp := BundleActionResponse{
		BundleID: bundleID,
		Action:   "stop",
		Success:  true,
		Message:  "vTPM stopped successfully",
	}

	h.logger.Info("vTPM stopped", "id", bundleID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetBundleState handles GET /api/v1/vtpm/bundles/{id}/state
func (h *VTPMHandlers) handleGetBundleState(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	running := h.service.IsRunning(bundleID)
	socketPath := ""
	if running {
		socketPath = h.service.GetTPMSocketPath(bundleID)
	}

	resp := BundleStateResponse{
		ID:         bundleID,
		Running:    running,
		SocketPath: socketPath,
		Timestamp:  time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Bundle Validation Handlers
// =============================================================================

// handleValidateBundle handles POST /api/v1/vtpm/bundles/{id}/validate
func (h *VTPMHandlers) handleValidateBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	err := h.service.ValidateBundle(ctx, bundleID)

	// Check if the error is a "not found" type - return proper HTTP error status
	if err != nil {
		var bundleNotFound vtpm.ErrBundleNotFound
		if errors.As(err, &bundleNotFound) {
			h.writeVTPMError(w, "validate", err)
			return
		}
	}

	// For validation errors (bundle exists but has issues), return 200 with valid=false
	resp := ValidateBundleResponse{
		Valid:     err == nil,
		Timestamp: time.Now().UTC(),
	}

	if err != nil {
		resp.Errors = []string{err.Error()}
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Bundle Path Handlers
// =============================================================================

// handleGetBundlePath handles GET /api/v1/vtpm/bundles/{id}/path
func (h *VTPMHandlers) handleGetBundlePath(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	path := h.service.GetBundlePath(bundleID)

	resp := PathResponse{
		Path: path,
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetTPMSocketPath handles GET /api/v1/vtpm/bundles/{id}/tpm-socket
func (h *VTPMHandlers) handleGetTPMSocketPath(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	path := h.service.GetTPMSocketPath(bundleID)

	resp := PathResponse{
		Path: path,
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetNVRAMPath handles GET /api/v1/vtpm/bundles/{id}/nvram
func (h *VTPMHandlers) handleGetNVRAMPath(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	path := h.service.GetNVRAMPath(bundleID)

	resp := PathResponse{
		Path: path,
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// TPM Operation Handlers
// =============================================================================

// handleQuote handles POST /api/v1/vtpm/bundles/{id}/quote
func (h *VTPMHandlers) handleQuote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	var req QuoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Nonce == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "nonce"})
		return
	}

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: "invalid base64 nonce"})
		return
	}

	for _, pcr := range req.PCRs {
		if pcr < 0 || pcr > 23 {
			h.writeError(w, http.StatusBadRequest, ErrVTPMInvalidPCRIndex{Index: pcr})
			return
		}
	}

	result, err := h.service.Quote(ctx, bundleID, nonce, req.PCRs)
	if err != nil {
		h.logger.Error("Failed to generate TPM quote", "error", err, "id", bundleID)
		h.writeVTPMError(w, "quote", err)
		return
	}

	pcrValues := make(map[int]string)
	for idx, val := range result.PCRValues {
		pcrValues[idx] = base64.StdEncoding.EncodeToString(val)
	}

	resp := QuoteResponse{
		BundleID:      bundleID,
		Quote:         base64.StdEncoding.EncodeToString(result.Quote),
		Signature:     base64.StdEncoding.EncodeToString(result.Signature),
		PCRValues:     pcrValues,
		HashAlgorithm: result.HashAlgorithm,
		Timestamp:     time.Now().UTC(),
	}

	h.logger.Debug("TPM quote generated", "id", bundleID, "pcrs", req.PCRs)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleReadPCR handles GET /api/v1/vtpm/bundles/{id}/pcr/{index}
func (h *VTPMHandlers) handleReadPCR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	indexStr := vars["index"]
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrVTPMInvalidPCRIndex{Index: -1})
		return
	}

	if index < 0 || index > 23 {
		h.writeError(w, http.StatusBadRequest, ErrVTPMInvalidPCRIndex{Index: index})
		return
	}

	value, err := h.service.ReadPCR(ctx, bundleID, index)
	if err != nil {
		h.logger.Error("Failed to read PCR", "error", err, "id", bundleID, "pcr", index)
		h.writeVTPMError(w, "read_pcr", err)
		return
	}

	resp := PCRReadResponse{
		BundleID:  bundleID,
		PCRIndex:  index,
		Value:     base64.StdEncoding.EncodeToString(value),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleExtendPCR handles POST /api/v1/vtpm/bundles/{id}/pcr/{index}/extend
func (h *VTPMHandlers) handleExtendPCR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	indexStr := vars["index"]
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrVTPMInvalidPCRIndex{Index: -1})
		return
	}

	if index < 0 || index > 23 {
		h.writeError(w, http.StatusBadRequest, ErrVTPMInvalidPCRIndex{Index: index})
		return
	}

	var req PCRExtendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Data == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "data"})
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: "invalid base64 data"})
		return
	}

	if err := h.service.ExtendPCR(ctx, bundleID, index, data); err != nil {
		h.logger.Error("Failed to extend PCR", "error", err, "id", bundleID, "pcr", index)
		h.writeVTPMError(w, "extend_pcr", err)
		return
	}

	resp := BundleActionResponse{
		BundleID: bundleID,
		Action:   "extend_pcr",
		Success:  true,
		Message:  fmt.Sprintf("PCR %d extended successfully", index),
	}

	h.logger.Debug("PCR extended", "id", bundleID, "pcr", index)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleSeal handles POST /api/v1/vtpm/bundles/{id}/seal
func (h *VTPMHandlers) handleSeal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	var req SealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Data == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "data"})
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: "invalid base64 data"})
		return
	}

	for _, pcr := range req.PCRs {
		if pcr < 0 || pcr > 23 {
			h.writeError(w, http.StatusBadRequest, ErrVTPMInvalidPCRIndex{Index: pcr})
			return
		}
	}

	opts := &vtpm.SealOptions{
		PCRs:      req.PCRs,
		AuthValue: req.AuthValue,
	}

	sealedData, err := h.service.Seal(ctx, bundleID, data, opts)
	if err != nil {
		h.logger.Error("Failed to seal data", "error", err, "id", bundleID)
		h.writeVTPMError(w, "seal", err)
		return
	}

	resp := SealResponse{
		BundleID:   bundleID,
		SealedData: base64.StdEncoding.EncodeToString(sealedData),
		Timestamp:  time.Now().UTC(),
	}

	h.logger.Debug("Data sealed", "id", bundleID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleUnseal handles POST /api/v1/vtpm/bundles/{id}/unseal
func (h *VTPMHandlers) handleUnseal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	var req UnsealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.SealedData == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "sealed_data"})
		return
	}

	sealedData, err := base64.StdEncoding.DecodeString(req.SealedData)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: "invalid base64 sealed_data"})
		return
	}

	data, err := h.service.Unseal(ctx, bundleID, sealedData, req.AuthValue)
	if err != nil {
		h.logger.Error("Failed to unseal data", "error", err, "id", bundleID)
		h.writeVTPMError(w, "unseal", err)
		return
	}

	resp := UnsealResponse{
		BundleID:  bundleID,
		Data:      base64.StdEncoding.EncodeToString(data),
		Timestamp: time.Now().UTC(),
	}

	h.logger.Debug("Data unsealed", "id", bundleID)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Export/Import Handlers
// =============================================================================

// handleExportBundle handles GET /api/v1/vtpm/bundles/{id}/export
func (h *VTPMHandlers) handleExportBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bundleID := vars["id"]
	if bundleID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBundleID{})
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.tar.gz", bundleID))

	if err := h.service.ExportBundle(ctx, bundleID, w); err != nil {
		h.logger.Error("Failed to export bundle", "error", err, "id", bundleID)
		h.writeVTPMError(w, "export", err)
		return
	}

	h.logger.Info("Bundle exported", "id", bundleID)
}

// handleImportBundle handles POST /api/v1/vtpm/bundles/import
func (h *VTPMHandlers) handleImportBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	bundle, err := h.service.ImportBundle(ctx, r.Body)
	if err != nil {
		h.logger.Error("Failed to import bundle", "error", err)
		h.writeVTPMError(w, "import", err)
		return
	}

	resp := ImportBundleResponse{
		Bundle:    h.bundleToResponse(bundle),
		Timestamp: time.Now().UTC(),
	}

	h.logger.Info("Bundle imported", "id", bundle.ID)
	h.writeJSON(w, http.StatusCreated, resp)
}

// =============================================================================
// Template Handlers
// =============================================================================

// handleCreateTemplate handles POST /api/v1/vtpm/templates
func (h *VTPMHandlers) handleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	var req CreateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.ID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "id"})
		return
	}

	ekAlg, err := vtpm.ParseEKAlgorithm(req.EKAlgorithm)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	opts := &vtpm.CreateTemplateOptions{
		ID:                req.ID,
		Description:       req.Description,
		EKAlgorithm:       ekAlg,
		SecureBootEnabled: req.SecureBootEnabled,
	}

	template, err := h.service.CreateTemplate(ctx, opts)
	if err != nil {
		h.logger.Error("Failed to create vTPM template", "error", err, "id", req.ID)
		h.writeVTPMError(w, "create_template", err)
		return
	}

	resp := h.templateToResponse(template)
	h.logger.Info("vTPM template created", "id", template.ID)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListTemplates handles GET /api/v1/vtpm/templates
func (h *VTPMHandlers) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	templates, err := h.service.ListTemplates(ctx)
	if err != nil {
		h.logger.Error("Failed to list vTPM templates", "error", err)
		h.writeVTPMError(w, "list_templates", err)
		return
	}

	responses := make([]TemplateResponse, 0, len(templates))
	for _, tmpl := range templates {
		responses = append(responses, h.templateToResponse(tmpl))
	}

	resp := TemplateListResponse{
		Templates: responses,
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetTemplate handles GET /api/v1/vtpm/templates/{id}
func (h *VTPMHandlers) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	templateID := vars["id"]
	if templateID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTemplateID{})
		return
	}

	template, err := h.service.GetTemplate(ctx, templateID)
	if err != nil {
		h.logger.Error("Failed to get vTPM template", "error", err, "id", templateID)
		h.writeVTPMError(w, "get_template", err)
		return
	}

	resp := h.templateToResponse(template)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteTemplate handles DELETE /api/v1/vtpm/templates/{id}
func (h *VTPMHandlers) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	templateID := vars["id"]
	if templateID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTemplateID{})
		return
	}

	if err := h.service.DeleteTemplate(ctx, templateID); err != nil {
		h.logger.Error("Failed to delete vTPM template", "error", err, "id", templateID)
		h.writeVTPMError(w, "delete_template", err)
		return
	}

	resp := BundleActionResponse{
		BundleID: templateID,
		Action:   "delete_template",
		Success:  true,
		Message:  "template deleted successfully",
	}

	h.logger.Info("vTPM template deleted", "id", templateID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleCloneTemplate handles POST /api/v1/vtpm/templates/{id}/clone
func (h *VTPMHandlers) handleCloneTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVTPMServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	templateID := vars["id"]
	if templateID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTemplateID{})
		return
	}

	var req CloneTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Hostname == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "hostname"})
		return
	}

	opts := &vtpm.CloneOptions{
		TemplateID: templateID,
		Hostname:   req.Hostname,
		Labels:     req.Labels,
	}

	bundle, err := h.service.CloneTemplate(ctx, opts)
	if err != nil {
		h.logger.Error("Failed to clone template", "error", err, "template", templateID)
		h.writeVTPMError(w, "clone_template", err)
		return
	}

	resp := h.bundleToResponse(bundle)
	h.logger.Info("Template cloned", "template", templateID, "bundle", bundle.ID)
	h.writeJSON(w, http.StatusCreated, resp)
}

// =============================================================================
// Helper Methods
// =============================================================================

// parseListOptions parses query parameters into ListOptions.
func (h *VTPMHandlers) parseListOptions(r *http.Request) *vtpm.ListOptions {
	query := r.URL.Query()

	opts := &vtpm.ListOptions{}

	if mode := query.Get("mode"); mode != "" {
		opts.Mode = vtpm.BundleMode(mode)
	}

	if labels := query.Get("labels"); labels != "" {
		opts.Labels = make(map[string]string)
		for _, kv := range splitLabels(labels) {
			if k, v, ok := parseLabel(kv); ok {
				opts.Labels[k] = v
			}
		}
	}

	if limit := query.Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 {
			opts.Limit = l
		}
	}

	if offset := query.Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			opts.Offset = o
		}
	}

	if profileID := query.Get("device_profile_id"); profileID != "" {
		if id, err := strconv.ParseUint(profileID, 10, 64); err == nil {
			opts.DeviceProfileID = id
		}
	}

	return opts
}

// splitLabels splits a comma-separated label string.
func splitLabels(labels string) []string {
	if labels == "" {
		return nil
	}
	var result []string
	for _, l := range splitString(labels, ',') {
		if l != "" {
			result = append(result, l)
		}
	}
	return result
}

// splitString splits a string by a delimiter.
func splitString(s string, sep byte) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

// parseLabel parses a key=value label string.
func parseLabel(kv string) (string, string, bool) {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i], kv[i+1:], true
		}
	}
	return "", "", false
}

// bundleToResponse converts a vtpm.Bundle to BundleResponse.
func (h *VTPMHandlers) bundleToResponse(bundle *vtpm.Bundle) BundleResponse {
	resp := BundleResponse{
		ID:         bundle.ID,
		Mode:       string(bundle.Mode),
		CreatedAt:  bundle.CreatedAt,
		ClonedFrom: bundle.ClonedFrom,
	}

	if bundle.Manifest != nil {
		resp.Hostname = bundle.Manifest.Hostname
		resp.EKAlgorithm = string(bundle.Manifest.EKAlgorithm)
		resp.SecureBootEnabled = bundle.Manifest.SecureBootEnabled
		resp.Labels = bundle.Manifest.Labels

		if bundle.Manifest.EKCertificate != nil {
			resp.EKCertificate = &EKCertificateResponse{
				Subject:      bundle.Manifest.EKCertificate.Subject,
				Issuer:       bundle.Manifest.EKCertificate.Issuer,
				SerialNumber: bundle.Manifest.EKCertificate.SerialNumber,
				NotBefore:    bundle.Manifest.EKCertificate.NotBefore,
				NotAfter:     bundle.Manifest.EKCertificate.NotAfter,
				Fingerprint:  bundle.Manifest.EKCertificate.Fingerprint,
			}
		}

		if bundle.Manifest.SecureBootKeys != nil {
			resp.SecureBootKeys = &SecureBootKeysResponse{
				PKFingerprint:  bundle.Manifest.SecureBootKeys.PKFingerprint,
				KEKFingerprint: bundle.Manifest.SecureBootKeys.KEKFingerprint,
				DBFingerprint:  bundle.Manifest.SecureBootKeys.DBFingerprint,
			}
		}
	}

	if h.service != nil {
		resp.Running = h.service.IsRunning(bundle.ID)
		if resp.Running {
			resp.SocketPath = h.service.GetTPMSocketPath(bundle.ID)
		}
	}

	return resp
}

// templateToResponse converts a vtpm.Template to TemplateResponse.
func (h *VTPMHandlers) templateToResponse(template *vtpm.Template) TemplateResponse {
	return TemplateResponse{
		ID:                template.ID,
		Description:       template.Description,
		EKAlgorithm:       string(template.EKAlgorithm),
		SecureBootEnabled: template.SecureBootEnabled,
		CreatedAt:         template.CreatedAt,
	}
}

// writeJSON writes a JSON response.
func (h *VTPMHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *VTPMHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// writeVTPMError maps vTPM errors to appropriate HTTP status codes.
func (h *VTPMHandlers) writeVTPMError(w http.ResponseWriter, operation string, err error) {
	var status int

	var bundleNotFound vtpm.ErrBundleNotFound
	var bundleExists vtpm.ErrBundleAlreadyExists
	var templateNotFound vtpm.ErrTemplateNotFound
	var templateExists vtpm.ErrTemplateAlreadyExists
	var invalidConfig vtpm.ErrInvalidConfig
	var invalidEKAlgorithm vtpm.ErrInvalidEKAlgorithm
	var invalidManifest vtpm.ErrInvalidManifest
	var vtpmNotRunning vtpm.ErrVTPMNotRunning
	var vtpmAlreadyRunning vtpm.ErrVTPMAlreadyRunning
	var invalidNonce vtpm.ErrInvalidNonce
	var invalidPCR vtpm.ErrInvalidPCRIndex
	var checksumMismatch vtpm.ErrChecksumMismatch
	var caUnavailable vtpm.ErrCAUnavailable

	switch {
	case errors.As(err, &bundleNotFound):
		status = http.StatusNotFound
	case errors.As(err, &bundleExists):
		status = http.StatusConflict
	case errors.As(err, &templateNotFound):
		status = http.StatusNotFound
	case errors.As(err, &templateExists):
		status = http.StatusConflict
	case errors.As(err, &invalidConfig):
		status = http.StatusBadRequest
	case errors.As(err, &invalidEKAlgorithm):
		status = http.StatusBadRequest
	case errors.As(err, &invalidManifest):
		status = http.StatusBadRequest
	case errors.As(err, &vtpmNotRunning):
		status = http.StatusConflict
	case errors.As(err, &vtpmAlreadyRunning):
		status = http.StatusConflict
	case errors.As(err, &invalidNonce):
		status = http.StatusBadRequest
	case errors.As(err, &invalidPCR):
		status = http.StatusBadRequest
	case errors.As(err, &checksumMismatch):
		status = http.StatusUnprocessableEntity
	case errors.As(err, &caUnavailable):
		status = http.StatusServiceUnavailable
	default:
		status = http.StatusInternalServerError
	}

	h.writeError(w, status, ErrVTPMOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}
