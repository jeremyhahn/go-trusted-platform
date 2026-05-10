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
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// =============================================================================
// TPM REST Handler Errors
// =============================================================================

// ErrTPMServiceNotAvailable is returned when the physical TPM service is not
// configured or unavailable.
type ErrTPMServiceNotAvailable struct{}

func (e ErrTPMServiceNotAvailable) Error() string {
	return "TPM service not available"
}

// ErrTPMInvalidPCRIndex is returned when a PCR index is out of range.
type ErrTPMInvalidPCRIndex struct {
	Index int
}

func (e ErrTPMInvalidPCRIndex) Error() string {
	return fmt.Sprintf("invalid PCR index: %d (must be 0-23)", e.Index)
}

// ErrTPMOperationFailed is returned when a TPM operation fails.
type ErrTPMOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrTPMOperationFailed) Error() string {
	return fmt.Sprintf("TPM operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrTPMOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrTPMInvalidNVIndex is returned when an NV index is invalid.
type ErrTPMInvalidNVIndex struct {
	Index string
}

func (e ErrTPMInvalidNVIndex) Error() string {
	if e.Index == "" {
		return "NV index is required"
	}
	return fmt.Sprintf("invalid NV index: %s", e.Index)
}

// ErrTPMInvalidRandomSize is returned when a random byte size is invalid.
type ErrTPMInvalidRandomSize struct {
	Size int
}

func (e ErrTPMInvalidRandomSize) Error() string {
	return fmt.Sprintf("invalid random size: %d (must be 1-1024)", e.Size)
}

// =============================================================================
// TPM Request/Response Types
// =============================================================================

// TPMInfoResponse represents the TPM info in API responses.
type TPMInfoResponse struct {
	Info         string           `json:"info"`
	Manufacturer *TPMManufacturer `json:"manufacturer,omitempty"`
	IsSimulator  bool             `json:"is_simulator"`
	FIPSMode     bool             `json:"fips_mode"`
	MaxNVRAMSize uint32           `json:"max_nvram_size,omitempty"`
	Capabilities []TPMCapability  `json:"capabilities,omitempty"`
	Timestamp    time.Time        `json:"timestamp"`
}

// TPMManufacturer represents TPM manufacturer information.
type TPMManufacturer struct {
	Name            string `json:"name"`
	Model           string `json:"model"`
	FirmwareVersion string `json:"firmware_version"`
}

// TPMCapability represents a single TPM capability.
type TPMCapability struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Supported bool   `json:"supported"`
}

// TPMProvisionRequest represents a TPM provision request.
type TPMProvisionRequest struct {
	OwnerPassword string `json:"owner_password,omitempty" secret:"true"`
}

// TPMStatusResponse represents a generic TPM status response.
type TPMStatusResponse struct {
	Success   bool      `json:"success"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// TPMClearRequest represents a TPM clear request.
type TPMClearRequest struct {
	OwnerPassword string `json:"owner_password,omitempty" secret:"true"`
}

// TPMKeyResponse represents a TPM key in API responses.
type TPMKeyResponse struct {
	Handle    uint32    `json:"handle"`
	PublicKey string    `json:"public_key"`
	Algorithm string    `json:"algorithm"`
	Timestamp time.Time `json:"timestamp"`
}

// TPMCertificateResponse represents a TPM certificate in API responses.
type TPMCertificateResponse struct {
	Certificate string    `json:"certificate"`
	Timestamp   time.Time `json:"timestamp"`
}

// TPMImportEKCertRequest represents an EK certificate import request.
type TPMImportEKCertRequest struct {
	Certificate string `json:"certificate"`
}

// TPMQuoteRequest represents a TPM quote request.
type TPMQuoteRequest struct {
	Nonce      string `json:"nonce"`
	PCRIndices []int  `json:"pcr_indices,omitempty"`
}

// TPMQuoteResponse represents a TPM quote response.
type TPMQuoteResponse struct {
	Quote     string    `json:"quote"`
	Signature string    `json:"signature"`
	EventLog  string    `json:"event_log,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// TPMPCRResponse represents PCR values in API responses.
type TPMPCRResponse struct {
	PCRValues []TPMPCRValue `json:"pcr_values"`
	Timestamp time.Time     `json:"timestamp"`
}

// TPMPCRValue represents a single PCR value.
type TPMPCRValue struct {
	Index int32  `json:"index"`
	Bank  string `json:"bank"`
	Value string `json:"value"`
}

// TPMPCRExtendRequest represents a PCR extend request.
type TPMPCRExtendRequest struct {
	PCRIndex int    `json:"pcr_index"`
	HashAlg  string `json:"hash_alg,omitempty"`
	Data     string `json:"data"`
}

// TPMEventLogResponse represents the TPM event log response.
type TPMEventLogResponse struct {
	EventLog   string    `json:"event_log"`
	Format     string    `json:"format"`
	EventCount uint64    `json:"event_count"`
	Timestamp  time.Time `json:"timestamp"`
}

// TPMRandomRequest represents a random bytes request.
type TPMRandomRequest struct {
	NumBytes int `json:"num_bytes"`
}

// TPMRandomResponse represents a random bytes response.
type TPMRandomResponse struct {
	RandomBytes string    `json:"random_bytes"`
	Timestamp   time.Time `json:"timestamp"`
}

// TPMSealRequest represents a TPM seal request.
type TPMSealRequest struct {
	Data string `json:"data"`
}

// TPMSealResponse represents a TPM seal response.
type TPMSealResponse struct {
	SealedData string    `json:"sealed_data"`
	Timestamp  time.Time `json:"timestamp"`
}

// TPMUnsealRequest represents a TPM unseal request.
type TPMUnsealRequest struct {
	CN string `json:"cn"`
}

// TPMUnsealResponse represents a TPM unseal response.
type TPMUnsealResponse struct {
	Data      string    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// TPMCertifyRequest represents a TPM certify request.
type TPMCertifyRequest struct {
	Handle uint32 `json:"handle"`
	Nonce  string `json:"nonce,omitempty"`
}

// TPMCertifyResponse represents a TPM certify response.
type TPMCertifyResponse struct {
	CertifyInfo string    `json:"certify_info"`
	Signature   string    `json:"signature"`
	Timestamp   time.Time `json:"timestamp"`
}

// TPMNVReadRequest represents an NV read request.
type TPMNVReadRequest struct {
	Index    uint32 `json:"index"`
	DataSize uint16 `json:"data_size"`
}

// TPMNVWriteRequest represents an NV write request.
type TPMNVWriteRequest struct {
	Index uint32 `json:"index"`
}

// TPMNVDeleteRequest represents an NV delete (undefine) request.
type TPMNVDeleteRequest struct {
	Index uint32 `json:"index"`
}

// TPMNVResponse represents an NV data response.
type TPMNVResponse struct {
	Data      string    `json:"data,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// TPMCSRRequest represents a CSR creation request.
type TPMCSRRequest struct {
	// No additional fields required; the TPM uses its configured keys.
}

// TPMCSRResponse represents a CSR creation response.
type TPMCSRResponse struct {
	CSR       string    `json:"csr"`
	Timestamp time.Time `json:"timestamp"`
}

// TPMPlatformAttributesResponse represents the platform attributes response.
type TPMPlatformAttributesResponse struct {
	Manufacturer string    `json:"manufacturer"`
	Model        string    `json:"model"`
	Version      string    `json:"version"`
	Serial       string    `json:"serial"`
	Timestamp    time.Time `json:"timestamp"`
}

// TPMCapabilitiesResponse represents the TPM capabilities response.
type TPMCapabilitiesResponse struct {
	Algorithms []string  `json:"algorithms,omitempty"`
	Commands   []string  `json:"commands,omitempty"`
	ECCCurves  []string  `json:"ecc_curves,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// =============================================================================
// TPM Handlers
// =============================================================================

// TPMHandlers provides REST API handlers for physical TPM operations.
type TPMHandlers struct {
	tpm    xkmssdk.TrustedPlatformModule
	logger *slog.Logger
	mu     sync.RWMutex
}

// NewTPMHandlers creates a new TPMHandlers instance.
func NewTPMHandlers(logger *slog.Logger) *TPMHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &TPMHandlers{
		logger: logger,
	}
}

// SetTPM2Service sets the physical TPM service for these handlers.
func (h *TPMHandlers) SetTPM2Service(tpm xkmssdk.TrustedPlatformModule) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tpm = tpm
}

// RegisterRoutes registers all physical TPM routes on the provided router.
func (h *TPMHandlers) RegisterRoutes(router *mux.Router) {
	// TPM info and management
	router.HandleFunc("/api/v1/tpm/info", h.handleGetInfo).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/tpm/provision", h.handleProvision).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tpm/clear", h.handleClear).Methods(http.MethodPost)

	// Key operations - EK
	router.HandleFunc("/api/v1/tpm/ek", h.handleGetEK).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/tpm/ek", h.handleCreateEK).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tpm/ek", h.handleDeleteEK).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/tpm/ek/certificate", h.handleGetEKCertificate).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/tpm/ek/certificate", h.handleImportEKCertificate).Methods(http.MethodPost)

	// Key operations - SRK
	router.HandleFunc("/api/v1/tpm/srk", h.handleGetSRK).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/tpm/srk", h.handleCreateSRK).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tpm/srk", h.handleDeleteSRK).Methods(http.MethodDelete)

	// Key operations - IAK (Attestation Key)
	router.HandleFunc("/api/v1/tpm/iak", h.handleGetIAK).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/tpm/iak", h.handleCreateIAK).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tpm/iak", h.handleDeleteIAK).Methods(http.MethodDelete)

	// Key operations - IDevID
	router.HandleFunc("/api/v1/tpm/idevid", h.handleGetIDevID).Methods(http.MethodGet)

	// Quote and attestation
	router.HandleFunc("/api/v1/tpm/quote", h.handleQuote).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tpm/verify-quote", h.handleVerifyQuote).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tpm/certify", h.handleCertify).Methods(http.MethodPost)

	// PCR operations
	router.HandleFunc("/api/v1/tpm/pcrs", h.handleReadPCRs).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/tpm/pcrs/extend", h.handleExtendPCR).Methods(http.MethodPost)

	// Event log
	router.HandleFunc("/api/v1/tpm/eventlog", h.handleEventLog).Methods(http.MethodGet)

	// Capabilities
	router.HandleFunc("/api/v1/tpm/capabilities", h.handleCapabilities).Methods(http.MethodGet)

	// Random
	router.HandleFunc("/api/v1/tpm/random", h.handleRandom).Methods(http.MethodPost)

	// Seal/Unseal
	router.HandleFunc("/api/v1/tpm/seal", h.handleSeal).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tpm/unseal", h.handleUnseal).Methods(http.MethodPost)

	// NVRAM operations
	router.HandleFunc("/api/v1/tpm/nv/read", h.handleNVRead).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tpm/nv/write", h.handleNVWrite).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tpm/nv", h.handleNVDelete).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/tpm/nv/define", h.handleNVDefine).Methods(http.MethodPost)

	// CSR operations
	router.HandleFunc("/api/v1/tpm/csr/idevid", h.handleCreateIDevIDCSR).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tpm/csr/ldevid", h.handleCreateLDevIDCSR).Methods(http.MethodPost)

	// Platform attributes
	router.HandleFunc("/api/v1/tpm/platform", h.handlePlatformAttributes).Methods(http.MethodGet)

	h.logger.Info("TPM REST routes registered")
}

// =============================================================================
// TPM Info and Management Handlers
// =============================================================================

// getTPM returns the TPM service under read lock, or nil if not set.
func (h *TPMHandlers) getTPM() xkmssdk.TrustedPlatformModule {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.tpm
}

// handleGetInfo handles GET /api/v1/tpm/info
func (h *TPMHandlers) handleGetInfo(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	info, err := tpm.Info()
	if err != nil {
		h.logger.Error("TPM Info failed", "error", err)
		h.writeTPMError(w, "info", err)
		return
	}

	resp := TPMInfoResponse{
		Info:      info,
		Timestamp: time.Now().UTC(),
	}

	// Get fixed properties for additional details
	props, propsErr := tpm.FixedProperties()
	if propsErr == nil && props != nil {
		fwVersion := fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor)
		resp.Manufacturer = &TPMManufacturer{
			Name:            props.Manufacturer,
			Model:           props.Model,
			FirmwareVersion: fwVersion,
		}
		resp.MaxNVRAMSize = props.NVBufferMax
		resp.FIPSMode = props.Fips1402
		resp.Capabilities = []TPMCapability{
			{Name: "lockout_counter", Value: fmt.Sprintf("%d", props.LockoutCounter), Supported: true},
			{Name: "max_auth_fail", Value: fmt.Sprintf("%d", props.MaxAuthFail), Supported: true},
			{Name: "family", Value: props.Family, Supported: true},
			{Name: "revision", Value: props.Revision, Supported: true},
			{Name: "vendor_id", Value: props.VendorID, Supported: true},
		}
	}

	cfg := tpm.Config()
	if cfg != nil {
		resp.IsSimulator = cfg.UseSimulator
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleProvision handles POST /api/v1/tpm/provision
func (h *TPMHandlers) handleProvision(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	var req TPMProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	var ownerPwd xkmssdk.Password
	if req.OwnerPassword != "" {
		ownerPwd = xkmssdk.NewPasswordFromString(req.OwnerPassword)
	}

	if _, err := tpm.ProvisionOwner(ownerPwd); err != nil {
		h.logger.Error("TPM Provision failed", "error", err)
		h.writeTPMError(w, "provision", err)
		return
	}

	h.logger.Info("TPM provisioned successfully")
	h.writeJSON(w, http.StatusOK, TPMStatusResponse{
		Success:   true,
		Message:   "TPM provisioned successfully",
		Timestamp: time.Now().UTC(),
	})
}

// handleClear handles POST /api/v1/tpm/clear
func (h *TPMHandlers) handleClear(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	var req TPMClearRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	var lockoutAuth []byte
	if req.OwnerPassword != "" {
		lockoutAuth = []byte(req.OwnerPassword)
	}

	if err := tpm.Clear(lockoutAuth); err != nil {
		h.logger.Error("TPM Clear failed", "error", err)
		h.writeTPMError(w, "clear", err)
		return
	}

	h.logger.Info("TPM cleared successfully")
	h.writeJSON(w, http.StatusOK, TPMStatusResponse{
		Success:   true,
		Message:   "TPM cleared successfully",
		Timestamp: time.Now().UTC(),
	})
}

// =============================================================================
// EK Handlers
// =============================================================================

// handleGetEK handles GET /api/v1/tpm/ek
func (h *TPMHandlers) handleGetEK(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		h.logger.Error("Failed to get EK attributes", "error", err)
		h.writeTPMError(w, "get_ek", err)
		return
	}

	h.writeJSON(w, http.StatusOK, TPMKeyResponse{
		Handle:    uint32(ekAttrs.TPMAttributes.Handle),
		PublicKey: base64.StdEncoding.EncodeToString(ekAttrs.TPMAttributes.PublicKeyBytes),
		Algorithm: ekAttrs.KeyAlgorithm.String(),
		Timestamp: time.Now().UTC(),
	})
}

// handleCreateEK handles POST /api/v1/tpm/ek
func (h *TPMHandlers) handleCreateEK(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		h.logger.Error("Failed to get EK attributes", "error", err)
		h.writeTPMError(w, "create_ek", err)
		return
	}

	if err := tpm.CreateEK(ekAttrs); err != nil {
		h.logger.Error("TPM CreateEK failed", "error", err)
		h.writeTPMError(w, "create_ek", err)
		return
	}

	h.logger.Info("EK created successfully")
	h.writeJSON(w, http.StatusCreated, TPMStatusResponse{
		Success:   true,
		Message:   fmt.Sprintf("EK created successfully at handle 0x%08x", ekAttrs.TPMAttributes.Handle),
		Timestamp: time.Now().UTC(),
	})
}

// handleDeleteEK handles DELETE /api/v1/tpm/ek
func (h *TPMHandlers) handleDeleteEK(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		h.logger.Error("Failed to get EK attributes", "error", err)
		h.writeTPMError(w, "delete_ek", err)
		return
	}

	tpm.Flush(ekAttrs.TPMAttributes.Handle)

	h.logger.Info("EK handle flushed")
	h.writeJSON(w, http.StatusOK, TPMStatusResponse{
		Success:   true,
		Message:   "EK handle flushed",
		Timestamp: time.Now().UTC(),
	})
}

// handleGetEKCertificate handles GET /api/v1/tpm/ek/certificate
func (h *TPMHandlers) handleGetEKCertificate(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	cert, err := tpm.EKCertificate()
	if err != nil {
		h.logger.Error("Failed to get EK certificate", "error", err)
		h.writeTPMError(w, "get_ek_certificate", err)
		return
	}

	h.writeJSON(w, http.StatusOK, TPMCertificateResponse{
		Certificate: base64.StdEncoding.EncodeToString(cert.Raw),
		Timestamp:   time.Now().UTC(),
	})
}

// handleImportEKCertificate handles POST /api/v1/tpm/ek/certificate
func (h *TPMHandlers) handleImportEKCertificate(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	var req TPMImportEKCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Certificate == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "certificate"})
		return
	}

	certBytes, err := base64.StdEncoding.DecodeString(req.Certificate)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: "invalid base64 certificate"})
		return
	}

	if err := tpm.ProvisionEKCert(nil, certBytes); err != nil {
		h.logger.Error("Failed to import EK certificate", "error", err)
		h.writeTPMError(w, "import_ek_certificate", err)
		return
	}

	h.logger.Info("EK certificate imported successfully")
	h.writeJSON(w, http.StatusOK, TPMStatusResponse{
		Success:   true,
		Message:   "EK certificate imported successfully",
		Timestamp: time.Now().UTC(),
	})
}

// =============================================================================
// SRK Handlers
// =============================================================================

// handleGetSRK handles GET /api/v1/tpm/srk
func (h *TPMHandlers) handleGetSRK(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	srkAttrs, err := tpm.SSRKAttributes()
	if err != nil {
		h.logger.Error("Failed to get SRK attributes", "error", err)
		h.writeTPMError(w, "get_srk", err)
		return
	}

	h.writeJSON(w, http.StatusOK, TPMKeyResponse{
		Handle:    uint32(srkAttrs.TPMAttributes.Handle),
		PublicKey: base64.StdEncoding.EncodeToString(srkAttrs.TPMAttributes.PublicKeyBytes),
		Algorithm: srkAttrs.KeyAlgorithm.String(),
		Timestamp: time.Now().UTC(),
	})
}

// handleCreateSRK handles POST /api/v1/tpm/srk
func (h *TPMHandlers) handleCreateSRK(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	srkAttrs, err := tpm.SSRKAttributes()
	if err != nil {
		h.logger.Error("Failed to get SRK attributes", "error", err)
		h.writeTPMError(w, "create_srk", err)
		return
	}

	if err := tpm.CreateSRK(srkAttrs); err != nil {
		h.logger.Error("TPM CreateSRK failed", "error", err)
		h.writeTPMError(w, "create_srk", err)
		return
	}

	h.logger.Info("SRK created successfully")
	h.writeJSON(w, http.StatusCreated, TPMStatusResponse{
		Success:   true,
		Message:   fmt.Sprintf("SRK created successfully at handle 0x%08x", srkAttrs.TPMAttributes.Handle),
		Timestamp: time.Now().UTC(),
	})
}

// handleDeleteSRK handles DELETE /api/v1/tpm/srk
func (h *TPMHandlers) handleDeleteSRK(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	srkAttrs, err := tpm.SSRKAttributes()
	if err != nil {
		h.logger.Error("Failed to get SRK attributes", "error", err)
		h.writeTPMError(w, "delete_srk", err)
		return
	}

	tpm.Flush(srkAttrs.TPMAttributes.Handle)

	h.logger.Info("SRK handle flushed")
	h.writeJSON(w, http.StatusOK, TPMStatusResponse{
		Success:   true,
		Message:   "SRK handle flushed",
		Timestamp: time.Now().UTC(),
	})
}

// =============================================================================
// IAK (Attestation Key) Handlers
// =============================================================================

// handleGetIAK handles GET /api/v1/tpm/iak
func (h *TPMHandlers) handleGetIAK(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		h.logger.Error("Failed to get IAK attributes", "error", err)
		h.writeTPMError(w, "get_iak", err)
		return
	}

	pubKey, iakErr := tpm.IAK()
	if iakErr != nil {
		h.writeTPMError(w, "get_iak", iakErr)
		return
	}
	if pubKey == nil {
		h.writeError(w, http.StatusNotFound, ErrTPMOperationFailed{
			Operation: "get_iak",
			Cause:     fmt.Errorf("IAK not found"),
		})
		return
	}

	h.writeJSON(w, http.StatusOK, TPMKeyResponse{
		Handle:    uint32(iakAttrs.TPMAttributes.Handle),
		PublicKey: base64.StdEncoding.EncodeToString(iakAttrs.TPMAttributes.PublicKeyBytes),
		Algorithm: iakAttrs.KeyAlgorithm.String(),
		Timestamp: time.Now().UTC(),
	})
}

// handleCreateIAK handles POST /api/v1/tpm/iak
func (h *TPMHandlers) handleCreateIAK(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		h.logger.Error("Failed to get EK attributes", "error", err)
		h.writeTPMError(w, "create_iak", err)
		return
	}

	iakAttrs, err := tpm.CreateIAK(ekAttrs, nil)
	if err != nil {
		h.logger.Error("TPM CreateIAK failed", "error", err)
		h.writeTPMError(w, "create_iak", err)
		return
	}

	h.logger.Info("IAK created successfully")
	h.writeJSON(w, http.StatusCreated, TPMStatusResponse{
		Success:   true,
		Message:   fmt.Sprintf("IAK created successfully at handle 0x%08x", iakAttrs.TPMAttributes.Handle),
		Timestamp: time.Now().UTC(),
	})
}

// handleDeleteIAK handles DELETE /api/v1/tpm/iak
func (h *TPMHandlers) handleDeleteIAK(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		h.logger.Error("Failed to get IAK attributes", "error", err)
		h.writeTPMError(w, "delete_iak", err)
		return
	}

	tpm.Flush(iakAttrs.TPMAttributes.Handle)

	h.logger.Info("IAK handle flushed")
	h.writeJSON(w, http.StatusOK, TPMStatusResponse{
		Success:   true,
		Message:   "IAK handle flushed",
		Timestamp: time.Now().UTC(),
	})
}

// =============================================================================
// IDevID Handler
// =============================================================================

// handleGetIDevID handles GET /api/v1/tpm/idevid
func (h *TPMHandlers) handleGetIDevID(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		h.logger.Error("Failed to get IDevID attributes", "error", err)
		h.writeTPMError(w, "get_idevid", err)
		return
	}

	pubKey, idevidErr := tpm.IDevID()
	if idevidErr != nil {
		h.writeTPMError(w, "get_idevid", idevidErr)
		return
	}
	if pubKey == nil {
		h.writeError(w, http.StatusNotFound, ErrTPMOperationFailed{
			Operation: "get_idevid",
			Cause:     fmt.Errorf("IDevID not found"),
		})
		return
	}

	h.writeJSON(w, http.StatusOK, TPMKeyResponse{
		Handle:    uint32(idevidAttrs.TPMAttributes.Handle),
		PublicKey: base64.StdEncoding.EncodeToString(idevidAttrs.TPMAttributes.PublicKeyBytes),
		Algorithm: idevidAttrs.KeyAlgorithm.String(),
		Timestamp: time.Now().UTC(),
	})
}

// =============================================================================
// Quote and Attestation Handlers
// =============================================================================

// handleQuote handles POST /api/v1/tpm/quote
func (h *TPMHandlers) handleQuote(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	var req TPMQuoteRequest
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

	for _, pcr := range req.PCRIndices {
		if pcr < 0 || pcr > 23 {
			h.writeError(w, http.StatusBadRequest, ErrTPMInvalidPCRIndex{Index: pcr})
			return
		}
	}

	pcrs := make([]uint, len(req.PCRIndices))
	for i, pcr := range req.PCRIndices {
		pcrs[i] = uint(pcr)
	}

	quote, err := tpm.Quote(pcrs, nonce)
	if err != nil {
		h.logger.Error("TPM Quote failed", "error", err)
		h.writeTPMError(w, "quote", err)
		return
	}

	resp := TPMQuoteResponse{
		Quote:     base64.StdEncoding.EncodeToString(quote.Quoted),
		Signature: base64.StdEncoding.EncodeToString(quote.Signature),
		Timestamp: time.Now().UTC(),
	}
	if len(quote.EventLog) > 0 {
		resp.EventLog = base64.StdEncoding.EncodeToString(quote.EventLog)
	}

	h.logger.Debug("TPM quote generated", "pcrs", req.PCRIndices)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleVerifyQuote handles POST /api/v1/tpm/verify-quote
func (h *TPMHandlers) handleVerifyQuote(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	// Quote verification is not yet implemented in the TPM interface
	h.writeError(w, http.StatusNotImplemented, ErrTPMOperationFailed{
		Operation: "verify_quote",
		Cause:     fmt.Errorf("quote verification not yet implemented"),
	})
}

// handleCertify handles POST /api/v1/tpm/certify
func (h *TPMHandlers) handleCertify(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	var req TPMCertifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Handle == 0 {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "handle"})
		return
	}

	var nonce []byte
	if req.Nonce != "" {
		var decodeErr error
		nonce, decodeErr = base64.StdEncoding.DecodeString(req.Nonce)
		if decodeErr != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: "invalid base64 nonce"})
			return
		}
	}

	keyAttrs, err := tpm.KeyAttributes(xkmssdk.TPMHandle(req.Handle))
	if err != nil {
		h.logger.Error("Failed to get key attributes for certify", "error", err, "handle", req.Handle)
		h.writeTPMError(w, "certify", err)
		return
	}

	result, err := tpm.CertifyKey(keyAttrs, nonce, nil)
	if err != nil {
		h.logger.Error("TPM Certify failed", "error", err, "handle", req.Handle)
		h.writeTPMError(w, "certify", err)
		return
	}

	h.writeJSON(w, http.StatusOK, TPMCertifyResponse{
		CertifyInfo: base64.StdEncoding.EncodeToString(result.CertifyInfo),
		Signature:   base64.StdEncoding.EncodeToString(result.Signature),
		Timestamp:   time.Now().UTC(),
	})
}

// =============================================================================
// PCR Handlers
// =============================================================================

// handleReadPCRs handles GET /api/v1/tpm/pcrs
func (h *TPMHandlers) handleReadPCRs(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	// Parse PCR indices from query parameter (comma-separated)
	var pcrs []uint
	if indicesParam := r.URL.Query().Get("indices"); indicesParam != "" {
		for _, s := range strings.Split(indicesParam, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			idx, err := strconv.Atoi(s)
			if err != nil || idx < 0 || idx > 23 {
				h.writeError(w, http.StatusBadRequest, ErrTPMInvalidPCRIndex{Index: idx})
				return
			}
			pcrs = append(pcrs, uint(idx))
		}
	}

	// Default to all standard PCRs (0-23)
	if len(pcrs) == 0 {
		pcrs = make([]uint, 24)
		for i := 0; i < 24; i++ {
			pcrs[i] = uint(i)
		}
	}

	pcrBanks, err := tpm.ReadPCRs(pcrs)
	if err != nil {
		h.logger.Error("Failed to read PCRs", "error", err)
		h.writeTPMError(w, "read_pcrs", err)
		return
	}

	pcrValues := make([]TPMPCRValue, 0, len(pcrs))
	for _, bank := range pcrBanks {
		for _, pcr := range bank.PCRs {
			pcrValues = append(pcrValues, TPMPCRValue{
				Index: pcr.ID,
				Bank:  bank.Algorithm,
				Value: base64.StdEncoding.EncodeToString(pcr.Value),
			})
		}
	}

	h.writeJSON(w, http.StatusOK, TPMPCRResponse{
		PCRValues: pcrValues,
		Timestamp: time.Now().UTC(),
	})
}

// handleExtendPCR handles POST /api/v1/tpm/pcrs/extend
func (h *TPMHandlers) handleExtendPCR(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	var req TPMPCRExtendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.PCRIndex < 0 || req.PCRIndex > 23 {
		h.writeError(w, http.StatusBadRequest, ErrTPMInvalidPCRIndex{Index: req.PCRIndex})
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

	hashAlg := req.HashAlg
	if hashAlg == "" {
		hashAlg = "sha256"
	}

	if err := tpm.ExtendPCR(req.PCRIndex, hashAlg, data); err != nil {
		h.logger.Error("Failed to extend PCR", "error", err, "pcr", req.PCRIndex)
		h.writeTPMError(w, "extend_pcr", err)
		return
	}

	h.logger.Debug("PCR extended", "pcr", req.PCRIndex)
	h.writeJSON(w, http.StatusOK, TPMStatusResponse{
		Success:   true,
		Message:   fmt.Sprintf("PCR %d extended successfully", req.PCRIndex),
		Timestamp: time.Now().UTC(),
	})
}

// =============================================================================
// Event Log Handler
// =============================================================================

// handleEventLog handles GET /api/v1/tpm/eventlog
func (h *TPMHandlers) handleEventLog(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	rawLog, err := tpm.EventLog()
	if err != nil {
		h.logger.Error("Failed to get event log", "error", err)
		h.writeTPMError(w, "eventlog", err)
		return
	}

	var eventCount uint64
	events, parseErr := tpm.ParsedEventLog()
	if parseErr == nil {
		eventCount = uint64(len(events))
	}

	h.writeJSON(w, http.StatusOK, TPMEventLogResponse{
		EventLog:   base64.StdEncoding.EncodeToString(rawLog),
		Format:     "tcg2",
		EventCount: eventCount,
		Timestamp:  time.Now().UTC(),
	})
}

// =============================================================================
// Capabilities Handler
// =============================================================================

// handleCapabilities handles GET /api/v1/tpm/capabilities
func (h *TPMHandlers) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	resp := TPMCapabilitiesResponse{
		Timestamp: time.Now().UTC(),
	}

	algorithms, err := tpm.SupportedAlgorithms()
	if err == nil {
		resp.Algorithms = algorithms
	}

	commands, err := tpm.SupportedCommands()
	if err == nil {
		resp.Commands = commands
	}

	curves, err := tpm.SupportedECCCurves()
	if err == nil {
		resp.ECCCurves = curves
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Random Handler
// =============================================================================

// handleRandom handles POST /api/v1/tpm/random
func (h *TPMHandlers) handleRandom(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	var req TPMRandomRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	numBytes := req.NumBytes
	if numBytes == 0 {
		numBytes = 32
	}
	if numBytes < 1 || numBytes > 1024 {
		h.writeError(w, http.StatusBadRequest, ErrTPMInvalidRandomSize{Size: numBytes})
		return
	}

	random, err := tpm.RandomBytes(numBytes)
	if err != nil {
		h.logger.Error("Failed to get random bytes", "error", err)
		h.writeTPMError(w, "random", err)
		return
	}

	h.writeJSON(w, http.StatusOK, TPMRandomResponse{
		RandomBytes: base64.StdEncoding.EncodeToString(random),
		Timestamp:   time.Now().UTC(),
	})
}

// =============================================================================
// Seal/Unseal Handlers
// =============================================================================

// handleSeal handles POST /api/v1/tpm/seal
func (h *TPMHandlers) handleSeal(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	var req TPMSealRequest
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

	ctx := r.Context()
	sealed, err := tpm.Seal(ctx, data, nil)
	if err != nil {
		h.logger.Error("TPM Seal failed", "error", err)
		h.writeTPMError(w, "seal", err)
		return
	}

	h.logger.Debug("Data sealed")
	h.writeJSON(w, http.StatusOK, TPMSealResponse{
		SealedData: base64.StdEncoding.EncodeToString(sealed.Ciphertext),
		Timestamp:  time.Now().UTC(),
	})
}

// handleUnseal handles POST /api/v1/tpm/unseal
func (h *TPMHandlers) handleUnseal(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	var req TPMUnsealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.CN == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "cn"})
		return
	}

	ctx := r.Context()
	sealed := &xkmssdk.SealedData{
		KeyID: req.CN,
	}

	data, err := tpm.Unseal(ctx, sealed, nil)
	if err != nil {
		h.logger.Error("TPM Unseal failed", "error", err, "cn", req.CN)
		h.writeTPMError(w, "unseal", err)
		return
	}

	h.logger.Debug("Data unsealed", "cn", req.CN)
	h.writeJSON(w, http.StatusOK, TPMUnsealResponse{
		Data:      base64.StdEncoding.EncodeToString(data),
		Timestamp: time.Now().UTC(),
	})
}

// =============================================================================
// NVRAM Handlers
// =============================================================================

// handleNVRead handles POST /api/v1/tpm/nv/read
func (h *TPMHandlers) handleNVRead(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	var req TPMNVReadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Index == 0 {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "index"})
		return
	}

	// NVRAM operations require KeyAttributes with NV index information
	h.writeError(w, http.StatusNotImplemented, ErrTPMOperationFailed{
		Operation: "nv_read",
		Cause:     fmt.Errorf("NVRAM read not yet fully implemented"),
	})
}

// handleNVWrite handles POST /api/v1/tpm/nv/write
func (h *TPMHandlers) handleNVWrite(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	var req TPMNVWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Index == 0 {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "index"})
		return
	}

	// NVRAM operations require KeyAttributes with NV index information
	h.writeError(w, http.StatusNotImplemented, ErrTPMOperationFailed{
		Operation: "nv_write",
		Cause:     fmt.Errorf("NVRAM write not yet fully implemented"),
	})
}

// handleNVDelete handles DELETE /api/v1/tpm/nv
func (h *TPMHandlers) handleNVDelete(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	// NVRAM operations require KeyAttributes with NV index information
	h.writeError(w, http.StatusNotImplemented, ErrTPMOperationFailed{
		Operation: "nv_delete",
		Cause:     fmt.Errorf("NVRAM undefine not yet fully implemented"),
	})
}

// handleNVDefine handles POST /api/v1/tpm/nv/define
func (h *TPMHandlers) handleNVDefine(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	// NVRAM operations require KeyAttributes with NV index information
	h.writeError(w, http.StatusNotImplemented, ErrTPMOperationFailed{
		Operation: "nv_define",
		Cause:     fmt.Errorf("NVRAM define not yet fully implemented"),
	})
}

// =============================================================================
// CSR Handlers
// =============================================================================

// handleCreateIDevIDCSR handles POST /api/v1/tpm/csr/idevid
func (h *TPMHandlers) handleCreateIDevIDCSR(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	// Get IAK and EK attributes for creating the IDevID CSR
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		h.logger.Error("Failed to get EK attributes for IDevID CSR", "error", err)
		h.writeTPMError(w, "create_idevid_csr", err)
		return
	}

	ekCert, err := tpm.EKCertificate()
	if err != nil {
		h.logger.Error("Failed to get EK certificate for IDevID CSR", "error", err)
		h.writeTPMError(w, "create_idevid_csr", err)
		return
	}

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		h.logger.Error("Failed to get IAK attributes for IDevID CSR", "error", err)
		h.writeTPMError(w, "create_idevid_csr", err)
		return
	}

	idevidAttrs, _, err := tpm.CreateIDevID(iakAttrs, ekCert, nil)
	if err != nil {
		h.logger.Error("Failed to create IDevID", "error", err)
		h.writeTPMError(w, "create_idevid_csr", err)
		return
	}

	// Create the TCG CSR
	csr, err := tpm.CreateTCG_CSR_IDEVID(ekCert, ekAttrs, idevidAttrs)
	if err != nil {
		h.logger.Error("Failed to create IDevID CSR", "error", err)
		h.writeTPMError(w, "create_idevid_csr", err)
		return
	}

	csrBytes, err := xkmssdk.PackIDevIDCSR(&csr)
	if err != nil {
		h.logger.Error("Failed to pack IDevID CSR", "error", err)
		h.writeTPMError(w, "create_idevid_csr", err)
		return
	}

	h.logger.Info("IDevID CSR created")
	h.writeJSON(w, http.StatusOK, TPMCSRResponse{
		CSR:       base64.StdEncoding.EncodeToString(csrBytes),
		Timestamp: time.Now().UTC(),
	})
}

// handleCreateLDevIDCSR handles POST /api/v1/tpm/csr/ldevid
func (h *TPMHandlers) handleCreateLDevIDCSR(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	// LDevID CSR creation requires local CA integration which is not yet
	// exposed through the TPM REST API
	h.writeError(w, http.StatusNotImplemented, ErrTPMOperationFailed{
		Operation: "create_ldevid_csr",
		Cause:     fmt.Errorf("LDevID CSR creation not yet implemented via REST"),
	})
}

// =============================================================================
// Platform Attributes Handler
// =============================================================================

// handlePlatformAttributes handles GET /api/v1/tpm/platform
func (h *TPMHandlers) handlePlatformAttributes(w http.ResponseWriter, r *http.Request) {
	tpm := h.getTPM()
	if tpm == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
		return
	}

	attrs := xkmssdk.DiscoverPlatformAttributes()

	h.writeJSON(w, http.StatusOK, TPMPlatformAttributesResponse{
		Manufacturer: attrs.Manufacturer,
		Model:        attrs.Model,
		Version:      attrs.Version,
		Serial:       attrs.Serial,
		Timestamp:    time.Now().UTC(),
	})
}

// =============================================================================
// Helper Methods
// =============================================================================

// writeJSON writes a JSON response with the given status code.
func (h *TPMHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response with the given status code.
func (h *TPMHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// writeTPMError maps TPM errors to appropriate HTTP status codes.
func (h *TPMHandlers) writeTPMError(w http.ResponseWriter, operation string, err error) {
	status := h.mapErrorToStatus(err)
	h.writeError(w, status, ErrTPMOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}

// tpmErrorStatusMap maps error message substrings to HTTP status codes.
// Checked in order; first match wins.
var tpmErrorStatusMap = []struct {
	substrings []string
	status     int
}{
	{
		substrings: []string{"not found", "does not exist", "no such", "not initialized", "not provisioned"},
		status:     http.StatusNotFound,
	},
	{
		substrings: []string{"already exists", "duplicate", "already open"},
		status:     http.StatusConflict,
	},
	{
		substrings: []string{"invalid", "required", "must be", "cannot be", "too large"},
		status:     http.StatusBadRequest,
	},
	{
		substrings: []string{"permission", "denied", "unauthorized", "forbidden", "authorization"},
		status:     http.StatusForbidden,
	},
	{
		substrings: []string{"not configured", "not available", "unavailable"},
		status:     http.StatusServiceUnavailable,
	},
}

// mapErrorToStatus converts a TPM error to an HTTP status code.
func (h *TPMHandlers) mapErrorToStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}

	errMsg := strings.ToLower(err.Error())
	for _, entry := range tpmErrorStatusMap {
		for _, substr := range entry.substrings {
			if strings.Contains(errMsg, substr) {
				return entry.status
			}
		}
	}

	return http.StatusInternalServerError
}

// Compile-time check that context.Context is available (used by seal/unseal).
var _ context.Context
