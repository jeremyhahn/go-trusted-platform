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
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// vTPM pagination defaults
const (
	vtpmDefaultLimit int = 50
	vtpmMaxLimit     int = 1000
)

// vTPM-specific sentinel errors
var (
	// ErrVTPMServiceNotAvailable is returned when the vTPM service is not configured or unavailable.
	ErrVTPMServiceNotAvailable = errors.New("vTPM service not available")

	// ErrVTPMMissingBundleID is returned when a bundle ID is required but not provided.
	ErrVTPMMissingBundleID = errors.New("bundle ID is required")

	// ErrVTPMMissingTemplateID is returned when a template ID is required but not provided.
	ErrVTPMMissingTemplateID = errors.New("template ID is required")

	// ErrVTPMMissingHostname is returned when a hostname is required but not provided.
	ErrVTPMMissingHostname = errors.New("hostname is required")

	// ErrVTPMMissingNonce is returned when a nonce is required but not provided.
	ErrVTPMMissingNonce = errors.New("nonce is required")

	// ErrVTPMMissingData is returned when data is required but not provided.
	ErrVTPMMissingData = errors.New("data is required")

	// ErrVTPMMissingSealedData is returned when sealed data is required but not provided.
	ErrVTPMMissingSealedData = errors.New("sealed data is required")

	// ErrVTPMInvalidPCRIndex is returned when a PCR index is out of range.
	ErrVTPMInvalidPCRIndex = errors.New("invalid PCR index (must be 0-23)")
)

// VTPMHandler handles vTPM operations over QUIC
type VTPMHandler struct {
	service vtpm.VTPMService
	logger  *logging.Logger
}

// NewVTPMHandler creates a new vTPM handler
func NewVTPMHandler(logger *logging.Logger, service vtpm.VTPMService) *VTPMHandler {
	return &VTPMHandler{
		service: service,
		logger:  logger,
	}
}

// HandleRequest processes a vTPM request and returns a response
func (h *VTPMHandler) HandleRequest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if req == nil {
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte(quicwire.ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	// Bundle CRUD operations
	case quicwire.OpVTPMCreate:
		return h.handleCreateBundle(ctx, req)
	case quicwire.OpVTPMGetBundle:
		return h.handleGetBundle(ctx, req)
	case quicwire.OpVTPMDelete:
		return h.handleDeleteBundle(ctx, req)
	case quicwire.OpVTPMList:
		return h.handleListBundles(ctx, req)

	// Template operations
	case quicwire.OpVTPMCreateTemplate:
		return h.handleCreateTemplate(ctx, req)
	case quicwire.OpVTPMGetTemplate:
		return h.handleGetTemplate(ctx, req)
	case quicwire.OpVTPMDeleteTemplate:
		return h.handleDeleteTemplate(ctx, req)
	case quicwire.OpVTPMListTemplates:
		return h.handleListTemplates(ctx, req)
	case quicwire.OpVTPMCloneTemplate:
		return h.handleCloneTemplate(ctx, req)

	// Lifecycle operations
	case quicwire.OpVTPMStart:
		return h.handleStart(ctx, req)
	case quicwire.OpVTPMStop:
		return h.handleStop(ctx, req)
	case quicwire.OpVTPMGetState:
		return h.handleGetState(ctx, req)
	case quicwire.OpVTPMIsRunning:
		return h.handleIsRunning(ctx, req)

	// TPM operations
	case quicwire.OpVTPMQuote:
		return h.handleQuote(ctx, req)
	case quicwire.OpVTPMReadPCR:
		return h.handleReadPCR(ctx, req)
	case quicwire.OpVTPMExtendPCR:
		return h.handleExtendPCR(ctx, req)
	case quicwire.OpVTPMSeal:
		return h.handleSeal(ctx, req)
	case quicwire.OpVTPMUnseal:
		return h.handleUnseal(ctx, req)

	// Export/Import operations
	case quicwire.OpVTPMExportBundle:
		return h.handleExportBundle(ctx, req)
	case quicwire.OpVTPMImportBundle:
		return h.handleImportBundle(ctx, req)
	case quicwire.OpVTPMValidateBundle:
		return h.handleValidateBundle(ctx, req)

	// Path operations
	case quicwire.OpVTPMGetBundlePath:
		return h.handleGetBundlePath(ctx, req)
	case quicwire.OpVTPMGetSocketPath:
		return h.handleGetSocketPath(ctx, req)
	case quicwire.OpVTPMGetNVRAMPath:
		return h.handleGetNVRAMPath(ctx, req)

	default:
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte("unknown vTPM operation"),
		}
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// VTPMCreateBundleRequest represents a vTPM bundle creation request
type VTPMCreateBundleRequest struct {
	Hostname          string            `codec:"hostname"`
	EKAlgorithm       string            `codec:"ek_algorithm"`
	SecureBootEnabled bool              `codec:"secure_boot_enabled"`
	Labels            map[string]string `codec:"labels"`
}

// VTPMBundleResponse represents a vTPM bundle in API responses
type VTPMBundleResponse struct {
	ID                string                      `codec:"id"`
	Mode              string                      `codec:"mode"`
	Hostname          string                      `codec:"hostname"`
	EKAlgorithm       string                      `codec:"ek_algorithm"`
	SecureBootEnabled bool                        `codec:"secure_boot_enabled"`
	Running           bool                        `codec:"running"`
	CreatedAt         int64                       `codec:"created_at"`
	ClonedFrom        string                      `codec:"cloned_from"`
	Labels            map[string]string           `codec:"labels"`
	SocketPath        string                      `codec:"socket_path"`
	EKCertificate     *VTPMEKCertificateResponse  `codec:"ek_certificate"`
	SecureBootKeys    *VTPMSecureBootKeysResponse `codec:"secure_boot_keys"`
	Timestamp         int64                       `codec:"timestamp"`
}

// VTPMEKCertificateResponse represents EK certificate info
type VTPMEKCertificateResponse struct {
	Subject      string `codec:"subject"`
	Issuer       string `codec:"issuer"`
	SerialNumber string `codec:"serial_number"`
	NotBefore    int64  `codec:"not_before"`
	NotAfter     int64  `codec:"not_after"`
	Fingerprint  string `codec:"fingerprint"`
}

// VTPMSecureBootKeysResponse represents Secure Boot key info
type VTPMSecureBootKeysResponse struct {
	PKFingerprint  string `codec:"pk_fingerprint"`
	KEKFingerprint string `codec:"kek_fingerprint"`
	DBFingerprint  string `codec:"db_fingerprint"`
}

// VTPMGetBundleRequest represents a get bundle request
type VTPMGetBundleRequest struct {
	ID string `codec:"id"`
}

// VTPMDeleteBundleRequest represents a delete bundle request
type VTPMDeleteBundleRequest struct {
	ID string `codec:"id"`
}

// VTPMDeleteBundleResponse represents a delete bundle response
type VTPMDeleteBundleResponse struct {
	BundleID  string `codec:"bundle_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMListBundlesRequest represents a list bundles request
type VTPMListBundlesRequest struct {
	Mode   string            `codec:"mode"`
	Labels map[string]string `codec:"labels"`
	Limit  int               `codec:"limit"`
	Offset int               `codec:"offset"`
}

// VTPMListBundlesResponse represents a list bundles response
type VTPMListBundlesResponse struct {
	Bundles   []*VTPMBundleResponse `codec:"bundles"`
	Count     int                   `codec:"count"`
	Timestamp int64                 `codec:"timestamp"`
}

// VTPMCreateTemplateRequest represents a template creation request
type VTPMCreateTemplateRequest struct {
	ID                string `codec:"id"`
	Description       string `codec:"description"`
	EKAlgorithm       string `codec:"ek_algorithm"`
	SecureBootEnabled bool   `codec:"secure_boot_enabled"`
}

// VTPMTemplateResponse represents a vTPM template in API responses
type VTPMTemplateResponse struct {
	ID                string `codec:"id"`
	Description       string `codec:"description"`
	EKAlgorithm       string `codec:"ek_algorithm"`
	SecureBootEnabled bool   `codec:"secure_boot_enabled"`
	CreatedAt         int64  `codec:"created_at"`
	Timestamp         int64  `codec:"timestamp"`
}

// VTPMGetTemplateRequest represents a get template request
type VTPMGetTemplateRequest struct {
	ID string `codec:"id"`
}

// VTPMDeleteTemplateRequest represents a delete template request
type VTPMDeleteTemplateRequest struct {
	ID string `codec:"id"`
}

// VTPMDeleteTemplateResponse represents a delete template response
type VTPMDeleteTemplateResponse struct {
	TemplateID string `codec:"template_id"`
	Success    bool   `codec:"success"`
	Timestamp  int64  `codec:"timestamp"`
}

// VTPMListTemplatesResponse represents a list templates response
type VTPMListTemplatesResponse struct {
	Templates []*VTPMTemplateResponse `codec:"templates"`
	Count     int                     `codec:"count"`
	Timestamp int64                   `codec:"timestamp"`
}

// VTPMCloneTemplateRequest represents a clone template request
type VTPMCloneTemplateRequest struct {
	TemplateID string            `codec:"template_id"`
	Hostname   string            `codec:"hostname"`
	Labels     map[string]string `codec:"labels"`
}

// VTPMStartRequest represents a start vTPM request
type VTPMStartRequest struct {
	BundleID string `codec:"bundle_id"`
}

// VTPMStartResponse represents a start vTPM response
type VTPMStartResponse struct {
	BundleID   string `codec:"bundle_id"`
	Success    bool   `codec:"success"`
	SocketPath string `codec:"socket_path"`
	Timestamp  int64  `codec:"timestamp"`
}

// VTPMStopRequest represents a stop vTPM request
type VTPMStopRequest struct {
	BundleID string `codec:"bundle_id"`
}

// VTPMStopResponse represents a stop vTPM response
type VTPMStopResponse struct {
	BundleID  string `codec:"bundle_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMGetStateRequest represents a get state request
type VTPMGetStateRequest struct {
	BundleID string `codec:"bundle_id"`
}

// VTPMGetStateResponse represents a get state response
type VTPMGetStateResponse struct {
	BundleID   string `codec:"bundle_id"`
	Running    bool   `codec:"running"`
	SocketPath string `codec:"socket_path"`
	Timestamp  int64  `codec:"timestamp"`
}

// VTPMIsRunningRequest represents an is running request
type VTPMIsRunningRequest struct {
	BundleID string `codec:"bundle_id"`
}

// VTPMIsRunningResponse represents an is running response
type VTPMIsRunningResponse struct {
	BundleID  string `codec:"bundle_id"`
	Running   bool   `codec:"running"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMQuoteRequest represents a TPM quote request
type VTPMQuoteRequest struct {
	BundleID string `codec:"bundle_id"`
	Nonce    []byte `codec:"nonce"`
	PCRs     []int  `codec:"pcrs"`
}

// VTPMQuoteResponse represents a TPM quote response
type VTPMQuoteResponse struct {
	BundleID      string         `codec:"bundle_id"`
	Quote         []byte         `codec:"quote"`
	Signature     []byte         `codec:"signature"`
	PCRValues     map[int][]byte `codec:"pcr_values"`
	HashAlgorithm string         `codec:"hash_algorithm"`
	Timestamp     int64          `codec:"timestamp"`
}

// VTPMReadPCRRequest represents a PCR read request
type VTPMReadPCRRequest struct {
	BundleID string `codec:"bundle_id"`
	PCRIndex int    `codec:"pcr_index"`
}

// VTPMReadPCRResponse represents a PCR read response
type VTPMReadPCRResponse struct {
	BundleID  string `codec:"bundle_id"`
	PCRIndex  int    `codec:"pcr_index"`
	Value     []byte `codec:"value"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMExtendPCRRequest represents a PCR extend request
type VTPMExtendPCRRequest struct {
	BundleID string `codec:"bundle_id"`
	PCRIndex int    `codec:"pcr_index"`
	Data     []byte `codec:"data"`
}

// VTPMExtendPCRResponse represents a PCR extend response
type VTPMExtendPCRResponse struct {
	BundleID  string `codec:"bundle_id"`
	PCRIndex  int    `codec:"pcr_index"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMSealRequest represents a TPM seal request
type VTPMSealRequest struct {
	BundleID  string `codec:"bundle_id"`
	Data      []byte `codec:"data"`
	PCRs      []int  `codec:"pcrs"`
	AuthValue string `codec:"auth_value"`
}

// VTPMSealResponse represents a TPM seal response
type VTPMSealResponse struct {
	BundleID   string `codec:"bundle_id"`
	SealedData []byte `codec:"sealed_data"`
	Timestamp  int64  `codec:"timestamp"`
}

// VTPMUnsealRequest represents a TPM unseal request
type VTPMUnsealRequest struct {
	BundleID   string `codec:"bundle_id"`
	SealedData []byte `codec:"sealed_data"`
	AuthValue  string `codec:"auth_value"`
}

// VTPMUnsealResponse represents a TPM unseal response
type VTPMUnsealResponse struct {
	BundleID  string `codec:"bundle_id"`
	Data      []byte `codec:"data"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMExportBundleRequest represents an export bundle request
type VTPMExportBundleRequest struct {
	BundleID string `codec:"bundle_id"`
}

// VTPMExportBundleResponse represents an export bundle response
type VTPMExportBundleResponse struct {
	BundleID  string `codec:"bundle_id"`
	Data      []byte `codec:"data"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMImportBundleRequest represents an import bundle request
type VTPMImportBundleRequest struct {
	Data []byte `codec:"data"`
}

// VTPMValidateBundleRequest represents a validate bundle request
type VTPMValidateBundleRequest struct {
	BundleID string `codec:"bundle_id"`
}

// VTPMValidateBundleResponse represents a validate bundle response
type VTPMValidateBundleResponse struct {
	BundleID  string `codec:"bundle_id"`
	Valid     bool   `codec:"valid"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMGetPathRequest represents a get path request
type VTPMGetPathRequest struct {
	BundleID string `codec:"bundle_id"`
}

// VTPMGetPathResponse represents a get path response
type VTPMGetPathResponse struct {
	BundleID  string `codec:"bundle_id"`
	Path      string `codec:"path"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// Bundle CRUD Handler Methods
// =============================================================================

// handleCreateBundle creates a new vTPM bundle
func (h *VTPMHandler) handleCreateBundle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var createReq VTPMCreateBundleRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if createReq.Hostname == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingHostname)
	}

	ekAlg := vtpm.EKAlgorithmRSA
	if createReq.EKAlgorithm == "ECC" || createReq.EKAlgorithm == "ECDSA" {
		ekAlg = vtpm.EKAlgorithmECC
	}

	opts := &vtpm.CreateBundleOptions{
		Mode:              vtpm.BundleModePreAssigned,
		Hostname:          createReq.Hostname,
		EKAlgorithm:       ekAlg,
		SecureBootEnabled: createReq.SecureBootEnabled,
		Labels:            createReq.Labels,
	}

	bundle, err := h.service.CreateBundle(ctx, opts)
	if err != nil {
		h.logger.Error(err, "failed to create vTPM bundle")
		return h.vtpmErrorResponse(err)
	}

	resp := h.bundleToResponse(bundle)
	h.logger.Info("vTPM bundle created", "id", bundle.ID, "hostname", createReq.Hostname)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetBundle retrieves a bundle by ID
func (h *VTPMHandler) handleGetBundle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var getReq VTPMGetBundleRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if getReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	bundle, err := h.service.GetBundle(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get vTPM bundle", "id", getReq.ID)
		return h.vtpmErrorResponse(err)
	}

	resp := h.bundleToResponse(bundle)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDeleteBundle deletes a bundle
func (h *VTPMHandler) handleDeleteBundle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var deleteReq VTPMDeleteBundleRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if deleteReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	if err := h.service.DeleteBundle(ctx, deleteReq.ID); err != nil {
		h.logger.Error(err, "failed to delete vTPM bundle", "id", deleteReq.ID)
		return h.vtpmErrorResponse(err)
	}

	resp := &VTPMDeleteBundleResponse{
		BundleID:  deleteReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Info("vTPM bundle deleted", "id", deleteReq.ID)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListBundles lists bundles matching the filter options
func (h *VTPMHandler) handleListBundles(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var listReq VTPMListBundlesRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	opts := &vtpm.ListOptions{
		Labels: listReq.Labels,
		Offset: listReq.Offset,
	}

	if listReq.Mode != "" {
		opts.Mode = vtpm.BundleMode(listReq.Mode)
	}

	if listReq.Limit > 0 {
		limit := listReq.Limit
		if limit > vtpmMaxLimit {
			limit = vtpmMaxLimit
		}
		opts.Limit = limit
	} else {
		opts.Limit = vtpmDefaultLimit
	}

	bundles, err := h.service.ListBundles(ctx, opts)
	if err != nil {
		h.logger.Error(err, "failed to list vTPM bundles")
		return h.vtpmErrorResponse(err)
	}

	bundleResponses := make([]*VTPMBundleResponse, 0, len(bundles))
	for _, bundle := range bundles {
		bundleResponses = append(bundleResponses, h.bundleToResponse(bundle))
	}

	resp := &VTPMListBundlesResponse{
		Bundles:   bundleResponses,
		Count:     len(bundleResponses),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Template Handler Methods
// =============================================================================

// handleCreateTemplate creates a new vTPM template
func (h *VTPMHandler) handleCreateTemplate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var createReq VTPMCreateTemplateRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if createReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingTemplateID)
	}

	ekAlg := vtpm.EKAlgorithmRSA
	if createReq.EKAlgorithm == "ECC" || createReq.EKAlgorithm == "ECDSA" {
		ekAlg = vtpm.EKAlgorithmECC
	}

	opts := &vtpm.CreateTemplateOptions{
		ID:                createReq.ID,
		Description:       createReq.Description,
		EKAlgorithm:       ekAlg,
		SecureBootEnabled: createReq.SecureBootEnabled,
	}

	template, err := h.service.CreateTemplate(ctx, opts)
	if err != nil {
		h.logger.Error(err, "failed to create vTPM template", "id", createReq.ID)
		return h.vtpmErrorResponse(err)
	}

	resp := h.templateToResponse(template)
	h.logger.Info("vTPM template created", "id", template.ID)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetTemplate retrieves a template by ID
func (h *VTPMHandler) handleGetTemplate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var getReq VTPMGetTemplateRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if getReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingTemplateID)
	}

	template, err := h.service.GetTemplate(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get vTPM template", "id", getReq.ID)
		return h.vtpmErrorResponse(err)
	}

	resp := h.templateToResponse(template)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDeleteTemplate deletes a template
func (h *VTPMHandler) handleDeleteTemplate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var deleteReq VTPMDeleteTemplateRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if deleteReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingTemplateID)
	}

	if err := h.service.DeleteTemplate(ctx, deleteReq.ID); err != nil {
		h.logger.Error(err, "failed to delete vTPM template", "id", deleteReq.ID)
		return h.vtpmErrorResponse(err)
	}

	resp := &VTPMDeleteTemplateResponse{
		TemplateID: deleteReq.ID,
		Success:    true,
		Timestamp:  time.Now().Unix(),
	}

	h.logger.Info("vTPM template deleted", "id", deleteReq.ID)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListTemplates lists all templates
func (h *VTPMHandler) handleListTemplates(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	templates, err := h.service.ListTemplates(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list vTPM templates")
		return h.vtpmErrorResponse(err)
	}

	templateResponses := make([]*VTPMTemplateResponse, 0, len(templates))
	for _, template := range templates {
		templateResponses = append(templateResponses, h.templateToResponse(template))
	}

	resp := &VTPMListTemplatesResponse{
		Templates: templateResponses,
		Count:     len(templateResponses),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleCloneTemplate clones a template to create a new bundle
func (h *VTPMHandler) handleCloneTemplate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var cloneReq VTPMCloneTemplateRequest
	if err := quicwire.DecodePayload(req.Payload, &cloneReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if cloneReq.TemplateID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingTemplateID)
	}

	if cloneReq.Hostname == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingHostname)
	}

	opts := &vtpm.CloneOptions{
		TemplateID: cloneReq.TemplateID,
		Hostname:   cloneReq.Hostname,
		Labels:     cloneReq.Labels,
	}

	bundle, err := h.service.CloneTemplate(ctx, opts)
	if err != nil {
		h.logger.Error(err, "failed to clone template", "template", cloneReq.TemplateID)
		return h.vtpmErrorResponse(err)
	}

	resp := h.bundleToResponse(bundle)
	h.logger.Info("template cloned", "template", cloneReq.TemplateID, "bundle", bundle.ID)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Lifecycle Handler Methods
// =============================================================================

// handleStart starts the vTPM for a bundle
func (h *VTPMHandler) handleStart(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var startReq VTPMStartRequest
	if err := quicwire.DecodePayload(req.Payload, &startReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if startReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	if err := h.service.Start(ctx, startReq.BundleID); err != nil {
		h.logger.Error(err, "failed to start vTPM", "bundle_id", startReq.BundleID)
		return h.vtpmErrorResponse(err)
	}

	socketPath := h.service.GetTPMSocketPath(startReq.BundleID)

	resp := &VTPMStartResponse{
		BundleID:   startReq.BundleID,
		Success:    true,
		SocketPath: socketPath,
		Timestamp:  time.Now().Unix(),
	}

	h.logger.Info("vTPM started", "bundle_id", startReq.BundleID)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleStop stops the vTPM for a bundle
func (h *VTPMHandler) handleStop(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var stopReq VTPMStopRequest
	if err := quicwire.DecodePayload(req.Payload, &stopReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if stopReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	if err := h.service.Stop(ctx, stopReq.BundleID); err != nil {
		h.logger.Error(err, "failed to stop vTPM", "bundle_id", stopReq.BundleID)
		return h.vtpmErrorResponse(err)
	}

	resp := &VTPMStopResponse{
		BundleID:  stopReq.BundleID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Info("vTPM stopped", "bundle_id", stopReq.BundleID)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetState gets the state of a vTPM bundle
func (h *VTPMHandler) handleGetState(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var stateReq VTPMGetStateRequest
	if err := quicwire.DecodePayload(req.Payload, &stateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if stateReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	running := h.service.IsRunning(stateReq.BundleID)
	socketPath := ""
	if running {
		socketPath = h.service.GetTPMSocketPath(stateReq.BundleID)
	}

	resp := &VTPMGetStateResponse{
		BundleID:   stateReq.BundleID,
		Running:    running,
		SocketPath: socketPath,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleIsRunning checks if a vTPM is running
func (h *VTPMHandler) handleIsRunning(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var runningReq VTPMIsRunningRequest
	if err := quicwire.DecodePayload(req.Payload, &runningReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if runningReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	running := h.service.IsRunning(runningReq.BundleID)

	resp := &VTPMIsRunningResponse{
		BundleID:  runningReq.BundleID,
		Running:   running,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// TPM Operation Handler Methods
// =============================================================================

// handleQuote generates a TPM quote
func (h *VTPMHandler) handleQuote(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var quoteReq VTPMQuoteRequest
	if err := quicwire.DecodePayload(req.Payload, &quoteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if quoteReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	if len(quoteReq.Nonce) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingNonce)
	}

	for _, pcr := range quoteReq.PCRs {
		if pcr < 0 || pcr > 23 {
			return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMInvalidPCRIndex)
		}
	}

	result, err := h.service.Quote(ctx, quoteReq.BundleID, quoteReq.Nonce, quoteReq.PCRs)
	if err != nil {
		h.logger.Error(err, "failed to generate TPM quote", "bundle_id", quoteReq.BundleID)
		return h.vtpmErrorResponse(err)
	}

	resp := &VTPMQuoteResponse{
		BundleID:      quoteReq.BundleID,
		Quote:         result.Quote,
		Signature:     result.Signature,
		PCRValues:     result.PCRValues,
		HashAlgorithm: result.HashAlgorithm,
		Timestamp:     time.Now().Unix(),
	}

	h.logger.Debug("TPM quote generated", "bundle_id", quoteReq.BundleID, "pcrs", quoteReq.PCRs)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleReadPCR reads a PCR value
func (h *VTPMHandler) handleReadPCR(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var readReq VTPMReadPCRRequest
	if err := quicwire.DecodePayload(req.Payload, &readReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if readReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	if readReq.PCRIndex < 0 || readReq.PCRIndex > 23 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMInvalidPCRIndex)
	}

	value, err := h.service.ReadPCR(ctx, readReq.BundleID, readReq.PCRIndex)
	if err != nil {
		h.logger.Error(err, "failed to read PCR", "bundle_id", readReq.BundleID, "pcr", readReq.PCRIndex)
		return h.vtpmErrorResponse(err)
	}

	resp := &VTPMReadPCRResponse{
		BundleID:  readReq.BundleID,
		PCRIndex:  readReq.PCRIndex,
		Value:     value,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleExtendPCR extends a PCR with data
func (h *VTPMHandler) handleExtendPCR(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var extendReq VTPMExtendPCRRequest
	if err := quicwire.DecodePayload(req.Payload, &extendReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if extendReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	if extendReq.PCRIndex < 0 || extendReq.PCRIndex > 23 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMInvalidPCRIndex)
	}

	if len(extendReq.Data) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingData)
	}

	if err := h.service.ExtendPCR(ctx, extendReq.BundleID, extendReq.PCRIndex, extendReq.Data); err != nil {
		h.logger.Error(err, "failed to extend PCR", "bundle_id", extendReq.BundleID, "pcr", extendReq.PCRIndex)
		return h.vtpmErrorResponse(err)
	}

	resp := &VTPMExtendPCRResponse{
		BundleID:  extendReq.BundleID,
		PCRIndex:  extendReq.PCRIndex,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Debug("PCR extended", "bundle_id", extendReq.BundleID, "pcr", extendReq.PCRIndex)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleSeal seals data to the TPM
func (h *VTPMHandler) handleSeal(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var sealReq VTPMSealRequest
	if err := quicwire.DecodePayload(req.Payload, &sealReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if sealReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	if len(sealReq.Data) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingData)
	}

	for _, pcr := range sealReq.PCRs {
		if pcr < 0 || pcr > 23 {
			return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMInvalidPCRIndex)
		}
	}

	opts := &vtpm.SealOptions{
		PCRs:      sealReq.PCRs,
		AuthValue: sealReq.AuthValue,
	}

	sealedData, err := h.service.Seal(ctx, sealReq.BundleID, sealReq.Data, opts)
	if err != nil {
		h.logger.Error(err, "failed to seal data", "bundle_id", sealReq.BundleID)
		return h.vtpmErrorResponse(err)
	}

	resp := &VTPMSealResponse{
		BundleID:   sealReq.BundleID,
		SealedData: sealedData,
		Timestamp:  time.Now().Unix(),
	}

	h.logger.Debug("data sealed", "bundle_id", sealReq.BundleID)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleUnseal unseals data from the TPM
func (h *VTPMHandler) handleUnseal(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var unsealReq VTPMUnsealRequest
	if err := quicwire.DecodePayload(req.Payload, &unsealReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if unsealReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	if len(unsealReq.SealedData) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingSealedData)
	}

	data, err := h.service.Unseal(ctx, unsealReq.BundleID, unsealReq.SealedData, unsealReq.AuthValue)
	if err != nil {
		h.logger.Error(err, "failed to unseal data", "bundle_id", unsealReq.BundleID)
		return h.vtpmErrorResponse(err)
	}

	resp := &VTPMUnsealResponse{
		BundleID:  unsealReq.BundleID,
		Data:      data,
		Timestamp: time.Now().Unix(),
	}

	h.logger.Debug("data unsealed", "bundle_id", unsealReq.BundleID)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Export/Import Handler Methods
// =============================================================================

// handleExportBundle exports a bundle to a tar.gz archive
func (h *VTPMHandler) handleExportBundle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var exportReq VTPMExportBundleRequest
	if err := quicwire.DecodePayload(req.Payload, &exportReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if exportReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	var buf bytes.Buffer
	if err := h.service.ExportBundle(ctx, exportReq.BundleID, &buf); err != nil {
		h.logger.Error(err, "failed to export bundle", "bundle_id", exportReq.BundleID)
		return h.vtpmErrorResponse(err)
	}

	resp := &VTPMExportBundleResponse{
		BundleID:  exportReq.BundleID,
		Data:      buf.Bytes(),
		Timestamp: time.Now().Unix(),
	}

	h.logger.Info("bundle exported", "bundle_id", exportReq.BundleID)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleImportBundle imports a bundle from a tar.gz archive
func (h *VTPMHandler) handleImportBundle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var importReq VTPMImportBundleRequest
	if err := quicwire.DecodePayload(req.Payload, &importReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if len(importReq.Data) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingData)
	}

	bundle, err := h.service.ImportBundle(ctx, io.NopCloser(bytes.NewReader(importReq.Data)))
	if err != nil {
		h.logger.Error(err, "failed to import bundle")
		return h.vtpmErrorResponse(err)
	}

	resp := h.bundleToResponse(bundle)
	h.logger.Info("bundle imported", "bundle_id", bundle.ID)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleValidateBundle validates bundle integrity
func (h *VTPMHandler) handleValidateBundle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var validateReq VTPMValidateBundleRequest
	if err := quicwire.DecodePayload(req.Payload, &validateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if validateReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	err := h.service.ValidateBundle(ctx, validateReq.BundleID)
	valid := err == nil

	if err != nil {
		h.logger.Warn("bundle validation failed", "bundle_id", validateReq.BundleID, "error", err)
	}

	resp := &VTPMValidateBundleResponse{
		BundleID:  validateReq.BundleID,
		Valid:     valid,
		Timestamp: time.Now().Unix(),
	}

	payload, encodeErr := quicwire.EncodePayload(resp)
	if encodeErr != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: encodeErr})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Path Handler Methods
// =============================================================================

// handleGetBundlePath returns the filesystem path to a bundle
func (h *VTPMHandler) handleGetBundlePath(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var pathReq VTPMGetPathRequest
	if err := quicwire.DecodePayload(req.Payload, &pathReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if pathReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	path := h.service.GetBundlePath(pathReq.BundleID)

	resp := &VTPMGetPathResponse{
		BundleID:  pathReq.BundleID,
		Path:      path,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetSocketPath returns the TPM socket path for a bundle
func (h *VTPMHandler) handleGetSocketPath(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var pathReq VTPMGetPathRequest
	if err := quicwire.DecodePayload(req.Payload, &pathReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if pathReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	path := h.service.GetTPMSocketPath(pathReq.BundleID)

	resp := &VTPMGetPathResponse{
		BundleID:  pathReq.BundleID,
		Path:      path,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetNVRAMPath returns the OVMF NVRAM path for a bundle
func (h *VTPMHandler) handleGetNVRAMPath(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVTPMServiceNotAvailable)
	}

	var pathReq VTPMGetPathRequest
	if err := quicwire.DecodePayload(req.Payload, &pathReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVTPMDecodingFailed{Cause: err})
	}

	if pathReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVTPMMissingBundleID)
	}

	path := h.service.GetNVRAMPath(pathReq.BundleID)

	resp := &VTPMGetPathResponse{
		BundleID:  pathReq.BundleID,
		Path:      path,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVTPMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Helper Methods
// =============================================================================

// bundleToResponse converts a vtpm.Bundle to VTPMBundleResponse
func (h *VTPMHandler) bundleToResponse(bundle *vtpm.Bundle) *VTPMBundleResponse {
	if bundle == nil {
		return nil
	}

	resp := &VTPMBundleResponse{
		ID:         bundle.ID,
		Mode:       string(bundle.Mode),
		CreatedAt:  bundle.CreatedAt.Unix(),
		ClonedFrom: bundle.ClonedFrom,
		Timestamp:  time.Now().Unix(),
	}

	if bundle.Manifest != nil {
		resp.Hostname = bundle.Manifest.Hostname
		resp.EKAlgorithm = string(bundle.Manifest.EKAlgorithm)
		resp.SecureBootEnabled = bundle.Manifest.SecureBootEnabled
		resp.Labels = bundle.Manifest.Labels

		if bundle.Manifest.EKCertificate != nil {
			resp.EKCertificate = &VTPMEKCertificateResponse{
				Subject:      bundle.Manifest.EKCertificate.Subject,
				Issuer:       bundle.Manifest.EKCertificate.Issuer,
				SerialNumber: bundle.Manifest.EKCertificate.SerialNumber,
				NotBefore:    bundle.Manifest.EKCertificate.NotBefore.Unix(),
				NotAfter:     bundle.Manifest.EKCertificate.NotAfter.Unix(),
				Fingerprint:  bundle.Manifest.EKCertificate.Fingerprint,
			}
		}

		if bundle.Manifest.SecureBootKeys != nil {
			resp.SecureBootKeys = &VTPMSecureBootKeysResponse{
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

// templateToResponse converts a vtpm.Template to VTPMTemplateResponse
func (h *VTPMHandler) templateToResponse(template *vtpm.Template) *VTPMTemplateResponse {
	if template == nil {
		return nil
	}

	return &VTPMTemplateResponse{
		ID:                template.ID,
		Description:       template.Description,
		EKAlgorithm:       string(template.EKAlgorithm),
		SecureBootEnabled: template.SecureBootEnabled,
		CreatedAt:         template.CreatedAt.Unix(),
		Timestamp:         time.Now().Unix(),
	}
}

// errorResponse creates an error response with the given status and error
func (h *VTPMHandler) errorResponse(status byte, err error) *quicwire.Response {
	return &quicwire.Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// vtpmErrorResponse maps vTPM errors to appropriate status codes
func (h *VTPMHandler) vtpmErrorResponse(err error) *quicwire.Response {
	var status byte

	var bundleNotFound vtpm.ErrBundleNotFound
	var bundleExists vtpm.ErrBundleAlreadyExists
	var templateNotFound vtpm.ErrTemplateNotFound
	var templateExists vtpm.ErrTemplateAlreadyExists
	var invalidConfig vtpm.ErrInvalidConfig
	var invalidManifest vtpm.ErrInvalidManifest
	var vtpmNotRunning vtpm.ErrVTPMNotRunning
	var vtpmAlreadyRunning vtpm.ErrVTPMAlreadyRunning
	var invalidNonce vtpm.ErrInvalidNonce
	var invalidPCR vtpm.ErrInvalidPCRIndex
	var checksumMismatch vtpm.ErrChecksumMismatch
	var caUnavailable vtpm.ErrCAUnavailable

	switch {
	case errors.As(err, &bundleNotFound):
		status = quicwire.StatusNotFound
	case errors.As(err, &bundleExists):
		status = quicwire.StatusAlreadyExists
	case errors.As(err, &templateNotFound):
		status = quicwire.StatusNotFound
	case errors.As(err, &templateExists):
		status = quicwire.StatusAlreadyExists
	case errors.As(err, &invalidConfig):
		status = quicwire.StatusInvalidArgument
	case errors.As(err, &invalidManifest):
		status = quicwire.StatusInvalidArgument
	case errors.As(err, &vtpmNotRunning):
		status = quicwire.StatusInvalidRequest
	case errors.As(err, &vtpmAlreadyRunning):
		status = quicwire.StatusAlreadyExists
	case errors.As(err, &invalidNonce):
		status = quicwire.StatusInvalidArgument
	case errors.As(err, &invalidPCR):
		status = quicwire.StatusInvalidArgument
	case errors.As(err, &checksumMismatch):
		status = quicwire.StatusInvalidArgument
	case errors.As(err, &caUnavailable):
		status = quicwire.StatusUnavailable
	default:
		status = quicwire.StatusInternalError
	}

	return h.errorResponse(status, err)
}

// =============================================================================
// vTPM Error Types
// =============================================================================

// ErrVTPMEncodingFailed represents an encoding failure error
type ErrVTPMEncodingFailed struct {
	Cause error
}

func (e ErrVTPMEncodingFailed) Error() string {
	return "failed to encode vTPM payload: " + e.Cause.Error()
}

func (e ErrVTPMEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrVTPMDecodingFailed represents a decoding failure error
type ErrVTPMDecodingFailed struct {
	Cause error
}

func (e ErrVTPMDecodingFailed) Error() string {
	return "failed to decode vTPM payload: " + e.Cause.Error()
}

func (e ErrVTPMDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrVTPMOperationFailed represents a vTPM operation failure
type ErrVTPMOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrVTPMOperationFailed) Error() string {
	return "vTPM operation " + e.Operation + " failed: " + e.Cause.Error()
}

func (e ErrVTPMOperationFailed) Unwrap() error {
	return e.Cause
}
