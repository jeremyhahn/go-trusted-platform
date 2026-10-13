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

package daemon

import (
	"bytes"
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// vTPM QUIC Request/Response Types
// =============================================================================

// VTPMGetBundleRequest represents a get bundle request
type VTPMGetBundleRequest struct {
	ID string `codec:"id"`
}

// VTPMGetBundleResponse represents a get bundle response
type VTPMGetBundleResponse struct {
	ID                string                  `codec:"id"`
	Mode              string                  `codec:"mode"`
	Hostname          string                  `codec:"hostname"`
	EKAlgorithm       string                  `codec:"ek_algorithm"`
	SecureBootEnabled bool                    `codec:"secure_boot_enabled"`
	CreatedAt         int64                   `codec:"created_at"`
	ClonedFrom        string                  `codec:"cloned_from"`
	Labels            map[string]string       `codec:"labels"`
	Checksums         map[string]string       `codec:"checksums"`
	TPMState          *VTPMTPMStateQUIC       `codec:"tpm_state"`
	OVMFState         *VTPMOVMFStateQUIC      `codec:"ovmf_state"`
	SecureBootKeys    *VTPMSecureBootKeysQUIC `codec:"secure_boot_keys"`
	EKCertificate     *VTPMEKCertInfoQUIC     `codec:"ek_certificate"`
	Timestamp         int64                   `codec:"timestamp"`
}

// VTPMTPMStateQUIC represents TPM state paths
type VTPMTPMStateQUIC struct {
	StateDir     string `codec:"state_dir"`
	PermallFile  string `codec:"permall_file"`
	VolatileFile string `codec:"volatile_file"`
}

// VTPMOVMFStateQUIC represents OVMF state paths
type VTPMOVMFStateQUIC struct {
	NVRAMFile string `codec:"nvram_file"`
}

// VTPMSecureBootKeysQUIC represents Secure Boot key paths
type VTPMSecureBootKeysQUIC struct {
	Dir     string `codec:"dir"`
	PKKey   string `codec:"pk_key"`
	PKCert  string `codec:"pk_crt"`
	KEKKey  string `codec:"kek_key"`
	KEKCert string `codec:"kek_crt"`
	DBKey   string `codec:"db_key"`
	DBCert  string `codec:"db_crt"`
}

// VTPMEKCertInfoQUIC represents EK certificate metadata
type VTPMEKCertInfoQUIC struct {
	Subject      string `codec:"subject"`
	Issuer       string `codec:"issuer"`
	SerialNumber string `codec:"serial_number"`
	NotBefore    int64  `codec:"not_before"`
	NotAfter     int64  `codec:"not_after"`
	Fingerprint  string `codec:"fingerprint"`
}

// VTPMSecureBootKeyInfoQUIC represents Secure Boot key info
type VTPMSecureBootKeyInfoQUIC struct {
	PKFingerprint  string `codec:"pk_fingerprint"`
	KEKFingerprint string `codec:"kek_fingerprint"`
	DBFingerprint  string `codec:"db_fingerprint"`
	OwnerGUID      string `codec:"owner_guid"`
}

// VTPMStartRequest represents a vTPM start request
type VTPMStartRequest struct {
	BundleID string `codec:"bundle_id"`
}

// VTPMStartResponse represents a vTPM start response
type VTPMStartResponse struct {
	BundleID   string `codec:"bundle_id"`
	Running    bool   `codec:"running"`
	SocketPath string `codec:"socket_path"`
	Timestamp  int64  `codec:"timestamp"`
}

// VTPMStopRequest represents a vTPM stop request
type VTPMStopRequest struct {
	BundleID string `codec:"bundle_id"`
}

// VTPMStopResponse represents a vTPM stop response
type VTPMStopResponse struct {
	BundleID  string `codec:"bundle_id"`
	Stopped   bool   `codec:"stopped"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMIsRunningRequest represents a vTPM is running check request
type VTPMIsRunningRequest struct {
	BundleID string `codec:"bundle_id"`
}

// VTPMIsRunningResponse represents a vTPM is running check response
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
	Extended  bool   `codec:"extended"`
	Timestamp int64  `codec:"timestamp"`
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

// VTPMCreateTemplateRequest represents a create template request
type VTPMCreateTemplateRequest struct {
	ID                string `codec:"id"`
	Description       string `codec:"description"`
	EKAlgorithm       string `codec:"ek_algorithm"`
	SecureBootEnabled bool   `codec:"secure_boot_enabled"`
}

// VTPMCreateTemplateResponse represents a create template response
type VTPMCreateTemplateResponse struct {
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

// VTPMGetTemplateResponse represents a get template response
type VTPMGetTemplateResponse struct {
	ID                string `codec:"id"`
	Description       string `codec:"description"`
	TPMStateDir       string `codec:"tpm_state_dir"`
	NVRAMPath         string `codec:"nvram_path"`
	SecureBootKeysDir string `codec:"secure_boot_keys_dir"`
	EKAlgorithm       string `codec:"ek_algorithm"`
	SecureBootEnabled bool   `codec:"secure_boot_enabled"`
	CreatedAt         int64  `codec:"created_at"`
	Timestamp         int64  `codec:"timestamp"`
}

// VTPMDeleteTemplateRequest represents a delete template request
type VTPMDeleteTemplateRequest struct {
	ID string `codec:"id"`
}

// VTPMDeleteTemplateResponse represents a delete template response
type VTPMDeleteTemplateResponse struct {
	ID        string `codec:"id"`
	Deleted   bool   `codec:"deleted"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMListTemplatesRequest represents a list templates request
type VTPMListTemplatesRequest struct {
	// No filters for templates currently
}

// VTPMTemplateSummary represents a template summary
type VTPMTemplateSummary struct {
	ID                string `codec:"id"`
	Description       string `codec:"description"`
	EKAlgorithm       string `codec:"ek_algorithm"`
	SecureBootEnabled bool   `codec:"secure_boot_enabled"`
	CreatedAt         int64  `codec:"created_at"`
}

// VTPMListTemplatesResponse represents a list templates response
type VTPMListTemplatesResponse struct {
	Templates []*VTPMTemplateSummary `codec:"templates"`
	Total     int                    `codec:"total"`
	Timestamp int64                  `codec:"timestamp"`
}

// VTPMCloneTemplateRequest represents a clone template request
type VTPMCloneTemplateRequest struct {
	TemplateID string            `codec:"template_id"`
	Hostname   string            `codec:"hostname"`
	Labels     map[string]string `codec:"labels"`
}

// VTPMCloneTemplateResponse represents a clone template response
type VTPMCloneTemplateResponse struct {
	BundleID   string `codec:"bundle_id"`
	TemplateID string `codec:"template_id"`
	Hostname   string `codec:"hostname"`
	CreatedAt  int64  `codec:"created_at"`
	Timestamp  int64  `codec:"timestamp"`
}

// VTPMExportBundleRequest represents an export bundle request
type VTPMExportBundleRequest struct {
	ID string `codec:"id"`
}

// VTPMExportBundleResponse represents an export bundle response
type VTPMExportBundleResponse struct {
	ID        string `codec:"id"`
	Data      []byte `codec:"data"`
	Size      int64  `codec:"size"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMImportBundleRequest represents an import bundle request
type VTPMImportBundleRequest struct {
	Data []byte `codec:"data"`
}

// VTPMImportBundleResponse represents an import bundle response
type VTPMImportBundleResponse struct {
	BundleID  string `codec:"bundle_id"`
	Hostname  string `codec:"hostname"`
	Mode      string `codec:"mode"`
	CreatedAt int64  `codec:"created_at"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMValidateBundleRequest represents a validate bundle request
type VTPMValidateBundleRequest struct {
	ID string `codec:"id"`
}

// VTPMValidateBundleResponse represents a validate bundle response
type VTPMValidateBundleResponse struct {
	ID        string   `codec:"id"`
	Valid     bool     `codec:"valid"`
	Errors    []string `codec:"errors"`
	Timestamp int64    `codec:"timestamp"`
}

// VTPMGetPathRequest represents a get path request (bundle, socket, or NVRAM)
type VTPMGetPathRequest struct {
	ID string `codec:"id"`
}

// VTPMGetPathResponse represents a get path response
type VTPMGetPathResponse struct {
	ID        string `codec:"id"`
	Path      string `codec:"path"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// vTPM QUIC Operation Handler
// =============================================================================

// handleVTPMOperation routes vTPM opcodes to their respective handlers.
// This handles both base vTPM operations (0x10-0x1F) and extended operations (0x03-0x0F).
func (h *QUICServiceHandler) handleVTPMOperation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.vtpmService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "vtpm"})
	}

	switch req.Opcode {
	// Extended vTPM Operations (0x03-0x0F) - Template and Bundle Management
	case quicwire.OpVTPMCreateTemplate:
		return h.handleVTPMCreateTemplate(ctx, req)
	case quicwire.OpVTPMGetTemplate:
		return h.handleVTPMGetTemplate(ctx, req)
	case quicwire.OpVTPMDeleteTemplate:
		return h.handleVTPMDeleteTemplate(ctx, req)
	case quicwire.OpVTPMListTemplates:
		return h.handleVTPMListTemplates(ctx, req)
	case quicwire.OpVTPMCloneTemplate:
		return h.handleVTPMCloneTemplate(ctx, req)
	case quicwire.OpVTPMExportBundle:
		return h.handleVTPMExportBundle(ctx, req)
	case quicwire.OpVTPMImportBundle:
		return h.handleVTPMImportBundle(ctx, req)
	case quicwire.OpVTPMValidateBundle:
		return h.handleVTPMValidateBundle(ctx, req)
	case quicwire.OpVTPMGetBundlePath:
		return h.handleVTPMGetBundlePath(ctx, req)
	case quicwire.OpVTPMGetSocketPath:
		return h.handleVTPMGetTPMSocketPath(ctx, req)
	case quicwire.OpVTPMGetNVRAMPath:
		return h.handleVTPMGetNVRAMPath(ctx, req)
	case quicwire.OpVTPMGetBundle:
		return h.handleVTPMGetBundle(ctx, req)
	case quicwire.OpVTPMIsRunning:
		return h.handleVTPMIsRunning(ctx, req)

	// Base vTPM Operations (0x10-0x1F)
	case quicwire.OpVTPMCreate:
		return h.handleVTPMCreate(ctx, req)
	case quicwire.OpVTPMDelete:
		return h.handleVTPMDelete(ctx, req)
	case quicwire.OpVTPMStart:
		return h.handleVTPMStart(ctx, req)
	case quicwire.OpVTPMStop:
		return h.handleVTPMStop(ctx, req)
	case quicwire.OpVTPMGetState:
		return h.handleVTPMGetBundle(ctx, req)
	case quicwire.OpVTPMList:
		return h.handleVTPMList(ctx, req)
	case quicwire.OpVTPMQuote:
		return h.handleVTPMQuote(ctx, req)
	case quicwire.OpVTPMSeal:
		return h.handleVTPMSeal(ctx, req)
	case quicwire.OpVTPMUnseal:
		return h.handleVTPMUnseal(ctx, req)
	case quicwire.OpVTPMExtendPCR:
		return h.handleVTPMExtendPCR(ctx, req)
	case quicwire.OpVTPMReadPCR:
		return h.handleVTPMReadPCR(ctx, req)

	default:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleVTPMGetBundle retrieves a bundle by ID with full details.
func (h *QUICServiceHandler) handleVTPMGetBundle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq VTPMGetBundleRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	bundle, err := h.vtpmService.GetBundle(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get vTPM bundle", "id", getReq.ID)
		return h.mapVTPMError(err)
	}

	resp := h.bundleToQUICResponse(bundle)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMStart starts a vTPM daemon for a bundle.
func (h *QUICServiceHandler) handleVTPMStart(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var startReq VTPMStartRequest
	if err := quicwire.DecodePayload(req.Payload, &startReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if startReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bundle_id"})
	}

	if err := h.vtpmService.Start(ctx, startReq.BundleID); err != nil {
		h.logger.Error(err, "failed to start vTPM", "bundle_id", startReq.BundleID)
		return h.mapVTPMError(err)
	}

	socketPath := h.vtpmService.GetTPMSocketPath(startReq.BundleID)

	resp := &VTPMStartResponse{
		BundleID:   startReq.BundleID,
		Running:    true,
		SocketPath: socketPath,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("vTPM started", "bundle_id", startReq.BundleID)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMStop stops a vTPM daemon for a bundle.
func (h *QUICServiceHandler) handleVTPMStop(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var stopReq VTPMStopRequest
	if err := quicwire.DecodePayload(req.Payload, &stopReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if stopReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bundle_id"})
	}

	if err := h.vtpmService.Stop(ctx, stopReq.BundleID); err != nil {
		h.logger.Error(err, "failed to stop vTPM", "bundle_id", stopReq.BundleID)
		return h.mapVTPMError(err)
	}

	resp := &VTPMStopResponse{
		BundleID:  stopReq.BundleID,
		Stopped:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("vTPM stopped", "bundle_id", stopReq.BundleID)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMIsRunning checks if a vTPM is running.
func (h *QUICServiceHandler) handleVTPMIsRunning(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var checkReq VTPMIsRunningRequest
	if err := quicwire.DecodePayload(req.Payload, &checkReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if checkReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bundle_id"})
	}

	running := h.vtpmService.IsRunning(checkReq.BundleID)

	resp := &VTPMIsRunningResponse{
		BundleID:  checkReq.BundleID,
		Running:   running,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMQuote generates a TPM quote.
func (h *QUICServiceHandler) handleVTPMQuote(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var quoteReq VTPMQuoteRequest
	if err := quicwire.DecodePayload(req.Payload, &quoteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if quoteReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bundle_id"})
	}

	if len(quoteReq.Nonce) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "nonce"})
	}

	result, err := h.vtpmService.Quote(ctx, quoteReq.BundleID, quoteReq.Nonce, quoteReq.PCRs)
	if err != nil {
		h.logger.Error(err, "failed to generate TPM quote", "bundle_id", quoteReq.BundleID)
		return h.mapVTPMError(err)
	}

	resp := &VTPMQuoteResponse{
		BundleID:      quoteReq.BundleID,
		Quote:         result.Quote,
		Signature:     result.Signature,
		PCRValues:     result.PCRValues,
		HashAlgorithm: result.HashAlgorithm,
		Timestamp:     time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMSeal seals data to the TPM.
func (h *QUICServiceHandler) handleVTPMSeal(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var sealReq VTPMSealRequest
	if err := quicwire.DecodePayload(req.Payload, &sealReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if sealReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bundle_id"})
	}

	if len(sealReq.Data) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "data"})
	}

	opts := &vtpm.SealOptions{
		PCRs:      sealReq.PCRs,
		AuthValue: sealReq.AuthValue,
	}

	sealedData, err := h.vtpmService.Seal(ctx, sealReq.BundleID, sealReq.Data, opts)
	if err != nil {
		h.logger.Error(err, "failed to seal data", "bundle_id", sealReq.BundleID)
		return h.mapVTPMError(err)
	}

	resp := &VTPMSealResponse{
		BundleID:   sealReq.BundleID,
		SealedData: sealedData,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMUnseal unseals data from the TPM.
func (h *QUICServiceHandler) handleVTPMUnseal(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var unsealReq VTPMUnsealRequest
	if err := quicwire.DecodePayload(req.Payload, &unsealReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if unsealReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bundle_id"})
	}

	if len(unsealReq.SealedData) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "sealed_data"})
	}

	data, err := h.vtpmService.Unseal(ctx, unsealReq.BundleID, unsealReq.SealedData, unsealReq.AuthValue)
	if err != nil {
		h.logger.Error(err, "failed to unseal data", "bundle_id", unsealReq.BundleID)
		return h.mapVTPMError(err)
	}

	resp := &VTPMUnsealResponse{
		BundleID:  unsealReq.BundleID,
		Data:      data,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMExtendPCR extends a PCR with data.
func (h *QUICServiceHandler) handleVTPMExtendPCR(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var extendReq VTPMExtendPCRRequest
	if err := quicwire.DecodePayload(req.Payload, &extendReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if extendReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bundle_id"})
	}

	if len(extendReq.Data) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "data"})
	}

	if err := h.vtpmService.ExtendPCR(ctx, extendReq.BundleID, extendReq.PCRIndex, extendReq.Data); err != nil {
		h.logger.Error(err, "failed to extend PCR", "bundle_id", extendReq.BundleID, "pcr", extendReq.PCRIndex)
		return h.mapVTPMError(err)
	}

	resp := &VTPMExtendPCRResponse{
		BundleID:  extendReq.BundleID,
		PCRIndex:  extendReq.PCRIndex,
		Extended:  true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMReadPCR reads a PCR value.
func (h *QUICServiceHandler) handleVTPMReadPCR(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var readReq VTPMReadPCRRequest
	if err := quicwire.DecodePayload(req.Payload, &readReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if readReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bundle_id"})
	}

	value, err := h.vtpmService.ReadPCR(ctx, readReq.BundleID, readReq.PCRIndex)
	if err != nil {
		h.logger.Error(err, "failed to read PCR", "bundle_id", readReq.BundleID, "pcr", readReq.PCRIndex)
		return h.mapVTPMError(err)
	}

	resp := &VTPMReadPCRResponse{
		BundleID:  readReq.BundleID,
		PCRIndex:  readReq.PCRIndex,
		Value:     value,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMCreateTemplate creates a new template.
func (h *QUICServiceHandler) handleVTPMCreateTemplate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var createReq VTPMCreateTemplateRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if createReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	ekAlg, err := vtpm.ParseEKAlgorithm(createReq.EKAlgorithm)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	opts := &vtpm.CreateTemplateOptions{
		ID:                createReq.ID,
		Description:       createReq.Description,
		EKAlgorithm:       ekAlg,
		SecureBootEnabled: createReq.SecureBootEnabled,
	}

	template, err := h.vtpmService.CreateTemplate(ctx, opts)
	if err != nil {
		h.logger.Error(err, "failed to create vTPM template", "id", createReq.ID)
		return h.mapVTPMError(err)
	}

	resp := &VTPMCreateTemplateResponse{
		ID:                template.ID,
		Description:       template.Description,
		EKAlgorithm:       string(template.EKAlgorithm),
		SecureBootEnabled: template.SecureBootEnabled,
		CreatedAt:         template.CreatedAt.Unix(),
		Timestamp:         time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("vTPM template created", "id", template.ID)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMGetTemplate retrieves a template by ID.
func (h *QUICServiceHandler) handleVTPMGetTemplate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq VTPMGetTemplateRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	template, err := h.vtpmService.GetTemplate(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get vTPM template", "id", getReq.ID)
		return h.mapVTPMError(err)
	}

	resp := &VTPMGetTemplateResponse{
		ID:                template.ID,
		Description:       template.Description,
		TPMStateDir:       template.TPMStateDir,
		NVRAMPath:         template.NVRAMPath,
		SecureBootKeysDir: template.SecureBootKeysDir,
		EKAlgorithm:       string(template.EKAlgorithm),
		SecureBootEnabled: template.SecureBootEnabled,
		CreatedAt:         template.CreatedAt.Unix(),
		Timestamp:         time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMDeleteTemplate deletes a template.
func (h *QUICServiceHandler) handleVTPMDeleteTemplate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var deleteReq VTPMDeleteTemplateRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	if err := h.vtpmService.DeleteTemplate(ctx, deleteReq.ID); err != nil {
		h.logger.Error(err, "failed to delete vTPM template", "id", deleteReq.ID)
		return h.mapVTPMError(err)
	}

	resp := &VTPMDeleteTemplateResponse{
		ID:        deleteReq.ID,
		Deleted:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("vTPM template deleted", "id", deleteReq.ID)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMListTemplates lists all templates.
func (h *QUICServiceHandler) handleVTPMListTemplates(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	templates, err := h.vtpmService.ListTemplates(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list vTPM templates")
		return h.mapVTPMError(err)
	}

	summaries := make([]*VTPMTemplateSummary, 0, len(templates))
	for _, t := range templates {
		summaries = append(summaries, &VTPMTemplateSummary{
			ID:                t.ID,
			Description:       t.Description,
			EKAlgorithm:       string(t.EKAlgorithm),
			SecureBootEnabled: t.SecureBootEnabled,
			CreatedAt:         t.CreatedAt.Unix(),
		})
	}

	resp := &VTPMListTemplatesResponse{
		Templates: summaries,
		Total:     len(summaries),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMCloneTemplate clones a template to create a new bundle.
func (h *QUICServiceHandler) handleVTPMCloneTemplate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var cloneReq VTPMCloneTemplateRequest
	if err := quicwire.DecodePayload(req.Payload, &cloneReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if cloneReq.TemplateID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "template_id"})
	}

	if cloneReq.Hostname == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "hostname"})
	}

	opts := &vtpm.CloneOptions{
		TemplateID: cloneReq.TemplateID,
		Hostname:   cloneReq.Hostname,
		Labels:     cloneReq.Labels,
	}

	bundle, err := h.vtpmService.CloneTemplate(ctx, opts)
	if err != nil {
		h.logger.Error(err, "failed to clone vTPM template", "template_id", cloneReq.TemplateID)
		return h.mapVTPMError(err)
	}

	// Use bundleToQUICResponse for consistency with other bundle operations
	resp := h.bundleToQUICResponse(bundle)

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("vTPM template cloned", "template_id", cloneReq.TemplateID, "bundle_id", bundle.ID)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMExportBundle exports a bundle to a tar.gz archive.
func (h *QUICServiceHandler) handleVTPMExportBundle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var exportReq VTPMExportBundleRequest
	if err := quicwire.DecodePayload(req.Payload, &exportReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if exportReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	var buf bytes.Buffer
	if err := h.vtpmService.ExportBundle(ctx, exportReq.ID, &buf); err != nil {
		h.logger.Error(err, "failed to export vTPM bundle", "id", exportReq.ID)
		return h.mapVTPMError(err)
	}

	resp := &VTPMExportBundleResponse{
		ID:        exportReq.ID,
		Data:      buf.Bytes(),
		Size:      int64(buf.Len()),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("vTPM bundle exported", "id", exportReq.ID, "size", buf.Len())

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMImportBundle imports a bundle from a tar.gz archive.
func (h *QUICServiceHandler) handleVTPMImportBundle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var importReq VTPMImportBundleRequest
	if err := quicwire.DecodePayload(req.Payload, &importReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if len(importReq.Data) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "data"})
	}

	buf := bytes.NewReader(importReq.Data)
	bundle, err := h.vtpmService.ImportBundle(ctx, buf)
	if err != nil {
		h.logger.Error(err, "failed to import vTPM bundle")
		return h.mapVTPMError(err)
	}

	hostname := ""
	if bundle.Manifest != nil {
		hostname = bundle.Manifest.Hostname
	}

	resp := &VTPMImportBundleResponse{
		BundleID:  bundle.ID,
		Hostname:  hostname,
		Mode:      string(bundle.Mode),
		CreatedAt: bundle.CreatedAt.Unix(),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("vTPM bundle imported", "bundle_id", bundle.ID)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMValidateBundle validates bundle integrity.
func (h *QUICServiceHandler) handleVTPMValidateBundle(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var validateReq VTPMValidateBundleRequest
	if err := quicwire.DecodePayload(req.Payload, &validateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if validateReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	err := h.vtpmService.ValidateBundle(ctx, validateReq.ID)

	var errors []string
	if err != nil {
		errors = []string{err.Error()}
	}

	resp := &VTPMValidateBundleResponse{
		ID:        validateReq.ID,
		Valid:     err == nil,
		Errors:    errors,
		Timestamp: time.Now().Unix(),
	}

	payload, encErr := quicwire.EncodePayload(resp)
	if encErr != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: encErr})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMGetBundlePath returns the filesystem path to a bundle.
func (h *QUICServiceHandler) handleVTPMGetBundlePath(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pathReq VTPMGetPathRequest
	if err := quicwire.DecodePayload(req.Payload, &pathReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if pathReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	path := h.vtpmService.GetBundlePath(pathReq.ID)

	resp := &VTPMGetPathResponse{
		ID:        pathReq.ID,
		Path:      path,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMGetTPMSocketPath returns the TPM socket path for a bundle.
func (h *QUICServiceHandler) handleVTPMGetTPMSocketPath(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pathReq VTPMGetPathRequest
	if err := quicwire.DecodePayload(req.Payload, &pathReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if pathReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	path := h.vtpmService.GetTPMSocketPath(pathReq.ID)

	resp := &VTPMGetPathResponse{
		ID:        pathReq.ID,
		Path:      path,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMGetNVRAMPath returns the NVRAM path for a bundle.
func (h *QUICServiceHandler) handleVTPMGetNVRAMPath(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var pathReq VTPMGetPathRequest
	if err := quicwire.DecodePayload(req.Payload, &pathReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if pathReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	path := h.vtpmService.GetNVRAMPath(pathReq.ID)

	resp := &VTPMGetPathResponse{
		ID:        pathReq.ID,
		Path:      path,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// vTPM Helper Functions
// =============================================================================

// bundleToQUICResponse converts a vtpm.Bundle to a QUIC response struct.
func (h *QUICServiceHandler) bundleToQUICResponse(bundle *vtpm.Bundle) *VTPMGetBundleResponse {
	resp := &VTPMGetBundleResponse{
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
		resp.Checksums = bundle.Manifest.Checksums

		if bundle.Manifest.EKCertificate != nil {
			resp.EKCertificate = &VTPMEKCertInfoQUIC{
				Subject:      bundle.Manifest.EKCertificate.Subject,
				Issuer:       bundle.Manifest.EKCertificate.Issuer,
				SerialNumber: bundle.Manifest.EKCertificate.SerialNumber,
				NotBefore:    bundle.Manifest.EKCertificate.NotBefore.Unix(),
				NotAfter:     bundle.Manifest.EKCertificate.NotAfter.Unix(),
				Fingerprint:  bundle.Manifest.EKCertificate.Fingerprint,
			}
		}
	}

	if bundle.TPMState != nil {
		resp.TPMState = &VTPMTPMStateQUIC{
			StateDir:     bundle.TPMState.StateDir,
			PermallFile:  bundle.TPMState.PermallFile,
			VolatileFile: bundle.TPMState.VolatileFile,
		}
	}

	if bundle.OVMFState != nil {
		resp.OVMFState = &VTPMOVMFStateQUIC{
			NVRAMFile: bundle.OVMFState.NVRAMFile,
		}
	}

	if bundle.SecureBootKeys != nil {
		resp.SecureBootKeys = &VTPMSecureBootKeysQUIC{
			Dir:     bundle.SecureBootKeys.Dir,
			PKKey:   bundle.SecureBootKeys.PKKey,
			PKCert:  bundle.SecureBootKeys.PKCert,
			KEKKey:  bundle.SecureBootKeys.KEKKey,
			KEKCert: bundle.SecureBootKeys.KEKCert,
			DBKey:   bundle.SecureBootKeys.DBKey,
			DBCert:  bundle.SecureBootKeys.DBCert,
		}
	}

	return resp
}

// mapVTPMError maps vTPM errors to appropriate QUIC status codes.
func (h *QUICServiceHandler) mapVTPMError(err error) *quicwire.Response {
	if err == nil {
		return nil
	}

	errMsg := err.Error()

	// Check for not found errors
	if containsVTPMErrorPattern(errMsg, "not found", "does not exist", "no such") {
		return h.errorResponse(quicwire.StatusNotFound, ErrQUICOperationFailed{Op: "vTPM", Cause: err})
	}

	// Check for already exists errors
	if containsVTPMErrorPattern(errMsg, "already exists", "already running") {
		return h.errorResponse(quicwire.StatusAlreadyExists, ErrQUICOperationFailed{Op: "vTPM", Cause: err})
	}

	// Check for invalid argument errors
	if containsVTPMErrorPattern(errMsg, "invalid", "required", "must be", "cannot be") {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICOperationFailed{Op: "vTPM", Cause: err})
	}

	// Check for not running errors
	if containsVTPMErrorPattern(errMsg, "not running", "not started") {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICOperationFailed{Op: "vTPM", Cause: err})
	}

	// Default to internal error
	return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "vTPM", Cause: err})
}

// containsVTPMErrorPattern checks if the error message contains any of the patterns.
func containsVTPMErrorPattern(s string, patterns ...string) bool {
	for _, pattern := range patterns {
		if len(s) >= len(pattern) {
			for i := 0; i <= len(s)-len(pattern); i++ {
				if s[i:i+len(pattern)] == pattern {
					return true
				}
			}
		}
	}
	return false
}

// VTPMCreateRequest represents a vTPM creation request
type VTPMCreateRequest struct {
	ID                string            `codec:"id"`
	Hostname          string            `codec:"hostname"`
	EKAlgorithm       string            `codec:"ek_algorithm"`
	SecureBootEnabled bool              `codec:"secure_boot_enabled"`
	Labels            map[string]string `codec:"labels"`
}

// VTPMCreateResponse represents a vTPM creation response
type VTPMCreateResponse struct {
	BundleID   string `codec:"bundle_id"`
	Hostname   string `codec:"hostname"`
	Mode       string `codec:"mode"`
	CreatedAt  int64  `codec:"created_at"`
	SocketPath string `codec:"socket_path"`
	Timestamp  int64  `codec:"timestamp"`
}

// VTPMDeleteRequest represents a vTPM deletion request
type VTPMDeleteRequest struct {
	BundleID string `codec:"bundle_id"`
}

// VTPMDeleteResponse represents a vTPM deletion response
type VTPMDeleteResponse struct {
	BundleID  string `codec:"bundle_id"`
	Deleted   bool   `codec:"deleted"`
	Timestamp int64  `codec:"timestamp"`
}

// VTPMListRequest represents a vTPM list request
type VTPMListRequest struct {
	Mode string `codec:"mode"`
}

// VTPMBundleSummary represents a bundle summary for listing
type VTPMBundleSummary struct {
	ID                string `codec:"id"`
	Hostname          string `codec:"hostname"`
	Mode              string `codec:"mode"`
	EKAlgorithm       string `codec:"ek_algorithm"`
	SecureBootEnabled bool   `codec:"secure_boot_enabled"`
	CreatedAt         int64  `codec:"created_at"`
	Running           bool   `codec:"running"`
}

// VTPMListResponse represents a vTPM list response
type VTPMListResponse struct {
	Bundles   []*VTPMBundleSummary `codec:"bundles"`
	Total     int                  `codec:"total"`
	Timestamp int64                `codec:"timestamp"`
}

// handleVTPMCreate creates a new vTPM bundle
func (h *QUICServiceHandler) handleVTPMCreate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var createReq VTPMCreateRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if createReq.Hostname == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "hostname"})
	}

	ekAlg, err := vtpm.ParseEKAlgorithm(createReq.EKAlgorithm)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	opts := &vtpm.CreateBundleOptions{
		Hostname:          createReq.Hostname,
		EKAlgorithm:       ekAlg,
		SecureBootEnabled: createReq.SecureBootEnabled,
		Labels:            createReq.Labels,
	}

	bundle, err := h.vtpmService.CreateBundle(ctx, opts)
	if err != nil {
		h.logger.Error(err, "failed to create vTPM bundle", "hostname", createReq.Hostname)
		return h.mapVTPMError(err)
	}

	resp := &VTPMCreateResponse{
		BundleID:   bundle.ID,
		Hostname:   createReq.Hostname,
		Mode:       string(bundle.Mode),
		CreatedAt:  bundle.CreatedAt.Unix(),
		SocketPath: h.vtpmService.GetTPMSocketPath(bundle.ID),
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("vTPM bundle created", "bundle_id", bundle.ID, "hostname", createReq.Hostname)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMDelete deletes a vTPM bundle
func (h *QUICServiceHandler) handleVTPMDelete(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var deleteReq VTPMDeleteRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.BundleID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bundle_id"})
	}

	if err := h.vtpmService.DeleteBundle(ctx, deleteReq.BundleID); err != nil {
		h.logger.Error(err, "failed to delete vTPM bundle", "bundle_id", deleteReq.BundleID)
		return h.mapVTPMError(err)
	}

	resp := &VTPMDeleteResponse{
		BundleID:  deleteReq.BundleID,
		Deleted:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("vTPM bundle deleted", "bundle_id", deleteReq.BundleID)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVTPMList lists all vTPM bundles
func (h *QUICServiceHandler) handleVTPMList(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var listReq VTPMListRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	bundles, err := h.vtpmService.ListBundles(ctx, nil)
	if err != nil {
		h.logger.Error(err, "failed to list vTPM bundles")
		return h.mapVTPMError(err)
	}

	summaries := make([]*VTPMBundleSummary, 0, len(bundles))
	for _, b := range bundles {
		// Filter by mode if specified
		if listReq.Mode != "" && string(b.Mode) != listReq.Mode {
			continue
		}

		hostname := ""
		ekAlg := ""
		secureBootEnabled := false
		if b.Manifest != nil {
			hostname = b.Manifest.Hostname
			ekAlg = string(b.Manifest.EKAlgorithm)
			secureBootEnabled = b.Manifest.SecureBootEnabled
		}

		summaries = append(summaries, &VTPMBundleSummary{
			ID:                b.ID,
			Hostname:          hostname,
			Mode:              string(b.Mode),
			EKAlgorithm:       ekAlg,
			SecureBootEnabled: secureBootEnabled,
			CreatedAt:         b.CreatedAt.Unix(),
			Running:           h.vtpmService.IsRunning(b.ID),
		})
	}

	resp := &VTPMListResponse{
		Bundles:   summaries,
		Total:     len(summaries),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}
