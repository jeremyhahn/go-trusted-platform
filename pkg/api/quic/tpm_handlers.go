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
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TPM2 sub-opcodes for the category opcode OpTPM2Category.
// The first byte of the payload selects the TPM2 operation.
const (
	SubOpTPM2Info          byte = 0x01
	SubOpTPM2Provision     byte = 0x02
	SubOpTPM2Clear         byte = 0x03
	SubOpTPM2GetEK         byte = 0x04
	SubOpTPM2CreateEK      byte = 0x05
	SubOpTPM2DeleteEK      byte = 0x06
	SubOpTPM2GetEKCert     byte = 0x07
	SubOpTPM2ImportEKCert  byte = 0x08
	SubOpTPM2GetSRK        byte = 0x09
	SubOpTPM2CreateSRK     byte = 0x0A
	SubOpTPM2DeleteSRK     byte = 0x0B
	SubOpTPM2GetIAK        byte = 0x0C
	SubOpTPM2CreateIAK     byte = 0x0D
	SubOpTPM2DeleteIAK     byte = 0x0E
	SubOpTPM2Quote         byte = 0x0F
	SubOpTPM2VerifyQuote   byte = 0x10
	SubOpTPM2ReadPCRs      byte = 0x11
	SubOpTPM2ExtendPCR     byte = 0x12
	SubOpTPM2EventLog      byte = 0x13
	SubOpTPM2Random        byte = 0x14
	SubOpTPM2Seal          byte = 0x15
	SubOpTPM2Unseal        byte = 0x16
	SubOpTPM2Capabilities  byte = 0x17
	SubOpTPM2NVRead        byte = 0x18
	SubOpTPM2NVWrite       byte = 0x19
	SubOpTPM2NVDelete      byte = 0x1A
	SubOpTPM2NVList        byte = 0x1B
	SubOpTPM2IDevIDCSR     byte = 0x1C
	SubOpTPM2LDevIDCSR     byte = 0x1D
	SubOpTPM2PlatformAttrs byte = 0x1E
	SubOpTPM2GetIDevID     byte = 0x1F
)

// TPM2 sentinel errors
var (
	// ErrTPM2ServiceNotAvailable is returned when the TPM2 service is not configured or unavailable.
	ErrTPM2ServiceNotAvailable = errors.New("TPM2 service not available")

	// ErrTPM2MissingSubOpcode is returned when a TPM2 category request has no sub-opcode.
	ErrTPM2MissingSubOpcode = errors.New("TPM2 sub-opcode is required")

	// ErrTPM2MissingData is returned when data is required but not provided.
	ErrTPM2MissingData = errors.New("data is required")

	// ErrTPM2MissingCN is returned when a common name is required but not provided.
	ErrTPM2MissingCN = errors.New("common name (cn) is required")

	// ErrTPM2MissingCertificate is returned when a certificate is required but not provided.
	ErrTPM2MissingCertificate = errors.New("certificate is required")

	// ErrTPM2InvalidNumBytes is returned when the requested random byte count is invalid.
	ErrTPM2InvalidNumBytes = errors.New("invalid number of bytes (maximum 1024)")

	// ErrTPM2InvalidPCRIndex is returned when a PCR index is out of range.
	ErrTPM2InvalidPCRIndex = errors.New("invalid PCR index (must be 0-23)")
)

// TPM2HandlerFunc is the function signature for TPM2 sub-opcode handlers.
type TPM2HandlerFunc func(ctx context.Context, payload []byte) *Response

// TPM2Handler handles physical TPM2 operations over QUIC using a category
// opcode with sub-opcode dispatch. The first byte of the payload is the
// sub-opcode that selects the TPM2 operation; remaining bytes are the
// operation-specific request payload.
type TPM2Handler struct {
	tpm      xkmssdk.TrustedPlatformModule
	logger   *logging.Logger
	handlers map[byte]TPM2HandlerFunc
}

// NewTPM2Handler creates a new TPM2 handler with map-based dispatch.
func NewTPM2Handler(logger *logging.Logger) *TPM2Handler {
	h := &TPM2Handler{
		logger: logger,
	}
	h.handlers = map[byte]TPM2HandlerFunc{
		SubOpTPM2Info:          h.handleInfo,
		SubOpTPM2Provision:     h.handleProvision,
		SubOpTPM2Clear:         h.handleClear,
		SubOpTPM2GetEK:         h.handleGetEK,
		SubOpTPM2CreateEK:      h.handleCreateEK,
		SubOpTPM2DeleteEK:      h.handleDeleteEK,
		SubOpTPM2GetEKCert:     h.handleGetEKCertificate,
		SubOpTPM2ImportEKCert:  h.handleImportEKCertificate,
		SubOpTPM2GetSRK:        h.handleGetSRK,
		SubOpTPM2CreateSRK:     h.handleCreateSRK,
		SubOpTPM2DeleteSRK:     h.handleDeleteSRK,
		SubOpTPM2GetIAK:        h.handleGetIAK,
		SubOpTPM2CreateIAK:     h.handleCreateIAK,
		SubOpTPM2DeleteIAK:     h.handleDeleteIAK,
		SubOpTPM2Quote:         h.handleQuote,
		SubOpTPM2VerifyQuote:   h.handleVerifyQuote,
		SubOpTPM2ReadPCRs:      h.handleReadPCRs,
		SubOpTPM2ExtendPCR:     h.handleExtendPCR,
		SubOpTPM2EventLog:      h.handleEventLog,
		SubOpTPM2Random:        h.handleRandom,
		SubOpTPM2Seal:          h.handleSeal,
		SubOpTPM2Unseal:        h.handleUnseal,
		SubOpTPM2Capabilities:  h.handleCapabilities,
		SubOpTPM2NVRead:        h.handleNVRead,
		SubOpTPM2NVWrite:       h.handleNVWrite,
		SubOpTPM2NVDelete:      h.handleNVDelete,
		SubOpTPM2NVList:        h.handleNVList,
		SubOpTPM2IDevIDCSR:     h.handleCreateIDevIDCSR,
		SubOpTPM2LDevIDCSR:     h.handleCreateLDevIDCSR,
		SubOpTPM2PlatformAttrs: h.handlePlatformAttributes,
		SubOpTPM2GetIDevID:     h.handleGetIDevID,
	}
	return h
}

// SetTPM2Service sets the TPM2 service for this handler.
func (h *TPM2Handler) SetTPM2Service(tpm xkmssdk.TrustedPlatformModule) {
	h.tpm = tpm
}

// HandleMessage dispatches a TPM2 category request to the appropriate
// sub-opcode handler. The first byte of the payload is consumed as the
// sub-opcode; remaining bytes are forwarded to the handler.
func (h *TPM2Handler) HandleMessage(ctx context.Context, req *Request) *Response {
	if req == nil {
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte(ErrNilRequest.Error()),
		}
	}

	if h.tpm == nil {
		return h.errorResponse(StatusUnavailable, ErrTPM2ServiceNotAvailable)
	}

	if len(req.Payload) == 0 {
		return h.errorResponse(StatusInvalidRequest, ErrTPM2MissingSubOpcode)
	}

	subOpcode := req.Payload[0]
	payload := req.Payload[1:]

	handler, ok := h.handlers[subOpcode]
	if !ok {
		return h.errorResponse(StatusNotImplemented,
			ErrTPM2UnknownSubOpcode{SubOpcode: subOpcode})
	}

	return handler(ctx, payload)
}

// =============================================================================
// Request/Response Types
// =============================================================================

// TPM2InfoResponse represents TPM information in API responses.
type TPM2InfoResponse struct {
	Info         string            `codec:"info"`
	Version      string            `codec:"version"`
	Manufacturer string            `codec:"manufacturer"`
	Model        string            `codec:"model"`
	FWVersion    string            `codec:"fw_version"`
	IsSimulator  bool              `codec:"is_simulator"`
	FIPSMode     bool              `codec:"fips_mode"`
	MaxNVRAMSize uint32            `codec:"max_nvram_size"`
	Properties   map[string]string `codec:"properties"`
	Timestamp    int64             `codec:"timestamp"`
}

// TPM2ProvisionRequest represents a TPM provision request.
type TPM2ProvisionRequest struct {
	OwnerPassword string `codec:"owner_password" secret:"true"`
}

// TPM2StatusResponse represents a generic status response.
type TPM2StatusResponse struct {
	Success   bool   `codec:"success"`
	Message   string `codec:"message"`
	Timestamp int64  `codec:"timestamp"`
}

// TPM2ClearRequest represents a TPM clear request.
type TPM2ClearRequest struct {
	OwnerPassword string `codec:"owner_password" secret:"true"`
}

// TPM2KeyResponse represents a TPM key response.
type TPM2KeyResponse struct {
	Handle    uint32 `codec:"handle"`
	PublicKey []byte `codec:"public_key"`
	Algorithm string `codec:"algorithm"`
	Timestamp int64  `codec:"timestamp"`
}

// TPM2CertificateResponse represents a TPM certificate response.
type TPM2CertificateResponse struct {
	Certificate []byte `codec:"certificate"`
	Timestamp   int64  `codec:"timestamp"`
}

// TPM2ImportEKCertRequest represents an EK certificate import request.
type TPM2ImportEKCertRequest struct {
	Certificate []byte `codec:"certificate"`
}

// TPM2QuoteRequest represents a TPM quote request.
type TPM2QuoteRequest struct {
	PCRIndices []uint32 `codec:"pcr_indices"`
	Nonce      []byte   `codec:"nonce"`
}

// TPM2QuoteResponse represents a TPM quote response.
type TPM2QuoteResponse struct {
	Quote     []byte `codec:"quote"`
	Signature []byte `codec:"signature"`
	EventLog  []byte `codec:"event_log"`
	Timestamp int64  `codec:"timestamp"`
}

// TPM2ReadPCRsRequest represents a PCR read request.
type TPM2ReadPCRsRequest struct {
	Indices []uint32 `codec:"indices"`
}

// TPM2PCRValue represents a single PCR value.
type TPM2PCRValue struct {
	Index     uint32 `codec:"index"`
	Bank      string `codec:"bank"`
	Value     []byte `codec:"value"`
	Timestamp int64  `codec:"timestamp"`
}

// TPM2ReadPCRsResponse represents a PCR read response.
type TPM2ReadPCRsResponse struct {
	PCRValues []*TPM2PCRValue `codec:"pcr_values"`
	Timestamp int64           `codec:"timestamp"`
}

// TPM2ExtendPCRRequest represents a PCR extend request.
type TPM2ExtendPCRRequest struct {
	PCRIndex int    `codec:"pcr_index"`
	HashAlg  string `codec:"hash_alg"`
	Data     []byte `codec:"data"`
}

// TPM2EventLogResponse represents an event log response.
type TPM2EventLogResponse struct {
	EventLog   []byte `codec:"event_log"`
	Format     string `codec:"format"`
	EventCount uint64 `codec:"event_count"`
	Timestamp  int64  `codec:"timestamp"`
}

// TPM2RandomRequest represents a random bytes request.
type TPM2RandomRequest struct {
	NumBytes uint32 `codec:"num_bytes"`
}

// TPM2RandomResponse represents a random bytes response.
type TPM2RandomResponse struct {
	RandomBytes []byte `codec:"random_bytes"`
	Timestamp   int64  `codec:"timestamp"`
}

// TPM2SealRequest represents a TPM seal request.
type TPM2SealRequest struct {
	Data []byte `codec:"data"`
}

// TPM2SealResponse represents a TPM seal response.
type TPM2SealResponse struct {
	SealedData []byte `codec:"sealed_data"`
	Timestamp  int64  `codec:"timestamp"`
}

// TPM2UnsealRequest represents a TPM unseal request.
type TPM2UnsealRequest struct {
	CN string `codec:"cn"`
}

// TPM2UnsealResponse represents a TPM unseal response.
type TPM2UnsealResponse struct {
	Data      []byte `codec:"data"`
	Timestamp int64  `codec:"timestamp"`
}

// TPM2CapabilitiesResponse represents TPM capabilities.
type TPM2CapabilitiesResponse struct {
	Algorithms []string `codec:"algorithms"`
	Commands   []string `codec:"commands"`
	ECCCurves  []string `codec:"ecc_curves"`
	Timestamp  int64    `codec:"timestamp"`
}

// TPM2NVReadRequest represents an NV read request.
type TPM2NVReadRequest struct {
	Index    uint32 `codec:"index"`
	DataSize uint16 `codec:"data_size"`
}

// TPM2NVReadResponse represents an NV read response.
type TPM2NVReadResponse struct {
	Index     uint32 `codec:"index"`
	Data      []byte `codec:"data"`
	Timestamp int64  `codec:"timestamp"`
}

// TPM2NVWriteRequest represents an NV write request.
type TPM2NVWriteRequest struct {
	Index uint32 `codec:"index"`
	Data  []byte `codec:"data"`
}

// TPM2NVDeleteRequest represents an NV delete request.
type TPM2NVDeleteRequest struct {
	Index uint32 `codec:"index"`
}

// TPM2PlatformAttributesResponse represents platform attributes.
type TPM2PlatformAttributesResponse struct {
	Device       string `codec:"device"`
	IsFIPS       bool   `codec:"is_fips"`
	PCRExtended  bool   `codec:"pcr_extended"`
	CanSeal      bool   `codec:"can_seal"`
	IsSimulator  bool   `codec:"is_simulator"`
	Manufacturer string `codec:"manufacturer"`
	Timestamp    int64  `codec:"timestamp"`
}

// TPM2IDevIDCSRRequest represents an IDevID CSR creation request.
type TPM2IDevIDCSRRequest struct {
	CommonName string `codec:"common_name"`
}

// TPM2CSRResponse represents a CSR response.
type TPM2CSRResponse struct {
	CSR       []byte `codec:"csr"`
	Timestamp int64  `codec:"timestamp"`
}

// TPM2IDevIDResponse represents an IDevID key response.
type TPM2IDevIDResponse struct {
	Handle    uint32 `codec:"handle"`
	PublicKey []byte `codec:"public_key"`
	Algorithm string `codec:"algorithm"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// Handler Methods
// =============================================================================

// handleInfo returns TPM capabilities and information.
func (h *TPM2Handler) handleInfo(ctx context.Context, payload []byte) *Response {
	info, err := h.tpm.Info()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	props, propsErr := h.tpm.FixedProperties()

	resp := &TPM2InfoResponse{
		Info:       info,
		Version:    "2.0",
		Properties: map[string]string{"info": info},
		Timestamp:  time.Now().Unix(),
	}

	if propsErr == nil && props != nil {
		resp.Manufacturer = props.Manufacturer
		resp.Model = props.Model
		resp.FWVersion = fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor)
		resp.FIPSMode = props.Fips1402
		resp.MaxNVRAMSize = props.NVBufferMax
		resp.Properties["family"] = props.Family
		resp.Properties["revision"] = props.Revision
		resp.Properties["vendor_id"] = props.VendorID
	}

	cfg := h.tpm.Config()
	if cfg != nil {
		resp.IsSimulator = cfg.UseSimulator
	}

	return h.encodeResponse(resp)
}

// handleProvision provisions the TPM with required keys.
func (h *TPM2Handler) handleProvision(ctx context.Context, payload []byte) *Response {
	var req TPM2ProvisionRequest
	if len(payload) > 0 {
		if err := DecodePayload(payload, &req); err != nil {
			return h.errorResponse(StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
		}
	}

	var ownerPwd xkmssdk.Password
	if req.OwnerPassword != "" {
		ownerPwd = xkmssdk.NewPasswordFromString(req.OwnerPassword)
	}

	if _, err := h.tpm.ProvisionOwner(ownerPwd); err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2StatusResponse{
		Success:   true,
		Message:   "TPM provisioned successfully",
		Timestamp: time.Now().Unix(),
	})
}

// handleClear clears the TPM (requires owner authorization).
func (h *TPM2Handler) handleClear(ctx context.Context, payload []byte) *Response {
	var req TPM2ClearRequest
	if len(payload) > 0 {
		if err := DecodePayload(payload, &req); err != nil {
			return h.errorResponse(StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
		}
	}

	var lockoutAuth []byte
	if req.OwnerPassword != "" {
		lockoutAuth = []byte(req.OwnerPassword)
	}

	if err := h.tpm.Clear(lockoutAuth); err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2StatusResponse{
		Success:   true,
		Message:   "TPM cleared successfully",
		Timestamp: time.Now().Unix(),
	})
}

// handleGetEK retrieves the Endorsement Key public key.
func (h *TPM2Handler) handleGetEK(ctx context.Context, payload []byte) *Response {
	ekAttrs, err := h.tpm.EKAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2KeyResponse{
		Handle:    uint32(ekAttrs.TPMAttributes.Handle),
		PublicKey: ekAttrs.TPMAttributes.PublicKeyBytes,
		Algorithm: ekAttrs.KeyAlgorithm.String(),
		Timestamp: time.Now().Unix(),
	})
}

// handleCreateEK creates an Endorsement Key.
func (h *TPM2Handler) handleCreateEK(ctx context.Context, payload []byte) *Response {
	ekAttrs, err := h.tpm.EKAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	if err := h.tpm.CreateEK(ekAttrs); err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2StatusResponse{
		Success:   true,
		Message:   fmt.Sprintf("EK created at handle 0x%08X", ekAttrs.TPMAttributes.Handle),
		Timestamp: time.Now().Unix(),
	})
}

// handleDeleteEK deletes (flushes) the Endorsement Key handle.
func (h *TPM2Handler) handleDeleteEK(ctx context.Context, payload []byte) *Response {
	ekAttrs, err := h.tpm.EKAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	h.tpm.Flush(ekAttrs.TPMAttributes.Handle)

	return h.encodeResponse(&TPM2StatusResponse{
		Success:   true,
		Message:   "EK handle flushed",
		Timestamp: time.Now().Unix(),
	})
}

// handleGetEKCertificate retrieves the EK certificate.
func (h *TPM2Handler) handleGetEKCertificate(ctx context.Context, payload []byte) *Response {
	cert, err := h.tpm.EKCertificate()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2CertificateResponse{
		Certificate: cert.Raw,
		Timestamp:   time.Now().Unix(),
	})
}

// handleImportEKCertificate imports an EK certificate into the TPM.
func (h *TPM2Handler) handleImportEKCertificate(ctx context.Context, payload []byte) *Response {
	var req TPM2ImportEKCertRequest
	if err := DecodePayload(payload, &req); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}

	if len(req.Certificate) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrTPM2MissingCertificate)
	}

	if err := h.tpm.ProvisionEKCert(nil, req.Certificate); err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2StatusResponse{
		Success:   true,
		Message:   "EK certificate imported successfully",
		Timestamp: time.Now().Unix(),
	})
}

// handleGetSRK retrieves the Storage Root Key.
func (h *TPM2Handler) handleGetSRK(ctx context.Context, payload []byte) *Response {
	srkAttrs, err := h.tpm.SSRKAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2KeyResponse{
		Handle:    uint32(srkAttrs.TPMAttributes.Handle),
		PublicKey: srkAttrs.TPMAttributes.PublicKeyBytes,
		Algorithm: srkAttrs.KeyAlgorithm.String(),
		Timestamp: time.Now().Unix(),
	})
}

// handleCreateSRK creates a Storage Root Key.
func (h *TPM2Handler) handleCreateSRK(ctx context.Context, payload []byte) *Response {
	srkAttrs, err := h.tpm.SSRKAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	if err := h.tpm.CreateSRK(srkAttrs); err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2StatusResponse{
		Success:   true,
		Message:   fmt.Sprintf("SRK created at handle 0x%08X", srkAttrs.TPMAttributes.Handle),
		Timestamp: time.Now().Unix(),
	})
}

// handleDeleteSRK deletes (flushes) the Storage Root Key handle.
func (h *TPM2Handler) handleDeleteSRK(ctx context.Context, payload []byte) *Response {
	srkAttrs, err := h.tpm.SSRKAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	h.tpm.Flush(srkAttrs.TPMAttributes.Handle)

	return h.encodeResponse(&TPM2StatusResponse{
		Success:   true,
		Message:   "SRK handle flushed",
		Timestamp: time.Now().Unix(),
	})
}

// handleGetIAK retrieves the Initial Attestation Key.
func (h *TPM2Handler) handleGetIAK(ctx context.Context, payload []byte) *Response {
	iakAttrs, err := h.tpm.IAKAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	pubKey, iakErr := h.tpm.IAK()
	if iakErr != nil {
		return h.tpmErrorResponse(iakErr)
	}
	if pubKey == nil {
		return h.errorResponse(StatusNotFound, ErrTPM2OperationFailed{
			Operation: "GetIAK",
			Cause:     errors.New("IAK not found"),
		})
	}

	return h.encodeResponse(&TPM2KeyResponse{
		Handle:    uint32(iakAttrs.TPMAttributes.Handle),
		PublicKey: iakAttrs.TPMAttributes.PublicKeyBytes,
		Algorithm: iakAttrs.KeyAlgorithm.String(),
		Timestamp: time.Now().Unix(),
	})
}

// handleCreateIAK creates an Initial Attestation Key.
func (h *TPM2Handler) handleCreateIAK(ctx context.Context, payload []byte) *Response {
	ekAttrs, err := h.tpm.EKAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	iakAttrs, err := h.tpm.CreateIAK(ekAttrs, nil)
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2StatusResponse{
		Success:   true,
		Message:   fmt.Sprintf("IAK created at handle 0x%08X", iakAttrs.TPMAttributes.Handle),
		Timestamp: time.Now().Unix(),
	})
}

// handleDeleteIAK deletes (flushes) the Initial Attestation Key handle.
func (h *TPM2Handler) handleDeleteIAK(ctx context.Context, payload []byte) *Response {
	iakAttrs, err := h.tpm.IAKAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	h.tpm.Flush(iakAttrs.TPMAttributes.Handle)

	return h.encodeResponse(&TPM2StatusResponse{
		Success:   true,
		Message:   "IAK handle flushed",
		Timestamp: time.Now().Unix(),
	})
}

// handleQuote creates a TPM quote over selected PCRs.
func (h *TPM2Handler) handleQuote(ctx context.Context, payload []byte) *Response {
	var req TPM2QuoteRequest
	if err := DecodePayload(payload, &req); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}

	pcrs := make([]uint, len(req.PCRIndices))
	for i, pcr := range req.PCRIndices {
		pcrs[i] = uint(pcr)
	}

	quote, err := h.tpm.Quote(pcrs, req.Nonce)
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2QuoteResponse{
		Quote:     quote.Quoted,
		Signature: quote.Signature,
		EventLog:  quote.EventLog,
		Timestamp: time.Now().Unix(),
	})
}

// handleVerifyQuote verifies a TPM quote.
func (h *TPM2Handler) handleVerifyQuote(ctx context.Context, payload []byte) *Response {
	return h.errorResponse(StatusNotImplemented,
		ErrTPM2OperationFailed{Operation: "VerifyQuote", Cause: errors.New("not yet implemented")})
}

// handleReadPCRs reads PCR values from the TPM.
func (h *TPM2Handler) handleReadPCRs(ctx context.Context, payload []byte) *Response {
	var req TPM2ReadPCRsRequest
	if len(payload) > 0 {
		if err := DecodePayload(payload, &req); err != nil {
			return h.errorResponse(StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
		}
	}

	pcrs := make([]uint, len(req.Indices))
	for i, idx := range req.Indices {
		pcrs[i] = uint(idx)
	}

	// Default to all standard PCRs (0-23) when none specified
	if len(pcrs) == 0 {
		pcrs = make([]uint, 24)
		for i := range pcrs {
			pcrs[i] = uint(i)
		}
	}

	pcrBanks, err := h.tpm.ReadPCRs(pcrs)
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	pcrValues := make([]*TPM2PCRValue, 0, len(pcrs))
	for _, bank := range pcrBanks {
		for _, pcr := range bank.PCRs {
			pcrValues = append(pcrValues, &TPM2PCRValue{
				Index: uint32(pcr.ID),
				Bank:  bank.Algorithm,
				Value: pcr.Value,
			})
		}
	}

	return h.encodeResponse(&TPM2ReadPCRsResponse{
		PCRValues: pcrValues,
		Timestamp: time.Now().Unix(),
	})
}

// handleExtendPCR extends a PCR with the given data.
func (h *TPM2Handler) handleExtendPCR(ctx context.Context, payload []byte) *Response {
	var req TPM2ExtendPCRRequest
	if err := DecodePayload(payload, &req); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}

	if req.PCRIndex < 0 || req.PCRIndex > 23 {
		return h.errorResponse(StatusInvalidArgument, ErrTPM2InvalidPCRIndex)
	}

	if len(req.Data) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrTPM2MissingData)
	}

	hashAlg := req.HashAlg
	if hashAlg == "" {
		hashAlg = "sha256"
	}

	if err := h.tpm.ExtendPCR(req.PCRIndex, hashAlg, req.Data); err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2StatusResponse{
		Success:   true,
		Message:   fmt.Sprintf("PCR %d extended", req.PCRIndex),
		Timestamp: time.Now().Unix(),
	})
}

// handleEventLog retrieves the TPM event log.
func (h *TPM2Handler) handleEventLog(ctx context.Context, payload []byte) *Response {
	rawLog, err := h.tpm.EventLog()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	events, parseErr := h.tpm.ParsedEventLog()
	var eventCount uint64
	if parseErr == nil {
		eventCount = uint64(len(events))
	}

	return h.encodeResponse(&TPM2EventLogResponse{
		EventLog:   rawLog,
		Format:     "tcg2",
		EventCount: eventCount,
		Timestamp:  time.Now().Unix(),
	})
}

// handleRandom returns random bytes from the TPM.
func (h *TPM2Handler) handleRandom(ctx context.Context, payload []byte) *Response {
	var req TPM2RandomRequest
	if len(payload) > 0 {
		if err := DecodePayload(payload, &req); err != nil {
			return h.errorResponse(StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
		}
	}

	numBytes := req.NumBytes
	if numBytes == 0 {
		numBytes = 32
	}
	if numBytes > 1024 {
		return h.errorResponse(StatusInvalidArgument, ErrTPM2InvalidNumBytes)
	}

	random, err := h.tpm.RandomBytes(int(numBytes))
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2RandomResponse{
		RandomBytes: random,
		Timestamp:   time.Now().Unix(),
	})
}

// handleSeal seals data to the TPM.
func (h *TPM2Handler) handleSeal(ctx context.Context, payload []byte) *Response {
	var req TPM2SealRequest
	if err := DecodePayload(payload, &req); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}

	if len(req.Data) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrTPM2MissingData)
	}

	sealed, err := h.tpm.Seal(ctx, req.Data, nil)
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2SealResponse{
		SealedData: sealed.Ciphertext,
		Timestamp:  time.Now().Unix(),
	})
}

// handleUnseal unseals data from the TPM by common name.
func (h *TPM2Handler) handleUnseal(ctx context.Context, payload []byte) *Response {
	var req TPM2UnsealRequest
	if err := DecodePayload(payload, &req); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}

	if req.CN == "" {
		return h.errorResponse(StatusInvalidArgument, ErrTPM2MissingCN)
	}

	sealed := &xkmssdk.SealedData{
		KeyID: req.CN,
	}

	data, err := h.tpm.Unseal(ctx, sealed, nil)
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2UnsealResponse{
		Data:      data,
		Timestamp: time.Now().Unix(),
	})
}

// handleCapabilities returns TPM supported algorithms, commands, and ECC curves.
func (h *TPM2Handler) handleCapabilities(ctx context.Context, payload []byte) *Response {
	algorithms, algErr := h.tpm.SupportedAlgorithms()
	if algErr != nil {
		return h.tpmErrorResponse(algErr)
	}

	commands, cmdErr := h.tpm.SupportedCommands()
	if cmdErr != nil {
		return h.tpmErrorResponse(cmdErr)
	}

	curves, curveErr := h.tpm.SupportedECCCurves()
	if curveErr != nil {
		return h.tpmErrorResponse(curveErr)
	}

	return h.encodeResponse(&TPM2CapabilitiesResponse{
		Algorithms: algorithms,
		Commands:   commands,
		ECCCurves:  curves,
		Timestamp:  time.Now().Unix(),
	})
}

// handleNVRead reads data from a TPM NVRAM index.
func (h *TPM2Handler) handleNVRead(ctx context.Context, payload []byte) *Response {
	return h.errorResponse(StatusNotImplemented,
		ErrTPM2OperationFailed{Operation: "NVRead", Cause: errors.New("not yet implemented")})
}

// handleNVWrite writes data to a TPM NVRAM index.
func (h *TPM2Handler) handleNVWrite(ctx context.Context, payload []byte) *Response {
	return h.errorResponse(StatusNotImplemented,
		ErrTPM2OperationFailed{Operation: "NVWrite", Cause: errors.New("not yet implemented")})
}

// handleNVDelete removes a TPM NVRAM index.
func (h *TPM2Handler) handleNVDelete(ctx context.Context, payload []byte) *Response {
	return h.errorResponse(StatusNotImplemented,
		ErrTPM2OperationFailed{Operation: "NVDelete", Cause: errors.New("not yet implemented")})
}

// handleNVList lists TPM NVRAM indices.
func (h *TPM2Handler) handleNVList(ctx context.Context, payload []byte) *Response {
	return h.errorResponse(StatusNotImplemented,
		ErrTPM2OperationFailed{Operation: "NVList", Cause: errors.New("not yet implemented")})
}

// handleCreateIDevIDCSR creates an IDevID Certificate Signing Request.
func (h *TPM2Handler) handleCreateIDevIDCSR(ctx context.Context, payload []byte) *Response {
	ekCert, err := h.tpm.EKCertificate()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	iakAttrs, err := h.tpm.IAKAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	idevidAttrs, err := h.tpm.IDevIDAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	csr, err := h.tpm.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, idevidAttrs)
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	// Encode the CSR structure to bytes
	csrBytes, err := EncodePayload(csr)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrTPM2EncodingFailed{Cause: err})
	}

	return h.encodeResponse(&TPM2CSRResponse{
		CSR:       csrBytes,
		Timestamp: time.Now().Unix(),
	})
}

// handleCreateLDevIDCSR creates an LDevID Certificate Signing Request.
func (h *TPM2Handler) handleCreateLDevIDCSR(ctx context.Context, payload []byte) *Response {
	// LDevID uses the same CSR flow as IDevID but for local device identity
	return h.handleCreateIDevIDCSR(ctx, payload)
}

// handlePlatformAttributes returns platform-level TPM attributes.
func (h *TPM2Handler) handlePlatformAttributes(ctx context.Context, payload []byte) *Response {
	device := h.tpm.Device()

	isFIPS, fipsErr := h.tpm.IsFIPS140_2()
	if fipsErr != nil {
		isFIPS = false
	}

	pcrExtended, pcrErr := h.tpm.IsPlatformPCRExtended()
	if pcrErr != nil {
		pcrExtended = false
	}

	canSeal := h.tpm.CanSeal()

	cfg := h.tpm.Config()
	isSimulator := false
	if cfg != nil {
		isSimulator = cfg.UseSimulator
	}

	props, propsErr := h.tpm.FixedProperties()
	manufacturer := ""
	if propsErr == nil && props != nil {
		manufacturer = props.Manufacturer
	}

	return h.encodeResponse(&TPM2PlatformAttributesResponse{
		Device:       device,
		IsFIPS:       isFIPS,
		PCRExtended:  pcrExtended,
		CanSeal:      canSeal,
		IsSimulator:  isSimulator,
		Manufacturer: manufacturer,
		Timestamp:    time.Now().Unix(),
	})
}

// handleGetIDevID retrieves the IDevID public key.
func (h *TPM2Handler) handleGetIDevID(ctx context.Context, payload []byte) *Response {
	idevidAttrs, err := h.tpm.IDevIDAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	pubKey, idevidErr := h.tpm.IDevID()
	if idevidErr != nil {
		return h.tpmErrorResponse(idevidErr)
	}
	if pubKey == nil {
		return h.errorResponse(StatusNotFound, ErrTPM2OperationFailed{
			Operation: "GetIDevID",
			Cause:     errors.New("IDevID not found"),
		})
	}

	return h.encodeResponse(&TPM2IDevIDResponse{
		Handle:    uint32(idevidAttrs.TPMAttributes.Handle),
		PublicKey: idevidAttrs.TPMAttributes.PublicKeyBytes,
		Algorithm: idevidAttrs.KeyAlgorithm.String(),
		Timestamp: time.Now().Unix(),
	})
}

// =============================================================================
// Helper Methods
// =============================================================================

// encodeResponse encodes a response struct and returns a QUIC Response.
func (h *TPM2Handler) encodeResponse(resp interface{}) *Response {
	encoded, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrTPM2EncodingFailed{Cause: err})
	}
	return &Response{
		Status:  StatusOK,
		Payload: encoded,
	}
}

// errorResponse creates an error response with the given status and error.
func (h *TPM2Handler) errorResponse(status byte, err error) *Response {
	return &Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// tpmErrorResponse maps TPM errors to appropriate QUIC status codes.
func (h *TPM2Handler) tpmErrorResponse(err error) *Response {
	errMsg := err.Error()

	var status byte
	switch {
	case containsAnyTPM(errMsg, "not found", "does not exist", "no such"):
		status = StatusNotFound
	case containsAnyTPM(errMsg, "already exists", "duplicate"):
		status = StatusAlreadyExists
	case containsAnyTPM(errMsg, "invalid", "required", "must be", "cannot be"):
		status = StatusInvalidArgument
	case containsAnyTPM(errMsg, "permission", "denied", "unauthorized", "forbidden", "authorization"):
		status = StatusPermissionDenied
	case containsAnyTPM(errMsg, "not implemented", "unimplemented", "not supported"):
		status = StatusNotImplemented
	case containsAnyTPM(errMsg, "unavailable", "not available"):
		status = StatusUnavailable
	default:
		status = StatusInternalError
	}

	return h.errorResponse(status, err)
}

// containsAnyTPM checks if the string contains any of the given substrings.
func containsAnyTPM(s string, substrings ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// =============================================================================
// TPM2 Error Types
// =============================================================================

// ErrTPM2EncodingFailed represents an encoding failure error.
type ErrTPM2EncodingFailed struct {
	Cause error
}

// Error returns the error message.
func (e ErrTPM2EncodingFailed) Error() string {
	return "failed to encode TPM2 payload: " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e ErrTPM2EncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrTPM2DecodingFailed represents a decoding failure error.
type ErrTPM2DecodingFailed struct {
	Cause error
}

// Error returns the error message.
func (e ErrTPM2DecodingFailed) Error() string {
	return "failed to decode TPM2 payload: " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e ErrTPM2DecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrTPM2OperationFailed represents a TPM2 operation failure.
type ErrTPM2OperationFailed struct {
	Operation string
	Cause     error
}

// Error returns the error message.
func (e ErrTPM2OperationFailed) Error() string {
	return "TPM2 operation " + e.Operation + " failed: " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e ErrTPM2OperationFailed) Unwrap() error {
	return e.Cause
}

// ErrTPM2UnknownSubOpcode represents an unknown TPM2 sub-opcode.
type ErrTPM2UnknownSubOpcode struct {
	SubOpcode byte
}

// Error returns the error message.
func (e ErrTPM2UnknownSubOpcode) Error() string {
	return fmt.Sprintf("unknown TPM2 sub-opcode: 0x%02X", e.SubOpcode)
}
