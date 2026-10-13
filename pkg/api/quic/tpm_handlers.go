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
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	tpmgo "github.com/google/go-tpm/tpm2"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmnv"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmsrk"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	attestvm "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
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

	// ErrTPM2MissingCredentialBlob is returned when ActivateCredential has no credential blob.
	ErrTPM2MissingCredentialBlob = errors.New("credential_blob is required")

	// ErrTPM2MissingEncryptedSecret is returned when ActivateCredential has no encrypted secret.
	ErrTPM2MissingEncryptedSecret = errors.New("encrypted_secret is required")

	// ErrTPM2InvalidNumBytes is returned when the requested random byte count is invalid.
	ErrTPM2InvalidNumBytes = errors.New("invalid number of bytes (maximum 1024)")

	// ErrTPM2InvalidPCRIndex is returned when a PCR index is out of range.
	ErrTPM2InvalidPCRIndex = errors.New("invalid PCR index (must be 0-23)")
)

// TPM2HandlerFunc is the function signature for TPM2 sub-opcode handlers.
type TPM2HandlerFunc func(ctx context.Context, payload []byte) *quicwire.Response

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
		quicwire.SubOpTPM2Info:          h.handleInfo,
		quicwire.SubOpTPM2Provision:     h.handleProvision,
		quicwire.SubOpTPM2Clear:         h.handleClear,
		quicwire.SubOpTPM2GetEK:         h.handleGetEK,
		quicwire.SubOpTPM2CreateEK:      h.handleCreateEK,
		quicwire.SubOpTPM2DeleteEK:      h.handleDeleteEK,
		quicwire.SubOpTPM2GetEKCert:     h.handleGetEKCertificate,
		quicwire.SubOpTPM2ImportEKCert:  h.handleImportEKCertificate,
		quicwire.SubOpTPM2GetSRK:        h.handleGetSRK,
		quicwire.SubOpTPM2CreateSRK:     h.handleCreateSRK,
		quicwire.SubOpTPM2DeleteSRK:     h.handleDeleteSRK,
		quicwire.SubOpTPM2GetIAK:        h.handleGetIAK,
		quicwire.SubOpTPM2CreateIAK:     h.handleCreateIAK,
		quicwire.SubOpTPM2DeleteIAK:     h.handleDeleteIAK,
		quicwire.SubOpTPM2Quote:         h.handleQuote,
		quicwire.SubOpTPM2VerifyQuote:   h.handleVerifyQuote,
		quicwire.SubOpTPM2ReadPCRs:      h.handleReadPCRs,
		quicwire.SubOpTPM2ExtendPCR:     h.handleExtendPCR,
		quicwire.SubOpTPM2EventLog:      h.handleEventLog,
		quicwire.SubOpTPM2Random:        h.handleRandom,
		quicwire.SubOpTPM2Seal:          h.handleSeal,
		quicwire.SubOpTPM2Unseal:        h.handleUnseal,
		quicwire.SubOpTPM2Capabilities:  h.handleCapabilities,
		quicwire.SubOpTPM2NVRead:        h.handleNVRead,
		quicwire.SubOpTPM2NVWrite:       h.handleNVWrite,
		quicwire.SubOpTPM2NVDelete:      h.handleNVDelete,
		quicwire.SubOpTPM2NVList:        h.handleNVList,
		quicwire.SubOpTPM2IDevIDCSR:     h.handleCreateIDevIDCSR,
		quicwire.SubOpTPM2LDevIDCSR:     h.handleCreateLDevIDCSR,
		quicwire.SubOpTPM2PlatformAttrs: h.handlePlatformAttributes,
		quicwire.SubOpTPM2GetIDevID:     h.handleGetIDevID,
		quicwire.SubOpTPM2MakeCred:      h.handleMakeCredential,
		quicwire.SubOpTPM2ActivateCred:  h.handleActivateCredential,
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
func (h *TPM2Handler) HandleMessage(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if req == nil {
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte(quicwire.ErrNilRequest.Error()),
		}
	}

	if h.tpm == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrTPM2ServiceNotAvailable)
	}

	if len(req.Payload) == 0 {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2MissingSubOpcode)
	}

	subOpcode := req.Payload[0]
	payload := req.Payload[1:]

	handler, ok := h.handlers[subOpcode]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented,
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

// TPM2GetSRKRequest names which storage root key a GetSRK call wants.
// Handle 0 means the SSRK, which is what an empty payload has always
// meant on this opcode.
type TPM2GetSRKRequest struct {
	Handle uint32 `codec:"handle"`
}

// TPM2MakeCredentialRequest represents a TPM2_MakeCredential request. When
// EKCert and IAKPub are both present the verifier path is used; otherwise
// the local EK is used together with AKName.
type TPM2MakeCredentialRequest struct {
	AKName []byte `codec:"ak_name"`
	Secret []byte `codec:"secret"`
	EKCert []byte `codec:"ek_cert"`
	IAKPub []byte `codec:"iak_pub"`
}

// TPM2MakeCredentialResponse represents a TPM2_MakeCredential response.
type TPM2MakeCredentialResponse struct {
	CredentialBlob  []byte `codec:"credential_blob"`
	EncryptedSecret []byte `codec:"encrypted_secret"`
	Secret          []byte `codec:"secret"`
	Timestamp       int64  `codec:"timestamp"`
}

// TPM2ActivateCredentialRequest represents a TPM2_ActivateCredential request.
type TPM2ActivateCredentialRequest struct {
	CredentialBlob  []byte `codec:"credential_blob"`
	EncryptedSecret []byte `codec:"encrypted_secret"`
}

// TPM2ActivateCredentialResponse represents a TPM2_ActivateCredential response.
type TPM2ActivateCredentialResponse struct {
	Secret    []byte `codec:"secret"`
	Timestamp int64  `codec:"timestamp"`
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
	// ChannelBinding is the TLS exporter of the connection the request
	// arrived on; the TPM quoted SHA-256(nonce || ChannelBinding) (#482).
	ChannelBinding []byte `codec:"channel_binding"`
	Timestamp      int64  `codec:"timestamp"`
}

// TPM2VerifyQuoteRequest represents a TPM quote verification request.
// Field names mirror the gRPC VerifyQuoteRequest proto.
type TPM2VerifyQuoteRequest struct {
	Quote     []byte `codec:"quote"`
	Signature []byte `codec:"signature"`
	Nonce     []byte `codec:"nonce"`
	AKPublic  []byte `codec:"ak_public"`
	// ChannelBinding, when set, is the binding the quote was produced
	// under; the quote must then carry SHA-256(Nonce || ChannelBinding).
	ChannelBinding []byte `codec:"channel_binding"`
}

// TPM2VerifyQuoteResponse represents a TPM quote verification response.
type TPM2VerifyQuoteResponse struct {
	Verified  bool   `codec:"verified"`
	Message   string `codec:"message"`
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

// TPM2NVReadRequest represents an NV read request. Field names mirror
// the gRPC ReadNVRAMRequest proto (index / size / offset / password).
type TPM2NVReadRequest struct {
	Index    uint32 `codec:"index"`
	Size     uint16 `codec:"size"`
	Offset   uint16 `codec:"offset"`
	Password string `codec:"password" secret:"true"`
}

// TPM2NVReadResponse represents an NV read response.
type TPM2NVReadResponse struct {
	Index     uint32 `codec:"index"`
	Data      []byte `codec:"data"`
	Timestamp int64  `codec:"timestamp"`
}

// TPM2NVWriteRequest represents an NV write request. Field names mirror
// the gRPC WriteNVRAMRequest proto (index / data / offset / password).
type TPM2NVWriteRequest struct {
	Index    uint32 `codec:"index"`
	Data     []byte `codec:"data"`
	Offset   uint16 `codec:"offset"`
	Password string `codec:"password" secret:"true"`
}

// TPM2NVDeleteRequest represents an NV delete request. parent_password
// authorizes the owner hierarchy, mirroring UndefineNVRAMRequest.
type TPM2NVDeleteRequest struct {
	Index          uint32 `codec:"index"`
	ParentPassword string `codec:"parent_password" secret:"true"`
}

// TPM2NVIndex describes a single defined NV index, mirroring the gRPC
// NVIndex proto shape.
type TPM2NVIndex struct {
	Handle    uint32 `codec:"handle"`
	Type      string `codec:"type"`
	Size      uint32 `codec:"size"`
	AuthRead  bool   `codec:"auth_read"`
	AuthWrite bool   `codec:"auth_write"`
}

// TPM2NVListResponse lists the NV indices defined on the device.
type TPM2NVListResponse struct {
	Indexes   []*TPM2NVIndex `codec:"indexes"`
	Timestamp int64          `codec:"timestamp"`
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
func (h *TPM2Handler) handleInfo(ctx context.Context, payload []byte) *quicwire.Response {
	info, err := h.tpm.Info()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	props, propsErr := h.tpm.FixedProperties()

	resp := &TPM2InfoResponse{
		Info:       info,
		Version:    "2.0",
		Properties: tpmsrk.InfoProperties(h.tpm),
		Timestamp:  time.Now().Unix(),
	}
	resp.Properties["info"] = info

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
func (h *TPM2Handler) handleProvision(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2ProvisionRequest
	if len(payload) > 0 {
		if err := quicwire.DecodePayload(payload, &req); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
		}
	}

	var ownerPwd xkmssdk.Password
	if req.OwnerPassword != "" {
		held, err := xkmssdk.NewPasswordFromString(req.OwnerPassword)
		if err != nil {
			return h.errorResponse(quicwire.StatusInternalError, err)
		}
		ownerPwd = held
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
func (h *TPM2Handler) handleClear(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2ClearRequest
	if len(payload) > 0 {
		if err := quicwire.DecodePayload(payload, &req); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
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
func (h *TPM2Handler) handleGetEK(ctx context.Context, payload []byte) *quicwire.Response {
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

// handleMakeCredential wraps TPM2_MakeCredential. With both EKCert and
// IAKPub present the verifier path (MakeCredentialWithExternalEK) is used;
// otherwise the local TPM EK is used with the supplied AKName.
func (h *TPM2Handler) handleMakeCredential(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2MakeCredentialRequest
	if len(payload) > 0 {
		if err := quicwire.DecodePayload(payload, &req); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
		}
	}

	var (
		credentialBlob, encryptedSecret, secret []byte
		err                                     error
	)
	if len(req.EKCert) > 0 && len(req.IAKPub) > 0 {
		ekCert, parseErr := x509.ParseCertificate(req.EKCert)
		if parseErr != nil {
			return h.errorResponse(quicwire.StatusInvalidArgument, ErrTPM2DecodingFailed{Cause: parseErr})
		}
		credentialBlob, encryptedSecret, secret, err = h.tpm.MakeCredentialWithExternalEK(ekCert, req.IAKPub, req.Secret)
	} else {
		credentialBlob, encryptedSecret, secret, err = h.tpm.MakeCredential(tpmgo.TPM2BName{Buffer: req.AKName}, req.Secret)
	}
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2MakeCredentialResponse{
		CredentialBlob:  credentialBlob,
		EncryptedSecret: encryptedSecret,
		Secret:          secret,
		Timestamp:       time.Now().Unix(),
	})
}

// handleActivateCredential wraps TPM2_ActivateCredential.
func (h *TPM2Handler) handleActivateCredential(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2ActivateCredentialRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}

	if len(req.CredentialBlob) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrTPM2MissingCredentialBlob)
	}
	if len(req.EncryptedSecret) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrTPM2MissingEncryptedSecret)
	}

	secret, err := h.tpm.ActivateCredential(req.CredentialBlob, req.EncryptedSecret)
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2ActivateCredentialResponse{
		Secret:    secret,
		Timestamp: time.Now().Unix(),
	})
}

// handleCreateEK creates an Endorsement Key.
func (h *TPM2Handler) handleCreateEK(ctx context.Context, payload []byte) *quicwire.Response {
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
func (h *TPM2Handler) handleDeleteEK(ctx context.Context, payload []byte) *quicwire.Response {
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
func (h *TPM2Handler) handleGetEKCertificate(ctx context.Context, payload []byte) *quicwire.Response {
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
func (h *TPM2Handler) handleImportEKCertificate(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2ImportEKCertRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}

	if len(req.Certificate) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrTPM2MissingCertificate)
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
func (h *TPM2Handler) handleGetSRK(ctx context.Context, payload []byte) *quicwire.Response {
	// The payload names which storage root key is wanted. It was
	// previously discarded, so a request for the PlatformSRK was
	// answered with the SSRK and a success status (#475). An absent or
	// empty payload still means the SSRK, as it always did.
	var req TPM2GetSRKRequest
	if len(payload) > 0 {
		if err := quicwire.DecodePayload(payload, &req); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2OperationFailed{
				Operation: "GetSRK",
				Cause:     err,
			})
		}
	}

	srkAttrs, err := tpmsrk.Resolve(h.tpm, req.Handle)
	if err != nil {
		if tpmsrk.IsUnknownHandle(err) {
			return h.errorResponse(quicwire.StatusNotFound, ErrTPM2OperationFailed{
				Operation: "GetSRK",
				Cause:     err,
			})
		}
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
func (h *TPM2Handler) handleCreateSRK(ctx context.Context, payload []byte) *quicwire.Response {
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
func (h *TPM2Handler) handleDeleteSRK(ctx context.Context, payload []byte) *quicwire.Response {
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
func (h *TPM2Handler) handleGetIAK(ctx context.Context, payload []byte) *quicwire.Response {
	iakAttrs, err := h.tpm.IAKAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	pubKey, iakErr := h.tpm.IAK()
	if iakErr != nil {
		return h.tpmErrorResponse(iakErr)
	}
	if pubKey == nil {
		return h.errorResponse(quicwire.StatusNotFound, ErrTPM2OperationFailed{
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
func (h *TPM2Handler) handleCreateIAK(ctx context.Context, payload []byte) *quicwire.Response {
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
func (h *TPM2Handler) handleDeleteIAK(ctx context.Context, payload []byte) *quicwire.Response {
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
func (h *TPM2Handler) handleQuote(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2QuoteRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}

	pcrs := make([]uint, len(req.PCRIndices))
	for i, pcr := range req.PCRIndices {
		pcrs[i] = uint(pcr)
	}

	// Quote the nonce bound to this connection, never the nonce as sent
	// (#482): a relay forwarding a caller's nonce over a second connection
	// gets a quote the caller refuses.
	bound, err := channelbind.Bind(ConnectionTLS(ctx), channelbind.TransportQUIC, req.Nonce)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, err)
	}

	quote, err := h.tpm.Quote(pcrs, bound.QualifyingData)
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	return h.encodeResponse(&TPM2QuoteResponse{
		Quote:          quote.Quoted,
		Signature:      quote.Signature,
		EventLog:       quote.EventLog,
		ChannelBinding: bound.Binding,
		Timestamp:      time.Now().Unix(),
	})
}

// handleVerifyQuote verifies a TPM 2.0 quote for parity with the gRPC
// TPMService.VerifyQuote RPC. The attestation-key public half is taken
// from the request (PKIX/PEM DER in ak_public) when supplied, otherwise
// it falls back to this platform's provisioned IAK. Verification reuses
// the canonical pkg/attestation/vm helpers: the anti-replay nonce
// (TPMS_ATTEST extraData) must match, and the signature over the quote
// must validate against the AK public key.
func (h *TPM2Handler) handleVerifyQuote(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2VerifyQuoteRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}
	if len(req.Quote) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, errors.New("quote is required"))
	}
	if len(req.Signature) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, errors.New("signature is required"))
	}

	akPublic, err := h.resolveVerifyAKPublic(req.AKPublic)
	if err != nil {
		return h.encodeResponse(&TPM2VerifyQuoteResponse{
			Verified:  false,
			Message:   "ak_public_resolution_failed: " + err.Error(),
			Timestamp: time.Now().Unix(),
		})
	}

	// A quote the node produced over a bound connection carries
	// SHA-256(nonce || binding), not the nonce itself.
	expectedNonce, err := channelbind.ExpectedQualifyingData(req.Nonce, req.ChannelBinding)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}
	if len(expectedNonce) > 0 {
		if err := attestvm.VerifyQuoteNonce(req.Quote, expectedNonce); err != nil {
			return h.encodeResponse(&TPM2VerifyQuoteResponse{
				Verified:  false,
				Message:   "nonce_verification_failed: " + err.Error(),
				Timestamp: time.Now().Unix(),
			})
		}
	}

	if err := attestvm.VerifyQuoteSignature(akPublic, req.Quote, req.Signature); err != nil {
		return h.encodeResponse(&TPM2VerifyQuoteResponse{
			Verified:  false,
			Message:   "signature_verification_failed: " + err.Error(),
			Timestamp: time.Now().Unix(),
		})
	}

	return h.encodeResponse(&TPM2VerifyQuoteResponse{
		Verified:  true,
		Message:   "quote verified: nonce matches, signature valid",
		Timestamp: time.Now().Unix(),
	})
}

// resolveVerifyAKPublic returns the PKIX-DER attestation-key public key
// used to verify a quote. A caller-supplied key (already PKIX/PEM DER)
// wins; otherwise the platform's provisioned IAK is marshaled to PKIX.
func (h *TPM2Handler) resolveVerifyAKPublic(akPublic []byte) ([]byte, error) {
	if len(akPublic) > 0 {
		return akPublic, nil
	}
	pub, err := h.tpm.IAK()
	if err != nil {
		return nil, err
	}
	if pub == nil {
		return nil, errors.New("IAK not found")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// handleReadPCRs reads PCR values from the TPM.
func (h *TPM2Handler) handleReadPCRs(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2ReadPCRsRequest
	if len(payload) > 0 {
		if err := quicwire.DecodePayload(payload, &req); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
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
func (h *TPM2Handler) handleExtendPCR(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2ExtendPCRRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}

	if req.PCRIndex < 0 || req.PCRIndex > 23 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrTPM2InvalidPCRIndex)
	}

	if len(req.Data) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrTPM2MissingData)
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
func (h *TPM2Handler) handleEventLog(ctx context.Context, payload []byte) *quicwire.Response {
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
func (h *TPM2Handler) handleRandom(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2RandomRequest
	if len(payload) > 0 {
		if err := quicwire.DecodePayload(payload, &req); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
		}
	}

	numBytes := req.NumBytes
	if numBytes == 0 {
		numBytes = 32
	}
	if numBytes > 1024 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrTPM2InvalidNumBytes)
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
func (h *TPM2Handler) handleSeal(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2SealRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}

	if len(req.Data) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrTPM2MissingData)
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
func (h *TPM2Handler) handleUnseal(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2UnsealRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}

	if req.CN == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrTPM2MissingCN)
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
func (h *TPM2Handler) handleCapabilities(ctx context.Context, payload []byte) *quicwire.Response {
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

// handleNVRead reads data from a TPM NVRAM index. It delegates to the
// shared tpmnv package so the QUIC path issues exactly the same
// TPM2_NVRead command sequence (and auth-hierarchy dispatch) as the
// gRPC TPMService.ReadNVRAM RPC. Device-agnostic: works identically for
// a hardware TPM and swtpm through the module transport.
func (h *TPM2Handler) handleNVRead(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2NVReadRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}
	if req.Index == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, errors.New("index is required"))
	}
	tr := h.tpm.Transport()
	if tr == nil {
		return h.errorResponse(quicwire.StatusUnavailable, errors.New("TPM transport not available"))
	}

	data, err := tpmnv.Read(tr, req.Index, req.Size, req.Offset, passwordBytes(req.Password))
	if err != nil {
		return h.tpmErrorResponse(ErrTPM2OperationFailed{Operation: "NVRead", Cause: err})
	}

	return h.encodeResponse(&TPM2NVReadResponse{
		Index:     req.Index,
		Data:      data,
		Timestamp: time.Now().Unix(),
	})
}

// handleNVWrite writes data to a TPM NVRAM index, delegating to the
// shared tpmnv package (same TPM2_NVWrite sequence as gRPC WriteNVRAM).
func (h *TPM2Handler) handleNVWrite(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2NVWriteRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}
	if req.Index == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, errors.New("index is required"))
	}
	if len(req.Data) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrTPM2MissingData)
	}
	tr := h.tpm.Transport()
	if tr == nil {
		return h.errorResponse(quicwire.StatusUnavailable, errors.New("TPM transport not available"))
	}

	if err := tpmnv.Write(tr, req.Index, req.Data, req.Offset, passwordBytes(req.Password)); err != nil {
		return h.tpmErrorResponse(ErrTPM2OperationFailed{Operation: "NVWrite", Cause: err})
	}

	return h.encodeResponse(&TPM2StatusResponse{
		Success:   true,
		Message:   fmt.Sprintf("wrote %d bytes to NV index 0x%08X", len(req.Data), req.Index),
		Timestamp: time.Now().Unix(),
	})
}

// handleNVDelete removes a TPM NVRAM index (TPM2_NVUndefineSpace),
// delegating to the shared tpmnv package.
func (h *TPM2Handler) handleNVDelete(ctx context.Context, payload []byte) *quicwire.Response {
	var req TPM2NVDeleteRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrTPM2DecodingFailed{Cause: err})
	}
	if req.Index == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, errors.New("index is required"))
	}
	tr := h.tpm.Transport()
	if tr == nil {
		return h.errorResponse(quicwire.StatusUnavailable, errors.New("TPM transport not available"))
	}

	if err := tpmnv.Undefine(tr, req.Index, passwordBytes(req.ParentPassword)); err != nil {
		return h.tpmErrorResponse(ErrTPM2OperationFailed{Operation: "NVDelete", Cause: err})
	}

	return h.encodeResponse(&TPM2StatusResponse{
		Success:   true,
		Message:   fmt.Sprintf("NV index 0x%08X undefined", req.Index),
		Timestamp: time.Now().Unix(),
	})
}

// handleNVList lists the NV indices defined on the device. It reuses the
// module's FixedProperties() view (which walks TPM_CAP_HANDLES at
// 0x01000000), giving the same NVIndex inventory the gRPC Info RPC
// surfaces — no separate raw command construction required.
func (h *TPM2Handler) handleNVList(ctx context.Context, payload []byte) *quicwire.Response {
	props, err := h.tpm.FixedProperties()
	if err != nil {
		return h.tpmErrorResponse(ErrTPM2OperationFailed{Operation: "NVList", Cause: err})
	}

	indexes := make([]*TPM2NVIndex, 0, len(props.NVIndexes))
	for _, ix := range props.NVIndexes {
		indexes = append(indexes, &TPM2NVIndex{
			Handle:    uint32(ix.Handle),
			Type:      ix.Type,
			Size:      uint32(ix.Size),
			AuthRead:  ix.AuthRead,
			AuthWrite: ix.AuthWrite,
		})
	}

	return h.encodeResponse(&TPM2NVListResponse{
		Indexes:   indexes,
		Timestamp: time.Now().Unix(),
	})
}

// passwordBytes converts an optional password string to the []byte auth
// value go-tpm expects, returning nil (not an empty slice) for the empty
// string. nil vs empty is meaningful: a nil PasswordAuth omits the auth
// value from the command frame, whereas an empty []byte sends a
// zero-length value that some TPMs reject with TPM_RC_SIZE.
func passwordBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

// handleCreateIDevIDCSR creates an IDevID Certificate Signing Request.
func (h *TPM2Handler) handleCreateIDevIDCSR(ctx context.Context, payload []byte) *quicwire.Response {
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
	csrBytes, err := quicwire.EncodePayload(csr)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrTPM2EncodingFailed{Cause: err})
	}

	return h.encodeResponse(&TPM2CSRResponse{
		CSR:       csrBytes,
		Timestamp: time.Now().Unix(),
	})
}

// handleCreateLDevIDCSR creates an LDevID Certificate Signing Request.
func (h *TPM2Handler) handleCreateLDevIDCSR(ctx context.Context, payload []byte) *quicwire.Response {
	// LDevID uses the same CSR flow as IDevID but for local device identity
	return h.handleCreateIDevIDCSR(ctx, payload)
}

// handlePlatformAttributes returns platform-level TPM attributes.
func (h *TPM2Handler) handlePlatformAttributes(ctx context.Context, payload []byte) *quicwire.Response {
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
func (h *TPM2Handler) handleGetIDevID(ctx context.Context, payload []byte) *quicwire.Response {
	idevidAttrs, err := h.tpm.IDevIDAttributes()
	if err != nil {
		return h.tpmErrorResponse(err)
	}

	pubKey, idevidErr := h.tpm.IDevID()
	if idevidErr != nil {
		return h.tpmErrorResponse(idevidErr)
	}
	if pubKey == nil {
		return h.errorResponse(quicwire.StatusNotFound, ErrTPM2OperationFailed{
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
func (h *TPM2Handler) encodeResponse(resp interface{}) *quicwire.Response {
	encoded, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrTPM2EncodingFailed{Cause: err})
	}
	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: encoded,
	}
}

// errorResponse creates an error response with the given status and error.
func (h *TPM2Handler) errorResponse(status byte, err error) *quicwire.Response {
	return &quicwire.Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// tpmErrorResponse maps TPM errors to appropriate QUIC status codes.
func (h *TPM2Handler) tpmErrorResponse(err error) *quicwire.Response {
	errMsg := err.Error()

	var status byte
	switch {
	case containsAnyTPM(errMsg, "not found", "does not exist", "no such"):
		status = quicwire.StatusNotFound
	case containsAnyTPM(errMsg, "already exists", "duplicate"):
		status = quicwire.StatusAlreadyExists
	case containsAnyTPM(errMsg, "invalid", "required", "must be", "cannot be"):
		status = quicwire.StatusInvalidArgument
	case containsAnyTPM(errMsg, "permission", "denied", "unauthorized", "forbidden", "authorization"):
		status = quicwire.StatusPermissionDenied
	case containsAnyTPM(errMsg, "not implemented", "unimplemented", "not supported"):
		status = quicwire.StatusNotImplemented
	case containsAnyTPM(errMsg, "unavailable", "not available"):
		status = quicwire.StatusUnavailable
	default:
		status = quicwire.StatusInternalError
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
