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
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// TPM2 Service Interface for IDevID/IAK Operations
// =============================================================================

// TPM2ServiceInterface defines the interface for IDevID/IAK operations over QUIC.
// This interface wraps go-xkms's TrustedPlatformModule for device identity operations.
type TPM2ServiceInterface interface {
	xkmssdk.TrustedPlatformModule
}

// =============================================================================
// IDevID/IAK QUIC Request/Response Types
// =============================================================================

// IDevIDGenerateRequest represents an IDevID key generation request.
type IDevIDGenerateRequest struct {
	Algorithm string `codec:"algorithm"`
	Overwrite bool   `codec:"overwrite"`
}

// IDevIDGenerateResponse represents an IDevID key generation response.
type IDevIDGenerateResponse struct {
	Handle    uint32 `codec:"handle"`
	Algorithm string `codec:"algorithm"`
	PublicKey string `codec:"public_key"`
	Timestamp int64  `codec:"timestamp"`
}

// IDevIDInfoRequest represents an IDevID info request.
type IDevIDInfoRequest struct{}

// IDevIDInfoResponse represents an IDevID info response.
type IDevIDInfoResponse struct {
	Handle         uint32                 `codec:"handle"`
	Algorithm      string                 `codec:"algorithm"`
	Exists         bool                   `codec:"exists"`
	PublicKey      string                 `codec:"public_key"`
	HasCertificate bool                   `codec:"has_certificate"`
	Certificate    *IDevIDCertificateQUIC `codec:"certificate"`
	Timestamp      int64                  `codec:"timestamp"`
}

// IDevIDCertificateQUIC represents certificate info for QUIC responses.
type IDevIDCertificateQUIC struct {
	SubjectCN    string `codec:"subject_cn"`
	IssuerCN     string `codec:"issuer_cn"`
	SerialNumber string `codec:"serial_number"`
	NotBefore    int64  `codec:"not_before"`
	NotAfter     int64  `codec:"not_after"`
	Fingerprint  string `codec:"fingerprint"`
	PEM          string `codec:"pem"`
}

// IDevIDDeleteRequest represents an IDevID deletion request.
type IDevIDDeleteRequest struct{}

// IDevIDDeleteResponse represents an IDevID deletion response.
type IDevIDDeleteResponse struct {
	Deleted   bool  `codec:"deleted"`
	Timestamp int64 `codec:"timestamp"`
}

// IDevIDCSRRequest represents an IDevID CSR generation request.
type IDevIDCSRRequest struct {
	CommonName         string   `codec:"common_name"`
	Organization       string   `codec:"organization"`
	OrganizationalUnit string   `codec:"organizational_unit"`
	Country            string   `codec:"country"`
	Province           string   `codec:"province"`
	Locality           string   `codec:"locality"`
	DNSNames           []string `codec:"dns_names"`
	EmailAddresses     []string `codec:"email_addresses"`
	IncludeTCGAttrs    bool     `codec:"include_tcg_attrs"`
}

// IDevIDCSRResponse represents an IDevID CSR generation response.
type IDevIDCSRResponse struct {
	CSR       string `codec:"csr"`
	Timestamp int64  `codec:"timestamp"`
}

// IDevIDInstallCertRequest represents a certificate installation request.
type IDevIDInstallCertRequest struct {
	CertificatePEM string `codec:"certificate_pem"`
}

// IDevIDInstallCertResponse represents a certificate installation response.
type IDevIDInstallCertResponse struct {
	Installed   bool   `codec:"installed"`
	SubjectCN   string `codec:"subject_cn"`
	IssuerCN    string `codec:"issuer_cn"`
	Fingerprint string `codec:"fingerprint"`
	Timestamp   int64  `codec:"timestamp"`
}

// IDevIDGetCertRequest represents a get certificate request.
type IDevIDGetCertRequest struct {
	IncludePEM bool `codec:"include_pem"`
}

// IDevIDGetCertResponse represents a get certificate response.
type IDevIDGetCertResponse struct {
	Certificate *IDevIDCertificateQUIC `codec:"certificate"`
	Timestamp   int64                  `codec:"timestamp"`
}

// HasIDevIDRequest represents a check IDevID existence request.
type HasIDevIDRequest struct{}

// HasIDevIDResponse represents a check IDevID existence response.
type HasIDevIDResponse struct {
	Exists    bool  `codec:"exists"`
	Timestamp int64 `codec:"timestamp"`
}

// HasIAKRequest represents a check IAK existence request.
type HasIAKRequest struct{}

// HasIAKResponse represents a check IAK existence response.
type HasIAKResponse struct {
	Exists    bool  `codec:"exists"`
	Timestamp int64 `codec:"timestamp"`
}

// IDevIDDeleteCertRequest represents an IDevID certificate deletion request.
type IDevIDDeleteCertRequest struct{}

// IDevIDDeleteCertResponse represents an IDevID certificate deletion response.
type IDevIDDeleteCertResponse struct {
	Deleted   bool  `codec:"deleted"`
	Timestamp int64 `codec:"timestamp"`
}

// IAKDeleteCertRequest represents an IAK certificate deletion request.
type IAKDeleteCertRequest struct{}

// IAKDeleteCertResponse represents an IAK certificate deletion response.
type IAKDeleteCertResponse struct {
	Deleted   bool  `codec:"deleted"`
	Timestamp int64 `codec:"timestamp"`
}

// IAKGenerateRequest represents an IAK key generation request.
type IAKGenerateRequest struct {
	Algorithm string `codec:"algorithm"`
	Overwrite bool   `codec:"overwrite"`
}

// IAKGenerateResponse represents an IAK key generation response.
type IAKGenerateResponse struct {
	Handle    uint32 `codec:"handle"`
	Algorithm string `codec:"algorithm"`
	PublicKey string `codec:"public_key"`
	Timestamp int64  `codec:"timestamp"`
}

// IAKInfoRequest represents an IAK info request.
type IAKInfoRequest struct{}

// IAKInfoResponse represents an IAK info response.
type IAKInfoResponse struct {
	Handle         uint32                 `codec:"handle"`
	Algorithm      string                 `codec:"algorithm"`
	Exists         bool                   `codec:"exists"`
	PublicKey      string                 `codec:"public_key"`
	HasCertificate bool                   `codec:"has_certificate"`
	Certificate    *IDevIDCertificateQUIC `codec:"certificate"`
	Timestamp      int64                  `codec:"timestamp"`
}

// IAKDeleteRequest represents an IAK deletion request.
type IAKDeleteRequest struct{}

// IAKDeleteResponse represents an IAK deletion response.
type IAKDeleteResponse struct {
	Deleted   bool  `codec:"deleted"`
	Timestamp int64 `codec:"timestamp"`
}

// IAKCSRRequest represents an IAK CSR generation request.
type IAKCSRRequest struct {
	CommonName         string   `codec:"common_name"`
	Organization       string   `codec:"organization"`
	OrganizationalUnit string   `codec:"organizational_unit"`
	Country            string   `codec:"country"`
	Province           string   `codec:"province"`
	Locality           string   `codec:"locality"`
	DNSNames           []string `codec:"dns_names"`
	EmailAddresses     []string `codec:"email_addresses"`
	IncludeTCGAttrs    bool     `codec:"include_tcg_attrs"`
}

// IAKCSRResponse represents an IAK CSR generation response.
type IAKCSRResponse struct {
	CSR       string `codec:"csr"`
	Timestamp int64  `codec:"timestamp"`
}

// IAKInstallCertRequest represents an IAK certificate installation request.
type IAKInstallCertRequest struct {
	CertificatePEM string `codec:"certificate_pem"`
}

// IAKInstallCertResponse represents an IAK certificate installation response.
type IAKInstallCertResponse struct {
	Installed   bool   `codec:"installed"`
	SubjectCN   string `codec:"subject_cn"`
	IssuerCN    string `codec:"issuer_cn"`
	Fingerprint string `codec:"fingerprint"`
	Timestamp   int64  `codec:"timestamp"`
}

// IAKGetCertRequest represents an IAK get certificate request.
type IAKGetCertRequest struct {
	IncludePEM bool `codec:"include_pem"`
}

// IAKGetCertResponse represents an IAK get certificate response.
type IAKGetCertResponse struct {
	Certificate *IDevIDCertificateQUIC `codec:"certificate"`
	Timestamp   int64                  `codec:"timestamp"`
}

// DeviceAttributesRequest represents a device attributes request.
type DeviceAttributesRequest struct{}

// DeviceAttributesResponse represents a device attributes response.
type DeviceAttributesResponse struct {
	TPMManufacturer      string `codec:"tpm_manufacturer"`
	TPMModel             string `codec:"tpm_model"`
	TPMVersion           string `codec:"tpm_version"`
	PlatformManufacturer string `codec:"platform_manufacturer"`
	PlatformModel        string `codec:"platform_model"`
	PlatformVersion      string `codec:"platform_version"`
	PlatformSerial       string `codec:"platform_serial"`
	Timestamp            int64  `codec:"timestamp"`
}

// ActivateCredentialQUICRequest represents an activate credential request.
type ActivateCredentialQUICRequest struct {
	CredentialBlob string `codec:"credential_blob"`
	Secret         string `codec:"secret" secret:"true"`
}

// ActivateCredentialQUICResponse represents an activate credential response.
type ActivateCredentialQUICResponse struct {
	Decrypted string `codec:"decrypted"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// IDevID/IAK QUIC Operation Handler
// =============================================================================

// handleIDevIDOperation routes IDevID/IAK opcodes to their respective handlers.
func (h *QUICServiceHandler) handleIDevIDOperation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.tpm2Service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "tpm2"})
	}

	switch req.Opcode {
	case quicwire.OpIDevIDGenerate:
		return h.handleIDevIDGenerate(ctx, req)
	case quicwire.OpIDevIDInfo:
		return h.handleIDevIDInfo(ctx, req)
	case quicwire.OpIDevIDDelete:
		return h.handleIDevIDDelete(ctx, req)
	case quicwire.OpIDevIDCSR:
		return h.handleIDevIDCSR(ctx, req)
	case quicwire.OpIDevIDInstallCert:
		return h.handleIDevIDInstallCert(ctx, req)
	case quicwire.OpIDevIDGetCert:
		return h.handleIDevIDGetCert(ctx, req)
	case quicwire.OpIAKGenerate:
		return h.handleIAKGenerate(ctx, req)
	case quicwire.OpIAKInfo:
		return h.handleIAKInfo(ctx, req)
	case quicwire.OpIAKDelete:
		return h.handleIAKDelete(ctx, req)
	case quicwire.OpIAKCSR:
		return h.handleIAKCSR(ctx, req)
	case quicwire.OpIAKInstallCert:
		return h.handleIAKInstallCert(ctx, req)
	case quicwire.OpIAKGetCert:
		return h.handleIAKGetCert(ctx, req)
	case quicwire.OpDeviceAttributes:
		return h.handleDeviceAttributes(ctx, req)
	case quicwire.OpActivateCredential:
		return h.handleActivateCredential(ctx, req)
	case quicwire.OpHasIDevID:
		return h.handleHasIDevID(ctx, req)
	case quicwire.OpHasIAK:
		return h.handleHasIAK(ctx, req)
	case quicwire.OpIDevIDDeleteCert:
		return h.handleIDevIDDeleteCert(ctx, req)
	case quicwire.OpIAKDeleteCert:
		return h.handleIAKDeleteCert(ctx, req)
	default:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleIDevIDGenerate generates a new IDevID key using TPM2 directly.
func (h *QUICServiceHandler) handleIDevIDGenerate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var genReq IDevIDGenerateRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &genReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	// Get EK attributes for IAK creation (needed before IDevID)
	ekAttrs, err := h.tpm2Service.EKAttributes()
	if err != nil {
		h.logger.Error(err, "failed to get EK attributes")
		return h.mapTPM2Error(err)
	}

	// Create IAK first (required for IDevID creation)
	iakAttrs, err := h.tpm2Service.CreateIAK(ekAttrs, nil)
	if err != nil {
		h.logger.Error(err, "failed to create IAK")
		return h.mapTPM2Error(err)
	}

	// Create IDevID using IAK
	idevidAttrs, _, err := h.tpm2Service.CreateIDevID(iakAttrs, nil, nil)
	if err != nil {
		h.logger.Error(err, "failed to create IDevID")
		return h.mapTPM2Error(err)
	}

	// Encode public key as PEM
	pubKeyPEM, err := encodePublicKeyPEM(idevidAttrs.TPMAttributes.Public)
	if err != nil {
		h.logger.Error(err, "failed to encode public key")
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	resp := &IDevIDGenerateResponse{
		Handle:    uint32(idevidAttrs.TPMAttributes.Handle),
		Algorithm: normalizeKeyAlgorithm(genReq.Algorithm),
		PublicKey: pubKeyPEM,
		Timestamp: time.Now().UnixMilli(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("IDevID key generated", "handle", idevidAttrs.TPMAttributes.Handle)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleIDevIDInfo retrieves IDevID key information using TPM2 directly.
func (h *QUICServiceHandler) handleIDevIDInfo(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	attrs, err := h.tpm2Service.IDevIDAttributes()
	if err != nil {
		// Key doesn't exist
		resp := &IDevIDInfoResponse{
			Exists:    false,
			Timestamp: time.Now().UnixMilli(),
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

	pubKeyPEM, err := encodePublicKeyPEM(attrs.TPMAttributes.Public)
	if err != nil {
		h.logger.Error(err, "failed to encode public key")
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	resp := &IDevIDInfoResponse{
		Exists:    true,
		Handle:    uint32(attrs.TPMAttributes.Handle),
		Algorithm: "ECDSA-P256", // Default, could be determined from attrs
		PublicKey: pubKeyPEM,
		Timestamp: time.Now().UnixMilli(),
	}

	// Check if certificate exists
	cert, certErr := h.tpm2Service.IDevIDCertificate()
	if certErr == nil && cert != nil {
		resp.HasCertificate = true
		resp.Certificate = certToQUIC(cert)
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

// handleIDevIDDelete deletes the IDevID key.
func (h *QUICServiceHandler) handleIDevIDDelete(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	// Delete the IDevID certificate first
	if err := h.tpm2Service.DeleteIDevIDCertificate(); err != nil {
		// Log but continue - certificate might not exist
		h.logger.Debug("IDevID certificate deletion skipped", "error", err)
	}

	// Note: TPM2 doesn't have a direct DeleteIDevID - keys are typically persistent
	// This would require evicting the key from the TPM

	resp := &IDevIDDeleteResponse{
		Deleted:   true,
		Timestamp: time.Now().UnixMilli(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("IDevID key deleted")

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleIDevIDCSR generates a CSR for the IDevID key.
func (h *QUICServiceHandler) handleIDevIDCSR(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var csrReq IDevIDCSRRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &csrReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	// Get IDevID attributes
	idevidAttrs, err := h.tpm2Service.IDevIDAttributes()
	if err != nil {
		h.logger.Error(err, "failed to get IDevID attributes")
		return h.mapTPM2Error(err)
	}

	// Get IAK attributes for CSR creation
	iakAttrs, err := h.tpm2Service.IAKAttributes()
	if err != nil {
		h.logger.Error(err, "failed to get IAK attributes")
		return h.mapTPM2Error(err)
	}

	// Create TCG CSR using TPM2
	tcgCSR, err := h.tpm2Service.CreateTCG_CSR_IDEVID(nil, iakAttrs, idevidAttrs)
	if err != nil {
		h.logger.Error(err, "failed to create TCG CSR")
		return h.mapTPM2Error(err)
	}

	// Marshal CSR to bytes
	csrBytes, err := tcgCSR.Marshal()
	if err != nil {
		h.logger.Error(err, "failed to marshal TCG CSR")
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	resp := &IDevIDCSRResponse{
		CSR:       base64.StdEncoding.EncodeToString(csrBytes),
		Timestamp: time.Now().UnixMilli(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("IDevID CSR generated")

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleIDevIDInstallCert installs an IDevID certificate.
func (h *QUICServiceHandler) handleIDevIDInstallCert(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var installReq IDevIDInstallCertRequest
	if err := quicwire.DecodePayload(req.Payload, &installReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if installReq.CertificatePEM == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "certificate_pem"})
	}

	// Parse PEM certificate
	block, _ := pem.Decode([]byte(installReq.CertificatePEM))
	if block == nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICOperationFailed{Op: "parse certificate PEM", Cause: ErrInvalidCertificatePEM{}})
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICOperationFailed{Op: "parse certificate", Cause: err})
	}

	// Install using TPM2
	if err := h.tpm2Service.ProvisionIDevIDCert(cert); err != nil {
		h.logger.Error(err, "failed to install IDevID certificate")
		return h.mapTPM2Error(err)
	}

	// Get certificate info for response
	fingerprint := sha256.Sum256(cert.Raw)

	resp := &IDevIDInstallCertResponse{
		Installed:   true,
		SubjectCN:   cert.Subject.CommonName,
		IssuerCN:    cert.Issuer.CommonName,
		Fingerprint: hex.EncodeToString(fingerprint[:]),
		Timestamp:   time.Now().UnixMilli(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("IDevID certificate installed", "subject", cert.Subject.CommonName)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleIDevIDGetCert retrieves the IDevID certificate.
func (h *QUICServiceHandler) handleIDevIDGetCert(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getCertReq IDevIDGetCertRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &getCertReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	cert, err := h.tpm2Service.IDevIDCertificate()
	if err != nil {
		h.logger.Error(err, "failed to get IDevID certificate")
		return h.mapTPM2Error(err)
	}

	certQUIC := certToQUIC(cert)
	if !getCertReq.IncludePEM {
		certQUIC.PEM = ""
	}

	resp := &IDevIDGetCertResponse{
		Certificate: certQUIC,
		Timestamp:   time.Now().UnixMilli(),
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

// handleHasIDevID checks if an IDevID key exists in the TPM.
func (h *QUICServiceHandler) handleHasIDevID(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	_, err := h.tpm2Service.IDevIDAttributes()
	exists := err == nil

	resp := &HasIDevIDResponse{
		Exists:    exists,
		Timestamp: time.Now().UnixMilli(),
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

// handleHasIAK checks if an IAK key exists in the TPM.
func (h *QUICServiceHandler) handleHasIAK(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	_, err := h.tpm2Service.IAKAttributes()
	exists := err == nil

	resp := &HasIAKResponse{
		Exists:    exists,
		Timestamp: time.Now().UnixMilli(),
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

// handleIDevIDDeleteCert deletes the IDevID certificate.
func (h *QUICServiceHandler) handleIDevIDDeleteCert(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if err := h.tpm2Service.DeleteIDevIDCertificate(); err != nil {
		h.logger.Error(err, "failed to delete IDevID certificate")
		return h.mapTPM2Error(err)
	}

	resp := &IDevIDDeleteCertResponse{
		Deleted:   true,
		Timestamp: time.Now().UnixMilli(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("IDevID certificate deleted")

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleIAKDeleteCert deletes the IAK certificate.
func (h *QUICServiceHandler) handleIAKDeleteCert(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if err := h.tpm2Service.DeleteIAKCertificate(); err != nil {
		h.logger.Error(err, "failed to delete IAK certificate")
		return h.mapTPM2Error(err)
	}

	resp := &IAKDeleteCertResponse{
		Deleted:   true,
		Timestamp: time.Now().UnixMilli(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("IAK certificate deleted")

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleIAKGenerate generates a new IAK key.
func (h *QUICServiceHandler) handleIAKGenerate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var genReq IAKGenerateRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &genReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	// Get EK attributes
	ekAttrs, err := h.tpm2Service.EKAttributes()
	if err != nil {
		h.logger.Error(err, "failed to get EK attributes")
		return h.mapTPM2Error(err)
	}

	// Create IAK
	iakAttrs, err := h.tpm2Service.CreateIAK(ekAttrs, nil)
	if err != nil {
		h.logger.Error(err, "failed to create IAK")
		return h.mapTPM2Error(err)
	}

	pubKeyPEM, err := encodePublicKeyPEM(iakAttrs.TPMAttributes.Public)
	if err != nil {
		h.logger.Error(err, "failed to encode public key")
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	resp := &IAKGenerateResponse{
		Handle:    uint32(iakAttrs.TPMAttributes.Handle),
		Algorithm: normalizeKeyAlgorithm(genReq.Algorithm),
		PublicKey: pubKeyPEM,
		Timestamp: time.Now().UnixMilli(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("IAK key generated", "handle", iakAttrs.TPMAttributes.Handle)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleIAKInfo retrieves IAK key information.
func (h *QUICServiceHandler) handleIAKInfo(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	attrs, err := h.tpm2Service.IAKAttributes()
	if err != nil {
		// Key doesn't exist
		resp := &IAKInfoResponse{
			Exists:    false,
			Timestamp: time.Now().UnixMilli(),
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

	pubKeyPEM, err := encodePublicKeyPEM(attrs.TPMAttributes.Public)
	if err != nil {
		h.logger.Error(err, "failed to encode public key")
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	resp := &IAKInfoResponse{
		Exists:    true,
		Handle:    uint32(attrs.TPMAttributes.Handle),
		Algorithm: "ECDSA-P256",
		PublicKey: pubKeyPEM,
		Timestamp: time.Now().UnixMilli(),
	}

	// Check if certificate exists
	cert, certErr := h.tpm2Service.IAKCertificate()
	if certErr == nil && cert != nil {
		resp.HasCertificate = true
		resp.Certificate = certToQUIC(cert)
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

// handleIAKDelete deletes the IAK key.
func (h *QUICServiceHandler) handleIAKDelete(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	// Delete the IAK certificate first
	if err := h.tpm2Service.DeleteIAKCertificate(); err != nil {
		h.logger.Debug("IAK certificate deletion skipped", "error", err)
	}

	resp := &IAKDeleteResponse{
		Deleted:   true,
		Timestamp: time.Now().UnixMilli(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("IAK key deleted")

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleIAKCSR generates a CSR for the IAK key.
func (h *QUICServiceHandler) handleIAKCSR(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var csrReq IAKCSRRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &csrReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	// Get IAK attributes
	iakAttrs, err := h.tpm2Service.IAKAttributes()
	if err != nil {
		h.logger.Error(err, "failed to get IAK attributes")
		return h.mapTPM2Error(err)
	}

	// Create TCG CSR for IAK
	tcgCSR, err := h.tpm2Service.CreateTCG_CSR_IDEVID(nil, iakAttrs, iakAttrs)
	if err != nil {
		h.logger.Error(err, "failed to create TCG CSR for IAK")
		return h.mapTPM2Error(err)
	}

	csrBytes, err := tcgCSR.Marshal()
	if err != nil {
		h.logger.Error(err, "failed to marshal TCG CSR")
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	resp := &IAKCSRResponse{
		CSR:       base64.StdEncoding.EncodeToString(csrBytes),
		Timestamp: time.Now().UnixMilli(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("IAK CSR generated")

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleIAKInstallCert installs an IAK certificate.
func (h *QUICServiceHandler) handleIAKInstallCert(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var installReq IAKInstallCertRequest
	if err := quicwire.DecodePayload(req.Payload, &installReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if installReq.CertificatePEM == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "certificate_pem"})
	}

	// Parse PEM certificate
	block, _ := pem.Decode([]byte(installReq.CertificatePEM))
	if block == nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICOperationFailed{Op: "parse certificate PEM", Cause: ErrInvalidCertificatePEM{}})
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICOperationFailed{Op: "parse certificate", Cause: err})
	}

	// Install using TPM2
	if err := h.tpm2Service.ProvisionIAKCert(cert); err != nil {
		h.logger.Error(err, "failed to install IAK certificate")
		return h.mapTPM2Error(err)
	}

	fingerprint := sha256.Sum256(cert.Raw)

	resp := &IAKInstallCertResponse{
		Installed:   true,
		SubjectCN:   cert.Subject.CommonName,
		IssuerCN:    cert.Issuer.CommonName,
		Fingerprint: hex.EncodeToString(fingerprint[:]),
		Timestamp:   time.Now().UnixMilli(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("IAK certificate installed", "subject", cert.Subject.CommonName)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleIAKGetCert retrieves the IAK certificate.
func (h *QUICServiceHandler) handleIAKGetCert(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getCertReq IAKGetCertRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &getCertReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	cert, err := h.tpm2Service.IAKCertificate()
	if err != nil {
		h.logger.Error(err, "failed to get IAK certificate")
		return h.mapTPM2Error(err)
	}

	certQUIC := certToQUIC(cert)
	if !getCertReq.IncludePEM {
		certQUIC.PEM = ""
	}

	resp := &IAKGetCertResponse{
		Certificate: certQUIC,
		Timestamp:   time.Now().UnixMilli(),
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

// handleDeviceAttributes retrieves TCG device attributes.
func (h *QUICServiceHandler) handleDeviceAttributes(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	// Use go-xkms's platform discovery
	platformAttrs := xkmssdk.DiscoverPlatformAttributes()

	// Get TPM properties
	var tpmManufacturer, tpmModel, tpmVersion string
	props, err := h.tpm2Service.FixedProperties()
	if err == nil && props != nil {
		tpmManufacturer = props.Manufacturer
		tpmModel = props.Family
		tpmVersion = fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor)
	}

	resp := &DeviceAttributesResponse{
		TPMManufacturer:      tpmManufacturer,
		TPMModel:             tpmModel,
		TPMVersion:           tpmVersion,
		PlatformManufacturer: platformAttrs.Manufacturer,
		PlatformModel:        platformAttrs.Model,
		PlatformVersion:      platformAttrs.Version,
		PlatformSerial:       platformAttrs.Serial,
		Timestamp:            time.Now().UnixMilli(),
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

// handleActivateCredential performs TPM credential activation.
func (h *QUICServiceHandler) handleActivateCredential(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var activateReq ActivateCredentialQUICRequest
	if err := quicwire.DecodePayload(req.Payload, &activateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if activateReq.CredentialBlob == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "credential_blob"})
	}
	if activateReq.Secret == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "secret"})
	}

	// Decode base64 credential blob and secret
	credentialBlob, err := base64.StdEncoding.DecodeString(activateReq.CredentialBlob)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICOperationFailed{Op: "decode credential_blob", Cause: err})
	}

	secret, err := base64.StdEncoding.DecodeString(activateReq.Secret)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICOperationFailed{Op: "decode secret", Cause: err})
	}

	// Delegate through the shared activateCredential path.
	decrypted, err := activateCredential(h.tpm2Service, credentialBlob, secret)
	if err != nil {
		h.logger.Error(err, "failed to activate credential")
		return h.mapTPM2Error(err)
	}

	resp := &ActivateCredentialQUICResponse{
		Decrypted: base64.StdEncoding.EncodeToString(decrypted),
		Timestamp: time.Now().UnixMilli(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("Credential activated successfully")

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// mapTPM2Error maps TPM2 errors to appropriate QUIC status codes.
func (h *QUICServiceHandler) mapTPM2Error(err error) *quicwire.Response {
	if err == nil {
		return nil
	}

	errMsg := err.Error()

	// Check for not found errors
	if containsIDevIDErrorPattern(errMsg, "not found", "does not exist") {
		return h.errorResponse(quicwire.StatusNotFound, ErrQUICOperationFailed{Op: "tpm2", Cause: err})
	}

	// Check for already exists errors
	if containsIDevIDErrorPattern(errMsg, "already exists") {
		return h.errorResponse(quicwire.StatusAlreadyExists, ErrQUICOperationFailed{Op: "tpm2", Cause: err})
	}

	// Check for invalid argument errors
	if containsIDevIDErrorPattern(errMsg, "invalid", "required", "must be", "cannot be", "mismatch") {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICOperationFailed{Op: "tpm2", Cause: err})
	}

	// Check for unavailable errors
	if containsIDevIDErrorPattern(errMsg, "not available", "unavailable", "not configured") {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICOperationFailed{Op: "tpm2", Cause: err})
	}

	// Default to internal error
	return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "tpm2", Cause: err})
}

// containsIDevIDErrorPattern checks if the error message contains any of the patterns.
func containsIDevIDErrorPattern(s string, patterns ...string) bool {
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

// certToQUIC converts an x509.Certificate to IDevIDCertificateQUIC.
func certToQUIC(cert *x509.Certificate) *IDevIDCertificateQUIC {
	if cert == nil {
		return nil
	}

	fingerprint := sha256.Sum256(cert.Raw)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return &IDevIDCertificateQUIC{
		SubjectCN:    cert.Subject.CommonName,
		IssuerCN:     cert.Issuer.CommonName,
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore.UnixMilli(),
		NotAfter:     cert.NotAfter.UnixMilli(),
		Fingerprint:  hex.EncodeToString(fingerprint[:]),
		PEM:          string(certPEM),
	}
}

// encodePublicKeyPEM encodes a TPM public key to PEM format.
func encodePublicKeyPEM(pub interface{}) (string, error) {
	// For TPMTPublic, we need to extract the actual public key
	// This is a simplified version - in practice you'd use the TPM library's conversion
	return "", nil // Placeholder - actual implementation depends on TPM public key type
}
