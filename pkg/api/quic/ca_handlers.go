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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	goca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	objstore "github.com/jeremyhahn/go-objstore/pkg/common"
	pkgca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// CA pagination defaults
const (
	caDefaultLimit  int32 = 50
	caMaxLimit      int32 = 1000
	caDefaultCursor       = ""
)

// CAHandler handles Certificate Authority operations over QUIC
type CAHandler struct {
	ca     goca.CACertificateAuthority
	logger *logging.Logger
}

// NewCAHandler creates a new CA handler
func NewCAHandler(logger *logging.Logger, ca goca.CACertificateAuthority) *CAHandler {
	return &CAHandler{
		ca:     ca,
		logger: logger,
	}
}

// HandleRequest processes a CA request and returns a response
func (h *CAHandler) HandleRequest(ctx context.Context, req *Request) *Response {
	if req == nil {
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte(ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	case OpCAInfo:
		return h.handleInfo(ctx, req)
	case OpCAIssue, OpCertIssue:
		return h.handleIssue(ctx, req)
	case OpCAGet, OpCertGet:
		return h.handleGet(ctx, req)
	case OpCAList, OpCertList:
		return h.handleList(ctx, req)
	case OpCARevoke, OpCertRevoke:
		return h.handleRevoke(ctx, req)
	case OpCARenew, OpCertRenew:
		return h.handleRenew(ctx, req)
	case OpCAVerify, OpCertVerify:
		return h.handleVerify(ctx, req)
	case OpCACRL, OpCertGetCRL:
		return h.handleCRL(ctx, req)
	case OpCABundle, OpCertGetChain:
		return h.handleBundle(ctx, req)
	default:
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte("unknown CA operation"),
		}
	}
}

// CAInfoRequest represents a CA info request
type CAInfoRequest struct{}

// CAInfoResponse represents CA information
type CAInfoResponse struct {
	CommonName       string                `codec:"common_name"`
	IsInitialized    bool                  `codec:"is_initialized"`
	IsIntermediate   bool                  `codec:"is_intermediate"`
	DefaultAlgorithm string                `codec:"default_algorithm"`
	DefaultValidity  int32                 `codec:"default_validity"`
	RootCert         *CertificateSummary   `codec:"root_cert"`
	Intermediates    []*CertificateSummary `codec:"intermediates"`
	Timestamp        int64                 `codec:"timestamp"`
}

// CertificateSummary contains certificate summary information
type CertificateSummary struct {
	Serial       string `codec:"serial"`
	CommonName   string `codec:"common_name"`
	Issuer       string `codec:"issuer"`
	NotBefore    int64  `codec:"not_before"`
	NotAfter     int64  `codec:"not_after"`
	Status       string `codec:"status"`
	KeyAlgorithm string `codec:"key_algorithm"`
}

// Certificate contains full certificate information
type Certificate struct {
	Serial             string   `codec:"serial"`
	Subject            *Subject `codec:"subject"`
	Issuer             string   `codec:"issuer"`
	NotBefore          int64    `codec:"not_before"`
	NotAfter           int64    `codec:"not_after"`
	Status             string   `codec:"status"`
	KeyAlgorithm       string   `codec:"key_algorithm"`
	SignatureAlgorithm string   `codec:"signature_algorithm"`
	IsCA               bool     `codec:"is_ca"`
	Pem                string   `codec:"pem"`
	Sans               *SANs    `codec:"sans"`
}

// Subject contains certificate subject information
type Subject struct {
	CommonName         string `codec:"common_name"`
	Organization       string `codec:"organization"`
	OrganizationalUnit string `codec:"organizational_unit"`
	Country            string `codec:"country"`
	Province           string `codec:"province"`
	Locality           string `codec:"locality"`
	Address            string `codec:"address"`
	PostalCode         string `codec:"postal_code"`
}

// SANs contains Subject Alternative Names
type SANs struct {
	DNS   []string `codec:"dns"`
	IPs   []string `codec:"ips"`
	Email []string `codec:"email"`
	URIs  []string `codec:"uris"`
}

// CAIssueRequest represents a certificate issuance request
type CAIssueRequest struct {
	Subject      *Subject `codec:"subject"`
	Sans         *SANs    `codec:"sans"`
	ValidDays    int32    `codec:"valid_days"`
	KeyAlgorithm string   `codec:"key_algorithm"`
	StoreType    string   `codec:"store_type"`
	KeyUsage     []string `codec:"key_usage"`
	ExtKeyUsage  []string `codec:"ext_key_usage"`
	IsCA         bool     `codec:"is_ca"`
	MaxPathLen   int32    `codec:"max_path_len"`
}

// CAIssueResponse represents a certificate issuance response
type CAIssueResponse struct {
	Certificate *Certificate `codec:"certificate"`
	Timestamp   int64        `codec:"timestamp"`
}

// CAGetRequest represents a certificate retrieval request
type CAGetRequest struct {
	Serial     string `codec:"serial"`
	IncludePem bool   `codec:"include_pem"`
}

// CAGetResponse represents a certificate retrieval response
type CAGetResponse struct {
	Certificate *Certificate `codec:"certificate"`
	Timestamp   int64        `codec:"timestamp"`
}

// CAListRequest represents a certificate list request
type CAListRequest struct {
	Limit  int32  `codec:"limit"`
	Cursor string `codec:"cursor"`
}

// CAListResponse represents a certificate list response
type CAListResponse struct {
	Certificates []*CertificateSummary `codec:"certificates"`
	NextCursor   string                `codec:"next_cursor"`
	HasMore      bool                  `codec:"has_more"`
	TotalCount   int32                 `codec:"total_count"`
	Timestamp    int64                 `codec:"timestamp"`
}

// CARevokeRequest represents a certificate revocation request
type CARevokeRequest struct {
	Serial     string `codec:"serial"`
	Reason     int32  `codec:"reason"`
	DeleteKeys bool   `codec:"delete_keys"`
}

// CARevokeResponse represents a certificate revocation response
type CARevokeResponse struct {
	Serial    string `codec:"serial"`
	Status    string `codec:"status"`
	RevokedAt int64  `codec:"revoked_at"`
	Reason    int32  `codec:"reason"`
	Timestamp int64  `codec:"timestamp"`
}

// CARenewRequest represents a certificate renewal request
type CARenewRequest struct {
	Serial        string `codec:"serial"`
	ExtendDays    int32  `codec:"extend_days"`
	PreserveAttrs bool   `codec:"preserve_attrs"`
}

// CARenewResponse represents a certificate renewal response
type CARenewResponse struct {
	OldSerial   string       `codec:"old_serial"`
	Certificate *Certificate `codec:"certificate"`
	Timestamp   int64        `codec:"timestamp"`
}

// CAVerifyRequest represents a certificate verification request
type CAVerifyRequest struct {
	CertificatePem string `codec:"certificate_pem"`
	CertificateDer []byte `codec:"certificate_der"`
	CheckRevoked   bool   `codec:"check_revoked"`
}

// CAVerifyResponse represents a certificate verification response
type CAVerifyResponse struct {
	Valid     bool                  `codec:"valid"`
	Status    string                `codec:"status"`
	Chain     []*CertificateSummary `codec:"chain"`
	Errors    []string              `codec:"errors"`
	Revoked   bool                  `codec:"revoked"`
	Timestamp int64                 `codec:"timestamp"`
}

// CACRLRequest represents a CRL retrieval request
type CACRLRequest struct{}

// RevokedCertEntry represents a revoked certificate entry
type RevokedCertEntry struct {
	Serial         string `codec:"serial"`
	RevocationTime int64  `codec:"revocation_time"`
	Reason         int32  `codec:"reason"`
}

// CACRLResponse represents a CRL retrieval response
type CACRLResponse struct {
	CRL          []byte              `codec:"crl"`
	LastUpdate   int64               `codec:"last_update"`
	NextUpdate   int64               `codec:"next_update"`
	RevokedCount int32               `codec:"revoked_count"`
	RevokedCerts []*RevokedCertEntry `codec:"revoked_certs"`
	Timestamp    int64               `codec:"timestamp"`
}

// CABundleRequest represents a CA bundle retrieval request
type CABundleRequest struct {
	StoreType string `codec:"store_type"`
	Algorithm string `codec:"algorithm"`
}

// CABundleResponse represents a CA bundle retrieval response
type CABundleResponse struct {
	Bundle       []byte                `codec:"bundle"`
	Certificates []*CertificateSummary `codec:"certificates"`
	CertCount    int32                 `codec:"cert_count"`
	Timestamp    int64                 `codec:"timestamp"`
}

// handleInfo returns CA information
func (h *CAHandler) handleInfo(ctx context.Context, req *Request) *Response {
	if h.ca == nil {
		return h.errorResponse(StatusUnavailable, ErrCANotInitialized)
	}

	now := time.Now().Unix()

	resp := &CAInfoResponse{
		IsInitialized: h.ca.IsInitialized(),
		Timestamp:     now,
	}

	if h.ca.IsInitialized() {
		resp.CommonName = h.ca.Identity()
		resp.DefaultAlgorithm = h.keyAlgorithmToString(h.ca.DefaultKeyAlgorithm())
		resp.DefaultValidity = int32(h.ca.DefaultValidityPeriod())

		rootCert, err := h.ca.TrustedRoot()
		if err == nil && rootCert != nil {
			resp.RootCert = h.certToSummary(rootCert)
		}

		intermediateCert, err := h.ca.TrustedIntermediate()
		if err == nil && intermediateCert != nil {
			resp.IsIntermediate = true
			resp.Intermediates = append(resp.Intermediates, h.certToSummary(intermediateCert))
		}
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrCAEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleIssue issues a new certificate
func (h *CAHandler) handleIssue(ctx context.Context, req *Request) *Response {
	if h.ca == nil {
		return h.errorResponse(StatusUnavailable, ErrCANotInitialized)
	}

	var issueReq CAIssueRequest
	if err := DecodePayload(req.Payload, &issueReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrCADecodingFailed{Cause: err})
	}

	if issueReq.Subject == nil || issueReq.Subject.CommonName == "" {
		return h.errorResponse(StatusInvalidArgument, ErrCAMissingCommonName)
	}

	keyAlg, err := h.parseKeyAlgorithm(issueReq.KeyAlgorithm)
	if err != nil {
		return h.errorResponse(StatusInvalidArgument, err)
	}

	caReq := &goca.CACertificateRequest{
		Subject: goca.CASubject{
			CommonName:         issueReq.Subject.CommonName,
			Organization:       issueReq.Subject.Organization,
			OrganizationalUnit: issueReq.Subject.OrganizationalUnit,
			Country:            issueReq.Subject.Country,
			Province:           issueReq.Subject.Province,
			Locality:           issueReq.Subject.Locality,
			Address:            issueReq.Subject.Address,
			PostalCode:         issueReq.Subject.PostalCode,
		},
		Valid:       int(issueReq.ValidDays),
		IsCA:        issueReq.IsCA,
		MaxPathLen:  int(issueReq.MaxPathLen),
		KeyUsage:    h.parseKeyUsage(issueReq.KeyUsage),
		ExtKeyUsage: h.parseExtKeyUsage(issueReq.ExtKeyUsage),
	}

	if issueReq.Sans != nil {
		caReq.SANS = &goca.CASubjectAlternativeNames{
			DNS:   issueReq.Sans.DNS,
			IPs:   issueReq.Sans.IPs,
			Email: issueReq.Sans.Email,
			URIs:  issueReq.Sans.URIs,
		}
	}

	storeType := h.parseStoreType(issueReq.StoreType)
	if storeType == xkmssdk.StoreUnknown {
		storeType = xkmssdk.StoreSoftware
	}

	caReq.KeyAttributes = &xkmssdk.KeyAttributes{
		CN:           issueReq.Subject.CommonName,
		KeyAlgorithm: keyAlg,
		StoreType:    storeType,
		KeyType:      xkmssdk.KeyTypeTLS,
	}

	issued, err := h.ca.IssueCertificate(caReq)
	if err != nil {
		h.logger.Error(err, "failed to issue certificate")
		return h.errorResponse(StatusInternalError, ErrCAIssueFailed{Cause: err})
	}

	cert := issued.Certificate
	resp := &CAIssueResponse{
		Certificate: h.certToFull(cert, true),
		Timestamp:   time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrCAEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleGet retrieves a certificate by serial number or common name
func (h *CAHandler) handleGet(ctx context.Context, req *Request) *Response {
	if h.ca == nil {
		return h.errorResponse(StatusUnavailable, ErrCANotInitialized)
	}

	var getReq CAGetRequest
	if err := DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrCADecodingFailed{Cause: err})
	}

	if getReq.Serial == "" {
		return h.errorResponse(StatusInvalidArgument, ErrCAMissingSerial)
	}

	cert := h.findCertByIdentifier(getReq.Serial)
	if cert == nil {
		return h.errorResponse(StatusNotFound, ErrCACertNotFound{Serial: getReq.Serial})
	}

	resp := &CAGetResponse{
		Certificate: h.certToFull(cert, getReq.IncludePem),
		Timestamp:   time.Now().Unix(),
	}
	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrCAEncodingFailed{Cause: err})
	}
	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleList lists certificates with pagination
func (h *CAHandler) handleList(ctx context.Context, req *Request) *Response {
	if h.ca == nil {
		return h.errorResponse(StatusUnavailable, ErrCANotInitialized)
	}

	var listReq CAListRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrCADecodingFailed{Cause: err})
	}

	limit := listReq.Limit
	if limit <= 0 {
		limit = caDefaultLimit
	}
	if limit > caMaxLimit {
		limit = caMaxLimit
	}

	certStore := h.ca.CertStore()
	if certStore == nil {
		return h.errorResponse(StatusUnavailable, ErrCACertStoreUnavailable)
	}

	var certificates []*CertificateSummary

	rootCert, err := h.ca.TrustedRoot()
	if err == nil && rootCert != nil {
		certificates = append(certificates, h.certToSummary(rootCert))
	}

	intermediateCert, err := h.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		certificates = append(certificates, h.certToSummary(intermediateCert))
	}

	total := int32(len(certificates))
	if int32(len(certificates)) > limit {
		certificates = certificates[:limit]
	}

	resp := &CAListResponse{
		Certificates: certificates,
		TotalCount:   total,
		HasMore:      total > limit,
		Timestamp:    time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrCAEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleRevoke revokes a certificate
func (h *CAHandler) handleRevoke(ctx context.Context, req *Request) *Response {
	if h.ca == nil {
		return h.errorResponse(StatusUnavailable, ErrCANotInitialized)
	}

	var revokeReq CARevokeRequest
	if err := DecodePayload(req.Payload, &revokeReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrCADecodingFailed{Cause: err})
	}

	if revokeReq.Serial == "" {
		return h.errorResponse(StatusInvalidArgument, ErrCAMissingSerial)
	}

	cert := h.findCertByIdentifier(revokeReq.Serial)
	if cert == nil {
		return h.errorResponse(StatusNotFound, ErrCACertNotFound{Serial: revokeReq.Serial})
	}

	var keyAttrs *xkmssdk.KeyAttributes
	if revokeReq.DeleteKeys {
		keyAttrs = &xkmssdk.KeyAttributes{
			CN: cert.Subject.CommonName,
		}
	}

	if err := h.ca.RevokeCert(cert, pkgca.RevokeOptions{DeleteKeys: keyAttrs != nil}); err != nil {
		h.logger.Error(err, "failed to revoke certificate")
		return h.errorResponse(StatusInternalError, ErrCARevokeFailed{Cause: err})
	}

	resp := &CARevokeResponse{
		Serial:    revokeReq.Serial,
		Status:    "REVOKED",
		RevokedAt: time.Now().Unix(),
		Reason:    revokeReq.Reason,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrCAEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleRenew renews an existing certificate
func (h *CAHandler) handleRenew(ctx context.Context, req *Request) *Response {
	if h.ca == nil {
		return h.errorResponse(StatusUnavailable, ErrCANotInitialized)
	}

	var renewReq CARenewRequest
	if err := DecodePayload(req.Payload, &renewReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrCADecodingFailed{Cause: err})
	}

	if renewReq.Serial == "" {
		return h.errorResponse(StatusInvalidArgument, ErrCAMissingSerial)
	}

	if renewReq.ExtendDays <= 0 {
		return h.errorResponse(StatusInvalidArgument, ErrCAInvalidExtendDays)
	}

	existingCert := h.findCertByIdentifier(renewReq.Serial)
	if existingCert == nil {
		return h.errorResponse(StatusNotFound, ErrCACertNotFound{Serial: renewReq.Serial})
	}

	caReq := &goca.CACertificateRequest{
		Subject: goca.CASubject{
			CommonName:         existingCert.Subject.CommonName,
			Organization:       firstOrEmpty(existingCert.Subject.Organization),
			OrganizationalUnit: firstOrEmpty(existingCert.Subject.OrganizationalUnit),
			Country:            firstOrEmpty(existingCert.Subject.Country),
			Province:           firstOrEmpty(existingCert.Subject.Province),
			Locality:           firstOrEmpty(existingCert.Subject.Locality),
			Address:            firstOrEmpty(existingCert.Subject.StreetAddress),
			PostalCode:         firstOrEmpty(existingCert.Subject.PostalCode),
		},
		Valid:       int(renewReq.ExtendDays),
		IsCA:        existingCert.IsCA,
		MaxPathLen:  existingCert.MaxPathLen,
		KeyUsage:    existingCert.KeyUsage,
		ExtKeyUsage: existingCert.ExtKeyUsage,
	}

	if len(existingCert.DNSNames) > 0 || len(existingCert.IPAddresses) > 0 ||
		len(existingCert.EmailAddresses) > 0 || len(existingCert.URIs) > 0 {
		caReq.SANS = &goca.CASubjectAlternativeNames{
			DNS:   existingCert.DNSNames,
			Email: existingCert.EmailAddresses,
		}
		for _, ip := range existingCert.IPAddresses {
			caReq.SANS.IPs = append(caReq.SANS.IPs, ip.String())
		}
		for _, uri := range existingCert.URIs {
			caReq.SANS.URIs = append(caReq.SANS.URIs, uri.String())
		}
	}

	caReq.KeyAttributes = &xkmssdk.KeyAttributes{
		CN:           existingCert.Subject.CommonName,
		KeyAlgorithm: existingCert.PublicKeyAlgorithm,
		StoreType:    xkmssdk.StoreSoftware,
		KeyType:      xkmssdk.KeyTypeTLS,
	}

	issuedRenew, err := h.ca.IssueCertificate(caReq)
	if err != nil {
		h.logger.Error(err, "failed to renew certificate")
		return h.errorResponse(StatusInternalError, ErrCARenewFailed{Cause: err})
	}

	newCert := issuedRenew.Certificate
	resp := &CARenewResponse{
		OldSerial:   renewReq.Serial,
		Certificate: h.certToFull(newCert, true),
		Timestamp:   time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrCAEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleVerify verifies a certificate against the CA bundle
func (h *CAHandler) handleVerify(ctx context.Context, req *Request) *Response {
	if h.ca == nil {
		return h.errorResponse(StatusUnavailable, ErrCANotInitialized)
	}

	var verifyReq CAVerifyRequest
	if err := DecodePayload(req.Payload, &verifyReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrCADecodingFailed{Cause: err})
	}

	if verifyReq.CertificatePem == "" && len(verifyReq.CertificateDer) == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrCAMissingCertificate)
	}

	var cert *x509.Certificate
	var err error

	if len(verifyReq.CertificateDer) > 0 {
		cert, err = x509.ParseCertificate(verifyReq.CertificateDer)
	} else {
		block, _ := pem.Decode([]byte(verifyReq.CertificatePem))
		if block == nil {
			return h.errorResponse(StatusInvalidArgument, ErrCAInvalidPEM)
		}
		cert, err = x509.ParseCertificate(block.Bytes)
	}

	if err != nil {
		return h.errorResponse(StatusInvalidArgument, ErrCAParseFailed{Cause: err})
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	rootCert, err := h.ca.TrustedRoot()
	if err == nil && rootCert != nil {
		roots.AddCert(rootCert)
	}

	intermediateCert, err := h.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		intermediates.AddCert(intermediateCert)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		resp := &CAVerifyResponse{
			Valid:     false,
			Status:    "INVALID",
			Errors:    []string{err.Error()},
			Timestamp: time.Now().Unix(),
		}
		payload, encErr := EncodePayload(resp)
		if encErr != nil {
			return h.errorResponse(StatusInternalError, ErrCAEncodingFailed{Cause: encErr})
		}
		return &Response{
			Status:  StatusOK,
			Payload: payload,
		}
	}

	now := time.Now()
	certStatus := "VALID"
	if now.Before(cert.NotBefore) {
		certStatus = "NOT_YET_VALID"
	} else if now.After(cert.NotAfter) {
		certStatus = "EXPIRED"
	}

	// Check CRL revocation status if requested
	var revoked bool
	if verifyReq.CheckRevoked {
		revoked, _ = h.ca.IsRevoked(cert.SerialNumber)
		// Workaround: go-trusted-ca's IsRevoked() delegates to go-xkms's
		// in-memory map which is not updated by Revoke(). Check the object store
		// directly using the same key pattern that Revoke() uses to persist
		// revocation information.
		if !revoked {
			revoked = h.checkRevocationViaObjectStore(cert)
		}
		if revoked {
			certStatus = "REVOKED"
		}
	}

	var chainSummaries []*CertificateSummary
	if len(chains) > 0 {
		for _, c := range chains[0] {
			chainSummaries = append(chainSummaries, h.certToSummary(c))
		}
	}

	resp := &CAVerifyResponse{
		Valid:     certStatus == "VALID",
		Status:    certStatus,
		Chain:     chainSummaries,
		Timestamp: time.Now().Unix(),
		Revoked:   revoked,
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrCAEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleCRL returns the Certificate Revocation List
func (h *CAHandler) handleCRL(ctx context.Context, req *Request) *Response {
	if h.ca == nil {
		return h.errorResponse(StatusUnavailable, ErrCANotInitialized)
	}

	type crlGenerator interface {
		GenerateCRL() ([]byte, error)
	}

	var crlDER []byte
	var err error

	gen, ok := h.ca.(crlGenerator)
	if !ok {
		return h.errorResponse(StatusNotImplemented, ErrCACRLNotSupported)
	}

	crlDER, err = gen.GenerateCRL()
	if err != nil {
		h.logger.Error(err, "failed to generate CRL")
		// Check if CRL generation is not supported by this CA
		if errors.Is(err, ErrCACRLNotSupported) {
			return h.errorResponse(StatusNotImplemented, ErrCACRLNotSupported)
		}
		return h.errorResponse(StatusInternalError, ErrCACRLFailed{Cause: err})
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		h.logger.Error(err, "failed to parse CRL")
		return h.errorResponse(StatusInternalError, ErrCACRLParseFailed{Cause: err})
	}

	var revokedCerts []*RevokedCertEntry
	for _, entry := range crl.RevokedCertificateEntries {
		revokedCerts = append(revokedCerts, &RevokedCertEntry{
			Serial:         hex.EncodeToString(entry.SerialNumber.Bytes()),
			RevocationTime: entry.RevocationTime.Unix(),
			Reason:         int32(entry.ReasonCode),
		})
	}

	resp := &CACRLResponse{
		CRL:          crlDER,
		LastUpdate:   crl.ThisUpdate.Unix(),
		NextUpdate:   crl.NextUpdate.Unix(),
		RevokedCount: int32(len(crl.RevokedCertificateEntries)),
		RevokedCerts: revokedCerts,
		Timestamp:    time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrCAEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleBundle returns the CA bundle
func (h *CAHandler) handleBundle(ctx context.Context, req *Request) *Response {
	if h.ca == nil {
		return h.errorResponse(StatusUnavailable, ErrCANotInitialized)
	}

	var bundleReq CABundleRequest
	if err := DecodePayload(req.Payload, &bundleReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrCADecodingFailed{Cause: err})
	}

	storeType := xkmssdk.StoreUnknown
	if bundleReq.StoreType != "" {
		storeType = h.parseStoreType(bundleReq.StoreType)
	}

	var keyAlg x509.PublicKeyAlgorithm
	if bundleReq.Algorithm != "" {
		var err error
		keyAlg, err = h.parseKeyAlgorithm(bundleReq.Algorithm)
		if err != nil {
			return h.errorResponse(StatusInvalidArgument, err)
		}
	}

	bundle, err := h.ca.CABundleFiltered(storeType, keyAlg)
	if err != nil {
		h.logger.Error(err, "failed to get CA bundle")
		return h.errorResponse(StatusInternalError, ErrCABundleFailed{Cause: err})
	}

	if len(bundle) == 0 {
		return h.errorResponse(StatusNotFound, ErrCABundleNotFound)
	}

	var certificates []*CertificateSummary
	certs, err := h.ca.ParseBundle(bundle)
	if err == nil {
		for _, cert := range certs {
			certificates = append(certificates, h.certToSummary(cert))
		}
	}

	resp := &CABundleResponse{
		Bundle:       bundle,
		Certificates: certificates,
		CertCount:    int32(len(certificates)),
		Timestamp:    time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrCAEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Certificate Lookup Helpers
// =============================================================================

// certMatchesIdentifier checks if a certificate matches the given identifier,
// which can be either a hex-encoded serial number or a common name.
func (h *CAHandler) certMatchesIdentifier(cert *x509.Certificate, identifier string) bool {
	if hex.EncodeToString(cert.SerialNumber.Bytes()) == identifier {
		return true
	}
	if strings.EqualFold(cert.Subject.CommonName, identifier) {
		return true
	}
	return false
}

// findCertByIdentifier searches for a certificate matching the given identifier.
// The identifier can be a hex-encoded serial number or a common name.
// It checks root and intermediate CA certificates first, then the certificate store.
// For the cert store, it tries a direct CN-based lookup first (fast path), then
// falls back to iterating all certificates and matching by hex-encoded serial.
func (h *CAHandler) findCertByIdentifier(identifier string) *x509.Certificate {
	// Check root certificate
	rootCert, err := h.ca.TrustedRoot()
	if err == nil && rootCert != nil {
		if h.certMatchesIdentifier(rootCert, identifier) {
			return rootCert
		}
	}

	// Check intermediate certificate
	intermediateCert, err := h.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		if h.certMatchesIdentifier(intermediateCert, identifier) {
			return intermediateCert
		}
	}

	// Try cert store lookup
	certStore := h.ca.CertStore()
	if certStore == nil {
		return nil
	}

	// Try direct CN-based lookup first (cert store uses CN as key)
	cert, err := certStore.GetCertificate(identifier)
	if err == nil && cert != nil {
		return cert
	}

	// Fall back to listing all certificates and matching by serial number
	certs, listErr := certStore.ListCertificates()
	if listErr != nil {
		return nil
	}

	for _, c := range certs {
		if hex.EncodeToString(c.SerialNumber.Bytes()) == identifier {
			return c
		}
	}

	return nil
}

// =============================================================================
// Revocation Helpers
// =============================================================================

// checkRevocationViaObjectStore checks if a certificate has been revoked by
// querying the CA's object store directly. This works around a bug in
// go-trusted-ca where Revoke() stores revocation info in the object store
// but IsRevoked() only checks go-xkms's in-memory map.
//
// The native TrustedCA interface does not expose the object store directly;
// the concrete *pkg/ca.CA struct does. Probe via an ad-hoc interface so this
// degrades gracefully when the underlying implementation changes.
func (h *CAHandler) checkRevocationViaObjectStore(cert *x509.Certificate) bool {
	type objectStoreProvider interface {
		ObjectStore() objstore.Storage
	}
	provider, ok := h.ca.(objectStoreProvider)
	if !ok {
		return false
	}
	objStore := provider.ObjectStore()
	if objStore == nil {
		return false
	}
	key := fmt.Sprintf("revocations/%s/%s.json", cert.Subject.CommonName, cert.SerialNumber.String())
	reader, err := objStore.Get(key)
	if err != nil {
		return false
	}
	_ = reader.Close()
	return true
}

// =============================================================================
// Helper methods
// =============================================================================

func (h *CAHandler) errorResponse(status byte, err error) *Response {
	return &Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

func (h *CAHandler) parseKeyAlgorithm(alg string) (x509.PublicKeyAlgorithm, error) {
	switch strings.ToUpper(alg) {
	case "RSA", "RSA2048", "RSA-2048", "RSA3072", "RSA-3072", "RSA4096", "RSA-4096":
		return x509.RSA, nil
	case "ECDSA", "EC", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "P256", "P384", "P521":
		return x509.ECDSA, nil
	case "ED25519":
		return x509.Ed25519, nil
	case "":
		return x509.ECDSA, nil
	default:
		return 0, ErrCAInvalidAlgorithm{Algorithm: alg}
	}
}

func (h *CAHandler) keyAlgorithmToString(alg x509.PublicKeyAlgorithm) string {
	switch alg {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "ED25519"
	default:
		return "UNKNOWN"
	}
}

func (h *CAHandler) signatureAlgorithmToString(alg x509.SignatureAlgorithm) string {
	return alg.String()
}

func (h *CAHandler) parseStoreType(storeType string) xkmssdk.StoreType {
	return xkmssdk.ParseStoreType(storeType)
}

func (h *CAHandler) parseKeyUsage(usages []string) x509.KeyUsage {
	var keyUsage x509.KeyUsage
	for _, u := range usages {
		switch strings.ToUpper(u) {
		case "DIGITALSIGNATURE", "DIGITAL_SIGNATURE":
			keyUsage |= x509.KeyUsageDigitalSignature
		case "CONTENTCOMMITMENT", "CONTENT_COMMITMENT":
			keyUsage |= x509.KeyUsageContentCommitment
		case "KEYENCIPHERMENT", "KEY_ENCIPHERMENT":
			keyUsage |= x509.KeyUsageKeyEncipherment
		case "DATAENCIPHERMENT", "DATA_ENCIPHERMENT":
			keyUsage |= x509.KeyUsageDataEncipherment
		case "KEYAGREEMENT", "KEY_AGREEMENT":
			keyUsage |= x509.KeyUsageKeyAgreement
		case "CERTSIGN", "CERT_SIGN":
			keyUsage |= x509.KeyUsageCertSign
		case "CRLSIGN", "CRL_SIGN":
			keyUsage |= x509.KeyUsageCRLSign
		case "ENCIPHERONLY", "ENCIPHER_ONLY":
			keyUsage |= x509.KeyUsageEncipherOnly
		case "DECIPHERONLY", "DECIPHER_ONLY":
			keyUsage |= x509.KeyUsageDecipherOnly
		}
	}
	return keyUsage
}

func (h *CAHandler) parseExtKeyUsage(usages []string) []x509.ExtKeyUsage {
	var extKeyUsage []x509.ExtKeyUsage
	for _, u := range usages {
		switch strings.ToUpper(u) {
		case "ANY":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageAny)
		case "SERVERAUTH", "SERVER_AUTH":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
		case "CLIENTAUTH", "CLIENT_AUTH":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
		case "CODESIGNING", "CODE_SIGNING":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageCodeSigning)
		case "EMAILPROTECTION", "EMAIL_PROTECTION":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageEmailProtection)
		case "TIMESTAMPING", "TIME_STAMPING":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageTimeStamping)
		case "OCSPSIGNING", "OCSP_SIGNING":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageOCSPSigning)
		}
	}
	return extKeyUsage
}

func (h *CAHandler) certToFull(cert *x509.Certificate, includePEM bool) *Certificate {
	if cert == nil {
		return nil
	}

	certStatus := "VALID"
	now := time.Now()
	if now.Before(cert.NotBefore) {
		certStatus = "NOT_YET_VALID"
	} else if now.After(cert.NotAfter) {
		certStatus = "EXPIRED"
	}

	c := &Certificate{
		Serial: hex.EncodeToString(cert.SerialNumber.Bytes()),
		Subject: &Subject{
			CommonName:         cert.Subject.CommonName,
			Organization:       firstOrEmpty(cert.Subject.Organization),
			OrganizationalUnit: firstOrEmpty(cert.Subject.OrganizationalUnit),
			Country:            firstOrEmpty(cert.Subject.Country),
			Province:           firstOrEmpty(cert.Subject.Province),
			Locality:           firstOrEmpty(cert.Subject.Locality),
			Address:            firstOrEmpty(cert.Subject.StreetAddress),
			PostalCode:         firstOrEmpty(cert.Subject.PostalCode),
		},
		Issuer:             cert.Issuer.CommonName,
		NotBefore:          cert.NotBefore.Unix(),
		NotAfter:           cert.NotAfter.Unix(),
		Status:             certStatus,
		KeyAlgorithm:       h.keyAlgorithmToString(cert.PublicKeyAlgorithm),
		SignatureAlgorithm: h.signatureAlgorithmToString(cert.SignatureAlgorithm),
		IsCA:               cert.IsCA,
	}

	// Add SANs if present
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 ||
		len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 {
		c.Sans = &SANs{
			DNS:   cert.DNSNames,
			Email: cert.EmailAddresses,
		}
		for _, ip := range cert.IPAddresses {
			c.Sans.IPs = append(c.Sans.IPs, ip.String())
		}
		for _, uri := range cert.URIs {
			c.Sans.URIs = append(c.Sans.URIs, uri.String())
		}
	}

	if includePEM {
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		c.Pem = string(pemBlock)
	}

	return c
}

func (h *CAHandler) certToSummary(cert *x509.Certificate) *CertificateSummary {
	if cert == nil {
		return nil
	}

	certStatus := "VALID"
	now := time.Now()
	if now.Before(cert.NotBefore) {
		certStatus = "NOT_YET_VALID"
	} else if now.After(cert.NotAfter) {
		certStatus = "EXPIRED"
	}

	return &CertificateSummary{
		Serial:       hex.EncodeToString(cert.SerialNumber.Bytes()),
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore.Unix(),
		NotAfter:     cert.NotAfter.Unix(),
		Status:       certStatus,
		KeyAlgorithm: h.keyAlgorithmToString(cert.PublicKeyAlgorithm),
	}
}

// firstOrEmpty returns the first element of a slice or empty string
func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
