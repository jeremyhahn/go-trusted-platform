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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// caMarshalOptions serializes the protobuf CA responses (issue, sign-csr,
// get certificate) in the proto-JSON shape the CA webservice also speaks, so
// the SDK REST transport decodes both servers alike. Unpopulated fields are
// emitted so response shapes stay stable.
var caMarshalOptions = protojson.MarshalOptions{
	EmitUnpopulated: true,
}

// caUnmarshalOptions decodes protobuf CA request bodies. Unknown fields are
// discarded for forward compatibility.
var caUnmarshalOptions = protojson.UnmarshalOptions{
	DiscardUnknown: true,
}

// revokeUnmarshalOptions decodes a revocation strictly: DiscardUnknown would
// also discard an unknown reason name, and a revocation must not record
// REVOCATION_REASON_UNSPECIFIED for a reason the caller misspelled.
var revokeUnmarshalOptions = protojson.UnmarshalOptions{}

const (
	caDefaultPageSize int32 = 50
	caMaxPageSize     int32 = 1000
)

// =============================================================================
// CA REST Handler Errors
// =============================================================================

// ErrCAServiceNotAvailable is returned when the CA service is not configured.
type ErrCAServiceNotAvailable struct{}

func (e ErrCAServiceNotAvailable) Error() string {
	return "certificate authority service not available"
}

// ErrCANotInitialized is returned when the CA service is not initialized.
type ErrCANotInitialized struct{}

func (e ErrCANotInitialized) Error() string {
	return "certificate authority not initialized"
}

// ErrInvalidSerialNumber is returned when a serial number is invalid or empty.
type ErrInvalidSerialNumber struct {
	Serial string
	Reason string
}

func (e ErrInvalidSerialNumber) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid serial number '%s': %s", e.Serial, e.Reason)
	}
	return fmt.Sprintf("invalid serial number: %s", e.Serial)
}

// ErrCertificateNotFound is returned when a certificate cannot be found.
type ErrCertificateNotFound struct {
	Serial string
}

func (e ErrCertificateNotFound) Error() string {
	if e.Serial != "" {
		return fmt.Sprintf("certificate not found: %s", e.Serial)
	}
	return "certificate not found"
}

// ErrInvalidCertificateRequest is returned when a certificate request is invalid.
type ErrInvalidCertificateRequest struct {
	Reason string
}

func (e ErrInvalidCertificateRequest) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid certificate request: %s", e.Reason)
	}
	return "invalid certificate request"
}

// ErrMissingCommonName is returned when common name is required but not provided.
type ErrMissingCommonName struct{}

func (e ErrMissingCommonName) Error() string {
	return "common name is required"
}

// ErrMissingCertificateRequest is returned when an issue request carries no
// certificate request.
type ErrMissingCertificateRequest struct{}

func (e ErrMissingCertificateRequest) Error() string {
	return "certificate request is required"
}

// ErrInvalidKeyAlgorithm is returned when an invalid key algorithm is specified.
type ErrInvalidKeyAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidKeyAlgorithm) Error() string {
	return fmt.Sprintf("invalid key algorithm: %s", e.Algorithm)
}

// ErrCertificateIssueFailed is returned when certificate issuance fails.
type ErrCertificateIssueFailed struct {
	Err error
}

func (e ErrCertificateIssueFailed) Error() string {
	return fmt.Sprintf("failed to issue certificate: %v", e.Err)
}

func (e ErrCertificateIssueFailed) Unwrap() error {
	return e.Err
}

// ErrCertificateRevokeFailed is returned when certificate revocation fails.
type ErrCertificateRevokeFailed struct {
	Serial string
	Err    error
}

func (e ErrCertificateRevokeFailed) Error() string {
	return fmt.Sprintf("failed to revoke certificate %s: %v", e.Serial, e.Err)
}

func (e ErrCertificateRevokeFailed) Unwrap() error {
	return e.Err
}

// ErrCertificateRenewFailed is returned when certificate renewal fails.
type ErrCertificateRenewFailed struct {
	Serial string
	Err    error
}

func (e ErrCertificateRenewFailed) Error() string {
	return fmt.Sprintf("failed to renew certificate %s: %v", e.Serial, e.Err)
}

func (e ErrCertificateRenewFailed) Unwrap() error {
	return e.Err
}

// ErrCertificateVerifyFailed is returned when certificate verification fails.
type ErrCertificateVerifyFailed struct {
	Err error
}

func (e ErrCertificateVerifyFailed) Error() string {
	return fmt.Sprintf("certificate verification failed: %v", e.Err)
}

func (e ErrCertificateVerifyFailed) Unwrap() error {
	return e.Err
}

// ErrCRLNotFound is returned when the CRL cannot be found.
type ErrCRLNotFound struct{}

func (e ErrCRLNotFound) Error() string {
	return "certificate revocation list not found"
}

// ErrCRLNotSupported is returned when CRL generation is not supported.
type ErrCRLNotSupported struct{}

func (e ErrCRLNotSupported) Error() string {
	return "CRL generation not supported"
}

// ErrCRLGenerationFailed is returned when CRL generation fails.
type ErrCRLGenerationFailed struct {
	Reason string
}

func (e ErrCRLGenerationFailed) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("CRL generation failed: %s", e.Reason)
	}
	return "CRL generation failed"
}

// ErrCABundleNotFound is returned when the CA bundle is not found.
type ErrCABundleNotFound struct{}

func (e ErrCABundleNotFound) Error() string {
	return "CA bundle not found"
}

// ErrCABundleFailed is returned when getting the CA bundle fails.
type ErrCABundleFailed struct {
	Err error
}

func (e ErrCABundleFailed) Error() string {
	return fmt.Sprintf("failed to get CA bundle: %v", e.Err)
}

func (e ErrCABundleFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidValidityPeriod is returned when an invalid validity period is specified.
type ErrInvalidValidityPeriod struct {
	Days   int
	Reason string
}

func (e ErrInvalidValidityPeriod) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid validity period %d days: %s", e.Days, e.Reason)
	}
	return fmt.Sprintf("invalid validity period: %d days", e.Days)
}

// =============================================================================
// Request/Response Types
// =============================================================================

// CASubjectRequest contains certificate subject information.
type CASubjectRequest struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
	Province           string `json:"province,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Address            string `json:"address,omitempty"`
	PostalCode         string `json:"postal_code,omitempty"`
}

// CASANsRequest contains Subject Alternative Names.
type CASANsRequest struct {
	DNS   []string `json:"dns,omitempty"`
	IPs   []string `json:"ips,omitempty"`
	Email []string `json:"email,omitempty"`
	URIs  []string `json:"uris,omitempty"`
}

// CertificateRenewRequest is the request body for renewing a certificate.
type CertificateRenewRequest struct {
	ValidDays    int            `json:"valid_days"`
	PreserveSANs bool           `json:"preserve_sans,omitempty"`
	NewSANs      *CASANsRequest `json:"new_sans,omitempty"`
}

// CertificateVerifyRequest is the request body for verifying a certificate.
type CertificateVerifyRequest struct {
	CertificatePEM   string   `json:"certificate_pem,omitempty"`
	CertificateDER   []byte   `json:"certificate_der,omitempty"`
	TrustedRoots     [][]byte `json:"trusted_roots,omitempty"`
	VerifyExpiration bool     `json:"verify_expiration,omitempty"`
	VerifyRevocation bool     `json:"verify_revocation,omitempty"`
}

// CACertificateResponse represents a certificate in API responses.
type CACertificateResponse struct {
	Serial             string           `json:"serial"`
	Subject            CASubjectRequest `json:"subject"`
	Issuer             string           `json:"issuer"`
	NotBefore          int64            `json:"not_before"`
	NotAfter           int64            `json:"not_after"`
	Status             string           `json:"status"`
	KeyAlgorithm       string           `json:"key_algorithm"`
	SignatureAlgorithm string           `json:"signature_algorithm"`
	IsCA               bool             `json:"is_ca"`
	MaxPathLen         int              `json:"max_path_len,omitempty"`
	KeyUsage           []string         `json:"key_usage,omitempty"`
	ExtKeyUsage        []string         `json:"ext_key_usage,omitempty"`
	FingerprintSHA256  string           `json:"fingerprint_sha256,omitempty"`
	DNSNames           []string         `json:"dns_names,omitempty"`
	IPAddresses        []string         `json:"ip_addresses,omitempty"`
	EmailAddresses     []string         `json:"email_addresses,omitempty"`
	URIs               []string         `json:"uris,omitempty"`
	PEM                string           `json:"pem,omitempty"`
	DER                []byte           `json:"der,omitempty"`
}

// CACertificateSummary contains a summary of a certificate for list responses.
type CACertificateSummary struct {
	Serial       string `json:"serial"`
	CommonName   string `json:"common_name"`
	Issuer       string `json:"issuer"`
	NotBefore    int64  `json:"not_before"`
	NotAfter     int64  `json:"not_after"`
	Status       string `json:"status"`
	KeyAlgorithm string `json:"key_algorithm"`
}

// CAInfoResponse contains CA information.
type CAInfoResponse struct {
	CommonName       string                 `json:"common_name"`
	IsInitialized    bool                   `json:"is_initialized"`
	IsIntermediate   bool                   `json:"is_intermediate"`
	RootCert         *CACertificateSummary  `json:"root_cert,omitempty"`
	Intermediates    []CACertificateSummary `json:"intermediates,omitempty"`
	DefaultAlgorithm string                 `json:"default_algorithm,omitempty"`
	DefaultValidity  int                    `json:"default_validity_days,omitempty"`
	Timestamp        int64                  `json:"timestamp"`
}

// CACertificateListResponse is the response for listing certificates.
type CACertificateListResponse struct {
	Certificates []CACertificateSummary `json:"certificates"`
	Page         int                    `json:"page"`
	PageSize     int                    `json:"page_size"`
	TotalItems   int                    `json:"total_items"`
	TotalPages   int                    `json:"total_pages"`
	Timestamp    int64                  `json:"timestamp"`
}

// CARenewCertificateResponse is the response for renewing a certificate.
type CARenewCertificateResponse struct {
	Success        bool                   `json:"success"`
	Message        string                 `json:"message"`
	OldCertificate *CACertificateResponse `json:"old_certificate,omitempty"`
	NewCertificate *CACertificateResponse `json:"new_certificate,omitempty"`
	Timestamp      int64                  `json:"timestamp"`
}

// CAVerifyCertificateResponse is the response for verifying a certificate.
type CAVerifyCertificateResponse struct {
	Success   bool     `json:"success"`
	Message   string   `json:"message"`
	Valid     bool     `json:"valid"`
	Revoked   bool     `json:"revoked"`
	Chain     []string `json:"chain,omitempty"`
	Errors    []string `json:"errors,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Timestamp int64    `json:"timestamp"`
}

// CARevokedCertEntry represents a revoked certificate entry.
type CARevokedCertEntry struct {
	Serial         string `json:"serial"`
	RevocationTime int64  `json:"revocation_time"`
	Reason         int    `json:"reason"`
}

// CACRLResponse contains CRL information.
type CACRLResponse struct {
	CRL          []byte               `json:"crl"`
	LastUpdate   int64                `json:"last_update"`
	NextUpdate   int64                `json:"next_update"`
	RevokedCount int                  `json:"revoked_count"`
	RevokedCerts []CARevokedCertEntry `json:"revoked_certs,omitempty"`
	Timestamp    int64                `json:"timestamp"`
}

// CABundleResponse contains CA bundle information.
type CABundleResponse struct {
	Bundle       []byte                 `json:"bundle"`
	Certificates []CACertificateSummary `json:"certificates,omitempty"`
	CertCount    int                    `json:"cert_count"`
	Timestamp    int64                  `json:"timestamp"`
}

// CAErrorResponse represents an error response.
type CAErrorResponse struct {
	Error     string `json:"error"`
	Code      int    `json:"code"`
	Timestamp int64  `json:"timestamp"`
}

// =============================================================================
// CA Service Interface
// =============================================================================

// CARevokeOptions carries a revocation's options to CAServiceInterface.Revoke.
type CARevokeOptions struct {
	// KeyAttrs names the certificate's key when the caller asked for it to be
	// deleted; nil keeps the key.
	KeyAttrs *xkmssdk.KeyAttributes
	// Reason is the caller's CRL reason. The RevocationReason values are the
	// RFC 5280 §5.3.1 CRLReason codes.
	Reason platformv1.RevocationReason
}

// CAServiceInterface defines the interface for CA operations.
type CAServiceInterface interface {
	// Identity returns the CA identity (common name).
	Identity() string
	// IsInitialized returns whether the CA is initialized.
	IsInitialized() bool
	// DefaultKeyAlgorithm returns the default key algorithm.
	DefaultKeyAlgorithm() x509.PublicKeyAlgorithm
	// DefaultValidityPeriod returns the default validity period.
	DefaultValidityPeriod() time.Duration
	// TrustedRoot returns the root certificate.
	TrustedRoot() (*x509.Certificate, error)
	// TrustedIntermediate returns the intermediate certificate.
	TrustedIntermediate() (*x509.Certificate, error)
	// IssueCertificate issues a new certificate.
	IssueCertificate(ctx context.Context, req *quicbaasca.CACertificateRequest) (*x509.Certificate, error)
	// SignCSR certifies the key in a PEM CSR, a key the CA never holds.
	SignCSR(ctx context.Context, csrPEM []byte, opts *quicbaasca.SignOptions) (*x509.Certificate, error)
	// Revoke revokes a certificate, recording opts.Reason as its CRL reason.
	Revoke(ctx context.Context, cert *x509.Certificate, opts CARevokeOptions) error
	// Renew replaces a certificate with one on re-keyed material.
	Renew(ctx context.Context, existing *x509.Certificate, opts issuance.RenewOptions) (*x509.Certificate, error)
	// CertificateStore returns the certificate store.
	CertificateStore() xkmssdk.CertStore
	// CABundle returns the CA bundle.
	CABundle(storeType xkmssdk.StoreType, keyAlg x509.PublicKeyAlgorithm) ([]byte, error)
	// ParseBundle parses a PEM bundle into certificates.
	ParseBundle(bundle []byte) ([]*x509.Certificate, error)
}

// =============================================================================
// CA Handlers
// =============================================================================

// CAHandlers provides REST API handlers for CA operations.
type CAHandlers struct {
	ca         CAServiceInterface
	logger     *slog.Logger
	objStorage objectstorage.Client
	kms        issuance.KMS
	guard      *ScopeGuard
}

// TokenAuthorizer validates a platform bearer token, with its DPoP proof
// when present, and authorizes it for requiredPerm.
type TokenAuthorizer interface {
	AuthorizeToken(ctx context.Context, token, requiredPerm, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error)
}

// WithScopeGuard sets the guard that gates sign-csr: only a platform bearer
// token granting ca:sign-csr reaches it. Without one, sign-csr refuses every
// request with 403.
func (h *CAHandlers) WithScopeGuard(guard *ScopeGuard) *CAHandlers {
	h.guard = guard
	return h
}

// WithKMS sets the KMS a CSR's key must belong to. Without one,
// POST /api/v1/ca/sign-csr refuses every request.
func (h *CAHandlers) WithKMS(kms issuance.KMS) *CAHandlers {
	h.kms = kms
	return h
}

// NewCAHandlers creates a new CAHandlers instance.
// objStorage may be nil; if nil, the revocation object-store check is skipped.
func NewCAHandlers(ca CAServiceInterface, logger *slog.Logger, objStorage objectstorage.Client) *CAHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &CAHandlers{
		ca:         ca,
		logger:     logger,
		objStorage: objStorage,
	}
}

// RegisterRoutes registers all CA routes on the provided router.
func (h *CAHandlers) RegisterRoutes(router *mux.Router) {
	// CA information, CRL and bundle serve public material and stay
	// ungated, as the webservice's RegisterPublicRoutes does: the CRL must
	// reach relying parties that hold no credential (RFC 5280 §4.2.1.13).
	router.HandleFunc("/api/v1/ca/info", h.handleGetCAInfo).Methods(http.MethodGet)

	// Certificate CRUD operations. Each takes the scope the gRPC, QUIC and
	// MCP transports check for the same operation; renewing issues a
	// certificate, so it takes the issuing scope. The daemon's mTLS peer
	// authenticator grants a certificate bound as a PXE install certificate
	// only pxe:write, so an installer reaches none of them (Codex 8238,
	// Codex 8646).
	router.HandleFunc("/api/v1/ca/certificates", h.guard.Require(scopeCertsGenerate, h.handleIssueCertificate)).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/ca/certificates", h.guard.Require(scopeCertsList, h.handleListCertificates)).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/ca/certificates/{serial}", h.guard.Require(scopeCertsRead, h.handleGetCertificate)).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/ca/certificates/{serial}", h.guard.Require(scopeCertsRevoke, h.handleRevokeCertificate)).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/ca/certificates/{serial}/renew", h.guard.Require(scopeCertsGenerate, h.handleRenewCertificate)).Methods(http.MethodPost)

	// Code-signing certification of a KMS key from its CSR. A client
	// certificate alone never certifies a code-signing key (#691).
	router.HandleFunc("/api/v1/ca/sign-csr", h.guard.RequireToken(issuance.SignCSRScope, h.handleSignCSR)).Methods(http.MethodPost)

	// Certificate verification
	router.HandleFunc("/api/v1/ca/certificates/verify", h.guard.Require(scopeCertsRead, h.handleVerifyCertificate)).Methods(http.MethodPost)

	// CRL and bundle
	router.HandleFunc("/api/v1/ca/crl", h.handleGetCRL).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/ca/bundle", h.handleGetCABundle).Methods(http.MethodGet)

	h.logger.Info("CA REST routes registered")
}

// =============================================================================
// Handler Implementations
// =============================================================================

// handleGetCAInfo handles GET /api/v1/ca/info
func (h *CAHandlers) handleGetCAInfo(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrCAServiceNotAvailable{})
		return
	}

	now := time.Now().Unix()

	resp := CAInfoResponse{
		IsInitialized: h.ca.IsInitialized(),
		Timestamp:     now,
	}

	if h.ca.IsInitialized() {
		resp.CommonName = h.ca.Identity()
		resp.DefaultAlgorithm = h.keyAlgorithmToString(h.ca.DefaultKeyAlgorithm())
		resp.DefaultValidity = int(h.ca.DefaultValidityPeriod() / (24 * time.Hour))

		// Get root certificate info
		rootCert, err := h.ca.TrustedRoot()
		if err == nil && rootCert != nil {
			summary := h.certToSummary(rootCert)
			resp.RootCert = &summary
		}

		// Get intermediate certificate info
		intermediateCert, err := h.ca.TrustedIntermediate()
		if err == nil && intermediateCert != nil {
			resp.IsIntermediate = true
			resp.Intermediates = append(resp.Intermediates, h.certToSummary(intermediateCert))
		}
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleIssueCertificate handles POST /api/v1/ca/certificates
func (h *CAHandlers) handleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrCAServiceNotAvailable{})
		return
	}

	req := &platformv1.IssueCertificateRequest{}
	if !h.decodeProto(w, r, req) {
		return
	}

	certReq := req.GetRequest()
	if certReq == nil {
		h.writeError(w, http.StatusBadRequest, ErrMissingCertificateRequest{})
		return
	}
	subject := certReq.GetSubject()
	if subject.GetCommonName() == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingCommonName{})
		return
	}

	// Build certificate request
	caReq := &quicbaasca.CACertificateRequest{
		Subject: quicbaasca.CASubject{
			CommonName:         subject.GetCommonName(),
			Organization:       subject.GetOrganization(),
			OrganizationalUnit: subject.GetOrganizationalUnit(),
			Country:            subject.GetCountry(),
			Province:           subject.GetProvince(),
			Locality:           subject.GetLocality(),
			Address:            subject.GetAddress(),
			PostalCode:         subject.GetPostalCode(),
		},
		Valid:       int(certReq.GetValidDays()),
		IsCA:        certReq.GetIsCa(),
		MaxPathLen:  int(certReq.GetMaxPathLen()),
		KeyUsage:    h.parseKeyUsage(certReq.GetKeyUsage()),
		ExtKeyUsage: h.parseExtKeyUsage(certReq.GetExtKeyUsage()),
	}

	// Add SANs if provided
	if sans := certReq.GetSans(); sans != nil {
		caReq.SANS = &quicbaasca.CASubjectAlternativeNames{
			DNS:   sans.GetDnsNames(),
			IPs:   sans.GetIpAddresses(),
			Email: sans.GetEmailAddresses(),
			URIs:  sans.GetUris(),
		}
	}

	// Set key attributes
	storeType, err := issuance.StoreType(certReq.GetStoreType())
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	caReq.KeyAttributes, err = issuance.KeyAttributes(certReq.GetKeyAlgorithm(), subject.GetCommonName(), storeType)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	// Issue the certificate
	cert, err := h.ca.IssueCertificate(r.Context(), caReq)
	if err != nil {
		if issuance.IsInvalidRequest(err) {
			h.writeError(w, http.StatusBadRequest, err)
			return
		}
		h.logger.Error("Failed to issue certificate", "error", err, "cn", subject.GetCommonName())
		h.writeError(w, http.StatusInternalServerError, ErrCertificateIssueFailed{Err: err})
		return
	}
	h.writeIssued(w, cert)
}

// handleSignCSR handles POST /api/v1/ca/sign-csr. It certifies, for code
// signing only, the KMS key a CSR names — a key the CA never holds.
func (h *CAHandlers) handleSignCSR(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrCAServiceNotAvailable{})
		return
	}

	req := &platformv1.SignCSRRequest{}
	if !h.decodeProto(w, r, req) {
		return
	}

	cert, err := issuance.SignCSR(r.Context(), h.ca, h.kms, &issuance.CSR{
		PEM:       []byte(req.GetCsrPem()),
		ValidDays: int(req.GetValidDays()),
	})
	if err != nil {
		if issuance.IsInvalidRequest(err) {
			h.writeError(w, http.StatusBadRequest, err)
			return
		}
		h.logger.Error("Failed to sign CSR", "error", err)
		h.writeError(w, http.StatusInternalServerError, ErrCertificateIssueFailed{Err: err})
		return
	}
	h.writeIssued(w, cert)
}

// requestURL is the DPoP htu of r: its absolute URL without query or
// fragment (RFC 9449 §4.3).
func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

// writeIssued answers a request with the certificate it issued.
func (h *CAHandlers) writeIssued(w http.ResponseWriter, cert *x509.Certificate) {
	resp := &platformv1.IssueCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "certificate issued successfully",
		},
		Certificate: h.certToProto(cert, true, false),
		Timestamp:   timestamppb.Now(),
	}

	h.logger.Info("Certificate issued", "serial", hex.EncodeToString(cert.SerialNumber.Bytes()), "cn", cert.Subject.CommonName)
	h.writeProto(w, http.StatusCreated, resp)
}

// handleListCertificates handles GET /api/v1/ca/certificates
func (h *CAHandlers) handleListCertificates(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrCAServiceNotAvailable{})
		return
	}

	// Parse pagination parameters
	page := h.parseInt(r.URL.Query().Get("page"), 1)
	pageSize := h.parseInt(r.URL.Query().Get("page_size"), int(caDefaultPageSize))

	if pageSize > int(caMaxPageSize) {
		pageSize = int(caMaxPageSize)
	}
	if pageSize < 1 {
		pageSize = int(caDefaultPageSize)
	}
	if page < 1 {
		page = 1
	}

	// Collect certificates
	var certificates []CACertificateSummary

	rootCert, err := h.ca.TrustedRoot()
	if err == nil && rootCert != nil {
		certificates = append(certificates, h.certToSummary(rootCert))
	}

	intermediateCert, err := h.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		certificates = append(certificates, h.certToSummary(intermediateCert))
	}

	// List from certificate store if available
	certStore := h.ca.CertificateStore()
	if certStore != nil {
		certs, err := certStore.ListCertificates()
		if err == nil {
			for _, cert := range certs {
				// Skip root and intermediate as they are already added
				if rootCert != nil && cert.SerialNumber.Cmp(rootCert.SerialNumber) == 0 {
					continue
				}
				if intermediateCert != nil && cert.SerialNumber.Cmp(intermediateCert.SerialNumber) == 0 {
					continue
				}
				certificates = append(certificates, h.certToSummary(cert))
			}
		}
	}

	// Apply pagination
	totalItems := len(certificates)
	totalPages := (totalItems + pageSize - 1) / pageSize
	startIdx := (page - 1) * pageSize
	endIdx := startIdx + pageSize

	if startIdx >= totalItems {
		certificates = []CACertificateSummary{}
	} else {
		if endIdx > totalItems {
			endIdx = totalItems
		}
		certificates = certificates[startIdx:endIdx]
	}

	resp := CACertificateListResponse{
		Certificates: certificates,
		Page:         page,
		PageSize:     pageSize,
		TotalItems:   totalItems,
		TotalPages:   totalPages,
		Timestamp:    time.Now().Unix(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetCertificate handles GET /api/v1/ca/certificates/{serial}
func (h *CAHandlers) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrCAServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	serial := vars["serial"]
	if serial == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidSerialNumber{Serial: "", Reason: "serial number is required"})
		return
	}

	query := r.URL.Query()
	includePEM := query.Get("include_pem") == "true"
	includeDER := query.Get("include_der") == "true"

	// Look up certificate by serial number
	cert := h.findCertificateBySerial(serial)
	if cert == nil {
		h.writeError(w, http.StatusNotFound, ErrCertificateNotFound{Serial: serial})
		return
	}

	h.writeProto(w, http.StatusOK, &platformv1.GetCertificateResponse{
		Certificate: h.certToProto(cert, includePEM, includeDER),
		Timestamp:   timestamppb.Now(),
	})
}

// Scopes the CA certificate routes require, the names the gRPC, QUIC and MCP
// transports check for the same operations (pkg/api/mcp/authz.go).
const (
	// scopeCertsGenerate authorizes issuing and renewing a certificate.
	scopeCertsGenerate = "certs:generate"
	// scopeCertsList authorizes enumerating issued certificates.
	scopeCertsList = "certs:list"
	// scopeCertsRead authorizes reading or verifying one certificate.
	scopeCertsRead = "certs:read"
	// scopeCertsRevoke is the scope the revoke route requires, as the
	// webservice's DELETE /api/v1/ca/certificates/{serial} does.
	scopeCertsRevoke = "certs:revoke"
)

// handleRevokeCertificate handles DELETE /api/v1/ca/certificates/{serial},
// the shape the Go and JS SDKs send. The optional body is a protojson
// platformv1.RevokeCertificateRequest (reason as the enum name, deleteKeys or
// delete_keys); no body is a plain revocation. The answer is a protojson
// platformv1.RevokeCertificateResponse, as the webservice's route returns.
func (h *CAHandlers) handleRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrCAServiceNotAvailable{})
		return
	}

	serial := mux.Vars(r)["serial"]
	if serial == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidSerialNumber{Serial: "", Reason: "serial number is required"})
		return
	}

	// The body is optional; the path names the certificate.
	req := &platformv1.RevokeCertificateRequest{}
	if !h.decodeProtoWith(revokeUnmarshalOptions, w, r, req) {
		return
	}
	req.Serial = serial

	if err := issuance.ValidateRevocationReason(int(req.GetReason())); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	cert := h.findCertificateBySerial(serial)
	if cert == nil {
		h.writeError(w, http.StatusNotFound, ErrCertificateNotFound{Serial: serial})
		return
	}

	var keyAttrs *xkmssdk.KeyAttributes
	if req.GetDeleteKeys() {
		keyAttrs = &xkmssdk.KeyAttributes{
			CN: cert.Subject.CommonName,
		}
	}

	if err := h.ca.Revoke(r.Context(), cert, CARevokeOptions{KeyAttrs: keyAttrs, Reason: req.GetReason()}); err != nil {
		h.logger.Error("Failed to revoke certificate", "error", err, "serial", serial)
		h.writeError(w, http.StatusInternalServerError, ErrCertificateRevokeFailed{Serial: serial, Err: err})
		return
	}

	h.logger.Info("Certificate revoked", "serial", serial)
	now := timestamppb.Now()
	h.writeProto(w, http.StatusOK, &platformv1.RevokeCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "certificate revoked successfully",
		},
		Serial:            serial,
		CertificateStatus: platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED,
		RevokedAt:         now,
		Reason:            req.GetReason(),
		Timestamp:         now,
	})
}

// handleRenewCertificate handles POST /api/v1/ca/certificates/{serial}/renew
func (h *CAHandlers) handleRenewCertificate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrCAServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	serial := vars["serial"]
	if serial == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidSerialNumber{Serial: "", Reason: "serial number is required"})
		return
	}

	var req CertificateRenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.ValidDays <= 0 {
		h.writeError(w, http.StatusBadRequest, ErrInvalidValidityPeriod{Days: req.ValidDays, Reason: "must be positive"})
		return
	}

	// Find the existing certificate
	existingCert := h.findCertificateBySerial(serial)
	if existingCert == nil {
		h.writeError(w, http.StatusNotFound, ErrCertificateNotFound{Serial: serial})
		return
	}

	renewOpts := issuance.RenewOptions{
		ValidDays:    req.ValidDays,
		PreserveSANs: req.PreserveSANs,
	}
	if req.NewSANs != nil {
		renewOpts.NewSANs = &quicbaasca.CASubjectAlternativeNames{
			DNS:   req.NewSANs.DNS,
			IPs:   req.NewSANs.IPs,
			Email: req.NewSANs.Email,
			URIs:  req.NewSANs.URIs,
		}
	}

	newCert, err := h.ca.Renew(r.Context(), existingCert, renewOpts)
	if err != nil {
		// A renewal the issuer or the SDK's CA profile refuses is the
		// caller's to fix, as it is for issuance.
		if issuance.IsInvalidRequest(err) {
			h.writeError(w, http.StatusBadRequest, err)
			return
		}
		h.logger.Error("Failed to renew certificate", "error", err, "serial", serial)
		h.writeError(w, http.StatusInternalServerError, ErrCertificateRenewFailed{Serial: serial, Err: err})
		return
	}

	resp := CARenewCertificateResponse{
		Success:        true,
		Message:        "certificate renewed successfully",
		OldCertificate: h.certToResponse(existingCert, false),
		NewCertificate: h.certToResponse(newCert, true),
		Timestamp:      time.Now().Unix(),
	}

	h.logger.Info("Certificate renewed", "old_serial", serial, "new_serial", hex.EncodeToString(newCert.SerialNumber.Bytes()))
	h.writeJSON(w, http.StatusOK, resp)
}

// handleVerifyCertificate handles POST /api/v1/ca/certificates/verify
func (h *CAHandlers) handleVerifyCertificate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrCAServiceNotAvailable{})
		return
	}

	var req CertificateVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.CertificatePEM == "" && len(req.CertificateDER) == 0 {
		h.writeError(w, http.StatusBadRequest, ErrInvalidCertificateRequest{Reason: "certificate (PEM or DER) is required"})
		return
	}

	// Parse the certificate to verify
	var cert *x509.Certificate
	var parseErr error

	if len(req.CertificateDER) > 0 {
		cert, parseErr = x509.ParseCertificate(req.CertificateDER)
	} else {
		block, _ := pem.Decode([]byte(req.CertificatePEM))
		if block == nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidCertificateRequest{Reason: "failed to decode PEM certificate"})
			return
		}
		cert, parseErr = x509.ParseCertificate(block.Bytes)
	}

	if parseErr != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidCertificateRequest{Reason: "failed to parse certificate: " + parseErr.Error()})
		return
	}

	// Build verification pool from CA bundle
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

	// Add any additional trusted roots from request
	for _, rootDER := range req.TrustedRoots {
		extraRoot, err := x509.ParseCertificate(rootDER)
		if err == nil {
			roots.AddCert(extraRoot)
		}
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	chains, verifyErr := cert.Verify(opts)

	var errors []string
	var warnings []string

	if verifyErr != nil {
		errors = append(errors, verifyErr.Error())
	}

	// Check certificate validity period if requested
	now := time.Now()
	if req.VerifyExpiration {
		if now.Before(cert.NotBefore) {
			warnings = append(warnings, "certificate is not yet valid")
		} else if now.After(cert.NotAfter) {
			errors = append(errors, "certificate has expired")
		}
	}

	// Check CRL revocation status if requested
	var revoked bool
	if req.VerifyRevocation {
		type revokeChecker interface {
			IsRevoked(serial *big.Int) (bool, error)
		}
		if checker, ok := h.ca.(revokeChecker); ok {
			revoked, _ = checker.IsRevoked(cert.SerialNumber)
		}
		// Workaround: go-trusted-ca's IsRevoked() delegates to go-xkms's
		// in-memory map which is not updated by Revoke(). Check the object store
		// directly using the same key pattern that Revoke() uses to persist
		// revocation information.
		if !revoked {
			revoked = h.checkRevocationViaObjectStore(cert)
		}
		if revoked {
			errors = append(errors, "certificate has been revoked")
		}
	}

	// Build chain response as serial numbers
	var chainSerials []string
	if len(chains) > 0 {
		for _, c := range chains[0] {
			chainSerials = append(chainSerials, hex.EncodeToString(c.SerialNumber.Bytes()))
		}
	}

	valid := len(errors) == 0 && verifyErr == nil

	var message string
	switch {
	case valid:
		message = "certificate verification successful"
	case len(errors) > 0:
		message = "certificate verification failed: " + errors[0]
	default:
		message = "certificate verification failed"
	}

	resp := CAVerifyCertificateResponse{
		Success:   valid,
		Message:   message,
		Valid:     valid,
		Revoked:   revoked,
		Chain:     chainSerials,
		Errors:    errors,
		Warnings:  warnings,
		Timestamp: time.Now().Unix(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetCRL handles GET /api/v1/ca/crl
func (h *CAHandlers) handleGetCRL(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrCAServiceNotAvailable{})
		return
	}

	// The CA interface does not directly expose GenerateCRL, but we can access
	// the underlying CA if it implements the method
	type crlGenerator interface {
		GenerateCRL(ctx context.Context) ([]byte, error)
	}

	var crlDER []byte
	var err error

	if gen, ok := h.ca.(crlGenerator); ok {
		crlDER, err = gen.GenerateCRL(r.Context())
		if err != nil {
			h.logger.Error("Failed to generate CRL", "error", err)
			// Check if this is a "not supported" error
			if strings.Contains(strings.ToLower(err.Error()), "not supported") {
				h.writeError(w, http.StatusNotImplemented, ErrCRLNotSupported{})
				return
			}
			h.writeError(w, http.StatusInternalServerError, ErrCRLGenerationFailed{Reason: err.Error()})
			return
		}
	} else {
		h.writeError(w, http.StatusNotImplemented, ErrCRLNotFound{})
		return
	}

	// Parse the CRL to get metadata
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		h.logger.Error("Failed to parse CRL", "error", err)
		h.writeError(w, http.StatusInternalServerError, ErrCRLGenerationFailed{Reason: err.Error()})
		return
	}

	// Build revoked certificates list
	includeEntries := r.URL.Query().Get("include_entries") == "true"
	var revokedCerts []CARevokedCertEntry
	if includeEntries {
		for _, entry := range crl.RevokedCertificateEntries {
			revokedCerts = append(revokedCerts, CARevokedCertEntry{
				Serial:         hex.EncodeToString(entry.SerialNumber.Bytes()),
				RevocationTime: entry.RevocationTime.Unix(),
				Reason:         entry.ReasonCode,
			})
		}
	}

	resp := CACRLResponse{
		CRL:          crlDER,
		LastUpdate:   crl.ThisUpdate.Unix(),
		NextUpdate:   crl.NextUpdate.Unix(),
		RevokedCount: len(crl.RevokedCertificateEntries),
		RevokedCerts: revokedCerts,
		Timestamp:    time.Now().Unix(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetCABundle handles GET /api/v1/ca/bundle
func (h *CAHandlers) handleGetCABundle(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrCAServiceNotAvailable{})
		return
	}

	// Get optional store type and algorithm parameters
	storeTypeStr := r.URL.Query().Get("store_type")
	algorithmStr := r.URL.Query().Get("algorithm")

	storeType := xkmssdk.StoreUnknown
	if storeTypeStr != "" {
		storeType = xkmssdk.ParseStoreType(storeTypeStr)
	}

	var keyAlg x509.PublicKeyAlgorithm
	if algorithmStr != "" {
		var err error
		keyAlg, err = h.parseKeyAlgorithm(algorithmStr)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	// Get the CA bundle
	bundle, err := h.ca.CABundle(storeType, keyAlg)
	if err != nil {
		h.logger.Error("Failed to get CA bundle", "error", err)
		h.writeError(w, http.StatusInternalServerError, ErrCABundleFailed{Err: err})
		return
	}

	if len(bundle) == 0 {
		h.writeError(w, http.StatusNotFound, ErrCABundleNotFound{})
		return
	}

	// Parse bundle to get certificate summaries
	includeIntermediates := r.URL.Query().Get("include_intermediates") != "false"
	var certificates []CACertificateSummary
	certs, err := h.ca.ParseBundle(bundle)
	if err == nil {
		for _, cert := range certs {
			// Skip non-CA intermediates if not requested
			if !includeIntermediates && !cert.IsCA {
				continue
			}
			certificates = append(certificates, h.certToSummary(cert))
		}
	}

	// Support raw PEM downloads via Accept header for tooling that needs to
	// import the bundle into a trust store without unwrapping JSON. Default
	// remains JSON for backwards compatibility with existing SDK clients.
	if accept := r.Header.Get("Accept"); accept == "application/x-pem-file" || accept == "application/pem-certificate-chain" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename=\"ca-bundle.pem\"")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		// #nosec G705 -- not an HTML sink. The body is the CA's own PEM
		// bundle, served as application/x-pem-file with an attachment
		// disposition and nosniff, so no browser renders it as a document.
		// It is not request-derived: it comes from the CA, not the caller.
		if _, writeErr := w.Write(bundle); writeErr != nil {
			h.logger.Error("Failed to write CA bundle PEM", "error", writeErr)
		}
		return
	}

	resp := CABundleResponse{
		Bundle:       bundle,
		Certificates: certificates,
		CertCount:    len(certificates),
		Timestamp:    time.Now().Unix(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Helper Methods
// =============================================================================

// certMatchesIdentifier checks if a certificate matches an identifier string.
// The identifier can be a hex-encoded serial number or a Common Name (case-insensitive).
func (h *CAHandlers) certMatchesIdentifier(cert *x509.Certificate, identifier string) bool {
	if cert == nil || identifier == "" {
		return false
	}
	if hex.EncodeToString(cert.SerialNumber.Bytes()) == identifier {
		return true
	}
	if strings.EqualFold(cert.Subject.CommonName, identifier) {
		return true
	}
	return false
}

// findCertificateBySerial looks up a certificate by its serial number or Common Name.
// It checks root and intermediate CA certs first, then queries the certificate store
// by CN (which is how certificates are keyed in the store), and finally falls back
// to listing all certificates and matching by serial or CN.
func (h *CAHandlers) findCertificateBySerial(identifier string) *x509.Certificate {
	// Check if it matches root CA (by serial or CN)
	rootCert, err := h.ca.TrustedRoot()
	if err == nil && rootCert != nil {
		if h.certMatchesIdentifier(rootCert, identifier) {
			return rootCert
		}
	}

	// Check if it matches intermediate CA (by serial or CN)
	intermediateCert, err := h.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		if h.certMatchesIdentifier(intermediateCert, identifier) {
			return intermediateCert
		}
	}

	// Try to look up in cert store by CN (certificates are stored by CN)
	certStore := h.ca.CertificateStore()
	if certStore != nil {
		cert, err := certStore.GetCertificate(identifier)
		if err == nil && cert != nil {
			return cert
		}

		// Fall back to listing all and matching by serial or CN
		certs, err := certStore.ListCertificates()
		if err == nil {
			for _, cert := range certs {
				if h.certMatchesIdentifier(cert, identifier) {
					return cert
				}
			}
		}
	}

	return nil
}

// checkRevocationViaObjectStore checks if a certificate has been revoked by
// querying the QuicBaaS ObjectStorage directly. Revocation records are written
// by go-xkms CA at "revocations/<serial-decimal>.json".
func (h *CAHandlers) checkRevocationViaObjectStore(cert *x509.Certificate) bool {
	if h.objStorage == nil {
		return false
	}
	key := fmt.Sprintf("revocations/%s.json", cert.SerialNumber.Text(10))
	_, err := h.objStorage.GetObject(context.Background(), &objectstorage.GetObjectRequest{Key: key})
	return err == nil
}

// certToResponse converts an x509.Certificate to CACertificateResponse.
func (h *CAHandlers) certToResponse(cert *x509.Certificate, includePEM bool) *CACertificateResponse {
	if cert == nil {
		return nil
	}

	status := h.certStatusToString(cert)
	fingerprint := sha256.Sum256(cert.Raw)

	resp := &CACertificateResponse{
		Serial: hex.EncodeToString(cert.SerialNumber.Bytes()),
		Subject: CASubjectRequest{
			CommonName:         cert.Subject.CommonName,
			Organization:       h.firstOrEmpty(cert.Subject.Organization),
			OrganizationalUnit: h.firstOrEmpty(cert.Subject.OrganizationalUnit),
			Country:            h.firstOrEmpty(cert.Subject.Country),
			Province:           h.firstOrEmpty(cert.Subject.Province),
			Locality:           h.firstOrEmpty(cert.Subject.Locality),
			Address:            h.firstOrEmpty(cert.Subject.StreetAddress),
			PostalCode:         h.firstOrEmpty(cert.Subject.PostalCode),
		},
		Issuer:             cert.Issuer.CommonName,
		NotBefore:          cert.NotBefore.Unix(),
		NotAfter:           cert.NotAfter.Unix(),
		Status:             status,
		KeyAlgorithm:       h.keyAlgorithmToString(cert.PublicKeyAlgorithm),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
		MaxPathLen:         cert.MaxPathLen,
		KeyUsage:           h.keyUsageToStrings(cert.KeyUsage),
		ExtKeyUsage:        h.extKeyUsageToStrings(cert.ExtKeyUsage),
		FingerprintSHA256:  hex.EncodeToString(fingerprint[:]),
		DNSNames:           cert.DNSNames,
		EmailAddresses:     cert.EmailAddresses,
	}

	// Convert IP addresses to strings
	for _, ip := range cert.IPAddresses {
		resp.IPAddresses = append(resp.IPAddresses, ip.String())
	}

	// Convert URIs to strings
	for _, uri := range cert.URIs {
		resp.URIs = append(resp.URIs, uri.String())
	}

	if includePEM {
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		resp.PEM = string(pemBlock)
	}

	return resp
}

// certToProto converts a certificate to the protobuf shape the gRPC CA
// service and the proto-JSON CA webservice return, so the issue, sign-csr
// and get-certificate routes answer in the same shape on every server.
func (h *CAHandlers) certToProto(cert *x509.Certificate, includePEM, includeDER bool) *platformv1.Certificate {
	if cert == nil {
		return nil
	}

	fingerprint := sha256.Sum256(cert.Raw)

	out := &platformv1.Certificate{
		Serial: hex.EncodeToString(cert.SerialNumber.Bytes()),
		Subject: &platformv1.Subject{
			CommonName:         cert.Subject.CommonName,
			Organization:       h.firstOrEmpty(cert.Subject.Organization),
			OrganizationalUnit: h.firstOrEmpty(cert.Subject.OrganizationalUnit),
			Country:            h.firstOrEmpty(cert.Subject.Country),
			Province:           h.firstOrEmpty(cert.Subject.Province),
			Locality:           h.firstOrEmpty(cert.Subject.Locality),
			Address:            h.firstOrEmpty(cert.Subject.StreetAddress),
			PostalCode:         h.firstOrEmpty(cert.Subject.PostalCode),
		},
		Issuer:             cert.Issuer.CommonName,
		NotBefore:          timestamppb.New(cert.NotBefore),
		NotAfter:           timestamppb.New(cert.NotAfter),
		Status:             certStatusToProto(cert, time.Now()),
		KeyAlgorithm:       issuance.PublicKeyAlgorithm(cert.PublicKey),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCa:               cert.IsCA,
		MaxPathLen:         int32(cert.MaxPathLen),
		KeyUsage:           h.keyUsageToStrings(cert.KeyUsage),
		ExtKeyUsage:        h.extKeyUsageToStrings(cert.ExtKeyUsage),
		FingerprintSha256:  hex.EncodeToString(fingerprint[:]),
	}

	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 ||
		len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 {
		out.Sans = &platformv1.SubjectAlternativeNames{
			DnsNames:       cert.DNSNames,
			EmailAddresses: cert.EmailAddresses,
		}
		for _, ip := range cert.IPAddresses {
			out.Sans.IpAddresses = append(out.Sans.IpAddresses, ip.String())
		}
		for _, uri := range cert.URIs {
			out.Sans.Uris = append(out.Sans.Uris, uri.String())
		}
	}

	if includePEM && len(cert.Raw) > 0 {
		out.Pem = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
	}
	if includeDER {
		out.Der = cert.Raw
	}
	return out
}

// certStatusToProto reports a certificate's validity at now.
func certStatusToProto(cert *x509.Certificate, now time.Time) platformv1.CertificateStatus {
	if now.Before(cert.NotBefore) {
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING
	}
	if now.After(cert.NotAfter) {
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED
	}
	return platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID
}

// decodeProto reads a protojson request body into msg. An empty body
// leaves msg at its zero value. It writes a 400 and reports false when the
// body cannot be read or decoded.
func (h *CAHandlers) decodeProto(w http.ResponseWriter, r *http.Request, msg proto.Message) bool {
	return h.decodeProtoWith(caUnmarshalOptions, w, r, msg)
}

// decodeProtoWith is decodeProto with the given unmarshal options. A missing
// or empty body leaves msg at its zero value.
func (h *CAHandlers) decodeProtoWith(opts protojson.UnmarshalOptions, w http.ResponseWriter, r *http.Request, msg proto.Message) bool {
	if r.Body == nil {
		return true
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return false
	}
	if len(data) == 0 {
		return true
	}
	if err := opts.Unmarshal(data, msg); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return false
	}
	return true
}

// writeProto writes msg as protojson with the given HTTP status.
func (h *CAHandlers) writeProto(w http.ResponseWriter, statusCode int, msg proto.Message) {
	payload, err := caMarshalOptions.Marshal(msg)
	if err != nil {
		h.logger.Error("Failed to marshal CA response", "error", err)
		h.writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if _, err := w.Write(payload); err != nil {
		h.logger.Error("Failed to write CA response", "error", err)
	}
}

// certToSummary converts an x509.Certificate to CACertificateSummary.
func (h *CAHandlers) certToSummary(cert *x509.Certificate) CACertificateSummary {
	if cert == nil {
		return CACertificateSummary{}
	}

	return CACertificateSummary{
		Serial:       hex.EncodeToString(cert.SerialNumber.Bytes()),
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore.Unix(),
		NotAfter:     cert.NotAfter.Unix(),
		Status:       h.certStatusToString(cert),
		KeyAlgorithm: h.keyAlgorithmToString(cert.PublicKeyAlgorithm),
	}
}

// certStatusToString returns the status of a certificate as a string.
func (h *CAHandlers) certStatusToString(cert *x509.Certificate) string {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return "NOT_YET_VALID"
	} else if now.After(cert.NotAfter) {
		return "EXPIRED"
	}
	return "VALID"
}

// keyAlgorithmToString converts a key algorithm to string.
func (h *CAHandlers) keyAlgorithmToString(alg x509.PublicKeyAlgorithm) string {
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

// parseKeyAlgorithm parses a key algorithm string.
func (h *CAHandlers) parseKeyAlgorithm(s string) (x509.PublicKeyAlgorithm, error) {
	switch strings.ToUpper(s) {
	case "RSA", "RSA2048", "RSA-2048", "RSA3072", "RSA-3072", "RSA4096", "RSA-4096":
		return x509.RSA, nil
	case "ECDSA", "EC", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "P256", "P384", "P521":
		return x509.ECDSA, nil
	case "ED25519":
		return x509.Ed25519, nil
	case "":
		return x509.ECDSA, nil // Default
	default:
		return 0, ErrInvalidKeyAlgorithm{Algorithm: s}
	}
}

// parseKeyUsage parses key usage strings into x509.KeyUsage.
func (h *CAHandlers) parseKeyUsage(usages []string) x509.KeyUsage {
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

// parseExtKeyUsage parses extended key usage strings.
func (h *CAHandlers) parseExtKeyUsage(usages []string) []x509.ExtKeyUsage {
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

// keyUsageToStrings converts key usage to strings.
func (h *CAHandlers) keyUsageToStrings(usage x509.KeyUsage) []string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DIGITAL_SIGNATURE")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "CONTENT_COMMITMENT")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KEY_ENCIPHERMENT")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DATA_ENCIPHERMENT")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KEY_AGREEMENT")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CERT_SIGN")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL_SIGN")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "ENCIPHER_ONLY")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DECIPHER_ONLY")
	}
	return usages
}

// extKeyUsageToStrings converts extended key usage to strings.
func (h *CAHandlers) extKeyUsageToStrings(usages []x509.ExtKeyUsage) []string {
	var result []string
	for _, u := range usages {
		switch u {
		case x509.ExtKeyUsageAny:
			result = append(result, "ANY")
		case x509.ExtKeyUsageServerAuth:
			result = append(result, "SERVER_AUTH")
		case x509.ExtKeyUsageClientAuth:
			result = append(result, "CLIENT_AUTH")
		case x509.ExtKeyUsageCodeSigning:
			result = append(result, "CODE_SIGNING")
		case x509.ExtKeyUsageEmailProtection:
			result = append(result, "EMAIL_PROTECTION")
		case x509.ExtKeyUsageTimeStamping:
			result = append(result, "TIME_STAMPING")
		case x509.ExtKeyUsageOCSPSigning:
			result = append(result, "OCSP_SIGNING")
		}
	}
	return result
}

// firstOrEmpty returns the first element of a slice or empty string.
func (h *CAHandlers) firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// parseInt parses an integer with a default value.
func (h *CAHandlers) parseInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return val
}

// writeJSON writes a JSON response.
func (h *CAHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *CAHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, CAErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().Unix(),
	})
}
