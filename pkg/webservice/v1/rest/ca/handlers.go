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

package ca

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	goca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

const (
	defaultLimit  int32 = 50
	maxLimit      int32 = 1000
	defaultCursor       = ""

	// contentTypePEM is the MIME type for PEM certificate chains.
	contentTypePEM = "application/pem-certificate-chain"
)

// CAHandlers provides REST handlers for CA operations
type CAHandlers struct {
	logger     *logging.Logger
	ca         goca.CACertificateAuthority
	respWriter response.HttpWriter
}

// NewCAHandlers creates a new CAHandlers instance
func NewCAHandlers(
	logger *logging.Logger,
	ca goca.CACertificateAuthority,
	respWriter response.HttpWriter,
) *CAHandlers {
	return &CAHandlers{
		logger:     logger,
		ca:         ca,
		respWriter: respWriter,
	}
}

// Helper methods

func (h *CAHandlers) getSerial(r *http.Request) string {
	return mux.Vars(r)["serial"]
}

func (h *CAHandlers) getPaginationParams(r *http.Request) (int32, string) {
	limit := defaultLimit
	cursor := defaultCursor

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.ParseInt(l, 10, 32); err == nil {
			limit = int32(parsed)
			if limit > maxLimit {
				limit = maxLimit
			}
			if limit < 1 {
				limit = defaultLimit
			}
		}
	}

	if c := r.URL.Query().Get("cursor"); c != "" {
		cursor = c
	}

	return limit, cursor
}

func (h *CAHandlers) decodeJSON(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// Algorithm conversion helpers

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

func (h *CAHandlers) signatureAlgorithmToString(alg x509.SignatureAlgorithm) string {
	return alg.String()
}

func (h *CAHandlers) parseStoreType(s string) xkmssdk.StoreType {
	return xkmssdk.ParseStoreType(s)
}

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

// Response conversion helpers

func (h *CAHandlers) certToResponse(cert *x509.Certificate) *CertificateResponse {
	if cert == nil {
		return nil
	}

	status := "VALID"
	now := time.Now()
	if now.Before(cert.NotBefore) {
		status = "NOT_YET_VALID"
	} else if now.After(cert.NotAfter) {
		status = "EXPIRED"
	}

	return &CertificateResponse{
		Serial: hex.EncodeToString(cert.SerialNumber.Bytes()),
		Subject: SubjectRequest{
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
		Status:             status,
		KeyAlgorithm:       h.keyAlgorithmToString(cert.PublicKeyAlgorithm),
		SignatureAlgorithm: h.signatureAlgorithmToString(cert.SignatureAlgorithm),
		IsCA:               cert.IsCA,
	}
}

func (h *CAHandlers) certToSummary(cert *x509.Certificate) CertificateSummary {
	if cert == nil {
		return CertificateSummary{}
	}

	status := "VALID"
	now := time.Now()
	if now.Before(cert.NotBefore) {
		status = "NOT_YET_VALID"
	} else if now.After(cert.NotAfter) {
		status = "EXPIRED"
	}

	return CertificateSummary{
		Serial:       hex.EncodeToString(cert.SerialNumber.Bytes()),
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore.Unix(),
		NotAfter:     cert.NotAfter.Unix(),
		Status:       status,
		KeyAlgorithm: h.keyAlgorithmToString(cert.PublicKeyAlgorithm),
	}
}

func (h *CAHandlers) certToPEM(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return string(pemBlock)
}

func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// =============================================================================
// CA Information Handlers
// =============================================================================

// GetInfo handles GET /api/v1/ca/info
func (h *CAHandlers) GetInfo(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.respWriter.Error500(w, r, ErrCANotInitialized{})
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

	h.respWriter.Success200(w, r, resp)
}

// =============================================================================
// Certificate Management Handlers
// =============================================================================

// ListCertificates handles GET /api/v1/ca/certificates
func (h *CAHandlers) ListCertificates(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.respWriter.Error500(w, r, ErrCANotInitialized{})
		return
	}

	limit, cursor := h.getPaginationParams(r)

	// The CA interface uses CertificateStore() for certificate listing
	certStore := h.ca.CertificateStore()
	if certStore == nil {
		h.respWriter.Error500(w, r, ErrCANotInitialized{})
		return
	}

	// For now, we return the CA certificates (root and intermediate)
	// In a full implementation, this would query the certificate store
	var certificates []CertificateSummary

	rootCert, err := h.ca.TrustedRoot()
	if err == nil && rootCert != nil {
		certificates = append(certificates, h.certToSummary(rootCert))
	}

	intermediateCert, err := h.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		certificates = append(certificates, h.certToSummary(intermediateCert))
	}

	// Apply pagination (simplified)
	_ = cursor
	total := int32(len(certificates))
	if int32(len(certificates)) > limit {
		certificates = certificates[:limit]
	}

	h.respWriter.Success200(w, r, CertificateListResponse{
		PaginatedResponse: PaginatedResponse{
			TotalCount: total,
			HasMore:    total > limit,
		},
		Certificates: certificates,
		Timestamp:    time.Now().Unix(),
	})
}

// GetCertificate handles GET /api/v1/ca/certificates/{serial}
func (h *CAHandlers) GetCertificate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.respWriter.Error500(w, r, ErrCANotInitialized{})
		return
	}

	serial := h.getSerial(r)
	if serial == "" {
		h.respWriter.Error400(w, r, ErrInvalidSerialNumber{Serial: "", Reason: "serial number is required"})
		return
	}

	// Get optional parameters
	includePEM := r.URL.Query().Get("include_pem") == "true"

	// Look up certificate by serial number
	// First check if it matches root or intermediate CA
	rootCert, err := h.ca.TrustedRoot()
	if err == nil && rootCert != nil {
		if hex.EncodeToString(rootCert.SerialNumber.Bytes()) == serial {
			resp := h.certToResponse(rootCert)
			if includePEM {
				resp.PEM = h.certToPEM(rootCert)
			}
			h.respWriter.Success200(w, r, GetCertificateResponse{
				Certificate: resp,
				Timestamp:   time.Now().Unix(),
			})
			return
		}
	}

	intermediateCert, err := h.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		if hex.EncodeToString(intermediateCert.SerialNumber.Bytes()) == serial {
			resp := h.certToResponse(intermediateCert)
			if includePEM {
				resp.PEM = h.certToPEM(intermediateCert)
			}
			h.respWriter.Success200(w, r, GetCertificateResponse{
				Certificate: resp,
				Timestamp:   time.Now().Unix(),
			})
			return
		}
	}

	// Try to look up by common name in cert store
	// The serial might be used as a lookup key
	certStore := h.ca.CertificateStore()
	if certStore != nil {
		cert, err := certStore.GetCertificate(serial)
		if err == nil && cert != nil {
			resp := h.certToResponse(cert)
			if includePEM {
				resp.PEM = h.certToPEM(cert)
			}
			h.respWriter.Success200(w, r, GetCertificateResponse{
				Certificate: resp,
				Timestamp:   time.Now().Unix(),
			})
			return
		}
	}

	h.respWriter.Error404(w, r, ErrCertificateNotFound{Serial: serial})
}

// IssueCertificate handles POST /api/v1/ca/certificates
func (h *CAHandlers) IssueCertificate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.respWriter.Error500(w, r, ErrCANotInitialized{})
		return
	}

	var req CertificateIssueRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Subject.CommonName == "" {
		h.respWriter.Error400(w, r, ErrMissingCommonName{})
		return
	}

	// Parse key algorithm
	keyAlg, err := h.parseKeyAlgorithm(req.KeyAlgorithm)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}

	// Build certificate request
	caReq := &goca.CACertificateRequest{
		Subject: goca.CASubject{
			CommonName:         req.Subject.CommonName,
			Organization:       req.Subject.Organization,
			OrganizationalUnit: req.Subject.OrganizationalUnit,
			Country:            req.Subject.Country,
			Province:           req.Subject.Province,
			Locality:           req.Subject.Locality,
			Address:            req.Subject.Address,
			PostalCode:         req.Subject.PostalCode,
		},
		Valid:       req.ValidDays,
		IsCA:        req.IsCA,
		MaxPathLen:  req.MaxPathLen,
		KeyUsage:    h.parseKeyUsage(req.KeyUsage),
		ExtKeyUsage: h.parseExtKeyUsage(req.ExtKeyUsage),
	}

	// Add SANs if provided
	if req.SANs != nil {
		caReq.SANS = &goca.CASubjectAlternativeNames{
			DNS:   req.SANs.DNS,
			IPs:   req.SANs.IPs,
			Email: req.SANs.Email,
			URIs:  req.SANs.URIs,
		}
	}

	// Set key attributes
	storeType := h.parseStoreType(req.StoreType)
	if storeType == xkmssdk.StoreUnknown {
		storeType = xkmssdk.StoreSoftware // Default to software store
	}

	caReq.KeyAttributes = &xkmssdk.KeyAttributes{
		CN:           req.Subject.CommonName,
		KeyAlgorithm: keyAlg,
		StoreType:    storeType,
		KeyType:      xkmssdk.KeyTypeTLS,
	}

	// Issue the certificate
	cert, err := h.ca.IssueCertificate(caReq)
	if err != nil {
		h.respWriter.Error500(w, r, ErrInvalidCertificateRequest{Reason: err.Error()})
		return
	}

	// Build response
	resp := h.certToResponse(cert)
	resp.PEM = h.certToPEM(cert)

	h.respWriter.Success201(w, r, IssueCertificateResponse{
		Certificate: resp,
		Timestamp:   time.Now().Unix(),
	})
}

// RevokeCertificate handles DELETE /api/v1/ca/certificates/{serial}
func (h *CAHandlers) RevokeCertificate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.respWriter.Error500(w, r, ErrCANotInitialized{})
		return
	}

	serial := h.getSerial(r)
	if serial == "" {
		h.respWriter.Error400(w, r, ErrInvalidSerialNumber{Serial: "", Reason: "serial number is required"})
		return
	}

	// Parse optional request body
	var req CertificateRevokeRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := h.decodeJSON(r, &req); err != nil {
			h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	// Find the certificate first
	var cert *x509.Certificate
	var keyAttrs *xkmssdk.KeyAttributes

	// Check if serial matches any known certificate
	certStore := h.ca.CertificateStore()
	if certStore != nil {
		foundCert, err := certStore.GetCertificate(serial)
		if err == nil && foundCert != nil {
			cert = foundCert
		}
	}

	if cert == nil {
		h.respWriter.Error404(w, r, ErrCertificateNotFound{Serial: serial})
		return
	}

	// Set up key attributes for deletion if requested
	if req.DeleteKeys {
		keyAttrs = &xkmssdk.KeyAttributes{
			CN: cert.Subject.CommonName,
		}
	}

	// Revoke the certificate
	if err := h.ca.Revoke(cert, keyAttrs); err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, RevokeCertificateResponse{
		Serial:    serial,
		Status:    "REVOKED",
		RevokedAt: time.Now().Unix(),
		Reason:    req.Reason,
		Timestamp: time.Now().Unix(),
	})
}

// =============================================================================
// CA Bundle Handlers
// =============================================================================

// GetBundle handles GET /api/v1/ca/bundle
func (h *CAHandlers) GetBundle(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.respWriter.Error500(w, r, ErrCANotInitialized{})
		return
	}

	// Get optional store type and algorithm parameters
	storeTypeStr := r.URL.Query().Get("store_type")
	algorithmStr := r.URL.Query().Get("algorithm")

	storeType := xkmssdk.StoreUnknown
	if storeTypeStr != "" {
		storeType = h.parseStoreType(storeTypeStr)
	}

	var keyAlg x509.PublicKeyAlgorithm
	if algorithmStr != "" {
		var err error
		keyAlg, err = h.parseKeyAlgorithm(algorithmStr)
		if err != nil {
			h.respWriter.Error400(w, r, err)
			return
		}
	}

	// Get the CA bundle
	bundle, err := h.ca.CABundle(storeType, keyAlg)
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}

	if len(bundle) == 0 {
		h.respWriter.Error404(w, r, ErrBundleNotFound{})
		return
	}

	// Parse bundle to get certificate summaries
	var certificates []CertificateSummary
	certs, err := h.ca.ParseBundle(bundle)
	if err == nil {
		for _, cert := range certs {
			certificates = append(certificates, h.certToSummary(cert))
		}
	}

	h.respWriter.Success200(w, r, BundleResponse{
		Bundle:       bundle,
		Certificates: certificates,
		CertCount:    len(certificates),
		Timestamp:    time.Now().Unix(),
	})
}

// =============================================================================
// Bootstrap Handlers
// =============================================================================

// GetBootstrapBundle handles GET /api/v1/ca/bootstrap. It returns the CA
// certificate bundle as raw PEM text for unauthenticated trust bootstrapping.
// Optional query parameters store_type and algorithm filter the bundle.
func (h *CAHandlers) GetBootstrapBundle(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		http.Error(w, ErrCANotInitialized{}.Error(), http.StatusServiceUnavailable)
		return
	}

	// Get optional store type and algorithm parameters
	storeTypeStr := r.URL.Query().Get("store_type")
	algorithmStr := r.URL.Query().Get("algorithm")

	storeType := xkmssdk.StoreUnknown
	if storeTypeStr != "" {
		storeType = h.parseStoreType(storeTypeStr)
	}

	var keyAlg x509.PublicKeyAlgorithm
	if algorithmStr != "" {
		var err error
		keyAlg, err = h.parseKeyAlgorithm(algorithmStr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Get the CA bundle
	bundle, err := h.ca.CABundle(storeType, keyAlg)
	if err != nil {
		http.Error(w, ErrBootstrapBundleFailed{Cause: err}.Error(), http.StatusInternalServerError)
		return
	}

	if len(bundle) == 0 {
		http.Error(w, ErrBundleNotFound{}.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", contentTypePEM)
	w.WriteHeader(http.StatusOK)
	w.Write(bundle) // #nosec G705 -- PEM certificate data, not HTML; Content-Type prevents browser rendering
}

// =============================================================================
// CRL Handlers
// =============================================================================

// GetCRL handles GET /api/v1/ca/crl
func (h *CAHandlers) GetCRL(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.respWriter.Error500(w, r, ErrCANotInitialized{})
		return
	}

	// The CA interface does not directly expose GenerateCRL, but we can access
	// the underlying CA if it implements the method
	type crlGenerator interface {
		GenerateCRL() ([]byte, error)
	}

	var crlDER []byte
	var err error

	if gen, ok := h.ca.(crlGenerator); ok {
		crlDER, err = gen.GenerateCRL()
		if err != nil {
			h.respWriter.Error500(w, r, ErrCRLGenerationFailed{Reason: err.Error()})
			return
		}
	} else {
		// If GenerateCRL is not available, try to access the object store
		objStore := h.ca.ObjectStore()
		if objStore == nil {
			h.respWriter.Error500(w, r, ErrCRLNotFound{})
			return
		}
		// In a full implementation, we would retrieve the CRL from storage
		h.respWriter.Error500(w, r, ErrCRLNotFound{})
		return
	}

	// Parse the CRL to get metadata
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		h.respWriter.Error500(w, r, ErrCRLGenerationFailed{Reason: err.Error()})
		return
	}

	// Build revoked certificates list
	var revokedCerts []RevokedCertEntry
	for _, entry := range crl.RevokedCertificateEntries {
		revokedCerts = append(revokedCerts, RevokedCertEntry{
			Serial:         hex.EncodeToString(entry.SerialNumber.Bytes()),
			RevocationTime: entry.RevocationTime.Unix(),
			Reason:         entry.ReasonCode,
		})
	}

	h.respWriter.Success200(w, r, CRLResponse{
		CRL:          crlDER,
		LastUpdate:   crl.ThisUpdate.Unix(),
		NextUpdate:   crl.NextUpdate.Unix(),
		RevokedCount: len(crl.RevokedCertificateEntries),
		RevokedCerts: revokedCerts,
		Timestamp:    time.Now().Unix(),
	})
}
