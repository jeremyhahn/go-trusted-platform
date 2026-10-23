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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// IDevID/IAK REST Request/Response Types
// =============================================================================

// IDevIDGenerateRESTRequest represents an IDevID key generation request.
type IDevIDGenerateRESTRequest struct {
	Algorithm string `json:"algorithm"`
	Overwrite bool   `json:"overwrite"`
}

// IDevIDGenerateRESTResponse represents an IDevID key generation response.
type IDevIDGenerateRESTResponse struct {
	Handle       string `json:"handle"`
	Algorithm    string `json:"algorithm"`
	PublicKeyPEM string `json:"public_key_pem"`
	CreatedAt    int64  `json:"created_at"`
}

// IDevIDInfoRESTResponse represents an IDevID info response.
type IDevIDInfoRESTResponse struct {
	Handle       string `json:"handle,omitempty"`
	Algorithm    string `json:"algorithm,omitempty"`
	Exists       bool   `json:"exists"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	CreatedAt    int64  `json:"created_at,omitempty"`
}

// HasIDevIDRESTResponse represents a response for checking IDevID existence.
type HasIDevIDRESTResponse struct {
	Exists bool `json:"exists"`
}

// HasIAKRESTResponse represents a response for checking IAK existence.
type HasIAKRESTResponse struct {
	Exists bool `json:"exists"`
}

// IDevIDCertificateRESTInfo represents certificate info for REST responses.
type IDevIDCertificateRESTInfo struct {
	SubjectCN    string    `json:"subject_cn"`
	IssuerCN     string    `json:"issuer_cn"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Fingerprint  string    `json:"fingerprint"`
	PEM          string    `json:"pem,omitempty"`
}

// IDevIDCSRRESTRequest represents an IDevID CSR generation request.
type IDevIDCSRRESTRequest struct {
	CommonName         string   `json:"common_name"`
	Organization       string   `json:"organization"`
	OrganizationalUnit string   `json:"organizational_unit"`
	Country            string   `json:"country"`
	Province           string   `json:"province"`
	Locality           string   `json:"locality"`
	DNSNames           []string `json:"dns_names"`
	EmailAddresses     []string `json:"email_addresses"`
	IncludeTCGAttrs    bool     `json:"include_tcg_attrs"`
}

// IDevIDCSRRESTResponse represents an IDevID CSR generation response.
type IDevIDCSRRESTResponse struct {
	CSRPEM string `json:"csr_pem"`
}

// IDevIDInstallCertRESTRequest represents a certificate installation request.
type IDevIDInstallCertRESTRequest struct {
	CertificatePEM string `json:"certificate_pem"`
}

// IDevIDInstallCertRESTResponse represents a certificate installation response.
type IDevIDInstallCertRESTResponse struct {
	Installed bool   `json:"installed"`
	Message   string `json:"message,omitempty"`
}

// IDevIDGetCertRESTResponse represents a get certificate response.
type IDevIDGetCertRESTResponse struct {
	CertificatePEM string `json:"certificate_pem"`
	Subject        string `json:"subject"`
	Issuer         string `json:"issuer"`
	SerialNumber   string `json:"serial_number"`
	NotBefore      int64  `json:"not_before"`
	NotAfter       int64  `json:"not_after"`
}

// IDevIDDeleteCertRESTResponse represents an IDevID certificate deletion response.
type IDevIDDeleteCertRESTResponse struct {
	Deleted bool   `json:"deleted"`
	Message string `json:"message,omitempty"`
}

// IAKGenerateRESTRequest represents an IAK key generation request.
type IAKGenerateRESTRequest struct {
	Algorithm string `json:"algorithm"`
	Overwrite bool   `json:"overwrite"`
}

// IAKGenerateRESTResponse represents an IAK key generation response.
type IAKGenerateRESTResponse struct {
	Handle       string `json:"handle"`
	Algorithm    string `json:"algorithm"`
	PublicKeyPEM string `json:"public_key_pem"`
	CreatedAt    int64  `json:"created_at"`
}

// IAKInfoRESTResponse represents an IAK info response.
type IAKInfoRESTResponse struct {
	Handle       string `json:"handle,omitempty"`
	Algorithm    string `json:"algorithm,omitempty"`
	Exists       bool   `json:"exists"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	CreatedAt    int64  `json:"created_at,omitempty"`
}

// IAKCSRRESTRequest represents an IAK CSR generation request.
type IAKCSRRESTRequest struct {
	CommonName         string   `json:"common_name"`
	Organization       string   `json:"organization"`
	OrganizationalUnit string   `json:"organizational_unit"`
	Country            string   `json:"country"`
	Province           string   `json:"province"`
	Locality           string   `json:"locality"`
	DNSNames           []string `json:"dns_names"`
	EmailAddresses     []string `json:"email_addresses"`
	IncludeTCGAttrs    bool     `json:"include_tcg_attrs"`
}

// IAKCSRRESTResponse represents an IAK CSR generation response.
type IAKCSRRESTResponse struct {
	CSRPEM string `json:"csr_pem"`
}

// IAKInstallCertRESTRequest represents an IAK certificate installation request.
type IAKInstallCertRESTRequest struct {
	CertificatePEM string `json:"certificate_pem"`
}

// IAKInstallCertRESTResponse represents an IAK certificate installation response.
type IAKInstallCertRESTResponse struct {
	Installed bool   `json:"installed"`
	Message   string `json:"message,omitempty"`
}

// IAKGetCertRESTResponse represents an IAK get certificate response.
type IAKGetCertRESTResponse struct {
	CertificatePEM string `json:"certificate_pem"`
	Subject        string `json:"subject"`
	Issuer         string `json:"issuer"`
	SerialNumber   string `json:"serial_number"`
	NotBefore      int64  `json:"not_before"`
	NotAfter       int64  `json:"not_after"`
}

// IAKDeleteCertRESTResponse represents an IAK certificate deletion response.
type IAKDeleteCertRESTResponse struct {
	Deleted bool   `json:"deleted"`
	Message string `json:"message,omitempty"`
}

// DeviceAttributesRESTResponse represents a device attributes response.
type DeviceAttributesRESTResponse struct {
	TPMManufacturer      string `json:"tpm_manufacturer"`
	TPMModel             string `json:"tpm_model"`
	TPMVersion           string `json:"tpm_version"`
	PlatformManufacturer string `json:"platform_manufacturer"`
	PlatformModel        string `json:"platform_model"`
	PlatformVersion      string `json:"platform_version"`
	PlatformSerial       string `json:"platform_serial"`
}

// =============================================================================
// IDevID REST Route Registration
// =============================================================================

// registerIDevIDRoutes registers IDevID/IAK REST endpoints.
func (s *RESTServer) registerIDevIDRoutes(api *mux.Router) {
	// IDevID operations - paths match test adapter expectations
	api.HandleFunc("/tpm/idevid", s.handleIDevIDInfo).Methods(http.MethodGet)
	api.HandleFunc("/tpm/idevid/exists", s.handleHasIDevID).Methods(http.MethodGet)
	api.HandleFunc("/tpm/idevid/generate", s.handleIDevIDGenerate).Methods(http.MethodPost)
	api.HandleFunc("/tpm/idevid", s.handleIDevIDDelete).Methods(http.MethodDelete)
	api.HandleFunc("/tpm/idevid/csr", s.handleIDevIDCSR).Methods(http.MethodPost)
	api.HandleFunc("/tpm/idevid/cert", s.handleIDevIDGetCert).Methods(http.MethodGet)
	api.HandleFunc("/tpm/idevid/install", s.handleIDevIDInstallCert).Methods(http.MethodPost)
	api.HandleFunc("/tpm/idevid/cert", s.handleIDevIDDeleteCert).Methods(http.MethodDelete)

	// IAK operations - paths match test adapter expectations
	api.HandleFunc("/tpm/iak", s.handleIAKInfo).Methods(http.MethodGet)
	api.HandleFunc("/tpm/iak/exists", s.handleHasIAK).Methods(http.MethodGet)
	api.HandleFunc("/tpm/iak/generate", s.handleIAKGenerate).Methods(http.MethodPost)
	api.HandleFunc("/tpm/iak", s.handleIAKDelete).Methods(http.MethodDelete)
	api.HandleFunc("/tpm/iak/csr", s.handleIAKCSR).Methods(http.MethodPost)
	api.HandleFunc("/tpm/iak/cert", s.handleIAKGetCert).Methods(http.MethodGet)
	api.HandleFunc("/tpm/iak/install", s.handleIAKInstallCert).Methods(http.MethodPost)
	api.HandleFunc("/tpm/iak/cert", s.handleIAKDeleteCert).Methods(http.MethodDelete)

	// Device attributes. POST /tpm/activate-credential is the TPMService
	// route in pkg/api/rest/tpm_handlers.go.
	api.HandleFunc("/tpm/device/attributes", s.handleDeviceAttributes).Methods(http.MethodGet)

	s.logger.Info("IDevID/IAK REST routes registered")

	// LDevID (802.1AR) issuance route.
	s.registerLDevIDRoutes(api)
}

// =============================================================================
// IDevID REST Handlers
// =============================================================================

// handleIDevIDGenerate handles POST /api/v1/tpm/idevid/generate
func (s *RESTServer) handleIDevIDGenerate(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	var req IDevIDGenerateRESTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Get EK attributes for IAK creation (needed before IDevID)
	ekAttrs, err := s.tpm2Service.EKAttributes()
	if err != nil {
		s.logger.Error("Failed to get EK attributes", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "EKAttributes", Cause: err})
		return
	}

	// Create IAK first (required for IDevID creation)
	iakAttrs, err := s.tpm2Service.CreateIAK(ekAttrs, nil)
	if err != nil {
		s.logger.Error("Failed to create IAK", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "CreateIAK", Cause: err})
		return
	}

	// Create IDevID using IAK
	idevidAttrs, _, err := s.tpm2Service.CreateIDevID(iakAttrs, nil, nil)
	if err != nil {
		s.logger.Error("Failed to create IDevID", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "CreateIDevID", Cause: err})
		return
	}

	resp := &IDevIDGenerateRESTResponse{
		Handle:    fmt.Sprintf("0x%08X", idevidAttrs.TPMAttributes.Handle),
		Algorithm: normalizeKeyAlgorithm(req.Algorithm),
		CreatedAt: time.Now().Unix(),
	}

	s.logger.Info("IDevID key generated", "handle", idevidAttrs.TPMAttributes.Handle)
	s.writeJSON(w, http.StatusOK, resp)
}

// handleIDevIDInfo handles GET /api/v1/tpm/idevid
func (s *RESTServer) handleIDevIDInfo(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	attrs, err := s.tpm2Service.IDevIDAttributes()
	if err != nil {
		// Key doesn't exist
		resp := &IDevIDInfoRESTResponse{
			Exists: false,
		}
		s.writeJSON(w, http.StatusOK, resp)
		return
	}

	resp := &IDevIDInfoRESTResponse{
		Exists:    true,
		Handle:    fmt.Sprintf("0x%08X", attrs.TPMAttributes.Handle),
		Algorithm: "ECDSA-P256",
		CreatedAt: time.Now().Unix(),
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleHasIDevID handles GET /api/v1/tpm/idevid/exists
func (s *RESTServer) handleHasIDevID(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	_, err := s.tpm2Service.IDevIDAttributes()
	exists := err == nil

	resp := &HasIDevIDRESTResponse{
		Exists: exists,
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleIDevIDDelete handles DELETE /api/v1/tpm/idevid
func (s *RESTServer) handleIDevIDDelete(w http.ResponseWriter, r *http.Request) {
	// The persistent IDevID key is not evicted, so refuse as the gRPC
	// service does and touch nothing; the certificate has DELETE .../cert.
	refused := ErrDeviceIdentityKeyNotDeletable{Key: "IDevID"}
	s.writeError(w, idevidGRPCToHTTPStatus(refused), refused)
}

// handleIDevIDCSR handles POST /api/v1/tpm/idevid/csr
func (s *RESTServer) handleIDevIDCSR(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	var req IDevIDCSRRESTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Get IDevID attributes
	idevidAttrs, err := s.tpm2Service.IDevIDAttributes()
	if err != nil {
		s.logger.Error("Failed to get IDevID attributes", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "IDevIDAttributes", Cause: err})
		return
	}

	// Get IAK attributes for CSR creation
	iakAttrs, err := s.tpm2Service.IAKAttributes()
	if err != nil {
		s.logger.Error("Failed to get IAK attributes", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "IAKAttributes", Cause: err})
		return
	}

	// Create TCG CSR using TPM2
	tcgCSR, err := s.tpm2Service.CreateTCG_CSR_IDEVID(nil, iakAttrs, idevidAttrs)
	if err != nil {
		s.logger.Error("Failed to create TCG CSR", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "CreateTCG_CSR_IDEVID", Cause: err})
		return
	}

	csrBytes, err := tcgCSR.Marshal()
	if err != nil {
		s.logger.Error("Failed to marshal TCG CSR", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "MarshalCSR", Cause: err})
		return
	}

	resp := &IDevIDCSRRESTResponse{
		CSRPEM: base64.StdEncoding.EncodeToString(csrBytes),
	}

	s.logger.Info("IDevID CSR generated")
	s.writeJSON(w, http.StatusOK, resp)
}

// handleIDevIDInstallCert handles POST /api/v1/tpm/idevid/install
func (s *RESTServer) handleIDevIDInstallCert(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	var req IDevIDInstallCertRESTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.CertificatePEM == "" {
		s.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "certificate_pem"})
		return
	}

	// Parse PEM certificate
	block, _ := pem.Decode([]byte(req.CertificatePEM))
	if block == nil {
		s.writeError(w, http.StatusBadRequest, ErrInvalidCertificatePEM{})
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: "invalid certificate: " + err.Error()})
		return
	}

	if err := s.tpm2Service.ProvisionIDevIDCert(cert); err != nil {
		s.logger.Error("Failed to install IDevID certificate", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "ProvisionIDevIDCert", Cause: err})
		return
	}

	resp := &IDevIDInstallCertRESTResponse{
		Installed: true,
		Message:   "IDevID certificate installed successfully",
	}

	s.logger.Info("IDevID certificate installed")
	s.writeJSON(w, http.StatusOK, resp)
}

// handleIDevIDGetCert handles GET /api/v1/tpm/idevid/cert
func (s *RESTServer) handleIDevIDGetCert(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	cert, err := s.tpm2Service.IDevIDCertificate()
	if err != nil {
		s.logger.Error("Failed to get IDevID certificate", "error", err)
		s.writeError(w, http.StatusNotFound, ErrIDevIDCertificateNotFound{})
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	resp := &IDevIDGetCertRESTResponse{
		CertificatePEM: string(certPEM),
		Subject:        cert.Subject.CommonName,
		Issuer:         cert.Issuer.CommonName,
		SerialNumber:   cert.SerialNumber.String(),
		NotBefore:      cert.NotBefore.Unix(),
		NotAfter:       cert.NotAfter.Unix(),
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleIDevIDDeleteCert handles DELETE /api/v1/tpm/idevid/cert
func (s *RESTServer) handleIDevIDDeleteCert(w http.ResponseWriter, r *http.Request) {
	// Delegate to the shared IDevID service so the delete answers in the
	// classes gRPC, QUIC and MCP answer in.
	if s.idevidService == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrIDevIDServiceNotConfigured{})
		return
	}

	if _, err := s.idevidService.DeleteIDevIDCertificate(r.Context(), &platformv1.DeleteIDevIDCertificateRequest{}); err != nil {
		s.logger.Error("Failed to delete IDevID certificate", "error", err)
		s.writeError(w, idevidGRPCToHTTPStatus(err), err)
		return
	}

	resp := &IDevIDDeleteCertRESTResponse{
		Deleted: true,
		Message: "IDevID certificate deleted successfully",
	}

	s.logger.Info("IDevID certificate deleted")
	s.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// IAK REST Handlers
// =============================================================================

// handleIAKGenerate handles POST /api/v1/tpm/iak/generate
func (s *RESTServer) handleIAKGenerate(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	var req IAKGenerateRESTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Get EK attributes
	ekAttrs, err := s.tpm2Service.EKAttributes()
	if err != nil {
		s.logger.Error("Failed to get EK attributes", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "EKAttributes", Cause: err})
		return
	}

	// Create IAK
	iakAttrs, err := s.tpm2Service.CreateIAK(ekAttrs, nil)
	if err != nil {
		s.logger.Error("Failed to create IAK", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "CreateIAK", Cause: err})
		return
	}

	resp := &IAKGenerateRESTResponse{
		Handle:    fmt.Sprintf("0x%08X", iakAttrs.TPMAttributes.Handle),
		Algorithm: normalizeKeyAlgorithm(req.Algorithm),
		CreatedAt: time.Now().Unix(),
	}

	s.logger.Info("IAK key generated", "handle", iakAttrs.TPMAttributes.Handle)
	s.writeJSON(w, http.StatusOK, resp)
}

// handleIAKInfo handles GET /api/v1/tpm/iak
func (s *RESTServer) handleIAKInfo(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	attrs, err := s.tpm2Service.IAKAttributes()
	if err != nil {
		// Key doesn't exist
		resp := &IAKInfoRESTResponse{
			Exists: false,
		}
		s.writeJSON(w, http.StatusOK, resp)
		return
	}

	resp := &IAKInfoRESTResponse{
		Exists:    true,
		Handle:    fmt.Sprintf("0x%08X", attrs.TPMAttributes.Handle),
		Algorithm: "ECDSA-P256",
		CreatedAt: time.Now().Unix(),
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleHasIAK handles GET /api/v1/tpm/iak/exists
func (s *RESTServer) handleHasIAK(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	_, err := s.tpm2Service.IAKAttributes()
	exists := err == nil

	resp := &HasIAKRESTResponse{
		Exists: exists,
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleIAKDelete handles DELETE /api/v1/tpm/iak
func (s *RESTServer) handleIAKDelete(w http.ResponseWriter, r *http.Request) {
	// The persistent IAK is not evicted, so refuse as the gRPC service does
	// and touch nothing; the certificate has DELETE .../cert.
	refused := ErrDeviceIdentityKeyNotDeletable{Key: "IAK"}
	s.writeError(w, idevidGRPCToHTTPStatus(refused), refused)
}

// handleIAKCSR handles POST /api/v1/tpm/iak/csr
func (s *RESTServer) handleIAKCSR(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	var req IAKCSRRESTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Get IAK attributes
	iakAttrs, err := s.tpm2Service.IAKAttributes()
	if err != nil {
		s.logger.Error("Failed to get IAK attributes", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "IAKAttributes", Cause: err})
		return
	}

	// Create TCG CSR for IAK
	tcgCSR, err := s.tpm2Service.CreateTCG_CSR_IDEVID(nil, iakAttrs, iakAttrs)
	if err != nil {
		s.logger.Error("Failed to create TCG CSR for IAK", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "CreateTCG_CSR_IDEVID", Cause: err})
		return
	}

	csrBytes, err := tcgCSR.Marshal()
	if err != nil {
		s.logger.Error("Failed to marshal TCG CSR", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "MarshalCSR", Cause: err})
		return
	}

	resp := &IAKCSRRESTResponse{
		CSRPEM: base64.StdEncoding.EncodeToString(csrBytes),
	}

	s.logger.Info("IAK CSR generated")
	s.writeJSON(w, http.StatusOK, resp)
}

// handleIAKInstallCert handles POST /api/v1/tpm/iak/install
func (s *RESTServer) handleIAKInstallCert(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	var req IAKInstallCertRESTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.CertificatePEM == "" {
		s.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "certificate_pem"})
		return
	}

	// Parse PEM certificate
	block, _ := pem.Decode([]byte(req.CertificatePEM))
	if block == nil {
		s.writeError(w, http.StatusBadRequest, ErrInvalidCertificatePEM{})
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: "invalid certificate: " + err.Error()})
		return
	}

	if err := s.tpm2Service.ProvisionIAKCert(cert); err != nil {
		s.logger.Error("Failed to install IAK certificate", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrTPM2OperationFailed{Operation: "ProvisionIAKCert", Cause: err})
		return
	}

	resp := &IAKInstallCertRESTResponse{
		Installed: true,
		Message:   "IAK certificate installed successfully",
	}

	s.logger.Info("IAK certificate installed")
	s.writeJSON(w, http.StatusOK, resp)
}

// handleIAKGetCert handles GET /api/v1/tpm/iak/cert
func (s *RESTServer) handleIAKGetCert(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	cert, err := s.tpm2Service.IAKCertificate()
	if err != nil {
		s.logger.Error("Failed to get IAK certificate", "error", err)
		s.writeError(w, http.StatusNotFound, ErrIAKCertificateNotFound{})
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	resp := &IAKGetCertRESTResponse{
		CertificatePEM: string(certPEM),
		Subject:        cert.Subject.CommonName,
		Issuer:         cert.Issuer.CommonName,
		SerialNumber:   cert.SerialNumber.String(),
		NotBefore:      cert.NotBefore.Unix(),
		NotAfter:       cert.NotAfter.Unix(),
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleIAKDeleteCert handles DELETE /api/v1/tpm/iak/cert
func (s *RESTServer) handleIAKDeleteCert(w http.ResponseWriter, r *http.Request) {
	// Delegate to the shared IDevID service so the delete answers in the
	// classes gRPC, QUIC and MCP answer in.
	if s.idevidService == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrIDevIDServiceNotConfigured{})
		return
	}

	if _, err := s.idevidService.DeleteIAKCertificate(r.Context(), &platformv1.DeleteIAKCertificateRequest{}); err != nil {
		s.logger.Error("Failed to delete IAK certificate", "error", err)
		s.writeError(w, idevidGRPCToHTTPStatus(err), err)
		return
	}

	resp := &IAKDeleteCertRESTResponse{
		Deleted: true,
		Message: "IAK certificate deleted successfully",
	}

	s.logger.Info("IAK certificate deleted")
	s.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Device Attributes and Credential Activation REST Handlers
// =============================================================================

// handleDeviceAttributes handles GET /api/v1/tpm/device/attributes
func (s *RESTServer) handleDeviceAttributes(w http.ResponseWriter, r *http.Request) {
	if s.tpm2Service == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrTPM2ServiceNotAvailable{})
		return
	}

	// Use go-xkms's platform discovery
	platformAttrs := xkmssdk.DiscoverPlatformAttributes()

	// Get TPM properties
	var tpmManufacturer, tpmModel, tpmVersion string
	props, err := s.tpm2Service.FixedProperties()
	if err == nil && props != nil {
		tpmManufacturer = props.Manufacturer
		tpmModel = props.Family
		tpmVersion = fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor)
	}

	resp := &DeviceAttributesRESTResponse{
		TPMManufacturer:      tpmManufacturer,
		TPMModel:             tpmModel,
		TPMVersion:           tpmVersion,
		PlatformManufacturer: platformAttrs.Manufacturer,
		PlatformModel:        platformAttrs.Model,
		PlatformVersion:      platformAttrs.Version,
		PlatformSerial:       platformAttrs.Serial,
	}

	s.writeJSON(w, http.StatusOK, resp)
}
