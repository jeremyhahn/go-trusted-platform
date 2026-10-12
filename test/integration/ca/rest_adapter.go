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

//go:build integration

package ca

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// =============================================================================
// REST Protocol Adapter Constants
// =============================================================================

const (
	// DefaultRESTTimeout is the default timeout for REST HTTP requests.
	DefaultRESTTimeout = 30 * time.Second
)

// =============================================================================
// REST Error Types
// =============================================================================

// ErrRESTRequestFailed indicates an HTTP request failure.
type ErrRESTRequestFailed struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
	Err        error
}

func (e ErrRESTRequestFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("REST %s %s failed: %v", e.Method, e.Path, e.Err)
	}
	return fmt.Sprintf("REST %s %s failed (status %d): %s", e.Method, e.Path, e.StatusCode, e.Body)
}

func (e ErrRESTRequestFailed) Unwrap() error {
	return e.Err
}

// ErrRESTResponseParseFailed indicates a response parsing failure.
type ErrRESTResponseParseFailed struct {
	Operation string
	Err       error
}

func (e ErrRESTResponseParseFailed) Error() string {
	return fmt.Sprintf("REST response parse failed for %s: %v", e.Operation, e.Err)
}

func (e ErrRESTResponseParseFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// REST API Response Types (matching pkg/api/rest/ca_handlers.go)
// =============================================================================

type restCAInfoResponse struct {
	CommonName       string                     `json:"common_name"`
	IsInitialized    bool                       `json:"is_initialized"`
	IsIntermediate   bool                       `json:"is_intermediate"`
	RootCert         *restCACertificateSummary  `json:"root_cert,omitempty"`
	Intermediates    []restCACertificateSummary `json:"intermediates,omitempty"`
	DefaultAlgorithm string                     `json:"default_algorithm,omitempty"`
	DefaultValidity  int                        `json:"default_validity_days,omitempty"`
	Timestamp        int64                      `json:"timestamp"`
}

type restCACertificateSummary struct {
	Serial       string `json:"serial"`
	CommonName   string `json:"common_name"`
	Issuer       string `json:"issuer"`
	NotBefore    int64  `json:"not_before"`
	NotAfter     int64  `json:"not_after"`
	Status       string `json:"status"`
	KeyAlgorithm string `json:"key_algorithm"`
}

type restCASubjectRequest struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
	Province           string `json:"province,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Address            string `json:"address,omitempty"`
	PostalCode         string `json:"postal_code,omitempty"`
}

type restCASANsRequest struct {
	DNS   []string `json:"dns,omitempty"`
	IPs   []string `json:"ips,omitempty"`
	Email []string `json:"email,omitempty"`
	URIs  []string `json:"uris,omitempty"`
}

type restCertificateIssueRequest struct {
	Subject      restCASubjectRequest `json:"subject"`
	SANs         *restCASANsRequest   `json:"sans,omitempty"`
	ValidDays    int                  `json:"valid_days,omitempty"`
	KeyAlgorithm string               `json:"key_algorithm,omitempty"`
	StoreType    string               `json:"store_type,omitempty"`
	KeyUsage     []string             `json:"key_usage,omitempty"`
	ExtKeyUsage  []string             `json:"ext_key_usage,omitempty"`
	IsCA         bool                 `json:"is_ca,omitempty"`
	MaxPathLen   int                  `json:"max_path_len,omitempty"`
}

type restCACertificateResponse struct {
	Serial             string               `json:"serial"`
	Subject            restCASubjectRequest `json:"subject"`
	Issuer             string               `json:"issuer"`
	NotBefore          int64                `json:"not_before"`
	NotAfter           int64                `json:"not_after"`
	Status             string               `json:"status"`
	KeyAlgorithm       string               `json:"key_algorithm"`
	SignatureAlgorithm string               `json:"signature_algorithm"`
	IsCA               bool                 `json:"is_ca"`
	MaxPathLen         int                  `json:"max_path_len,omitempty"`
	KeyUsage           []string             `json:"key_usage,omitempty"`
	ExtKeyUsage        []string             `json:"ext_key_usage,omitempty"`
	FingerprintSHA256  string               `json:"fingerprint_sha256,omitempty"`
	DNSNames           []string             `json:"dns_names,omitempty"`
	IPAddresses        []string             `json:"ip_addresses,omitempty"`
	EmailAddresses     []string             `json:"email_addresses,omitempty"`
	URIs               []string             `json:"uris,omitempty"`
	PEM                string               `json:"pem,omitempty"`
}

type restCAIssueCertificateResponse struct {
	Success     bool                       `json:"success"`
	Message     string                     `json:"message"`
	Certificate *restCACertificateResponse `json:"certificate,omitempty"`
	Timestamp   int64                      `json:"timestamp"`
}

type restCAGetCertificateResponse struct {
	Certificate *restCACertificateResponse `json:"certificate"`
	Timestamp   int64                      `json:"timestamp"`
}

type restCACertificateListResponse struct {
	Certificates []restCACertificateSummary `json:"certificates"`
	Page         int                        `json:"page"`
	PageSize     int                        `json:"page_size"`
	TotalItems   int                        `json:"total_items"`
	TotalPages   int                        `json:"total_pages"`
	Timestamp    int64                      `json:"timestamp"`
}

type restCertificateVerifyRequest struct {
	CertificatePEM   string `json:"certificate_pem,omitempty"`
	VerifyExpiration bool   `json:"verify_expiration,omitempty"`
	VerifyRevocation bool   `json:"verify_revocation,omitempty"`
}

type restCAVerifyCertificateResponse struct {
	Success   bool     `json:"success"`
	Message   string   `json:"message"`
	Valid     bool     `json:"valid"`
	Revoked   bool     `json:"revoked"`
	Chain     []string `json:"chain,omitempty"`
	Errors    []string `json:"errors,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Timestamp int64    `json:"timestamp"`
}

type restCertificateRevokeRequest struct {
	Reason     int  `json:"reason,omitempty"`
	DeleteKeys bool `json:"delete_keys,omitempty"`
}

type restCARevokeCertificateResponse struct {
	Serial    string `json:"serial"`
	Status    string `json:"status"`
	RevokedAt int64  `json:"revoked_at"`
	Reason    int    `json:"reason"`
	Timestamp int64  `json:"timestamp"`
}

type restCertificateRenewRequest struct {
	ValidDays    int                `json:"valid_days"`
	PreserveSANs bool               `json:"preserve_sans,omitempty"`
	NewSANs      *restCASANsRequest `json:"new_sans,omitempty"`
}

type restCARenewCertificateResponse struct {
	Success        bool                       `json:"success"`
	Message        string                     `json:"message"`
	OldCertificate *restCACertificateResponse `json:"old_certificate,omitempty"`
	NewCertificate *restCACertificateResponse `json:"new_certificate,omitempty"`
	Timestamp      int64                      `json:"timestamp"`
}

type restCARevokedCertEntry struct {
	Serial         string `json:"serial"`
	RevocationTime int64  `json:"revocation_time"`
	Reason         int    `json:"reason"`
}

type restCACRLResponse struct {
	CRL          []byte                   `json:"crl"`
	LastUpdate   int64                    `json:"last_update"`
	NextUpdate   int64                    `json:"next_update"`
	RevokedCount int                      `json:"revoked_count"`
	RevokedCerts []restCARevokedCertEntry `json:"revoked_certs,omitempty"`
	Timestamp    int64                    `json:"timestamp"`
}

type restCABundleResponse struct {
	Bundle       []byte                     `json:"bundle"`
	Certificates []restCACertificateSummary `json:"certificates,omitempty"`
	CertCount    int                        `json:"cert_count"`
	Timestamp    int64                      `json:"timestamp"`
}

type restCAErrorResponse struct {
	Error     string `json:"error"`
	Code      int    `json:"code"`
	Timestamp int64  `json:"timestamp"`
}

// =============================================================================
// REST Protocol Adapter
// =============================================================================

// RESTAdapter implements CACommands using REST API calls to platformd.
type RESTAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewRESTAdapter creates a new REST protocol adapter instance.
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup initializes the REST adapter and verifies connectivity.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformRESTEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformREST
	}
	r.baseURL = endpoint

	r.httpClient = &http.Client{
		Timeout: DefaultRESTTimeout,
		Transport: &http.Transport{
			TLSClientConfig: helpers.TLSConfigOrInsecure(),
		},
	}

	// Verify connectivity with the CA info endpoint
	_, err := r.Info(ctx)
	if err != nil {
		return ErrConnectionFailed{Protocol: "REST", Endpoint: r.baseURL, Err: err}
	}

	return nil
}

// Teardown performs cleanup.
func (r *RESTAdapter) Teardown() error {
	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
	return nil
}

// =============================================================================
// HTTP Request Helpers
// =============================================================================

// doGet sends an HTTP GET request and decodes the JSON response.
func (r *RESTAdapter) doGet(ctx context.Context, path string, result interface{}) error {
	reqURL := r.baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return ErrRESTRequestFailed{Method: "GET", Path: path, Err: err}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return ErrRESTRequestFailed{Method: "GET", Path: path, Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrRESTRequestFailed{Method: "GET", Path: path, StatusCode: resp.StatusCode, Err: err}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrRESTRequestFailed{
			Method:     "GET",
			Path:       path,
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}

	if result != nil {
		if err := json.Unmarshal(body, result); err != nil {
			return ErrRESTResponseParseFailed{Operation: "GET " + path, Err: err}
		}
	}

	return nil
}

// doPost sends an HTTP POST request with a JSON body and decodes the response.
func (r *RESTAdapter) doPost(ctx context.Context, path string, reqBody interface{}, result interface{}) error {
	reqURL := r.baseURL + path

	var bodyReader io.Reader
	if reqBody != nil {
		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			return ErrRESTRequestFailed{Method: "POST", Path: path, Err: err}
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bodyReader)
	if err != nil {
		return ErrRESTRequestFailed{Method: "POST", Path: path, Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return ErrRESTRequestFailed{Method: "POST", Path: path, Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrRESTRequestFailed{Method: "POST", Path: path, StatusCode: resp.StatusCode, Err: err}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrRESTRequestFailed{
			Method:     "POST",
			Path:       path,
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}

	if result != nil {
		if err := json.Unmarshal(body, result); err != nil {
			return ErrRESTResponseParseFailed{Operation: "POST " + path, Err: err}
		}
	}

	return nil
}

// =============================================================================
// CA Info Operations
// =============================================================================

// Info retrieves CA information via REST.
func (r *RESTAdapter) Info(ctx context.Context) (*InfoResult, error) {
	var resp restCAInfoResponse
	if err := r.doGet(ctx, "/api/v1/ca/info", &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GetCAInfo", Err: err}
	}

	result := &InfoResult{
		CommonName:          resp.CommonName,
		IsInitialized:       resp.IsInitialized,
		IsIntermediate:      resp.IsIntermediate,
		DefaultAlgorithm:    resp.DefaultAlgorithm,
		DefaultValidityDays: int32(resp.DefaultValidity),
	}

	if resp.RootCert != nil {
		result.RootCertificate = convertRESTCertSummary(resp.RootCert)
	}

	for i := range resp.Intermediates {
		result.Intermediates = append(result.Intermediates, *convertRESTCertSummary(&resp.Intermediates[i]))
	}

	return result, nil
}

// =============================================================================
// CA Init Operations
// =============================================================================

// Init initializes the CA via REST.
// Note: CA initialization is done during daemon startup, not exposed via REST.
func (r *RESTAdapter) Init(ctx context.Context, opts InitOptions) (*InitResult, error) {
	return nil, surface.ErrNoSurface{Transport: "REST", Operation: "CA init"}
}

// =============================================================================
// Certificate Issue Operations
// =============================================================================

// IssueCertificate issues a new certificate via REST.
func (r *RESTAdapter) IssueCertificate(ctx context.Context, opts IssueCertificateOptions) (*IssueCertificateResult, error) {
	reqBody := restCertificateIssueRequest{
		Subject: restCASubjectRequest{
			CommonName: opts.CommonName,
		},
		ValidDays:    int(opts.ValidDays),
		KeyAlgorithm: opts.Algorithm,
		StoreType:    opts.StoreType,
		KeyUsage:     opts.KeyUsage,
		ExtKeyUsage:  opts.ExtKeyUsage,
		IsCA:         opts.IsCA,
		MaxPathLen:   int(opts.MaxPathLen),
	}

	if len(opts.SANsDNS) > 0 || len(opts.SANsIPs) > 0 || len(opts.SANsEmail) > 0 {
		reqBody.SANs = &restCASANsRequest{
			DNS:   opts.SANsDNS,
			IPs:   opts.SANsIPs,
			Email: opts.SANsEmail,
		}
	}

	var resp restCAIssueCertificateResponse
	if err := r.doPost(ctx, "/api/v1/ca/certificates", reqBody, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "IssueCertificate", Err: err}
	}

	result := &IssueCertificateResult{
		Success: resp.Success,
	}

	if resp.Certificate != nil {
		result.Certificate = convertRESTCertificate(resp.Certificate)
	}

	return result, nil
}

// =============================================================================
// Certificate Get Operations
// =============================================================================

// GetCertificate retrieves a certificate via REST.
// When only CommonName is provided (Serial empty), the CN is used as the path
// identifier because the server's findCertificateBySerial accepts both serial
// numbers and common names.
func (r *RESTAdapter) GetCertificate(ctx context.Context, opts GetCertificateOptions) (*GetCertificateResult, error) {
	identifier := opts.Serial
	if identifier == "" {
		identifier = opts.CommonName
	}
	if identifier == "" {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GetCertificate", Err: ErrInvalidSerial{Serial: "<empty>"}}
	}

	path := fmt.Sprintf("/api/v1/ca/certificates/%s", url.PathEscape(identifier))
	if opts.IncludePEM {
		path += "?include_pem=true"
	}

	var resp restCAGetCertificateResponse
	if err := r.doGet(ctx, path, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GetCertificate", Err: err}
	}

	result := &GetCertificateResult{}
	if resp.Certificate != nil {
		result.Certificate = convertRESTCertificate(resp.Certificate)
	}

	return result, nil
}

// =============================================================================
// Certificate List Operations
// =============================================================================

// ListCertificates lists certificates via REST.
func (r *RESTAdapter) ListCertificates(ctx context.Context, opts ListCertificatesOptions) (*ListCertificatesResult, error) {
	path := "/api/v1/ca/certificates"

	params := url.Values{}
	if opts.Limit > 0 {
		params.Set("page_size", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Offset > 0 && opts.Limit > 0 {
		page := (opts.Offset / opts.Limit) + 1
		params.Set("page", fmt.Sprintf("%d", page))
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var resp restCACertificateListResponse
	if err := r.doGet(ctx, path, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "ListCertificates", Err: err}
	}

	result := &ListCertificatesResult{
		Certificates: make([]CertificateSummary, 0, len(resp.Certificates)),
		Total:        int32(resp.TotalItems),
	}

	for i := range resp.Certificates {
		result.Certificates = append(result.Certificates, *convertRESTCertSummary(&resp.Certificates[i]))
	}

	return result, nil
}

// =============================================================================
// Certificate Verify Operations
// =============================================================================

// VerifyCertificate verifies a certificate via REST.
func (r *RESTAdapter) VerifyCertificate(ctx context.Context, opts VerifyCertificateOptions) (*VerifyCertificateResult, error) {
	reqBody := restCertificateVerifyRequest{
		CertificatePEM:   string(opts.CertificatePEM),
		VerifyExpiration: opts.CheckExpiration,
		VerifyRevocation: opts.CheckCRL,
	}

	var resp restCAVerifyCertificateResponse
	if err := r.doPost(ctx, "/api/v1/ca/certificates/verify", reqBody, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "VerifyCertificate", Err: err}
	}

	result := &VerifyCertificateResult{
		Revoked:       resp.Revoked,
		Valid:         resp.Valid,
		ChainValid:    resp.Valid && len(resp.Errors) == 0,
		ChainLength:   len(resp.Chain),
		ChainSubjects: resp.Chain,
		Errors:        resp.Errors,
		Warnings:      resp.Warnings,
	}

	if !resp.Success {
		result.ValidationError = resp.Message
	}

	return result, nil
}

// =============================================================================
// Certificate Revoke Operations
// =============================================================================

// RevokeCertificate revokes a certificate via REST.
func (r *RESTAdapter) RevokeCertificate(ctx context.Context, opts RevokeCertificateOptions) (*RevokeCertificateResult, error) {
	path := fmt.Sprintf("/api/v1/ca/certificates/%s/revoke", url.PathEscape(opts.Serial))

	reqBody := restCertificateRevokeRequest{
		Reason:     int(opts.Reason),
		DeleteKeys: opts.DeleteKeys,
	}

	var resp restCARevokeCertificateResponse
	if err := r.doPost(ctx, path, reqBody, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "RevokeCertificate", Err: err}
	}

	result := &RevokeCertificateResult{
		Success:   true,
		Serial:    resp.Serial,
		Status:    CertificateStatusRevoked,
		RevokedAt: time.Unix(resp.RevokedAt, 0),
		Reason:    RevocationReason(resp.Reason),
	}

	return result, nil
}

// =============================================================================
// Certificate Renew Operations
// =============================================================================

// RenewCertificate renews a certificate via REST.
func (r *RESTAdapter) RenewCertificate(ctx context.Context, opts RenewCertificateOptions) (*RenewCertificateResult, error) {
	path := fmt.Sprintf("/api/v1/ca/certificates/%s/renew", url.PathEscape(opts.Serial))

	reqBody := restCertificateRenewRequest{
		ValidDays:    int(opts.ValidDays),
		PreserveSANs: opts.PreserveSANs,
	}

	if len(opts.NewSANsDNS) > 0 || len(opts.NewSANsIPs) > 0 || len(opts.NewSANsEmail) > 0 {
		reqBody.NewSANs = &restCASANsRequest{
			DNS:   opts.NewSANsDNS,
			IPs:   opts.NewSANsIPs,
			Email: opts.NewSANsEmail,
		}
	}

	var resp restCARenewCertificateResponse
	if err := r.doPost(ctx, path, reqBody, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "RenewCertificate", Err: err}
	}

	result := &RenewCertificateResult{
		Success: resp.Success,
		Message: resp.Message,
	}

	if resp.OldCertificate != nil {
		result.OldCertificate = convertRESTCertificate(resp.OldCertificate)
	}

	if resp.NewCertificate != nil {
		result.NewCertificate = convertRESTCertificate(resp.NewCertificate)
	}

	return result, nil
}

// =============================================================================
// CRL Operations
// =============================================================================

// GetCRL retrieves the CRL via REST.
func (r *RESTAdapter) GetCRL(ctx context.Context, opts GetCRLOptions) (*GetCRLResult, error) {
	path := "/api/v1/ca/crl"
	if opts.IncludeEntries {
		path += "?include_entries=true"
	}

	var resp restCACRLResponse
	if err := r.doGet(ctx, path, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GetCRL", Err: err}
	}

	result := &GetCRLResult{
		Data:         resp.CRL,
		RevokedCount: int32(resp.RevokedCount),
		ThisUpdate:   time.Unix(resp.LastUpdate, 0),
		NextUpdate:   time.Unix(resp.NextUpdate, 0),
	}

	for _, entry := range resp.RevokedCerts {
		result.RevokedCerts = append(result.RevokedCerts, RevokedCertEntry{
			Serial:         entry.Serial,
			RevocationTime: time.Unix(entry.RevocationTime, 0),
			Reason:         RevocationReason(entry.Reason),
		})
	}

	return result, nil
}

// GenerateCRL generates a new CRL via REST.
func (r *RESTAdapter) GenerateCRL(ctx context.Context) (*GenerateCRLResult, error) {
	var resp restCACRLResponse
	if err := r.doGet(ctx, "/api/v1/ca/crl", &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GenerateCRL", Err: err}
	}

	result := &GenerateCRLResult{
		Success:    true,
		ThisUpdate: time.Unix(resp.LastUpdate, 0),
		NextUpdate: time.Unix(resp.NextUpdate, 0),
	}

	return result, nil
}

// ExportCRL exports the CRL via REST.
// Note: CRL export to file is a CLI operation, not exposed via REST.
func (r *RESTAdapter) ExportCRL(ctx context.Context, output string) (*ExportCRLResult, error) {
	return nil, surface.ErrNoSurface{Transport: "REST", Operation: "CRL export"}
}

// =============================================================================
// Export Bundle Operations
// =============================================================================

// ExportBundle exports the CA bundle via REST.
func (r *RESTAdapter) ExportBundle(ctx context.Context, output string) (*ExportBundleResult, error) {
	var resp restCABundleResponse
	if err := r.doGet(ctx, "/api/v1/ca/bundle", &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GetCABundle", Err: err}
	}

	result := &ExportBundleResult{
		Success:   len(resp.Bundle) > 0,
		CertCount: int32(resp.CertCount),
		Size:      int64(len(resp.Bundle)),
	}

	if output != "" {
		if err := os.WriteFile(output, resp.Bundle, 0644); err != nil {
			return nil, ErrExportFailed{Type: "CA bundle", Path: output, Reason: err.Error()}
		}
		result.FilePath = output
	}

	return result, nil
}

// =============================================================================
// Install/Uninstall Operations
// =============================================================================

// InstallCACertificates installs CA certificates via REST.
// Note: CA certificate installation is a local OS operation, not exposed via REST.
func (r *RESTAdapter) InstallCACertificates(ctx context.Context) (*InstallCACertificatesResult, error) {
	return nil, surface.ErrNoSurface{Transport: "REST", Operation: "install CA certificates"}
}

// UninstallCACertificates uninstalls CA certificates via REST.
// Note: CA certificate uninstallation is a local OS operation, not exposed via REST.
func (r *RESTAdapter) UninstallCACertificates(ctx context.Context) (*UninstallCACertificatesResult, error) {
	return nil, surface.ErrNoSurface{Transport: "REST", Operation: "uninstall CA certificates"}
}

// =============================================================================
// Conversion Helpers
// =============================================================================

// convertRESTCertSummary converts a REST certificate summary to the adapter type.
func convertRESTCertSummary(s *restCACertificateSummary) *CertificateSummary {
	if s == nil {
		return nil
	}
	return &CertificateSummary{
		Serial:       s.Serial,
		CommonName:   s.CommonName,
		Issuer:       s.Issuer,
		NotBefore:    time.Unix(s.NotBefore, 0),
		NotAfter:     time.Unix(s.NotAfter, 0),
		Status:       restStatusToCertStatus(s.Status),
		KeyAlgorithm: s.KeyAlgorithm,
	}
}

// convertRESTCertificate converts a REST certificate response to the adapter type.
func convertRESTCertificate(c *restCACertificateResponse) *Certificate {
	if c == nil {
		return nil
	}
	return &Certificate{
		Serial: c.Serial,
		Subject: Subject{
			CommonName:         c.Subject.CommonName,
			Organization:       c.Subject.Organization,
			OrganizationalUnit: c.Subject.OrganizationalUnit,
			Country:            c.Subject.Country,
			Province:           c.Subject.Province,
			Locality:           c.Subject.Locality,
			Address:            c.Subject.Address,
			PostalCode:         c.Subject.PostalCode,
		},
		Issuer:             c.Issuer,
		NotBefore:          time.Unix(c.NotBefore, 0),
		NotAfter:           time.Unix(c.NotAfter, 0),
		Status:             restStatusToCertStatus(c.Status),
		KeyAlgorithm:       c.KeyAlgorithm,
		SignatureAlgorithm: c.SignatureAlgorithm,
		IsCA:               c.IsCA,
		MaxPathLen:         int32(c.MaxPathLen),
		KeyUsage:           c.KeyUsage,
		ExtKeyUsage:        c.ExtKeyUsage,
		FingerprintSHA256:  c.FingerprintSHA256,
		SANsDNS:            c.DNSNames,
		SANsIPs:            c.IPAddresses,
		SANsEmail:          c.EmailAddresses,
		SANsURIs:           c.URIs,
		PEM:                []byte(c.PEM),
	}
}

// restStatusToCertStatus converts a REST status string to CertificateStatus.
func restStatusToCertStatus(status string) CertificateStatus {
	statusMap := map[string]CertificateStatus{
		"VALID":         CertificateStatusValid,
		"REVOKED":       CertificateStatusRevoked,
		"EXPIRED":       CertificateStatusExpired,
		"NOT_YET_VALID": CertificateStatusPending,
		"PENDING":       CertificateStatusPending,
	}
	if s, ok := statusMap[status]; ok {
		return s
	}
	return CertificateStatusUnspecified
}

// Ensure RESTAdapter implements CACommands interface.
var _ CACommands = (*RESTAdapter)(nil)
