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

package rest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock CA Service
// =============================================================================

type mockCAService struct {
	identity           string
	initialized        bool
	defaultKeyAlg      x509.PublicKeyAlgorithm
	defaultValidity    time.Duration
	rootCert           *x509.Certificate
	intermediateCert   *x509.Certificate
	certStore          *mockCertStore
	issuedCerts        map[string]*x509.Certificate
	issueErr           error
	revokeErr          error
	bundleErr          error
	parseErr           error
	bundle             []byte
	generateCRLSupport bool
	crlData            []byte
	crlErr             error
}

func newMockCAService() *mockCAService {
	// Generate self-signed certificates for testing
	// Note: For test purposes we create self-signed certs - we don't need a valid chain
	rootCert := generateTestCertificate("Test Root CA", true, nil, nil)
	intermediateCert := generateTestCertificate("Test Intermediate CA", true, nil, nil)

	// Create the cert store with the root cert pre-populated
	store := newMockCertStore()
	if rootCert != nil {
		store.certs[hex.EncodeToString(rootCert.SerialNumber.Bytes())] = rootCert
	}

	return &mockCAService{
		identity:         "Test CA",
		initialized:      true,
		defaultKeyAlg:    x509.ECDSA,
		defaultValidity:  365 * 24 * time.Hour,
		rootCert:         rootCert,
		intermediateCert: intermediateCert,
		certStore:        store,
		issuedCerts:      make(map[string]*x509.Certificate),
	}
}

func (m *mockCAService) Identity() string {
	return m.identity
}

func (m *mockCAService) IsInitialized() bool {
	return m.initialized
}

func (m *mockCAService) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm {
	return m.defaultKeyAlg
}

func (m *mockCAService) DefaultValidityPeriod() time.Duration {
	return m.defaultValidity
}

func (m *mockCAService) TrustedRoot() (*x509.Certificate, error) {
	return m.rootCert, nil
}

func (m *mockCAService) TrustedIntermediate() (*x509.Certificate, error) {
	return m.intermediateCert, nil
}

func (m *mockCAService) IssueCertificate(_ context.Context, req *quicbaasca.CACertificateRequest) (*x509.Certificate, error) {
	if m.issueErr != nil {
		return nil, m.issueErr
	}
	cert := generateTestCertificate(req.Subject.CommonName, req.IsCA, nil, req)
	if cert == nil {
		return nil, errors.New("failed to generate certificate")
	}
	m.issuedCerts[hex.EncodeToString(cert.SerialNumber.Bytes())] = cert
	m.certStore.certs[hex.EncodeToString(cert.SerialNumber.Bytes())] = cert
	return cert, nil
}

func (m *mockCAService) Revoke(_ context.Context, cert *x509.Certificate, keyAttrs *xkmssdk.KeyAttributes) error {
	if m.revokeErr != nil {
		return m.revokeErr
	}
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	delete(m.issuedCerts, serial)
	delete(m.certStore.certs, serial)
	return nil
}

func (m *mockCAService) CertificateStore() xkmssdk.CertStore {
	return m.certStore
}

func (m *mockCAService) CABundle(storeType xkmssdk.StoreType, keyAlg x509.PublicKeyAlgorithm) ([]byte, error) {
	if m.bundleErr != nil {
		return nil, m.bundleErr
	}
	if m.bundle != nil {
		return m.bundle, nil
	}
	// Generate default bundle
	var bundlePEM bytes.Buffer
	if m.intermediateCert != nil {
		bundlePEM.Write(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: m.intermediateCert.Raw,
		}))
	}
	if m.rootCert != nil {
		bundlePEM.Write(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: m.rootCert.Raw,
		}))
	}
	return bundlePEM.Bytes(), nil
}

func (m *mockCAService) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
	if m.parseErr != nil {
		return nil, m.parseErr
	}
	var certs []*x509.Certificate
	remaining := bundle
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certs = append(certs, cert)
		}
		remaining = rest
	}
	return certs, nil
}

func (m *mockCAService) GenerateCRL(_ context.Context) ([]byte, error) {
	if !m.generateCRLSupport {
		return nil, errors.New("CRL generation not supported")
	}
	if m.crlErr != nil {
		return nil, m.crlErr
	}
	if m.crlData != nil {
		return m.crlData, nil
	}
	return generateTestCRL(m.intermediateCert)
}

// =============================================================================
// Mock Certificate Store
// =============================================================================

type mockCertStore struct {
	certs   map[string]*x509.Certificate
	listErr error
	getErr  error
}

func newMockCertStore() *mockCertStore {
	return &mockCertStore{
		certs: make(map[string]*x509.Certificate),
	}
}

func (m *mockCertStore) ListCertificates() ([]*x509.Certificate, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	certs := make([]*x509.Certificate, 0, len(m.certs))
	for _, cert := range m.certs {
		certs = append(certs, cert)
	}
	return certs, nil
}

func (m *mockCertStore) GetCertificate(cn string) (*x509.Certificate, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	cert, ok := m.certs[cn]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return cert, nil
}

// Implement remaining xkmssdk.CertStore interface methods as no-ops
func (m *mockCertStore) StoreCertificate(cert *x509.Certificate) error { return nil }
func (m *mockCertStore) DeleteCertificate(cn string) error             { return nil }
func (m *mockCertStore) StoreCertificateChain(chain []*x509.Certificate) error {
	return nil
}
func (m *mockCertStore) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCertStore) StoreCRL(crl *x509.RevocationList) error { return nil }
func (m *mockCertStore) GetCRL(issuer string) (*x509.RevocationList, error) {
	return nil, nil
}
func (m *mockCertStore) VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error {
	return nil
}
func (m *mockCertStore) IsRevoked(cert *x509.Certificate) (bool, error) {
	return false, nil
}
func (m *mockCertStore) Close() error { return nil }

// =============================================================================
// Test Helpers
// =============================================================================

// generateTestCertificate creates a self-signed test certificate.
// The parent parameter is kept for API compatibility but is ignored - all test
// certificates are self-signed to avoid key management complexity in tests.
func generateTestCertificate(cn string, isCA bool, parent *x509.Certificate, req *quicbaasca.CACertificateRequest) *x509.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		PublicKeyAlgorithm:    x509.ECDSA,
	}

	if req != nil {
		if req.Subject.Organization != "" {
			template.Subject.Organization = []string{req.Subject.Organization}
		}
		if req.Valid > 0 {
			template.NotAfter = time.Now().Add(time.Duration(req.Valid) * 24 * time.Hour)
		}
		if req.SANS != nil {
			template.DNSNames = req.SANS.DNS
			template.EmailAddresses = req.SANS.Email
		}
	}

	// Always self-sign for test purposes - we don't need a valid chain
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil
	}

	return cert
}

func generateTestCRL(issuer *x509.Certificate) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	crl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	// For CRL signing, we need the issuer's private key, but we don't have it.
	// Use the newly generated key with a self-signed issuer for test purposes.
	if issuer == nil {
		issuer = &x509.Certificate{
			Subject: pkix.Name{CommonName: "Test CRL Issuer"},
		}
	}

	// Create a temporary self-signed cert to use as issuer for CRL
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               issuer.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	selfSignedIssuer, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return x509.CreateRevocationList(rand.Reader, crl, selfSignedIssuer, priv)
}

func setupCAHandlers(ca CAServiceInterface) (*CAHandlers, *mux.Router) {
	logger := slog.Default()
	handlers := NewCAHandlers(ca, logger, nil)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return handlers, router
}

// =============================================================================
// Tests: CA Info
// =============================================================================

func TestCAHandlers_GetCAInfo_Success(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CAInfoResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.True(t, resp.IsInitialized)
	assert.Equal(t, "Test CA", resp.CommonName)
	assert.Equal(t, "ECDSA", resp.DefaultAlgorithm)
	assert.Equal(t, 365, resp.DefaultValidity)
	assert.NotNil(t, resp.RootCert)
	assert.True(t, resp.IsIntermediate)
	assert.NotEmpty(t, resp.Intermediates)
}

func TestCAHandlers_GetCAInfo_CANotAvailable(t *testing.T) {
	_, router := setupCAHandlers(nil)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

	var resp CAErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "not available")
}

func TestCAHandlers_GetCAInfo_NotInitialized(t *testing.T) {
	ca := newMockCAService()
	ca.initialized = false
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CAInfoResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.IsInitialized)
	assert.Empty(t, resp.CommonName)
}

// =============================================================================
// Tests: Issue Certificate
// =============================================================================

func TestCAHandlers_IssueCertificate_Success(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	reqBody := CertificateIssueRequest{
		Subject: CASubjectRequest{
			CommonName:   "test.example.com",
			Organization: "Test Org",
		},
		ValidDays:    90,
		KeyAlgorithm: "ECDSA",
		SANs: &CASANsRequest{
			DNS: []string{"test.example.com", "www.test.example.com"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp CAIssueCertificateResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.True(t, resp.Success)
	assert.Equal(t, "certificate issued successfully", resp.Message)
	assert.NotNil(t, resp.Certificate)
	assert.Equal(t, "test.example.com", resp.Certificate.Subject.CommonName)
	assert.NotEmpty(t, resp.Certificate.PEM)
}

func TestCAHandlers_IssueCertificate_MissingCommonName(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	reqBody := CertificateIssueRequest{
		Subject: CASubjectRequest{
			Organization: "Test Org",
		},
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var resp CAErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "common name")
}

func TestCAHandlers_IssueCertificate_InvalidKeyAlgorithm(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	reqBody := CertificateIssueRequest{
		Subject: CASubjectRequest{
			CommonName: "test.example.com",
		},
		KeyAlgorithm: "INVALID_ALG",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var resp CAErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "invalid key algorithm")
}

func TestCAHandlers_IssueCertificate_InvalidRequestBody(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCAHandlers_IssueCertificate_IssueFailed(t *testing.T) {
	ca := newMockCAService()
	ca.issueErr = errors.New("issuance failed")
	_, router := setupCAHandlers(ca)

	reqBody := CertificateIssueRequest{
		Subject: CASubjectRequest{
			CommonName: "test.example.com",
		},
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestCAHandlers_IssueCertificate_CANotAvailable(t *testing.T) {
	_, router := setupCAHandlers(nil)

	reqBody := CertificateIssueRequest{
		Subject: CASubjectRequest{
			CommonName: "test.example.com",
		},
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// =============================================================================
// Tests: List Certificates
// =============================================================================

func TestCAHandlers_ListCertificates_Success(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/certificates", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CACertificateListResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	// At least the root cert should be in the store
	assert.GreaterOrEqual(t, len(resp.Certificates), 1)
	assert.Equal(t, 1, resp.Page)
	assert.Equal(t, 50, resp.PageSize)
}

func TestCAHandlers_ListCertificates_WithPagination(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/certificates?page=1&page_size=10", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CACertificateListResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, 1, resp.Page)
	assert.Equal(t, 10, resp.PageSize)
}

func TestCAHandlers_ListCertificates_MaxPageSize(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/certificates?page_size=5000", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CACertificateListResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, int(caMaxPageSize), resp.PageSize)
}

func TestCAHandlers_ListCertificates_CANotAvailable(t *testing.T) {
	_, router := setupCAHandlers(nil)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/certificates", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// =============================================================================
// Tests: Get Certificate
// =============================================================================

func TestCAHandlers_GetCertificate_RootCert(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	serial := hex.EncodeToString(ca.rootCert.SerialNumber.Bytes())
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/certificates/"+serial, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CAGetCertificateResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.Certificate)
	assert.Equal(t, serial, resp.Certificate.Serial)
}

func TestCAHandlers_GetCertificate_WithPEM(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	serial := hex.EncodeToString(ca.rootCert.SerialNumber.Bytes())
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/certificates/"+serial+"?include_pem=true", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CAGetCertificateResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Certificate.PEM)
	assert.Contains(t, resp.Certificate.PEM, "BEGIN CERTIFICATE")
}

func TestCAHandlers_GetCertificate_NotFound(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/certificates/nonexistent", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestCAHandlers_GetCertificate_EmptySerial(t *testing.T) {
	ca := newMockCAService()

	// Test the handler directly
	handlers := NewCAHandlers(ca, nil, nil)
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/certificates/", nil)
	req = mux.SetURLVars(req, map[string]string{"serial": ""})
	rr := httptest.NewRecorder()

	handlers.handleGetCertificate(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCAHandlers_GetCertificate_CANotAvailable(t *testing.T) {
	_, router := setupCAHandlers(nil)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/certificates/someserial", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// =============================================================================
// Tests: Revoke Certificate
// =============================================================================

func TestCAHandlers_RevokeCertificate_Success(t *testing.T) {
	ca := newMockCAService()
	// Issue a certificate first
	cert := generateTestCertificate("revoke.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert

	_, router := setupCAHandlers(ca)

	reqBody := CertificateRevokeRequest{
		Reason: 1, // Key compromise
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/"+serial+"/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CARevokeCertificateResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, serial, resp.Serial)
	assert.Equal(t, "REVOKED", resp.Status)
	assert.Equal(t, 1, resp.Reason)
}

func TestCAHandlers_RevokeCertificate_WithDeleteKeys(t *testing.T) {
	ca := newMockCAService()
	cert := generateTestCertificate("revoke.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert

	_, router := setupCAHandlers(ca)

	reqBody := CertificateRevokeRequest{
		DeleteKeys: true,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/"+serial+"/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestCAHandlers_RevokeCertificate_NotFound(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/nonexistent/revoke", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestCAHandlers_RevokeCertificate_RevokeFailed(t *testing.T) {
	ca := newMockCAService()
	ca.revokeErr = errors.New("revocation failed")

	cert := generateTestCertificate("revoke.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert

	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/"+serial+"/revoke", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestCAHandlers_RevokeCertificate_InvalidBody(t *testing.T) {
	ca := newMockCAService()
	cert := generateTestCertificate("revoke.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert

	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/"+serial+"/revoke", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// =============================================================================
// Tests: Renew Certificate
// =============================================================================

func TestCAHandlers_RenewCertificate_Success(t *testing.T) {
	ca := newMockCAService()
	cert := generateTestCertificate("renew.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert

	_, router := setupCAHandlers(ca)

	reqBody := CertificateRenewRequest{
		ValidDays: 180,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/"+serial+"/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CARenewCertificateResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.True(t, resp.Success)
	assert.NotNil(t, resp.OldCertificate)
	assert.NotNil(t, resp.NewCertificate)
	assert.NotEqual(t, resp.OldCertificate.Serial, resp.NewCertificate.Serial)
}

func TestCAHandlers_RenewCertificate_PreserveSANs(t *testing.T) {
	ca := newMockCAService()
	cert := generateTestCertificate("renew.test.com", false, nil, &quicbaasca.CACertificateRequest{
		Subject: quicbaasca.CASubject{CommonName: "renew.test.com"},
		SANS:    &quicbaasca.CASubjectAlternativeNames{DNS: []string{"www.renew.test.com"}},
	})
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert

	_, router := setupCAHandlers(ca)

	reqBody := CertificateRenewRequest{
		ValidDays:    180,
		PreserveSANs: true,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/"+serial+"/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestCAHandlers_RenewCertificate_NewSANs(t *testing.T) {
	ca := newMockCAService()
	cert := generateTestCertificate("renew.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert

	_, router := setupCAHandlers(ca)

	reqBody := CertificateRenewRequest{
		ValidDays: 180,
		NewSANs: &CASANsRequest{
			DNS: []string{"new.renew.test.com"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/"+serial+"/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestCAHandlers_RenewCertificate_InvalidValidDays(t *testing.T) {
	ca := newMockCAService()
	cert := generateTestCertificate("renew.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert

	_, router := setupCAHandlers(ca)

	reqBody := CertificateRenewRequest{
		ValidDays: 0,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/"+serial+"/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCAHandlers_RenewCertificate_NotFound(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	reqBody := CertificateRenewRequest{
		ValidDays: 180,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/nonexistent/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestCAHandlers_RenewCertificate_RenewFailed(t *testing.T) {
	ca := newMockCAService()
	ca.issueErr = errors.New("renewal failed")

	cert := generateTestCertificate("renew.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert

	_, router := setupCAHandlers(ca)

	reqBody := CertificateRenewRequest{
		ValidDays: 180,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/"+serial+"/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// =============================================================================
// Tests: Verify Certificate
// =============================================================================

func TestCAHandlers_VerifyCertificate_Success_PEM(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	// Create a certificate PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.rootCert.Raw,
	})

	reqBody := CertificateVerifyRequest{
		CertificatePEM:   string(certPEM),
		VerifyExpiration: true,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CAVerifyCertificateResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Note: verification may fail due to mock chain, but handler should work
	assert.NotEmpty(t, resp.Message)
}

func TestCAHandlers_VerifyCertificate_Success_DER(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	reqBody := CertificateVerifyRequest{
		CertificateDER: ca.rootCert.Raw,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestCAHandlers_VerifyCertificate_MissingCertificate(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	reqBody := CertificateVerifyRequest{}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCAHandlers_VerifyCertificate_InvalidPEM(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	reqBody := CertificateVerifyRequest{
		CertificatePEM: "invalid pem data",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCAHandlers_VerifyCertificate_InvalidDER(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	reqBody := CertificateVerifyRequest{
		CertificateDER: []byte("invalid der data"),
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCAHandlers_VerifyCertificate_WithTrustedRoots(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.rootCert.Raw,
	})

	reqBody := CertificateVerifyRequest{
		CertificatePEM: string(certPEM),
		TrustedRoots:   [][]byte{ca.rootCert.Raw},
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// =============================================================================
// Tests: Get CRL
// =============================================================================

func TestCAHandlers_GetCRL_Success(t *testing.T) {
	ca := newMockCAService()
	ca.generateCRLSupport = true
	crl, _ := generateTestCRL(ca.rootCert)
	ca.crlData = crl

	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/crl", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CACRLResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.CRL)
	assert.GreaterOrEqual(t, resp.RevokedCount, 0)
}

func TestCAHandlers_GetCRL_WithEntries(t *testing.T) {
	ca := newMockCAService()
	ca.generateCRLSupport = true
	crl, _ := generateTestCRL(ca.rootCert)
	ca.crlData = crl

	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/crl?include_entries=true", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestCAHandlers_GetCRL_NotSupported(t *testing.T) {
	ca := newMockCAService()
	ca.generateCRLSupport = false

	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/crl", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotImplemented, rr.Code)
}

func TestCAHandlers_GetCRL_GenerationFailed(t *testing.T) {
	ca := newMockCAService()
	ca.generateCRLSupport = true
	ca.crlErr = errors.New("CRL generation failed")

	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/crl", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// =============================================================================
// Tests: Get CA Bundle
// =============================================================================

func TestCAHandlers_GetCABundle_Success(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/bundle", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CABundleResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Bundle)
	assert.GreaterOrEqual(t, resp.CertCount, 1)
}

func TestCAHandlers_GetCABundle_WithStoreType(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/bundle?store_type=software", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestCAHandlers_GetCABundle_WithAlgorithm(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/bundle?algorithm=ECDSA", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestCAHandlers_GetCABundle_InvalidAlgorithm(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/bundle?algorithm=INVALID", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCAHandlers_GetCABundle_NotFound(t *testing.T) {
	ca := newMockCAService()
	ca.bundle = []byte{}

	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/bundle", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestCAHandlers_GetCABundle_BundleFailed(t *testing.T) {
	ca := newMockCAService()
	ca.bundleErr = errors.New("bundle retrieval failed")

	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/bundle", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestCAHandlers_GetCABundle_ExcludeIntermediates(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/bundle?include_intermediates=false", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// =============================================================================
// Tests: Error Types
// =============================================================================

func TestCAHandlers_ErrorTypes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrCAServiceNotAvailable", ErrCAServiceNotAvailable{}, "certificate authority service not available"},
		{"ErrCANotInitialized", ErrCANotInitialized{}, "certificate authority not initialized"},
		{"ErrInvalidSerialNumber empty", ErrInvalidSerialNumber{}, "invalid serial number: "},
		{"ErrInvalidSerialNumber with reason", ErrInvalidSerialNumber{Serial: "123", Reason: "bad"}, "invalid serial number '123': bad"},
		{"ErrCertificateNotFound empty", ErrCertificateNotFound{}, "certificate not found"},
		{"ErrCertificateNotFound with serial", ErrCertificateNotFound{Serial: "123"}, "certificate not found: 123"},
		{"ErrInvalidCertificateRequest empty", ErrInvalidCertificateRequest{}, "invalid certificate request"},
		{"ErrInvalidCertificateRequest with reason", ErrInvalidCertificateRequest{Reason: "bad"}, "invalid certificate request: bad"},
		{"ErrMissingCommonName", ErrMissingCommonName{}, "common name is required"},
		{"ErrInvalidKeyAlgorithm", ErrInvalidKeyAlgorithm{Algorithm: "BAD"}, "invalid key algorithm: BAD"},
		{"ErrCertificateIssueFailed", ErrCertificateIssueFailed{Err: errors.New("fail")}, "failed to issue certificate: fail"},
		{"ErrCertificateRevokeFailed", ErrCertificateRevokeFailed{Serial: "123", Err: errors.New("fail")}, "failed to revoke certificate 123: fail"},
		{"ErrCertificateRenewFailed", ErrCertificateRenewFailed{Serial: "123", Err: errors.New("fail")}, "failed to renew certificate 123: fail"},
		{"ErrCertificateVerifyFailed", ErrCertificateVerifyFailed{Err: errors.New("fail")}, "certificate verification failed: fail"},
		{"ErrCRLNotFound", ErrCRLNotFound{}, "certificate revocation list not found"},
		{"ErrCRLNotSupported", ErrCRLNotSupported{}, "CRL generation not supported"},
		{"ErrCRLGenerationFailed empty", ErrCRLGenerationFailed{}, "CRL generation failed"},
		{"ErrCRLGenerationFailed with reason", ErrCRLGenerationFailed{Reason: "bad"}, "CRL generation failed: bad"},
		{"ErrCABundleNotFound", ErrCABundleNotFound{}, "CA bundle not found"},
		{"ErrCABundleFailed", ErrCABundleFailed{Err: errors.New("fail")}, "failed to get CA bundle: fail"},
		{"ErrInvalidValidityPeriod empty", ErrInvalidValidityPeriod{Days: 0}, "invalid validity period: 0 days"},
		{"ErrInvalidValidityPeriod with reason", ErrInvalidValidityPeriod{Days: -1, Reason: "bad"}, "invalid validity period -1 days: bad"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestCAHandlers_ErrorUnwrap(t *testing.T) {
	innerErr := errors.New("inner error")

	tests := []struct {
		name string
		err  error
	}{
		{"ErrCertificateIssueFailed", ErrCertificateIssueFailed{Err: innerErr}},
		{"ErrCertificateRevokeFailed", ErrCertificateRevokeFailed{Err: innerErr}},
		{"ErrCertificateRenewFailed", ErrCertificateRenewFailed{Err: innerErr}},
		{"ErrCertificateVerifyFailed", ErrCertificateVerifyFailed{Err: innerErr}},
		{"ErrCABundleFailed", ErrCABundleFailed{Err: innerErr}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unwrapped := errors.Unwrap(tt.err)
			assert.Equal(t, innerErr, unwrapped)
		})
	}
}

// =============================================================================
// Tests: Helper Functions
// =============================================================================

func TestCAHandlers_ParseKeyAlgorithm(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	tests := []struct {
		input    string
		expected x509.PublicKeyAlgorithm
		hasError bool
	}{
		{"RSA", x509.RSA, false},
		{"rsa", x509.RSA, false},
		{"RSA2048", x509.RSA, false},
		{"RSA-4096", x509.RSA, false},
		{"ECDSA", x509.ECDSA, false},
		{"EC", x509.ECDSA, false},
		{"P256", x509.ECDSA, false},
		{"ECDSA-P384", x509.ECDSA, false},
		{"ED25519", x509.Ed25519, false},
		{"", x509.ECDSA, false}, // Default
		{"INVALID", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := handlers.parseKeyAlgorithm(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCAHandlers_KeyAlgorithmToString(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	tests := []struct {
		input    x509.PublicKeyAlgorithm
		expected string
	}{
		{x509.RSA, "RSA"},
		{x509.ECDSA, "ECDSA"},
		{x509.Ed25519, "ED25519"},
		{x509.DSA, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := handlers.keyAlgorithmToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCAHandlers_ParseKeyUsage(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	usages := []string{
		"DIGITAL_SIGNATURE",
		"KEY_ENCIPHERMENT",
		"CERT_SIGN",
		"CRL_SIGN",
	}

	result := handlers.parseKeyUsage(usages)

	assert.True(t, result&x509.KeyUsageDigitalSignature != 0)
	assert.True(t, result&x509.KeyUsageKeyEncipherment != 0)
	assert.True(t, result&x509.KeyUsageCertSign != 0)
	assert.True(t, result&x509.KeyUsageCRLSign != 0)
}

func TestCAHandlers_ParseExtKeyUsage(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	usages := []string{
		"SERVER_AUTH",
		"CLIENT_AUTH",
		"CODE_SIGNING",
	}

	result := handlers.parseExtKeyUsage(usages)

	assert.Contains(t, result, x509.ExtKeyUsageServerAuth)
	assert.Contains(t, result, x509.ExtKeyUsageClientAuth)
	assert.Contains(t, result, x509.ExtKeyUsageCodeSigning)
}

func TestCAHandlers_KeyUsageToStrings(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	result := handlers.keyUsageToStrings(usage)

	assert.Contains(t, result, "DIGITAL_SIGNATURE")
	assert.Contains(t, result, "CERT_SIGN")
	assert.Contains(t, result, "CRL_SIGN")
}

func TestCAHandlers_ExtKeyUsageToStrings(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	usages := []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageOCSPSigning,
	}

	result := handlers.extKeyUsageToStrings(usages)

	assert.Contains(t, result, "SERVER_AUTH")
	assert.Contains(t, result, "CLIENT_AUTH")
	assert.Contains(t, result, "OCSP_SIGNING")
}

func TestCAHandlers_FirstOrEmpty(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	assert.Equal(t, "first", handlers.firstOrEmpty([]string{"first", "second"}))
	assert.Equal(t, "", handlers.firstOrEmpty([]string{}))
	assert.Equal(t, "", handlers.firstOrEmpty(nil))
}

func TestCAHandlers_ParseInt(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	assert.Equal(t, 10, handlers.parseInt("10", 5))
	assert.Equal(t, 5, handlers.parseInt("", 5))
	assert.Equal(t, 5, handlers.parseInt("invalid", 5))
}

func TestCAHandlers_CertStatusToString(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	// Valid certificate
	validCert := generateTestCertificate("valid.test.com", false, nil, nil)
	assert.Equal(t, "VALID", handlers.certStatusToString(validCert))
}

func TestCAHandlers_CertToSummary(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	cert := generateTestCertificate("test.example.com", false, nil, nil)
	summary := handlers.certToSummary(cert)

	assert.Equal(t, "test.example.com", summary.CommonName)
	assert.NotEmpty(t, summary.Serial)
	assert.Equal(t, "ECDSA", summary.KeyAlgorithm)
}

func TestCAHandlers_CertToSummary_NilCert(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	summary := handlers.certToSummary(nil)
	assert.Equal(t, CACertificateSummary{}, summary)
}

func TestCAHandlers_CertToResponse(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	cert := generateTestCertificate("test.example.com", false, nil, nil)
	resp := handlers.certToResponse(cert, true)

	assert.NotNil(t, resp)
	assert.Equal(t, "test.example.com", resp.Subject.CommonName)
	assert.NotEmpty(t, resp.PEM)
	assert.NotEmpty(t, resp.FingerprintSHA256)
}

func TestCAHandlers_CertToResponse_NilCert(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	resp := handlers.certToResponse(nil, true)
	assert.Nil(t, resp)
}

func TestCAHandlers_CertToResponse_NoPEM(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)

	cert := generateTestCertificate("test.example.com", false, nil, nil)
	resp := handlers.certToResponse(cert, false)

	assert.NotNil(t, resp)
	assert.Empty(t, resp.PEM)
}

// =============================================================================
// Tests: Constructor
// =============================================================================

func TestNewCAHandlers(t *testing.T) {
	ca := newMockCAService()

	// With logger
	logger := slog.Default()
	handlers := NewCAHandlers(ca, logger, nil)
	assert.NotNil(t, handlers)
	assert.Equal(t, ca, handlers.ca)
	assert.Equal(t, logger, handlers.logger)

	// Without logger (should use default)
	handlers2 := NewCAHandlers(ca, nil, nil)
	assert.NotNil(t, handlers2)
	assert.NotNil(t, handlers2.logger)
}

// =============================================================================
// Tests: Route Registration
// =============================================================================

func TestCAHandlers_RegisterRoutes(t *testing.T) {
	ca := newMockCAService()
	handlers := NewCAHandlers(ca, nil, nil)
	router := mux.NewRouter()

	handlers.RegisterRoutes(router)

	// Verify routes are registered by walking the router
	expectedRoutes := map[string][]string{
		"/api/v1/ca/info":                         {http.MethodGet},
		"/api/v1/ca/certificates":                 {http.MethodPost, http.MethodGet},
		"/api/v1/ca/certificates/{serial}":        {http.MethodGet},
		"/api/v1/ca/certificates/{serial}/revoke": {http.MethodPost},
		"/api/v1/ca/certificates/{serial}/renew":  {http.MethodPost},
		"/api/v1/ca/certificates/verify":          {http.MethodPost},
		"/api/v1/ca/crl":                          {http.MethodGet},
		"/api/v1/ca/bundle":                       {http.MethodGet},
	}

	registeredRoutes := make(map[string][]string)
	err := router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		if len(methods) > 0 {
			registeredRoutes[path] = append(registeredRoutes[path], methods...)
		}
		return nil
	})
	require.NoError(t, err)

	for path, expectedMethods := range expectedRoutes {
		t.Run(path, func(t *testing.T) {
			registeredMethods, ok := registeredRoutes[path]
			assert.True(t, ok, "Route should be registered: %s", path)
			for _, method := range expectedMethods {
				found := false
				for _, rm := range registeredMethods {
					if strings.EqualFold(rm, method) {
						found = true
						break
					}
				}
				assert.True(t, found, "Method %s should be registered for route %s", method, path)
			}
		})
	}
}
