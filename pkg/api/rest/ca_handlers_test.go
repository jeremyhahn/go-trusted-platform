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
	"io"
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
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
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
	// csrCA certifies CSRs; nil until a test sets it.
	renewals []issuance.RenewOptions
	csrCA    *issuancetest.CA
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

func (m *mockCAService) SignCSR(ctx context.Context, csrPEM []byte, opts *quicbaasca.SignOptions) (*x509.Certificate, error) {
	if m.csrCA == nil {
		return nil, errors.New("no CSR CA")
	}
	return m.csrCA.SignCSR(ctx, csrPEM, opts)
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

func (m *mockCAService) Renew(ctx context.Context, existing *x509.Certificate, opts issuance.RenewOptions) (*x509.Certificate, error) {
	m.renewals = append(m.renewals, opts)
	if err := m.Revoke(ctx, existing, nil); err != nil {
		return nil, err
	}
	return m.IssueCertificate(ctx, &quicbaasca.CACertificateRequest{
		Subject: quicbaasca.CASubject{CommonName: existing.Subject.CommonName},
		Valid:   opts.ValidDays,
		SANS:    opts.NewSANs,
	})
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
	guard := NewScopeGuard(&scopedAuthorizer{scopes: map[string][]string{adminToken: {scopeCertsRevoke}}}, nil, nil)
	handlers := NewCAHandlers(ca, logger, nil).WithScopeGuard(guard)
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

	rr := postJSON(t, router, "/api/v1/ca/certificates", &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{
				CommonName:   "test.example.com",
				Organization: "Test Org",
			},
			ValidDays:    90,
			KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
			Sans: &platformv1.SubjectAlternativeNames{
				DnsNames: []string{"test.example.com", "www.test.example.com"},
			},
		},
	})
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())

	resp := &platformv1.IssueCertificateResponse{}
	require.NoError(t, protojson.Unmarshal(rr.Body.Bytes(), resp))

	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, "certificate issued successfully", resp.GetStatus().GetMessage())
	assert.NotNil(t, resp.GetTimestamp())
	require.NotNil(t, resp.GetCertificate())
	assert.Equal(t, "test.example.com", resp.GetCertificate().GetSubject().GetCommonName())
	assert.Contains(t, string(resp.GetCertificate().GetPem()), "BEGIN CERTIFICATE")
	assert.Len(t, ca.issuedCerts, 1)
}

// The issue route takes the protobuf IssueCertificateRequest, which wraps
// the certificate request; a body without it is refused before the CA.
func TestCAHandlers_IssueCertificate_MissingRequest(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	rr := postJSON(t, router, "/api/v1/ca/certificates", map[string]any{
		"subject": map[string]string{"common_name": "test.example.com"},
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), ErrMissingCertificateRequest{}.Error())
	assert.Empty(t, ca.issuedCerts, "a request without a certificate request reached the CA")
}

func TestCAHandlers_IssueCertificate_MissingCommonName(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	rr := postJSON(t, router, "/api/v1/ca/certificates", &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{Organization: "Test Org"},
		},
	})

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var resp CAErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "common name")
}

func TestCAHandlers_IssueCertificate_InvalidKeyAlgorithm(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	rr := postJSON(t, router, "/api/v1/ca/certificates", &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject:      &platformv1.Subject{CommonName: "test.example.com"},
			KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_DILITHIUM2,
		},
	})

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

	rr := postJSON(t, router, "/api/v1/ca/certificates", &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{CommonName: "test.example.com"},
		},
	})

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestCAHandlers_IssueCertificate_CANotAvailable(t *testing.T) {
	_, router := setupCAHandlers(nil)

	rr := postJSON(t, router, "/api/v1/ca/certificates", &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{CommonName: "test.example.com"},
		},
	})

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

	resp := &platformv1.GetCertificateResponse{}
	require.NoError(t, protojson.Unmarshal(rr.Body.Bytes(), resp))

	require.NotNil(t, resp.GetCertificate())
	assert.Equal(t, serial, resp.GetCertificate().GetSerial())
	assert.Empty(t, resp.GetCertificate().GetPem())
	assert.NotNil(t, resp.GetTimestamp())
}

func TestCAHandlers_GetCertificate_WithPEM(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	serial := hex.EncodeToString(ca.rootCert.SerialNumber.Bytes())
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/ca/certificates/"+serial+"?include_pem=true", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	resp := &platformv1.GetCertificateResponse{}
	require.NoError(t, protojson.Unmarshal(rr.Body.Bytes(), resp))

	assert.Contains(t, string(resp.GetCertificate().GetPem()), "BEGIN CERTIFICATE")
}

// The DER rides only when asked for, as include_der does on gRPC (#691).
func TestCAHandlers_GetCertificate_IncludeDer(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)
	serial := hex.EncodeToString(ca.rootCert.SerialNumber.Bytes())

	get := func(query string) *platformv1.Certificate {
		req, err := http.NewRequest(http.MethodGet, "/api/v1/ca/certificates/"+serial+query, nil)
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		resp := &platformv1.GetCertificateResponse{}
		require.NoError(t, protojson.Unmarshal(rr.Body.Bytes(), resp))
		return resp.GetCertificate()
	}

	assert.Equal(t, ca.rootCert.Raw, get("?include_der=true").GetDer())
	assert.Empty(t, get("").GetDer())
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

	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/"+serial, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
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
	assert.NotContains(t, ca.certStore.certs, serial, "DELETE must reach CA Revoke")
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

	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/"+serial, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestCAHandlers_RevokeCertificate_NotFound(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestCAHandlers_RevokeCertificate_RequiresRevokeScope proves DELETE is
// refused, and the certificate left unrevoked, for a caller without
// certs:revoke.
func TestCAHandlers_RevokeCertificate_RequiresRevokeScope(t *testing.T) {
	ca := newMockCAService()
	cert := generateTestCertificate("revoke.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert

	guard := NewScopeGuard(&scopedAuthorizer{scopes: map[string][]string{"reader": {"certs:read"}}}, nil, nil)
	router := mux.NewRouter()
	NewCAHandlers(ca, slog.Default(), nil).WithScopeGuard(guard).RegisterRoutes(router)

	for name, token := range map[string]string{"no token": "", "wrong scope": "reader"} {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/"+serial, nil)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, rr.Code)
			assert.Contains(t, ca.certStore.certs, serial, "the certificate must not be revoked")
		})
	}
}

// TestCAHandlers_RevokeCertificate_PostRevokeRouteRemoved proves the old
// POST .../revoke shape is gone: DELETE is the only revoke route.
func TestCAHandlers_RevokeCertificate_PostRevokeRouteRemoved(t *testing.T) {
	ca := newMockCAService()
	cert := generateTestCertificate("revoke.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert
	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/ca/certificates/"+serial+"/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rr.Code)
	assert.Contains(t, ca.certStore.certs, serial, "the certificate must not be revoked")
}

func TestCAHandlers_RevokeCertificate_RevokeFailed(t *testing.T) {
	ca := newMockCAService()
	ca.revokeErr = errors.New("revocation failed")

	cert := generateTestCertificate("revoke.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert

	_, router := setupCAHandlers(ca)

	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/"+serial, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
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

	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/"+serial, bytes.NewReader([]byte("invalid")))
	req.Header.Set("Authorization", "Bearer "+adminToken)
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

// The handler renews through the CA's shared renewal, handing it the request's
// validity and names unchanged.
func TestCAHandlers_RenewCertificate_HandsTheRequestToTheSharedRenewal(t *testing.T) {
	ca := newMockCAService()
	cert := generateTestCertificate("renew.test.com", false, nil, nil)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	ca.certStore.certs[serial] = cert
	_, router := setupCAHandlers(ca)

	body, err := json.Marshal(CertificateRenewRequest{
		ValidDays:    90,
		PreserveSANs: true,
		NewSANs:      &CASANsRequest{DNS: []string{"new.renew.test.com"}},
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates/"+serial+"/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Len(t, ca.renewals, 1)
	assert.Equal(t, 90, ca.renewals[0].ValidDays)
	assert.True(t, ca.renewals[0].PreserveSANs)
	require.NotNil(t, ca.renewals[0].NewSANs)
	assert.Equal(t, []string{"new.renew.test.com"}, ca.renewals[0].NewSANs.DNS)
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

// certToProto answers in the gRPC CA shape: protobuf times and enums, the
// PEM and DER only when asked for.
func TestCAHandlers_CertToProto(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)
	cert := generateTestCertificate("test.example.com", false, nil, nil)

	got := handlers.certToProto(cert, true, true)
	require.NotNil(t, got)
	assert.Equal(t, hex.EncodeToString(cert.SerialNumber.Bytes()), got.GetSerial())
	assert.Equal(t, "test.example.com", got.GetSubject().GetCommonName())
	assert.Equal(t, cert.NotBefore.Unix(), got.GetNotBefore().AsTime().Unix())
	assert.Equal(t, cert.NotAfter.Unix(), got.GetNotAfter().AsTime().Unix())
	assert.Equal(t, platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID, got.GetStatus())
	assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, got.GetKeyAlgorithm())
	assert.Contains(t, string(got.GetPem()), "BEGIN CERTIFICATE")
	assert.Equal(t, cert.Raw, got.GetDer())
	assert.NotEmpty(t, got.GetFingerprintSha256())

	bare := handlers.certToProto(cert, false, false)
	assert.Empty(t, bare.GetPem())
	assert.Empty(t, bare.GetDer())
}

func TestCAHandlers_CertToProto_NilCert(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)
	assert.Nil(t, handlers.certToProto(nil, true, true))
}

func TestCertStatusToProto(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}

	assert.Equal(t, platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID, certStatusToProto(cert, now))
	assert.Equal(t, platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING, certStatusToProto(cert, now.Add(-2*time.Hour)))
	assert.Equal(t, platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED, certStatusToProto(cert, now.Add(2*time.Hour)))
}

func TestKeyAlgorithmToProto(t *testing.T) {
	assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048, keyAlgorithmToProto(x509.RSA))
	assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, keyAlgorithmToProto(x509.ECDSA))
	assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519, keyAlgorithmToProto(x509.Ed25519))
	assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED, keyAlgorithmToProto(x509.DSA))
}

func TestProtoKeyAlgorithmToX509(t *testing.T) {
	cases := map[platformv1.KeyAlgorithm]x509.PublicKeyAlgorithm{
		platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED: x509.ECDSA,
		platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096:    x509.RSA,
		platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384:  x509.ECDSA,
		platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519:     x509.Ed25519,
	}
	for in, want := range cases {
		got, err := protoKeyAlgorithmToX509(in)
		require.NoError(t, err, in.String())
		assert.Equal(t, want, got, in.String())
	}
}

func TestProtoKeyAlgorithmToX509_Unsupported(t *testing.T) {
	_, err := protoKeyAlgorithmToX509(platformv1.KeyAlgorithm_KEY_ALGORITHM_DILITHIUM3)
	var invalid ErrInvalidKeyAlgorithm
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "KEY_ALGORITHM_DILITHIUM3", invalid.Algorithm)
}

// failingBody is a request body whose read fails.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestCAHandlers_DecodeProto(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)
	decode := func(body io.Reader) (*platformv1.SignCSRRequest, *httptest.ResponseRecorder, bool) {
		msg := &platformv1.SignCSRRequest{}
		rr := httptest.NewRecorder()
		ok := handlers.decodeProto(rr, httptest.NewRequest(http.MethodPost, "/", body), msg)
		return msg, rr, ok
	}

	msg, _, ok := decode(strings.NewReader(`{"csrPem":"pem","validDays":7}`))
	require.True(t, ok)
	assert.Equal(t, "pem", msg.GetCsrPem())
	assert.Equal(t, int32(7), msg.GetValidDays())

	msg, _, ok = decode(strings.NewReader(`{"csr_pem":"pem","unknown":1}`))
	require.True(t, ok, "snake_case names and unknown fields are accepted")
	assert.Equal(t, "pem", msg.GetCsrPem())

	_, _, ok = decode(strings.NewReader(""))
	assert.True(t, ok, "an empty body is the zero request")
}

func TestCAHandlers_DecodeProto_Errors(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)
	for name, body := range map[string]io.Reader{
		"not JSON":    strings.NewReader("{"),
		"wrong type":  strings.NewReader(`{"validDays":"seven"}`),
		"read failed": failingBody{},
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			ok := handlers.decodeProto(rr, httptest.NewRequest(http.MethodPost, "/", body), &platformv1.SignCSRRequest{})
			assert.False(t, ok)
			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Contains(t, rr.Body.String(), "invalid request body")
		})
	}
}

func TestCAHandlers_WriteProto(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)
	rr := httptest.NewRecorder()
	handlers.writeProto(rr, http.StatusCreated, &platformv1.Status{Success: true})

	assert.Equal(t, http.StatusCreated, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	got := &platformv1.Status{}
	require.NoError(t, protojson.Unmarshal(rr.Body.Bytes(), got))
	assert.True(t, got.GetSuccess())
	assert.Contains(t, rr.Body.String(), `"message":""`, "unpopulated fields are emitted")
}

// A message protojson cannot encode (a string that is not UTF-8) is a 500,
// not a half-written body.
func TestCAHandlers_WriteProto_MarshalError(t *testing.T) {
	handlers := NewCAHandlers(nil, nil, nil)
	rr := httptest.NewRecorder()
	handlers.writeProto(rr, http.StatusOK, &platformv1.Status{Message: "\xff"})

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.NotContains(t, rr.Body.String(), `"success"`)
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
		"/api/v1/ca/info":                        {http.MethodGet},
		"/api/v1/ca/certificates":                {http.MethodPost, http.MethodGet},
		"/api/v1/ca/certificates/{serial}":       {http.MethodGet, http.MethodDelete},
		"/api/v1/ca/certificates/{serial}/renew": {http.MethodPost},
		"/api/v1/ca/certificates/verify":         {http.MethodPost},
		"/api/v1/ca/crl":                         {http.MethodGet},
		"/api/v1/ca/bundle":                      {http.MethodGet},
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
