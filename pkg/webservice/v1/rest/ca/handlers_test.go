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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	xkmsca "github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock CA Implementation
// =============================================================================

type mockCertificateAuthority struct {
	baseMockCA

	// Configuration
	initialized       bool
	identity          string
	defaultKeyAlg     x509.PublicKeyAlgorithm
	defaultSigAlg     x509.SignatureAlgorithm
	defaultValidity   int
	hash              crypto.Hash
	isAutoImportingCA bool
	config            xkmsca.CAConfig

	// Certificates
	rootCert         *x509.Certificate
	intermediateCert *x509.Certificate

	// Store mocks
	certStore xkmssdk.CertStore

	// Method overrides for testing
	signCSRFn             func(csrPEM []byte, opts *xkmsca.SignOptions) (*x509.Certificate, error)
	caBundleFn            func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error)
	issueCertificateFn    func(request *xkmsca.CertificateRequest) (*xkmsca.IssuedCertificate, error)
	revokeFn              func(certificate *x509.Certificate, opts xkmsca.RevokeOptions) error
	parseBundleFn         func(bundle []byte) ([]*x509.Certificate, error)
	trustedRootFn         func() (*x509.Certificate, error)
	trustedIntermediateFn func() (*x509.Certificate, error)
	certificateFn         func(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error)
	certificateStoreFn    func() xkmssdk.CertStore
	signerFn              func() (crypto.Signer, error)
	publicKeyFn           func() crypto.PublicKey
	signFn                func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

func (m *mockCertificateAuthority) Public() crypto.PublicKey {
	if m.publicKeyFn != nil {
		return m.publicKeyFn()
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &key.PublicKey
}
func (m *mockCertificateAuthority) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if m.signFn != nil {
		return m.signFn(r, digest, opts)
	}
	return []byte("mock-signature"), nil
}
func (m *mockCertificateAuthority) SignCSR(csrPEM []byte, opts *xkmsca.SignOptions) (*x509.Certificate, error) {
	if m.signCSRFn != nil {
		return m.signCSRFn(csrPEM, opts)
	}
	return nil, errors.New("not implemented")
}
func (m *mockCertificateAuthority) CABundle() ([]byte, error) {
	if m.caBundleFn != nil {
		return m.caBundleFn("", 0)
	}
	return []byte("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"), nil
}
func (m *mockCertificateAuthority) CABundleFiltered(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
	if m.caBundleFn != nil {
		return m.caBundleFn(storeType, keyAlgorithm)
	}
	return []byte("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"), nil
}
func (m *mockCertificateAuthority) Certificate(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	if m.certificateFn != nil {
		return m.certificateFn(attrs)
	}
	return nil, errors.New("not found")
}
func (m *mockCertificateAuthority) Signer() (crypto.Signer, error) {
	if m.signerFn != nil {
		return m.signerFn()
	}
	return m, nil
}
func (m *mockCertificateAuthority) TrustedRoot() (*x509.Certificate, error) {
	if m.trustedRootFn != nil {
		return m.trustedRootFn()
	}
	return m.rootCert, nil
}
func (m *mockCertificateAuthority) TrustedIntermediate() (*x509.Certificate, error) {
	if m.trustedIntermediateFn != nil {
		return m.trustedIntermediateFn()
	}
	return m.intermediateCert, nil
}
func (m *mockCertificateAuthority) IssueCertificate(request *xkmsca.CertificateRequest) (*xkmsca.IssuedCertificate, error) {
	if m.issueCertificateFn != nil {
		return m.issueCertificateFn(request)
	}
	cert := createTestCertificate(request.Subject.CommonName)
	return &xkmsca.IssuedCertificate{Certificate: cert}, nil
}
func (m *mockCertificateAuthority) RevokeCert(cert *x509.Certificate, opts xkmsca.RevokeOptions) error {
	if m.revokeFn != nil {
		return m.revokeFn(cert, opts)
	}
	return nil
}
func (m *mockCertificateAuthority) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
	if m.parseBundleFn != nil {
		return m.parseBundleFn(bundle)
	}
	return []*x509.Certificate{m.rootCert}, nil
}
func (m *mockCertificateAuthority) RootCertificate(_ *x509.Certificate) (*x509.Certificate, error) {
	return m.rootCert, nil
}
func (m *mockCertificateAuthority) CertStore() xkmssdk.CertStore {
	if m.certificateStoreFn != nil {
		return m.certificateStoreFn()
	}
	return m.certStore
}
func (m *mockCertificateAuthority) IsAutoImportingIssuerCAs() bool { return m.isAutoImportingCA }
func (m *mockCertificateAuthority) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm {
	if m.defaultKeyAlg != 0 {
		return m.defaultKeyAlg
	}
	return x509.ECDSA
}
func (m *mockCertificateAuthority) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	if m.defaultSigAlg != 0 {
		return m.defaultSigAlg
	}
	return x509.ECDSAWithSHA256
}
func (m *mockCertificateAuthority) DefaultValidityPeriod() int {
	if m.defaultValidity != 0 {
		return m.defaultValidity
	}
	return 365
}
func (m *mockCertificateAuthority) Hash() crypto.Hash {
	if m.hash != 0 {
		return m.hash
	}
	return crypto.SHA256
}
func (m *mockCertificateAuthority) Identity() string {
	if m.identity != "" {
		return m.identity
	}
	return "Test CA"
}
func (m *mockCertificateAuthority) Init() error {
	m.initialized = true
	return nil
}
func (m *mockCertificateAuthority) IsInitialized() bool       { return m.initialized }
func (m *mockCertificateAuthority) CAConfig() xkmsca.CAConfig { return m.config }
func (m *mockCertificateAuthority) GenerateCRL() ([]byte, error) {
	return nil, errors.New("CRL generation not supported")
}

// =============================================================================
// Mock CA with CRL Generator - for testing GetCRL success path
// =============================================================================

type mockCAWithCRLGenerator struct {
	mockCertificateAuthority
	generateCRLFn func() ([]byte, error)
}

func (m *mockCAWithCRLGenerator) GenerateCRL() ([]byte, error) {
	if m.generateCRLFn != nil {
		return m.generateCRLFn()
	}
	return nil, errors.New("CRL generation not configured")
}

// =============================================================================
// Mock Certificate Store - implements xkmssdk.CertStore interface
// =============================================================================

type mockCertStore struct {
	getCertificateFn func(cn string) (*x509.Certificate, error)
}

// Basic Certificate Operations
func (m *mockCertStore) StoreCertificate(cert *x509.Certificate) error {
	return nil
}

func (m *mockCertStore) GetCertificate(cn string) (*x509.Certificate, error) {
	if m.getCertificateFn != nil {
		return m.getCertificateFn(cn)
	}
	return nil, errors.New("certificate not found")
}

func (m *mockCertStore) DeleteCertificate(cn string) error {
	return nil
}

func (m *mockCertStore) ListCertificates() ([]*x509.Certificate, error) {
	return []*x509.Certificate{}, nil
}

// Certificate Chain Operations
func (m *mockCertStore) StoreCertificateChain(chain []*x509.Certificate) error {
	return nil
}

func (m *mockCertStore) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	return nil, errors.New("not found")
}

// CRL Operations
func (m *mockCertStore) StoreCRL(crl *x509.RevocationList) error {
	return nil
}

func (m *mockCertStore) GetCRL(issuer string) (*x509.RevocationList, error) {
	return nil, errors.New("not found")
}

// Validation Operations
func (m *mockCertStore) VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error {
	return nil
}

func (m *mockCertStore) IsRevoked(cert *x509.Certificate) (bool, error) {
	return false, nil
}

// Lifecycle
func (m *mockCertStore) Close() error {
	return nil
}

// =============================================================================
// Mock HttpWriter
// =============================================================================

type mockHttpWriter struct {
	lastStatus  int
	lastPayload interface{}
	lastError   error
}

func (m *mockHttpWriter) Write(w http.ResponseWriter, r *http.Request, status int, resp interface{}) {
	m.lastStatus = status
	m.lastPayload = resp
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) WriteYaml(w http.ResponseWriter, status int, resp interface{}) {
	m.lastStatus = status
	m.lastPayload = resp
	w.WriteHeader(status)
}

func (m *mockHttpWriter) WriteJson(w http.ResponseWriter, status int, resp interface{}) {
	m.lastStatus = status
	m.lastPayload = resp
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.lastStatus = http.StatusOK
	m.lastPayload = payload
	w.WriteHeader(http.StatusOK)
	resp := response.WebServiceResponse{Code: 200, Success: true, Payload: payload}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.lastStatus = http.StatusCreated
	m.lastPayload = payload
	w.WriteHeader(http.StatusCreated)
	resp := response.WebServiceResponse{Code: 201, Success: true, Payload: payload}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	m.lastStatus = http.StatusNotFound
	m.lastPayload = payload
	m.lastError = err
	w.WriteHeader(http.StatusNotFound)
}

func (m *mockHttpWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusOK
	m.lastError = err
	w.WriteHeader(http.StatusOK)
}

func (m *mockHttpWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusBadRequest
	m.lastError = err
	w.WriteHeader(http.StatusBadRequest)
	resp := response.WebServiceResponse{Code: 400, Success: false, Error: err.Error()}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusUnauthorized
	m.lastError = err
	w.WriteHeader(http.StatusUnauthorized)
}

func (m *mockHttpWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.lastStatus = http.StatusForbidden
	m.lastError = err
	m.lastPayload = payload
	w.WriteHeader(http.StatusForbidden)
}

func (m *mockHttpWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusNotFound
	m.lastError = err
	w.WriteHeader(http.StatusNotFound)
	resp := response.WebServiceResponse{Code: 404, Success: false, Error: err.Error()}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusInternalServerError
	m.lastError = err
	w.WriteHeader(http.StatusInternalServerError)
	resp := response.WebServiceResponse{Code: 500, Success: false, Error: err.Error()}
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, os.Stdout)
}

func newTestHandlers(ca xkmsca.TCGCA) (*CAHandlers, *mockHttpWriter) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewCAHandlers(logger, ca, writer, nil)
	return handlers, writer
}

func createTestCertificate(cn string) *x509.Certificate {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		PublicKeyAlgorithm:    x509.ECDSA,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
}

func createTestRootCertificate() *x509.Certificate {
	cert := createTestCertificate("Test Root CA")
	cert.IsCA = true
	cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	return cert
}

func createTestIntermediateCertificate() *x509.Certificate {
	cert := createTestCertificate("Test Intermediate CA")
	cert.IsCA = true
	cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	cert.Issuer = pkix.Name{
		CommonName: "Test Root CA",
	}
	return cert
}

// createTestCRL creates a valid CRL DER for testing
func createTestCRL() ([]byte, error) {
	// Generate a key for signing
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create subject key identifier from public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(pubKeyBytes)
	subjectKeyId := hash[:20]

	// Create a self-signed certificate to use as the issuer
	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          subjectKeyId,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	// Parse the certificate
	issuer, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	// Create revocation list template
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   big.NewInt(12345),
				RevocationTime: time.Now().Add(-1 * time.Hour),
				ReasonCode:     1, // keyCompromise
			},
		},
	}

	// Create the CRL
	crlDER, err := x509.CreateRevocationList(rand.Reader, template, issuer, key)
	if err != nil {
		return nil, err
	}

	return crlDER, nil
}

// =============================================================================
// NewCAHandlers Tests
// =============================================================================

func TestNewCAHandlers(t *testing.T) {
	t.Run("creates handlers with all dependencies", func(t *testing.T) {
		logger := newTestLogger()
		mockCA := &mockCertificateAuthority{}
		writer := &mockHttpWriter{}

		handlers := NewCAHandlers(logger, mockCA, writer, nil)

		require.NotNil(t, handlers)
		assert.NotNil(t, handlers.logger)
		assert.NotNil(t, handlers.ca)
		assert.NotNil(t, handlers.respWriter)
	})

	t.Run("creates handlers with nil CA", func(t *testing.T) {
		logger := newTestLogger()
		writer := &mockHttpWriter{}

		handlers := NewCAHandlers(logger, nil, writer, nil)

		require.NotNil(t, handlers)
		assert.Nil(t, handlers.ca)
	})
}

// =============================================================================
// GetInfo Handler Tests
// =============================================================================

// decodeProtoBody parses the response body emitted by handlers that go
// through protorest.WriteSuccess and arrives as
// `{"code":200,"success":true,"payload":<protojson(...)>}`. The payload
// itself uses protojson camelCase / RFC3339 conventions.
func decodeProtoBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var envelope struct {
		Code    int                    `json:"code"`
		Success bool                   `json:"success"`
		Payload map[string]interface{} `json:"payload"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, rec.Body.String())
	}
	return envelope.Payload
}

// decodeGetCAInfoBody is preserved as a thin alias for the GetInfo tests.
func decodeGetCAInfoBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	return decodeProtoBody(t, rec)
}

func TestGetInfo_Success(t *testing.T) {
	t.Run("returns CA info when initialized", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized:     true,
			identity:        "Test Root CA",
			defaultKeyAlg:   x509.ECDSA,
			defaultValidity: 365,
			rootCert:        createTestRootCertificate(),
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
		rec := httptest.NewRecorder()

		handlers.GetInfo(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		payload := decodeGetCAInfoBody(t, rec)
		caInfo, ok := payload["caInfo"].(map[string]interface{})
		require.True(t, ok, "payload.caInfo should be an object")
		assert.True(t, caInfo["isInitialized"].(bool))
		assert.Equal(t, "Test Root CA", caInfo["commonName"])
		require.NotNil(t, caInfo["rootCert"])
		_, hasTimestamp := payload["timestamp"].(string)
		assert.True(t, hasTimestamp, "payload.timestamp should be RFC3339 string")
	})

	t.Run("returns info when CA is not initialized", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: false,
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
		rec := httptest.NewRecorder()

		handlers.GetInfo(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		payload := decodeGetCAInfoBody(t, rec)
		caInfo, ok := payload["caInfo"].(map[string]interface{})
		require.True(t, ok)
		assert.False(t, caInfo["isInitialized"].(bool))
	})

	t.Run("includes intermediate CA info", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized:      true,
			identity:         "Test Intermediate CA",
			rootCert:         createTestRootCertificate(),
			intermediateCert: createTestIntermediateCertificate(),
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
		rec := httptest.NewRecorder()

		handlers.GetInfo(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		payload := decodeGetCAInfoBody(t, rec)
		caInfo, ok := payload["caInfo"].(map[string]interface{})
		require.True(t, ok)
		assert.True(t, caInfo["isIntermediate"].(bool))
		intermediates, ok := caInfo["intermediates"].([]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, intermediates)
	})
}

func TestGetInfo_Error(t *testing.T) {
	t.Run("returns 503 when CA is nil", func(t *testing.T) {
		handlers, writer := newTestHandlers(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
		rec := httptest.NewRecorder()

		handlers.GetInfo(rec, req)

		// protorest.WriteError maps Unavailable -> 503 for missing service.
		assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
	})
}

// =============================================================================
// ListCertificates Handler Tests
// =============================================================================

func TestListCertificates_Success(t *testing.T) {
	t.Run("returns certificate list", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			rootCert:    createTestRootCertificate(),
			certStore:   &mockCertStore{},
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates", nil)
		rec := httptest.NewRecorder()

		handlers.ListCertificates(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		payload := decodeProtoBody(t, rec)
		certs, ok := payload["certificates"].([]interface{})
		require.True(t, ok, "payload.certificates should be an array")
		assert.NotEmpty(t, certs)
	})

	t.Run("respects pagination limit", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			rootCert:    createTestRootCertificate(),
			certStore:   &mockCertStore{},
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates?limit=1", nil)
		rec := httptest.NewRecorder()

		handlers.ListCertificates(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		payload := decodeProtoBody(t, rec)
		certs, _ := payload["certificates"].([]interface{})
		assert.LessOrEqual(t, len(certs), 1)
	})

	t.Run("handles pagination cursor", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			rootCert:    createTestRootCertificate(),
			certStore:   &mockCertStore{},
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates?cursor=abc123", nil)
		rec := httptest.NewRecorder()

		handlers.ListCertificates(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
	})

	t.Run("caps limit at maximum", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			rootCert:    createTestRootCertificate(),
			certStore:   &mockCertStore{},
		}
		handlers, _ := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates?limit=10000", nil)

		// Test getPaginationParams directly
		limit, _ := handlers.getPaginationParams(req)
		assert.Equal(t, int32(1000), limit) // Should be capped at maxLimit
	})
}

func TestListCertificates_Error(t *testing.T) {
	t.Run("returns error when CA is nil", func(t *testing.T) {
		handlers, writer := newTestHandlers(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates", nil)
		rec := httptest.NewRecorder()

		handlers.ListCertificates(rec, req)

		// protorest.WriteError maps Unavailable -> 503 for missing service.
		assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
	})

	t.Run("returns error when cert store is nil", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			certStore:   nil,
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates", nil)
		rec := httptest.NewRecorder()

		handlers.ListCertificates(rec, req)

		// FailedPrecondition (gRPC) maps to 400 via protorest.WriteError.
		assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	})
}

// =============================================================================
// GetCertificate Handler Tests
// =============================================================================

func TestGetCertificate_Success(t *testing.T) {
	t.Run("returns root certificate by serial", func(t *testing.T) {
		rootCert := createTestRootCertificate()
		serial := hex.EncodeToString(rootCert.SerialNumber.Bytes())

		mockCA := &mockCertificateAuthority{
			initialized: true,
			rootCert:    rootCert,
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates/"+serial, nil)
		req = mux.SetURLVars(req, map[string]string{"serial": serial})
		rec := httptest.NewRecorder()

		handlers.GetCertificate(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		payload := decodeProtoBody(t, rec)
		cert, ok := payload["certificate"].(map[string]interface{})
		require.True(t, ok, "payload.certificate should be an object")
		assert.Equal(t, serial, cert["serial"])
	})

	t.Run("returns intermediate certificate by serial", func(t *testing.T) {
		intermediateCert := createTestIntermediateCertificate()
		serial := hex.EncodeToString(intermediateCert.SerialNumber.Bytes())

		mockCA := &mockCertificateAuthority{
			initialized:      true,
			rootCert:         createTestRootCertificate(),
			intermediateCert: intermediateCert,
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates/"+serial, nil)
		req = mux.SetURLVars(req, map[string]string{"serial": serial})
		rec := httptest.NewRecorder()

		handlers.GetCertificate(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
	})

	t.Run("includes PEM when requested", func(t *testing.T) {
		rootCert := createTestRootCertificate()
		serial := hex.EncodeToString(rootCert.SerialNumber.Bytes())

		mockCA := &mockCertificateAuthority{
			initialized: true,
			rootCert:    rootCert,
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates/"+serial+"?include_pem=true", nil)
		req = mux.SetURLVars(req, map[string]string{"serial": serial})
		rec := httptest.NewRecorder()

		handlers.GetCertificate(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		payload := decodeProtoBody(t, rec)
		_, ok := payload["certificate"].(map[string]interface{})
		require.True(t, ok)
		// Note: PEM will be empty because rootCert.Raw is nil in test
	})

	t.Run("returns certificate from cert store", func(t *testing.T) {
		testCert := createTestCertificate("test.example.com")
		mockCertStore := &mockCertStore{
			getCertificateFn: func(cn string) (*x509.Certificate, error) {
				if cn == "lookup-serial" {
					return testCert, nil
				}
				return nil, errors.New("not found")
			},
		}

		mockCA := &mockCertificateAuthority{
			initialized: true,
			rootCert:    createTestRootCertificate(),
			certStore:   mockCertStore,
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates/lookup-serial", nil)
		req = mux.SetURLVars(req, map[string]string{"serial": "lookup-serial"})
		rec := httptest.NewRecorder()

		handlers.GetCertificate(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
	})
}

func TestGetCertificate_Error(t *testing.T) {
	t.Run("returns error when CA is nil", func(t *testing.T) {
		handlers, writer := newTestHandlers(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates/abc123", nil)
		req = mux.SetURLVars(req, map[string]string{"serial": "abc123"})
		rec := httptest.NewRecorder()

		handlers.GetCertificate(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
	})

	t.Run("returns error when serial is empty", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{initialized: true}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates/", nil)
		req = mux.SetURLVars(req, map[string]string{"serial": ""})
		rec := httptest.NewRecorder()

		handlers.GetCertificate(rec, req)

		// gRPC InvalidArgument -> 400 via protorest.WriteError; the error
		// itself is now a *status.Error wrapping ErrInvalidSerialNumber's
		// Error() string, so we check the message rather than the type.
		assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
		require.NotNil(t, writer.lastError)
		assert.Contains(t, writer.lastError.Error(), "serial")
	})

	t.Run("returns 404 when certificate not found", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			rootCert:    createTestRootCertificate(),
			certStore:   &mockCertStore{},
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates/nonexistent", nil)
		req = mux.SetURLVars(req, map[string]string{"serial": "nonexistent"})
		rec := httptest.NewRecorder()

		handlers.GetCertificate(rec, req)

		assert.Equal(t, http.StatusNotFound, writer.lastStatus)
		require.NotNil(t, writer.lastError)
		assert.Contains(t, writer.lastError.Error(), "nonexistent")
	})
}

// =============================================================================
// IssueCertificate Handler Tests
// =============================================================================

func TestIssueCertificate_Success(t *testing.T) {
	t.Run("issues certificate with minimal request", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			issueCertificateFn: func(request *xkmsca.CertificateRequest) (*xkmsca.IssuedCertificate, error) {
				return &xkmsca.IssuedCertificate{Certificate: createTestCertificate(request.Subject.CommonName)}, nil
			},
		}
		handlers, writer := newTestHandlers(mockCA)

		// Proto IssueCertificateRequest: {request: {subject: {commonName: ...}}}
		body := []byte(`{"request":{"subject":{"commonName":"test.example.com"}}}`)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handlers.IssueCertificate(rec, req)

		assert.Equal(t, http.StatusCreated, writer.lastStatus)
		payload := decodeProtoBody(t, rec)
		cert, ok := payload["certificate"].(map[string]interface{})
		require.True(t, ok, "payload.certificate should be an object")
		subject, ok := cert["subject"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "test.example.com", subject["commonName"])
	})

	t.Run("issues certificate with full request", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			issueCertificateFn: func(request *xkmsca.CertificateRequest) (*xkmsca.IssuedCertificate, error) {
				return &xkmsca.IssuedCertificate{Certificate: createTestCertificate(request.Subject.CommonName)}, nil
			},
		}
		handlers, writer := newTestHandlers(mockCA)

		// Proto-shaped request body. KeyAlgorithm uses the enum name.
		body := []byte(`{"request":{
			"subject":{"commonName":"server.example.com","organization":"Example Corp","country":"US"},
			"sans":{"dnsNames":["server.example.com","api.example.com"],"ipAddresses":["192.168.1.1"]},
			"validDays":365,
			"keyAlgorithm":"KEY_ALGORITHM_ECDSA_P256",
			"storeType":"software",
			"keyUsage":["digitalSignature","keyEncipherment"],
			"extKeyUsage":["serverAuth","clientAuth"]
		}}`)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handlers.IssueCertificate(rec, req)

		assert.Equal(t, http.StatusCreated, writer.lastStatus)
	})

	t.Run("issues CA certificate", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			issueCertificateFn: func(request *xkmsca.CertificateRequest) (*xkmsca.IssuedCertificate, error) {
				cert := createTestCertificate(request.Subject.CommonName)
				cert.IsCA = request.IsCA
				return &xkmsca.IssuedCertificate{Certificate: cert}, nil
			},
		}
		handlers, writer := newTestHandlers(mockCA)

		// Proto field name is `is_ca` (jsonName: isCa).
		body := []byte(`{"request":{
			"subject":{"commonName":"Intermediate CA"},
			"isCa":true,
			"maxPathLen":1,
			"keyUsage":["certSign","crlSign"]
		}}`)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handlers.IssueCertificate(rec, req)

		assert.Equal(t, http.StatusCreated, writer.lastStatus)
	})
}

func TestIssueCertificate_Error(t *testing.T) {
	t.Run("returns error when CA is nil", func(t *testing.T) {
		handlers, writer := newTestHandlers(nil)

		body := []byte(`{"request":{"subject":{"commonName":"test.com"}}}`)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handlers.IssueCertificate(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{initialized: true}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handlers.IssueCertificate(rec, req)

		assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
		// Body parsing now goes through protorest.DecodeRequest which wraps
		// the protojson error in *protorest.ErrInvalidJSON.
		require.NotNil(t, writer.lastError)
	})

	t.Run("returns error when common name is missing", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{initialized: true}
		handlers, writer := newTestHandlers(mockCA)

		body := []byte(`{"request":{"subject":{"commonName":""}}}`)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handlers.IssueCertificate(rec, req)

		assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
		require.NotNil(t, writer.lastError)
		assert.Contains(t, writer.lastError.Error(), "common name")
	})

	t.Run("returns error for invalid key algorithm", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{initialized: true}
		handlers, writer := newTestHandlers(mockCA)

		// Numeric enum values out of the declared range pass through
		// protojson decoding as the raw int but fail the
		// protoKeyAlgorithmToX509 switch, surfacing
		// ErrInvalidKeyAlgorithm via gRPC InvalidArgument -> HTTP 400.
		body := []byte(`{"request":{
			"subject":{"commonName":"test.com"},
			"keyAlgorithm":99
		}}`)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handlers.IssueCertificate(rec, req)

		assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
		require.NotNil(t, writer.lastError)
	})

	t.Run("returns error when CA fails to issue", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			issueCertificateFn: func(request *xkmsca.CertificateRequest) (*xkmsca.IssuedCertificate, error) {
				return nil, errors.New("issuance failed")
			},
		}
		handlers, writer := newTestHandlers(mockCA)

		body := []byte(`{"request":{"subject":{"commonName":"test.com"}}}`)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handlers.IssueCertificate(rec, req)

		assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	})
}

// =============================================================================
// RevokeCertificate Handler Tests
// =============================================================================

func TestRevokeCertificate_Success(t *testing.T) {
	t.Run("revokes certificate", func(t *testing.T) {
		testCert := createTestCertificate("revoke.example.com")
		mockCertStore := &mockCertStore{
			getCertificateFn: func(cn string) (*x509.Certificate, error) {
				return testCert, nil
			},
		}

		mockCA := &mockCertificateAuthority{
			initialized: true,
			certStore:   mockCertStore,
			revokeFn: func(certificate *x509.Certificate, _ xkmsca.RevokeOptions) error {
				return nil
			},
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/abc123", nil)
		req = mux.SetURLVars(req, map[string]string{"serial": "abc123"})
		rec := httptest.NewRecorder()

		handlers.RevokeCertificate(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		payload := decodeProtoBody(t, rec)
		assert.Equal(t, "abc123", payload["serial"])
		// Proto certificateStatus is the enum CERTIFICATE_STATUS_REVOKED (jsonName camelCase).
		assert.Equal(t, "CERTIFICATE_STATUS_REVOKED", payload["certificateStatus"])
	})

	t.Run("revokes certificate with reason", func(t *testing.T) {
		testCert := createTestCertificate("revoke.example.com")
		mockCertStore := &mockCertStore{
			getCertificateFn: func(cn string) (*x509.Certificate, error) {
				return testCert, nil
			},
		}

		mockCA := &mockCertificateAuthority{
			initialized: true,
			certStore:   mockCertStore,
		}
		handlers, writer := newTestHandlers(mockCA)

		// Proto RevokeCertificateRequest uses RevocationReason enum.
		body := []byte(`{"reason":"REVOCATION_REASON_KEY_COMPROMISE","deleteKeys":false}`)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/abc123", bytes.NewReader(body))
		req = mux.SetURLVars(req, map[string]string{"serial": "abc123"})
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handlers.RevokeCertificate(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		payload := decodeProtoBody(t, rec)
		assert.Equal(t, "REVOCATION_REASON_KEY_COMPROMISE", payload["reason"])
	})

	t.Run("revokes certificate and deletes keys", func(t *testing.T) {
		testCert := createTestCertificate("revoke.example.com")
		mockCertStore := &mockCertStore{
			getCertificateFn: func(cn string) (*x509.Certificate, error) {
				return testCert, nil
			},
		}

		var capturedDeleteKeys bool
		mockCA := &mockCertificateAuthority{
			initialized: true,
			certStore:   mockCertStore,
			revokeFn: func(_ *x509.Certificate, opts xkmsca.RevokeOptions) error {
				capturedDeleteKeys = opts.DeleteKeys
				return nil
			},
		}
		handlers, writer := newTestHandlers(mockCA)

		body := []byte(`{"reason":"REVOCATION_REASON_AFFILIATION_CHANGED","deleteKeys":true}`)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/abc123", bytes.NewReader(body))
		req = mux.SetURLVars(req, map[string]string{"serial": "abc123"})
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handlers.RevokeCertificate(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		assert.True(t, capturedDeleteKeys)
	})
}

func TestRevokeCertificate_Error(t *testing.T) {
	t.Run("returns error when CA is nil", func(t *testing.T) {
		handlers, writer := newTestHandlers(nil)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/abc123", nil)
		req = mux.SetURLVars(req, map[string]string{"serial": "abc123"})
		rec := httptest.NewRecorder()

		handlers.RevokeCertificate(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
	})

	t.Run("returns error when serial is empty", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{initialized: true}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/", nil)
		req = mux.SetURLVars(req, map[string]string{"serial": ""})
		rec := httptest.NewRecorder()

		handlers.RevokeCertificate(rec, req)

		assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	})

	t.Run("returns 404 when certificate not found", func(t *testing.T) {
		mockCertStore := &mockCertStore{
			getCertificateFn: func(cn string) (*x509.Certificate, error) {
				return nil, errors.New("not found")
			},
		}

		mockCA := &mockCertificateAuthority{
			initialized: true,
			certStore:   mockCertStore,
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/nonexistent", nil)
		req = mux.SetURLVars(req, map[string]string{"serial": "nonexistent"})
		rec := httptest.NewRecorder()

		handlers.RevokeCertificate(rec, req)

		assert.Equal(t, http.StatusNotFound, writer.lastStatus)
	})

	t.Run("returns error for invalid request body", func(t *testing.T) {
		testCert := createTestCertificate("test.com")
		mockCertStore := &mockCertStore{
			getCertificateFn: func(cn string) (*x509.Certificate, error) {
				return testCert, nil
			},
		}

		mockCA := &mockCertificateAuthority{
			initialized: true,
			certStore:   mockCertStore,
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/abc123", bytes.NewReader([]byte("invalid json")))
		req = mux.SetURLVars(req, map[string]string{"serial": "abc123"})
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = 12
		rec := httptest.NewRecorder()

		handlers.RevokeCertificate(rec, req)

		assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	})

	t.Run("returns error when revocation fails", func(t *testing.T) {
		testCert := createTestCertificate("test.com")
		mockCertStore := &mockCertStore{
			getCertificateFn: func(cn string) (*x509.Certificate, error) {
				return testCert, nil
			},
		}

		mockCA := &mockCertificateAuthority{
			initialized: true,
			certStore:   mockCertStore,
			revokeFn: func(certificate *x509.Certificate, _ xkmsca.RevokeOptions) error {
				return errors.New("revocation failed")
			},
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/ca/certificates/abc123", nil)
		req = mux.SetURLVars(req, map[string]string{"serial": "abc123"})
		rec := httptest.NewRecorder()

		handlers.RevokeCertificate(rec, req)

		assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	})
}

// =============================================================================
// GetBundle Handler Tests
// =============================================================================

func TestGetBundle_Success(t *testing.T) {
	t.Run("returns CA bundle", func(t *testing.T) {
		rootCert := createTestRootCertificate()
		mockCA := &mockCertificateAuthority{
			initialized: true,
			rootCert:    rootCert,
			caBundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				return []byte("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"), nil
			},
			parseBundleFn: func(bundle []byte) ([]*x509.Certificate, error) {
				return []*x509.Certificate{rootCert}, nil
			},
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle", nil)
		rec := httptest.NewRecorder()

		handlers.GetBundle(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		payload := decodeProtoBody(t, rec)
		bundle, ok := payload["bundle"].(map[string]interface{})
		require.True(t, ok, "payload.bundle should be an object")
		// Proto bundle.pem is `bytes` so protojson encodes it as base64.
		assert.NotEmpty(t, bundle["pem"])
		assert.GreaterOrEqual(t, int(bundle["certCount"].(float64)), 1)
	})

	t.Run("respects store_type parameter", func(t *testing.T) {
		var capturedStoreType xkmssdk.StoreType
		mockCA := &mockCertificateAuthority{
			initialized: true,
			caBundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				capturedStoreType = storeType
				return []byte("bundle"), nil
			},
			parseBundleFn: func(bundle []byte) ([]*x509.Certificate, error) {
				return []*x509.Certificate{}, nil
			},
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle?store_type=software", nil)
		rec := httptest.NewRecorder()

		handlers.GetBundle(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		assert.Equal(t, xkmssdk.StoreSoftware, capturedStoreType)
	})

	t.Run("respects algorithm parameter", func(t *testing.T) {
		var capturedAlgorithm x509.PublicKeyAlgorithm
		mockCA := &mockCertificateAuthority{
			initialized: true,
			caBundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				capturedAlgorithm = keyAlgorithm
				return []byte("bundle"), nil
			},
			parseBundleFn: func(bundle []byte) ([]*x509.Certificate, error) {
				return []*x509.Certificate{}, nil
			},
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle?algorithm=ECDSA", nil)
		rec := httptest.NewRecorder()

		handlers.GetBundle(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		assert.Equal(t, x509.ECDSA, capturedAlgorithm)
	})
}

func TestGetBundle_Error(t *testing.T) {
	t.Run("returns error when CA is nil", func(t *testing.T) {
		handlers, writer := newTestHandlers(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle", nil)
		rec := httptest.NewRecorder()

		handlers.GetBundle(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
	})

	t.Run("returns error for invalid algorithm", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{initialized: true}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle?algorithm=INVALID", nil)
		rec := httptest.NewRecorder()

		handlers.GetBundle(rec, req)

		assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	})

	t.Run("returns 404 when bundle is empty", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			caBundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				return []byte{}, nil
			},
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle", nil)
		rec := httptest.NewRecorder()

		handlers.GetBundle(rec, req)

		assert.Equal(t, http.StatusNotFound, writer.lastStatus)
	})

	t.Run("returns error when CA bundle fails", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			caBundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				return nil, errors.New("bundle error")
			},
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle", nil)
		rec := httptest.NewRecorder()

		handlers.GetBundle(rec, req)

		assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	})
}

// =============================================================================
// GetCRL Handler Tests
// =============================================================================

func TestGetCRL_Success(t *testing.T) {
	t.Run("returns CRL when CA supports CRL generation", func(t *testing.T) {
		// Create a valid CRL
		crlDER, err := createTestCRL()
		require.NoError(t, err)

		mockCA := &mockCAWithCRLGenerator{
			mockCertificateAuthority: mockCertificateAuthority{
				initialized: true,
			},
			generateCRLFn: func() ([]byte, error) {
				return crlDER, nil
			},
		}

		logger := newTestLogger()
		writer := &mockHttpWriter{}
		handlers := NewCAHandlers(logger, mockCA, writer, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/crl", nil)
		rec := httptest.NewRecorder()

		handlers.GetCRL(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
		payload := decodeProtoBody(t, rec)
		crl, ok := payload["crl"].(map[string]interface{})
		require.True(t, ok, "payload.crl should be an object")
		assert.NotEmpty(t, crl["data"])
		assert.Equal(t, float64(1), crl["revokedCount"])
		revoked, ok := crl["revokedCerts"].([]interface{})
		require.True(t, ok, "payload.crl.revokedCerts should be an array")
		assert.NotEmpty(t, revoked)
	})
}

func TestGetCRL_Error(t *testing.T) {
	t.Run("returns error when CA is nil", func(t *testing.T) {
		handlers, writer := newTestHandlers(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/crl", nil)
		rec := httptest.NewRecorder()

		handlers.GetCRL(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
	})

	t.Run("returns error when CRL generation not supported", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
		}
		handlers, writer := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/crl", nil)
		rec := httptest.NewRecorder()

		handlers.GetCRL(rec, req)

		assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	})

	t.Run("returns error when CRL generation fails", func(t *testing.T) {
		mockCA := &mockCAWithCRLGenerator{
			mockCertificateAuthority: mockCertificateAuthority{
				initialized: true,
			},
			generateCRLFn: func() ([]byte, error) {
				return nil, errors.New("CRL generation failed")
			},
		}

		logger := newTestLogger()
		writer := &mockHttpWriter{}
		handlers := NewCAHandlers(logger, mockCA, writer, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/crl", nil)
		rec := httptest.NewRecorder()

		handlers.GetCRL(rec, req)

		assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	})

	t.Run("returns error when CRL parsing fails", func(t *testing.T) {
		mockCA := &mockCAWithCRLGenerator{
			mockCertificateAuthority: mockCertificateAuthority{
				initialized: true,
			},
			generateCRLFn: func() ([]byte, error) {
				return []byte("invalid CRL data"), nil
			},
		}

		logger := newTestLogger()
		writer := &mockHttpWriter{}
		handlers := NewCAHandlers(logger, mockCA, writer, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/crl", nil)
		rec := httptest.NewRecorder()

		handlers.GetCRL(rec, req)

		assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	})
}

// =============================================================================
// Helper Method Tests
// =============================================================================

func TestParseKeyAlgorithm(t *testing.T) {
	mockCA := &mockCertificateAuthority{}
	handlers, _ := newTestHandlers(mockCA)

	testCases := []struct {
		input    string
		expected x509.PublicKeyAlgorithm
		hasError bool
	}{
		{"RSA", x509.RSA, false},
		{"rsa", x509.RSA, false},
		{"RSA2048", x509.RSA, false},
		{"RSA-2048", x509.RSA, false},
		{"RSA4096", x509.RSA, false},
		{"ECDSA", x509.ECDSA, false},
		{"ecdsa", x509.ECDSA, false},
		{"EC", x509.ECDSA, false},
		{"P256", x509.ECDSA, false},
		{"P384", x509.ECDSA, false},
		{"ED25519", x509.Ed25519, false},
		{"", x509.ECDSA, false},  // Default
		{"INVALID", 0, true},     // Invalid
		{"MD5", 0, true},         // Invalid
		{"UNKNOWN-ALG", 0, true}, // Invalid
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result, err := handlers.parseKeyAlgorithm(tc.input)
			if tc.hasError {
				assert.Error(t, err)
				assert.IsType(t, ErrInvalidKeyAlgorithm{}, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestKeyAlgorithmToString(t *testing.T) {
	mockCA := &mockCertificateAuthority{}
	handlers, _ := newTestHandlers(mockCA)

	testCases := []struct {
		input    x509.PublicKeyAlgorithm
		expected string
	}{
		{x509.RSA, "RSA"},
		{x509.ECDSA, "ECDSA"},
		{x509.Ed25519, "ED25519"},
		{x509.PublicKeyAlgorithm(99), "UNKNOWN"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := handlers.keyAlgorithmToString(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseKeyUsage(t *testing.T) {
	mockCA := &mockCertificateAuthority{}
	handlers, _ := newTestHandlers(mockCA)

	t.Run("parses multiple key usages", func(t *testing.T) {
		usages := []string{"digitalSignature", "keyEncipherment", "certSign"}
		result := handlers.parseKeyUsage(usages)

		assert.True(t, result&x509.KeyUsageDigitalSignature != 0)
		assert.True(t, result&x509.KeyUsageKeyEncipherment != 0)
		assert.True(t, result&x509.KeyUsageCertSign != 0)
	})

	t.Run("handles underscore format", func(t *testing.T) {
		usages := []string{"DIGITAL_SIGNATURE", "KEY_ENCIPHERMENT"}
		result := handlers.parseKeyUsage(usages)

		assert.True(t, result&x509.KeyUsageDigitalSignature != 0)
		assert.True(t, result&x509.KeyUsageKeyEncipherment != 0)
	})

	t.Run("handles empty list", func(t *testing.T) {
		usages := []string{}
		result := handlers.parseKeyUsage(usages)
		assert.Equal(t, x509.KeyUsage(0), result)
	})

	t.Run("parses all key usage types", func(t *testing.T) {
		usages := []string{
			"contentCommitment",
			"CONTENT_COMMITMENT",
			"dataEncipherment",
			"DATA_ENCIPHERMENT",
			"keyAgreement",
			"KEY_AGREEMENT",
			"crlSign",
			"CRL_SIGN",
			"encipherOnly",
			"ENCIPHER_ONLY",
			"decipherOnly",
			"DECIPHER_ONLY",
		}
		result := handlers.parseKeyUsage(usages)

		assert.True(t, result&x509.KeyUsageContentCommitment != 0)
		assert.True(t, result&x509.KeyUsageDataEncipherment != 0)
		assert.True(t, result&x509.KeyUsageKeyAgreement != 0)
		assert.True(t, result&x509.KeyUsageCRLSign != 0)
		assert.True(t, result&x509.KeyUsageEncipherOnly != 0)
		assert.True(t, result&x509.KeyUsageDecipherOnly != 0)
	})

	t.Run("ignores unknown key usages", func(t *testing.T) {
		usages := []string{"unknown", "digitalSignature", "invalid"}
		result := handlers.parseKeyUsage(usages)

		assert.True(t, result&x509.KeyUsageDigitalSignature != 0)
		// Unknown usages are silently ignored
	})
}

func TestParseExtKeyUsage(t *testing.T) {
	mockCA := &mockCertificateAuthority{}
	handlers, _ := newTestHandlers(mockCA)

	t.Run("parses multiple ext key usages", func(t *testing.T) {
		usages := []string{"serverAuth", "clientAuth", "codeSigning"}
		result := handlers.parseExtKeyUsage(usages)

		assert.Contains(t, result, x509.ExtKeyUsageServerAuth)
		assert.Contains(t, result, x509.ExtKeyUsageClientAuth)
		assert.Contains(t, result, x509.ExtKeyUsageCodeSigning)
	})

	t.Run("handles underscore format", func(t *testing.T) {
		usages := []string{"SERVER_AUTH", "CLIENT_AUTH"}
		result := handlers.parseExtKeyUsage(usages)

		assert.Contains(t, result, x509.ExtKeyUsageServerAuth)
		assert.Contains(t, result, x509.ExtKeyUsageClientAuth)
	})

	t.Run("handles empty list", func(t *testing.T) {
		usages := []string{}
		result := handlers.parseExtKeyUsage(usages)
		assert.Empty(t, result)
	})

	t.Run("parses all ext key usage types", func(t *testing.T) {
		usages := []string{
			"any",
			"ANY",
			"emailProtection",
			"EMAIL_PROTECTION",
			"timeStamping",
			"TIME_STAMPING",
			"ocspSigning",
			"OCSP_SIGNING",
		}
		result := handlers.parseExtKeyUsage(usages)

		assert.Contains(t, result, x509.ExtKeyUsageAny)
		assert.Contains(t, result, x509.ExtKeyUsageEmailProtection)
		assert.Contains(t, result, x509.ExtKeyUsageTimeStamping)
		assert.Contains(t, result, x509.ExtKeyUsageOCSPSigning)
	})

	t.Run("ignores unknown ext key usages", func(t *testing.T) {
		usages := []string{"unknown", "serverAuth", "invalid"}
		result := handlers.parseExtKeyUsage(usages)

		assert.Contains(t, result, x509.ExtKeyUsageServerAuth)
		assert.Len(t, result, 1) // Only serverAuth
	})
}

func TestGetPaginationParams(t *testing.T) {
	mockCA := &mockCertificateAuthority{}
	handlers, _ := newTestHandlers(mockCA)

	t.Run("uses defaults when no params", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		limit, cursor := handlers.getPaginationParams(req)

		assert.Equal(t, int32(50), limit) // defaultLimit
		assert.Equal(t, "", cursor)
	})

	t.Run("parses limit parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?limit=100", nil)
		limit, _ := handlers.getPaginationParams(req)

		assert.Equal(t, int32(100), limit)
	})

	t.Run("parses cursor parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?cursor=abc123", nil)
		_, cursor := handlers.getPaginationParams(req)

		assert.Equal(t, "abc123", cursor)
	})

	t.Run("caps limit at maximum", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?limit=5000", nil)
		limit, _ := handlers.getPaginationParams(req)

		assert.Equal(t, int32(1000), limit) // maxLimit
	})

	t.Run("uses default for invalid limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?limit=invalid", nil)
		limit, _ := handlers.getPaginationParams(req)

		assert.Equal(t, int32(50), limit) // defaultLimit
	})

	t.Run("uses default for negative limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?limit=-10", nil)
		limit, _ := handlers.getPaginationParams(req)

		assert.Equal(t, int32(50), limit) // defaultLimit
	})
}

func TestCertToResponse(t *testing.T) {
	mockCA := &mockCertificateAuthority{}
	handlers, _ := newTestHandlers(mockCA)

	t.Run("converts valid certificate", func(t *testing.T) {
		cert := createTestCertificate("test.example.com")
		result := handlers.certToResponse(cert)

		require.NotNil(t, result)
		assert.Equal(t, "test.example.com", result.Subject.CommonName)
		assert.Equal(t, "Test CA", result.Issuer)
		assert.Equal(t, "ECDSA", result.KeyAlgorithm)
		assert.Equal(t, "VALID", result.Status)
	})

	t.Run("returns nil for nil certificate", func(t *testing.T) {
		result := handlers.certToResponse(nil)
		assert.Nil(t, result)
	})

	t.Run("detects expired certificate", func(t *testing.T) {
		cert := createTestCertificate("expired.example.com")
		cert.NotAfter = time.Now().Add(-24 * time.Hour)
		result := handlers.certToResponse(cert)

		assert.Equal(t, "EXPIRED", result.Status)
	})

	t.Run("detects not yet valid certificate", func(t *testing.T) {
		cert := createTestCertificate("future.example.com")
		cert.NotBefore = time.Now().Add(24 * time.Hour)
		result := handlers.certToResponse(cert)

		assert.Equal(t, "NOT_YET_VALID", result.Status)
	})
}

func TestCertToSummary(t *testing.T) {
	mockCA := &mockCertificateAuthority{}
	handlers, _ := newTestHandlers(mockCA)

	t.Run("converts valid certificate", func(t *testing.T) {
		cert := createTestCertificate("test.example.com")
		result := handlers.certToSummary(cert)

		assert.Equal(t, "test.example.com", result.CommonName)
		assert.Equal(t, "Test CA", result.Issuer)
		assert.Equal(t, "ECDSA", result.KeyAlgorithm)
		assert.Equal(t, "VALID", result.Status)
	})

	t.Run("returns empty for nil certificate", func(t *testing.T) {
		result := handlers.certToSummary(nil)
		assert.Empty(t, result.Serial)
		assert.Empty(t, result.CommonName)
	})

	t.Run("detects expired certificate in summary", func(t *testing.T) {
		cert := createTestCertificate("expired.example.com")
		cert.NotAfter = time.Now().Add(-24 * time.Hour)
		result := handlers.certToSummary(cert)

		assert.Equal(t, "EXPIRED", result.Status)
	})

	t.Run("detects not yet valid certificate in summary", func(t *testing.T) {
		cert := createTestCertificate("future.example.com")
		cert.NotBefore = time.Now().Add(24 * time.Hour)
		result := handlers.certToSummary(cert)

		assert.Equal(t, "NOT_YET_VALID", result.Status)
	})
}

func TestFirstOrEmpty(t *testing.T) {
	t.Run("returns first element", func(t *testing.T) {
		result := firstOrEmpty([]string{"first", "second"})
		assert.Equal(t, "first", result)
	})

	t.Run("returns empty for empty slice", func(t *testing.T) {
		result := firstOrEmpty([]string{})
		assert.Empty(t, result)
	})

	t.Run("returns empty for nil slice", func(t *testing.T) {
		result := firstOrEmpty(nil)
		assert.Empty(t, result)
	})
}
