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

package system

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockCertificateAuthority is a simple mock that only implements methods used by the system handlers
type mockCertificateAuthority struct {
	mock.Mock
	trustedca.CACertificateAuthority // Embed to satisfy interface
}

func (m *mockCertificateAuthority) Certificate(ctx context.Context, keyAttrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	args := m.Called(ctx, keyAttrs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (m *mockCertificateAuthority) PEM(ctx context.Context, keyAttrs *xkmssdk.KeyAttributes) ([]byte, error) {
	args := m.Called(ctx, keyAttrs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockCertificateAuthority) CABundle() ([]byte, error) {
	return m.CABundleFiltered(xkmssdk.StoreUnknown, 0)
}
func (m *mockCertificateAuthority) CABundleFiltered(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
	args := m.Called(storeType, keyAlgorithm)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockCertificateAuthority) CAConfig() xkmsca.CAConfig {
	args := m.Called()
	return args.Get(0).(xkmsca.CAConfig)
}

// mockTrustedPlatformModule is a simple mock that only implements methods used by system.TPMInfo
type mockTrustedPlatformModule struct {
	mock.Mock
	xkmssdk.TrustedPlatformModule // Embed to satisfy interface
}

func (m *mockTrustedPlatformModule) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*xkmssdk.PropertiesFixed), args.Error(1)
}

func (m *mockTrustedPlatformModule) Info() (string, error) {
	args := m.Called()
	return args.Get(0).(string), args.Error(1)
}

func (m *mockTrustedPlatformModule) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*xkmssdk.KeyAttributes), args.Error(1)
}

func (m *mockTrustedPlatformModule) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*xkmssdk.KeyAttributes), args.Error(1)
}

// mockHttpWriter mocks the HttpWriter interface
type mockHttpWriter struct {
	mock.Mock
}

func (m *mockHttpWriter) Write(w http.ResponseWriter, r *http.Request, status int, response interface{}) {
	m.Called(w, r, status, response)
}

func (m *mockHttpWriter) WriteYaml(w http.ResponseWriter, status int, response interface{}) {
	m.Called(w, status, response)
}

func (m *mockHttpWriter) WriteJson(w http.ResponseWriter, status int, response interface{}) {
	m.Called(w, status, response)
}

func (m *mockHttpWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.Called(w, r, payload)
}

func (m *mockHttpWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.Success200(w, r, payload)
}

func (m *mockHttpWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	m.Called(w, r, payload, err)
}

func (m *mockHttpWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *mockHttpWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *mockHttpWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *mockHttpWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *mockHttpWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.Called(w, r, err, payload)
}

func (m *mockHttpWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

// Test helper functions

func createTestCertificate(t *testing.T) *x509.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.localhost",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	return cert
}

func createTestKeyAttributes() *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:           "test.localhost",
		KeyType:      xkmssdk.KeyTypeTLS,
		StoreType:    xkmssdk.StoreSoftware,
		KeyAlgorithm: x509.ECDSA,
		Hash:         crypto.SHA256,
	}
}

func createTestCAConfig() *trustedca.CAConfig {
	return &trustedca.CAConfig{
		Identity: []trustedca.CAIdentity{
			{
				Subject: trustedca.CASubject{
					CommonName:   "Test Root CA",
					Organization: "Test Org",
					Country:      "US",
				},
				Valid: 10,
				Keys: []*xkmssdk.KeyConfig{
					{
						KeyAlgorithm: "RSA",
						RSAConfig:    &xkmssdk.KeyRSAConfig{KeySize: 2048},
					},
				},
				KeystoreType: xkmssdk.StoreSoftware,
			},
		},
		SelectedCA: 0,
	}
}

// Test NewHandler
func TestNewHandler(t *testing.T) {
	mockCA := new(mockCertificateAuthority)
	mockTPM := new(mockTrustedPlatformModule)
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()
	keyAttrs := createTestKeyAttributes()
	caConfig := createTestCAConfig()

	handler := NewHandler(mockCA, caConfig, keyAttrs, mockWriter, logger, mockTPM)

	assert.NotNil(t, handler)
	assert.NotNil(t, handler.(*Handler).ca)
	assert.NotNil(t, handler.(*Handler).caConfig)
	assert.NotNil(t, handler.(*Handler).httpWriter)
	assert.NotNil(t, handler.(*Handler).logger)
	assert.NotNil(t, handler.(*Handler).serverKeyAttributes)
	assert.NotNil(t, handler.(*Handler).tpm)
}

// Test PublicKey - Success
func TestPublicKey_Success(t *testing.T) {
	mockCA := new(mockCertificateAuthority)
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()
	keyAttrs := createTestKeyAttributes()

	cert := createTestCertificate(t)
	pubPEM, err := xkmssdk.EncodePubKeyPEM(cert.PublicKey)
	assert.NoError(t, err)

	mockCA.On("Certificate", mock.Anything, keyAttrs).Return(cert, nil)
	mockWriter.On("Write", mock.Anything, mock.Anything, http.StatusOK, string(pubPEM)).Return()

	handler := NewHandler(mockCA, nil, keyAttrs, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/public-key", nil)
	w := httptest.NewRecorder()

	handler.PublicKey(w, req)

	mockCA.AssertExpectations(t)
	mockWriter.AssertExpectations(t)
}

// Test PublicKey - Certificate Not Found
func TestPublicKey_CertNotFound(t *testing.T) {
	mockCA := new(mockCertificateAuthority)
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()
	keyAttrs := createTestKeyAttributes()

	mockCA.On("Certificate", mock.Anything, keyAttrs).Return(nil, xkmssdk.ErrCertNotFound)
	mockWriter.On("Error404", mock.Anything, mock.Anything, xkmssdk.ErrCertNotFound).Return()

	handler := NewHandler(mockCA, nil, keyAttrs, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/public-key", nil)
	w := httptest.NewRecorder()

	handler.PublicKey(w, req)

	mockCA.AssertExpectations(t)
	mockWriter.AssertExpectations(t)
}

// Test PublicKey - CA Error
func TestPublicKey_CAError(t *testing.T) {
	mockCA := new(mockCertificateAuthority)
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()
	keyAttrs := createTestKeyAttributes()

	expectedErr := errors.New("CA error")
	mockCA.On("Certificate", mock.Anything, keyAttrs).Return(nil, expectedErr)
	mockWriter.On("Error500", mock.Anything, mock.Anything, expectedErr).Return()

	handler := NewHandler(mockCA, nil, keyAttrs, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/public-key", nil)
	w := httptest.NewRecorder()

	handler.PublicKey(w, req)

	mockCA.AssertExpectations(t)
	mockWriter.AssertExpectations(t)
}

// Test PublicKey - Encoding Error
func TestPublicKey_EncodingError(t *testing.T) {
	mockCA := new(mockCertificateAuthority)
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()
	keyAttrs := createTestKeyAttributes()

	// Create a certificate with an invalid public key type that will fail encoding
	cert := &x509.Certificate{
		PublicKey: "invalid-key-type", // This will cause EncodePubKeyPEM to fail
	}

	mockCA.On("Certificate", mock.Anything, keyAttrs).Return(cert, nil)
	mockWriter.On("Error500", mock.Anything, mock.Anything, mock.AnythingOfType("*errors.errorString")).Return()

	handler := NewHandler(mockCA, nil, keyAttrs, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/public-key", nil)
	w := httptest.NewRecorder()

	handler.PublicKey(w, req)

	mockCA.AssertExpectations(t)
	mockWriter.AssertExpectations(t)
}

// Test Certificate - Success
func TestCertificate_Success(t *testing.T) {
	mockCA := new(mockCertificateAuthority)
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()
	keyAttrs := createTestKeyAttributes()

	certPEM := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	mockCA.On("PEM", mock.Anything, keyAttrs).Return(certPEM, nil)
	mockWriter.On("Write", mock.Anything, mock.Anything, http.StatusOK, string(certPEM)).Return()

	handler := NewHandler(mockCA, nil, keyAttrs, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/certificate", nil)
	w := httptest.NewRecorder()

	handler.Certificate(w, req)

	mockCA.AssertExpectations(t)
	mockWriter.AssertExpectations(t)
}

// Test Certificate - Not Found
func TestCertificate_NotFound(t *testing.T) {
	mockCA := new(mockCertificateAuthority)
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()
	keyAttrs := createTestKeyAttributes()

	mockCA.On("PEM", mock.Anything, keyAttrs).Return(nil, xkmssdk.ErrCertNotFound)
	mockWriter.On("Error404", mock.Anything, mock.Anything, xkmssdk.ErrCertNotFound).Return()

	handler := NewHandler(mockCA, nil, keyAttrs, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/certificate", nil)
	w := httptest.NewRecorder()

	handler.Certificate(w, req)

	mockCA.AssertExpectations(t)
	mockWriter.AssertExpectations(t)
}

// Test Certificate - CA Error
func TestCertificate_CAError(t *testing.T) {
	mockCA := new(mockCertificateAuthority)
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()
	keyAttrs := createTestKeyAttributes()

	expectedErr := errors.New("CA error")
	mockCA.On("PEM", mock.Anything, keyAttrs).Return(nil, expectedErr)
	mockWriter.On("Error500", mock.Anything, mock.Anything, expectedErr).Return()

	handler := NewHandler(mockCA, nil, keyAttrs, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/certificate", nil)
	w := httptest.NewRecorder()

	handler.Certificate(w, req)

	mockCA.AssertExpectations(t)
	mockWriter.AssertExpectations(t)
}

// Test CABundleHandler - Success
func TestCABundleHandler_Success(t *testing.T) {
	mockCA := new(mockCertificateAuthority)
	logger := logging.DefaultLogger()

	bundlePEM := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	mockCA.On("CABundleFiltered", xkmssdk.StoreUnknown, x509.PublicKeyAlgorithm(0)).Return(bundlePEM, nil)

	handler := NewHandler(mockCA, nil, nil, nil, logger, nil)

	req := httptest.NewRequest("GET", "/system/ca-bundle", nil)
	w := httptest.NewRecorder()

	handler.CABundleHandler(w, req)

	mockCA.AssertExpectations(t)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "application/pem-certificate-chain", w.Header().Get("Content-Type"))
	assert.Equal(t, bundlePEM, w.Body.Bytes())
}

// Test CABundleHandler - CA Error
func TestCABundleHandler_CAError(t *testing.T) {
	mockCA := new(mockCertificateAuthority)
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()

	expectedErr := errors.New("CA error")
	mockCA.On("CABundleFiltered", xkmssdk.StoreUnknown, x509.PublicKeyAlgorithm(0)).Return(nil, expectedErr)
	mockWriter.On("Write", mock.Anything, mock.Anything, http.StatusInternalServerError, "CA error").Return()

	handler := NewHandler(mockCA, nil, nil, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/ca-bundle", nil)
	w := httptest.NewRecorder()

	handler.CABundleHandler(w, req)

	mockCA.AssertExpectations(t)
	mockWriter.AssertExpectations(t)
}

// Test Config
func TestConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewHandler(nil, nil, nil, nil, logger, nil)

	req := httptest.NewRequest("GET", "/system/config", nil)
	w := httptest.NewRecorder()

	// Config handler currently does nothing, just verify it doesn't panic
	handler.Config(w, req)
}

// Test Status - Success with TPM and CA
func TestStatus_Success(t *testing.T) {
	mockCA := new(mockCertificateAuthority)
	mockTPM := new(mockTrustedPlatformModule)
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()
	caConfig := createTestCAConfig()

	// Set up TPM mocks
	fixedProps := &xkmssdk.PropertiesFixed{
		Manufacturer: "Test Manufacturer",
		FwMajor:      1,
		FwMinor:      2,
		Family:       "2.0",
	}
	mockTPM.On("FixedProperties").Return(fixedProps, nil)
	mockTPM.On("Info").Return("Test TPM", nil)
	mockTPM.On("EKAttributes").Return(&xkmssdk.KeyAttributes{}, nil)
	mockTPM.On("SSRKAttributes").Return(&xkmssdk.KeyAttributes{}, nil)

	mockWriter.On("Success200", mock.Anything, mock.Anything, mock.MatchedBy(func(status entities.System) bool {
		// Verify system status has expected fields
		return status.Runtime != nil &&
			status.TPM != nil &&
			status.CA != nil &&
			status.OS != nil &&
			status.Network != nil
	})).Return()

	handler := NewHandler(mockCA, caConfig, nil, mockWriter, logger, mockTPM)

	req := httptest.NewRequest("GET", "/system/status", nil)
	w := httptest.NewRecorder()

	handler.Status(w, req)

	mockTPM.AssertExpectations(t)
	mockWriter.AssertExpectations(t)
}

// Test Status - Success without TPM
func TestStatus_SuccessNoTPM(t *testing.T) {
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()
	caConfig := createTestCAConfig()

	mockWriter.On("Success200", mock.Anything, mock.Anything, mock.MatchedBy(func(status entities.System) bool {
		// Verify TPM is nil when not provided
		return status.Runtime != nil &&
			status.TPM == nil &&
			status.CA != nil
	})).Return()

	handler := NewHandler(nil, caConfig, nil, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/status", nil)
	w := httptest.NewRecorder()

	handler.Status(w, req)

	mockWriter.AssertExpectations(t)
}

// Test Status - Success without CA
func TestStatus_SuccessNoCA(t *testing.T) {
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()

	mockWriter.On("Success200", mock.Anything, mock.Anything, mock.MatchedBy(func(status entities.System) bool {
		// Verify CA is nil when not provided
		return status.Runtime != nil && status.CA == nil
	})).Return()

	handler := NewHandler(nil, nil, nil, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/status", nil)
	w := httptest.NewRecorder()

	handler.Status(w, req)

	mockWriter.AssertExpectations(t)
}

// Test EventsPage - Success
func TestEventsPage_Success(t *testing.T) {
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()

	mockWriter.On("Success200", mock.Anything, mock.Anything, 42).Return()

	handler := NewHandler(nil, nil, nil, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/events/42", nil)
	req = mux.SetURLVars(req, map[string]string{"page": "42"})
	w := httptest.NewRecorder()

	handler.EventsPage(w, req)

	mockWriter.AssertExpectations(t)
}

// Test EventsPage - Invalid Page Number
func TestEventsPage_InvalidPageNumber(t *testing.T) {
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()

	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.AnythingOfType("*strconv.NumError")).Return()

	handler := NewHandler(nil, nil, nil, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/events/invalid", nil)
	req = mux.SetURLVars(req, map[string]string{"page": "invalid"})
	w := httptest.NewRecorder()

	handler.EventsPage(w, req)

	mockWriter.AssertExpectations(t)
}

// Test EventsPage - Negative Page Number
func TestEventsPage_NegativePageNumber(t *testing.T) {
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()

	// Even negative numbers are successfully parsed, the handler accepts them
	mockWriter.On("Success200", mock.Anything, mock.Anything, -1).Return()

	handler := NewHandler(nil, nil, nil, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/events/-1", nil)
	req = mux.SetURLVars(req, map[string]string{"page": "-1"})
	w := httptest.NewRecorder()

	handler.EventsPage(w, req)

	mockWriter.AssertExpectations(t)
}

// Test EventsPage - Zero Page Number
func TestEventsPage_ZeroPageNumber(t *testing.T) {
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()

	mockWriter.On("Success200", mock.Anything, mock.Anything, 0).Return()

	handler := NewHandler(nil, nil, nil, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/events/0", nil)
	req = mux.SetURLVars(req, map[string]string{"page": "0"})
	w := httptest.NewRecorder()

	handler.EventsPage(w, req)

	mockWriter.AssertExpectations(t)
}

// Test EventsPage - Large Page Number
func TestEventsPage_LargePageNumber(t *testing.T) {
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()

	mockWriter.On("Success200", mock.Anything, mock.Anything, 999999).Return()

	handler := NewHandler(nil, nil, nil, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/events/999999", nil)
	req = mux.SetURLVars(req, map[string]string{"page": "999999"})
	w := httptest.NewRecorder()

	handler.EventsPage(w, req)

	mockWriter.AssertExpectations(t)
}

// Integration test for Status with real system.SystemInfo
func TestStatus_Integration(t *testing.T) {
	logger := logging.DefaultLogger()

	// Use real response writer for integration test
	httpWriter := response.NewResponseWriter(logger, nil)

	handler := NewHandler(nil, nil, nil, httpWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/status", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	handler.Status(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	// Response should contain system info
	body := w.Body.String()
	assert.NotEmpty(t, body)
	assert.Contains(t, body, "\"success\":true")
}

// Test TPM status integration
func TestStatus_TPMInfo(t *testing.T) {
	mockTPM := new(mockTrustedPlatformModule)
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()

	// Mock TPM with simulated device
	fixedProps := &xkmssdk.PropertiesFixed{
		Manufacturer: "IBM",
		FwMajor:      1,
		FwMinor:      38,
		Family:       "2.0",
	}
	mockTPM.On("FixedProperties").Return(fixedProps, nil)
	mockTPM.On("Info").Return("IBM SW TPM Simulator", nil)
	mockTPM.On("EKAttributes").Return(&xkmssdk.KeyAttributes{}, nil)
	mockTPM.On("SSRKAttributes").Return(nil, errors.New("not found"))

	mockWriter.On("Success200", mock.Anything, mock.Anything, mock.MatchedBy(func(status entities.System) bool {
		// Verify TPM status is populated correctly
		if status.TPM == nil {
			return false
		}
		return status.TPM.Available &&
			status.TPM.Manufacturer == "IBM" &&
			status.TPM.FwVersion == "1.38" &&
			status.TPM.Simulated &&
			status.TPM.EKPresent &&
			!status.TPM.SRKPresent
	})).Return()

	handler := NewHandler(nil, nil, nil, mockWriter, logger, mockTPM)

	req := httptest.NewRequest("GET", "/system/status", nil)
	w := httptest.NewRecorder()

	handler.Status(w, req)

	mockTPM.AssertExpectations(t)
	mockWriter.AssertExpectations(t)
}

// Test CA status integration
func TestStatus_CAInfo(t *testing.T) {
	mockWriter := new(mockHttpWriter)
	logger := logging.DefaultLogger()

	caConfig := &trustedca.CAConfig{
		Identity: []trustedca.CAIdentity{
			{
				Subject: trustedca.CASubject{
					CommonName:   "Test Root CA",
					Organization: "Test Org",
					Country:      "US",
				},
				Valid: 10,
				Keys: []*xkmssdk.KeyConfig{
					{
						KeyAlgorithm:       "RSA",
						Hash:               "SHA-512",
						SignatureAlgorithm: "SHA512-RSA",
						RSAConfig:          &xkmssdk.KeyRSAConfig{KeySize: 4096},
					},
				},
				KeystoreType: xkmssdk.StoreSoftware,
				SANS: &trustedca.CASubjectAlternativeNames{
					DNS: []string{"ca.test.local"},
					IPs: []string{"192.168.1.1"},
				},
			},
		},
		SelectedCA: 0,
	}

	mockWriter.On("Success200", mock.Anything, mock.Anything, mock.MatchedBy(func(status entities.System) bool {
		// Verify CA status is populated correctly
		if status.CA == nil {
			return false
		}
		if status.CA.RootCA == nil {
			return false
		}
		return status.CA.Available &&
			status.CA.RootCA.CN == "Test Root CA" &&
			status.CA.RootCA.KeyAlgorithm == "RSA" &&
			status.CA.RootCA.KeySize == 4096 &&
			status.CA.RootCA.SignatureAlgorithm == "SHA512-RSA" &&
			status.CA.RootCA.Hash == "SHA-512"
	})).Return()

	handler := NewHandler(nil, caConfig, nil, mockWriter, logger, nil)

	req := httptest.NewRequest("GET", "/system/status", nil)
	w := httptest.NewRecorder()

	handler.Status(w, req)

	mockWriter.AssertExpectations(t)
}

// Test handler type assertion
func TestHandlerTypeAssertion(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewHandler(nil, nil, nil, nil, logger, nil)

	// Verify handler implements RestHandler interface (compile-time check via return type)
	_ = handler

	// Verify we can access the concrete type
	concreteHandler, ok := handler.(*Handler)
	assert.True(t, ok, "Should be able to cast to concrete Handler type")
	assert.NotNil(t, concreteHandler)
}

// Benchmark tests use real implementations to avoid mock issues with multiple invocations

func BenchmarkStatus(b *testing.B) {
	logger := logging.DefaultLogger()
	httpWriter := response.NewResponseWriter(logger, nil)
	caConfig := createTestCAConfig()

	handler := NewHandler(nil, caConfig, nil, httpWriter, logger, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/system/status", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()
		handler.Status(w, req)
	}
}

func BenchmarkEventsPage(b *testing.B) {
	logger := logging.DefaultLogger()
	httpWriter := response.NewResponseWriter(logger, nil)

	handler := NewHandler(nil, nil, nil, httpWriter, logger, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/system/events/42", nil)
		req = mux.SetURLVars(req, map[string]string{"page": "42"})
		w := httptest.NewRecorder()
		handler.EventsPage(w, req)
	}
}
