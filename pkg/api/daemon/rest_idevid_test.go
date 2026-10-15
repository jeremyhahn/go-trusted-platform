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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
)

// mockTPM2RESTService implements xkmssdk.TrustedPlatformModule for REST IDevID/IAK testing
type mockTPM2RESTService struct {
	xkmssdk.TrustedPlatformModule

	// Configuration for behavior
	hasIDevID             bool
	hasIAK                bool
	hasIDevIDCert         bool
	hasIAKCert            bool
	ekAttrsErr            error
	createIAKErr          error
	createIDevIDErr       error
	iakAttrsErr           error
	idevidAttrsErr        error
	readIDevIDCertErr     error
	readIAKCertErr        error
	writeIDevIDCertErr    error
	writeIAKCertErr       error
	deleteIDevIDCertErr   error
	deleteIAKCertErr      error
	createCSRErr          error
	activateCredentialErr error
	fixedPropsErr         error
}

func (m *mockTPM2RESTService) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	if m.ekAttrsErr != nil {
		return nil, m.ekAttrsErr
	}
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81010001,
		},
		KeyAlgorithm: x509.ECDSA,
	}, nil
}

func (m *mockTPM2RESTService) CreateIAK(ekAttrs *xkmssdk.KeyAttributes, qualifyingData []byte) (*xkmssdk.KeyAttributes, error) {
	if m.createIAKErr != nil {
		return nil, m.createIAKErr
	}
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81020001,
		},
		KeyAlgorithm: x509.ECDSA,
	}, nil
}

func (m *mockTPM2RESTService) CreateIDevID(akAttrs *xkmssdk.KeyAttributes, ekCert *x509.Certificate, qualifyingData []byte) (*xkmssdk.KeyAttributes, *xkmssdk.TCG_CSR_IDEVID, error) {
	if m.createIDevIDErr != nil {
		return nil, nil, m.createIDevIDErr
	}
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81030001,
		},
		KeyAlgorithm: x509.ECDSA,
	}, &xkmssdk.TCG_CSR_IDEVID{}, nil
}

func (m *mockTPM2RESTService) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	if m.iakAttrsErr != nil {
		return nil, m.iakAttrsErr
	}
	if !m.hasIAK {
		return nil, errors.New("IAK not found")
	}
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81020001,
		},
		KeyAlgorithm: x509.ECDSA,
	}, nil
}

func (m *mockTPM2RESTService) IDevIDAttributes() (*xkmssdk.KeyAttributes, error) {
	if m.idevidAttrsErr != nil {
		return nil, m.idevidAttrsErr
	}
	if !m.hasIDevID {
		return nil, errors.New("IDevID not found")
	}
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81030001,
		},
		KeyAlgorithm: x509.ECDSA,
	}, nil
}

func (m *mockTPM2RESTService) IDevIDCertificate() (*x509.Certificate, error) {
	if m.readIDevIDCertErr != nil {
		return nil, m.readIDevIDCertErr
	}
	if !m.hasIDevIDCert {
		return nil, errors.New("IDevID certificate not found")
	}
	return generateRESTTestCert("IDevID Test")
}

func (m *mockTPM2RESTService) IAKCertificate() (*x509.Certificate, error) {
	if m.readIAKCertErr != nil {
		return nil, m.readIAKCertErr
	}
	if !m.hasIAKCert {
		return nil, errors.New("IAK certificate not found")
	}
	return generateRESTTestCert("IAK Test")
}

func (m *mockTPM2RESTService) ProvisionIDevIDCert(cert *x509.Certificate) error {
	if m.writeIDevIDCertErr != nil {
		return m.writeIDevIDCertErr
	}
	return nil
}

func (m *mockTPM2RESTService) ProvisionIAKCert(cert *x509.Certificate) error {
	if m.writeIAKCertErr != nil {
		return m.writeIAKCertErr
	}
	return nil
}

func (m *mockTPM2RESTService) DeleteIDevIDCertificate() error {
	if m.deleteIDevIDCertErr != nil {
		return m.deleteIDevIDCertErr
	}
	m.hasIDevIDCert = false
	return nil
}

func (m *mockTPM2RESTService) DeleteIAKCertificate() error {
	if m.deleteIAKCertErr != nil {
		return m.deleteIAKCertErr
	}
	m.hasIAKCert = false
	return nil
}

func (m *mockTPM2RESTService) CreateTCG_CSR_IDEVID(ekCert *x509.Certificate, iakAttrs, idevidAttrs *xkmssdk.KeyAttributes) (xkmssdk.TCG_CSR_IDEVID, error) {
	if m.createCSRErr != nil {
		return xkmssdk.TCG_CSR_IDEVID{}, m.createCSRErr
	}
	return xkmssdk.TCG_CSR_IDEVID{}, nil
}

func (m *mockTPM2RESTService) ActivateCredential(credentialBlob, secret []byte) ([]byte, error) {
	if m.activateCredentialErr != nil {
		return nil, m.activateCredentialErr
	}
	return []byte("decrypted-secret"), nil
}

func (m *mockTPM2RESTService) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	if m.fixedPropsErr != nil {
		return nil, m.fixedPropsErr
	}
	return &xkmssdk.PropertiesFixed{
		Manufacturer: "Test Manufacturer",
		Family:       "2.0",
		FwMajor:      1,
		FwMinor:      2,
	}, nil
}

// generateRESTTestCert creates a test X.509 certificate for REST IDevID testing
func generateRESTTestCert(cn string) (*x509.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// generateRESTTestCertPEM generates a test certificate and returns its PEM encoding
func generateRESTTestCertPEM(cn string) (string, error) {
	cert, err := generateRESTTestCert(cn)
	if err != nil {
		return "", err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return string(pemBytes), nil
}

// createTestRESTServer creates a REST server for testing with mock TPM2 service
func createTestRESTServer(t *testing.T, mockTPM *mockTPM2RESTService) *RESTServer {
	config := DefaultConfig()
	config.RESTListenAddr = "127.0.0.1:0"

	service, err := NewService(config)
	require.NoError(t, err)

	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)

	if mockTPM != nil {
		server.SetTPM2Service(mockTPM)
	}

	return server
}

// executeRESTRequest executes a request against the REST server and returns the response
func executeRESTRequest(t *testing.T, server *RESTServer, method, path string, body interface{}) *httptest.ResponseRecorder {
	var reqBody bytes.Buffer
	if body != nil {
		err := json.NewEncoder(&reqBody).Encode(body)
		require.NoError(t, err)
	}

	req := httptest.NewRequest(method, path, &reqBody)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)
	return rr
}

// =============================================================================
// IDevID REST Handler Tests
// =============================================================================

func TestRESTIDevIDGenerate_Success(t *testing.T) {
	mockTPM := &mockTPM2RESTService{}
	server := createTestRESTServer(t, mockTPM)

	body := IDevIDGenerateRESTRequest{
		Algorithm: "ecdsa-p256",
		Overwrite: false,
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/generate", body)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IDevIDGenerateRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Handle)
	assert.Equal(t, "ECDSA-P256", resp.Algorithm)
}

func TestRESTIDevIDGenerate_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil) // No TPM2 service

	body := IDevIDGenerateRESTRequest{
		Algorithm: "ecdsa-p256",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/generate", body)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTIDevIDGenerate_InvalidRequestBody(t *testing.T) {
	mockTPM := &mockTPM2RESTService{}
	server := createTestRESTServer(t, mockTPM)

	// Send invalid JSON
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/idevid/generate", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRESTIDevIDGenerate_EKAttributesError(t *testing.T) {
	mockTPM := &mockTPM2RESTService{
		ekAttrsErr: errors.New("EK not available"),
	}
	server := createTestRESTServer(t, mockTPM)

	body := IDevIDGenerateRESTRequest{
		Algorithm: "ecdsa-p256",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/generate", body)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRESTIDevIDGenerate_CreateIAKError(t *testing.T) {
	mockTPM := &mockTPM2RESTService{
		createIAKErr: errors.New("IAK creation failed"),
	}
	server := createTestRESTServer(t, mockTPM)

	body := IDevIDGenerateRESTRequest{
		Algorithm: "ecdsa-p256",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/generate", body)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRESTIDevIDGenerate_CreateIDevIDError(t *testing.T) {
	mockTPM := &mockTPM2RESTService{
		createIDevIDErr: errors.New("IDevID creation failed"),
	}
	server := createTestRESTServer(t, mockTPM)

	body := IDevIDGenerateRESTRequest{
		Algorithm: "ecdsa-p256",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/generate", body)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRESTIDevIDInfo_Exists(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: true}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/idevid", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IDevIDInfoRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Exists)
	assert.NotEmpty(t, resp.Handle)
}

func TestRESTIDevIDInfo_NotExists(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: false}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/idevid", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IDevIDInfoRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Exists)
}

func TestRESTIDevIDInfo_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/idevid", nil)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTHasIDevID_Exists(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: true}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/idevid/exists", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp HasIDevIDRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Exists)
}

func TestRESTHasIDevID_NotExists(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: false}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/idevid/exists", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp HasIDevIDRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Exists)
}

func TestRESTHasIDevID_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/idevid/exists", nil)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// TestRESTIDevIDDelete_RefusedKeyAndCertRemain pins #304: the REST key delete
// is refused with 412 (the FailedPrecondition class) and touches nothing, so
// the key and its certificate are both still there afterwards.
func TestRESTIDevIDDelete_RefusedKeyAndCertRemain(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: true, hasIDevIDCert: true}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodDelete, "/api/v1/tpm/idevid", nil)

	assert.Equal(t, http.StatusPreconditionFailed, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &errResp))
	assert.Equal(t, ErrDeviceIdentityKeyNotDeletable{Key: "IDevID"}.Error(), errResp.Error)
	assert.NotContains(t, rr.Body.String(), `"deleted"`)

	assert.True(t, mockTPM.hasIDevID, "IDevID key must remain")
	assert.True(t, mockTPM.hasIDevIDCert, "IDevID certificate must remain")
	rr = executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/idevid/cert", nil)
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestRESTIDevIDDelete_RefusedWithoutTPMService checks the refusal does not
// depend on TPM availability, matching the gRPC service.
func TestRESTIDevIDDelete_RefusedWithoutTPMService(t *testing.T) {
	server := createTestRESTServer(t, nil)

	rr := executeRESTRequest(t, server, http.MethodDelete, "/api/v1/tpm/idevid", nil)

	assert.Equal(t, http.StatusPreconditionFailed, rr.Code)
}

func TestRESTIDevIDCSR_Success(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: true, hasIAK: true}
	server := createTestRESTServer(t, mockTPM)

	body := IDevIDCSRRESTRequest{
		CommonName:   "test-device",
		Organization: "Test Org",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/csr", body)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IDevIDCSRRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CSRPEM)
}

func TestRESTIDevIDCSR_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	body := IDevIDCSRRESTRequest{
		CommonName: "test-device",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/csr", body)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTIDevIDCSR_NoIDevID(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: false, hasIAK: true}
	server := createTestRESTServer(t, mockTPM)

	body := IDevIDCSRRESTRequest{
		CommonName: "test-device",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/csr", body)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRESTIDevIDCSR_NoIAK(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: true, hasIAK: false}
	server := createTestRESTServer(t, mockTPM)

	body := IDevIDCSRRESTRequest{
		CommonName: "test-device",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/csr", body)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRESTIDevIDInstallCert_Success(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: true}
	server := createTestRESTServer(t, mockTPM)

	certPEM, err := generateRESTTestCertPEM("Test IDevID")
	require.NoError(t, err)

	body := IDevIDInstallCertRESTRequest{
		CertificatePEM: certPEM,
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/install", body)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IDevIDInstallCertRESTResponse
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Installed)
}

func TestRESTIDevIDInstallCert_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	body := IDevIDInstallCertRESTRequest{
		CertificatePEM: "-----BEGIN CERTIFICATE-----\n...",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/install", body)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTIDevIDInstallCert_MissingCertificate(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: true}
	server := createTestRESTServer(t, mockTPM)

	body := IDevIDInstallCertRESTRequest{
		CertificatePEM: "",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/install", body)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRESTIDevIDInstallCert_InvalidPEM(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: true}
	server := createTestRESTServer(t, mockTPM)

	body := IDevIDInstallCertRESTRequest{
		CertificatePEM: "not-a-valid-pem",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/install", body)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRESTIDevIDInstallCert_WriteError(t *testing.T) {
	mockTPM := &mockTPM2RESTService{
		hasIDevID:          true,
		writeIDevIDCertErr: errors.New("write failed"),
	}
	server := createTestRESTServer(t, mockTPM)

	certPEM, err := generateRESTTestCertPEM("Test IDevID")
	require.NoError(t, err)

	body := IDevIDInstallCertRESTRequest{
		CertificatePEM: certPEM,
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/idevid/install", body)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRESTIDevIDGetCert_Success(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: true, hasIDevIDCert: true}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/idevid/cert", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IDevIDGetCertRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
	assert.NotEmpty(t, resp.Subject)
}

func TestRESTIDevIDGetCert_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/idevid/cert", nil)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTIDevIDGetCert_NotFound(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: true, hasIDevIDCert: false}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/idevid/cert", nil)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestRESTIDevIDDeleteCert_Success(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: true, hasIDevIDCert: true}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodDelete, "/api/v1/tpm/idevid/cert", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IDevIDDeleteCertRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Deleted)
}

func TestRESTIDevIDDeleteCert_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	rr := executeRESTRequest(t, server, http.MethodDelete, "/api/v1/tpm/idevid/cert", nil)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTIDevIDDeleteCert_Error(t *testing.T) {
	mockTPM := &mockTPM2RESTService{
		hasIDevID:           true,
		deleteIDevIDCertErr: errors.New("delete failed"),
	}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodDelete, "/api/v1/tpm/idevid/cert", nil)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// =============================================================================
// IAK REST Handler Tests
// =============================================================================

func TestRESTIAKGenerate_Success(t *testing.T) {
	mockTPM := &mockTPM2RESTService{}
	server := createTestRESTServer(t, mockTPM)

	body := IAKGenerateRESTRequest{
		Algorithm: "ecdsa-p256",
		Overwrite: false,
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/iak/generate", body)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAKGenerateRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Handle)
}

func TestRESTIAKGenerate_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	body := IAKGenerateRESTRequest{
		Algorithm: "ecdsa-p256",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/iak/generate", body)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTIAKGenerate_EKError(t *testing.T) {
	mockTPM := &mockTPM2RESTService{
		ekAttrsErr: errors.New("EK not available"),
	}
	server := createTestRESTServer(t, mockTPM)

	body := IAKGenerateRESTRequest{
		Algorithm: "ecdsa-p256",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/iak/generate", body)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRESTIAKGenerate_CreateError(t *testing.T) {
	mockTPM := &mockTPM2RESTService{
		createIAKErr: errors.New("IAK creation failed"),
	}
	server := createTestRESTServer(t, mockTPM)

	body := IAKGenerateRESTRequest{
		Algorithm: "ecdsa-p256",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/iak/generate", body)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRESTIAKInfo_Exists(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: true}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/iak", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAKInfoRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Exists)
}

func TestRESTIAKInfo_NotExists(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: false}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/iak", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAKInfoRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Exists)
}

func TestRESTIAKInfo_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/iak", nil)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTHasIAK_Exists(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: true}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/iak/exists", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp HasIAKRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Exists)
}

func TestRESTHasIAK_NotExists(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: false}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/iak/exists", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp HasIAKRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Exists)
}

// TestRESTIAKDelete_RefusedKeyAndCertRemain pins #304 for the IAK: refused
// with 412 and nothing touched.
func TestRESTIAKDelete_RefusedKeyAndCertRemain(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: true, hasIAKCert: true}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodDelete, "/api/v1/tpm/iak", nil)

	assert.Equal(t, http.StatusPreconditionFailed, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &errResp))
	assert.Equal(t, ErrDeviceIdentityKeyNotDeletable{Key: "IAK"}.Error(), errResp.Error)
	assert.NotContains(t, rr.Body.String(), `"deleted"`)

	assert.True(t, mockTPM.hasIAK, "IAK must remain")
	assert.True(t, mockTPM.hasIAKCert, "IAK certificate must remain")
	rr = executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/iak/cert", nil)
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestRESTIAKDelete_RefusedWithoutTPMService checks the refusal does not
// depend on TPM availability, matching the gRPC service.
func TestRESTIAKDelete_RefusedWithoutTPMService(t *testing.T) {
	server := createTestRESTServer(t, nil)

	rr := executeRESTRequest(t, server, http.MethodDelete, "/api/v1/tpm/iak", nil)

	assert.Equal(t, http.StatusPreconditionFailed, rr.Code)
}

func TestRESTIAKCSR_Success(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: true}
	server := createTestRESTServer(t, mockTPM)

	body := IAKCSRRESTRequest{
		CommonName:   "test-iak",
		Organization: "Test Org",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/iak/csr", body)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAKCSRRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CSRPEM)
}

func TestRESTIAKCSR_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	body := IAKCSRRESTRequest{
		CommonName: "test-iak",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/iak/csr", body)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTIAKCSR_NoIAK(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: false}
	server := createTestRESTServer(t, mockTPM)

	body := IAKCSRRESTRequest{
		CommonName: "test-iak",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/iak/csr", body)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRESTIAKInstallCert_Success(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: true}
	server := createTestRESTServer(t, mockTPM)

	certPEM, err := generateRESTTestCertPEM("Test IAK")
	require.NoError(t, err)

	body := IAKInstallCertRESTRequest{
		CertificatePEM: certPEM,
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/iak/install", body)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAKInstallCertRESTResponse
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Installed)
}

func TestRESTIAKInstallCert_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	body := IAKInstallCertRESTRequest{
		CertificatePEM: "-----BEGIN CERTIFICATE-----\n...",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/iak/install", body)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTIAKInstallCert_MissingCertificate(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: true}
	server := createTestRESTServer(t, mockTPM)

	body := IAKInstallCertRESTRequest{
		CertificatePEM: "",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/iak/install", body)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRESTIAKInstallCert_InvalidPEM(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: true}
	server := createTestRESTServer(t, mockTPM)

	body := IAKInstallCertRESTRequest{
		CertificatePEM: "not-a-valid-pem",
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/iak/install", body)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRESTIAKInstallCert_WriteError(t *testing.T) {
	mockTPM := &mockTPM2RESTService{
		hasIAK:          true,
		writeIAKCertErr: errors.New("write failed"),
	}
	server := createTestRESTServer(t, mockTPM)

	certPEM, err := generateRESTTestCertPEM("Test IAK")
	require.NoError(t, err)

	body := IAKInstallCertRESTRequest{
		CertificatePEM: certPEM,
	}

	rr := executeRESTRequest(t, server, http.MethodPost, "/api/v1/tpm/iak/install", body)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRESTIAKGetCert_Success(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: true, hasIAKCert: true}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/iak/cert", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAKGetCertRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestRESTIAKGetCert_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/iak/cert", nil)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTIAKGetCert_NotFound(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: true, hasIAKCert: false}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/iak/cert", nil)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestRESTIAKDeleteCert_Success(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIAK: true, hasIAKCert: true}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodDelete, "/api/v1/tpm/iak/cert", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAKDeleteCertRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Deleted)
}

func TestRESTIAKDeleteCert_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	rr := executeRESTRequest(t, server, http.MethodDelete, "/api/v1/tpm/iak/cert", nil)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTIAKDeleteCert_Error(t *testing.T) {
	mockTPM := &mockTPM2RESTService{
		hasIAK:           true,
		deleteIAKCertErr: errors.New("delete failed"),
	}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodDelete, "/api/v1/tpm/iak/cert", nil)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// =============================================================================
// Device Attributes and Activate Credential REST Handler Tests
// =============================================================================

func TestRESTDeviceAttributes_Success(t *testing.T) {
	mockTPM := &mockTPM2RESTService{}
	server := createTestRESTServer(t, mockTPM)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/device/attributes", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp DeviceAttributesRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Test Manufacturer", resp.TPMManufacturer)
}

func TestRESTDeviceAttributes_ServiceNotAvailable(t *testing.T) {
	server := createTestRESTServer(t, nil)

	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/device/attributes", nil)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestRESTDeviceAttributes_FixedPropsError(t *testing.T) {
	mockTPM := &mockTPM2RESTService{
		fixedPropsErr: errors.New("TPM error"),
	}
	server := createTestRESTServer(t, mockTPM)

	// Should still return OK, just with empty TPM info
	rr := executeRESTRequest(t, server, http.MethodGet, "/api/v1/tpm/device/attributes", nil)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp DeviceAttributesRESTResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp.TPMManufacturer)
}

// =============================================================================
// Route Registration Test
// =============================================================================

func TestRESTIDevIDRouteRegistration(t *testing.T) {
	mockTPM := &mockTPM2RESTService{hasIDevID: true, hasIAK: true}
	server := createTestRESTServer(t, mockTPM)

	// Test all IDevID routes are registered
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/tpm/idevid"},
		{http.MethodGet, "/api/v1/tpm/idevid/exists"},
		{http.MethodPost, "/api/v1/tpm/idevid/generate"},
		{http.MethodDelete, "/api/v1/tpm/idevid"},
		{http.MethodPost, "/api/v1/tpm/idevid/csr"},
		{http.MethodGet, "/api/v1/tpm/idevid/cert"},
		{http.MethodPost, "/api/v1/tpm/idevid/install"},
		{http.MethodDelete, "/api/v1/tpm/idevid/cert"},
		{http.MethodGet, "/api/v1/tpm/iak"},
		{http.MethodGet, "/api/v1/tpm/iak/exists"},
		{http.MethodPost, "/api/v1/tpm/iak/generate"},
		{http.MethodDelete, "/api/v1/tpm/iak"},
		{http.MethodPost, "/api/v1/tpm/iak/csr"},
		{http.MethodGet, "/api/v1/tpm/iak/cert"},
		{http.MethodPost, "/api/v1/tpm/iak/install"},
		{http.MethodDelete, "/api/v1/tpm/iak/cert"},
		{http.MethodGet, "/api/v1/tpm/device/attributes"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			match := &mux.RouteMatch{}
			req := httptest.NewRequest(route.method, route.path, nil)
			matched := server.router.Match(req, match)
			assert.True(t, matched, "route %s %s should be registered", route.method, route.path)
		})
	}
}
