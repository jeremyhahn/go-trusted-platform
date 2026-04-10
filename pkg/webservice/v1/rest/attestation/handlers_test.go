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

package attestation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// mockAttestationService implements AttestationService for testing.
type mockAttestationService struct {
	getManifestFn    func(ctx context.Context) (*manifest.HostManifest, error)
	buildManifestFn  func(ctx context.Context, opts *BuildManifestOptions) (*manifest.HostManifest, error)
	verifyManifestFn func(ctx context.Context, m *manifest.HostManifest, publicKey crypto.PublicKey, expectedNonce []byte) (*manifest.VerificationResult, error)
	getQuoteFn       func(ctx context.Context, opts *GetQuoteOptions) (*QuoteResult, error)
	verifyQuoteFn    func(ctx context.Context, opts *VerifyQuoteOptions) (*manifest.VerificationResult, error)
}

func (m *mockAttestationService) GetManifest(ctx context.Context) (*manifest.HostManifest, error) {
	if m.getManifestFn != nil {
		return m.getManifestFn(ctx)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) BuildManifest(ctx context.Context, opts *BuildManifestOptions) (*manifest.HostManifest, error) {
	if m.buildManifestFn != nil {
		return m.buildManifestFn(ctx, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) VerifyManifest(ctx context.Context, man *manifest.HostManifest, publicKey crypto.PublicKey, expectedNonce []byte) (*manifest.VerificationResult, error) {
	if m.verifyManifestFn != nil {
		return m.verifyManifestFn(ctx, man, publicKey, expectedNonce)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) GetQuote(ctx context.Context, opts *GetQuoteOptions) (*QuoteResult, error) {
	if m.getQuoteFn != nil {
		return m.getQuoteFn(ctx, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) VerifyQuote(ctx context.Context, opts *VerifyQuoteOptions) (*manifest.VerificationResult, error) {
	if m.verifyQuoteFn != nil {
		return m.verifyQuoteFn(ctx, opts)
	}
	return nil, errors.New("not implemented")
}

// mockHttpWriter implements response.HttpWriter for testing.
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

// Helper functions for tests

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, os.Stdout)
}

func newTestHandlers(service *mockAttestationService) (*AttestationHandlers, *mockHttpWriter) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewAttestationHandlers(logger, service, writer)
	return handlers, writer
}

func createRequestWithBody(method, path string, body interface{}) *http.Request {
	var reqBody bytes.Buffer
	if body != nil {
		json.NewEncoder(&reqBody).Encode(body)
	}

	req := httptest.NewRequest(method, path, &reqBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return req
}

func createTestManifest() *manifest.HostManifest {
	now := time.Now().UTC()
	nonce := []byte("test-nonce-1234567890")
	merkleRoot := []byte("test-merkle-root-hash")
	signature := []byte("test-signature")

	return &manifest.HostManifest{
		ID:        "test-manifest-123",
		HostID:    "test-host-001",
		Timestamp: now,
		Nonce:     nonce,
		Host: &manifest.HostAttestation{
			QuoteData:          []byte("test-quote-data"),
			Signature:          []byte("test-quote-sig"),
			SignatureAlgorithm: "RSASSA-PKCS1-v1_5",
			PCRs: []manifest.PCRValue{
				{Index: 0, Value: []byte("pcr0-value"), Algorithm: manifest.HashAlgorithmSHA256},
				{Index: 1, Value: []byte("pcr1-value"), Algorithm: manifest.HashAlgorithmSHA256},
			},
			PCRDigest:     []byte("test-pcr-digest"),
			Nonce:         nonce,
			Timestamp:     now,
			AKPublicKey:   []byte("test-ak-pubkey"),
			HashAlgorithm: manifest.HashAlgorithmSHA256,
		},
		VMs:                nil,
		Containers:         nil,
		MerkleRoot:         merkleRoot,
		Signature:          signature,
		SignatureAlgorithm: "RSASSA-PKCS1-v1_5",
		Version:            "1.0",
		Metadata:           map[string]string{"env": "test"},
	}
}

func createTestQuoteResult() *QuoteResult {
	now := time.Now().UTC()
	nonce := []byte("test-nonce-1234567890")

	return &QuoteResult{
		QuoteData:          []byte("test-quote-data"),
		Signature:          []byte("test-quote-sig"),
		SignatureAlgorithm: "RSASSA-PKCS1-v1_5",
		PCRs: []manifest.PCRValue{
			{Index: 0, Value: []byte("pcr0-value"), Algorithm: manifest.HashAlgorithmSHA256},
			{Index: 1, Value: []byte("pcr1-value"), Algorithm: manifest.HashAlgorithmSHA256},
		},
		PCRDigest:     []byte("test-pcr-digest"),
		Nonce:         nonce,
		Timestamp:     now,
		AKPublicKey:   []byte("test-ak-pubkey"),
		HashAlgorithm: manifest.HashAlgorithmSHA256,
	}
}

func createTestVerificationResult(verified bool) *manifest.VerificationResult {
	status := manifest.VerificationStatusVerified
	if !verified {
		status = manifest.VerificationStatusFailed
	}
	return &manifest.VerificationResult{
		Status:                     status,
		SignatureValid:             verified,
		MerkleRootValid:            verified,
		NonceValid:                 verified,
		TimestampValid:             verified,
		HostAttestationValid:       verified,
		VMAttestationsValid:        verified,
		ContainerAttestationsValid: verified,
		VerifiedAt:                 time.Now().UTC(),
		Errors:                     nil,
	}
}

// createTestPublicKeyPEM generates a valid ECDSA public key PEM for testing.
func createTestPublicKeyPEM(t *testing.T) string {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock))
}

// Tests for NewAttestationHandlers

func TestNewAttestationHandlers(t *testing.T) {
	logger := newTestLogger()
	service := &mockAttestationService{}
	writer := &mockHttpWriter{}

	handlers := NewAttestationHandlers(logger, service, writer)

	require.NotNil(t, handlers)
	assert.NotNil(t, handlers.logger)
	assert.NotNil(t, handlers.service)
	assert.NotNil(t, handlers.respWriter)
}

// Tests for GetManifest

func TestGetManifest_Success(t *testing.T) {
	testManifest := createTestManifest()

	service := &mockAttestationService{
		getManifestFn: func(ctx context.Context) (*manifest.HostManifest, error) {
			return testManifest, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/manifest", nil)
	rec := httptest.NewRecorder()

	handlers.GetManifest(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	resp, ok := writer.lastPayload.(*ManifestResponse)
	require.True(t, ok)
	assert.Equal(t, testManifest.ID, resp.ID)
	assert.Equal(t, testManifest.HostID, resp.HostID)
}

func TestGetManifest_NotFound(t *testing.T) {
	service := &mockAttestationService{
		getManifestFn: func(ctx context.Context) (*manifest.HostManifest, error) {
			return nil, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/manifest", nil)
	rec := httptest.NewRecorder()

	handlers.GetManifest(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
	_, ok := writer.lastError.(ErrManifestNotFound)
	assert.True(t, ok)
}

func TestGetManifest_ServiceError(t *testing.T) {
	service := &mockAttestationService{
		getManifestFn: func(ctx context.Context) (*manifest.HostManifest, error) {
			return nil, errors.New("service error")
		},
	}

	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/manifest", nil)
	rec := httptest.NewRecorder()

	handlers.GetManifest(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Tests for BuildManifest

func TestBuildManifest_Success(t *testing.T) {
	testManifest := createTestManifest()

	service := &mockAttestationService{
		buildManifestFn: func(ctx context.Context, opts *BuildManifestOptions) (*manifest.HostManifest, error) {
			assert.Equal(t, "test-host", opts.HostID)
			assert.Equal(t, manifest.HashAlgorithmSHA256, opts.HashAlgorithm)
			return testManifest, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	body := BuildManifestRequest{
		HostID:        "test-host",
		HashAlgorithm: "sha256",
		PCRIndices:    []int{0, 1, 2},
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/manifest/build", body)
	rec := httptest.NewRecorder()

	handlers.BuildManifest(rec, req)

	assert.Equal(t, http.StatusCreated, writer.lastStatus)
	resp, ok := writer.lastPayload.(*ManifestResponse)
	require.True(t, ok)
	assert.Equal(t, testManifest.ID, resp.ID)
}

func TestBuildManifest_WithNonce(t *testing.T) {
	testManifest := createTestManifest()
	expectedNonce := []byte("custom-nonce-value")

	service := &mockAttestationService{
		buildManifestFn: func(ctx context.Context, opts *BuildManifestOptions) (*manifest.HostManifest, error) {
			assert.Equal(t, expectedNonce, opts.Nonce)
			return testManifest, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	body := BuildManifestRequest{
		Nonce: base64.StdEncoding.EncodeToString(expectedNonce),
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/manifest/build", body)
	rec := httptest.NewRecorder()

	handlers.BuildManifest(rec, req)

	assert.Equal(t, http.StatusCreated, writer.lastStatus)
}

func TestBuildManifest_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifest/build", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.BuildManifest(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestBuildManifest_InvalidPCRIndex(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	body := BuildManifestRequest{
		PCRIndices: []int{0, 25}, // 25 is invalid
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/manifest/build", body)
	rec := httptest.NewRecorder()

	handlers.BuildManifest(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidPCRIndex)
	assert.True(t, ok)
}

func TestBuildManifest_InvalidBase64Nonce(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	body := BuildManifestRequest{
		Nonce: "not-valid-base64!!!",
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/manifest/build", body)
	rec := httptest.NewRecorder()

	handlers.BuildManifest(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestBuildManifest_ServiceError(t *testing.T) {
	service := &mockAttestationService{
		buildManifestFn: func(ctx context.Context, opts *BuildManifestOptions) (*manifest.HostManifest, error) {
			return nil, errors.New("build failed")
		},
	}

	handlers, writer := newTestHandlers(service)

	body := BuildManifestRequest{}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/manifest/build", body)
	rec := httptest.NewRecorder()

	handlers.BuildManifest(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestBuildManifest_WithIncludeVMsAndContainers(t *testing.T) {
	testManifest := createTestManifest()

	service := &mockAttestationService{
		buildManifestFn: func(ctx context.Context, opts *BuildManifestOptions) (*manifest.HostManifest, error) {
			assert.True(t, opts.IncludeVMs)
			assert.True(t, opts.IncludeContainers)
			return testManifest, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	body := BuildManifestRequest{
		IncludeVMs:        true,
		IncludeContainers: true,
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/manifest/build", body)
	rec := httptest.NewRecorder()

	handlers.BuildManifest(rec, req)

	assert.Equal(t, http.StatusCreated, writer.lastStatus)
}

// Tests for VerifyManifest

func TestVerifyManifest_Success(t *testing.T) {
	verificationResult := createTestVerificationResult(true)

	service := &mockAttestationService{
		verifyManifestFn: func(ctx context.Context, m *manifest.HostManifest, publicKey crypto.PublicKey, expectedNonce []byte) (*manifest.VerificationResult, error) {
			return verificationResult, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	manifestReq := &ManifestRequest{
		ID:                 "test-manifest",
		HostID:             "test-host",
		Timestamp:          time.Now(),
		Nonce:              base64.StdEncoding.EncodeToString([]byte("test-nonce-value")),
		MerkleRoot:         base64.StdEncoding.EncodeToString([]byte("merkle-root")),
		SignatureAlgorithm: "RSA",
		Version:            "1.0",
		Host: &HostAttestationRequest{
			QuoteData:          base64.StdEncoding.EncodeToString([]byte("quote")),
			Signature:          base64.StdEncoding.EncodeToString([]byte("sig")),
			SignatureAlgorithm: "RSA",
			PCRDigest:          base64.StdEncoding.EncodeToString([]byte("digest")),
			Nonce:              base64.StdEncoding.EncodeToString([]byte("nonce")),
			HashAlgorithm:      "sha256",
			PCRs: []PCRValueRequest{
				{Index: 0, Value: base64.StdEncoding.EncodeToString([]byte("pcr0")), Algorithm: "sha256"},
			},
		},
	}

	body := VerifyManifestRequest{
		Manifest: manifestReq,
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyManifest(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	resp, ok := writer.lastPayload.(*VerificationResponse)
	require.True(t, ok)
	assert.True(t, resp.Valid)
	assert.Equal(t, "verified", resp.Status)
}

func TestVerifyManifest_MissingManifest(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	body := VerifyManifestRequest{
		Manifest: nil,
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyManifest(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingManifest)
	assert.True(t, ok)
}

func TestVerifyManifest_InvalidBase64InManifest(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	manifestReq := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      "invalid-base64!!!",
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
	}

	body := VerifyManifestRequest{
		Manifest: manifestReq,
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyManifest(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestVerifyManifest_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/verify", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.VerifyManifest(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestVerifyManifest_WithExpectedNonce(t *testing.T) {
	verificationResult := createTestVerificationResult(true)
	expectedNonce := []byte("expected-nonce-value")

	service := &mockAttestationService{
		verifyManifestFn: func(ctx context.Context, m *manifest.HostManifest, publicKey crypto.PublicKey, expNonce []byte) (*manifest.VerificationResult, error) {
			assert.Equal(t, expectedNonce, expNonce)
			return verificationResult, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	manifestReq := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
	}

	body := VerifyManifestRequest{
		Manifest:      manifestReq,
		ExpectedNonce: base64.StdEncoding.EncodeToString(expectedNonce),
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyManifest(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestVerifyManifest_InvalidExpectedNonce(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	manifestReq := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
	}

	body := VerifyManifestRequest{
		Manifest:      manifestReq,
		ExpectedNonce: "invalid-base64!!!",
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyManifest(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestVerifyManifest_InvalidPublicKeyPEM(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	manifestReq := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
	}

	body := VerifyManifestRequest{
		Manifest:     manifestReq,
		PublicKeyPEM: "invalid-pem-data",
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyManifest(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestVerifyManifest_ServiceError(t *testing.T) {
	service := &mockAttestationService{
		verifyManifestFn: func(ctx context.Context, m *manifest.HostManifest, publicKey crypto.PublicKey, expectedNonce []byte) (*manifest.VerificationResult, error) {
			return nil, errors.New("verification failed")
		},
	}

	handlers, writer := newTestHandlers(service)

	manifestReq := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
	}

	body := VerifyManifestRequest{
		Manifest: manifestReq,
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyManifest(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestVerifyManifest_WithValidPublicKey(t *testing.T) {
	verificationResult := createTestVerificationResult(true)

	service := &mockAttestationService{
		verifyManifestFn: func(ctx context.Context, m *manifest.HostManifest, publicKey crypto.PublicKey, expectedNonce []byte) (*manifest.VerificationResult, error) {
			assert.NotNil(t, publicKey)
			return verificationResult, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	manifestReq := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
	}

	body := VerifyManifestRequest{
		Manifest:     manifestReq,
		PublicKeyPEM: createTestPublicKeyPEM(t),
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyManifest(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

// Tests for GetQuote

func TestGetQuote_Success(t *testing.T) {
	quoteResult := createTestQuoteResult()

	service := &mockAttestationService{
		getQuoteFn: func(ctx context.Context, opts *GetQuoteOptions) (*QuoteResult, error) {
			return quoteResult, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/quote", nil)
	rec := httptest.NewRecorder()

	handlers.GetQuote(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	resp, ok := writer.lastPayload.(*QuoteResponse)
	require.True(t, ok)
	assert.NotEmpty(t, resp.QuoteData)
}

func TestGetQuote_WithParameters(t *testing.T) {
	quoteResult := createTestQuoteResult()
	expectedNonce := []byte("custom-nonce")

	service := &mockAttestationService{
		getQuoteFn: func(ctx context.Context, opts *GetQuoteOptions) (*QuoteResult, error) {
			assert.Equal(t, expectedNonce, opts.Nonce)
			assert.Equal(t, []int{0, 1, 2}, opts.PCRIndices)
			assert.Equal(t, manifest.HashAlgorithmSHA384, opts.HashAlgorithm)
			return quoteResult, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	url := "/api/v1/attestation/quote?nonce=" + base64.StdEncoding.EncodeToString(expectedNonce) +
		"&pcrs=0,1,2&hash_algorithm=sha384"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()

	handlers.GetQuote(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestGetQuote_InvalidNonce(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/quote?nonce=invalid!!!", nil)
	rec := httptest.NewRecorder()

	handlers.GetQuote(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestGetQuote_InvalidPCRs(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/quote?pcrs=0,25", nil)
	rec := httptest.NewRecorder()

	handlers.GetQuote(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetQuote_ServiceError(t *testing.T) {
	service := &mockAttestationService{
		getQuoteFn: func(ctx context.Context, opts *GetQuoteOptions) (*QuoteResult, error) {
			return nil, errors.New("quote failed")
		},
	}

	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/quote", nil)
	rec := httptest.NewRecorder()

	handlers.GetQuote(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Tests for VerifyQuote

func TestVerifyQuote_Success(t *testing.T) {
	verificationResult := createTestVerificationResult(true)

	service := &mockAttestationService{
		verifyQuoteFn: func(ctx context.Context, opts *VerifyQuoteOptions) (*manifest.VerificationResult, error) {
			assert.NotNil(t, opts.QuoteData)
			assert.NotNil(t, opts.Signature)
			assert.NotNil(t, opts.PublicKey)
			assert.NotNil(t, opts.ExpectedNonce)
			return verificationResult, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	body := VerifyQuoteRequest{
		QuoteData:     base64.StdEncoding.EncodeToString([]byte("quote-data")),
		Signature:     base64.StdEncoding.EncodeToString([]byte("signature")),
		PublicKeyPEM:  createTestPublicKeyPEM(t),
		ExpectedNonce: base64.StdEncoding.EncodeToString([]byte("nonce")),
		HashAlgorithm: "sha256",
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/quote/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	resp, ok := writer.lastPayload.(*VerificationResponse)
	require.True(t, ok)
	assert.True(t, resp.Valid)
}

func TestVerifyQuote_SuccessWithPCRs(t *testing.T) {
	verificationResult := createTestVerificationResult(true)

	service := &mockAttestationService{
		verifyQuoteFn: func(ctx context.Context, opts *VerifyQuoteOptions) (*manifest.VerificationResult, error) {
			assert.Len(t, opts.PCRs, 2)
			assert.Equal(t, 0, opts.PCRs[0].Index)
			assert.Equal(t, 1, opts.PCRs[1].Index)
			return verificationResult, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	body := VerifyQuoteRequest{
		QuoteData:     base64.StdEncoding.EncodeToString([]byte("quote-data")),
		Signature:     base64.StdEncoding.EncodeToString([]byte("signature")),
		PublicKeyPEM:  createTestPublicKeyPEM(t),
		ExpectedNonce: base64.StdEncoding.EncodeToString([]byte("nonce")),
		HashAlgorithm: "sha384",
		PCRs: []PCRValueRequest{
			{Index: 0, Value: base64.StdEncoding.EncodeToString([]byte("pcr0")), Algorithm: "sha256"},
			{Index: 1, Value: base64.StdEncoding.EncodeToString([]byte("pcr1")), Algorithm: "sha256"},
		},
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/quote/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestVerifyQuote_ServiceError(t *testing.T) {
	service := &mockAttestationService{
		verifyQuoteFn: func(ctx context.Context, opts *VerifyQuoteOptions) (*manifest.VerificationResult, error) {
			return nil, errors.New("verification failed")
		},
	}

	handlers, writer := newTestHandlers(service)

	body := VerifyQuoteRequest{
		QuoteData:     base64.StdEncoding.EncodeToString([]byte("quote-data")),
		Signature:     base64.StdEncoding.EncodeToString([]byte("signature")),
		PublicKeyPEM:  createTestPublicKeyPEM(t),
		ExpectedNonce: base64.StdEncoding.EncodeToString([]byte("nonce")),
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/quote/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestVerifyQuote_InvalidExpectedNonceWithValidKey(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	body := VerifyQuoteRequest{
		QuoteData:     base64.StdEncoding.EncodeToString([]byte("data")),
		Signature:     base64.StdEncoding.EncodeToString([]byte("sig")),
		PublicKeyPEM:  createTestPublicKeyPEM(t),
		ExpectedNonce: "invalid!!!",
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/quote/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestVerifyQuote_InvalidPCRValueWithValidKey(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	body := VerifyQuoteRequest{
		QuoteData:     base64.StdEncoding.EncodeToString([]byte("data")),
		Signature:     base64.StdEncoding.EncodeToString([]byte("sig")),
		PublicKeyPEM:  createTestPublicKeyPEM(t),
		ExpectedNonce: base64.StdEncoding.EncodeToString([]byte("nonce")),
		PCRs: []PCRValueRequest{
			{Index: 0, Value: "invalid!!!", Algorithm: "sha256"},
		},
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/quote/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestVerifyQuote_MissingQuoteData(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	body := VerifyQuoteRequest{
		Signature:     base64.StdEncoding.EncodeToString([]byte("sig")),
		PublicKeyPEM:  "key",
		ExpectedNonce: base64.StdEncoding.EncodeToString([]byte("nonce")),
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/quote/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingQuoteData)
	assert.True(t, ok)
}

func TestVerifyQuote_MissingSignature(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	body := VerifyQuoteRequest{
		QuoteData:     base64.StdEncoding.EncodeToString([]byte("data")),
		PublicKeyPEM:  "key",
		ExpectedNonce: base64.StdEncoding.EncodeToString([]byte("nonce")),
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/quote/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSignature)
	assert.True(t, ok)
}

func TestVerifyQuote_MissingPublicKey(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	body := VerifyQuoteRequest{
		QuoteData:     base64.StdEncoding.EncodeToString([]byte("data")),
		Signature:     base64.StdEncoding.EncodeToString([]byte("sig")),
		ExpectedNonce: base64.StdEncoding.EncodeToString([]byte("nonce")),
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/quote/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingPublicKey)
	assert.True(t, ok)
}

func TestVerifyQuote_MissingNonce(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	body := VerifyQuoteRequest{
		QuoteData:    base64.StdEncoding.EncodeToString([]byte("data")),
		Signature:    base64.StdEncoding.EncodeToString([]byte("sig")),
		PublicKeyPEM: "key",
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/quote/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingNonce)
	assert.True(t, ok)
}

func TestVerifyQuote_InvalidBase64QuoteData(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	body := VerifyQuoteRequest{
		QuoteData:     "invalid!!!",
		Signature:     base64.StdEncoding.EncodeToString([]byte("sig")),
		PublicKeyPEM:  "key",
		ExpectedNonce: base64.StdEncoding.EncodeToString([]byte("nonce")),
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/quote/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestVerifyQuote_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/quote/verify", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestVerifyQuote_InvalidBase64Signature(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	body := VerifyQuoteRequest{
		QuoteData:     base64.StdEncoding.EncodeToString([]byte("data")),
		Signature:     "invalid!!!",
		PublicKeyPEM:  "key",
		ExpectedNonce: base64.StdEncoding.EncodeToString([]byte("nonce")),
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/quote/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestVerifyQuote_InvalidPublicKeyPEM(t *testing.T) {
	handlers, writer := newTestHandlers(&mockAttestationService{})

	body := VerifyQuoteRequest{
		QuoteData:     base64.StdEncoding.EncodeToString([]byte("data")),
		Signature:     base64.StdEncoding.EncodeToString([]byte("sig")),
		PublicKeyPEM:  "invalid-pem",
		ExpectedNonce: base64.StdEncoding.EncodeToString([]byte("nonce")),
	}

	req := createRequestWithBody(http.MethodPost, "/api/v1/attestation/quote/verify", body)
	rec := httptest.NewRecorder()

	handlers.VerifyQuote(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

// Tests for helper methods

func TestParseHashAlgorithm(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	tests := []struct {
		input    string
		expected manifest.HashAlgorithm
	}{
		{"sha256", manifest.HashAlgorithmSHA256},
		{"SHA256", manifest.HashAlgorithmSHA256},
		{"sha384", manifest.HashAlgorithmSHA384},
		{"SHA384", manifest.HashAlgorithmSHA384},
		{"sha512", manifest.HashAlgorithmSHA512},
		{"SHA512", manifest.HashAlgorithmSHA512},
		{"sha1", manifest.HashAlgorithmSHA1},
		{"SHA1", manifest.HashAlgorithmSHA1},
		{"unknown", manifest.HashAlgorithmSHA256}, // defaults to SHA256
		{"", manifest.HashAlgorithmSHA256},        // defaults to SHA256
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := handlers.parseHashAlgorithm(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidatePCRIndices(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	tests := []struct {
		name    string
		indices []int
		wantErr bool
	}{
		{"valid single", []int{0}, false},
		{"valid multiple", []int{0, 1, 2, 14}, false},
		{"valid max", []int{23}, false},
		{"invalid negative", []int{-1}, true},
		{"invalid too high", []int{24}, true},
		{"mixed valid invalid", []int{0, 25}, true},
		{"empty", []int{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handlers.validatePCRIndices(tt.indices)
			if tt.wantErr {
				assert.Error(t, err)
				_, ok := err.(ErrInvalidPCRIndex)
				assert.True(t, ok)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetDefaultPCRIndices(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	indices := handlers.getDefaultPCRIndices()

	expected := []int{0, 1, 2, 3, 4, 5, 6, 7, 14}
	assert.Equal(t, expected, indices)
}

func TestParsePCRString(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	tests := []struct {
		name     string
		input    string
		expected []int
		wantErr  bool
	}{
		{"single value", "0", []int{0}, false},
		{"multiple values", "0,1,2", []int{0, 1, 2}, false},
		{"with spaces", "0, 1, 2", []int{0, 1, 2}, false},
		{"empty string", "", []int{0, 1, 2, 3, 4, 5, 6, 7, 14}, false},
		{"invalid index too high", "0,25", nil, true},
		{"invalid non-numeric", "abc", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handlers.parsePCRString(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestHandleServiceError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"not found error", errors.New("manifest not found"), http.StatusNotFound},
		{"does not exist error", errors.New("key does not exist"), http.StatusNotFound},
		{"no such error", errors.New("no such file"), http.StatusNotFound},
		{"invalid error", errors.New("invalid request"), http.StatusBadRequest},
		{"required error", errors.New("field required"), http.StatusBadRequest},
		{"unsupported error", errors.New("unsupported algorithm"), http.StatusBadRequest},
		{"must be error", errors.New("value must be positive"), http.StatusBadRequest},
		{"cannot be error", errors.New("field cannot be empty"), http.StatusBadRequest},
		{"generic error", errors.New("something failed"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlers, writer := newTestHandlers(&mockAttestationService{})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()

			handlers.handleServiceError(rec, req, tt.err)

			assert.Equal(t, tt.expectedStatus, writer.lastStatus)
		})
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name       string
		s          string
		substrings []string
		expected   bool
	}{
		{"contains first", "error not found", []string{"not found", "invalid"}, true},
		{"contains second", "invalid request", []string{"not found", "invalid"}, true},
		{"contains none", "success", []string{"not found", "invalid"}, false},
		{"empty string", "", []string{"not found"}, false},
		{"empty substrings", "test", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsAny(tt.s, tt.substrings...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Tests for conversion helpers

func TestManifestToResponse(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})
	testManifest := createTestManifest()

	resp := handlers.manifestToResponse(testManifest)

	require.NotNil(t, resp)
	assert.Equal(t, testManifest.ID, resp.ID)
	assert.Equal(t, testManifest.HostID, resp.HostID)
	assert.Equal(t, base64.StdEncoding.EncodeToString(testManifest.Nonce), resp.Nonce)
	assert.Equal(t, base64.StdEncoding.EncodeToString(testManifest.MerkleRoot), resp.MerkleRoot)
	assert.Equal(t, testManifest.Version, resp.Version)
	assert.NotNil(t, resp.Host)
}

func TestManifestToResponse_Nil(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	resp := handlers.manifestToResponse(nil)

	assert.Nil(t, resp)
}

func TestManifestToResponse_NoSignature(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})
	testManifest := createTestManifest()
	testManifest.Signature = nil

	resp := handlers.manifestToResponse(testManifest)

	require.NotNil(t, resp)
	assert.Empty(t, resp.Signature)
	assert.Empty(t, resp.SignatureAlgorithm)
}

func TestManifestToResponse_NoHost(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})
	testManifest := createTestManifest()
	testManifest.Host = nil

	resp := handlers.manifestToResponse(testManifest)

	require.NotNil(t, resp)
	assert.Nil(t, resp.Host)
}

func TestHostAttestationToResponse(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})
	testManifest := createTestManifest()

	resp := handlers.hostAttestationToResponse(testManifest.Host)

	require.NotNil(t, resp)
	assert.Equal(t, base64.StdEncoding.EncodeToString(testManifest.Host.QuoteData), resp.QuoteData)
	assert.Equal(t, base64.StdEncoding.EncodeToString(testManifest.Host.Signature), resp.Signature)
	assert.Equal(t, testManifest.Host.HashAlgorithm.String(), resp.HashAlgorithm)
	assert.Len(t, resp.PCRs, len(testManifest.Host.PCRs))
}

func TestHostAttestationToResponse_Nil(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	resp := handlers.hostAttestationToResponse(nil)

	assert.Nil(t, resp)
}

func TestHostAttestationToResponse_NoAKPublicKey(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})
	testManifest := createTestManifest()
	testManifest.Host.AKPublicKey = nil

	resp := handlers.hostAttestationToResponse(testManifest.Host)

	require.NotNil(t, resp)
	assert.Empty(t, resp.AKPublicKeyPEM)
}

func TestQuoteResultToResponse(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})
	quoteResult := createTestQuoteResult()

	resp := handlers.quoteResultToResponse(quoteResult)

	require.NotNil(t, resp)
	assert.Equal(t, base64.StdEncoding.EncodeToString(quoteResult.QuoteData), resp.QuoteData)
	assert.Equal(t, base64.StdEncoding.EncodeToString(quoteResult.Signature), resp.Signature)
	assert.Equal(t, quoteResult.HashAlgorithm.String(), resp.HashAlgorithm)
}

func TestQuoteResultToResponse_Nil(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	resp := handlers.quoteResultToResponse(nil)

	assert.Nil(t, resp)
}

func TestVerificationResultToResponse(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})
	verResult := createTestVerificationResult(true)

	resp := handlers.verificationResultToResponse(verResult)

	require.NotNil(t, resp)
	assert.True(t, resp.Valid)
	assert.Equal(t, "verified", resp.Status)
	assert.True(t, resp.SignatureValid)
	assert.True(t, resp.MerkleRootValid)
	assert.True(t, resp.NonceValid)
}

func TestVerificationResultToResponse_Failed(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})
	verResult := createTestVerificationResult(false)

	resp := handlers.verificationResultToResponse(verResult)

	require.NotNil(t, resp)
	assert.False(t, resp.Valid)
	assert.Equal(t, "failed", resp.Status)
}

func TestVerificationResultToResponse_Nil(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	resp := handlers.verificationResultToResponse(nil)

	assert.Nil(t, resp)
}

func TestRequestToManifest_Nil(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	m, err := handlers.requestToManifest(nil)

	assert.Error(t, err)
	assert.Nil(t, m)
	_, ok := err.(ErrMissingManifest)
	assert.True(t, ok)
}

func TestRequestToManifest_InvalidMerkleRoot(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: "invalid-base64!!!",
	}

	m, err := handlers.requestToManifest(req)

	assert.Error(t, err)
	assert.Nil(t, m)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToManifest_InvalidSignature(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
		Signature:  "invalid-base64!!!",
	}

	m, err := handlers.requestToManifest(req)

	assert.Error(t, err)
	assert.Nil(t, m)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToManifest_WithHostAttestation(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
		Signature:  base64.StdEncoding.EncodeToString([]byte("sig")),
		Host: &HostAttestationRequest{
			QuoteData:     base64.StdEncoding.EncodeToString([]byte("quote")),
			Signature:     base64.StdEncoding.EncodeToString([]byte("sig")),
			PCRDigest:     base64.StdEncoding.EncodeToString([]byte("digest")),
			Nonce:         base64.StdEncoding.EncodeToString([]byte("nonce")),
			HashAlgorithm: "sha256",
		},
	}

	m, err := handlers.requestToManifest(req)

	require.NoError(t, err)
	assert.NotNil(t, m)
	assert.NotNil(t, m.Host)
}

func TestRequestToManifest_WithVMs(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
		VMs: []VMAttestationRequest{
			{
				VMID:          "vm-1",
				HostID:        "host-1",
				QuoteData:     base64.StdEncoding.EncodeToString([]byte("quote")),
				Signature:     base64.StdEncoding.EncodeToString([]byte("sig")),
				PCRDigest:     base64.StdEncoding.EncodeToString([]byte("digest")),
				Nonce:         base64.StdEncoding.EncodeToString([]byte("nonce")),
				HashAlgorithm: "sha256",
			},
		},
	}

	m, err := handlers.requestToManifest(req)

	require.NoError(t, err)
	assert.NotNil(t, m)
	assert.Len(t, m.VMs, 1)
	assert.Equal(t, "vm-1", m.VMs[0].VMID)
}

func TestRequestToManifest_WithContainers(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
		Containers: []ContainerAttestationRequest{
			{
				ContainerID: "container-1",
				ImageID:     "image-1",
				Digest:      base64.StdEncoding.EncodeToString([]byte("digest")),
				PCRValue:    base64.StdEncoding.EncodeToString([]byte("pcr")),
			},
		},
	}

	m, err := handlers.requestToManifest(req)

	require.NoError(t, err)
	assert.NotNil(t, m)
	assert.Len(t, m.Containers, 1)
	assert.Equal(t, "container-1", m.Containers[0].ContainerID)
}

func TestRequestToManifest_InvalidVMQuoteData(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
		VMs: []VMAttestationRequest{
			{
				VMID:      "vm-1",
				QuoteData: "invalid!!!",
			},
		},
	}

	m, err := handlers.requestToManifest(req)

	assert.Error(t, err)
	assert.Nil(t, m)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToManifest_InvalidContainerDigest(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
		Containers: []ContainerAttestationRequest{
			{
				ContainerID: "container-1",
				Digest:      "invalid!!!",
			},
		},
	}

	m, err := handlers.requestToManifest(req)

	assert.Error(t, err)
	assert.Nil(t, m)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToHostAttestation_Nil(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	a, err := handlers.requestToHostAttestation(nil)

	assert.NoError(t, err)
	assert.Nil(t, a)
}

func TestRequestToHostAttestation_InvalidQuoteData(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &HostAttestationRequest{
		QuoteData: "invalid!!!",
	}

	a, err := handlers.requestToHostAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToHostAttestation_InvalidSignature(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &HostAttestationRequest{
		QuoteData: base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature: "invalid!!!",
	}

	a, err := handlers.requestToHostAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToHostAttestation_InvalidPCRDigest(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &HostAttestationRequest{
		QuoteData: base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		PCRDigest: "invalid!!!",
	}

	a, err := handlers.requestToHostAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToHostAttestation_InvalidNonce(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &HostAttestationRequest{
		QuoteData: base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		PCRDigest: base64.StdEncoding.EncodeToString([]byte("digest")),
		Nonce:     "invalid!!!",
	}

	a, err := handlers.requestToHostAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToHostAttestation_InvalidAKPublicKey(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &HostAttestationRequest{
		QuoteData:   base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature:   base64.StdEncoding.EncodeToString([]byte("sig")),
		PCRDigest:   base64.StdEncoding.EncodeToString([]byte("digest")),
		Nonce:       base64.StdEncoding.EncodeToString([]byte("nonce")),
		AKPublicKey: "invalid!!!",
	}

	a, err := handlers.requestToHostAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToHostAttestation_InvalidIDevIDCert(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &HostAttestationRequest{
		QuoteData:         base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature:         base64.StdEncoding.EncodeToString([]byte("sig")),
		PCRDigest:         base64.StdEncoding.EncodeToString([]byte("digest")),
		Nonce:             base64.StdEncoding.EncodeToString([]byte("nonce")),
		IDevIDCertificate: "invalid!!!",
	}

	a, err := handlers.requestToHostAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToHostAttestation_InvalidPCRValue(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &HostAttestationRequest{
		QuoteData: base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		PCRDigest: base64.StdEncoding.EncodeToString([]byte("digest")),
		Nonce:     base64.StdEncoding.EncodeToString([]byte("nonce")),
		PCRs: []PCRValueRequest{
			{Index: 0, Value: "invalid!!!", Algorithm: "sha256"},
		},
	}

	a, err := handlers.requestToHostAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToHostAttestation_WithAllFields(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &HostAttestationRequest{
		QuoteData:          base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature:          base64.StdEncoding.EncodeToString([]byte("sig")),
		SignatureAlgorithm: "RSA",
		PCRDigest:          base64.StdEncoding.EncodeToString([]byte("digest")),
		Nonce:              base64.StdEncoding.EncodeToString([]byte("nonce")),
		Timestamp:          time.Now(),
		AKPublicKey:        base64.StdEncoding.EncodeToString([]byte("ak-key")),
		IDevIDCertificate:  base64.StdEncoding.EncodeToString([]byte("cert")),
		HashAlgorithm:      "sha256",
		FirmwareVersion:    "1.0",
		PCRs: []PCRValueRequest{
			{Index: 0, Value: base64.StdEncoding.EncodeToString([]byte("pcr0")), Algorithm: "sha256"},
		},
	}

	a, err := handlers.requestToHostAttestation(req)

	require.NoError(t, err)
	assert.NotNil(t, a)
	assert.Equal(t, []byte("quote"), a.QuoteData)
	assert.Equal(t, []byte("sig"), a.Signature)
	assert.Equal(t, []byte("ak-key"), a.AKPublicKey)
	assert.Equal(t, []byte("cert"), a.IDevIDCertificate)
	assert.Len(t, a.PCRs, 1)
}

func TestRequestToVMAttestation_Nil(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	a, err := handlers.requestToVMAttestation(nil)

	assert.NoError(t, err)
	assert.Nil(t, a)
}

func TestRequestToVMAttestation_InvalidQuoteData(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &VMAttestationRequest{
		QuoteData: "invalid!!!",
	}

	a, err := handlers.requestToVMAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToVMAttestation_InvalidSignature(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &VMAttestationRequest{
		QuoteData: base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature: "invalid!!!",
	}

	a, err := handlers.requestToVMAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToVMAttestation_InvalidPCRDigest(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &VMAttestationRequest{
		QuoteData: base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		PCRDigest: "invalid!!!",
	}

	a, err := handlers.requestToVMAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToVMAttestation_InvalidNonce(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &VMAttestationRequest{
		QuoteData: base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		PCRDigest: base64.StdEncoding.EncodeToString([]byte("digest")),
		Nonce:     "invalid!!!",
	}

	a, err := handlers.requestToVMAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToVMAttestation_InvalidAIKPublicKey(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &VMAttestationRequest{
		QuoteData:    base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature:    base64.StdEncoding.EncodeToString([]byte("sig")),
		PCRDigest:    base64.StdEncoding.EncodeToString([]byte("digest")),
		Nonce:        base64.StdEncoding.EncodeToString([]byte("nonce")),
		AIKPublicKey: "invalid!!!",
	}

	a, err := handlers.requestToVMAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToVMAttestation_InvalidEKCertificate(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &VMAttestationRequest{
		QuoteData:     base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature:     base64.StdEncoding.EncodeToString([]byte("sig")),
		PCRDigest:     base64.StdEncoding.EncodeToString([]byte("digest")),
		Nonce:         base64.StdEncoding.EncodeToString([]byte("nonce")),
		EKCertificate: "invalid!!!",
	}

	a, err := handlers.requestToVMAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToVMAttestation_InvalidWorkloadPCR(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &VMAttestationRequest{
		QuoteData:   base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature:   base64.StdEncoding.EncodeToString([]byte("sig")),
		PCRDigest:   base64.StdEncoding.EncodeToString([]byte("digest")),
		Nonce:       base64.StdEncoding.EncodeToString([]byte("nonce")),
		WorkloadPCR: "invalid!!!",
	}

	a, err := handlers.requestToVMAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToVMAttestation_InvalidPCRValue(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &VMAttestationRequest{
		QuoteData: base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		PCRDigest: base64.StdEncoding.EncodeToString([]byte("digest")),
		Nonce:     base64.StdEncoding.EncodeToString([]byte("nonce")),
		PCRs: []PCRValueRequest{
			{Index: 0, Value: "invalid!!!", Algorithm: "sha256"},
		},
	}

	a, err := handlers.requestToVMAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToVMAttestation_WithAllFields(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &VMAttestationRequest{
		VMID:               "vm-1",
		HostID:             "host-1",
		QuoteData:          base64.StdEncoding.EncodeToString([]byte("quote")),
		Signature:          base64.StdEncoding.EncodeToString([]byte("sig")),
		SignatureAlgorithm: "RSA",
		PCRDigest:          base64.StdEncoding.EncodeToString([]byte("digest")),
		Nonce:              base64.StdEncoding.EncodeToString([]byte("nonce")),
		Timestamp:          time.Now(),
		AIKPublicKey:       base64.StdEncoding.EncodeToString([]byte("aik-key")),
		EKCertificate:      base64.StdEncoding.EncodeToString([]byte("ek-cert")),
		WorkloadPCR:        base64.StdEncoding.EncodeToString([]byte("workload")),
		HashAlgorithm:      "sha384",
		Metadata:           map[string]string{"key": "value"},
		PCRs: []PCRValueRequest{
			{Index: 0, Value: base64.StdEncoding.EncodeToString([]byte("pcr0")), Algorithm: "sha256"},
		},
	}

	a, err := handlers.requestToVMAttestation(req)

	require.NoError(t, err)
	assert.NotNil(t, a)
	assert.Equal(t, "vm-1", a.VMID)
	assert.Equal(t, "host-1", a.HostID)
	assert.Equal(t, []byte("quote"), a.QuoteData)
	assert.Equal(t, []byte("sig"), a.Signature)
	assert.Equal(t, []byte("aik-key"), a.AIKPublicKey)
	assert.Equal(t, []byte("ek-cert"), a.EKCertificate)
	assert.Equal(t, []byte("workload"), a.WorkloadPCR)
	assert.Equal(t, manifest.HashAlgorithmSHA384, a.HashAlgorithm)
	assert.Len(t, a.PCRs, 1)
}

func TestRequestToContainerAttestation_Nil(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	a, err := handlers.requestToContainerAttestation(nil)

	assert.NoError(t, err)
	assert.Nil(t, a)
}

func TestRequestToContainerAttestation_InvalidDigest(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &ContainerAttestationRequest{
		ContainerID: "c1",
		Digest:      "invalid!!!",
	}

	a, err := handlers.requestToContainerAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToContainerAttestation_InvalidPCRValue(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &ContainerAttestationRequest{
		ContainerID: "c1",
		Digest:      base64.StdEncoding.EncodeToString([]byte("digest")),
		PCRValue:    "invalid!!!",
	}

	a, err := handlers.requestToContainerAttestation(req)

	assert.Error(t, err)
	assert.Nil(t, a)
	_, ok := err.(ErrInvalidBase64)
	assert.True(t, ok)
}

func TestRequestToContainerAttestation_WithAllFields(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})
	now := time.Now()

	req := &ContainerAttestationRequest{
		ContainerID: "container-1",
		ImageID:     "image-1",
		ImageDigest: "sha256:abc123",
		Digest:      base64.StdEncoding.EncodeToString([]byte("digest")),
		PCRValue:    base64.StdEncoding.EncodeToString([]byte("pcr")),
		Timestamp:   now,
		Metadata:    map[string]string{"key": "value"},
	}

	a, err := handlers.requestToContainerAttestation(req)

	require.NoError(t, err)
	assert.NotNil(t, a)
	assert.Equal(t, "container-1", a.ContainerID)
	assert.Equal(t, "image-1", a.ImageID)
	assert.Equal(t, "sha256:abc123", a.ImageDigest)
	assert.Equal(t, []byte("digest"), a.Digest)
	assert.Equal(t, []byte("pcr"), a.PCRValue)
	assert.Equal(t, now, a.Timestamp)
	assert.Equal(t, map[string]string{"key": "value"}, a.Metadata)
}

func TestRequestToManifest_InvalidHostAttestation(t *testing.T) {
	handlers, _ := newTestHandlers(&mockAttestationService{})

	req := &ManifestRequest{
		ID:         "test",
		HostID:     "test",
		Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
		MerkleRoot: base64.StdEncoding.EncodeToString([]byte("root")),
		Host: &HostAttestationRequest{
			QuoteData: "invalid!!!",
		},
	}

	m, err := handlers.requestToManifest(req)

	assert.Error(t, err)
	assert.Nil(t, m)
}
