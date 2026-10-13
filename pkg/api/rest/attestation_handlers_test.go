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
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"

	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// =============================================================================
// Mock Attestation Service
// =============================================================================

type mockAttestationService struct {
	getManifestFunc            func(ctx context.Context, id string) (*manifest.HostManifest, error)
	buildManifestFunc          func(ctx context.Context, config *BuildManifestConfig) (*manifest.HostManifest, error)
	verifyManifestFunc         func(ctx context.Context, m *manifest.HostManifest, opts *VerifyManifestOptions) (*manifest.VerificationResult, error)
	collectHostAttestationFunc func(ctx context.Context, opts *CollectAttestationOptions) (*manifest.HostAttestation, error)
	attestVMFunc               func(ctx context.Context, vmID string, opts *CollectAttestationOptions) (*manifest.VMAttestation, error)
	attestContainerFunc        func(ctx context.Context, containerID string, opts *CollectAttestationOptions) (*manifest.ContainerAttestation, error)
	attestDeviceFunc           func(ctx context.Context, deviceID string, opts *CollectAttestationOptions) (*DeviceAttestationResult, error)
	listReportsFunc            func(ctx context.Context, filter *ReportFilter) ([]*AttestationReportResponse, int, error)
	getReportFunc              func(ctx context.Context, id string) (*AttestationReportResponse, error)
	createPolicyFunc           func(ctx context.Context, policy *AttestationPolicyRequest) (*AttestationPolicyResponse, error)
	listPoliciesFunc           func(ctx context.Context, filter *AttestationPolicyFilter) ([]*AttestationPolicyResponse, int, error)
}

func (m *mockAttestationService) GetManifest(ctx context.Context, id string) (*manifest.HostManifest, error) {
	if m.getManifestFunc != nil {
		return m.getManifestFunc(ctx, id)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) BuildManifest(ctx context.Context, config *BuildManifestConfig) (*manifest.HostManifest, error) {
	if m.buildManifestFunc != nil {
		return m.buildManifestFunc(ctx, config)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) VerifyManifest(ctx context.Context, man *manifest.HostManifest, opts *VerifyManifestOptions) (*manifest.VerificationResult, error) {
	if m.verifyManifestFunc != nil {
		return m.verifyManifestFunc(ctx, man, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) CollectHostAttestation(ctx context.Context, opts *CollectAttestationOptions) (*manifest.HostAttestation, error) {
	if m.collectHostAttestationFunc != nil {
		return m.collectHostAttestationFunc(ctx, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) AttestVM(ctx context.Context, vmID string, opts *CollectAttestationOptions) (*manifest.VMAttestation, error) {
	if m.attestVMFunc != nil {
		return m.attestVMFunc(ctx, vmID, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) AttestContainer(ctx context.Context, containerID string, opts *CollectAttestationOptions) (*manifest.ContainerAttestation, error) {
	if m.attestContainerFunc != nil {
		return m.attestContainerFunc(ctx, containerID, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) AttestDevice(ctx context.Context, deviceID string, opts *CollectAttestationOptions) (*DeviceAttestationResult, error) {
	if m.attestDeviceFunc != nil {
		return m.attestDeviceFunc(ctx, deviceID, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) ListReports(ctx context.Context, filter *ReportFilter) ([]*AttestationReportResponse, int, error) {
	if m.listReportsFunc != nil {
		return m.listReportsFunc(ctx, filter)
	}
	return nil, 0, errors.New("not implemented")
}

func (m *mockAttestationService) GetReport(ctx context.Context, id string) (*AttestationReportResponse, error) {
	if m.getReportFunc != nil {
		return m.getReportFunc(ctx, id)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) CreatePolicy(ctx context.Context, policy *AttestationPolicyRequest) (*AttestationPolicyResponse, error) {
	if m.createPolicyFunc != nil {
		return m.createPolicyFunc(ctx, policy)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAttestationService) ListPolicies(ctx context.Context, filter *AttestationPolicyFilter) ([]*AttestationPolicyResponse, int, error) {
	if m.listPoliciesFunc != nil {
		return m.listPoliciesFunc(ctx, filter)
	}
	return nil, 0, errors.New("not implemented")
}

// =============================================================================
// Test Helpers
// =============================================================================

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func createTestManifest() *manifest.HostManifest {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	merkleRoot := make([]byte, 32)
	for i := range merkleRoot {
		merkleRoot[i] = byte(i + 32)
	}
	quoteData := make([]byte, 64)
	signature := make([]byte, 256)
	pcrValue := make([]byte, 32)

	return &manifest.HostManifest{
		ID:                 "test-manifest-001",
		HostID:             "host-001",
		Timestamp:          time.Now().UTC(),
		Nonce:              nonce,
		MerkleRoot:         merkleRoot,
		Signature:          signature,
		SignatureAlgorithm: "RSASSA-PKCS1-v1_5-SHA256",
		Version:            "1.0",
		Metadata:           map[string]string{"env": "test"},
		Host: &manifest.HostAttestation{
			QuoteData:          quoteData,
			Signature:          signature,
			SignatureAlgorithm: "RSASSA-PKCS1-v1_5-SHA256",
			PCRDigest:          merkleRoot,
			Nonce:              nonce,
			Timestamp:          time.Now().UTC(),
			HashAlgorithm:      manifest.HashAlgorithmSHA256,
			FirmwareVersion:    "1.2.3",
			PCRs: []manifest.PCRValue{
				{Index: 0, Value: pcrValue, Algorithm: manifest.HashAlgorithmSHA256},
				{Index: 7, Value: pcrValue, Algorithm: manifest.HashAlgorithmSHA256},
			},
		},
		VMs: []manifest.VMAttestation{
			{
				VMID:               "vm-001",
				HostID:             "host-001",
				QuoteData:          quoteData,
				Signature:          signature,
				SignatureAlgorithm: "RSASSA-PKCS1-v1_5-SHA256",
				PCRDigest:          merkleRoot,
				Nonce:              nonce,
				Timestamp:          time.Now().UTC(),
				HashAlgorithm:      manifest.HashAlgorithmSHA256,
				PCRs: []manifest.PCRValue{
					{Index: 0, Value: pcrValue, Algorithm: manifest.HashAlgorithmSHA256},
				},
			},
		},
		Containers: []manifest.ContainerAttestation{
			{
				ContainerID: "container-001",
				ImageID:     "sha256:abc123",
				ImageDigest: "sha256:abc123",
				Digest:      pcrValue,
				PCRValue:    pcrValue,
				Timestamp:   time.Now().UTC(),
			},
		},
	}
}

func createTestHostAttestation() *manifest.HostAttestation {
	nonce := make([]byte, 32)
	quoteData := make([]byte, 64)
	signature := make([]byte, 256)
	pcrDigest := make([]byte, 32)
	pcrValue := make([]byte, 32)

	return &manifest.HostAttestation{
		QuoteData:          quoteData,
		Signature:          signature,
		SignatureAlgorithm: "RSASSA-PKCS1-v1_5-SHA256",
		PCRDigest:          pcrDigest,
		Nonce:              nonce,
		Timestamp:          time.Now().UTC(),
		HashAlgorithm:      manifest.HashAlgorithmSHA256,
		FirmwareVersion:    "1.2.3",
		PCRs: []manifest.PCRValue{
			{Index: 0, Value: pcrValue, Algorithm: manifest.HashAlgorithmSHA256},
			{Index: 7, Value: pcrValue, Algorithm: manifest.HashAlgorithmSHA256},
		},
	}
}

func createTestVMAttestation(vmID string) *manifest.VMAttestation {
	nonce := make([]byte, 32)
	quoteData := make([]byte, 64)
	signature := make([]byte, 256)
	pcrDigest := make([]byte, 32)
	pcrValue := make([]byte, 32)
	workloadPCR := make([]byte, 32)

	return &manifest.VMAttestation{
		VMID:               vmID,
		HostID:             "host-001",
		QuoteData:          quoteData,
		Signature:          signature,
		SignatureAlgorithm: "RSASSA-PKCS1-v1_5-SHA256",
		PCRDigest:          pcrDigest,
		Nonce:              nonce,
		Timestamp:          time.Now().UTC(),
		HashAlgorithm:      manifest.HashAlgorithmSHA256,
		WorkloadPCR:        workloadPCR,
		PCRs: []manifest.PCRValue{
			{Index: 0, Value: pcrValue, Algorithm: manifest.HashAlgorithmSHA256},
			{Index: 14, Value: workloadPCR, Algorithm: manifest.HashAlgorithmSHA256},
		},
	}
}

func createTestContainerAttestation(containerID string) *manifest.ContainerAttestation {
	digest := make([]byte, 32)
	pcrValue := make([]byte, 32)

	return &manifest.ContainerAttestation{
		ContainerID: containerID,
		ImageID:     "sha256:abc123",
		ImageDigest: "sha256:abc123",
		Digest:      digest,
		PCRValue:    pcrValue,
		Timestamp:   time.Now().UTC(),
		Metadata:    map[string]string{"env": "test"},
	}
}

func createTestDeviceAttestation(deviceID string) *DeviceAttestationResult {
	quoteData := make([]byte, 64)
	signature := make([]byte, 256)
	pcrValue := make([]byte, 32)

	return &DeviceAttestationResult{
		DeviceID:   deviceID,
		DeviceType: "tpm",
		Verified:   true,
		QuoteData:  quoteData,
		Signature:  signature,
		PCRValues:  map[int][]byte{0: pcrValue, 7: pcrValue},
		Timestamp:  time.Now().UTC(),
		Metadata:   map[string]string{"firmware": "1.0"},
		PolicyResult: &AttestationPolicyEvaluation{
			PolicyID:    "policy-001",
			PolicyName:  "default",
			Passed:      true,
			EvaluatedAt: time.Now().UTC(),
		},
	}
}

func createTestVerificationResult() *manifest.VerificationResult {
	return &manifest.VerificationResult{
		Status:                     manifest.VerificationStatusVerified,
		SignatureValid:             true,
		MerkleRootValid:            true,
		NonceValid:                 true,
		TimestampValid:             true,
		HostAttestationValid:       true,
		VMAttestationsValid:        true,
		ContainerAttestationsValid: true,
		VerifiedAt:                 time.Now().UTC(),
		VMErrors:                   make(map[string]string),
		ContainerErrors:            make(map[string]string),
	}
}

// =============================================================================
// Handler Construction Tests
// =============================================================================

func TestNewAttestationHandlers(t *testing.T) {
	t.Run("WithService", func(t *testing.T) {
		service := &mockAttestationService{}
		logger := testLogger()
		handlers := NewAttestationHandlers(service, logger)

		if handlers == nil {
			t.Fatal("expected handlers to be non-nil")
		}
		if handlers.service == nil {
			t.Error("expected service to be set")
		}
		if handlers.logger == nil {
			t.Error("expected logger to be set")
		}
	})

	t.Run("NilLogger", func(t *testing.T) {
		service := &mockAttestationService{}
		handlers := NewAttestationHandlers(service, nil)

		if handlers == nil {
			t.Fatal("expected handlers to be non-nil")
		}
		if handlers.logger == nil {
			t.Error("expected default logger to be set")
		}
	})
}

func TestAttestationHandlers_RegisterRoutes(t *testing.T) {
	service := &mockAttestationService{}
	logger := testLogger()
	handlers := NewAttestationHandlers(service, logger)

	router := mux.NewRouter()
	handlers.RegisterAttestationRoutes(router)

	expectedRoutes := []struct {
		path   string
		method string
	}{
		{"/api/v1/attestation/manifest", http.MethodGet},
		{"/api/v1/attestation/manifest", http.MethodPost},
		{"/api/v1/attestation/manifest/verify", http.MethodPost},
		{"/api/v1/attestation/host", http.MethodPost},
		{"/api/v1/attestation/vm/{id}", http.MethodPost},
		{"/api/v1/attestation/container/{id}", http.MethodPost},
		{"/api/v1/attestation/device/{id}", http.MethodPost},
		{"/api/v1/attestation/reports", http.MethodGet},
		{"/api/v1/attestation/reports/{id}", http.MethodGet},
		{"/api/v1/attestation/policies", http.MethodPost},
		{"/api/v1/attestation/policies", http.MethodGet},
	}

	for _, expected := range expectedRoutes {
		route := router.GetRoute(expected.path + "_" + expected.method)
		if route == nil {
			var match mux.RouteMatch
			req := httptest.NewRequest(expected.method, expected.path, nil)
			switch expected.path {
			case "/api/v1/attestation/vm/{id}":
				req = httptest.NewRequest(expected.method, "/api/v1/attestation/vm/test-vm", nil)
			case "/api/v1/attestation/container/{id}":
				req = httptest.NewRequest(expected.method, "/api/v1/attestation/container/test-container", nil)
			case "/api/v1/attestation/device/{id}":
				req = httptest.NewRequest(expected.method, "/api/v1/attestation/device/test-device", nil)
			case "/api/v1/attestation/reports/{id}":
				req = httptest.NewRequest(expected.method, "/api/v1/attestation/reports/test-report", nil)
			}
			if !router.Match(req, &match) {
				t.Errorf("route not found: %s %s", expected.method, expected.path)
			}
		}
	}
}

// =============================================================================
// Manifest Handler Tests
// =============================================================================

func TestAttestationHandlers_GetManifest(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		testManifest := createTestManifest()
		service := &mockAttestationService{
			getManifestFunc: func(ctx context.Context, id string) (*manifest.HostManifest, error) {
				return testManifest, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/manifest", nil)
		w := httptest.NewRecorder()

		handlers.handleGetManifest(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		var resp ManifestResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.ID != testManifest.ID {
			t.Errorf("expected ID %s, got %s", testManifest.ID, resp.ID)
		}
		if resp.HostID != testManifest.HostID {
			t.Errorf("expected HostID %s, got %s", testManifest.HostID, resp.HostID)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		service := &mockAttestationService{
			getManifestFunc: func(ctx context.Context, id string) (*manifest.HostManifest, error) {
				return nil, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/manifest?id=nonexistent", nil)
		w := httptest.NewRecorder()

		handlers.handleGetManifest(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("ServiceError", func(t *testing.T) {
		service := &mockAttestationService{
			getManifestFunc: func(ctx context.Context, id string) (*manifest.HostManifest, error) {
				return nil, errors.New("service error")
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/manifest", nil)
		w := httptest.NewRecorder()

		handlers.handleGetManifest(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
	})

	t.Run("ServiceNotAvailable", func(t *testing.T) {
		handlers := NewAttestationHandlers(nil, testLogger())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/manifest", nil)
		w := httptest.NewRecorder()

		handlers.handleGetManifest(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
		}
	})
}

func TestAttestationHandlers_BuildManifest(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		testManifest := createTestManifest()
		service := &mockAttestationService{
			buildManifestFunc: func(ctx context.Context, config *BuildManifestConfig) (*manifest.HostManifest, error) {
				return testManifest, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		reqBody := BuildManifestRequest{
			HostID:        "host-001",
			HashAlgorithm: "sha256",
			PCRIndices:    []int{0, 1, 7},
			Sign:          true,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifest", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handlers.handleBuildManifest(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
		}

		var resp ManifestResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.ID != testManifest.ID {
			t.Errorf("expected ID %s, got %s", testManifest.ID, resp.ID)
		}
	})

	t.Run("WithNonce", func(t *testing.T) {
		testManifest := createTestManifest()
		var receivedNonce []byte
		service := &mockAttestationService{
			buildManifestFunc: func(ctx context.Context, config *BuildManifestConfig) (*manifest.HostManifest, error) {
				receivedNonce = config.Nonce
				return testManifest, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		nonce := make([]byte, 32)
		for i := range nonce {
			nonce[i] = byte(i)
		}
		reqBody := BuildManifestRequest{
			HostID: "host-001",
			Nonce:  base64.StdEncoding.EncodeToString(nonce),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifest", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handlers.handleBuildManifest(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
		}

		if !bytes.Equal(receivedNonce, nonce) {
			t.Error("nonce was not passed correctly to service")
		}
	})

	t.Run("InvalidBody", func(t *testing.T) {
		service := &mockAttestationService{}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifest", strings.NewReader("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handlers.handleBuildManifest(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("InvalidNonce", func(t *testing.T) {
		service := &mockAttestationService{}
		handlers := NewAttestationHandlers(service, testLogger())

		reqBody := BuildManifestRequest{
			HostID: "host-001",
			Nonce:  "invalid-base64!!!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifest", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handlers.handleBuildManifest(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("InvalidHashAlgorithm", func(t *testing.T) {
		service := &mockAttestationService{}
		handlers := NewAttestationHandlers(service, testLogger())

		reqBody := BuildManifestRequest{
			HostID:        "host-001",
			HashAlgorithm: "md5",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifest", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handlers.handleBuildManifest(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("InvalidPCRIndex", func(t *testing.T) {
		service := &mockAttestationService{}
		handlers := NewAttestationHandlers(service, testLogger())

		reqBody := BuildManifestRequest{
			HostID:     "host-001",
			PCRIndices: []int{0, 24}, // 24 is invalid
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifest", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handlers.handleBuildManifest(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

func TestAttestationHandlers_VerifyManifest(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		result := createTestVerificationResult()
		service := &mockAttestationService{
			verifyManifestFunc: func(ctx context.Context, m *manifest.HostManifest, opts *VerifyManifestOptions) (*manifest.VerificationResult, error) {
				return result, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		testManifest := createTestManifest()
		reqBody := VerifyManifestRequest{
			Manifest: &ManifestRequest{
				ID:         testManifest.ID,
				HostID:     testManifest.HostID,
				Timestamp:  testManifest.Timestamp,
				Nonce:      base64.StdEncoding.EncodeToString(testManifest.Nonce),
				MerkleRoot: base64.StdEncoding.EncodeToString(testManifest.MerkleRoot),
				Signature:  base64.StdEncoding.EncodeToString(testManifest.Signature),
				Version:    testManifest.Version,
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifest/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handlers.handleVerifyManifest(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp VerificationResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if !resp.Valid {
			t.Error("expected verification to be valid")
		}
	})

	t.Run("MissingManifest", func(t *testing.T) {
		service := &mockAttestationService{}
		handlers := NewAttestationHandlers(service, testLogger())

		reqBody := VerifyManifestRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifest/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handlers.handleVerifyManifest(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

// =============================================================================
// Host Attestation Handler Tests
// =============================================================================

func TestAttestationHandlers_CollectHostAttestation(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		testAttestation := createTestHostAttestation()
		service := &mockAttestationService{
			collectHostAttestationFunc: func(ctx context.Context, opts *CollectAttestationOptions) (*manifest.HostAttestation, error) {
				return testAttestation, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		reqBody := CollectHostAttestationRequest{
			PCRIndices:    []int{0, 7},
			HashAlgorithm: "sha256",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/host", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = testutil.ServerConnectionState(t)
		w := httptest.NewRecorder()

		handlers.handleCollectHostAttestation(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp HostAttestationResp
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.HashAlgorithm != "sha256" {
			t.Errorf("expected hash algorithm sha256, got %s", resp.HashAlgorithm)
		}
	})

	t.Run("QuotesTheNonceBoundToItsOwnConnection", func(t *testing.T) {
		var quoted []byte
		service := &mockAttestationService{
			collectHostAttestationFunc: func(ctx context.Context, opts *CollectAttestationOptions) (*manifest.HostAttestation, error) {
				quoted = opts.Nonce
				return createTestHostAttestation(), nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())
		nonce := []byte("0123456789abcdef")
		body, err := json.Marshal(CollectHostAttestationRequest{Nonce: base64.StdEncoding.EncodeToString(nonce)})
		if err != nil {
			t.Fatalf("failed to encode request: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/host", bytes.NewReader(body))
		req.TLS = testutil.ServerConnectionState(t)
		w := httptest.NewRecorder()

		handlers.handleCollectHostAttestation(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
		binding, err := req.TLS.ExportKeyingMaterial(xkmssdk.PeerChannelBindingExporterLabel, nil, xkmssdk.PeerChannelBindingLength)
		if err != nil {
			t.Fatalf("exporter failed: %v", err)
		}
		if !bytes.Equal(quoted, xkmssdk.PeerQualifyingData(nonce, binding)) {
			t.Errorf("the service was handed %x, want the nonce bound to the request's connection (#482)", quoted)
		}
	})

	t.Run("RefusesAConnectionWithNoBinding", func(t *testing.T) {
		states := map[string]*tls.ConnectionState{
			"plain HTTP":       nil,
			"exporter refused": {Version: tls.VersionTLS12},
		}
		for name, state := range states {
			t.Run(name, func(t *testing.T) {
				called := false
				service := &mockAttestationService{
					collectHostAttestationFunc: func(ctx context.Context, opts *CollectAttestationOptions) (*manifest.HostAttestation, error) {
						called = true
						return createTestHostAttestation(), nil
					},
				}
				handlers := NewAttestationHandlers(service, testLogger())

				req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/host", strings.NewReader(`{}`))
				req.TLS = state
				w := httptest.NewRecorder()

				handlers.handleCollectHostAttestation(w, req)

				if w.Code != http.StatusBadRequest {
					t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
				}
				if called {
					t.Error("an unbound request must never reach the TPM")
				}
			})
		}
	})

	t.Run("ServiceError", func(t *testing.T) {
		service := &mockAttestationService{
			collectHostAttestationFunc: func(ctx context.Context, opts *CollectAttestationOptions) (*manifest.HostAttestation, error) {
				return nil, errors.New("TPM not available")
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		reqBody := CollectHostAttestationRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/host", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = testutil.ServerConnectionState(t)
		w := httptest.NewRecorder()

		handlers.handleCollectHostAttestation(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
		}
	})
}

// =============================================================================
// Workload Attestation Handler Tests
// =============================================================================

func TestAttestationHandlers_AttestVM(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		vmID := "vm-001"
		testAttestation := createTestVMAttestation(vmID)
		service := &mockAttestationService{
			attestVMFunc: func(ctx context.Context, id string, opts *CollectAttestationOptions) (*manifest.VMAttestation, error) {
				if id != vmID {
					t.Errorf("expected VM ID %s, got %s", vmID, id)
				}
				return testAttestation, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		router := mux.NewRouter()
		router.HandleFunc("/api/v1/attestation/vm/{id}", handlers.handleAttestVM).Methods(http.MethodPost)

		reqBody := AttestWorkloadRequest{
			PCRIndices:    []int{0, 14},
			HashAlgorithm: "sha256",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/vm/"+vmID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp VMAttestationResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.VMID != vmID {
			t.Errorf("expected VM ID %s, got %s", vmID, resp.VMID)
		}
	})

	t.Run("MissingVMID", func(t *testing.T) {
		service := &mockAttestationService{}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/vm/", nil)
		w := httptest.NewRecorder()

		handlers.handleAttestVM(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("VMNotFound", func(t *testing.T) {
		service := &mockAttestationService{
			attestVMFunc: func(ctx context.Context, id string, opts *CollectAttestationOptions) (*manifest.VMAttestation, error) {
				return nil, errors.New("VM not found")
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		router := mux.NewRouter()
		router.HandleFunc("/api/v1/attestation/vm/{id}", handlers.handleAttestVM).Methods(http.MethodPost)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/vm/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})
}

func TestAttestationHandlers_AttestContainer(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		containerID := "container-001"
		testAttestation := createTestContainerAttestation(containerID)
		service := &mockAttestationService{
			attestContainerFunc: func(ctx context.Context, id string, opts *CollectAttestationOptions) (*manifest.ContainerAttestation, error) {
				if id != containerID {
					t.Errorf("expected container ID %s, got %s", containerID, id)
				}
				return testAttestation, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		router := mux.NewRouter()
		router.HandleFunc("/api/v1/attestation/container/{id}", handlers.handleAttestContainer).Methods(http.MethodPost)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/container/"+containerID, nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp ContainerAttestationResp
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.ContainerID != containerID {
			t.Errorf("expected container ID %s, got %s", containerID, resp.ContainerID)
		}
	})

	t.Run("MissingContainerID", func(t *testing.T) {
		service := &mockAttestationService{}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/container/", nil)
		w := httptest.NewRecorder()

		handlers.handleAttestContainer(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

func TestAttestationHandlers_AttestDevice(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		deviceID := "device-001"
		testResult := createTestDeviceAttestation(deviceID)
		service := &mockAttestationService{
			attestDeviceFunc: func(ctx context.Context, id string, opts *CollectAttestationOptions) (*DeviceAttestationResult, error) {
				if id != deviceID {
					t.Errorf("expected device ID %s, got %s", deviceID, id)
				}
				return testResult, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		router := mux.NewRouter()
		router.HandleFunc("/api/v1/attestation/device/{id}", handlers.handleAttestDevice).Methods(http.MethodPost)

		reqBody := AttestWorkloadRequest{
			PolicyID: "policy-001",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/device/"+deviceID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp DeviceAttestationResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.DeviceID != deviceID {
			t.Errorf("expected device ID %s, got %s", deviceID, resp.DeviceID)
		}
		if !resp.Verified {
			t.Error("expected device to be verified")
		}
	})

	t.Run("MissingDeviceID", func(t *testing.T) {
		service := &mockAttestationService{}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/device/", nil)
		w := httptest.NewRecorder()

		handlers.handleAttestDevice(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

// =============================================================================
// Report Handler Tests
// =============================================================================

func TestAttestationHandlers_ListReports(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		reports := []*AttestationReportResponse{
			{
				ID:        "report-001",
				HostID:    "host-001",
				Type:      "host",
				Status:    "verified",
				CreatedAt: time.Now().UTC(),
			},
			{
				ID:         "report-002",
				HostID:     "host-001",
				Type:       "vm",
				WorkloadID: "vm-001",
				Status:     "verified",
				CreatedAt:  time.Now().UTC(),
			},
		}
		service := &mockAttestationService{
			listReportsFunc: func(ctx context.Context, filter *ReportFilter) ([]*AttestationReportResponse, int, error) {
				return reports, len(reports), nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/reports", nil)
		w := httptest.NewRecorder()

		handlers.handleListReports(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		var resp ReportListResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.Count != 2 {
			t.Errorf("expected 2 reports, got %d", resp.Count)
		}
	})

	t.Run("WithFilter", func(t *testing.T) {
		var receivedFilter *ReportFilter
		service := &mockAttestationService{
			listReportsFunc: func(ctx context.Context, filter *ReportFilter) ([]*AttestationReportResponse, int, error) {
				receivedFilter = filter
				return nil, 0, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/reports?host_id=host-001&status=verified&limit=10", nil)
		w := httptest.NewRecorder()

		handlers.handleListReports(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		if receivedFilter.HostID != "host-001" {
			t.Errorf("expected host_id filter host-001, got %s", receivedFilter.HostID)
		}
		if receivedFilter.Status != "verified" {
			t.Errorf("expected status filter verified, got %s", receivedFilter.Status)
		}
		if receivedFilter.Limit != 10 {
			t.Errorf("expected limit 10, got %d", receivedFilter.Limit)
		}
	})
}

func TestAttestationHandlers_GetReport(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		reportID := "report-001"
		report := &AttestationReportResponse{
			ID:        reportID,
			HostID:    "host-001",
			Type:      "host",
			Status:    "verified",
			CreatedAt: time.Now().UTC(),
		}
		service := &mockAttestationService{
			getReportFunc: func(ctx context.Context, id string) (*AttestationReportResponse, error) {
				if id != reportID {
					t.Errorf("expected report ID %s, got %s", reportID, id)
				}
				return report, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		router := mux.NewRouter()
		router.HandleFunc("/api/v1/attestation/reports/{id}", handlers.handleGetReport).Methods(http.MethodGet)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/reports/"+reportID, nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		service := &mockAttestationService{
			getReportFunc: func(ctx context.Context, id string) (*AttestationReportResponse, error) {
				return nil, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		router := mux.NewRouter()
		router.HandleFunc("/api/v1/attestation/reports/{id}", handlers.handleGetReport).Methods(http.MethodGet)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/reports/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("MissingID", func(t *testing.T) {
		service := &mockAttestationService{}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/reports/", nil)
		w := httptest.NewRecorder()

		handlers.handleGetReport(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

// =============================================================================
// Policy Handler Tests
// =============================================================================

func TestAttestationHandlers_CreatePolicy(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		service := &mockAttestationService{
			createPolicyFunc: func(ctx context.Context, policy *AttestationPolicyRequest) (*AttestationPolicyResponse, error) {
				return &AttestationPolicyResponse{
					ID:          "policy-001",
					Name:        policy.Name,
					Description: policy.Description,
					Active:      policy.Active,
					CreatedAt:   time.Now().UTC(),
					UpdatedAt:   time.Now().UTC(),
				}, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		reqBody := AttestationPolicyRequest{
			Name:        "default-policy",
			Description: "Default attestation policy",
			Active:      true,
			PCRPolicy: &AttestationPCRPolicy{
				RequiredPCRs: []int{0, 7},
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/policies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handlers.handleCreatePolicy(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
		}

		var resp AttestationPolicyResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.Name != reqBody.Name {
			t.Errorf("expected name %s, got %s", reqBody.Name, resp.Name)
		}
	})

	t.Run("MissingName", func(t *testing.T) {
		service := &mockAttestationService{}
		handlers := NewAttestationHandlers(service, testLogger())

		reqBody := AttestationPolicyRequest{
			Description: "Policy without name",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/policies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handlers.handleCreatePolicy(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("InvalidBody", func(t *testing.T) {
		service := &mockAttestationService{}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/policies", strings.NewReader("invalid"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handlers.handleCreatePolicy(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

func TestAttestationHandlers_ListPolicies(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		policies := []*AttestationPolicyResponse{
			{
				ID:        "policy-001",
				Name:      "default",
				Active:    true,
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			},
			{
				ID:        "policy-002",
				Name:      "strict",
				Active:    true,
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			},
		}
		service := &mockAttestationService{
			listPoliciesFunc: func(ctx context.Context, filter *AttestationPolicyFilter) ([]*AttestationPolicyResponse, int, error) {
				return policies, len(policies), nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/policies", nil)
		w := httptest.NewRecorder()

		handlers.handleListPolicies(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		var resp AttestationPolicyListResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.Count != 2 {
			t.Errorf("expected 2 policies, got %d", resp.Count)
		}
	})

	t.Run("WithFilter", func(t *testing.T) {
		var receivedFilter *AttestationPolicyFilter
		service := &mockAttestationService{
			listPoliciesFunc: func(ctx context.Context, filter *AttestationPolicyFilter) ([]*AttestationPolicyResponse, int, error) {
				receivedFilter = filter
				return nil, 0, nil
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/policies?name=default&active=true", nil)
		w := httptest.NewRecorder()

		handlers.handleListPolicies(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		if receivedFilter.Name != "default" {
			t.Errorf("expected name filter default, got %s", receivedFilter.Name)
		}
	})
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestAttestationErrorTypes(t *testing.T) {
	t.Run("ErrAttestationServiceNotAvailable", func(t *testing.T) {
		err := ErrAttestationServiceNotAvailable{}
		expected := "attestation service not available"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrInvalidManifestID", func(t *testing.T) {
		err := ErrInvalidManifestID{}
		if !strings.Contains(err.Error(), "manifest ID") {
			t.Errorf("expected error to mention manifest ID")
		}

		err = ErrInvalidManifestID{ID: "test-id"}
		if !strings.Contains(err.Error(), "test-id") {
			t.Errorf("expected error to contain ID")
		}
	})

	t.Run("ErrInvalidVMID", func(t *testing.T) {
		err := ErrInvalidVMID{}
		if !strings.Contains(err.Error(), "VM ID") {
			t.Errorf("expected error to mention VM ID")
		}

		err = ErrInvalidVMID{ID: "vm-001"}
		if !strings.Contains(err.Error(), "vm-001") {
			t.Errorf("expected error to contain ID")
		}
	})

	t.Run("ErrInvalidDeviceID", func(t *testing.T) {
		err := ErrInvalidDeviceID{}
		if !strings.Contains(err.Error(), "device ID") {
			t.Errorf("expected error to mention device ID")
		}
	})

	t.Run("ErrAttestationFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrAttestationFailed{Operation: "test", Cause: cause}
		if !strings.Contains(err.Error(), "test") {
			t.Errorf("expected error to contain operation")
		}
		if errors.Unwrap(err) != cause {
			t.Error("expected Unwrap to return cause")
		}
	})

	t.Run("ErrInvalidNonce", func(t *testing.T) {
		err := ErrInvalidNonce{Reason: "too short"}
		if !strings.Contains(err.Error(), "nonce") {
			t.Errorf("expected error to mention nonce")
		}
	})

	t.Run("ErrInvalidHashAlgorithm", func(t *testing.T) {
		err := ErrInvalidHashAlgorithm{Algorithm: "md5"}
		if !strings.Contains(err.Error(), "md5") {
			t.Errorf("expected error to contain algorithm")
		}
	})

	t.Run("ErrManifestNotFound", func(t *testing.T) {
		err := ErrManifestNotFound{ID: "manifest-001"}
		if !strings.Contains(err.Error(), "manifest-001") {
			t.Errorf("expected error to contain ID")
		}
	})

	t.Run("ErrReportNotFound", func(t *testing.T) {
		err := ErrReportNotFound{ID: "report-001"}
		if !strings.Contains(err.Error(), "report-001") {
			t.Errorf("expected error to contain ID")
		}
	})

	t.Run("ErrAttestationPolicyNotFound", func(t *testing.T) {
		err := ErrAttestationPolicyNotFound{ID: "policy-001"}
		if !strings.Contains(err.Error(), "policy-001") {
			t.Errorf("expected error to contain ID")
		}
	})

	t.Run("ErrInvalidPCRIndex", func(t *testing.T) {
		err := ErrInvalidPCRIndex{Index: 25}
		if !strings.Contains(err.Error(), "25") {
			t.Errorf("expected error to contain index")
		}
	})
}

// =============================================================================
// Request to Manifest Tests
// =============================================================================

func TestRequestToManifest(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

	t.Run("ValidRequest", func(t *testing.T) {
		nonce := make([]byte, 32)
		merkleRoot := make([]byte, 32)
		req := &ManifestRequest{
			ID:         "test-001",
			HostID:     "host-001",
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			MerkleRoot: base64.StdEncoding.EncodeToString(merkleRoot),
		}

		m, err := handlers.requestToManifest(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if m.ID != req.ID {
			t.Errorf("expected ID %s, got %s", req.ID, m.ID)
		}
	})

	t.Run("InvalidNonce", func(t *testing.T) {
		req := &ManifestRequest{
			ID:         "test-001",
			Nonce:      "invalid-base64!!!",
			MerkleRoot: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		}

		_, err := handlers.requestToManifest(req)
		if err == nil {
			t.Error("expected error for invalid nonce")
		}
	})

	t.Run("InvalidMerkleRoot", func(t *testing.T) {
		req := &ManifestRequest{
			ID:         "test-001",
			Nonce:      base64.StdEncoding.EncodeToString(make([]byte, 32)),
			MerkleRoot: "invalid-base64!!!",
		}

		_, err := handlers.requestToManifest(req)
		if err == nil {
			t.Error("expected error for invalid merkle root")
		}
	})

	t.Run("NilRequest", func(t *testing.T) {
		_, err := handlers.requestToManifest(nil)
		if err == nil {
			t.Error("expected error for nil request")
		}
	})
}

// =============================================================================
// Error Mapping Tests
// =============================================================================

func TestAttestationHandlers_WriteAttestationError(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "NotFound",
			err:            errors.New("manifest not found"),
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Invalid",
			err:            errors.New("invalid nonce"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Expired",
			err:            errors.New("manifest expired"),
			expectedStatus: http.StatusGone,
		},
		{
			name:           "NotAvailable",
			err:            errors.New("TPM not available"),
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "PermissionDenied",
			err:            errors.New("permission denied"),
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "InternalError",
			err:            errors.New("internal error"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handlers.writeAttestationError(w, "test", tc.err)

			if w.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, w.Code)
			}
		})
	}
}

// =============================================================================
// Parser Function Tests
// =============================================================================

func TestParseVerifyOptions(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

	t.Run("EmptyRequest", func(t *testing.T) {
		req := &VerifyManifestRequest{}
		opts, err := handlers.parseVerifyOptions(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if opts == nil {
			t.Error("expected non-nil options")
		}
	})

	t.Run("ValidNonce", func(t *testing.T) {
		nonce := make([]byte, 32)
		for i := range nonce {
			nonce[i] = byte(i)
		}
		req := &VerifyManifestRequest{
			ExpectedNonce: base64.StdEncoding.EncodeToString(nonce),
		}
		opts, err := handlers.parseVerifyOptions(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(opts.ExpectedNonce) != 32 {
			t.Errorf("expected 32 byte nonce, got %d", len(opts.ExpectedNonce))
		}
	})

	t.Run("InvalidNonceBase64", func(t *testing.T) {
		req := &VerifyManifestRequest{
			ExpectedNonce: "not-valid-base64!!!",
		}
		_, err := handlers.parseVerifyOptions(req)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("ValidPublicKey", func(t *testing.T) {
		req := &VerifyManifestRequest{
			PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...\n-----END PUBLIC KEY-----",
		}
		opts, err := handlers.parseVerifyOptions(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(opts.PublicKeyPEM) == 0 {
			t.Error("expected non-empty public key")
		}
	})

	t.Run("ValidPCRs", func(t *testing.T) {
		pcrValue := make([]byte, 32)
		req := &VerifyManifestRequest{
			ExpectedPCRs: map[int]string{
				0: base64.StdEncoding.EncodeToString(pcrValue),
				7: base64.StdEncoding.EncodeToString(pcrValue),
			},
		}
		opts, err := handlers.parseVerifyOptions(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(opts.ExpectedPCRs) != 2 {
			t.Errorf("expected 2 PCRs, got %d", len(opts.ExpectedPCRs))
		}
	})

	t.Run("InvalidPCRIndex", func(t *testing.T) {
		pcrValue := make([]byte, 32)
		req := &VerifyManifestRequest{
			ExpectedPCRs: map[int]string{
				25: base64.StdEncoding.EncodeToString(pcrValue),
			},
		}
		_, err := handlers.parseVerifyOptions(req)
		if err == nil {
			t.Error("expected error for invalid PCR index")
		}
	})

	t.Run("InvalidPCRBase64", func(t *testing.T) {
		req := &VerifyManifestRequest{
			ExpectedPCRs: map[int]string{
				0: "not-valid-base64!!!",
			},
		}
		_, err := handlers.parseVerifyOptions(req)
		if err == nil {
			t.Error("expected error for invalid PCR base64")
		}
	})
}

func TestParseCollectAttestationOptions(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

	t.Run("EmptyRequest", func(t *testing.T) {
		req := &CollectHostAttestationRequest{}
		opts, err := handlers.parseCollectAttestationOptions(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if opts == nil {
			t.Error("expected non-nil options")
		}
	})

	t.Run("ValidNonce", func(t *testing.T) {
		nonce := make([]byte, 32)
		req := &CollectHostAttestationRequest{
			Nonce: base64.StdEncoding.EncodeToString(nonce),
		}
		opts, err := handlers.parseCollectAttestationOptions(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(opts.Nonce) != 32 {
			t.Errorf("expected 32 byte nonce, got %d", len(opts.Nonce))
		}
	})

	t.Run("InvalidNonceBase64", func(t *testing.T) {
		req := &CollectHostAttestationRequest{
			Nonce: "invalid-base64!!!",
		}
		_, err := handlers.parseCollectAttestationOptions(req)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("ValidHashAlgorithm", func(t *testing.T) {
		req := &CollectHostAttestationRequest{
			HashAlgorithm: "sha256",
		}
		opts, err := handlers.parseCollectAttestationOptions(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if opts == nil {
			t.Error("expected non-nil options")
		}
	})

	t.Run("InvalidHashAlgorithm", func(t *testing.T) {
		req := &CollectHostAttestationRequest{
			HashAlgorithm: "INVALID-HASH",
		}
		_, err := handlers.parseCollectAttestationOptions(req)
		if err == nil {
			t.Error("expected error for invalid hash algorithm")
		}
	})

	t.Run("ValidPCRIndices", func(t *testing.T) {
		req := &CollectHostAttestationRequest{
			PCRIndices: []int{0, 1, 7},
		}
		opts, err := handlers.parseCollectAttestationOptions(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(opts.PCRIndices) != 3 {
			t.Errorf("expected 3 PCR indices, got %d", len(opts.PCRIndices))
		}
	})

	t.Run("InvalidPCRIndices", func(t *testing.T) {
		req := &CollectHostAttestationRequest{
			PCRIndices: []int{0, 25},
		}
		_, err := handlers.parseCollectAttestationOptions(req)
		if err == nil {
			t.Error("expected error for invalid PCR indices")
		}
	})

	t.Run("IncludeEventLog", func(t *testing.T) {
		req := &CollectHostAttestationRequest{
			IncludeEventLog: true,
		}
		opts, err := handlers.parseCollectAttestationOptions(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !opts.IncludeEventLog {
			t.Error("expected IncludeEventLog to be true")
		}
	})
}

func TestParseWorkloadAttestationOptions(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

	t.Run("EmptyRequest", func(t *testing.T) {
		req := &AttestWorkloadRequest{}
		opts, err := handlers.parseWorkloadAttestationOptions(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if opts == nil {
			t.Error("expected non-nil options")
		}
	})

	t.Run("ValidNonce", func(t *testing.T) {
		nonce := make([]byte, 32)
		req := &AttestWorkloadRequest{
			Nonce: base64.StdEncoding.EncodeToString(nonce),
		}
		opts, err := handlers.parseWorkloadAttestationOptions(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(opts.Nonce) != 32 {
			t.Errorf("expected 32 byte nonce, got %d", len(opts.Nonce))
		}
	})

	t.Run("InvalidNonceBase64", func(t *testing.T) {
		req := &AttestWorkloadRequest{
			Nonce: "invalid-base64!!!",
		}
		_, err := handlers.parseWorkloadAttestationOptions(req)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("ValidHashAlgorithm", func(t *testing.T) {
		req := &AttestWorkloadRequest{
			HashAlgorithm: "sha384",
		}
		opts, err := handlers.parseWorkloadAttestationOptions(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if opts == nil {
			t.Error("expected non-nil options")
		}
	})

	t.Run("InvalidHashAlgorithm", func(t *testing.T) {
		req := &AttestWorkloadRequest{
			HashAlgorithm: "INVALID-HASH",
		}
		_, err := handlers.parseWorkloadAttestationOptions(req)
		if err == nil {
			t.Error("expected error for invalid hash algorithm")
		}
	})

	t.Run("InvalidPCRIndices", func(t *testing.T) {
		req := &AttestWorkloadRequest{
			PCRIndices: []int{-1, 0},
		}
		_, err := handlers.parseWorkloadAttestationOptions(req)
		if err == nil {
			t.Error("expected error for invalid PCR indices")
		}
	})
}

// =============================================================================
// Additional Tests for 90% Coverage
// =============================================================================

func TestParseReportFilter_AdditionalCases(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

	t.Run("AllParameters", func(t *testing.T) {
		now := time.Now().UTC()
		startStr := now.Add(-time.Hour).Format(time.RFC3339)
		endStr := now.Format(time.RFC3339)
		url := "/reports?host_id=host-001&status=verified&limit=25&offset=10&start_time=" + startStr + "&end_time=" + endStr
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		filter := handlers.parseReportFilter(req)

		if filter.HostID != "host-001" {
			t.Errorf("expected host_id 'host-001', got %q", filter.HostID)
		}
		if filter.Status != "verified" {
			t.Errorf("expected status 'verified', got %q", filter.Status)
		}
		if filter.Limit != 25 {
			t.Errorf("expected limit 25, got %d", filter.Limit)
		}
		if filter.Offset != 10 {
			t.Errorf("expected offset 10, got %d", filter.Offset)
		}
		if filter.StartTime.IsZero() {
			t.Error("expected non-zero start time")
		}
		if filter.EndTime.IsZero() {
			t.Error("expected non-zero end time")
		}
	})
}

func TestParsePolicyFilter(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

	t.Run("EmptyQuery", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/policies", nil)
		filter := handlers.parsePolicyFilter(req)
		if filter == nil {
			t.Fatal("expected non-nil filter")
		}
		if filter.Limit != 50 {
			t.Errorf("expected default limit 50, got %d", filter.Limit)
		}
	})

	t.Run("WithName", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/policies?name=secure-boot", nil)
		filter := handlers.parsePolicyFilter(req)
		if filter.Name != "secure-boot" {
			t.Errorf("expected name 'secure-boot', got %q", filter.Name)
		}
	})

	t.Run("WithActive", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/policies?active=true", nil)
		filter := handlers.parsePolicyFilter(req)
		if !filter.Active {
			t.Error("expected Active to be true")
		}
	})

	t.Run("AllParameters", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/policies?name=test&active=true&limit=25&offset=5", nil)
		filter := handlers.parsePolicyFilter(req)
		if filter.Name != "test" {
			t.Errorf("expected name 'test', got %q", filter.Name)
		}
		if !filter.Active {
			t.Error("expected Active to be true")
		}
		if filter.Limit != 25 {
			t.Errorf("expected limit 25, got %d", filter.Limit)
		}
		if filter.Offset != 5 {
			t.Errorf("expected offset 5, got %d", filter.Offset)
		}
	})
}

func TestParseHashAlgorithm_AllCases(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

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
		{"", manifest.HashAlgorithmSHA256},
		{"invalid", manifest.HashAlgorithmSHA256},
		{"md5", manifest.HashAlgorithmSHA256},
	}

	for _, tt := range tests {
		t.Run("Algorithm_"+tt.input, func(t *testing.T) {
			result := handlers.parseHashAlgorithm(tt.input)
			if result != tt.expected {
				t.Errorf("parseHashAlgorithm(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestServiceErrors(t *testing.T) {
	t.Run("ListReportsError", func(t *testing.T) {
		service := &mockAttestationService{
			listReportsFunc: func(ctx context.Context, filter *ReportFilter) ([]*AttestationReportResponse, int, error) {
				return nil, 0, errors.New("database error")
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/reports", nil)
		w := httptest.NewRecorder()
		handlers.handleListReports(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
	})

	t.Run("ListPoliciesError", func(t *testing.T) {
		service := &mockAttestationService{
			listPoliciesFunc: func(ctx context.Context, filter *AttestationPolicyFilter) ([]*AttestationPolicyResponse, int, error) {
				return nil, 0, errors.New("database error")
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/policies", nil)
		w := httptest.NewRecorder()
		handlers.handleListPolicies(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
	})

	t.Run("CreatePolicyError", func(t *testing.T) {
		service := &mockAttestationService{
			createPolicyFunc: func(ctx context.Context, policy *AttestationPolicyRequest) (*AttestationPolicyResponse, error) {
				return nil, errors.New("creation failed")
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		reqBody := AttestationPolicyRequest{Name: "test-policy"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/policies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handlers.handleCreatePolicy(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
	})

	t.Run("GetReportError", func(t *testing.T) {
		service := &mockAttestationService{
			getReportFunc: func(ctx context.Context, id string) (*AttestationReportResponse, error) {
				return nil, errors.New("database error")
			},
		}
		handlers := NewAttestationHandlers(service, testLogger())

		router := mux.NewRouter()
		router.HandleFunc("/api/v1/attestation/reports/{id}", handlers.handleGetReport).Methods(http.MethodGet)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/reports/report-001", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
	})
}

// =============================================================================
// Error Type Branch Coverage
// =============================================================================

func TestErrorTypesBranches(t *testing.T) {
	t.Run("ErrInvalidReportID_EmptyID", func(t *testing.T) {
		err := ErrInvalidReportID{}
		msg := err.Error()
		if !strings.Contains(msg, "report ID") {
			t.Errorf("expected error to mention report ID, got %q", msg)
		}
	})

	t.Run("ErrManifestNotFound_EmptyID", func(t *testing.T) {
		err := ErrManifestNotFound{}
		msg := err.Error()
		if !strings.Contains(msg, "manifest") {
			t.Errorf("expected error to mention manifest, got %q", msg)
		}
	})

	t.Run("ErrReportNotFound_EmptyID", func(t *testing.T) {
		err := ErrReportNotFound{}
		msg := err.Error()
		if !strings.Contains(msg, "report") {
			t.Errorf("expected error to mention report, got %q", msg)
		}
	})

	t.Run("ErrAttestationPolicyNotFound_EmptyID", func(t *testing.T) {
		err := ErrAttestationPolicyNotFound{}
		msg := err.Error()
		if !strings.Contains(msg, "policy") {
			t.Errorf("expected error to mention policy, got %q", msg)
		}
	})

	t.Run("ErrInvalidDeviceID_EmptyID", func(t *testing.T) {
		err := ErrInvalidDeviceID{}
		msg := err.Error()
		if !strings.Contains(msg, "device") {
			t.Errorf("expected error to mention device, got %q", msg)
		}
	})
}

func TestServiceUnavailableHandlers(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

	t.Run("VerifyManifest", func(t *testing.T) {
		nonce := make([]byte, 32)
		merkleRoot := make([]byte, 32)
		reqBody := VerifyManifestRequest{
			Manifest: &ManifestRequest{
				ID:         "test-001",
				HostID:     "host-001",
				Nonce:      base64.StdEncoding.EncodeToString(nonce),
				MerkleRoot: base64.StdEncoding.EncodeToString(merkleRoot),
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifest/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handlers.handleVerifyManifest(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
		}
	})

	t.Run("CollectHostAttestation", func(t *testing.T) {
		reqBody := CollectHostAttestationRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/host", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handlers.handleCollectHostAttestation(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
		}
	})

	t.Run("AttestContainer", func(t *testing.T) {
		router := mux.NewRouter()
		router.HandleFunc("/api/v1/attestation/container/{id}", handlers.handleAttestContainer).Methods(http.MethodPost)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/container/container-001", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
		}
	})

	t.Run("AttestDevice", func(t *testing.T) {
		router := mux.NewRouter()
		router.HandleFunc("/api/v1/attestation/device/{id}", handlers.handleAttestDevice).Methods(http.MethodPost)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/device/device-001", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
		}
	})
}

func TestInvalidBodyParsing(t *testing.T) {
	service := &mockAttestationService{}
	handlers := NewAttestationHandlers(service, testLogger())

	t.Run("VerifyManifestInvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifest/verify", strings.NewReader("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handlers.handleVerifyManifest(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("CollectHostInvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/host", strings.NewReader("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handlers.handleCollectHostAttestation(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

func TestContainerServiceError(t *testing.T) {
	service := &mockAttestationService{
		attestContainerFunc: func(ctx context.Context, id string, opts *CollectAttestationOptions) (*manifest.ContainerAttestation, error) {
			return nil, errors.New("container not found")
		},
	}
	handlers := NewAttestationHandlers(service, testLogger())

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/attestation/container/{id}", handlers.handleAttestContainer).Methods(http.MethodPost)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/container/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDeviceServiceError(t *testing.T) {
	service := &mockAttestationService{
		attestDeviceFunc: func(ctx context.Context, id string, opts *CollectAttestationOptions) (*DeviceAttestationResult, error) {
			return nil, errors.New("device not found")
		},
	}
	handlers := NewAttestationHandlers(service, testLogger())

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/attestation/device/{id}", handlers.handleAttestDevice).Methods(http.MethodPost)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/device/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestBuildManifestServiceUnavailable(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

	reqBody := BuildManifestRequest{HostID: "host-001"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handlers.handleBuildManifest(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

func TestRequestToHostAttestation(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

	t.Run("NilRequest", func(t *testing.T) {
		attestation, err := handlers.requestToHostAttestation(nil)
		if err != nil {
			t.Errorf("expected no error for nil request, got %v", err)
		}
		if attestation != nil {
			t.Error("expected nil attestation for nil request")
		}
	})

	t.Run("ValidRequest", func(t *testing.T) {
		quoteData := make([]byte, 64)
		signature := make([]byte, 256)
		pcrDigest := make([]byte, 32)
		nonce := make([]byte, 32)

		req := &HostAttestationRequest{
			QuoteData:     base64.StdEncoding.EncodeToString(quoteData),
			Signature:     base64.StdEncoding.EncodeToString(signature),
			PCRDigest:     base64.StdEncoding.EncodeToString(pcrDigest),
			Nonce:         base64.StdEncoding.EncodeToString(nonce),
			HashAlgorithm: "sha256",
		}

		attestation, err := handlers.requestToHostAttestation(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if attestation == nil {
			t.Fatal("expected non-nil attestation")
		}
	})

	t.Run("InvalidQuoteData", func(t *testing.T) {
		req := &HostAttestationRequest{
			QuoteData: "invalid-base64!!!",
		}

		_, err := handlers.requestToHostAttestation(req)
		if err == nil {
			t.Error("expected error for invalid quote data")
		}
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		quoteData := make([]byte, 64)
		req := &HostAttestationRequest{
			QuoteData: base64.StdEncoding.EncodeToString(quoteData),
			Signature: "invalid-base64!!!",
		}

		_, err := handlers.requestToHostAttestation(req)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("InvalidPCRDigest", func(t *testing.T) {
		quoteData := make([]byte, 64)
		signature := make([]byte, 256)
		req := &HostAttestationRequest{
			QuoteData: base64.StdEncoding.EncodeToString(quoteData),
			Signature: base64.StdEncoding.EncodeToString(signature),
			PCRDigest: "invalid-base64!!!",
		}

		_, err := handlers.requestToHostAttestation(req)
		if err == nil {
			t.Error("expected error for invalid PCR digest")
		}
	})

	t.Run("InvalidNonce", func(t *testing.T) {
		quoteData := make([]byte, 64)
		signature := make([]byte, 256)
		pcrDigest := make([]byte, 32)
		req := &HostAttestationRequest{
			QuoteData: base64.StdEncoding.EncodeToString(quoteData),
			Signature: base64.StdEncoding.EncodeToString(signature),
			PCRDigest: base64.StdEncoding.EncodeToString(pcrDigest),
			Nonce:     "invalid-base64!!!",
		}

		_, err := handlers.requestToHostAttestation(req)
		if err == nil {
			t.Error("expected error for invalid nonce")
		}
	})
}

func TestRequestToVMAttestation(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

	t.Run("NilRequest", func(t *testing.T) {
		attestation, err := handlers.requestToVMAttestation(nil)
		if err != nil {
			t.Errorf("expected no error for nil request, got %v", err)
		}
		if attestation != nil {
			t.Error("expected nil attestation for nil request")
		}
	})

	t.Run("ValidRequest", func(t *testing.T) {
		quoteData := make([]byte, 64)
		signature := make([]byte, 256)
		pcrDigest := make([]byte, 32)
		nonce := make([]byte, 32)

		req := &VMAttestationRequest{
			VMID:          "vm-001",
			QuoteData:     base64.StdEncoding.EncodeToString(quoteData),
			Signature:     base64.StdEncoding.EncodeToString(signature),
			PCRDigest:     base64.StdEncoding.EncodeToString(pcrDigest),
			Nonce:         base64.StdEncoding.EncodeToString(nonce),
			HashAlgorithm: "sha256",
		}

		attestation, err := handlers.requestToVMAttestation(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if attestation == nil {
			t.Fatal("expected non-nil attestation")
		}
		if attestation.VMID != "vm-001" {
			t.Errorf("expected VM ID 'vm-001', got %q", attestation.VMID)
		}
	})

	t.Run("InvalidQuoteData", func(t *testing.T) {
		req := &VMAttestationRequest{
			VMID:      "vm-001",
			QuoteData: "invalid-base64!!!",
		}

		_, err := handlers.requestToVMAttestation(req)
		if err == nil {
			t.Error("expected error for invalid quote data")
		}
	})
}

func TestRequestToContainerAttestation(t *testing.T) {
	handlers := NewAttestationHandlers(nil, testLogger())

	t.Run("NilRequest", func(t *testing.T) {
		attestation, err := handlers.requestToContainerAttestation(nil)
		if err != nil {
			t.Errorf("expected no error for nil request, got %v", err)
		}
		if attestation != nil {
			t.Error("expected nil attestation for nil request")
		}
	})

	t.Run("ValidRequest", func(t *testing.T) {
		digest := make([]byte, 32)
		pcrValue := make([]byte, 32)

		req := &ContainerAttestationReq{
			ContainerID: "container-001",
			ImageID:     "sha256:abc123",
			ImageDigest: "sha256:abc123",
			Digest:      base64.StdEncoding.EncodeToString(digest),
			PCRValue:    base64.StdEncoding.EncodeToString(pcrValue),
		}

		attestation, err := handlers.requestToContainerAttestation(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if attestation == nil {
			t.Fatal("expected non-nil attestation")
		}
		if attestation.ContainerID != "container-001" {
			t.Errorf("expected container ID 'container-001', got %q", attestation.ContainerID)
		}
	})

	t.Run("InvalidDigest", func(t *testing.T) {
		req := &ContainerAttestationReq{
			ContainerID: "container-001",
			Digest:      "invalid-base64!!!",
		}

		_, err := handlers.requestToContainerAttestation(req)
		if err == nil {
			t.Error("expected error for invalid digest")
		}
	})
}

// =============================================================================
// ParseIntParamWithDefault Tests
// =============================================================================

func TestParseIntParamWithDefault(t *testing.T) {
	t.Parallel()

	t.Run("empty_returns_default", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		result := ParseIntParamWithDefault(req, "limit", 50)
		if result != 50 {
			t.Errorf("expected 50, got %d", result)
		}
	})

	t.Run("valid_int_returns_parsed", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/test?limit=100", nil)
		result := ParseIntParamWithDefault(req, "limit", 50)
		if result != 100 {
			t.Errorf("expected 100, got %d", result)
		}
	})

	t.Run("invalid_int_returns_default", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/test?limit=invalid", nil)
		result := ParseIntParamWithDefault(req, "limit", 50)
		if result != 50 {
			t.Errorf("expected 50, got %d", result)
		}
	})

	t.Run("negative_int_returns_parsed", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/test?offset=-10", nil)
		result := ParseIntParamWithDefault(req, "offset", 0)
		if result != -10 {
			t.Errorf("expected -10, got %d", result)
		}
	})

	t.Run("zero_returns_parsed", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/test?page=0", nil)
		result := ParseIntParamWithDefault(req, "page", 1)
		if result != 0 {
			t.Errorf("expected 0, got %d", result)
		}
	})

	t.Run("float_returns_default", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/test?limit=10.5", nil)
		result := ParseIntParamWithDefault(req, "limit", 50)
		if result != 50 {
			t.Errorf("expected 50, got %d", result)
		}
	})

	t.Run("large_int_returns_parsed", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/test?count=2147483647", nil)
		result := ParseIntParamWithDefault(req, "count", 0)
		if result != 2147483647 {
			t.Errorf("expected 2147483647, got %d", result)
		}
	})

	t.Run("missing_param_returns_default", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/test?other=value", nil)
		result := ParseIntParamWithDefault(req, "limit", 25)
		if result != 25 {
			t.Errorf("expected 25, got %d", result)
		}
	})
}
