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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Mock KMS Service
// =============================================================================

type mockKMSService struct {
	generateKeyResp       *KMSGenerateKeyServiceResponse
	generateKeyErr        error
	importKeyResp         *KMSImportKeyServiceResponse
	importKeyErr          error
	getKeyResp            *KMSGetKeyServiceResponse
	getKeyErr             error
	listKeysResp          *KMSListKeysServiceResponse
	listKeysErr           error
	deleteKeyResp         *KMSDeleteKeyServiceResponse
	deleteKeyErr          error
	rotateKeyResp         *KMSRotateKeyServiceResponse
	rotateKeyErr          error
	updateKeyStatusResp   *KMSUpdateKeyStatusServiceResponse
	updateKeyStatusErr    error
	exportKeyResp         *KMSExportKeyServiceResponse
	exportKeyErr          error
	getKeyVersionsResp    *KMSGetKeyVersionsServiceResponse
	getKeyVersionsErr     error
	backendStatusResp     *KMSBackendStatusServiceResponse
	backendStatusErr      error
	encryptResp           *KMSEncryptServiceResponse
	encryptErr            error
	decryptResp           *KMSDecryptServiceResponse
	decryptErr            error
	signResp              *KMSSignServiceResponse
	signErr               error
	verifyResp            *KMSVerifyServiceResponse
	verifyErr             error
	generateRandomResp    *KMSGenerateRandomServiceResponse
	generateRandomErr     error
	hashResp              *KMSHashServiceResponse
	hashErr               error
	hmacResp              *KMSHMACServiceResponse
	hmacErr               error
	verifyHMACResp        *KMSVerifyHMACServiceResponse
	verifyHMACErr         error
	batchEncryptResp      *KMSBatchEncryptServiceResponse
	batchEncryptErr       error
	batchDecryptResp      *KMSBatchDecryptServiceResponse
	batchDecryptErr       error
	rewrapResp            *KMSRewrapServiceResponse
	rewrapErr             error
	lastGenerateKeyReq    *KMSGenerateKeyServiceRequest
	lastImportKeyReq      *KMSImportKeyServiceRequest
	lastGetKeyReq         *KMSGetKeyServiceRequest
	lastListKeysReq       *KMSListKeysServiceRequest
	lastDeleteKeyReq      *KMSDeleteKeyServiceRequest
	lastRotateKeyReq      *KMSRotateKeyServiceRequest
	lastExportKeyReq      *KMSExportKeyServiceRequest
	lastGetKeyVersionsReq *KMSGetKeyVersionsServiceRequest
	lastEncryptReq        *KMSEncryptServiceRequest
	lastDecryptReq        *KMSDecryptServiceRequest
	lastSignReq           *KMSSignServiceRequest
	lastVerifyReq         *KMSVerifyServiceRequest
	lastHashReq           *KMSHashServiceRequest
	lastHMACReq           *KMSHMACServiceRequest
	lastBatchEncryptReq   *KMSBatchEncryptServiceRequest
	lastBatchDecryptReq   *KMSBatchDecryptServiceRequest
	lastRewrapReq         *KMSRewrapServiceRequest
}

func newMockKMSService() *mockKMSService {
	return &mockKMSService{}
}

func (m *mockKMSService) GenerateKey(ctx context.Context, req *KMSGenerateKeyServiceRequest) (*KMSGenerateKeyServiceResponse, error) {
	m.lastGenerateKeyReq = req
	if m.generateKeyErr != nil {
		return nil, m.generateKeyErr
	}
	if m.generateKeyResp != nil {
		return m.generateKeyResp, nil
	}
	return &KMSGenerateKeyServiceResponse{
		Key: &KMSKeyHandle{
			KeyID:     "test-key-123",
			Version:   1,
			Algorithm: 3,
			Status:    1,
			CreatedAt: time.Now().Unix(),
		},
		Metadata: &KMSKeyMetadata{
			KeyID:       "test-key-123",
			Name:        req.Name,
			Description: req.Description,
			Algorithm:   3,
			Status:      1,
			Version:     1,
			CreatedAt:   time.Now().Unix(),
		},
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) ImportKey(ctx context.Context, req *KMSImportKeyServiceRequest) (*KMSImportKeyServiceResponse, error) {
	m.lastImportKeyReq = req
	if m.importKeyErr != nil {
		return nil, m.importKeyErr
	}
	if m.importKeyResp != nil {
		return m.importKeyResp, nil
	}
	return &KMSImportKeyServiceResponse{
		Key: &KMSKeyHandle{
			KeyID:     "imported-key-123",
			Version:   1,
			Algorithm: 3,
			Status:    1,
			CreatedAt: time.Now().Unix(),
		},
		Metadata: &KMSKeyMetadata{
			KeyID:       "imported-key-123",
			Name:        req.Name,
			Description: req.Description,
			Algorithm:   3,
			Status:      1,
			Version:     1,
			CreatedAt:   time.Now().Unix(),
		},
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) GetKey(ctx context.Context, req *KMSGetKeyServiceRequest) (*KMSGetKeyServiceResponse, error) {
	m.lastGetKeyReq = req
	if m.getKeyErr != nil {
		return nil, m.getKeyErr
	}
	if m.getKeyResp != nil {
		return m.getKeyResp, nil
	}
	return &KMSGetKeyServiceResponse{
		Key: &KMSKeyHandle{
			KeyID:     req.KeyID,
			Version:   1,
			Algorithm: 3,
			Status:    1,
			CreatedAt: time.Now().Unix(),
		},
		Metadata: &KMSKeyMetadata{
			KeyID:     req.KeyID,
			Name:      "test-key",
			Algorithm: 3,
			Status:    1,
			Version:   1,
			CreatedAt: time.Now().Unix(),
		},
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) ListKeys(ctx context.Context, req *KMSListKeysServiceRequest) (*KMSListKeysServiceResponse, error) {
	m.lastListKeysReq = req
	if m.listKeysErr != nil {
		return nil, m.listKeysErr
	}
	if m.listKeysResp != nil {
		return m.listKeysResp, nil
	}
	return &KMSListKeysServiceResponse{
		Keys: []*KMSKeyHandle{
			{
				KeyID:     "key-1",
				Version:   1,
				Algorithm: 3,
				Status:    1,
				CreatedAt: time.Now().Unix(),
			},
			{
				KeyID:     "key-2",
				Version:   1,
				Algorithm: 3,
				Status:    1,
				CreatedAt: time.Now().Unix(),
			},
		},
		TotalCount: 2,
		HasMore:    false,
		Timestamp:  time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) DeleteKey(ctx context.Context, req *KMSDeleteKeyServiceRequest) (*KMSDeleteKeyServiceResponse, error) {
	m.lastDeleteKeyReq = req
	if m.deleteKeyErr != nil {
		return nil, m.deleteKeyErr
	}
	if m.deleteKeyResp != nil {
		return m.deleteKeyResp, nil
	}
	return &KMSDeleteKeyServiceResponse{
		KeyID:     req.KeyID,
		Status:    3,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) RotateKey(ctx context.Context, req *KMSRotateKeyServiceRequest) (*KMSRotateKeyServiceResponse, error) {
	m.lastRotateKeyReq = req
	if m.rotateKeyErr != nil {
		return nil, m.rotateKeyErr
	}
	if m.rotateKeyResp != nil {
		return m.rotateKeyResp, nil
	}
	return &KMSRotateKeyServiceResponse{
		KeyID:      req.KeyID,
		OldVersion: 1,
		NewVersion: 2,
		Timestamp:  time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) UpdateKeyStatus(ctx context.Context, req *KMSUpdateKeyStatusServiceRequest) (*KMSUpdateKeyStatusServiceResponse, error) {
	if m.updateKeyStatusErr != nil {
		return nil, m.updateKeyStatusErr
	}
	if m.updateKeyStatusResp != nil {
		return m.updateKeyStatusResp, nil
	}
	return &KMSUpdateKeyStatusServiceResponse{
		KeyID:     req.KeyID,
		Version:   req.Version,
		Status:    req.Status,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) ExportKey(ctx context.Context, req *KMSExportKeyServiceRequest) (*KMSExportKeyServiceResponse, error) {
	m.lastExportKeyReq = req
	if m.exportKeyErr != nil {
		return nil, m.exportKeyErr
	}
	if m.exportKeyResp != nil {
		return m.exportKeyResp, nil
	}
	return &KMSExportKeyServiceResponse{
		KeyID:           req.KeyID,
		Format:          1,
		WrappedMaterial: []byte("wrapped-key-material"),
		Version:         1,
		Timestamp:       time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) GetKeyVersions(ctx context.Context, req *KMSGetKeyVersionsServiceRequest) (*KMSGetKeyVersionsServiceResponse, error) {
	m.lastGetKeyVersionsReq = req
	if m.getKeyVersionsErr != nil {
		return nil, m.getKeyVersionsErr
	}
	if m.getKeyVersionsResp != nil {
		return m.getKeyVersionsResp, nil
	}
	return &KMSGetKeyVersionsServiceResponse{
		KeyID: req.KeyID,
		Versions: []*KMSKeyVersionInfo{
			{Version: 1, Status: 1, Algorithm: 3, CreatedAt: time.Now().Unix()},
			{Version: 2, Status: 1, Algorithm: 3, CreatedAt: time.Now().Unix()},
		},
		HasMore:   false,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) BackendStatus(ctx context.Context) (*KMSBackendStatusServiceResponse, error) {
	if m.backendStatusErr != nil {
		return nil, m.backendStatusErr
	}
	if m.backendStatusResp != nil {
		return m.backendStatusResp, nil
	}
	return &KMSBackendStatusServiceResponse{
		BackendType:  "software",
		Status:       "healthy",
		Capabilities: map[string]bool{"encrypt": true, "decrypt": true, "sign": true, "verify": true},
		Timestamp:    time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) Encrypt(ctx context.Context, req *KMSEncryptServiceRequest) (*KMSEncryptServiceResponse, error) {
	m.lastEncryptReq = req
	if m.encryptErr != nil {
		return nil, m.encryptErr
	}
	if m.encryptResp != nil {
		return m.encryptResp, nil
	}
	return &KMSEncryptServiceResponse{
		KeyID:      req.KeyID,
		KeyVersion: 1,
		Ciphertext: []byte("encrypted-data"),
		Nonce:      []byte("nonce123"),
		Timestamp:  time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) Decrypt(ctx context.Context, req *KMSDecryptServiceRequest) (*KMSDecryptServiceResponse, error) {
	m.lastDecryptReq = req
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}
	if m.decryptResp != nil {
		return m.decryptResp, nil
	}
	return &KMSDecryptServiceResponse{
		KeyID:      req.KeyID,
		KeyVersion: 1,
		Plaintext:  []byte("decrypted-data"),
		Timestamp:  time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) Sign(ctx context.Context, req *KMSSignServiceRequest) (*KMSSignServiceResponse, error) {
	m.lastSignReq = req
	if m.signErr != nil {
		return nil, m.signErr
	}
	if m.signResp != nil {
		return m.signResp, nil
	}
	return &KMSSignServiceResponse{
		KeyID:         req.KeyID,
		KeyVersion:    1,
		Signature:     []byte("signature"),
		HashAlgorithm: 1,
		Timestamp:     time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) Verify(ctx context.Context, req *KMSVerifyServiceRequest) (*KMSVerifyServiceResponse, error) {
	m.lastVerifyReq = req
	if m.verifyErr != nil {
		return nil, m.verifyErr
	}
	if m.verifyResp != nil {
		return m.verifyResp, nil
	}
	return &KMSVerifyServiceResponse{
		KeyID:      req.KeyID,
		KeyVersion: 1,
		Valid:      true,
		Timestamp:  time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) GenerateRandom(ctx context.Context, req *KMSGenerateRandomServiceRequest) (*KMSGenerateRandomServiceResponse, error) {
	if m.generateRandomErr != nil {
		return nil, m.generateRandomErr
	}
	if m.generateRandomResp != nil {
		return m.generateRandomResp, nil
	}
	randomBytes := make([]byte, req.NumBytes)
	for i := range randomBytes {
		randomBytes[i] = byte(i % 256)
	}
	return &KMSGenerateRandomServiceResponse{
		RandomBytes: randomBytes,
		Timestamp:   time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) Hash(ctx context.Context, req *KMSHashServiceRequest) (*KMSHashServiceResponse, error) {
	m.lastHashReq = req
	if m.hashErr != nil {
		return nil, m.hashErr
	}
	if m.hashResp != nil {
		return m.hashResp, nil
	}
	return &KMSHashServiceResponse{
		Algorithm: req.Algorithm,
		Hash:      []byte("hash-result"),
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) HMAC(ctx context.Context, req *KMSHMACServiceRequest) (*KMSHMACServiceResponse, error) {
	m.lastHMACReq = req
	if m.hmacErr != nil {
		return nil, m.hmacErr
	}
	if m.hmacResp != nil {
		return m.hmacResp, nil
	}
	return &KMSHMACServiceResponse{
		KeyID:         req.KeyID,
		KeyVersion:    1,
		HMAC:          []byte("hmac-result"),
		HashAlgorithm: 1,
		Timestamp:     time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) VerifyHMAC(ctx context.Context, req *KMSVerifyHMACServiceRequest) (*KMSVerifyHMACServiceResponse, error) {
	if m.verifyHMACErr != nil {
		return nil, m.verifyHMACErr
	}
	if m.verifyHMACResp != nil {
		return m.verifyHMACResp, nil
	}
	return &KMSVerifyHMACServiceResponse{
		KeyID:      req.KeyID,
		KeyVersion: 1,
		Valid:      true,
		Timestamp:  time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) BatchEncrypt(ctx context.Context, req *KMSBatchEncryptServiceRequest) (*KMSBatchEncryptServiceResponse, error) {
	m.lastBatchEncryptReq = req
	if m.batchEncryptErr != nil {
		return nil, m.batchEncryptErr
	}
	if m.batchEncryptResp != nil {
		return m.batchEncryptResp, nil
	}
	results := make([]*KMSBatchEncryptResultItem, len(req.Items))
	for i := range req.Items {
		results[i] = &KMSBatchEncryptResultItem{
			Ciphertext: []byte("encrypted-data"),
			Nonce:      []byte("nonce123"),
		}
	}
	return &KMSBatchEncryptServiceResponse{
		KeyID:        req.KeyID,
		KeyVersion:   1,
		Results:      results,
		SuccessCount: int32(len(req.Items)),
		FailureCount: 0,
		Timestamp:    time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) BatchDecrypt(ctx context.Context, req *KMSBatchDecryptServiceRequest) (*KMSBatchDecryptServiceResponse, error) {
	m.lastBatchDecryptReq = req
	if m.batchDecryptErr != nil {
		return nil, m.batchDecryptErr
	}
	if m.batchDecryptResp != nil {
		return m.batchDecryptResp, nil
	}
	results := make([]*KMSBatchDecryptResultItem, len(req.Items))
	for i := range req.Items {
		results[i] = &KMSBatchDecryptResultItem{
			Plaintext:  []byte("decrypted-data"),
			KeyVersion: 1,
		}
	}
	return &KMSBatchDecryptServiceResponse{
		KeyID:        req.KeyID,
		Results:      results,
		SuccessCount: int32(len(req.Items)),
		FailureCount: 0,
		Timestamp:    time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) Rewrap(ctx context.Context, req *KMSRewrapServiceRequest) (*KMSRewrapServiceResponse, error) {
	m.lastRewrapReq = req
	if m.rewrapErr != nil {
		return nil, m.rewrapErr
	}
	if m.rewrapResp != nil {
		return m.rewrapResp, nil
	}
	return &KMSRewrapServiceResponse{
		SourceKeyID:      req.SourceKeyID,
		DestinationKeyID: req.DestinationKeyID,
		SourceKeyVersion: req.SourceKeyVersion,
		DestKeyVersion:   1,
		Ciphertext:       []byte("rewrapped-data"),
		Nonce:            []byte("nonce123"),
		Timestamp:        time.Now().Unix(),
	}, nil
}

// Ensure mock implements interface
var _ KMSService = (*mockKMSService)(nil)

// =============================================================================
// Test Helpers
// =============================================================================

func setupKMSTestHandler(svc *mockKMSService) (*KMSHandlers, *mux.Router) {
	logger := slog.Default()
	handlers := NewKMSHandlers(svc, logger)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return handlers, router
}

func decodeKMSResponse(t *testing.T, body io.Reader, v interface{}) {
	t.Helper()
	err := json.NewDecoder(body).Decode(v)
	require.NoError(t, err)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestKMSHandlerErrors(t *testing.T) {
	t.Run("ErrKMSServiceNotAvailable", func(t *testing.T) {
		err := ErrKMSServiceNotAvailable{}
		assert.Equal(t, "KMS service not available", err.Error())
	})

	t.Run("ErrInvalidKeyID with empty ID", func(t *testing.T) {
		err := ErrInvalidKeyID{}
		assert.Equal(t, "key ID is required", err.Error())
	})

	t.Run("ErrInvalidKeyID with ID", func(t *testing.T) {
		err := ErrInvalidKeyID{ID: "bad-id"}
		assert.Equal(t, "invalid key ID: bad-id", err.Error())
	})

	t.Run("ErrKMSRequestBodyInvalid", func(t *testing.T) {
		err := ErrKMSRequestBodyInvalid{Reason: "invalid JSON"}
		assert.Equal(t, "invalid KMS request body: invalid JSON", err.Error())
	})

	t.Run("ErrKMSMissingRequiredField", func(t *testing.T) {
		err := ErrKMSMissingRequiredField{Field: "key_id"}
		assert.Equal(t, "missing required field: key_id", err.Error())
	})

	t.Run("ErrKMSHandlerOperationFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrKMSHandlerOperationFailed{Operation: "encrypt", Cause: cause}
		assert.Equal(t, "KMS operation encrypt failed: underlying error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrInvalidBase64", func(t *testing.T) {
		cause := errors.New("decode error")
		err := ErrInvalidBase64{Field: "plaintext", Cause: cause}
		assert.Equal(t, "invalid base64 encoding for field plaintext: decode error", err.Error())
	})

	t.Run("ErrInvalidNumBytes", func(t *testing.T) {
		err := ErrInvalidNumBytes{NumBytes: 0, Reason: "must be greater than 0"}
		assert.Equal(t, "invalid num_bytes 0: must be greater than 0", err.Error())
	})
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewKMSHandlers(t *testing.T) {
	t.Run("creates handlers with service and logger", func(t *testing.T) {
		svc := newMockKMSService()
		logger := slog.Default()
		handlers := NewKMSHandlers(svc, logger)
		require.NotNil(t, handlers)
		assert.Equal(t, svc, handlers.service)
		assert.Equal(t, logger, handlers.logger)
	})

	t.Run("creates handlers with nil logger uses default", func(t *testing.T) {
		svc := newMockKMSService()
		handlers := NewKMSHandlers(svc, nil)
		require.NotNil(t, handlers)
		assert.NotNil(t, handlers.logger)
	})
}

func TestRegisterKMSRoutes(t *testing.T) {
	t.Run("registers all KMS routes", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		routes := []struct {
			method string
			path   string
		}{
			{http.MethodPost, "/api/v1/kms/keys"},
			{http.MethodGet, "/api/v1/kms/keys"},
			{http.MethodPost, "/api/v1/kms/keys/import"},
			{http.MethodGet, "/api/v1/kms/keys/test-id"},
			{http.MethodDelete, "/api/v1/kms/keys/test-id"},
			{http.MethodPost, "/api/v1/kms/keys/test-id/rotate"},
			{http.MethodGet, "/api/v1/kms/keys/test-id/export"},
			{http.MethodGet, "/api/v1/kms/keys/test-id/versions"},
			{http.MethodPost, "/api/v1/kms/encrypt"},
			{http.MethodPost, "/api/v1/kms/decrypt"},
			{http.MethodPost, "/api/v1/kms/sign"},
			{http.MethodPost, "/api/v1/kms/verify"},
			{http.MethodPost, "/api/v1/kms/hash"},
			{http.MethodPost, "/api/v1/kms/hmac"},
			{http.MethodPost, "/api/v1/kms/random"},
			{http.MethodGet, "/api/v1/kms/status"},
		}

		for _, route := range routes {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			matched := router.Match(req, match)
			assert.True(t, matched, "Route %s %s should be registered", route.method, route.path)
		}
	})
}

// =============================================================================
// Generate Key Tests
// =============================================================================

func TestHandleGenerateKey(t *testing.T) {
	t.Run("generates key successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSGenerateKeyRequest{
			Name: "test-key",
			KeySpec: KMSKeySpecRequest{
				Algorithm: "AES-256-GCM",
				Usage:     []string{"ENCRYPT", "DECRYPT"},
			},
			Description: "Test key",
			Tags:        map[string]string{"env": "test"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var genResp KMSGenerateKeyResponse
		decodeKMSResponse(t, resp.Body, &genResp)
		assert.Equal(t, "test-key-123", genResp.Key.KeyID)
		assert.Equal(t, "test-key", genResp.Metadata.Name)
		require.NotNil(t, svc.lastGenerateKeyReq.KeySpec)
		assert.Equal(t, int32(3), svc.lastGenerateKeyReq.KeySpec.Algorithm, "AES-256-GCM")
		assert.Equal(t, []int32{1, 2}, svc.lastGenerateKeyReq.KeySpec.Usage, "ENCRYPT, DECRYPT")
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := KMSGenerateKeyRequest{
			Name:    "test-key",
			KeySpec: KMSKeySpecRequest{Algorithm: "AES-256-GCM"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys", bytes.NewReader([]byte("invalid json")))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when name is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSGenerateKeyRequest{
			KeySpec: KMSKeySpecRequest{Algorithm: "AES-256-GCM"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when algorithm is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSGenerateKeyRequest{
			Name:    "test-key",
			KeySpec: KMSKeySpecRequest{},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.generateKeyErr = ErrKMSOperationFailed{Reason: "backend error"}
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSGenerateKeyRequest{
			Name:    "test-key",
			KeySpec: KMSKeySpecRequest{Algorithm: "AES-256-GCM"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// List Keys Tests
// =============================================================================

func TestHandleListKeys(t *testing.T) {
	t.Run("lists keys successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp KMSListKeysResponse
		decodeKMSResponse(t, resp.Body, &listResp)
		assert.Equal(t, 2, len(listResp.Keys))
		assert.Equal(t, int32(2), listResp.TotalCount)
	})

	t.Run("lists keys with pagination", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys?limit=10&cursor=abc123", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, int32(10), svc.lastListKeysReq.Limit)
		assert.Equal(t, "abc123", svc.lastListKeysReq.Cursor)
	})

	t.Run("lists keys with filter", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys?status=enabled&owner=user1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "enabled", svc.lastListKeysReq.Filter["status"])
		assert.Equal(t, "user1", svc.lastListKeysReq.Filter["owner"])
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.listKeysErr = ErrKMSServiceUnavailable{Reason: "backend error"}
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Get Key Tests
// =============================================================================

func TestHandleGetKey(t *testing.T) {
	t.Run("gets key successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/test-key-123", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var getResp KMSGetKeyResponse
		decodeKMSResponse(t, resp.Body, &getResp)
		assert.Equal(t, "test-key-123", getResp.Key.KeyID)
	})

	t.Run("gets key with version", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/test-key-123?version=2", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, uint64(2), svc.lastGetKeyReq.Version)
	})

	t.Run("returns error when key not found", func(t *testing.T) {
		svc := newMockKMSService()
		svc.getKeyErr = ErrKMSKeyNotFound{KeyID: "not-found"}
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/not-found", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/test-key", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Delete Key Tests
// =============================================================================

func TestHandleDeleteKey(t *testing.T) {
	t.Run("deletes key successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/kms/keys/test-key-123", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var delResp KMSDeleteKeyResponse
		decodeKMSResponse(t, resp.Body, &delResp)
		assert.Equal(t, "test-key-123", delResp.KeyID)
	})

	t.Run("deletes key with options", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/kms/keys/test-key-123?pending_window_days=7&force=true", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, int32(7), svc.lastDeleteKeyReq.PendingWindowDays)
		assert.True(t, svc.lastDeleteKeyReq.Force)
	})

	t.Run("returns error when key not found", func(t *testing.T) {
		svc := newMockKMSService()
		svc.deleteKeyErr = ErrKMSKeyNotFound{KeyID: "not-found"}
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/kms/keys/not-found", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/kms/keys/test-key", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Rotate Key Tests
// =============================================================================

func TestHandleRotateKey(t *testing.T) {
	t.Run("rotates key successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/test-key-123/rotate", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var rotResp KMSRotateKeyResponse
		decodeKMSResponse(t, resp.Body, &rotResp)
		assert.Equal(t, "test-key-123", rotResp.KeyID)
		assert.Equal(t, uint64(1), rotResp.OldVersion)
		assert.Equal(t, uint64(2), rotResp.NewVersion)
	})

	t.Run("rotates key with retain_old_version", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRotateKeyRequest{RetainOldVersion: true}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/test-key-123/rotate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, svc.lastRotateKeyReq.RetainOldVersion)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/test-key-123/rotate", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Length", "7")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/test-key/rotate", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.rotateKeyErr = ErrKMSKeyDisabled{KeyID: "test-key-123"}
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/test-key-123/rotate", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

// =============================================================================
// Export Key Tests
// =============================================================================

func TestHandleExportKey(t *testing.T) {
	t.Run("exports key successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/test-key-123/export", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var expResp KMSExportKeyResponse
		decodeKMSResponse(t, resp.Body, &expResp)
		assert.Equal(t, "test-key-123", expResp.KeyID)
		assert.NotEmpty(t, expResp.WrappedMaterial)
	})

	t.Run("exports key with options", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/test-key-123/export?wrapping_key_id=wrap-key&format=1&version=2", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "wrap-key", svc.lastExportKeyReq.WrappingKeyID)
		assert.Equal(t, int32(1), svc.lastExportKeyReq.Format)
		assert.Equal(t, uint64(2), svc.lastExportKeyReq.Version)
	})

	t.Run("returns error when key not exportable", func(t *testing.T) {
		svc := newMockKMSService()
		svc.exportKeyErr = ErrKMSKeyNotExportable{KeyID: "test-key-123"}
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/test-key-123/export", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/test-key/export", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Get Key Versions Tests
// =============================================================================

func TestHandleGetKeyVersions(t *testing.T) {
	t.Run("gets key versions successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/test-key-123/versions", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var versResp KMSGetKeyVersionsResponse
		decodeKMSResponse(t, resp.Body, &versResp)
		assert.Equal(t, "test-key-123", versResp.KeyID)
		assert.Equal(t, 2, len(versResp.Versions))
	})

	t.Run("gets key versions with pagination", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/test-key-123/versions?limit=5&cursor=xyz", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, int32(5), svc.lastGetKeyVersionsReq.Limit)
		assert.Equal(t, "xyz", svc.lastGetKeyVersionsReq.Cursor)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/test-key/versions", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.getKeyVersionsErr = ErrKMSKeyNotFound{KeyID: "test-key-123"}
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/test-key-123/versions", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// =============================================================================
// Import Key Tests
// =============================================================================

func TestHandleImportKey(t *testing.T) {
	t.Run("imports key successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		keyMaterial := base64.StdEncoding.EncodeToString([]byte("test-key-material"))
		reqBody := KMSImportKeyRequest{
			Name:        "imported-key",
			KeyMaterial: keyMaterial,
			KeySpec: KMSKeySpecRequest{
				Algorithm: "AES-256-GCM",
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/import", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var impResp KMSImportKeyResponse
		decodeKMSResponse(t, resp.Body, &impResp)
		assert.Equal(t, "imported-key-123", impResp.Key.KeyID)
		assert.Equal(t, []byte("test-key-material"), svc.lastImportKeyReq.KeyMaterial, "the key material reaches the KMS decoded")
		require.NotNil(t, svc.lastImportKeyReq.KeySpec)
		assert.Equal(t, int32(3), svc.lastImportKeyReq.KeySpec.Algorithm, "AES-256-GCM")
	})

	t.Run("returns error when key_material is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSImportKeyRequest{
			Name:    "imported-key",
			KeySpec: KMSKeySpecRequest{Algorithm: "AES-256-GCM"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/import", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when name is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSImportKeyRequest{
			KeyMaterial: base64.StdEncoding.EncodeToString([]byte("key")),
			KeySpec:     KMSKeySpecRequest{Algorithm: "AES-256-GCM"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/import", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid base64", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSImportKeyRequest{
			Name:        "imported-key",
			KeyMaterial: "not-valid-base64!!!",
			KeySpec:     KMSKeySpecRequest{Algorithm: "AES-256-GCM"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/import", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := KMSImportKeyRequest{
			Name:        "key",
			KeyMaterial: base64.StdEncoding.EncodeToString([]byte("key")),
			KeySpec:     KMSKeySpecRequest{Algorithm: "AES-256-GCM"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/import", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.importKeyErr = ErrKMSKeyAlreadyExists{KeyID: "imported-key"}
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSImportKeyRequest{
			Name:        "imported-key",
			KeyMaterial: base64.StdEncoding.EncodeToString([]byte("key")),
			KeySpec:     KMSKeySpecRequest{Algorithm: "AES-256-GCM"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/import", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})
}

// =============================================================================
// Encrypt Tests
// =============================================================================

func TestHandleEncrypt(t *testing.T) {
	t.Run("encrypts data successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		plaintext := base64.StdEncoding.EncodeToString([]byte("test plaintext"))
		reqBody := KMSEncryptRequest{
			KeyID:     "test-key-123",
			Plaintext: plaintext,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/encrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var encResp KMSEncryptResponse
		decodeKMSResponse(t, resp.Body, &encResp)
		assert.Equal(t, "test-key-123", encResp.KeyID)
		assert.NotEmpty(t, encResp.Ciphertext)
	})

	t.Run("encrypts with context and nonce", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSEncryptRequest{
			KeyID:     "test-key-123",
			Plaintext: base64.StdEncoding.EncodeToString([]byte("test")),
			Context:   base64.StdEncoding.EncodeToString([]byte("context")),
			Nonce:     base64.StdEncoding.EncodeToString([]byte("nonce")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/encrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, []byte("context"), svc.lastEncryptReq.Context)
		assert.Equal(t, []byte("nonce"), svc.lastEncryptReq.Nonce)
	})

	t.Run("returns error when key_id is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSEncryptRequest{
			Plaintext: base64.StdEncoding.EncodeToString([]byte("test")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/encrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when plaintext is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSEncryptRequest{
			KeyID: "test-key-123",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/encrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid plaintext base64", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSEncryptRequest{
			KeyID:     "test-key-123",
			Plaintext: "not-valid-base64!!!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/encrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid context base64", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSEncryptRequest{
			KeyID:     "test-key-123",
			Plaintext: base64.StdEncoding.EncodeToString([]byte("test")),
			Context:   "invalid!!!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/encrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid nonce base64", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSEncryptRequest{
			KeyID:     "test-key-123",
			Plaintext: base64.StdEncoding.EncodeToString([]byte("test")),
			Nonce:     "invalid!!!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/encrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.encryptErr = ErrKMSEncryptionFailed{Reason: "encryption error"}
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSEncryptRequest{
			KeyID:     "test-key-123",
			Plaintext: base64.StdEncoding.EncodeToString([]byte("test")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/encrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := KMSEncryptRequest{
			KeyID:     "key",
			Plaintext: base64.StdEncoding.EncodeToString([]byte("test")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/encrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Decrypt Tests
// =============================================================================

func TestHandleDecrypt(t *testing.T) {
	t.Run("decrypts data successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted data"))
		reqBody := KMSDecryptRequest{
			KeyID:      "test-key-123",
			Ciphertext: ciphertext,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/decrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var decResp KMSDecryptResponse
		decodeKMSResponse(t, resp.Body, &decResp)
		assert.Equal(t, "test-key-123", decResp.KeyID)
		assert.NotEmpty(t, decResp.Plaintext)
	})

	t.Run("decrypts with context and nonce", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSDecryptRequest{
			KeyID:      "test-key-123",
			Ciphertext: base64.StdEncoding.EncodeToString([]byte("encrypted")),
			Context:    base64.StdEncoding.EncodeToString([]byte("context")),
			Nonce:      base64.StdEncoding.EncodeToString([]byte("nonce")),
			KeyVersion: 2,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/decrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, []byte("context"), svc.lastDecryptReq.Context)
		assert.Equal(t, []byte("nonce"), svc.lastDecryptReq.Nonce)
		assert.Equal(t, uint64(2), svc.lastDecryptReq.KeyVersion)
	})

	t.Run("returns error when key_id is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSDecryptRequest{
			Ciphertext: base64.StdEncoding.EncodeToString([]byte("test")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/decrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when ciphertext is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSDecryptRequest{
			KeyID: "test-key-123",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/decrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid base64", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSDecryptRequest{
			KeyID:      "test-key-123",
			Ciphertext: "not-valid!!!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/decrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid context base64", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSDecryptRequest{
			KeyID:      "test-key-123",
			Ciphertext: base64.StdEncoding.EncodeToString([]byte("test")),
			Context:    "invalid!!!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/decrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid nonce base64", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSDecryptRequest{
			KeyID:      "test-key-123",
			Ciphertext: base64.StdEncoding.EncodeToString([]byte("test")),
			Nonce:      "invalid!!!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/decrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.decryptErr = ErrKMSDecryptionFailed{Reason: "decryption error"}
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSDecryptRequest{
			KeyID:      "test-key-123",
			Ciphertext: base64.StdEncoding.EncodeToString([]byte("test")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/decrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := KMSDecryptRequest{
			KeyID:      "key",
			Ciphertext: base64.StdEncoding.EncodeToString([]byte("test")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/decrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Sign Tests
// =============================================================================

func TestHandleSign(t *testing.T) {
	t.Run("signs message successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		message := base64.StdEncoding.EncodeToString([]byte("message to sign"))
		reqBody := KMSSignRequest{
			KeyID:   "test-key-123",
			Message: message,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/sign", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var signResp KMSSignResponse
		decodeKMSResponse(t, resp.Body, &signResp)
		assert.Equal(t, "test-key-123", signResp.KeyID)
		assert.NotEmpty(t, signResp.Signature)
		assert.Equal(t, []byte("message to sign"), svc.lastSignReq.Message, "the message reaches the KMS decoded")
	})

	t.Run("returns error when key_id is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSSignRequest{
			Message: base64.StdEncoding.EncodeToString([]byte("test")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/sign", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when message is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSSignRequest{
			KeyID: "test-key-123",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/sign", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid base64", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSSignRequest{
			KeyID:   "test-key-123",
			Message: "not-valid!!!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/sign", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.signErr = ErrKMSSigningFailed{Reason: "signing error"}
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSSignRequest{
			KeyID:   "test-key-123",
			Message: base64.StdEncoding.EncodeToString([]byte("test")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/sign", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := KMSSignRequest{
			KeyID:   "key",
			Message: base64.StdEncoding.EncodeToString([]byte("test")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/sign", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Verify Tests
// =============================================================================

func TestHandleVerify(t *testing.T) {
	t.Run("verifies signature successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSVerifyRequest{
			KeyID:     "test-key-123",
			Message:   base64.StdEncoding.EncodeToString([]byte("message")),
			Signature: base64.StdEncoding.EncodeToString([]byte("signature")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var verifyResp KMSVerifyResponse
		decodeKMSResponse(t, resp.Body, &verifyResp)
		assert.Equal(t, "test-key-123", verifyResp.KeyID)
		assert.True(t, verifyResp.Valid)
		assert.Equal(t, []byte("message"), svc.lastVerifyReq.Message, "the message reaches the KMS decoded")
		assert.Equal(t, []byte("signature"), svc.lastVerifyReq.Signature, "the signature reaches the KMS decoded")
	})

	t.Run("returns error when key_id is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSVerifyRequest{
			Message:   base64.StdEncoding.EncodeToString([]byte("message")),
			Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when message is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSVerifyRequest{
			KeyID:     "test-key-123",
			Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when signature is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSVerifyRequest{
			KeyID:   "test-key-123",
			Message: base64.StdEncoding.EncodeToString([]byte("message")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid message base64", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSVerifyRequest{
			KeyID:     "test-key-123",
			Message:   "invalid!!!",
			Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid signature base64", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSVerifyRequest{
			KeyID:     "test-key-123",
			Message:   base64.StdEncoding.EncodeToString([]byte("message")),
			Signature: "invalid!!!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.verifyErr = ErrKMSVerificationFailed{Reason: "verification error"}
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSVerifyRequest{
			KeyID:     "test-key-123",
			Message:   base64.StdEncoding.EncodeToString([]byte("message")),
			Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := KMSVerifyRequest{
			KeyID:     "key",
			Message:   base64.StdEncoding.EncodeToString([]byte("message")),
			Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Hash Tests
// =============================================================================

func TestHandleHash(t *testing.T) {
	t.Run("hashes data successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSHashRequest{
			Data:      base64.StdEncoding.EncodeToString([]byte("data to hash")),
			Algorithm: 1,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hash", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var hashResp KMSHashResponse
		decodeKMSResponse(t, resp.Body, &hashResp)
		assert.NotEmpty(t, hashResp.Hash)
		assert.Equal(t, []byte("data to hash"), svc.lastHashReq.Data, "the data reaches the KMS decoded")
	})

	t.Run("returns error when data is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSHashRequest{
			Algorithm: 1,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hash", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid base64", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSHashRequest{
			Data: "not-valid!!!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hash", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := KMSHashRequest{
			Data: base64.StdEncoding.EncodeToString([]byte("data")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hash", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.hashErr = ErrKMSOperationFailed{Reason: "error"}
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSHashRequest{
			Data: base64.StdEncoding.EncodeToString([]byte("data")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hash", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// HMAC Tests
// =============================================================================

func TestHandleHMAC(t *testing.T) {
	t.Run("generates HMAC successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSHMACRequest{
			KeyID:   "test-key-123",
			Message: base64.StdEncoding.EncodeToString([]byte("message")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hmac", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var hmacResp KMSHMACResponse
		decodeKMSResponse(t, resp.Body, &hmacResp)
		assert.Equal(t, "test-key-123", hmacResp.KeyID)
		assert.NotEmpty(t, hmacResp.HMAC)
		assert.Equal(t, []byte("message"), svc.lastHMACReq.Message, "the message reaches the KMS decoded")
	})

	t.Run("returns error when key_id is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSHMACRequest{
			Message: base64.StdEncoding.EncodeToString([]byte("message")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hmac", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when message is missing", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSHMACRequest{
			KeyID: "test-key-123",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hmac", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid base64", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSHMACRequest{
			KeyID:   "test-key-123",
			Message: "not-valid!!!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hmac", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := KMSHMACRequest{
			KeyID:   "key",
			Message: base64.StdEncoding.EncodeToString([]byte("message")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hmac", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.hmacErr = ErrKMSOperationFailed{Reason: "error"}
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSHMACRequest{
			KeyID:   "test-key-123",
			Message: base64.StdEncoding.EncodeToString([]byte("message")),
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hmac", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// Random Tests
// =============================================================================

func TestHandleRandom(t *testing.T) {
	t.Run("generates random bytes successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRandomRequest{
			NumBytes: 32,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/random", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var randResp KMSRandomResponse
		decodeKMSResponse(t, resp.Body, &randResp)
		assert.NotEmpty(t, randResp.RandomBytes)

		decoded, err := base64.StdEncoding.DecodeString(randResp.RandomBytes)
		require.NoError(t, err)
		assert.Len(t, decoded, 32)
	})

	t.Run("returns error when num_bytes is 0", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRandomRequest{
			NumBytes: 0,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/random", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when num_bytes is negative", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRandomRequest{
			NumBytes: -1,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/random", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when num_bytes exceeds max", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRandomRequest{
			NumBytes: kmsMaxRandomBytes + 1,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/random", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := KMSRandomRequest{NumBytes: 16}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/random", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.generateRandomErr = ErrKMSOperationFailed{Reason: "error"}
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRandomRequest{NumBytes: 16}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/random", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// Backend Status Tests
// =============================================================================

func TestHandleBackendStatus(t *testing.T) {
	t.Run("gets backend status successfully", func(t *testing.T) {
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var statusResp KMSBackendStatusResponse
		decodeKMSResponse(t, resp.Body, &statusResp)
		assert.Equal(t, "software", statusResp.BackendType)
		assert.Equal(t, "healthy", statusResp.Status)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewKMSHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		svc := newMockKMSService()
		svc.backendStatusErr = ErrKMSServiceUnavailable{Reason: "backend down"}
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Algorithm and Usage Conversion Tests
// =============================================================================

func TestAlgorithmConversions(t *testing.T) {
	h := NewKMSHandlers(nil, nil)

	tests := []struct {
		name     string
		expected int32
	}{
		{"AES-128-GCM", 1},
		{"AES-192-GCM", 2},
		{"AES-256-GCM", 3},
		{"CHACHA20-POLY1305", 4},
		{"XCHACHA20-POLY1305", 5},
		{"RSA-2048", 10},
		{"RSA-3072", 11},
		{"RSA-4096", 12},
		{"ECDSA-P256", 20},
		{"ECDSA-P384", 21},
		{"ECDSA-P521", 22},
		{"ED25519", 30},
		{"ED448", 31},
		{"X25519", 40},
		{"X448", 41},
		{"HMAC-SHA256", 50},
		{"HMAC-SHA384", 51},
		{"HMAC-SHA512", 52},
		{"UNKNOWN", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := h.stringToKeyAlgorithm(tt.name)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUsageConversions(t *testing.T) {
	h := NewKMSHandlers(nil, nil)

	tests := []struct {
		name     string
		expected int32
	}{
		{"ENCRYPT", 1},
		{"DECRYPT", 2},
		{"SIGN", 3},
		{"VERIFY", 4},
		{"WRAP_KEY", 5},
		{"DERIVE_KEY", 6},
		{"GENERATE_MAC", 7},
		{"VERIFY_MAC", 8},
		{"UNKNOWN", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := h.stringToKeyUsage(tt.name)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Error Mapping Tests
// =============================================================================

func TestWriteKMSError(t *testing.T) {
	h := NewKMSHandlers(nil, slog.Default())

	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"message never decides the class", ErrKMSOperationFailed{Reason: "not implemented"}, http.StatusInternalServerError},
		{"batch items empty", ErrKMSBatchItemsEmpty{}, http.StatusBadRequest},
		{"batch items too many", ErrKMSBatchItemsTooMany{Count: 2, Max: 1}, http.StatusBadRequest},
		{"batch partly failed", ErrKMSBatchOperationFailed{Operation: "encrypt"}, http.StatusMultiStatus},
		{"operation failed", ErrKMSOperationFailed{Reason: "other"}, http.StatusInternalServerError},
		{"key not found", ErrKMSKeyNotFound{KeyID: "key"}, http.StatusNotFound},
		{"key already exists", ErrKMSKeyAlreadyExists{KeyID: "key"}, http.StatusConflict},
		{"invalid key spec", ErrKMSInvalidKeySpec{Reason: "bad"}, http.StatusBadRequest},
		{"key not exportable", ErrKMSKeyNotExportable{KeyID: "key"}, http.StatusForbidden},
		{"key disabled", ErrKMSKeyDisabled{KeyID: "key"}, http.StatusForbidden},
		{"key pending deletion", ErrKMSKeyPendingDeletion{KeyID: "key"}, http.StatusForbidden},
		{"encryption failed", ErrKMSEncryptionFailed{Reason: "err"}, http.StatusInternalServerError},
		{"decryption failed", ErrKMSDecryptionFailed{Reason: "err"}, http.StatusInternalServerError},
		{"signing failed", ErrKMSSigningFailed{Reason: "err"}, http.StatusInternalServerError},
		{"verification failed", ErrKMSVerificationFailed{Reason: "err"}, http.StatusInternalServerError},
		{"invalid algorithm", ErrKMSInvalidAlgorithm{Algorithm: "999"}, http.StatusBadRequest},
		{"service unavailable", ErrKMSServiceUnavailable{Reason: "down"}, http.StatusServiceUnavailable},
		{"unknown error", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.writeKMSError(w, "test", tt.err)
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

// TestWriteKMSError_Classes covers the errors the live KMS backend returns:
// REST answers each with the HTTP status for its class, as gRPC does (#304).
func TestWriteKMSError_Classes(t *testing.T) {
	h := NewKMSHandlers(nil, slog.Default())

	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"sdk not found", sdkerrors.NewNotFound("GetKey", "no key"), http.StatusNotFound},
		{"database not found", quicbaas.NewDatabaseError(quicbaas.ErrNotFound, "GetKey", "no key"), http.StatusNotFound},
		{"sdk invalid input", sdkerrors.NewInvalidInput("GetKey", "bad id"), http.StatusBadRequest},
		{"sdk already exists", sdkerrors.NewAlreadyExists("ImportKey", "dup"), http.StatusConflict},
		{"sdk precondition", sdkerrors.NewPreconditionFailed("DeleteKey", "in use"), http.StatusPreconditionFailed},
		{"sdk forbidden", sdkerrors.NewForbidden("ExportKey", "no"), http.StatusForbidden},
		{"sdk unimplemented", sdkerrors.NewUnimplemented("Rewrap", "later"), http.StatusNotImplemented},
		{"sdk unavailable", sdkerrors.NewUnavailable("GetKey", "down"), http.StatusServiceUnavailable},
		{"typed status error", status.Error(codes.InvalidArgument, "bad cursor"), http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.writeKMSError(w, "test", tt.err)
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

// TestKMSHandlers_GetKey_SDKNotFound asks REST for a key the SDK does not
// have: the answer is 404, not 500.
func TestKMSHandlers_GetKey_SDKNotFound(t *testing.T) {
	svc := newMockKMSService()
	svc.getKeyErr = sdkerrors.NewNotFound("GetKey", "no key missing")
	_, router := setupKMSTestHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/missing", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// =============================================================================
// Helper Method Tests
// =============================================================================

func TestGetPaginationParams(t *testing.T) {
	h := NewKMSHandlers(nil, nil)

	t.Run("default values", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		limit, cursor := h.getPaginationParams(req)
		assert.Equal(t, kmsDefaultLimit, limit)
		assert.Empty(t, cursor)
	})

	t.Run("custom values", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?limit=25&cursor=abc", nil)
		limit, cursor := h.getPaginationParams(req)
		assert.Equal(t, int32(25), limit)
		assert.Equal(t, "abc", cursor)
	})

	t.Run("limit exceeds max", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?limit=5000", nil)
		limit, _ := h.getPaginationParams(req)
		assert.Equal(t, kmsMaxLimit, limit)
	})

	t.Run("limit less than 1", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?limit=0", nil)
		limit, _ := h.getPaginationParams(req)
		assert.Equal(t, kmsDefaultLimit, limit)
	})

	t.Run("invalid limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?limit=invalid", nil)
		limit, _ := h.getPaginationParams(req)
		assert.Equal(t, kmsDefaultLimit, limit)
	})
}

func TestKeySpecRequestToService(t *testing.T) {
	h := NewKMSHandlers(nil, nil)

	t.Run("nil input", func(t *testing.T) {
		result := h.keySpecRequestToService(nil)
		assert.Nil(t, result)
	})

	t.Run("full conversion", func(t *testing.T) {
		spec := &KMSKeySpecRequest{
			Algorithm:          "AES-256-GCM",
			KeySize:            256,
			Usage:              []string{"ENCRYPT", "DECRYPT"},
			Exportable:         true,
			DeletionProtection: true,
		}
		result := h.keySpecRequestToService(spec)
		assert.NotNil(t, result)
		assert.Equal(t, int32(3), result.Algorithm)
		assert.Equal(t, int32(256), result.KeySize)
		assert.Equal(t, []int32{1, 2}, result.Usage)
		assert.True(t, result.Exportable)
		assert.True(t, result.DeletionProtection)
	})
}

func TestKeyHandleToResponse(t *testing.T) {
	h := NewKMSHandlers(nil, nil)

	t.Run("nil input", func(t *testing.T) {
		result := h.keyHandleToResponse(nil)
		assert.Nil(t, result)
	})

	t.Run("full conversion", func(t *testing.T) {
		handle := &KMSKeyHandle{
			KeyID:     "key-123",
			Version:   5,
			Algorithm: 3,
			Status:    1,
			CreatedAt: 12345,
		}
		result := h.keyHandleToResponse(handle)
		assert.NotNil(t, result)
		assert.Equal(t, "key-123", result.KeyID)
		assert.Equal(t, uint64(5), result.Version)
		assert.Equal(t, int32(3), result.Algorithm)
		assert.Equal(t, int32(1), result.Status)
		assert.Equal(t, int64(12345), result.CreatedAt)
	})
}

func TestKeyMetadataToResponse(t *testing.T) {
	h := NewKMSHandlers(nil, nil)

	t.Run("nil input", func(t *testing.T) {
		result := h.keyMetadataToResponse(nil)
		assert.Nil(t, result)
	})

	t.Run("full conversion", func(t *testing.T) {
		metadata := &KMSKeyMetadata{
			KeyID:              "key-123",
			Name:               "test-key",
			Description:        "Test description",
			Algorithm:          3,
			Status:             1,
			Usage:              []int32{1, 2},
			Version:            5,
			Exportable:         true,
			DeletionProtection: false,
			CreatedAt:          12345,
			UpdatedAt:          12346,
			LastUsedAt:         12347,
			Tags:               map[string]string{"env": "test"},
			Owner:              "user1",
		}
		result := h.keyMetadataToResponse(metadata)
		assert.NotNil(t, result)
		assert.Equal(t, "key-123", result.KeyID)
		assert.Equal(t, "test-key", result.Name)
		assert.Equal(t, "Test description", result.Description)
		assert.Equal(t, int32(3), result.Algorithm)
		assert.Equal(t, int32(1), result.Status)
		assert.Equal(t, []int32{1, 2}, result.Usage)
		assert.Equal(t, uint64(5), result.Version)
		assert.True(t, result.Exportable)
		assert.False(t, result.DeletionProtection)
		assert.Equal(t, int64(12345), result.CreatedAt)
		assert.Equal(t, int64(12346), result.UpdatedAt)
		assert.Equal(t, int64(12347), result.LastUsedAt)
		assert.Equal(t, map[string]string{"env": "test"}, result.Tags)
		assert.Equal(t, "user1", result.Owner)
	})
}

// =============================================================================
// Batch Encrypt Handler Tests
// =============================================================================

func TestKMSHandlers_BatchEncrypt(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchEncryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchEncryptItemRequest{
				{Plaintext: base64.StdEncoding.EncodeToString([]byte("hello"))},
				{Plaintext: base64.StdEncoding.EncodeToString([]byte("world"))},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-encrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		var resp KMSBatchEncryptResponse
		decodeKMSResponse(t, rec.Body, &resp)
		assert.Equal(t, "test-key-id", resp.KeyID)
		assert.Len(t, resp.Results, 2)
		require.Len(t, svc.lastBatchEncryptReq.Items, 2)
		assert.Equal(t, []byte("hello"), svc.lastBatchEncryptReq.Items[0].Plaintext, "each item reaches the KMS decoded, in order")
		assert.Equal(t, []byte("world"), svc.lastBatchEncryptReq.Items[1].Plaintext)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-encrypt", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing key_id", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchEncryptRequest{
			KeyID: "",
			Items: []KMSBatchEncryptItemRequest{
				{Plaintext: base64.StdEncoding.EncodeToString([]byte("hello"))},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-encrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("empty items", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchEncryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchEncryptItemRequest{},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-encrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing plaintext in item", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchEncryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchEncryptItemRequest{
				{Plaintext: ""},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-encrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid base64 plaintext", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchEncryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchEncryptItemRequest{
				{Plaintext: "not-valid-base64!!!"},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-encrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid base64 context", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchEncryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchEncryptItemRequest{
				{
					Plaintext: base64.StdEncoding.EncodeToString([]byte("hello")),
					Context:   "not-valid-base64!!!",
				},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-encrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid base64 nonce", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchEncryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchEncryptItemRequest{
				{
					Plaintext: base64.StdEncoding.EncodeToString([]byte("hello")),
					Nonce:     "not-valid-base64!!!",
				},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-encrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("service error", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		svc.batchEncryptErr = errors.New("encryption failed")
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchEncryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchEncryptItemRequest{
				{Plaintext: base64.StdEncoding.EncodeToString([]byte("hello"))},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-encrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

// =============================================================================
// Batch Decrypt Handler Tests
// =============================================================================

func TestKMSHandlers_BatchDecrypt(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchDecryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchDecryptItemRequest{
				{Ciphertext: base64.StdEncoding.EncodeToString([]byte("encrypted1"))},
				{Ciphertext: base64.StdEncoding.EncodeToString([]byte("encrypted2"))},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-decrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		var resp KMSBatchDecryptResponse
		decodeKMSResponse(t, rec.Body, &resp)
		assert.Equal(t, "test-key-id", resp.KeyID)
		assert.Len(t, resp.Results, 2)
		require.Len(t, svc.lastBatchDecryptReq.Items, 2)
		assert.Equal(t, []byte("encrypted1"), svc.lastBatchDecryptReq.Items[0].Ciphertext, "each item reaches the KMS decoded, in order")
		assert.Equal(t, []byte("encrypted2"), svc.lastBatchDecryptReq.Items[1].Ciphertext)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-decrypt", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing key_id", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchDecryptRequest{
			KeyID: "",
			Items: []KMSBatchDecryptItemRequest{
				{Ciphertext: base64.StdEncoding.EncodeToString([]byte("encrypted1"))},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-decrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("empty items", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchDecryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchDecryptItemRequest{},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-decrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing ciphertext in item", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchDecryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchDecryptItemRequest{
				{Ciphertext: ""},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-decrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid base64 ciphertext", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchDecryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchDecryptItemRequest{
				{Ciphertext: "not-valid-base64!!!"},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-decrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid base64 context", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchDecryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchDecryptItemRequest{
				{
					Ciphertext: base64.StdEncoding.EncodeToString([]byte("encrypted1")),
					Context:    "not-valid-base64!!!",
				},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-decrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid base64 nonce", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchDecryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchDecryptItemRequest{
				{
					Ciphertext: base64.StdEncoding.EncodeToString([]byte("encrypted1")),
					Nonce:      "not-valid-base64!!!",
				},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-decrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("service error", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		svc.batchDecryptErr = errors.New("decryption failed")
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSBatchDecryptRequest{
			KeyID: "test-key-id",
			Items: []KMSBatchDecryptItemRequest{
				{Ciphertext: base64.StdEncoding.EncodeToString([]byte("encrypted1"))},
			},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch-decrypt", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

// =============================================================================
// Rewrap Handler Tests
// =============================================================================

func TestKMSHandlers_Rewrap(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRewrapRequest{
			SourceKeyID:      "source-key",
			DestinationKeyID: "dest-key",
			Ciphertext:       base64.StdEncoding.EncodeToString([]byte("encrypted")),
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/rewrap", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		var resp KMSRewrapResponse
		decodeKMSResponse(t, rec.Body, &resp)
		assert.NotEmpty(t, resp.Ciphertext)
		assert.Equal(t, "source-key", svc.lastRewrapReq.SourceKeyID)
		assert.Equal(t, "dest-key", svc.lastRewrapReq.DestinationKeyID, "source and destination must not be swapped")
		assert.Equal(t, []byte("encrypted"), svc.lastRewrapReq.Ciphertext, "the ciphertext reaches the KMS decoded")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/rewrap", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing source_key_id", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRewrapRequest{
			SourceKeyID:      "",
			DestinationKeyID: "dest-key",
			Ciphertext:       base64.StdEncoding.EncodeToString([]byte("encrypted")),
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/rewrap", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing destination_key_id", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRewrapRequest{
			SourceKeyID:      "source-key",
			DestinationKeyID: "",
			Ciphertext:       base64.StdEncoding.EncodeToString([]byte("encrypted")),
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/rewrap", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing ciphertext", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRewrapRequest{
			SourceKeyID:      "source-key",
			DestinationKeyID: "dest-key",
			Ciphertext:       "",
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/rewrap", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid base64 ciphertext", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRewrapRequest{
			SourceKeyID:      "source-key",
			DestinationKeyID: "dest-key",
			Ciphertext:       "not-valid-base64!!!",
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/rewrap", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid base64 context", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRewrapRequest{
			SourceKeyID:      "source-key",
			DestinationKeyID: "dest-key",
			Ciphertext:       base64.StdEncoding.EncodeToString([]byte("encrypted")),
			SourceContext:    "not-valid-base64!!!",
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/rewrap", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("service error", func(t *testing.T) {
		t.Parallel()
		svc := newMockKMSService()
		svc.rewrapErr = errors.New("rewrap failed")
		_, router := setupKMSTestHandler(svc)

		reqBody := KMSRewrapRequest{
			SourceKeyID:      "source-key",
			DestinationKeyID: "dest-key",
			Ciphertext:       base64.StdEncoding.EncodeToString([]byte("encrypted")),
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/rewrap", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
