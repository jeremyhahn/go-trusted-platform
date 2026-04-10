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

package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// Mock gRPC clients for testing

type mockKeyManagementClient struct {
	proto.KeyManagementClient

	generateKeyFn     func(ctx context.Context, req *proto.GenerateKeyRequest, opts ...grpc.CallOption) (*proto.GenerateKeyResponse, error)
	importKeyFn       func(ctx context.Context, req *proto.ImportKeyRequest, opts ...grpc.CallOption) (*proto.ImportKeyResponse, error)
	getKeyFn          func(ctx context.Context, req *proto.GetKeyRequest, opts ...grpc.CallOption) (*proto.GetKeyResponse, error)
	listKeysFn        func(ctx context.Context, req *proto.ListKeysRequest, opts ...grpc.CallOption) (*proto.ListKeysResponse, error)
	listKeyVersionsFn func(ctx context.Context, req *proto.ListKeyVersionsRequest, opts ...grpc.CallOption) (*proto.ListKeyVersionsResponse, error)
	rotateKeyFn       func(ctx context.Context, req *proto.RotateKeyRequest, opts ...grpc.CallOption) (*proto.RotateKeyResponse, error)
	deleteKeyFn       func(ctx context.Context, req *proto.DeleteKeyRequest, opts ...grpc.CallOption) (*proto.DeleteKeyResponse, error)
	updateKeyStatusFn func(ctx context.Context, req *proto.UpdateKeyStatusRequest, opts ...grpc.CallOption) (*proto.UpdateKeyStatusResponse, error)
	backendStatusFn   func(ctx context.Context, req *proto.BackendStatusRequest, opts ...grpc.CallOption) (*proto.BackendStatusResponse, error)
	backendTestFn     func(ctx context.Context, req *proto.BackendTestRequest, opts ...grpc.CallOption) (*proto.BackendTestResponse, error)
}

func (m *mockKeyManagementClient) GenerateKey(ctx context.Context, req *proto.GenerateKeyRequest, opts ...grpc.CallOption) (*proto.GenerateKeyResponse, error) {
	if m.generateKeyFn != nil {
		return m.generateKeyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockKeyManagementClient) ImportKey(ctx context.Context, req *proto.ImportKeyRequest, opts ...grpc.CallOption) (*proto.ImportKeyResponse, error) {
	if m.importKeyFn != nil {
		return m.importKeyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockKeyManagementClient) GetKey(ctx context.Context, req *proto.GetKeyRequest, opts ...grpc.CallOption) (*proto.GetKeyResponse, error) {
	if m.getKeyFn != nil {
		return m.getKeyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockKeyManagementClient) ListKeys(ctx context.Context, req *proto.ListKeysRequest, opts ...grpc.CallOption) (*proto.ListKeysResponse, error) {
	if m.listKeysFn != nil {
		return m.listKeysFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockKeyManagementClient) ListKeyVersions(ctx context.Context, req *proto.ListKeyVersionsRequest, opts ...grpc.CallOption) (*proto.ListKeyVersionsResponse, error) {
	if m.listKeyVersionsFn != nil {
		return m.listKeyVersionsFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockKeyManagementClient) RotateKey(ctx context.Context, req *proto.RotateKeyRequest, opts ...grpc.CallOption) (*proto.RotateKeyResponse, error) {
	if m.rotateKeyFn != nil {
		return m.rotateKeyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockKeyManagementClient) DeleteKey(ctx context.Context, req *proto.DeleteKeyRequest, opts ...grpc.CallOption) (*proto.DeleteKeyResponse, error) {
	if m.deleteKeyFn != nil {
		return m.deleteKeyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockKeyManagementClient) UpdateKeyStatus(ctx context.Context, req *proto.UpdateKeyStatusRequest, opts ...grpc.CallOption) (*proto.UpdateKeyStatusResponse, error) {
	if m.updateKeyStatusFn != nil {
		return m.updateKeyStatusFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockKeyManagementClient) BackendStatus(ctx context.Context, req *proto.BackendStatusRequest, opts ...grpc.CallOption) (*proto.BackendStatusResponse, error) {
	if m.backendStatusFn != nil {
		return m.backendStatusFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockKeyManagementClient) BackendTest(ctx context.Context, req *proto.BackendTestRequest, opts ...grpc.CallOption) (*proto.BackendTestResponse, error) {
	if m.backendTestFn != nil {
		return m.backendTestFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

type mockCryptoClient struct {
	proto.CryptoClient

	encryptFn func(ctx context.Context, req *proto.CryptoEncryptRequest, opts ...grpc.CallOption) (*proto.CryptoEncryptResponse, error)
	decryptFn func(ctx context.Context, req *proto.CryptoDecryptRequest, opts ...grpc.CallOption) (*proto.CryptoDecryptResponse, error)
}

func (m *mockCryptoClient) Encrypt(ctx context.Context, req *proto.CryptoEncryptRequest, opts ...grpc.CallOption) (*proto.CryptoEncryptResponse, error) {
	if m.encryptFn != nil {
		return m.encryptFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockCryptoClient) Decrypt(ctx context.Context, req *proto.CryptoDecryptRequest, opts ...grpc.CallOption) (*proto.CryptoDecryptResponse, error) {
	if m.decryptFn != nil {
		return m.decryptFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

type mockDEKManagementClient struct {
	proto.DEKManagementClient

	createDEKFn    func(ctx context.Context, req *proto.CreateDEKRequest, opts ...grpc.CallOption) (*proto.CreateDEKResponse, error)
	getDEKFn       func(ctx context.Context, req *proto.GetDEKRequest, opts ...grpc.CallOption) (*proto.GetDEKResponse, error)
	listDEKsFn     func(ctx context.Context, req *proto.ListDEKsRequest, opts ...grpc.CallOption) (*proto.ListDEKsResponse, error)
	rotateDEKFn    func(ctx context.Context, req *proto.RotateDEKRequest, opts ...grpc.CallOption) (*proto.RotateDEKResponse, error)
	deleteDEKFn    func(ctx context.Context, req *proto.DeleteDEKRequest, opts ...grpc.CallOption) (*proto.DeleteDEKResponse, error)
	getDEKStatusFn func(ctx context.Context, req *proto.GetDEKStatusRequest, opts ...grpc.CallOption) (*proto.GetDEKStatusResponse, error)
}

func (m *mockDEKManagementClient) CreateDEK(ctx context.Context, req *proto.CreateDEKRequest, opts ...grpc.CallOption) (*proto.CreateDEKResponse, error) {
	if m.createDEKFn != nil {
		return m.createDEKFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockDEKManagementClient) GetDEK(ctx context.Context, req *proto.GetDEKRequest, opts ...grpc.CallOption) (*proto.GetDEKResponse, error) {
	if m.getDEKFn != nil {
		return m.getDEKFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockDEKManagementClient) ListDEKs(ctx context.Context, req *proto.ListDEKsRequest, opts ...grpc.CallOption) (*proto.ListDEKsResponse, error) {
	if m.listDEKsFn != nil {
		return m.listDEKsFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockDEKManagementClient) RotateDEK(ctx context.Context, req *proto.RotateDEKRequest, opts ...grpc.CallOption) (*proto.RotateDEKResponse, error) {
	if m.rotateDEKFn != nil {
		return m.rotateDEKFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockDEKManagementClient) DeleteDEK(ctx context.Context, req *proto.DeleteDEKRequest, opts ...grpc.CallOption) (*proto.DeleteDEKResponse, error) {
	if m.deleteDEKFn != nil {
		return m.deleteDEKFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockDEKManagementClient) GetDEKStatus(ctx context.Context, req *proto.GetDEKStatusRequest, opts ...grpc.CallOption) (*proto.GetDEKStatusResponse, error) {
	if m.getDEKStatusFn != nil {
		return m.getDEKStatusFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// Mock HttpWriter for response handling
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

func newTestHandlers(keyMgmt *mockKeyManagementClient, crypto *mockCryptoClient, dekMgmt *mockDEKManagementClient) (*KMSHandlers, *mockHttpWriter) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	return handlers, writer
}

func createRequestWithVars(method, path string, body interface{}, vars map[string]string) *http.Request {
	var reqBody bytes.Buffer
	if body != nil {
		json.NewEncoder(&reqBody).Encode(body)
	}

	req := httptest.NewRequest(method, path, &reqBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if vars != nil {
		req = mux.SetURLVars(req, vars)
	}

	return req
}

// Tests for NewKMSHandlers

func TestNewKMSHandlers(t *testing.T) {
	logger := newTestLogger()
	keyMgmt := &mockKeyManagementClient{}
	crypto := &mockCryptoClient{}
	dekMgmt := &mockDEKManagementClient{}
	writer := &mockHttpWriter{}

	handlers := NewKMSHandlers(logger, keyMgmt, crypto, dekMgmt, nil, writer)

	require.NotNil(t, handlers)
	assert.NotNil(t, handlers.logger)
	assert.NotNil(t, handlers.keyMgmtClient)
	assert.NotNil(t, handlers.cryptoClient)
	assert.NotNil(t, handlers.dekMgmtClient)
	assert.NotNil(t, handlers.respWriter)
}

// Tests for Key Management Handlers

func TestGenerateKey_Success(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		generateKeyFn: func(ctx context.Context, req *proto.GenerateKeyRequest, opts ...grpc.CallOption) (*proto.GenerateKeyResponse, error) {
			return &proto.GenerateKeyResponse{
				Key: &proto.KeyHandle{
					KeyId:     req.Name,
					Version:   1,
					Algorithm: req.KeySpec.Algorithm,
					Status:    proto.KeyStatus_KEY_STATUS_ENABLED,
					CreatedAt: 1234567890,
				},
				Metadata: &proto.KeyMetadata{
					KeyId:       req.Name,
					Name:        req.Name,
					Description: req.Description,
					Algorithm:   req.KeySpec.Algorithm,
					Status:      proto.KeyStatus_KEY_STATUS_ENABLED,
				},
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := GenerateKeyRequest{
		KeySpec: KeySpecRequest{
			Algorithm: "AES-256-GCM",
			Usage:     []string{"ENCRYPT", "DECRYPT"},
		},
		Name:        "my-key",
		Description: "Test key",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys", body, nil)
	rec := httptest.NewRecorder()

	handlers.GenerateKey(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(GenerateKeyResponse)
	require.True(t, ok)
	assert.Equal(t, "my-key", payload.Key.KeyID)
}

func TestGenerateKey_MissingName(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := GenerateKeyRequest{
		KeySpec: KeySpecRequest{
			Algorithm: "AES-256-GCM",
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys", body, nil)
	rec := httptest.NewRecorder()

	handlers.GenerateKey(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingKeyName)
	assert.True(t, ok)
}

func TestGenerateKey_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	body := GenerateKeyRequest{Name: "test"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys", body, nil)
	rec := httptest.NewRecorder()

	handlers.GenerateKey(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGenerateKey_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.GenerateKey(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestImportKey_Success(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		importKeyFn: func(ctx context.Context, req *proto.ImportKeyRequest, opts ...grpc.CallOption) (*proto.ImportKeyResponse, error) {
			return &proto.ImportKeyResponse{
				Key: &proto.KeyHandle{
					KeyId:   req.Name,
					Version: 1,
				},
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := ImportKeyRequest{
		KeyMaterial: []byte("secret-key-material"),
		KeySpec:     KeySpecRequest{Algorithm: "AES-256-GCM"},
		Name:        "imported-key",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys/import", body, nil)
	rec := httptest.NewRecorder()

	handlers.ImportKey(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestImportKey_MissingKeyMaterial(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := ImportKeyRequest{
		Name: "imported-key",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys/import", body, nil)
	rec := httptest.NewRecorder()

	handlers.ImportKey(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrKeyMaterialRequired)
	assert.True(t, ok)
}

func TestListKeys_Success(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		listKeysFn: func(ctx context.Context, req *proto.ListKeysRequest, opts ...grpc.CallOption) (*proto.ListKeysResponse, error) {
			return &proto.ListKeysResponse{
				Keys: []*proto.KeyHandle{
					{KeyId: "key-1", Version: 1, Algorithm: proto.KeyAlgorithm_KEY_ALG_AES_256_GCM},
					{KeyId: "key-2", Version: 1, Algorithm: proto.KeyAlgorithm_KEY_ALG_RSA_2048},
				},
				TotalCount: 2,
				HasMore:    false,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/keys", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListKeys(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListKeysResponse)
	require.True(t, ok)
	assert.Len(t, payload.Keys, 2)
}

func TestGetKey_Success(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		getKeyFn: func(ctx context.Context, req *proto.GetKeyRequest, opts ...grpc.CallOption) (*proto.GetKeyResponse, error) {
			return &proto.GetKeyResponse{
				Key: &proto.KeyHandle{
					KeyId:   req.KeyId,
					Version: 1,
				},
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/keys/my-key", nil, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.GetKey(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestGetKey_MissingName(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/keys/", nil, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.GetKey(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetKey_NotFound(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		getKeyFn: func(ctx context.Context, req *proto.GetKeyRequest, opts ...grpc.CallOption) (*proto.GetKeyResponse, error) {
			return nil, status.Error(codes.NotFound, "key not found")
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/keys/nonexistent", nil, map[string]string{"name": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.GetKey(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestRotateKey_Success(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		rotateKeyFn: func(ctx context.Context, req *proto.RotateKeyRequest, opts ...grpc.CallOption) (*proto.RotateKeyResponse, error) {
			return &proto.RotateKeyResponse{
				KeyId:      req.KeyId,
				OldVersion: 1,
				NewVersion: 2,
				Timestamp:  1234567890,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys/my-key/rotate", nil, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.RotateKey(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(RotateKeyResponse)
	require.True(t, ok)
	assert.Equal(t, uint64(1), payload.OldVersion)
	assert.Equal(t, uint64(2), payload.NewVersion)
}

func TestDeleteKey_Success(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		deleteKeyFn: func(ctx context.Context, req *proto.DeleteKeyRequest, opts ...grpc.CallOption) (*proto.DeleteKeyResponse, error) {
			return &proto.DeleteKeyResponse{
				KeyId:  req.KeyId,
				Status: proto.KeyStatus_KEY_STATUS_PENDING_DELETION,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/kms/keys/my-key", nil, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.DeleteKey(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestUpdateKeyStatus_Success(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		updateKeyStatusFn: func(ctx context.Context, req *proto.UpdateKeyStatusRequest, opts ...grpc.CallOption) (*proto.UpdateKeyStatusResponse, error) {
			return &proto.UpdateKeyStatusResponse{
				KeyId:   req.KeyId,
				Version: req.Version,
				Status:  req.Status,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := UpdateKeyStatusRequest{
		Status: "DISABLED",
	}

	req := createRequestWithVars(http.MethodPut, "/api/v1/kms/keys/my-key/status", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.UpdateKeyStatus(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestUpdateKeyStatus_MissingStatus(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := UpdateKeyStatusRequest{}

	req := createRequestWithVars(http.MethodPut, "/api/v1/kms/keys/my-key/status", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.UpdateKeyStatus(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListKeyVersions_Success(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		listKeyVersionsFn: func(ctx context.Context, req *proto.ListKeyVersionsRequest, opts ...grpc.CallOption) (*proto.ListKeyVersionsResponse, error) {
			return &proto.ListKeyVersionsResponse{
				KeyId: req.KeyId,
				Versions: []*proto.KeyVersionInfo{
					{Version: 1, Status: proto.KeyStatus_KEY_STATUS_DISABLED},
					{Version: 2, Status: proto.KeyStatus_KEY_STATUS_ENABLED},
				},
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/keys/my-key/versions", nil, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.ListKeyVersions(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListKeyVersionsResponse)
	require.True(t, ok)
	assert.Len(t, payload.Versions, 2)
}

// Tests for Backend Handlers

func TestBackendStatus_Success(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		backendStatusFn: func(ctx context.Context, req *proto.BackendStatusRequest, opts ...grpc.CallOption) (*proto.BackendStatusResponse, error) {
			return &proto.BackendStatusResponse{
				BackendType:  "tpm2",
				Status:       "healthy",
				Device:       "/dev/tpm0",
				Capabilities: map[string]bool{"seal": true, "unseal": true},
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/backend/status", nil, nil)
	rec := httptest.NewRecorder()

	handlers.BackendStatus(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(BackendStatusResponse)
	require.True(t, ok)
	assert.Equal(t, "tpm2", payload.BackendType)
	assert.Equal(t, "healthy", payload.Status)
}

func TestBackendTest_Success(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		backendTestFn: func(ctx context.Context, req *proto.BackendTestRequest, opts ...grpc.CallOption) (*proto.BackendTestResponse, error) {
			return &proto.BackendTestResponse{
				Success:    true,
				DurationMs: 150,
				Message:    "Test passed",
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/backend/test", nil, nil)
	rec := httptest.NewRecorder()

	handlers.BackendTest(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(BackendTestResponse)
	require.True(t, ok)
	assert.True(t, payload.Success)
}

// Tests for Crypto Handlers

func TestEncrypt_Success(t *testing.T) {
	crypto := &mockCryptoClient{
		encryptFn: func(ctx context.Context, req *proto.CryptoEncryptRequest, opts ...grpc.CallOption) (*proto.CryptoEncryptResponse, error) {
			return &proto.CryptoEncryptResponse{
				KeyId:      req.KeyId,
				KeyVersion: 1,
				Ciphertext: []byte("encrypted-data"),
				Nonce:      []byte("random-nonce"),
			}, nil
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := EncryptRequest{
		Plaintext: []byte("secret data"),
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/encrypt/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Encrypt(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(EncryptResponse)
	require.True(t, ok)
	assert.Equal(t, "my-key", payload.KeyID)
}

func TestEncrypt_MissingPlaintext(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := EncryptRequest{}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/encrypt/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Encrypt(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingPlaintext)
	assert.True(t, ok)
}

func TestEncrypt_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, &mockKeyManagementClient{}, nil, nil, nil, writer)

	body := EncryptRequest{Plaintext: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/encrypt/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Encrypt(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestDecrypt_Success(t *testing.T) {
	crypto := &mockCryptoClient{
		decryptFn: func(ctx context.Context, req *proto.CryptoDecryptRequest, opts ...grpc.CallOption) (*proto.CryptoDecryptResponse, error) {
			return &proto.CryptoDecryptResponse{
				KeyId:     req.KeyId,
				Plaintext: []byte("decrypted data"),
			}, nil
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := DecryptRequest{
		Ciphertext: []byte("encrypted-data"),
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/decrypt/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Decrypt(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDecrypt_MissingCiphertext(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := DecryptRequest{}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/decrypt/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Decrypt(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingCiphertext)
	assert.True(t, ok)
}

// Tests for DEK Management Handlers

func TestCreateDEK_Success(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		createDEKFn: func(ctx context.Context, req *proto.CreateDEKRequest, opts ...grpc.CallOption) (*proto.CreateDEKResponse, error) {
			return &proto.CreateDEKResponse{
				Dek: &proto.DEKMetadata{
					Path:      req.Path,
					Algorithm: req.Algorithm,
					Version:   1,
					Status:    "active",
				},
			}, nil
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	body := CreateDEKRequest{
		Path:      "/tenant/app",
		Algorithm: "AES-256-GCM",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/deks", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateDEK(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestCreateDEK_MissingPath(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := CreateDEKRequest{}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/deks", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateDEK(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingDEKPath)
	assert.True(t, ok)
}

func TestListDEKs_Success(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		listDEKsFn: func(ctx context.Context, req *proto.ListDEKsRequest, opts ...grpc.CallOption) (*proto.ListDEKsResponse, error) {
			return &proto.ListDEKsResponse{
				Deks: []*proto.DEKMetadata{
					{Path: "/tenant/app1", Version: 1},
					{Path: "/tenant/app2", Version: 1},
				},
			}, nil
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/deks", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListDEKs(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListDEKsResponse)
	require.True(t, ok)
	assert.Len(t, payload.DEKs, 2)
}

func TestGetDEK_Success(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		getDEKFn: func(ctx context.Context, req *proto.GetDEKRequest, opts ...grpc.CallOption) (*proto.GetDEKResponse, error) {
			return &proto.GetDEKResponse{
				Dek: &proto.DEKMetadata{
					Path:    req.Path,
					Version: 1,
				},
			}, nil
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/deks/tenant/app", nil, map[string]string{"path": "tenant/app"})
	rec := httptest.NewRecorder()

	handlers.GetDEK(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestGetDEK_MissingPath(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/deks/", nil, map[string]string{"path": ""})
	rec := httptest.NewRecorder()

	handlers.GetDEK(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRotateDEK_Success(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		rotateDEKFn: func(ctx context.Context, req *proto.RotateDEKRequest, opts ...grpc.CallOption) (*proto.RotateDEKResponse, error) {
			return &proto.RotateDEKResponse{
				Path:       req.Path,
				OldVersion: 1,
				NewVersion: 2,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/deks/tenant/app/rotate", nil, map[string]string{"path": "tenant/app"})
	rec := httptest.NewRecorder()

	handlers.RotateDEK(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteDEK_Success(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		deleteDEKFn: func(ctx context.Context, req *proto.DeleteDEKRequest, opts ...grpc.CallOption) (*proto.DeleteDEKResponse, error) {
			return &proto.DeleteDEKResponse{
				Path:    req.Path,
				Deleted: true,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/kms/deks/tenant/app", nil, map[string]string{"path": "tenant/app"})
	rec := httptest.NewRecorder()

	handlers.DeleteDEK(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestGetDEKStatus_Success(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		getDEKStatusFn: func(ctx context.Context, req *proto.GetDEKStatusRequest, opts ...grpc.CallOption) (*proto.GetDEKStatusResponse, error) {
			return &proto.GetDEKStatusResponse{
				Dek: &proto.DEKMetadata{
					Path:    req.Path,
					Version: 2,
				},
				ReencryptionProgress: &proto.ReencryptionProgress{
					InProgress: false,
				},
			}, nil
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/deks/tenant/app/status", nil, map[string]string{"path": "tenant/app"})
	rec := httptest.NewRecorder()

	handlers.GetDEKStatus(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(GetDEKStatusResponse)
	require.True(t, ok)
	assert.NotNil(t, payload.DEK)
}

// Tests for helper methods

func TestGetPaginationParams(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	t.Run("default values", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys", nil)
		limit, cursor := handlers.getPaginationParams(req)
		assert.Equal(t, defaultLimit, limit)
		assert.Equal(t, "", cursor)
	})

	t.Run("custom values", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys?limit=25&cursor=abc123", nil)
		limit, cursor := handlers.getPaginationParams(req)
		assert.Equal(t, int32(25), limit)
		assert.Equal(t, "abc123", cursor)
	})

	t.Run("limit exceeds max", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys?limit=5000", nil)
		limit, _ := handlers.getPaginationParams(req)
		assert.Equal(t, maxLimit, limit)
	})

	t.Run("invalid limit uses default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys?limit=invalid", nil)
		limit, _ := handlers.getPaginationParams(req)
		assert.Equal(t, defaultLimit, limit)
	})
}

func TestAlgorithmConversion(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	tests := []struct {
		str string
		alg proto.KeyAlgorithm
	}{
		{"AES-128-GCM", proto.KeyAlgorithm_KEY_ALG_AES_128_GCM},
		{"AES-256-GCM", proto.KeyAlgorithm_KEY_ALG_AES_256_GCM},
		{"RSA-2048", proto.KeyAlgorithm_KEY_ALG_RSA_2048},
		{"ED25519", proto.KeyAlgorithm_KEY_ALG_ED25519},
		{"UNKNOWN", proto.KeyAlgorithm_KEY_ALG_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			alg := handlers.stringToKeyAlgorithm(tt.str)
			assert.Equal(t, tt.alg, alg)

			if tt.alg != proto.KeyAlgorithm_KEY_ALG_UNSPECIFIED {
				str := handlers.keyAlgorithmToString(tt.alg)
				assert.Equal(t, tt.str, str)
			}
		})
	}
}

func TestStatusConversion(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	tests := []struct {
		str    string
		status proto.KeyStatus
	}{
		{"ENABLED", proto.KeyStatus_KEY_STATUS_ENABLED},
		{"DISABLED", proto.KeyStatus_KEY_STATUS_DISABLED},
		{"PENDING_DELETION", proto.KeyStatus_KEY_STATUS_PENDING_DELETION},
		{"UNKNOWN", proto.KeyStatus_KEY_STATUS_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			status := handlers.stringToKeyStatus(tt.str)
			assert.Equal(t, tt.status, status)

			if tt.status != proto.KeyStatus_KEY_STATUS_UNSPECIFIED {
				str := handlers.keyStatusToString(tt.status)
				assert.Equal(t, tt.str, str)
			}
		})
	}
}

func TestUsageConversion(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	tests := []struct {
		str   string
		usage proto.KeyUsage
	}{
		{"ENCRYPT", proto.KeyUsage_KEY_USAGE_ENCRYPT},
		{"DECRYPT", proto.KeyUsage_KEY_USAGE_DECRYPT},
		{"SIGN", proto.KeyUsage_KEY_USAGE_SIGN},
		{"VERIFY", proto.KeyUsage_KEY_USAGE_VERIFY},
		{"UNKNOWN", proto.KeyUsage_KEY_USAGE_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			usage := handlers.stringToKeyUsage(tt.str)
			assert.Equal(t, tt.usage, usage)

			if tt.usage != proto.KeyUsage_KEY_USAGE_UNSPECIFIED {
				str := handlers.keyUsageToString(tt.usage)
				assert.Equal(t, tt.str, str)
			}
		})
	}
}

func TestHandleGRPCError(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	tests := []struct {
		name         string
		err          error
		expectedCode int
	}{
		{"not found", status.Error(codes.NotFound, "not found"), http.StatusNotFound},
		{"invalid argument", status.Error(codes.InvalidArgument, "invalid"), http.StatusBadRequest},
		{"permission denied", status.Error(codes.PermissionDenied, "denied"), http.StatusUnauthorized},
		{"unauthenticated", status.Error(codes.Unauthenticated, "unauthenticated"), http.StatusUnauthorized},
		{"already exists", status.Error(codes.AlreadyExists, "exists"), http.StatusBadRequest},
		{"internal error", status.Error(codes.Internal, "internal"), http.StatusInternalServerError},
		{"non-grpc error", assert.AnError, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			handlers.handleGRPCError(rec, req, tt.err)
			assert.Equal(t, tt.expectedCode, writer.lastStatus)
		})
	}
}

// Additional tests for complete algorithm coverage

func TestAlgorithmConversion_AllAlgorithms(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	algorithms := []struct {
		str string
		alg proto.KeyAlgorithm
	}{
		{"AES-128-GCM", proto.KeyAlgorithm_KEY_ALG_AES_128_GCM},
		{"AES-192-GCM", proto.KeyAlgorithm_KEY_ALG_AES_192_GCM},
		{"AES-256-GCM", proto.KeyAlgorithm_KEY_ALG_AES_256_GCM},
		{"CHACHA20-POLY1305", proto.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305},
		{"XCHACHA20-POLY1305", proto.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305},
		{"RSA-2048", proto.KeyAlgorithm_KEY_ALG_RSA_2048},
		{"RSA-3072", proto.KeyAlgorithm_KEY_ALG_RSA_3072},
		{"RSA-4096", proto.KeyAlgorithm_KEY_ALG_RSA_4096},
		{"ECDSA-P256", proto.KeyAlgorithm_KEY_ALG_ECDSA_P256},
		{"ECDSA-P384", proto.KeyAlgorithm_KEY_ALG_ECDSA_P384},
		{"ECDSA-P521", proto.KeyAlgorithm_KEY_ALG_ECDSA_P521},
		{"ED25519", proto.KeyAlgorithm_KEY_ALG_ED25519},
		{"ED448", proto.KeyAlgorithm_KEY_ALG_ED448},
		{"X25519", proto.KeyAlgorithm_KEY_ALG_X25519},
		{"X448", proto.KeyAlgorithm_KEY_ALG_X448},
		{"HMAC-SHA256", proto.KeyAlgorithm_KEY_ALG_HMAC_SHA256},
		{"HMAC-SHA384", proto.KeyAlgorithm_KEY_ALG_HMAC_SHA384},
		{"HMAC-SHA512", proto.KeyAlgorithm_KEY_ALG_HMAC_SHA512},
	}

	for _, tt := range algorithms {
		t.Run(tt.str, func(t *testing.T) {
			alg := handlers.stringToKeyAlgorithm(tt.str)
			assert.Equal(t, tt.alg, alg)
			str := handlers.keyAlgorithmToString(tt.alg)
			assert.Equal(t, tt.str, str)
		})
	}

	// Test unspecified
	assert.Equal(t, proto.KeyAlgorithm_KEY_ALG_UNSPECIFIED, handlers.stringToKeyAlgorithm("INVALID"))
	assert.Equal(t, "UNSPECIFIED", handlers.keyAlgorithmToString(proto.KeyAlgorithm_KEY_ALG_UNSPECIFIED))
}

func TestStatusConversion_AllStatuses(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	statuses := []struct {
		str    string
		status proto.KeyStatus
	}{
		{"ENABLED", proto.KeyStatus_KEY_STATUS_ENABLED},
		{"DISABLED", proto.KeyStatus_KEY_STATUS_DISABLED},
		{"PENDING_DELETION", proto.KeyStatus_KEY_STATUS_PENDING_DELETION},
		{"DELETED", proto.KeyStatus_KEY_STATUS_DELETED},
		{"ROTATING", proto.KeyStatus_KEY_STATUS_ROTATING},
		{"COMPROMISED", proto.KeyStatus_KEY_STATUS_COMPROMISED},
	}

	for _, tt := range statuses {
		t.Run(tt.str, func(t *testing.T) {
			status := handlers.stringToKeyStatus(tt.str)
			assert.Equal(t, tt.status, status)
			str := handlers.keyStatusToString(tt.status)
			assert.Equal(t, tt.str, str)
		})
	}

	assert.Equal(t, proto.KeyStatus_KEY_STATUS_UNSPECIFIED, handlers.stringToKeyStatus("INVALID"))
	assert.Equal(t, "UNSPECIFIED", handlers.keyStatusToString(proto.KeyStatus_KEY_STATUS_UNSPECIFIED))
}

func TestUsageConversion_AllUsages(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	usages := []struct {
		str   string
		usage proto.KeyUsage
	}{
		{"ENCRYPT", proto.KeyUsage_KEY_USAGE_ENCRYPT},
		{"DECRYPT", proto.KeyUsage_KEY_USAGE_DECRYPT},
		{"SIGN", proto.KeyUsage_KEY_USAGE_SIGN},
		{"VERIFY", proto.KeyUsage_KEY_USAGE_VERIFY},
		{"WRAP_KEY", proto.KeyUsage_KEY_USAGE_WRAP_KEY},
		{"DERIVE_KEY", proto.KeyUsage_KEY_USAGE_DERIVE_KEY},
		{"GENERATE_MAC", proto.KeyUsage_KEY_USAGE_GENERATE_MAC},
		{"VERIFY_MAC", proto.KeyUsage_KEY_USAGE_VERIFY_MAC},
	}

	for _, tt := range usages {
		t.Run(tt.str, func(t *testing.T) {
			usage := handlers.stringToKeyUsage(tt.str)
			assert.Equal(t, tt.usage, usage)
			str := handlers.keyUsageToString(tt.usage)
			assert.Equal(t, tt.str, str)
		})
	}

	assert.Equal(t, proto.KeyUsage_KEY_USAGE_UNSPECIFIED, handlers.stringToKeyUsage("INVALID"))
	assert.Equal(t, "UNSPECIFIED", handlers.keyUsageToString(proto.KeyUsage_KEY_USAGE_UNSPECIFIED))
}

func TestKeyUsageSliceConversion(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	// Test empty slices
	result := handlers.stringsToKeyUsage([]string{})
	assert.Empty(t, result)

	result2 := handlers.keyUsageToStrings([]proto.KeyUsage{})
	assert.Empty(t, result2)

	// Test with data
	strs := []string{"ENCRYPT", "DECRYPT", "SIGN"}
	usages := handlers.stringsToKeyUsage(strs)
	assert.Len(t, usages, 3)

	converted := handlers.keyUsageToStrings(usages)
	assert.Equal(t, strs, converted)
}

// Tests for nil response handling

func TestKeyHandleToResponse_Nil(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})
	result := handlers.keyHandleToResponse(nil)
	assert.Nil(t, result)
}

func TestRotationPolicyToResponse_Nil(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})
	result := handlers.rotationPolicyToResponse(nil)
	assert.Nil(t, result)
}

func TestDEKMetadataToResponse_Nil(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})
	result := handlers.dekMetadataToResponse(nil)
	assert.Nil(t, result)
}

func TestReencryptionProgressToResponse_Nil(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})
	result := handlers.reencryptionProgressToResponse(nil)
	assert.Nil(t, result)
}

// Additional handler tests for error paths

func TestImportKey_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	body := ImportKeyRequest{KeyMaterial: []byte("key"), Name: "test"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys/import", body, nil)
	rec := httptest.NewRecorder()

	handlers.ImportKey(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestImportKey_InvalidBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/import", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.ImportKey(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestImportKey_MissingName(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := ImportKeyRequest{KeyMaterial: []byte("key")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys/import", body, nil)
	rec := httptest.NewRecorder()

	handlers.ImportKey(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestImportKey_GRPCError(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		importKeyFn: func(ctx context.Context, req *proto.ImportKeyRequest, opts ...grpc.CallOption) (*proto.ImportKeyResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "key exists")
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := ImportKeyRequest{KeyMaterial: []byte("key"), Name: "test"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys/import", body, nil)
	rec := httptest.NewRecorder()

	handlers.ImportKey(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListKeys_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/keys", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListKeys(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestListKeys_GRPCError(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		listKeysFn: func(ctx context.Context, req *proto.ListKeysRequest, opts ...grpc.CallOption) (*proto.ListKeysResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/keys", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListKeys(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestListKeys_EmptyList(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		listKeysFn: func(ctx context.Context, req *proto.ListKeysRequest, opts ...grpc.CallOption) (*proto.ListKeysResponse, error) {
			return &proto.ListKeysResponse{
				Keys:       []*proto.KeyHandle{},
				TotalCount: 0,
				HasMore:    false,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/keys", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListKeys(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListKeysResponse)
	require.True(t, ok)
	assert.Empty(t, payload.Keys)
	assert.Equal(t, int32(0), payload.TotalCount)
	assert.False(t, payload.HasMore)
}

func TestListKeys_WithPagination(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		listKeysFn: func(ctx context.Context, req *proto.ListKeysRequest, opts ...grpc.CallOption) (*proto.ListKeysResponse, error) {
			// Verify pagination parameters were passed correctly
			assert.Equal(t, int32(10), req.Limit)
			assert.Equal(t, "cursor123", req.Cursor)

			return &proto.ListKeysResponse{
				Keys: []*proto.KeyHandle{
					{KeyId: "key-11", Version: 1, Algorithm: proto.KeyAlgorithm_KEY_ALG_AES_256_GCM},
					{KeyId: "key-12", Version: 1, Algorithm: proto.KeyAlgorithm_KEY_ALG_RSA_2048},
				},
				NextCursor: "cursor456",
				TotalCount: 25,
				HasMore:    true,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys?limit=10&cursor=cursor123", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.ListKeys(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListKeysResponse)
	require.True(t, ok)
	assert.Len(t, payload.Keys, 2)
	assert.Equal(t, "cursor456", payload.NextCursor)
	assert.Equal(t, int32(25), payload.TotalCount)
	assert.True(t, payload.HasMore)
	assert.Equal(t, "key-11", payload.Keys[0].KeyID)
	assert.Equal(t, "key-12", payload.Keys[1].KeyID)
}

func TestGetKey_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/keys/test", nil, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.GetKey(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestRotateKey_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys/test/rotate", nil, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.RotateKey(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestRotateKey_MissingName(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys//rotate", nil, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.RotateKey(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRotateKey_InvalidBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys/test/rotate", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"name": "test"})
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = 7 // Set content length to trigger body parsing
	rec := httptest.NewRecorder()

	handlers.RotateKey(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRotateKey_GRPCError(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		rotateKeyFn: func(ctx context.Context, req *proto.RotateKeyRequest, opts ...grpc.CallOption) (*proto.RotateKeyResponse, error) {
			return nil, status.Error(codes.NotFound, "key not found")
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys/test/rotate", nil, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.RotateKey(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDeleteKey_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/kms/keys/test", nil, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.DeleteKey(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestDeleteKey_MissingName(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/kms/keys/", nil, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.DeleteKey(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteKey_GRPCError(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		deleteKeyFn: func(ctx context.Context, req *proto.DeleteKeyRequest, opts ...grpc.CallOption) (*proto.DeleteKeyResponse, error) {
			return nil, status.Error(codes.NotFound, "key not found")
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/kms/keys/test", nil, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.DeleteKey(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDeleteKey_WithQueryParams(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		deleteKeyFn: func(ctx context.Context, req *proto.DeleteKeyRequest, opts ...grpc.CallOption) (*proto.DeleteKeyResponse, error) {
			assert.Equal(t, int32(7), req.PendingWindowDays)
			assert.True(t, req.Force)
			return &proto.DeleteKeyResponse{KeyId: req.KeyId}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/kms/keys/test?pending_window_days=7&force=true", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.DeleteKey(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestUpdateKeyStatus_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	body := UpdateKeyStatusRequest{Status: "DISABLED"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/kms/keys/test/status", body, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.UpdateKeyStatus(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestUpdateKeyStatus_MissingName(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := UpdateKeyStatusRequest{Status: "DISABLED"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/kms/keys//status", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.UpdateKeyStatus(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateKeyStatus_InvalidBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/kms/keys/test/status", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"name": "test"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.UpdateKeyStatus(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateKeyStatus_GRPCError(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		updateKeyStatusFn: func(ctx context.Context, req *proto.UpdateKeyStatusRequest, opts ...grpc.CallOption) (*proto.UpdateKeyStatusResponse, error) {
			return nil, status.Error(codes.NotFound, "key not found")
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := UpdateKeyStatusRequest{Status: "DISABLED"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/kms/keys/test/status", body, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.UpdateKeyStatus(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestListKeyVersions_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/keys/test/versions", nil, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.ListKeyVersions(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestListKeyVersions_MissingName(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/keys//versions", nil, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.ListKeyVersions(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListKeyVersions_GRPCError(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		listKeyVersionsFn: func(ctx context.Context, req *proto.ListKeyVersionsRequest, opts ...grpc.CallOption) (*proto.ListKeyVersionsResponse, error) {
			return nil, status.Error(codes.NotFound, "key not found")
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/keys/test/versions", nil, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.ListKeyVersions(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestBackendStatus_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/backend/status", nil, nil)
	rec := httptest.NewRecorder()

	handlers.BackendStatus(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestBackendStatus_GRPCError(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		backendStatusFn: func(ctx context.Context, req *proto.BackendStatusRequest, opts ...grpc.CallOption) (*proto.BackendStatusResponse, error) {
			return nil, status.Error(codes.Unavailable, "backend unavailable")
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/backend/status", nil, nil)
	rec := httptest.NewRecorder()

	handlers.BackendStatus(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestBackendTest_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/backend/test", nil, nil)
	rec := httptest.NewRecorder()

	handlers.BackendTest(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestBackendTest_GRPCError(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		backendTestFn: func(ctx context.Context, req *proto.BackendTestRequest, opts ...grpc.CallOption) (*proto.BackendTestResponse, error) {
			return nil, status.Error(codes.Internal, "test failed")
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/backend/test", nil, nil)
	rec := httptest.NewRecorder()

	handlers.BackendTest(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestEncrypt_MissingName(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := EncryptRequest{Plaintext: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/encrypt/", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.Encrypt(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestEncrypt_InvalidBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/encrypt/key", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"name": "key"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.Encrypt(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestEncrypt_GRPCError(t *testing.T) {
	crypto := &mockCryptoClient{
		encryptFn: func(ctx context.Context, req *proto.CryptoEncryptRequest, opts ...grpc.CallOption) (*proto.CryptoEncryptResponse, error) {
			return nil, status.Error(codes.NotFound, "key not found")
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := EncryptRequest{Plaintext: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/encrypt/key", body, map[string]string{"name": "key"})
	rec := httptest.NewRecorder()

	handlers.Encrypt(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDecrypt_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, &mockKeyManagementClient{}, nil, nil, nil, writer)

	body := DecryptRequest{Ciphertext: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/decrypt/key", body, map[string]string{"name": "key"})
	rec := httptest.NewRecorder()

	handlers.Decrypt(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestDecrypt_MissingName(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := DecryptRequest{Ciphertext: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/decrypt/", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.Decrypt(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDecrypt_InvalidBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/decrypt/key", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"name": "key"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.Decrypt(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDecrypt_GRPCError(t *testing.T) {
	crypto := &mockCryptoClient{
		decryptFn: func(ctx context.Context, req *proto.CryptoDecryptRequest, opts ...grpc.CallOption) (*proto.CryptoDecryptResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "invalid ciphertext")
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := DecryptRequest{Ciphertext: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/decrypt/key", body, map[string]string{"name": "key"})
	rec := httptest.NewRecorder()

	handlers.Decrypt(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestCreateDEK_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	body := CreateDEKRequest{Path: "/tenant/app"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/deks", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateDEK(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestCreateDEK_InvalidBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/deks", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.CreateDEK(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestCreateDEK_GRPCError(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		createDEKFn: func(ctx context.Context, req *proto.CreateDEKRequest, opts ...grpc.CallOption) (*proto.CreateDEKResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "DEK exists")
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	body := CreateDEKRequest{Path: "/tenant/app"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/deks", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateDEK(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListDEKs_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/deks", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListDEKs(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestListDEKs_GRPCError(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		listDEKsFn: func(ctx context.Context, req *proto.ListDEKsRequest, opts ...grpc.CallOption) (*proto.ListDEKsResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/deks", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListDEKs(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestListDEKs_WithQueryParams(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		listDEKsFn: func(ctx context.Context, req *proto.ListDEKsRequest, opts ...grpc.CallOption) (*proto.ListDEKsResponse, error) {
			assert.Equal(t, "tenant", req.Prefix)
			assert.True(t, req.Recursive)
			return &proto.ListDEKsResponse{Deks: []*proto.DEKMetadata{}}, nil
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/deks?prefix=tenant&recursive=true", nil)
	rec := httptest.NewRecorder()

	handlers.ListDEKs(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestGetDEK_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/deks/path", nil, map[string]string{"path": "path"})
	rec := httptest.NewRecorder()

	handlers.GetDEK(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGetDEK_GRPCError(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		getDEKFn: func(ctx context.Context, req *proto.GetDEKRequest, opts ...grpc.CallOption) (*proto.GetDEKResponse, error) {
			return nil, status.Error(codes.NotFound, "DEK not found")
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/deks/path", nil, map[string]string{"path": "path"})
	rec := httptest.NewRecorder()

	handlers.GetDEK(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestRotateDEK_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/deks/path/rotate", nil, map[string]string{"path": "path"})
	rec := httptest.NewRecorder()

	handlers.RotateDEK(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestRotateDEK_MissingPath(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/deks//rotate", nil, map[string]string{"path": ""})
	rec := httptest.NewRecorder()

	handlers.RotateDEK(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRotateDEK_InvalidBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/deks/path/rotate", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"path": "path"})
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = 7
	rec := httptest.NewRecorder()

	handlers.RotateDEK(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRotateDEK_GRPCError(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		rotateDEKFn: func(ctx context.Context, req *proto.RotateDEKRequest, opts ...grpc.CallOption) (*proto.RotateDEKResponse, error) {
			return nil, status.Error(codes.NotFound, "DEK not found")
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/deks/path/rotate", nil, map[string]string{"path": "path"})
	rec := httptest.NewRecorder()

	handlers.RotateDEK(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDeleteDEK_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/kms/deks/path", nil, map[string]string{"path": "path"})
	rec := httptest.NewRecorder()

	handlers.DeleteDEK(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestDeleteDEK_MissingPath(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/kms/deks/", nil, map[string]string{"path": ""})
	rec := httptest.NewRecorder()

	handlers.DeleteDEK(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteDEK_GRPCError(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		deleteDEKFn: func(ctx context.Context, req *proto.DeleteDEKRequest, opts ...grpc.CallOption) (*proto.DeleteDEKResponse, error) {
			return nil, status.Error(codes.FailedPrecondition, "DEK in use")
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/kms/deks/path", nil, map[string]string{"path": "path"})
	rec := httptest.NewRecorder()

	handlers.DeleteDEK(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestDeleteDEK_WithQueryParams(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		deleteDEKFn: func(ctx context.Context, req *proto.DeleteDEKRequest, opts ...grpc.CallOption) (*proto.DeleteDEKResponse, error) {
			assert.True(t, req.Force)
			assert.Equal(t, "new/path", req.MigrateTo)
			return &proto.DeleteDEKResponse{Path: req.Path, Deleted: true}, nil
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/kms/deks/path?force=true&migrate_to=new/path", nil)
	req = mux.SetURLVars(req, map[string]string{"path": "path"})
	rec := httptest.NewRecorder()

	handlers.DeleteDEK(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestGetDEKStatus_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/deks/path/status", nil, map[string]string{"path": "path"})
	rec := httptest.NewRecorder()

	handlers.GetDEKStatus(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGetDEKStatus_MissingPath(t *testing.T) {
	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/deks//status", nil, map[string]string{"path": ""})
	rec := httptest.NewRecorder()

	handlers.GetDEKStatus(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetDEKStatus_GRPCError(t *testing.T) {
	dekMgmt := &mockDEKManagementClient{
		getDEKStatusFn: func(ctx context.Context, req *proto.GetDEKStatusRequest, opts ...grpc.CallOption) (*proto.GetDEKStatusResponse, error) {
			return nil, status.Error(codes.NotFound, "DEK not found")
		},
	}

	handlers, writer := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, dekMgmt)

	req := createRequestWithVars(http.MethodGet, "/api/v1/kms/deks/path/status", nil, map[string]string{"path": "path"})
	rec := httptest.NewRecorder()

	handlers.GetDEKStatus(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestGetKey_WithVersion(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		getKeyFn: func(ctx context.Context, req *proto.GetKeyRequest, opts ...grpc.CallOption) (*proto.GetKeyResponse, error) {
			assert.Equal(t, uint64(2), req.Version)
			return &proto.GetKeyResponse{
				Key: &proto.KeyHandle{KeyId: req.KeyId, Version: req.Version},
			}, nil
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/test?version=2", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.GetKey(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestGenerateKey_GRPCError(t *testing.T) {
	keyMgmt := &mockKeyManagementClient{
		generateKeyFn: func(ctx context.Context, req *proto.GenerateKeyRequest, opts ...grpc.CallOption) (*proto.GenerateKeyResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "invalid key spec")
		},
	}

	handlers, writer := newTestHandlers(keyMgmt, &mockCryptoClient{}, &mockDEKManagementClient{})

	body := GenerateKeyRequest{Name: "test", KeySpec: KeySpecRequest{Algorithm: "INVALID"}}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/keys", body, nil)
	rec := httptest.NewRecorder()

	handlers.GenerateKey(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

// =============================================================================
// Tests for Helper Functions
// =============================================================================

func TestGetSecretName(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	t.Run("extracts secret name from URL", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets/my-secret", nil)
		req = mux.SetURLVars(req, map[string]string{"name": "my-secret"})

		name := handlers.getSecretName(req)
		assert.Equal(t, "my-secret", name)
	})

	t.Run("returns empty string when name not set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets/", nil)
		req = mux.SetURLVars(req, map[string]string{})

		name := handlers.getSecretName(req)
		assert.Equal(t, "", name)
	})

	t.Run("handles complex secret name", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets/prod-db-password-v2", nil)
		req = mux.SetURLVars(req, map[string]string{"name": "prod-db-password-v2"})

		name := handlers.getSecretName(req)
		assert.Equal(t, "prod-db-password-v2", name)
	})
}

func TestGetVersion(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	t.Run("extracts version from URL", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets/my-secret/versions/5", nil)
		req = mux.SetURLVars(req, map[string]string{"name": "my-secret", "version": "5"})

		version := handlers.getVersion(req)
		assert.Equal(t, "5", version)
	})

	t.Run("returns empty string when version not set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets/my-secret/versions/", nil)
		req = mux.SetURLVars(req, map[string]string{"name": "my-secret"})

		version := handlers.getVersion(req)
		assert.Equal(t, "", version)
	})

	t.Run("handles zero version", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets/my-secret/versions/0", nil)
		req = mux.SetURLVars(req, map[string]string{"name": "my-secret", "version": "0"})

		version := handlers.getVersion(req)
		assert.Equal(t, "0", version)
	})
}

func TestHashAlgorithmConversion(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	// Table-driven tests for all hash algorithms
	hashAlgorithms := []struct {
		strValue  string
		protoEnum proto.HashAlgorithm
	}{
		{"SHA256", proto.HashAlgorithm_HASH_ALG_SHA256},
		{"SHA-256", proto.HashAlgorithm_HASH_ALG_SHA256},
		{"SHA384", proto.HashAlgorithm_HASH_ALG_SHA384},
		{"SHA-384", proto.HashAlgorithm_HASH_ALG_SHA384},
		{"SHA512", proto.HashAlgorithm_HASH_ALG_SHA512},
		{"SHA-512", proto.HashAlgorithm_HASH_ALG_SHA512},
		{"SHA3-256", proto.HashAlgorithm_HASH_ALG_SHA3_256},
		{"SHA3-384", proto.HashAlgorithm_HASH_ALG_SHA3_384},
		{"SHA3-512", proto.HashAlgorithm_HASH_ALG_SHA3_512},
		{"BLAKE2B-256", proto.HashAlgorithm_HASH_ALG_BLAKE2B_256},
		{"BLAKE2B-512", proto.HashAlgorithm_HASH_ALG_BLAKE2B_512},
	}

	t.Run("stringToHashAlgorithm", func(t *testing.T) {
		for _, tt := range hashAlgorithms {
			t.Run(tt.strValue, func(t *testing.T) {
				result := handlers.stringToHashAlgorithm(tt.strValue)
				assert.Equal(t, tt.protoEnum, result)
			})
		}

		// Test unspecified/unknown case
		t.Run("returns UNSPECIFIED for unknown algorithm", func(t *testing.T) {
			result := handlers.stringToHashAlgorithm("INVALID")
			assert.Equal(t, proto.HashAlgorithm_HASH_ALG_UNSPECIFIED, result)
		})

		t.Run("returns UNSPECIFIED for empty string", func(t *testing.T) {
			result := handlers.stringToHashAlgorithm("")
			assert.Equal(t, proto.HashAlgorithm_HASH_ALG_UNSPECIFIED, result)
		})
	})

	t.Run("hashAlgorithmToString", func(t *testing.T) {
		// Test all algorithms return their expected string representation
		expectedStrings := map[proto.HashAlgorithm]string{
			proto.HashAlgorithm_HASH_ALG_SHA256:      "SHA256",
			proto.HashAlgorithm_HASH_ALG_SHA384:      "SHA384",
			proto.HashAlgorithm_HASH_ALG_SHA512:      "SHA512",
			proto.HashAlgorithm_HASH_ALG_SHA3_256:    "SHA3-256",
			proto.HashAlgorithm_HASH_ALG_SHA3_384:    "SHA3-384",
			proto.HashAlgorithm_HASH_ALG_SHA3_512:    "SHA3-512",
			proto.HashAlgorithm_HASH_ALG_BLAKE2B_256: "BLAKE2B-256",
			proto.HashAlgorithm_HASH_ALG_BLAKE2B_512: "BLAKE2B-512",
		}

		for protoEnum, expectedStr := range expectedStrings {
			t.Run(expectedStr, func(t *testing.T) {
				result := handlers.hashAlgorithmToString(protoEnum)
				assert.Equal(t, expectedStr, result)
			})
		}

		t.Run("returns UNSPECIFIED for unknown enum value", func(t *testing.T) {
			result := handlers.hashAlgorithmToString(proto.HashAlgorithm_HASH_ALG_UNSPECIFIED)
			assert.Equal(t, "UNSPECIFIED", result)
		})
	})

	t.Run("round-trip conversion", func(t *testing.T) {
		// Test that conversion from proto to string and back works
		testCases := []proto.HashAlgorithm{
			proto.HashAlgorithm_HASH_ALG_SHA256,
			proto.HashAlgorithm_HASH_ALG_SHA384,
			proto.HashAlgorithm_HASH_ALG_SHA512,
			proto.HashAlgorithm_HASH_ALG_SHA3_256,
			proto.HashAlgorithm_HASH_ALG_BLAKE2B_256,
		}

		for _, alg := range testCases {
			str := handlers.hashAlgorithmToString(alg)
			roundTrip := handlers.stringToHashAlgorithm(str)
			assert.Equal(t, alg, roundTrip, "round-trip failed for %v", alg)
		}
	})
}

func TestSecretStatusConversion_Handlers(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	// Table-driven tests for all secret statuses
	secretStatuses := []struct {
		strValue  string
		protoEnum proto.SecretStatus
	}{
		{"ENABLED", proto.SecretStatus_SECRET_STATUS_ENABLED},
		{"DISABLED", proto.SecretStatus_SECRET_STATUS_DISABLED},
		{"DELETED", proto.SecretStatus_SECRET_STATUS_DELETED},
	}

	t.Run("stringToSecretStatus", func(t *testing.T) {
		for _, tt := range secretStatuses {
			t.Run(tt.strValue, func(t *testing.T) {
				result := handlers.stringToSecretStatus(tt.strValue)
				assert.Equal(t, tt.protoEnum, result)
			})
		}

		t.Run("returns UNSPECIFIED for unknown status", func(t *testing.T) {
			result := handlers.stringToSecretStatus("INVALID")
			assert.Equal(t, proto.SecretStatus_SECRET_STATUS_UNSPECIFIED, result)
		})

		t.Run("returns UNSPECIFIED for empty string", func(t *testing.T) {
			result := handlers.stringToSecretStatus("")
			assert.Equal(t, proto.SecretStatus_SECRET_STATUS_UNSPECIFIED, result)
		})

		t.Run("is case sensitive", func(t *testing.T) {
			result := handlers.stringToSecretStatus("enabled")
			assert.Equal(t, proto.SecretStatus_SECRET_STATUS_UNSPECIFIED, result)
		})
	})

	t.Run("secretStatusToString", func(t *testing.T) {
		for _, tt := range secretStatuses {
			t.Run(tt.strValue, func(t *testing.T) {
				result := handlers.secretStatusToString(tt.protoEnum)
				assert.Equal(t, tt.strValue, result)
			})
		}

		t.Run("returns UNSPECIFIED for unknown enum value", func(t *testing.T) {
			result := handlers.secretStatusToString(proto.SecretStatus_SECRET_STATUS_UNSPECIFIED)
			assert.Equal(t, "UNSPECIFIED", result)
		})
	})

	t.Run("round-trip conversion", func(t *testing.T) {
		testCases := []proto.SecretStatus{
			proto.SecretStatus_SECRET_STATUS_ENABLED,
			proto.SecretStatus_SECRET_STATUS_DISABLED,
			proto.SecretStatus_SECRET_STATUS_DELETED,
		}

		for _, status := range testCases {
			str := handlers.secretStatusToString(status)
			roundTrip := handlers.stringToSecretStatus(str)
			assert.Equal(t, status, roundTrip, "round-trip failed for %v", status)
		}
	})
}

func TestPaginationParams_EdgeCases(t *testing.T) {
	handlers, _ := newTestHandlers(&mockKeyManagementClient{}, &mockCryptoClient{}, &mockDEKManagementClient{})

	t.Run("negative limit uses default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys?limit=-10", nil)
		limit, _ := handlers.getPaginationParams(req)
		assert.Equal(t, defaultLimit, limit)
	})

	t.Run("zero limit uses default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys?limit=0", nil)
		limit, _ := handlers.getPaginationParams(req)
		assert.Equal(t, defaultLimit, limit)
	})

	t.Run("limit at max boundary", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys?limit=1000", nil)
		limit, _ := handlers.getPaginationParams(req)
		assert.Equal(t, maxLimit, limit)
	})

	t.Run("limit just below max", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys?limit=999", nil)
		limit, _ := handlers.getPaginationParams(req)
		assert.Equal(t, int32(999), limit)
	})

	t.Run("cursor with special characters", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys?cursor=abc%3D%3D123", nil)
		_, cursor := handlers.getPaginationParams(req)
		assert.Equal(t, "abc==123", cursor)
	})
}
