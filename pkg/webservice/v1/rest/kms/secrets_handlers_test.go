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
)

// mockSecretsManagementClient implements proto.SecretsManagementClient for testing
type mockSecretsManagementClient struct {
	proto.SecretsManagementClient

	storeSecretFn        func(ctx context.Context, req *proto.StoreSecretRequest, opts ...grpc.CallOption) (*proto.StoreSecretResponse, error)
	getSecretFn          func(ctx context.Context, req *proto.GetSecretRequest, opts ...grpc.CallOption) (*proto.GetSecretResponse, error)
	listSecretsFn        func(ctx context.Context, req *proto.ListSecretsRequest, opts ...grpc.CallOption) (*proto.ListSecretsResponse, error)
	deleteSecretFn       func(ctx context.Context, req *proto.DeleteSecretRequest, opts ...grpc.CallOption) (*proto.DeleteSecretResponse, error)
	rotateSecretFn       func(ctx context.Context, req *proto.RotateSecretRequest, opts ...grpc.CallOption) (*proto.RotateSecretResponse, error)
	getSecretVersionFn   func(ctx context.Context, req *proto.GetSecretVersionRequest, opts ...grpc.CallOption) (*proto.GetSecretVersionResponse, error)
	listSecretVersionsFn func(ctx context.Context, req *proto.ListSecretVersionsRequest, opts ...grpc.CallOption) (*proto.ListSecretVersionsResponse, error)
	rollbackSecretFn     func(ctx context.Context, req *proto.RollbackSecretRequest, opts ...grpc.CallOption) (*proto.RollbackSecretResponse, error)
	updateSecretStatusFn func(ctx context.Context, req *proto.UpdateSecretStatusRequest, opts ...grpc.CallOption) (*proto.UpdateSecretStatusResponse, error)
	setRotationPolicyFn  func(ctx context.Context, req *proto.SetRotationPolicyRequest, opts ...grpc.CallOption) (*proto.SetRotationPolicyResponse, error)
	getRotationPolicyFn  func(ctx context.Context, req *proto.GetRotationPolicyRequest, opts ...grpc.CallOption) (*proto.GetRotationPolicyResponse, error)
	getSecretsByPrefixFn func(ctx context.Context, req *proto.GetSecretsByPrefixRequest, opts ...grpc.CallOption) (*proto.GetSecretsByPrefixResponse, error)
}

func (m *mockSecretsManagementClient) StoreSecret(ctx context.Context, req *proto.StoreSecretRequest, opts ...grpc.CallOption) (*proto.StoreSecretResponse, error) {
	if m.storeSecretFn != nil {
		return m.storeSecretFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSecretsManagementClient) GetSecret(ctx context.Context, req *proto.GetSecretRequest, opts ...grpc.CallOption) (*proto.GetSecretResponse, error) {
	if m.getSecretFn != nil {
		return m.getSecretFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSecretsManagementClient) ListSecrets(ctx context.Context, req *proto.ListSecretsRequest, opts ...grpc.CallOption) (*proto.ListSecretsResponse, error) {
	if m.listSecretsFn != nil {
		return m.listSecretsFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSecretsManagementClient) DeleteSecret(ctx context.Context, req *proto.DeleteSecretRequest, opts ...grpc.CallOption) (*proto.DeleteSecretResponse, error) {
	if m.deleteSecretFn != nil {
		return m.deleteSecretFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSecretsManagementClient) RotateSecret(ctx context.Context, req *proto.RotateSecretRequest, opts ...grpc.CallOption) (*proto.RotateSecretResponse, error) {
	if m.rotateSecretFn != nil {
		return m.rotateSecretFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSecretsManagementClient) GetSecretVersion(ctx context.Context, req *proto.GetSecretVersionRequest, opts ...grpc.CallOption) (*proto.GetSecretVersionResponse, error) {
	if m.getSecretVersionFn != nil {
		return m.getSecretVersionFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSecretsManagementClient) ListSecretVersions(ctx context.Context, req *proto.ListSecretVersionsRequest, opts ...grpc.CallOption) (*proto.ListSecretVersionsResponse, error) {
	if m.listSecretVersionsFn != nil {
		return m.listSecretVersionsFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSecretsManagementClient) RollbackSecret(ctx context.Context, req *proto.RollbackSecretRequest, opts ...grpc.CallOption) (*proto.RollbackSecretResponse, error) {
	if m.rollbackSecretFn != nil {
		return m.rollbackSecretFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSecretsManagementClient) UpdateSecretStatus(ctx context.Context, req *proto.UpdateSecretStatusRequest, opts ...grpc.CallOption) (*proto.UpdateSecretStatusResponse, error) {
	if m.updateSecretStatusFn != nil {
		return m.updateSecretStatusFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSecretsManagementClient) SetRotationPolicy(ctx context.Context, req *proto.SetRotationPolicyRequest, opts ...grpc.CallOption) (*proto.SetRotationPolicyResponse, error) {
	if m.setRotationPolicyFn != nil {
		return m.setRotationPolicyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSecretsManagementClient) GetRotationPolicy(ctx context.Context, req *proto.GetRotationPolicyRequest, opts ...grpc.CallOption) (*proto.GetRotationPolicyResponse, error) {
	if m.getRotationPolicyFn != nil {
		return m.getRotationPolicyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSecretsManagementClient) GetSecretsByPrefix(ctx context.Context, req *proto.GetSecretsByPrefixRequest, opts ...grpc.CallOption) (*proto.GetSecretsByPrefixResponse, error) {
	if m.getSecretsByPrefixFn != nil {
		return m.getSecretsByPrefixFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// Helper functions for secrets tests

func newSecretsTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, os.Stdout)
}

func newSecretsTestHandlers(secretsClient *mockSecretsManagementClient) (*KMSHandlers, *mockHttpWriter) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, secretsClient, writer)
	return handlers, writer
}

func createSecretsRequestWithVars(method, path string, body interface{}, vars map[string]string) *http.Request {
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

// =============================================================================
// StoreSecret Tests
// =============================================================================

func TestStoreSecret_Success(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		storeSecretFn: func(ctx context.Context, req *proto.StoreSecretRequest, opts ...grpc.CallOption) (*proto.StoreSecretResponse, error) {
			return &proto.StoreSecretResponse{
				SecretId:  "secret-123",
				Version:   1,
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	body := StoreSecretRequest{
		Name:        "my-secret",
		Description: "Test secret",
		Data:        []byte("secret-value"),
		Tags:        map[string]string{"env": "test"},
	}

	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets", body, nil)
	rec := httptest.NewRecorder()

	handlers.StoreSecret(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(StoreSecretResponse)
	require.True(t, ok)
	assert.Equal(t, "secret-123", payload.SecretID)
	assert.Equal(t, uint64(1), payload.Version)
}

func TestStoreSecret_NilClient(t *testing.T) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	body := StoreSecretRequest{Name: "test", Data: []byte("data")}
	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets", body, nil)
	rec := httptest.NewRecorder()

	handlers.StoreSecret(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	_, ok := writer.lastError.(ErrSecretsManagementClientNotInitialized)
	assert.True(t, ok)
}

func TestStoreSecret_InvalidBody(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/secrets", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.StoreSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestStoreSecret_MissingName(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	body := StoreSecretRequest{
		Data: []byte("secret-value"),
	}

	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets", body, nil)
	rec := httptest.NewRecorder()

	handlers.StoreSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSecretName)
	assert.True(t, ok)
}

func TestStoreSecret_MissingData(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	body := StoreSecretRequest{
		Name: "my-secret",
	}

	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets", body, nil)
	rec := httptest.NewRecorder()

	handlers.StoreSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSecretData)
	assert.True(t, ok)
}

func TestStoreSecret_GRPCError(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		storeSecretFn: func(ctx context.Context, req *proto.StoreSecretRequest, opts ...grpc.CallOption) (*proto.StoreSecretResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "secret already exists")
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	body := StoreSecretRequest{
		Name: "my-secret",
		Data: []byte("secret-value"),
	}

	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets", body, nil)
	rec := httptest.NewRecorder()

	handlers.StoreSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

// =============================================================================
// GetSecret Tests
// =============================================================================

func TestGetSecret_Success(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		getSecretFn: func(ctx context.Context, req *proto.GetSecretRequest, opts ...grpc.CallOption) (*proto.GetSecretResponse, error) {
			return &proto.GetSecretResponse{
				SecretId:  req.SecretId,
				Version:   1,
				Data:      []byte("secret-value"),
				Metadata:  map[string]string{"key": "value"},
				CreatedAt: 1234567890,
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/my-secret", nil, map[string]string{"name": "my-secret"})
	rec := httptest.NewRecorder()

	handlers.GetSecret(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(GetSecretResponse)
	require.True(t, ok)
	assert.Equal(t, "my-secret", payload.SecretID)
	assert.Equal(t, []byte("secret-value"), payload.Data)
}

func TestGetSecret_NilClient(t *testing.T) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/test", nil, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.GetSecret(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGetSecret_MissingName(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/", nil, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.GetSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSecretName)
	assert.True(t, ok)
}

func TestGetSecret_NotFound(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		getSecretFn: func(ctx context.Context, req *proto.GetSecretRequest, opts ...grpc.CallOption) (*proto.GetSecretResponse, error) {
			return nil, status.Error(codes.NotFound, "secret not found")
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/nonexistent", nil, map[string]string{"name": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.GetSecret(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestGetSecret_WithVersion(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		getSecretFn: func(ctx context.Context, req *proto.GetSecretRequest, opts ...grpc.CallOption) (*proto.GetSecretResponse, error) {
			assert.Equal(t, uint64(2), req.Version)
			return &proto.GetSecretResponse{
				SecretId: req.SecretId,
				Version:  req.Version,
				Data:     []byte("secret-v2"),
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets/my-secret?version=2", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "my-secret"})
	rec := httptest.NewRecorder()

	handlers.GetSecret(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

// =============================================================================
// ListSecrets Tests
// =============================================================================

func TestListSecrets_Success(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		listSecretsFn: func(ctx context.Context, req *proto.ListSecretsRequest, opts ...grpc.CallOption) (*proto.ListSecretsResponse, error) {
			return &proto.ListSecretsResponse{
				Secrets: []*proto.Secret{
					{SecretId: "secret-1", Name: "secret-1", CurrentVersion: 1},
					{SecretId: "secret-2", Name: "secret-2", CurrentVersion: 2},
				},
				TotalCount: 2,
				HasMore:    false,
				Timestamp:  1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListSecrets(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListSecretsResponse)
	require.True(t, ok)
	assert.Len(t, payload.Secrets, 2)
	assert.Equal(t, int32(2), payload.TotalCount)
}

func TestListSecrets_NilClient(t *testing.T) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListSecrets(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestListSecrets_GRPCError(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		listSecretsFn: func(ctx context.Context, req *proto.ListSecretsRequest, opts ...grpc.CallOption) (*proto.ListSecretsResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListSecrets(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestListSecrets_WithFilters(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		listSecretsFn: func(ctx context.Context, req *proto.ListSecretsRequest, opts ...grpc.CallOption) (*proto.ListSecretsResponse, error) {
			assert.Equal(t, "test", req.Filter["owner"])
			return &proto.ListSecretsResponse{
				Secrets:   []*proto.Secret{},
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets?owner=test&limit=10", nil)
	rec := httptest.NewRecorder()

	handlers.ListSecrets(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestListSecrets_WithPrefix_CallsGetSecretsByPrefix(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		getSecretsByPrefixFn: func(ctx context.Context, req *proto.GetSecretsByPrefixRequest, opts ...grpc.CallOption) (*proto.GetSecretsByPrefixResponse, error) {
			assert.Equal(t, "app/", req.Prefix)
			return &proto.GetSecretsByPrefixResponse{
				Secrets:   make(map[string]*proto.SecretData),
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets?prefix=app/", nil)
	rec := httptest.NewRecorder()

	handlers.ListSecrets(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

// =============================================================================
// DeleteSecret Tests
// =============================================================================

func TestDeleteSecret_Success(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		deleteSecretFn: func(ctx context.Context, req *proto.DeleteSecretRequest, opts ...grpc.CallOption) (*proto.DeleteSecretResponse, error) {
			return &proto.DeleteSecretResponse{
				SecretId:  req.SecretId,
				Deleted:   true,
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := createSecretsRequestWithVars(http.MethodDelete, "/api/v1/kms/secrets/my-secret", nil, map[string]string{"name": "my-secret"})
	rec := httptest.NewRecorder()

	handlers.DeleteSecret(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(DeleteSecretResponse)
	require.True(t, ok)
	assert.True(t, payload.Deleted)
}

func TestDeleteSecret_NilClient(t *testing.T) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createSecretsRequestWithVars(http.MethodDelete, "/api/v1/kms/secrets/test", nil, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.DeleteSecret(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestDeleteSecret_MissingName(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := createSecretsRequestWithVars(http.MethodDelete, "/api/v1/kms/secrets/", nil, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.DeleteSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSecretName)
	assert.True(t, ok)
}

func TestDeleteSecret_GRPCError(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		deleteSecretFn: func(ctx context.Context, req *proto.DeleteSecretRequest, opts ...grpc.CallOption) (*proto.DeleteSecretResponse, error) {
			return nil, status.Error(codes.NotFound, "secret not found")
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := createSecretsRequestWithVars(http.MethodDelete, "/api/v1/kms/secrets/nonexistent", nil, map[string]string{"name": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.DeleteSecret(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDeleteSecret_WithPermanentlyDelete(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		deleteSecretFn: func(ctx context.Context, req *proto.DeleteSecretRequest, opts ...grpc.CallOption) (*proto.DeleteSecretResponse, error) {
			assert.True(t, req.PermanentlyDelete)
			return &proto.DeleteSecretResponse{
				SecretId: req.SecretId,
				Deleted:  true,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/kms/secrets/my-secret?permanently_delete=true", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "my-secret"})
	rec := httptest.NewRecorder()

	handlers.DeleteSecret(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

// =============================================================================
// RotateSecret Tests
// =============================================================================

func TestRotateSecret_Success(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		rotateSecretFn: func(ctx context.Context, req *proto.RotateSecretRequest, opts ...grpc.CallOption) (*proto.RotateSecretResponse, error) {
			return &proto.RotateSecretResponse{
				SecretId:   req.SecretId,
				OldVersion: 1,
				NewVersion: 2,
				Timestamp:  1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	body := RotateSecretRequest{
		NewData:  []byte("new-secret-value"),
		Metadata: map[string]string{"rotated": "true"},
	}

	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets/my-secret/rotate", body, map[string]string{"name": "my-secret"})
	rec := httptest.NewRecorder()

	handlers.RotateSecret(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(RotateSecretResponse)
	require.True(t, ok)
	assert.Equal(t, uint64(1), payload.OldVersion)
	assert.Equal(t, uint64(2), payload.NewVersion)
}

func TestRotateSecret_NilClient(t *testing.T) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	body := RotateSecretRequest{NewData: []byte("data")}
	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets/test/rotate", body, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.RotateSecret(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestRotateSecret_MissingName(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	body := RotateSecretRequest{NewData: []byte("data")}
	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets//rotate", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.RotateSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSecretName)
	assert.True(t, ok)
}

func TestRotateSecret_InvalidBody(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/secrets/test/rotate", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"name": "test"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.RotateSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRotateSecret_MissingData(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	body := RotateSecretRequest{}
	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets/test/rotate", body, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.RotateSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSecretData)
	assert.True(t, ok)
}

func TestRotateSecret_GRPCError(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		rotateSecretFn: func(ctx context.Context, req *proto.RotateSecretRequest, opts ...grpc.CallOption) (*proto.RotateSecretResponse, error) {
			return nil, status.Error(codes.NotFound, "secret not found")
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	body := RotateSecretRequest{NewData: []byte("data")}
	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets/nonexistent/rotate", body, map[string]string{"name": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.RotateSecret(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// =============================================================================
// GetSecretVersion Tests
// =============================================================================

func TestGetSecretVersion_Success(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		getSecretVersionFn: func(ctx context.Context, req *proto.GetSecretVersionRequest, opts ...grpc.CallOption) (*proto.GetSecretVersionResponse, error) {
			return &proto.GetSecretVersionResponse{
				Version: &proto.SecretVersion{
					SecretId:  req.SecretId,
					Version:   req.Version,
					CreatedAt: 1234567890,
					Metadata:  map[string]string{"key": "value"},
				},
				Data:      []byte("secret-data"),
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/my-secret/versions/1", nil, map[string]string{"name": "my-secret", "version": "1"})
	rec := httptest.NewRecorder()

	handlers.GetSecretVersion(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(GetSecretVersionResponse)
	require.True(t, ok)
	assert.NotNil(t, payload.Version)
	assert.Equal(t, []byte("secret-data"), payload.Data)
}

func TestGetSecretVersion_NilClient(t *testing.T) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/test/versions/1", nil, map[string]string{"name": "test", "version": "1"})
	rec := httptest.NewRecorder()

	handlers.GetSecretVersion(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGetSecretVersion_MissingName(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets//versions/1", nil, map[string]string{"name": "", "version": "1"})
	rec := httptest.NewRecorder()

	handlers.GetSecretVersion(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSecretName)
	assert.True(t, ok)
}

func TestGetSecretVersion_MissingVersion(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/test/versions/", nil, map[string]string{"name": "test", "version": ""})
	rec := httptest.NewRecorder()

	handlers.GetSecretVersion(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidSecretVersion)
	assert.True(t, ok)
}

func TestGetSecretVersion_InvalidVersionFormat(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/test/versions/invalid", nil, map[string]string{"name": "test", "version": "invalid"})
	rec := httptest.NewRecorder()

	handlers.GetSecretVersion(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidSecretVersion)
	assert.True(t, ok)
}

func TestGetSecretVersion_GRPCError(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		getSecretVersionFn: func(ctx context.Context, req *proto.GetSecretVersionRequest, opts ...grpc.CallOption) (*proto.GetSecretVersionResponse, error) {
			return nil, status.Error(codes.NotFound, "version not found")
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/test/versions/99", nil, map[string]string{"name": "test", "version": "99"})
	rec := httptest.NewRecorder()

	handlers.GetSecretVersion(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// =============================================================================
// ListSecretVersions Tests
// =============================================================================

func TestListSecretVersions_Success(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		listSecretVersionsFn: func(ctx context.Context, req *proto.ListSecretVersionsRequest, opts ...grpc.CallOption) (*proto.ListSecretVersionsResponse, error) {
			return &proto.ListSecretVersionsResponse{
				Versions: []*proto.SecretVersion{
					{SecretId: req.SecretId, Version: 1, CreatedAt: 1234567890},
					{SecretId: req.SecretId, Version: 2, CreatedAt: 1234567891},
				},
				HasMore:   false,
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/my-secret/versions", nil, map[string]string{"name": "my-secret"})
	rec := httptest.NewRecorder()

	handlers.ListSecretVersions(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListSecretVersionsResponse)
	require.True(t, ok)
	assert.Len(t, payload.Versions, 2)
}

func TestListSecretVersions_NilClient(t *testing.T) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/test/versions", nil, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.ListSecretVersions(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestListSecretVersions_MissingName(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets//versions", nil, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.ListSecretVersions(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSecretName)
	assert.True(t, ok)
}

func TestListSecretVersions_GRPCError(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		listSecretVersionsFn: func(ctx context.Context, req *proto.ListSecretVersionsRequest, opts ...grpc.CallOption) (*proto.ListSecretVersionsResponse, error) {
			return nil, status.Error(codes.NotFound, "secret not found")
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/nonexistent/versions", nil, map[string]string{"name": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.ListSecretVersions(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// =============================================================================
// RollbackSecret Tests
// =============================================================================

func TestRollbackSecret_Success(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		rollbackSecretFn: func(ctx context.Context, req *proto.RollbackSecretRequest, opts ...grpc.CallOption) (*proto.RollbackSecretResponse, error) {
			return &proto.RollbackSecretResponse{
				SecretId:   req.SecretId,
				NewVersion: 3,
				Timestamp:  1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	body := RollbackSecretRequest{
		TargetVersion: 1,
	}

	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets/my-secret/rollback", body, map[string]string{"name": "my-secret"})
	rec := httptest.NewRecorder()

	handlers.RollbackSecret(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(RollbackSecretResponse)
	require.True(t, ok)
	assert.Equal(t, uint64(3), payload.NewVersion)
}

func TestRollbackSecret_NilClient(t *testing.T) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	body := RollbackSecretRequest{TargetVersion: 1}
	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets/test/rollback", body, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.RollbackSecret(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestRollbackSecret_MissingName(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	body := RollbackSecretRequest{TargetVersion: 1}
	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets//rollback", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.RollbackSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSecretName)
	assert.True(t, ok)
}

func TestRollbackSecret_InvalidBody(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/secrets/test/rollback", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"name": "test"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.RollbackSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRollbackSecret_MissingTargetVersion(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	body := RollbackSecretRequest{}
	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets/test/rollback", body, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.RollbackSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingTargetVersion)
	assert.True(t, ok)
}

func TestRollbackSecret_GRPCError(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		rollbackSecretFn: func(ctx context.Context, req *proto.RollbackSecretRequest, opts ...grpc.CallOption) (*proto.RollbackSecretResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "target version does not exist")
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	body := RollbackSecretRequest{TargetVersion: 99}
	req := createSecretsRequestWithVars(http.MethodPost, "/api/v1/kms/secrets/test/rollback", body, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.RollbackSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

// =============================================================================
// UpdateSecretStatus Tests
// =============================================================================

func TestUpdateSecretStatus_Success(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		updateSecretStatusFn: func(ctx context.Context, req *proto.UpdateSecretStatusRequest, opts ...grpc.CallOption) (*proto.UpdateSecretStatusResponse, error) {
			return &proto.UpdateSecretStatusResponse{
				SecretId:  req.SecretId,
				Status:    req.Status,
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	body := UpdateSecretStatusRequest{
		Status: "DISABLED",
	}

	req := createSecretsRequestWithVars(http.MethodPut, "/api/v1/kms/secrets/my-secret/status", body, map[string]string{"name": "my-secret"})
	rec := httptest.NewRecorder()

	handlers.UpdateSecretStatus(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(UpdateSecretStatusResponse)
	require.True(t, ok)
	assert.Equal(t, "DISABLED", payload.Status)
}

func TestUpdateSecretStatus_NilClient(t *testing.T) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	body := UpdateSecretStatusRequest{Status: "DISABLED"}
	req := createSecretsRequestWithVars(http.MethodPut, "/api/v1/kms/secrets/test/status", body, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.UpdateSecretStatus(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestUpdateSecretStatus_MissingName(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	body := UpdateSecretStatusRequest{Status: "DISABLED"}
	req := createSecretsRequestWithVars(http.MethodPut, "/api/v1/kms/secrets//status", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.UpdateSecretStatus(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSecretName)
	assert.True(t, ok)
}

func TestUpdateSecretStatus_InvalidBody(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/kms/secrets/test/status", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"name": "test"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.UpdateSecretStatus(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateSecretStatus_MissingStatus(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	body := UpdateSecretStatusRequest{}
	req := createSecretsRequestWithVars(http.MethodPut, "/api/v1/kms/secrets/test/status", body, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.UpdateSecretStatus(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidSecretStatus)
	assert.True(t, ok)
}

func TestUpdateSecretStatus_GRPCError(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		updateSecretStatusFn: func(ctx context.Context, req *proto.UpdateSecretStatusRequest, opts ...grpc.CallOption) (*proto.UpdateSecretStatusResponse, error) {
			return nil, status.Error(codes.NotFound, "secret not found")
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	body := UpdateSecretStatusRequest{Status: "DISABLED"}
	req := createSecretsRequestWithVars(http.MethodPut, "/api/v1/kms/secrets/nonexistent/status", body, map[string]string{"name": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.UpdateSecretStatus(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// =============================================================================
// SetRotationPolicy Tests
// =============================================================================

func TestSetRotationPolicy_Success(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		setRotationPolicyFn: func(ctx context.Context, req *proto.SetRotationPolicyRequest, opts ...grpc.CallOption) (*proto.SetRotationPolicyResponse, error) {
			return &proto.SetRotationPolicyResponse{
				SecretId: req.SecretId,
				Policy: &proto.SecretRotationPolicy{
					Enabled:         req.Policy.Enabled,
					IntervalSeconds: req.Policy.IntervalSeconds,
					RetainVersions:  req.Policy.RetainVersions,
				},
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	body := SetSecretRotationPolicyRequest{
		Policy: SecretRotationPolicyRequest{
			Enabled:         true,
			IntervalSeconds: 86400,
			RetainVersions:  5,
		},
	}

	req := createSecretsRequestWithVars(http.MethodPut, "/api/v1/kms/secrets/my-secret/policy", body, map[string]string{"name": "my-secret"})
	rec := httptest.NewRecorder()

	handlers.SetRotationPolicy(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(SetSecretRotationPolicyResponse)
	require.True(t, ok)
	assert.NotNil(t, payload.Policy)
	assert.True(t, payload.Policy.Enabled)
}

func TestSetRotationPolicy_NilClient(t *testing.T) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	body := SetSecretRotationPolicyRequest{Policy: SecretRotationPolicyRequest{Enabled: true}}
	req := createSecretsRequestWithVars(http.MethodPut, "/api/v1/kms/secrets/test/policy", body, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.SetRotationPolicy(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestSetRotationPolicy_MissingName(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	body := SetSecretRotationPolicyRequest{Policy: SecretRotationPolicyRequest{Enabled: true}}
	req := createSecretsRequestWithVars(http.MethodPut, "/api/v1/kms/secrets//policy", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.SetRotationPolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSecretName)
	assert.True(t, ok)
}

func TestSetRotationPolicy_InvalidBody(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/kms/secrets/test/policy", bytes.NewBufferString("invalid"))
	req = mux.SetURLVars(req, map[string]string{"name": "test"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.SetRotationPolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestSetRotationPolicy_GRPCError(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		setRotationPolicyFn: func(ctx context.Context, req *proto.SetRotationPolicyRequest, opts ...grpc.CallOption) (*proto.SetRotationPolicyResponse, error) {
			return nil, status.Error(codes.NotFound, "secret not found")
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	body := SetSecretRotationPolicyRequest{Policy: SecretRotationPolicyRequest{Enabled: true}}
	req := createSecretsRequestWithVars(http.MethodPut, "/api/v1/kms/secrets/nonexistent/policy", body, map[string]string{"name": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.SetRotationPolicy(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// =============================================================================
// GetRotationPolicy Tests
// =============================================================================

func TestGetRotationPolicy_Success(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		getRotationPolicyFn: func(ctx context.Context, req *proto.GetRotationPolicyRequest, opts ...grpc.CallOption) (*proto.GetRotationPolicyResponse, error) {
			return &proto.GetRotationPolicyResponse{
				SecretId: req.SecretId,
				Policy: &proto.SecretRotationPolicy{
					Enabled:         true,
					IntervalSeconds: 86400,
					RetainVersions:  5,
					NextRotation:    1234567890,
				},
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/my-secret/policy", nil, map[string]string{"name": "my-secret"})
	rec := httptest.NewRecorder()

	handlers.GetRotationPolicy(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(GetSecretRotationPolicyResponse)
	require.True(t, ok)
	assert.NotNil(t, payload.Policy)
	assert.True(t, payload.Policy.Enabled)
	assert.Equal(t, int64(86400), payload.Policy.IntervalSeconds)
}

func TestGetRotationPolicy_NilClient(t *testing.T) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/test/policy", nil, map[string]string{"name": "test"})
	rec := httptest.NewRecorder()

	handlers.GetRotationPolicy(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGetRotationPolicy_MissingName(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets//policy", nil, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.GetRotationPolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSecretName)
	assert.True(t, ok)
}

func TestGetRotationPolicy_GRPCError(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		getRotationPolicyFn: func(ctx context.Context, req *proto.GetRotationPolicyRequest, opts ...grpc.CallOption) (*proto.GetRotationPolicyResponse, error) {
			return nil, status.Error(codes.NotFound, "secret not found")
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := createSecretsRequestWithVars(http.MethodGet, "/api/v1/kms/secrets/nonexistent/policy", nil, map[string]string{"name": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.GetRotationPolicy(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// =============================================================================
// GetSecretsByPrefix Tests
// =============================================================================

func TestGetSecretsByPrefix_Success(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		getSecretsByPrefixFn: func(ctx context.Context, req *proto.GetSecretsByPrefixRequest, opts ...grpc.CallOption) (*proto.GetSecretsByPrefixResponse, error) {
			return &proto.GetSecretsByPrefixResponse{
				Secrets: map[string]*proto.SecretData{
					"app/secret1": {
						Data:     map[string][]byte{"key": []byte("value1")},
						Metadata: map[string]string{"env": "prod"},
						Version:  1,
					},
					"app/secret2": {
						Data:     map[string][]byte{"key": []byte("value2")},
						Metadata: map[string]string{"env": "staging"},
						Version:  2,
					},
				},
				TotalCount: 2,
				HasMore:    false,
				Timestamp:  1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets?prefix=app/", nil)
	rec := httptest.NewRecorder()

	handlers.GetSecretsByPrefix(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(GetSecretsByPrefixResponse)
	require.True(t, ok)
	assert.Len(t, payload.Secrets, 2)
	assert.Equal(t, int32(2), payload.TotalCount)
}

func TestGetSecretsByPrefix_NilClient(t *testing.T) {
	logger := newSecretsTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, nil, nil, nil, nil, writer)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets?prefix=app/", nil)
	rec := httptest.NewRecorder()

	handlers.GetSecretsByPrefix(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGetSecretsByPrefix_MissingPrefix(t *testing.T) {
	handlers, writer := newSecretsTestHandlers(&mockSecretsManagementClient{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets?prefix=", nil)
	rec := httptest.NewRecorder()

	handlers.GetSecretsByPrefix(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequest)
	assert.True(t, ok)
}

func TestGetSecretsByPrefix_WithIncludeData(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		getSecretsByPrefixFn: func(ctx context.Context, req *proto.GetSecretsByPrefixRequest, opts ...grpc.CallOption) (*proto.GetSecretsByPrefixResponse, error) {
			assert.True(t, req.IncludeData)
			return &proto.GetSecretsByPrefixResponse{
				Secrets:   make(map[string]*proto.SecretData),
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets?prefix=app/&include_data=true", nil)
	rec := httptest.NewRecorder()

	handlers.GetSecretsByPrefix(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestGetSecretsByPrefix_GRPCError(t *testing.T) {
	secretsClient := &mockSecretsManagementClient{
		getSecretsByPrefixFn: func(ctx context.Context, req *proto.GetSecretsByPrefixRequest, opts ...grpc.CallOption) (*proto.GetSecretsByPrefixResponse, error) {
			return nil, status.Error(codes.PermissionDenied, "access denied")
		},
	}

	handlers, writer := newSecretsTestHandlers(secretsClient)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets?prefix=restricted/", nil)
	rec := httptest.NewRecorder()

	handlers.GetSecretsByPrefix(rec, req)

	assert.Equal(t, http.StatusUnauthorized, writer.lastStatus)
}

// =============================================================================
// Secret Response Conversion Tests
// =============================================================================

func TestSecretRotationPolicyToResponse_Nil(t *testing.T) {
	handlers, _ := newSecretsTestHandlers(&mockSecretsManagementClient{})
	result := handlers.secretRotationPolicyToResponse(nil)
	assert.Nil(t, result)
}

func TestSecretRotationPolicyToResponse_WithData(t *testing.T) {
	handlers, _ := newSecretsTestHandlers(&mockSecretsManagementClient{})

	policy := &proto.SecretRotationPolicy{
		Enabled:         true,
		IntervalSeconds: 86400,
		NextRotation:    1234567890,
		RetainVersions:  5,
		RotationLambda:  "arn:aws:lambda:us-east-1:123456789:function:rotate",
	}

	result := handlers.secretRotationPolicyToResponse(policy)

	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Equal(t, int64(86400), result.IntervalSeconds)
	assert.Equal(t, int64(1234567890), result.NextRotation)
	assert.Equal(t, int32(5), result.RetainVersions)
	assert.Equal(t, "arn:aws:lambda:us-east-1:123456789:function:rotate", result.RotationLambda)
}

func TestSecretToResponse_Nil(t *testing.T) {
	handlers, _ := newSecretsTestHandlers(&mockSecretsManagementClient{})
	result := handlers.secretToResponse(nil)
	assert.Nil(t, result)
}

func TestSecretToResponse_WithData(t *testing.T) {
	handlers, _ := newSecretsTestHandlers(&mockSecretsManagementClient{})

	secret := &proto.Secret{
		SecretId:       "secret-123",
		Name:           "my-secret",
		Description:    "Test secret",
		CurrentVersion: 3,
		CreatedAt:      1234567890,
		UpdatedAt:      1234567900,
		RotationPolicy: &proto.SecretRotationPolicy{
			Enabled: true,
		},
		Tags:  map[string]string{"env": "prod"},
		Owner: "user@example.com",
	}

	result := handlers.secretToResponse(secret)

	require.NotNil(t, result)
	assert.Equal(t, "secret-123", result.SecretID)
	assert.Equal(t, "my-secret", result.Name)
	assert.Equal(t, "Test secret", result.Description)
	assert.Equal(t, uint64(3), result.CurrentVersion)
	assert.Equal(t, int64(1234567890), result.CreatedAt)
	assert.Equal(t, int64(1234567900), result.UpdatedAt)
	assert.NotNil(t, result.RotationPolicy)
	assert.Equal(t, "prod", result.Tags["env"])
	assert.Equal(t, "user@example.com", result.Owner)
}

func TestSecretVersionToResponse_Nil(t *testing.T) {
	handlers, _ := newSecretsTestHandlers(&mockSecretsManagementClient{})
	result := handlers.secretVersionToResponse(nil)
	assert.Nil(t, result)
}

func TestSecretVersionToResponse_WithData(t *testing.T) {
	handlers, _ := newSecretsTestHandlers(&mockSecretsManagementClient{})

	version := &proto.SecretVersion{
		SecretId:  "secret-123",
		Version:   2,
		Metadata:  map[string]string{"rotated": "true"},
		CreatedAt: 1234567890,
		CreatedBy: "user@example.com",
		DeletedAt: 0,
		ExpiresAt: 1234657890,
	}

	result := handlers.secretVersionToResponse(version)

	require.NotNil(t, result)
	assert.Equal(t, "secret-123", result.SecretID)
	assert.Equal(t, uint64(2), result.Version)
	assert.Equal(t, "true", result.Metadata["rotated"])
	assert.Equal(t, int64(1234567890), result.CreatedAt)
	assert.Equal(t, "user@example.com", result.CreatedBy)
	assert.Equal(t, int64(0), result.DeletedAt)
	assert.Equal(t, int64(1234657890), result.ExpiresAt)
}

func TestSecretDataToResponse_Nil(t *testing.T) {
	handlers, _ := newSecretsTestHandlers(&mockSecretsManagementClient{})
	result := handlers.secretDataToResponse(nil)
	assert.Nil(t, result)
}

func TestSecretDataToResponse_WithData(t *testing.T) {
	handlers, _ := newSecretsTestHandlers(&mockSecretsManagementClient{})

	data := &proto.SecretData{
		Data:     map[string][]byte{"key1": []byte("value1"), "key2": []byte("value2")},
		Metadata: map[string]string{"env": "test"},
		Version:  5,
	}

	result := handlers.secretDataToResponse(data)

	require.NotNil(t, result)
	assert.Equal(t, []byte("value1"), result.Data["key1"])
	assert.Equal(t, []byte("value2"), result.Data["key2"])
	assert.Equal(t, "test", result.Metadata["env"])
	assert.Equal(t, int64(5), result.Version)
}

// =============================================================================
// KeyMetadata Response Conversion Tests
// =============================================================================

func TestKeyMetadataToResponse_WithFullData(t *testing.T) {
	handlers, _ := newSecretsTestHandlers(&mockSecretsManagementClient{})

	metadata := &proto.KeyMetadata{
		KeyId:              "key-123",
		Name:               "my-key",
		Description:        "Test key",
		Algorithm:          proto.KeyAlgorithm_KEY_ALG_AES_256_GCM,
		Status:             proto.KeyStatus_KEY_STATUS_ENABLED,
		Usage:              []proto.KeyUsage{proto.KeyUsage_KEY_USAGE_ENCRYPT, proto.KeyUsage_KEY_USAGE_DECRYPT},
		Version:            1,
		Exportable:         false,
		DeletionProtection: true,
		CreatedAt:          1234567890,
		UpdatedAt:          1234567900,
		LastUsedAt:         1234567910,
		RotationPolicy: &proto.RotationPolicy{
			Enabled:         true,
			IntervalSeconds: 86400,
		},
		Tags:  map[string]string{"env": "prod"},
		Owner: "user@example.com",
	}

	result := handlers.keyMetadataToResponse(metadata)

	require.NotNil(t, result)
	assert.Equal(t, "key-123", result.KeyID)
	assert.Equal(t, "my-key", result.Name)
	assert.Equal(t, "Test key", result.Description)
	assert.Equal(t, "AES-256-GCM", result.Algorithm)
	assert.Equal(t, "ENABLED", result.Status)
	assert.Len(t, result.Usage, 2)
	assert.Equal(t, uint64(1), result.Version)
	assert.False(t, result.Exportable)
	assert.True(t, result.DeletionProtection)
	assert.NotNil(t, result.RotationPolicy)
	assert.Equal(t, "prod", result.Tags["env"])
	assert.Equal(t, "user@example.com", result.Owner)
}
