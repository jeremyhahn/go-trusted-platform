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

package eab

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHandler_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	mockService := &mockEABService{}
	mockDelivery := &mockDeliveryService{}

	h, err := NewHandler(HandlerParams{
		Logger:         logger,
		EABService:     mockService,
		Delivery:       mockDelivery,
		ResponseWriter: respWriter,
	})

	require.NoError(t, err)
	assert.NotNil(t, h)
}

func TestNewHandler_MissingLogger(t *testing.T) {
	respWriter := response.NewResponseWriter(logging.DefaultLogger(), nil)
	mockService := &mockEABService{}
	mockDelivery := &mockDeliveryService{}

	h, err := NewHandler(HandlerParams{
		Logger:         nil,
		EABService:     mockService,
		Delivery:       mockDelivery,
		ResponseWriter: respWriter,
	})

	require.Error(t, err)
	assert.Nil(t, h)
	var svcErr ErrServiceError
	assert.ErrorAs(t, err, &svcErr)
	assert.Equal(t, "NewHandler", svcErr.Operation)
}

func TestNewHandler_MissingEABService(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	mockDelivery := &mockDeliveryService{}

	h, err := NewHandler(HandlerParams{
		Logger:         logger,
		EABService:     nil,
		Delivery:       mockDelivery,
		ResponseWriter: respWriter,
	})

	require.Error(t, err)
	assert.Nil(t, h)
}

func TestNewHandler_MissingResponseWriter(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := &mockEABService{}
	mockDelivery := &mockDeliveryService{}

	h, err := NewHandler(HandlerParams{
		Logger:         logger,
		EABService:     mockService,
		Delivery:       mockDelivery,
		ResponseWriter: nil,
	})

	require.Error(t, err)
	assert.Nil(t, h)
}

func TestNewHandler_MissingDelivery(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	mockService := &mockEABService{}

	h, err := NewHandler(HandlerParams{
		Logger:         logger,
		EABService:     mockService,
		Delivery:       nil,
		ResponseWriter: respWriter,
	})

	require.Error(t, err)
	assert.Nil(t, h)
}

func TestToCredentialResponse(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	hmacKey := []byte("test-hmac-key-data-here-32bytes!")

	cred := &eab.Credential{
		ID:        1,
		KeyID:     "key-123",
		HMACKey:   hmacKey,
		ProfileID: 42,
		TenantID:  "tenant-abc",
		Status:    eab.StatusActive,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		UsedAt:    time.Time{},
	}

	t.Run("with HMAC key", func(t *testing.T) {
		resp := ToCredentialResponse(cred, true)
		assert.Equal(t, uint64(1), resp.ID)
		assert.Equal(t, "key-123", resp.KeyID)
		assert.Equal(t, base64.RawURLEncoding.EncodeToString(hmacKey), resp.HMACKey)
		assert.Equal(t, uint64(42), resp.ProfileID)
		assert.Equal(t, "tenant-abc", resp.TenantID)
		assert.Equal(t, "active", resp.Status)
		assert.NotEmpty(t, resp.CreatedAt)
		assert.NotEmpty(t, resp.ExpiresAt)
		assert.Empty(t, resp.UsedAt)
	})

	t.Run("without HMAC key", func(t *testing.T) {
		resp := ToCredentialResponse(cred, false)
		assert.Empty(t, resp.HMACKey)
		assert.Equal(t, "key-123", resp.KeyID)
	})

	t.Run("with used at time", func(t *testing.T) {
		usedCred := *cred
		usedCred.UsedAt = now
		resp := ToCredentialResponse(&usedCred, false)
		assert.NotEmpty(t, resp.UsedAt)
	})

	t.Run("without expiry", func(t *testing.T) {
		noExpCred := *cred
		noExpCred.ExpiresAt = time.Time{}
		resp := ToCredentialResponse(&noExpCred, false)
		assert.Empty(t, resp.ExpiresAt)
	})
}

func TestToCredentialListResponse(t *testing.T) {
	t.Run("with credentials", func(t *testing.T) {
		creds := []*eab.Credential{
			{ID: 1, KeyID: "key-1", Status: eab.StatusActive, CreatedAt: time.Now()},
			{ID: 2, KeyID: "key-2", Status: eab.StatusRevoked, CreatedAt: time.Now()},
		}
		resp := ToCredentialListResponse(creds)
		assert.Equal(t, 2, resp.Total)
		assert.Len(t, resp.Credentials, 2)
		assert.Equal(t, "key-1", resp.Credentials[0].KeyID)
		assert.Equal(t, "key-2", resp.Credentials[1].KeyID)
	})

	t.Run("with empty list", func(t *testing.T) {
		resp := ToCredentialListResponse([]*eab.Credential{})
		assert.Equal(t, 0, resp.Total)
		assert.Len(t, resp.Credentials, 0)
	})

	t.Run("with nil list", func(t *testing.T) {
		resp := ToCredentialListResponse(nil)
		assert.Equal(t, 0, resp.Total)
		assert.Len(t, resp.Credentials, 0)
	})
}

// Error tests

func TestErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{"ErrInvalidRequestBody with reason", ErrInvalidRequestBody{Reason: "bad json"}, "bad json"},
		{"ErrInvalidRequestBody without reason", ErrInvalidRequestBody{}, "invalid request body"},
		{"ErrMissingProfileID", ErrMissingProfileID{}, "profile_id"},
		{"ErrInvalidProfileID with ID", ErrInvalidProfileID{ID: "abc"}, "abc"},
		{"ErrInvalidProfileID without ID", ErrInvalidProfileID{}, "invalid profile_id"},
		{"ErrMissingTenantID", ErrMissingTenantID{}, "tenant_id"},
		{"ErrMissingCredentialID", ErrMissingCredentialID{}, "credential id"},
		{"ErrInvalidCredentialID with ID", ErrInvalidCredentialID{ID: "xyz"}, "xyz"},
		{"ErrMissingKeyID", ErrMissingKeyID{}, "key_id"},
		{"ErrMissingHMACKey", ErrMissingHMACKey{}, "hmac_key"},
		{"ErrInvalidHMACKey with reason", ErrInvalidHMACKey{Reason: "bad encoding"}, "bad encoding"},
		{"ErrInvalidHMACKey without reason", ErrInvalidHMACKey{}, "invalid hmac_key"},
		{"ErrCredentialNotFound by ID", ErrCredentialNotFound{ID: 42}, "id=42"},
		{"ErrCredentialNotFound by KeyID", ErrCredentialNotFound{KeyID: "k-1"}, "key_id=k-1"},
		{"ErrCredentialNotFound empty", ErrCredentialNotFound{}, "not found"},
		{"ErrCredentialExpired by KeyID", ErrCredentialExpired{KeyID: "k-1"}, "key_id=k-1"},
		{"ErrCredentialRevoked by ID", ErrCredentialRevoked{ID: 1}, "id=1"},
		{"ErrCredentialAlreadyUsed", ErrCredentialAlreadyUsed{ID: 5}, "id=5"},
		{"ErrCredentialAlreadyRevoked", ErrCredentialAlreadyRevoked{ID: 3}, "id=3"},
		{"ErrUnauthorized with reason", ErrUnauthorized{Reason: "no token"}, "no token"},
		{"ErrUnauthorized without reason", ErrUnauthorized{}, "unauthorized"},
		{"ErrNotTenantOwner", ErrNotTenantOwner{}, "tenant owner"},
		{"ErrServiceError with cause", ErrServiceError{Operation: "create", Cause: ErrMissingProfileID{}}, "create failed"},
		{"ErrServiceError without cause", ErrServiceError{Operation: "get"}, "get failed"},
		{"ErrMissingLogger", ErrMissingLogger{}, "logger"},
		{"ErrMissingEABService", ErrMissingEABService{}, "eab service"},
		{"ErrMissingResponseWriter", ErrMissingResponseWriter{}, "response writer"},
		{"ErrMissingDelivery", ErrMissingDelivery{}, "delivery"},
		{"ErrQRCodeGenerationFailed with cause", ErrQRCodeGenerationFailed{Cause: ErrMissingProfileID{}}, "QR code"},
		{"ErrURLGenerationFailed with cause", ErrURLGenerationFailed{Cause: ErrMissingProfileID{}}, "URL generation"},
		{"ErrInvalidExpiresIn with reason", ErrInvalidExpiresIn{Reason: "negative"}, "negative"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Contains(t, tt.err.Error(), tt.contains)
		})
	}
}

func TestErrServiceError_Unwrap(t *testing.T) {
	cause := ErrMissingProfileID{}
	err := ErrServiceError{Operation: "test", Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrQRCodeGenerationFailed_Unwrap(t *testing.T) {
	cause := ErrMissingProfileID{}
	err := ErrQRCodeGenerationFailed{Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrURLGenerationFailed_Unwrap(t *testing.T) {
	cause := ErrMissingProfileID{}
	err := ErrURLGenerationFailed{Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
}

// Compile-time interface check
var _ RestHandler = (*handler)(nil)

// Mock implementations

type mockEABService struct{}

func (m *mockEABService) Generate(ctx context.Context, params eab.GenerateParams) (*eab.Credential, error) {
	return nil, nil
}

func (m *mockEABService) Get(ctx context.Context, id uint64) (*eab.Credential, error) {
	return nil, nil
}

func (m *mockEABService) GetByKeyID(ctx context.Context, keyID string) (*eab.Credential, error) {
	return nil, nil
}

func (m *mockEABService) ListByProfile(ctx context.Context, profileID uint64) ([]*eab.Credential, error) {
	return nil, nil
}

func (m *mockEABService) ListByTenant(ctx context.Context, tenantID string) ([]*eab.Credential, error) {
	return nil, nil
}

func (m *mockEABService) Revoke(ctx context.Context, id uint64) error {
	return nil
}

func (m *mockEABService) Validate(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error) {
	return nil, nil
}

func (m *mockEABService) Delete(ctx context.Context, id uint64) error {
	return nil
}

func (m *mockEABService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*eab.Credential], error) {
	return datastore.PageResult[*eab.Credential]{}, nil
}

type mockDeliveryService struct{}

func (m *mockDeliveryService) ToQRCode(cred *eab.Credential) ([]byte, error) {
	return nil, nil
}

func (m *mockDeliveryService) ToURL(cred *eab.Credential) (string, error) {
	return "", nil
}
