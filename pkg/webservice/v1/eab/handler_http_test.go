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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testableEABService implements EABServicer with configurable responses
type testableEABService struct {
	generateFn      func(ctx context.Context, params eab.GenerateParams) (*eab.Credential, error)
	getFn           func(ctx context.Context, id uint64) (*eab.Credential, error)
	getByKeyIDFn    func(ctx context.Context, keyID string) (*eab.Credential, error)
	listByProfileFn func(ctx context.Context, profileID uint64) ([]*eab.Credential, error)
	listByTenantFn  func(ctx context.Context, tenantID string) ([]*eab.Credential, error)
	revokeFn        func(ctx context.Context, id uint64) error
	validateFn      func(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error)
	deleteFn        func(ctx context.Context, id uint64) error
}

func (s *testableEABService) Generate(ctx context.Context, params eab.GenerateParams) (*eab.Credential, error) {
	if s.generateFn != nil {
		return s.generateFn(ctx, params)
	}
	return &eab.Credential{ID: 1, KeyID: "key-1", ProfileID: params.ProfileID, TenantID: params.TenantID, Status: eab.StatusActive, CreatedAt: time.Now()}, nil
}

func (s *testableEABService) Get(ctx context.Context, id uint64) (*eab.Credential, error) {
	if s.getFn != nil {
		return s.getFn(ctx, id)
	}
	return &eab.Credential{ID: id, KeyID: "key-1", TenantID: "tenant-1", Status: eab.StatusActive, CreatedAt: time.Now()}, nil
}

func (s *testableEABService) GetByKeyID(ctx context.Context, keyID string) (*eab.Credential, error) {
	if s.getByKeyIDFn != nil {
		return s.getByKeyIDFn(ctx, keyID)
	}
	return &eab.Credential{ID: 1, KeyID: keyID, TenantID: "tenant-1", Status: eab.StatusActive, CreatedAt: time.Now()}, nil
}

func (s *testableEABService) ListByProfile(ctx context.Context, profileID uint64) ([]*eab.Credential, error) {
	if s.listByProfileFn != nil {
		return s.listByProfileFn(ctx, profileID)
	}
	return []*eab.Credential{}, nil
}

func (s *testableEABService) ListByTenant(ctx context.Context, tenantID string) ([]*eab.Credential, error) {
	if s.listByTenantFn != nil {
		return s.listByTenantFn(ctx, tenantID)
	}
	return []*eab.Credential{}, nil
}

func (s *testableEABService) Revoke(ctx context.Context, id uint64) error {
	if s.revokeFn != nil {
		return s.revokeFn(ctx, id)
	}
	return nil
}

func (s *testableEABService) Validate(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error) {
	if s.validateFn != nil {
		return s.validateFn(ctx, keyID, hmacKey)
	}
	return &eab.Credential{ID: 1, KeyID: keyID, Status: eab.StatusActive, CreatedAt: time.Now()}, nil
}

func (s *testableEABService) Delete(ctx context.Context, id uint64) error {
	if s.deleteFn != nil {
		return s.deleteFn(ctx, id)
	}
	return nil
}

func (s *testableEABService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*eab.Credential], error) {
	return datastore.PageResult[*eab.Credential]{}, nil
}

type testableDeliveryService struct {
	toQRCodeFn func(cred *eab.Credential) ([]byte, error)
	toURLFn    func(cred *eab.Credential) (string, error)
}

func (d *testableDeliveryService) ToQRCode(cred *eab.Credential) ([]byte, error) {
	if d.toQRCodeFn != nil {
		return d.toQRCodeFn(cred)
	}
	return []byte("fake-qr-png"), nil
}

func (d *testableDeliveryService) ToURL(cred *eab.Credential) (string, error) {
	if d.toURLFn != nil {
		return d.toURLFn(cred)
	}
	return "https://example.com/enroll?key=test", nil
}

func newTestHandler(t *testing.T, svc EABServicer, del DeliveryServicer) RestHandler {
	t.Helper()
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	h, err := NewHandler(HandlerParams{
		Logger:         logger,
		EABService:     svc,
		Delivery:       del,
		ResponseWriter: respWriter,
	})
	require.NoError(t, err)
	return h
}

func withTenantContext(r *http.Request, tenantID string, userID uint64, isOwner bool) *http.Request {
	ctx := tenant.SetTenantContext(r.Context(), tenantID, userID, isOwner)
	return r.WithContext(ctx)
}

// Create handler tests

func TestHandler_Create_Success(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"profile_id": 42}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials", bytes.NewBufferString(body))
	req = withTenantContext(req, "tenant-1", 1, true)
	rec := httptest.NewRecorder()

	h.Create(rec, req)
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestHandler_Create_MissingTenant(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"profile_id": 42}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	h.Create(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandler_Create_NotOwner(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"profile_id": 42}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials", bytes.NewBufferString(body))
	req = withTenantContext(req, "tenant-1", 1, false)
	rec := httptest.NewRecorder()

	h.Create(rec, req)
	// Error403 in response writer actually sends StatusBadRequest (400)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_Create_MissingProfileID(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"profile_id": 0}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials", bytes.NewBufferString(body))
	req = withTenantContext(req, "tenant-1", 1, true)
	rec := httptest.NewRecorder()

	h.Create(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_Create_NegativeExpiresIn(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"profile_id": 42, "expires_in_seconds": -100}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials", bytes.NewBufferString(body))
	req = withTenantContext(req, "tenant-1", 1, true)
	rec := httptest.NewRecorder()

	h.Create(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_Create_InvalidBody(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodPost, "/eab/credentials", bytes.NewBufferString("not json"))
	req = withTenantContext(req, "tenant-1", 1, true)
	rec := httptest.NewRecorder()

	h.Create(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_Create_ServiceError(t *testing.T) {
	svc := &testableEABService{
		generateFn: func(ctx context.Context, params eab.GenerateParams) (*eab.Credential, error) {
			return nil, errors.New("database error")
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"profile_id": 42}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials", bytes.NewBufferString(body))
	req = withTenantContext(req, "tenant-1", 1, true)
	rec := httptest.NewRecorder()

	h.Create(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHandler_Create_MissingUserID(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"profile_id": 42}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials", bytes.NewBufferString(body))
	ctx := tenant.SetTenantContext(req.Context(), "tenant-1", 0, true) // userID=0
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	h.Create(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// Get handler tests

func TestHandler_Get_Success(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/1", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.Get(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_Get_MissingTenant(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.Get(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandler_Get_InvalidID(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/abc", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"id": "abc"})
	rec := httptest.NewRecorder()

	h.Get(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_Get_WrongTenant(t *testing.T) {
	svc := &testableEABService{
		getFn: func(ctx context.Context, id uint64) (*eab.Credential, error) {
			return &eab.Credential{ID: id, TenantID: "other-tenant", CreatedAt: time.Now()}, nil
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/1", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.Get(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandler_Get_NotFound(t *testing.T) {
	svc := &testableEABService{
		getFn: func(ctx context.Context, id uint64) (*eab.Credential, error) {
			return nil, eab.ErrCredentialNotFound{ID: id}
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/999", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"id": "999"})
	rec := httptest.NewRecorder()

	h.Get(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandler_Get_ServiceError(t *testing.T) {
	svc := &testableEABService{
		getFn: func(ctx context.Context, id uint64) (*eab.Credential, error) {
			return nil, errors.New("database error")
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/1", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.Get(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// GetByKeyID handler tests

func TestHandler_GetByKeyID_Success(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/key/test-key", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"key_id": "test-key"})
	rec := httptest.NewRecorder()

	h.GetByKeyID(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_GetByKeyID_NotFound(t *testing.T) {
	svc := &testableEABService{
		getByKeyIDFn: func(ctx context.Context, keyID string) (*eab.Credential, error) {
			return nil, eab.ErrCredentialNotFound{KeyID: keyID}
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/key/missing", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"key_id": "missing"})
	rec := httptest.NewRecorder()

	h.GetByKeyID(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandler_GetByKeyID_ServiceError(t *testing.T) {
	svc := &testableEABService{
		getByKeyIDFn: func(ctx context.Context, keyID string) (*eab.Credential, error) {
			return nil, errors.New("database error")
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/key/test-key", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"key_id": "test-key"})
	rec := httptest.NewRecorder()

	h.GetByKeyID(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// List handler tests

func TestHandler_List_ByTenant(t *testing.T) {
	svc := &testableEABService{
		listByTenantFn: func(ctx context.Context, tenantID string) ([]*eab.Credential, error) {
			return []*eab.Credential{
				{ID: 1, KeyID: "k1", TenantID: tenantID, CreatedAt: time.Now()},
			}, nil
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	rec := httptest.NewRecorder()

	h.List(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp response.WebServiceResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

func TestHandler_List_ByProfile(t *testing.T) {
	svc := &testableEABService{
		listByProfileFn: func(ctx context.Context, profileID uint64) ([]*eab.Credential, error) {
			return []*eab.Credential{
				{ID: 1, KeyID: "k1", TenantID: "tenant-1", ProfileID: profileID, CreatedAt: time.Now()},
			}, nil
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials?profile_id=42", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	rec := httptest.NewRecorder()

	h.List(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_List_InvalidProfileID(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials?profile_id=abc", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	rec := httptest.NewRecorder()

	h.List(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_List_ListByTenantError(t *testing.T) {
	svc := &testableEABService{
		listByTenantFn: func(ctx context.Context, tenantID string) ([]*eab.Credential, error) {
			return nil, errors.New("database error")
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	rec := httptest.NewRecorder()

	h.List(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHandler_List_ListByProfileError(t *testing.T) {
	svc := &testableEABService{
		listByProfileFn: func(ctx context.Context, profileID uint64) ([]*eab.Credential, error) {
			return nil, errors.New("database error")
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials?profile_id=42", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	rec := httptest.NewRecorder()

	h.List(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// Validate handler tests

func TestHandler_Validate_Success(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"key_id": "test-key", "hmac_key": "dGVzdC1obWFjLWtleQ"}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials/validate", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	h.Validate(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_Validate_MissingKeyID(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"key_id": "", "hmac_key": "dGVzdA"}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials/validate", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	h.Validate(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_Validate_MissingHMACKey(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"key_id": "test-key", "hmac_key": ""}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials/validate", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	h.Validate(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_Validate_InvalidBase64(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"key_id": "test-key", "hmac_key": "!!!invalid!!!"}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials/validate", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	h.Validate(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_Validate_CredentialNotFound(t *testing.T) {
	svc := &testableEABService{
		validateFn: func(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error) {
			return nil, eab.ErrCredentialNotFound{KeyID: keyID}
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"key_id": "missing", "hmac_key": "dGVzdA"}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials/validate", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	h.Validate(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code) // Returns 200 with valid=false
}

func TestHandler_Validate_ServiceError(t *testing.T) {
	svc := &testableEABService{
		validateFn: func(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error) {
			return nil, errors.New("database error")
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	body := `{"key_id": "test", "hmac_key": "dGVzdA"}`
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials/validate", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	h.Validate(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// Delete handler tests

func TestHandler_Delete_Success(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodDelete, "/eab/credentials/1", nil)
	req = withTenantContext(req, "tenant-1", 1, true)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.Delete(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_Delete_NotOwner(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodDelete, "/eab/credentials/1", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.Delete(rec, req)
	// Error403 sends StatusBadRequest (400) in current implementation
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_Delete_ServiceError(t *testing.T) {
	svc := &testableEABService{
		deleteFn: func(ctx context.Context, id uint64) error {
			return errors.New("database error")
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodDelete, "/eab/credentials/1", nil)
	req = withTenantContext(req, "tenant-1", 1, true)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.Delete(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// Revoke handler tests

func TestHandler_Revoke_Success(t *testing.T) {
	svc := &testableEABService{}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodPost, "/eab/credentials/1/revoke", nil)
	req = withTenantContext(req, "tenant-1", 1, true)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.Revoke(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_Revoke_AlreadyRevoked(t *testing.T) {
	svc := &testableEABService{
		getFn: func(ctx context.Context, id uint64) (*eab.Credential, error) {
			return &eab.Credential{ID: id, TenantID: "tenant-1", Status: eab.StatusRevoked, CreatedAt: time.Now()}, nil
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodPost, "/eab/credentials/1/revoke", nil)
	req = withTenantContext(req, "tenant-1", 1, true)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.Revoke(rec, req)
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestHandler_Revoke_ServiceError(t *testing.T) {
	svc := &testableEABService{
		revokeFn: func(ctx context.Context, id uint64) error {
			return errors.New("database error")
		},
	}
	h := newTestHandler(t, svc, &testableDeliveryService{})

	req := httptest.NewRequest(http.MethodPost, "/eab/credentials/1/revoke", nil)
	req = withTenantContext(req, "tenant-1", 1, true)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.Revoke(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// QR Code handler tests

func TestHandler_GetQRCode_Success(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/1/qr", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.GetQRCode(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "image/png", rec.Header().Get("Content-Type"))
}

func TestHandler_GetQRCode_DeliveryError(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{
		toQRCodeFn: func(cred *eab.Credential) ([]byte, error) {
			return nil, errors.New("qr generation failed")
		},
	}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/1/qr", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.GetQRCode(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// Enrollment URL handler tests

func TestHandler_GetEnrollmentURL_Success(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/1/url", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.GetEnrollmentURL(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_GetEnrollmentURL_DeliveryError(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{
		toURLFn: func(cred *eab.Credential) (string, error) {
			return "", errors.New("url generation failed")
		},
	}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/1/url", nil)
	req = withTenantContext(req, "tenant-1", 1, false)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rec := httptest.NewRecorder()

	h.GetEnrollmentURL(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
