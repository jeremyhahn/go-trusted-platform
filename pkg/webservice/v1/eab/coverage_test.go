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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/tenant"
	"github.com/stretchr/testify/assert"
)

// TestErrors_ZeroValueBranches tests Error() methods with zero/nil inner values.
func TestErrors_ZeroValueBranches(t *testing.T) {
	t.Run("ErrInvalidCredentialID empty ID", func(t *testing.T) {
		err := ErrInvalidCredentialID{}
		assert.Equal(t, "eab: invalid credential id", err.Error())
	})

	t.Run("ErrCredentialNotFound all zero", func(t *testing.T) {
		err := ErrCredentialNotFound{}
		assert.Equal(t, "eab: credential not found", err.Error())
	})

	t.Run("ErrCredentialNotFound with KeyID", func(t *testing.T) {
		err := ErrCredentialNotFound{KeyID: "key-abc"}
		assert.Contains(t, err.Error(), "key-abc")
	})

	t.Run("ErrCredentialExpired all zero", func(t *testing.T) {
		err := ErrCredentialExpired{}
		assert.Equal(t, "eab: credential expired", err.Error())
	})

	t.Run("ErrCredentialExpired with KeyID", func(t *testing.T) {
		err := ErrCredentialExpired{KeyID: "key-abc"}
		assert.Contains(t, err.Error(), "key-abc")
	})

	t.Run("ErrCredentialExpired with ID", func(t *testing.T) {
		err := ErrCredentialExpired{ID: 42}
		assert.Contains(t, err.Error(), "42")
	})

	t.Run("ErrCredentialRevoked all zero", func(t *testing.T) {
		err := ErrCredentialRevoked{}
		assert.Equal(t, "eab: credential revoked", err.Error())
	})

	t.Run("ErrCredentialRevoked with KeyID", func(t *testing.T) {
		err := ErrCredentialRevoked{KeyID: "key-abc"}
		assert.Contains(t, err.Error(), "key-abc")
	})

	t.Run("ErrCredentialRevoked with ID", func(t *testing.T) {
		err := ErrCredentialRevoked{ID: 42}
		assert.Contains(t, err.Error(), "42")
	})

	t.Run("ErrCredentialAlreadyUsed all zero", func(t *testing.T) {
		err := ErrCredentialAlreadyUsed{}
		assert.Equal(t, "eab: credential already used", err.Error())
	})

	t.Run("ErrCredentialAlreadyUsed with KeyID", func(t *testing.T) {
		err := ErrCredentialAlreadyUsed{KeyID: "key-abc"}
		assert.Contains(t, err.Error(), "key-abc")
	})

	t.Run("ErrCredentialAlreadyUsed with ID", func(t *testing.T) {
		err := ErrCredentialAlreadyUsed{ID: 42}
		assert.Contains(t, err.Error(), "42")
	})

	t.Run("ErrCredentialAlreadyRevoked zero ID", func(t *testing.T) {
		err := ErrCredentialAlreadyRevoked{}
		assert.Equal(t, "eab: credential already revoked", err.Error())
	})

	t.Run("ErrQRCodeGenerationFailed nil cause", func(t *testing.T) {
		err := ErrQRCodeGenerationFailed{}
		assert.Equal(t, "eab: QR code generation failed", err.Error())
	})

	t.Run("ErrURLGenerationFailed nil cause", func(t *testing.T) {
		err := ErrURLGenerationFailed{}
		assert.Equal(t, "eab: URL generation failed", err.Error())
	})

	t.Run("ErrInvalidExpiresIn empty reason", func(t *testing.T) {
		err := ErrInvalidExpiresIn{}
		assert.Equal(t, "eab: invalid expires_in", err.Error())
	})
}

// TestHandler_Revoke_MissingTenant tests Revoke with missing tenant context.
func TestHandler_Revoke_MissingTenant(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/eab/credentials/1/revoke", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestHandler_Revoke_MissingUserID tests Revoke with missing user ID.
func TestHandler_Revoke_MissingUserID(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/eab/credentials/1/revoke", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-1", 0, false)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestHandler_Revoke_NotOwner tests Revoke by non-owner.
func TestHandler_Revoke_NotOwner(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/eab/credentials/1/revoke", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req = withTenantContext(req, "tenant-1", 1, false)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandler_Revoke_MissingID tests Revoke with missing credential ID.
func TestHandler_Revoke_MissingID(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/eab/credentials//revoke", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandler_Revoke_InvalidID tests Revoke with non-numeric credential ID.
func TestHandler_Revoke_InvalidID(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/eab/credentials/abc/revoke", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "abc"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandler_Revoke_WrongTenant tests Revoke when credential belongs to different tenant.
func TestHandler_Revoke_WrongTenant(t *testing.T) {
	svc := &testableEABService{
		getFn: func(ctx context.Context, id uint64) (*eab.Credential, error) {
			return &eab.Credential{ID: id, TenantID: "other-tenant", Status: eab.StatusActive}, nil
		},
	}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/eab/credentials/1/revoke", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestHandler_Delete_MissingTenant tests Delete with missing tenant context.
func TestHandler_Delete_MissingTenant(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/eab/credentials/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	h.Delete(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestHandler_Delete_MissingUserID tests Delete with missing user ID.
func TestHandler_Delete_MissingUserID(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/eab/credentials/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-1", 0, false)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Delete(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestHandler_Delete_MissingID tests Delete with missing credential ID.
func TestHandler_Delete_MissingID(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/eab/credentials/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.Delete(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandler_Delete_InvalidID tests Delete with non-numeric credential ID.
func TestHandler_Delete_InvalidID(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/eab/credentials/abc", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "abc"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.Delete(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandler_Delete_WrongTenant tests Delete when credential belongs to different tenant.
func TestHandler_Delete_WrongTenant(t *testing.T) {
	svc := &testableEABService{
		getFn: func(ctx context.Context, id uint64) (*eab.Credential, error) {
			return &eab.Credential{ID: id, TenantID: "other-tenant"}, nil
		},
	}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/eab/credentials/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.Delete(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestHandler_Delete_GetError tests Delete when Get returns an error.
func TestHandler_Delete_GetError(t *testing.T) {
	svc := &testableEABService{
		getFn: func(ctx context.Context, id uint64) (*eab.Credential, error) {
			return nil, errors.New("database error")
		},
	}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/eab/credentials/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.Delete(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestHandler_GetQRCode_MissingTenant tests GetQRCode with missing tenant.
func TestHandler_GetQRCode_MissingTenant(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials/1/qr", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	h.GetQRCode(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestHandler_GetQRCode_MissingID tests GetQRCode with missing credential ID.
func TestHandler_GetQRCode_MissingID(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials//qr", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.GetQRCode(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandler_GetQRCode_InvalidID tests GetQRCode with non-numeric ID.
func TestHandler_GetQRCode_InvalidID(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials/abc/qr", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "abc"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.GetQRCode(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandler_GetQRCode_WrongTenant tests GetQRCode when credential belongs to different tenant.
func TestHandler_GetQRCode_WrongTenant(t *testing.T) {
	svc := &testableEABService{
		getFn: func(ctx context.Context, id uint64) (*eab.Credential, error) {
			return &eab.Credential{ID: id, TenantID: "other-tenant"}, nil
		},
	}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials/1/qr", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.GetQRCode(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestHandler_GetQRCode_GetError tests GetQRCode when Get returns an error.
func TestHandler_GetQRCode_GetError(t *testing.T) {
	svc := &testableEABService{
		getFn: func(ctx context.Context, id uint64) (*eab.Credential, error) {
			return nil, errors.New("database error")
		},
	}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials/1/qr", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.GetQRCode(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestHandler_GetEnrollmentURL_MissingTenant tests GetEnrollmentURL with missing tenant.
func TestHandler_GetEnrollmentURL_MissingTenant(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials/1/url", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	h.GetEnrollmentURL(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestHandler_GetEnrollmentURL_MissingID tests GetEnrollmentURL with missing credential ID.
func TestHandler_GetEnrollmentURL_MissingID(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials//url", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.GetEnrollmentURL(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandler_GetEnrollmentURL_InvalidID tests GetEnrollmentURL with non-numeric ID.
func TestHandler_GetEnrollmentURL_InvalidID(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials/abc/url", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "abc"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.GetEnrollmentURL(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandler_GetEnrollmentURL_WrongTenant tests GetEnrollmentURL when credential belongs to different tenant.
func TestHandler_GetEnrollmentURL_WrongTenant(t *testing.T) {
	svc := &testableEABService{
		getFn: func(ctx context.Context, id uint64) (*eab.Credential, error) {
			return &eab.Credential{ID: id, TenantID: "other-tenant"}, nil
		},
	}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials/1/url", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.GetEnrollmentURL(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestHandler_GetEnrollmentURL_GetError tests GetEnrollmentURL when Get returns an error.
func TestHandler_GetEnrollmentURL_GetError(t *testing.T) {
	svc := &testableEABService{
		getFn: func(ctx context.Context, id uint64) (*eab.Credential, error) {
			return nil, errors.New("database error")
		},
	}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials/1/url", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.GetEnrollmentURL(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestHandler_GetByKeyID_MissingTenant tests GetByKeyID with missing tenant context.
func TestHandler_GetByKeyID_MissingTenant(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials/key/key-1", nil)
	req = mux.SetURLVars(req, map[string]string{"key_id": "key-1"})
	w := httptest.NewRecorder()

	h.GetByKeyID(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestHandler_GetByKeyID_MissingKeyID tests GetByKeyID with missing key ID.
func TestHandler_GetByKeyID_MissingKeyID(t *testing.T) {
	svc := &testableEABService{}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials/key/", nil)
	req = mux.SetURLVars(req, map[string]string{"key_id": ""})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.GetByKeyID(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandler_GetByKeyID_WrongTenant tests GetByKeyID when credential belongs to different tenant.
func TestHandler_GetByKeyID_WrongTenant(t *testing.T) {
	svc := &testableEABService{
		getByKeyIDFn: func(ctx context.Context, keyID string) (*eab.Credential, error) {
			return &eab.Credential{ID: 1, KeyID: keyID, TenantID: "other-tenant"}, nil
		},
	}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials/key/key-1", nil)
	req = mux.SetURLVars(req, map[string]string{"key_id": "key-1"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.GetByKeyID(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestHandler_Revoke_GetNotFound tests Revoke when credential is not found.
func TestHandler_Revoke_GetNotFound(t *testing.T) {
	svc := &testableEABService{
		getFn: func(ctx context.Context, id uint64) (*eab.Credential, error) {
			return nil, eab.ErrCredentialNotFound{ID: id}
		},
	}
	del := &testableDeliveryService{}
	h := newTestHandler(t, svc, del)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/eab/credentials/999/revoke", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "999"})
	req = withTenantContext(req, "tenant-1", 1, true)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
