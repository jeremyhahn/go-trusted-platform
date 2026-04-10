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

package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockEABRestHandler implements eab.RestHandler
type MockEABRestHandler struct {
	mock.Mock
}

func (m *MockEABRestHandler) Create(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusCreated)
}

func (m *MockEABRestHandler) Get(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockEABRestHandler) GetByKeyID(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockEABRestHandler) List(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockEABRestHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockEABRestHandler) Validate(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockEABRestHandler) Delete(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockEABRestHandler) GetQRCode(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockEABRestHandler) GetEnrollmentURL(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func passthroughMiddleware(next http.Handler) http.Handler {
	return next
}

func TestNewEABRouter(t *testing.T) {
	mockHandler := &MockEABRestHandler{}
	router := NewEABRouter(mockHandler, passthroughMiddleware)

	require.NotNil(t, router)
	eabRouter, ok := router.(*EABRouter)
	require.True(t, ok)
	assert.NotNil(t, eabRouter.handler)
	assert.NotNil(t, eabRouter.tenantMiddleware)
}

func TestEABRouter_RegisterRoutes(t *testing.T) {
	mockHandler := &MockEABRestHandler{}
	eabRouter := NewEABRouter(mockHandler, passthroughMiddleware)
	muxRouter := mux.NewRouter()

	require.NotPanics(t, func() {
		eabRouter.RegisterRoutes(muxRouter)
	})
}

func TestEABRouter_AllEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		handler    string
		wantStatus int
	}{
		{
			name:       "create credential",
			method:     http.MethodPost,
			path:       "/eab/credentials",
			handler:    "Create",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "list credentials",
			method:     http.MethodGet,
			path:       "/eab/credentials",
			handler:    "List",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get credential by ID",
			method:     http.MethodGet,
			path:       "/eab/credentials/123",
			handler:    "Get",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get credential by key ID",
			method:     http.MethodGet,
			path:       "/eab/credentials/key/test-key-id",
			handler:    "GetByKeyID",
			wantStatus: http.StatusOK,
		},
		{
			name:       "revoke credential",
			method:     http.MethodPost,
			path:       "/eab/credentials/123/revoke",
			handler:    "Revoke",
			wantStatus: http.StatusOK,
		},
		{
			name:       "validate credential",
			method:     http.MethodPost,
			path:       "/eab/credentials/validate",
			handler:    "Validate",
			wantStatus: http.StatusOK,
		},
		{
			name:       "delete credential",
			method:     http.MethodDelete,
			path:       "/eab/credentials/123",
			handler:    "Delete",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get QR code",
			method:     http.MethodGet,
			path:       "/eab/credentials/123/qr",
			handler:    "GetQRCode",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get enrollment URL",
			method:     http.MethodGet,
			path:       "/eab/credentials/123/url",
			handler:    "GetEnrollmentURL",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHandler := &MockEABRestHandler{}
			mockHandler.On(tt.handler, mock.Anything, mock.Anything).Return()

			eabRouter := NewEABRouter(mockHandler, passthroughMiddleware)
			muxRouter := mux.NewRouter()
			eabRouter.RegisterRoutes(muxRouter)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			muxRouter.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			mockHandler.AssertExpectations(t)
		})
	}
}

func TestEABRouter_ValidateNoTenantMiddleware(t *testing.T) {
	// Validate endpoint should work without tenant middleware
	mockHandler := &MockEABRestHandler{}
	mockHandler.On("Validate", mock.Anything, mock.Anything).Return()

	eabRouter := NewEABRouter(mockHandler, passthroughMiddleware)
	muxRouter := mux.NewRouter()
	eabRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodPost, "/eab/credentials/validate", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockHandler.AssertExpectations(t)
}

func TestRegisterEABRoutes(t *testing.T) {
	mockHandler := &MockEABRestHandler{}
	mockHandler.On("Validate", mock.Anything, mock.Anything).Return()

	muxRouter := mux.NewRouter()

	require.NotPanics(t, func() {
		RegisterEABRoutes(muxRouter, mockHandler, passthroughMiddleware)
	})

	// Verify routes are registered
	req := httptest.NewRequest(http.MethodPost, "/eab/credentials/validate", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEABRouter_ImplementsInterface(t *testing.T) {
	mockHandler := &MockEABRestHandler{}
	var router = NewEABRouter(mockHandler, passthroughMiddleware)
	assert.NotNil(t, router)
	assert.Implements(t, (*WebServiceRouter)(nil), router)
}

func TestEABRouter_InvalidCredentialIDFormat(t *testing.T) {
	mockHandler := &MockEABRestHandler{}

	eabRouter := NewEABRouter(mockHandler, passthroughMiddleware)
	muxRouter := mux.NewRouter()
	eabRouter.RegisterRoutes(muxRouter)

	// Non-numeric ID should not match the [0-9]+ pattern
	req := httptest.NewRequest(http.MethodGet, "/eab/credentials/abc", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	// gorilla/mux returns 404 or 405 for non-matching routes
	assert.NotEqual(t, http.StatusOK, rec.Code)
}
