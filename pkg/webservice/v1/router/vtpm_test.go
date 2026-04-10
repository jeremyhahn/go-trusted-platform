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

// MockVTPMRestHandler implements vtpm.RestHandler
type MockVTPMRestHandler struct {
	mock.Mock
}

func (m *MockVTPMRestHandler) CreateInstance(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusCreated)
}

func (m *MockVTPMRestHandler) ListInstances(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockVTPMRestHandler) GetInstance(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockVTPMRestHandler) GetInstanceByProfile(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockVTPMRestHandler) DeleteInstance(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockVTPMRestHandler) StartInstance(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockVTPMRestHandler) StopInstance(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockVTPMRestHandler) GetInstanceStatus(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockVTPMRestHandler) ExportEKCertificate(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockVTPMRestHandler) GetEKFingerprint(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func TestNewVTPMInstanceRouter(t *testing.T) {
	mockHandler := &MockVTPMRestHandler{}
	router := NewVTPMInstanceRouter(mockHandler)

	require.NotNil(t, router)
	vtpmRouter, ok := router.(*VTPMInstanceRouter)
	require.True(t, ok)
	assert.NotNil(t, vtpmRouter.handler)
}

func TestVTPMInstanceRouter_RegisterRoutes(t *testing.T) {
	mockHandler := &MockVTPMRestHandler{}
	vtpmRouter := NewVTPMInstanceRouter(mockHandler)
	muxRouter := mux.NewRouter()

	require.NotPanics(t, func() {
		vtpmRouter.RegisterRoutes(muxRouter)
	})
}

func TestVTPMInstanceRouter_AllEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		handler    string
		wantStatus int
	}{
		{
			name:       "create instance",
			method:     http.MethodPost,
			path:       "/vtpm/instances",
			handler:    "CreateInstance",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "list instances",
			method:     http.MethodGet,
			path:       "/vtpm/instances",
			handler:    "ListInstances",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get instance",
			method:     http.MethodGet,
			path:       "/vtpm/instances/test-id-123",
			handler:    "GetInstance",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get instance by profile",
			method:     http.MethodGet,
			path:       "/vtpm/instances/profile/42",
			handler:    "GetInstanceByProfile",
			wantStatus: http.StatusOK,
		},
		{
			name:       "delete instance",
			method:     http.MethodDelete,
			path:       "/vtpm/instances/test-id-123",
			handler:    "DeleteInstance",
			wantStatus: http.StatusOK,
		},
		{
			name:       "start instance",
			method:     http.MethodPost,
			path:       "/vtpm/instances/test-id-123/start",
			handler:    "StartInstance",
			wantStatus: http.StatusOK,
		},
		{
			name:       "stop instance",
			method:     http.MethodPost,
			path:       "/vtpm/instances/test-id-123/stop",
			handler:    "StopInstance",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get instance status",
			method:     http.MethodGet,
			path:       "/vtpm/instances/test-id-123/status",
			handler:    "GetInstanceStatus",
			wantStatus: http.StatusOK,
		},
		{
			name:       "export EK certificate",
			method:     http.MethodGet,
			path:       "/vtpm/instances/test-id-123/ek",
			handler:    "ExportEKCertificate",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get EK fingerprint",
			method:     http.MethodGet,
			path:       "/vtpm/instances/test-id-123/ek/fingerprint",
			handler:    "GetEKFingerprint",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHandler := &MockVTPMRestHandler{}
			mockHandler.On(tt.handler, mock.Anything, mock.Anything).Return()

			vtpmRouter := NewVTPMInstanceRouter(mockHandler)
			muxRouter := mux.NewRouter()
			vtpmRouter.RegisterRoutes(muxRouter)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			muxRouter.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			mockHandler.AssertExpectations(t)
		})
	}
}

func TestVTPMInstanceRouter_ImplementsInterface(t *testing.T) {
	mockHandler := &MockVTPMRestHandler{}
	var router = NewVTPMInstanceRouter(mockHandler)
	assert.NotNil(t, router)
	assert.Implements(t, (*WebServiceRouter)(nil), router)
}

func TestVTPMInstanceRouter_ProfileIDRegex(t *testing.T) {
	mockHandler := &MockVTPMRestHandler{}

	vtpmRouter := NewVTPMInstanceRouter(mockHandler)
	muxRouter := mux.NewRouter()
	vtpmRouter.RegisterRoutes(muxRouter)

	// Non-numeric profile ID should not match
	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances/profile/abc", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusOK, rec.Code)
}
