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

// MockInvitationRestHandler implements invitation.RestHandler
type MockInvitationRestHandler struct {
	mock.Mock
}

func (m *MockInvitationRestHandler) Create(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusCreated)
}

func (m *MockInvitationRestHandler) List(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockInvitationRestHandler) Get(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockInvitationRestHandler) GetByToken(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockInvitationRestHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func TestNewInvitationRouter(t *testing.T) {
	mockHandler := &MockInvitationRestHandler{}
	router := NewInvitationRouter(mockHandler, passthroughMiddleware)

	require.NotNil(t, router)
	invRouter, ok := router.(*InvitationRouter)
	require.True(t, ok)
	assert.NotNil(t, invRouter.handler)
	assert.NotNil(t, invRouter.tenantMiddleware)
}

func TestInvitationRouter_AllEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		handler    string
		wantStatus int
	}{
		{
			name:       "create invitation",
			method:     http.MethodPost,
			path:       "/invitations",
			handler:    "Create",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "list invitations",
			method:     http.MethodGet,
			path:       "/invitations",
			handler:    "List",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get invitation by ID",
			method:     http.MethodGet,
			path:       "/invitations/123",
			handler:    "Get",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get invitation by token",
			method:     http.MethodGet,
			path:       "/invitations/token/abc-secure-token",
			handler:    "GetByToken",
			wantStatus: http.StatusOK,
		},
		{
			name:       "revoke invitation",
			method:     http.MethodDelete,
			path:       "/invitations/123",
			handler:    "Revoke",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHandler := &MockInvitationRestHandler{}
			mockHandler.On(tt.handler, mock.Anything, mock.Anything).Return()

			invRouter := NewInvitationRouter(mockHandler, passthroughMiddleware)
			muxRouter := mux.NewRouter()
			invRouter.RegisterRoutes(muxRouter)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			muxRouter.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			mockHandler.AssertExpectations(t)
		})
	}
}

func TestRegisterInvitationRoutes(t *testing.T) {
	mockHandler := &MockInvitationRestHandler{}
	mockHandler.On("GetByToken", mock.Anything, mock.Anything).Return()

	muxRouter := mux.NewRouter()

	require.NotPanics(t, func() {
		RegisterInvitationRoutes(muxRouter, mockHandler, passthroughMiddleware)
	})

	// Verify routes are registered
	req := httptest.NewRequest(http.MethodGet, "/invitations/token/test-token", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestInvitationRouter_ImplementsInterface(t *testing.T) {
	mockHandler := &MockInvitationRestHandler{}
	var router = NewInvitationRouter(mockHandler, passthroughMiddleware)
	assert.NotNil(t, router)
	assert.Implements(t, (*WebServiceRouter)(nil), router)
}
