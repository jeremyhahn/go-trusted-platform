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

// MockSystemRestHandler implements system.RestHandler
type MockSystemRestHandler struct {
	mock.Mock
}

func (m *MockSystemRestHandler) CABundleHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockSystemRestHandler) Config(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockSystemRestHandler) Certificate(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockSystemRestHandler) EventsPage(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockSystemRestHandler) PublicKey(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockSystemRestHandler) Status(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func TestSystemRouter_RegisterRoutes(t *testing.T) {
	mockAuth := &MockAuthMiddleware{}
	mockJWT := &MockJsonWebTokenMiddleware{}
	mockSysHandler := &MockSystemRestHandler{}

	sysRouter := &SystemRouter{
		authMiddleware:    mockAuth,
		jwtMiddleware:     mockJWT,
		systemRestHandler: mockSysHandler,
	}

	muxRouter := mux.NewRouter()

	require.NotPanics(t, func() {
		sysRouter.RegisterRoutes(muxRouter)
	})
}

func TestSystemRouter_StatusEndpoint(t *testing.T) {
	mockAuth := &MockAuthMiddleware{}
	mockJWT := &MockJsonWebTokenMiddleware{}
	mockSysHandler := &MockSystemRestHandler{}
	mockSysHandler.On("Status", mock.Anything, mock.Anything).Return()

	sysRouter := &SystemRouter{
		authMiddleware:    mockAuth,
		jwtMiddleware:     mockJWT,
		systemRestHandler: mockSysHandler,
	}

	muxRouter := mux.NewRouter()
	sysRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockSysHandler.AssertExpectations(t)
}

func TestSystemRouter_PubkeyEndpoint(t *testing.T) {
	mockAuth := &MockAuthMiddleware{}
	mockJWT := &MockJsonWebTokenMiddleware{}
	mockSysHandler := &MockSystemRestHandler{}
	mockSysHandler.On("PublicKey", mock.Anything, mock.Anything).Return()

	sysRouter := &SystemRouter{
		authMiddleware:    mockAuth,
		jwtMiddleware:     mockJWT,
		systemRestHandler: mockSysHandler,
	}

	muxRouter := mux.NewRouter()
	sysRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodGet, "/pubkey", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockSysHandler.AssertExpectations(t)
}

func TestSystemRouter_CertificateEndpoint(t *testing.T) {
	mockAuth := &MockAuthMiddleware{}
	mockJWT := &MockJsonWebTokenMiddleware{}
	mockSysHandler := &MockSystemRestHandler{}
	mockSysHandler.On("Certificate", mock.Anything, mock.Anything).Return()

	sysRouter := &SystemRouter{
		authMiddleware:    mockAuth,
		jwtMiddleware:     mockJWT,
		systemRestHandler: mockSysHandler,
	}

	muxRouter := mux.NewRouter()
	sysRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodGet, "/certificate", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockSysHandler.AssertExpectations(t)
}

func TestSystemRouter_ConfigEndpoint(t *testing.T) {
	mockAuth := &MockAuthMiddleware{}
	mockJWT := &MockJsonWebTokenMiddleware{}
	mockSysHandler := &MockSystemRestHandler{}

	mockAuth.On("Verify", mock.Anything, mock.Anything, mock.Anything).Return()
	mockJWT.On("Verify", mock.Anything, mock.Anything, mock.Anything).Return()
	mockSysHandler.On("Config", mock.Anything, mock.Anything).Return()

	sysRouter := &SystemRouter{
		authMiddleware:    mockAuth,
		jwtMiddleware:     mockJWT,
		systemRestHandler: mockSysHandler,
	}

	muxRouter := mux.NewRouter()
	sysRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockSysHandler.AssertExpectations(t)
}

func TestSystemRouter_EventsEndpoint(t *testing.T) {
	mockAuth := &MockAuthMiddleware{}
	mockJWT := &MockJsonWebTokenMiddleware{}
	mockSysHandler := &MockSystemRestHandler{}

	mockAuth.On("Verify", mock.Anything, mock.Anything, mock.Anything).Return()
	mockJWT.On("Verify", mock.Anything, mock.Anything, mock.Anything).Return()
	mockSysHandler.On("EventsPage", mock.Anything, mock.Anything).Return()

	sysRouter := &SystemRouter{
		authMiddleware:    mockAuth,
		jwtMiddleware:     mockJWT,
		systemRestHandler: mockSysHandler,
	}

	muxRouter := mux.NewRouter()
	sysRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodGet, "/events/1", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockSysHandler.AssertExpectations(t)
}
