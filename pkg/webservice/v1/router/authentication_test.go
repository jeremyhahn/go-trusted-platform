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
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewAuthenticationRouter(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}

	router := NewAuthenticationRouter(mockMiddleware)

	require.NotNil(t, router)
	authRouter, ok := router.(*AuthenticationRouter)
	require.True(t, ok)
	assert.NotNil(t, authRouter.middleware)
	assert.Equal(t, mockMiddleware, authRouter.middleware)
}

// logoutMiddleware is a JWT middleware that can sign a session out (#215).
type logoutMiddleware struct {
	MockJsonWebTokenMiddleware
	calls int
}

func (m *logoutMiddleware) Logout(w http.ResponseWriter, _ *http.Request) {
	m.calls++
	w.WriteHeader(http.StatusOK)
}

func TestAuthenticationRouter_MountsLogoutOnPOST(t *testing.T) {
	middleware := &logoutMiddleware{}
	r := mux.NewRouter()
	NewAuthenticationRouter(middleware).RegisterRoutes(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/logout", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, middleware.calls)

	// A GET must not sign anyone out: an <img src="/logout"> on another
	// page would otherwise end the session.
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logout", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Equal(t, 1, middleware.calls)
}

func TestAuthenticationRouter_NoLogoutRouteWithoutALogoutHandler(t *testing.T) {
	r := mux.NewRouter()
	NewAuthenticationRouter(&MockJsonWebTokenMiddleware{}).RegisterRoutes(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/logout", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestAuthenticationRouter_RegisterRoutes(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	authRouter := NewAuthenticationRouter(mockMiddleware)

	muxRouter := mux.NewRouter()

	// RegisterRoutes should not panic
	require.NotPanics(t, func() {
		authRouter.RegisterRoutes(muxRouter)
	})
}

func TestAuthenticationRouter_Login(t *testing.T) {
	t.Run("successful login", func(t *testing.T) {
		mockMiddleware := &MockJsonWebTokenMiddleware{}
		mockMiddleware.On("GenerateToken", mock.Anything, mock.Anything).Return()

		authRouter := NewAuthenticationRouter(mockMiddleware)
		muxRouter := mux.NewRouter()
		authRouter.RegisterRoutes(muxRouter)

		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "test-token")
		mockMiddleware.AssertExpectations(t)
	})

	t.Run("login endpoint exists", func(t *testing.T) {
		mockMiddleware := &MockJsonWebTokenMiddleware{}
		mockMiddleware.On("GenerateToken", mock.Anything, mock.Anything).Return()

		authRouter := NewAuthenticationRouter(mockMiddleware)
		muxRouter := mux.NewRouter()
		authRouter.RegisterRoutes(muxRouter)

		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		assert.NotEqual(t, http.StatusNotFound, rec.Code)
		mockMiddleware.AssertExpectations(t)
	})
}

func TestAuthenticationRouter_RefreshToken(t *testing.T) {
	t.Run("successful token refresh", func(t *testing.T) {
		mockMiddleware := &MockJsonWebTokenMiddleware{}
		mockMiddleware.On("RefreshToken", mock.Anything, mock.Anything).Return()

		authRouter := NewAuthenticationRouter(mockMiddleware)
		muxRouter := mux.NewRouter()
		authRouter.RegisterRoutes(muxRouter)

		req := httptest.NewRequest(http.MethodGet, "/login/refresh", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "refreshed-token")
		mockMiddleware.AssertExpectations(t)
	})

	t.Run("refresh endpoint exists", func(t *testing.T) {
		mockMiddleware := &MockJsonWebTokenMiddleware{}
		mockMiddleware.On("RefreshToken", mock.Anything, mock.Anything).Return()

		authRouter := NewAuthenticationRouter(mockMiddleware)
		muxRouter := mux.NewRouter()
		authRouter.RegisterRoutes(muxRouter)

		req := httptest.NewRequest(http.MethodGet, "/login/refresh", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		assert.NotEqual(t, http.StatusNotFound, rec.Code)
		mockMiddleware.AssertExpectations(t)
	})
}

func TestAuthenticationRouter_NotFoundRoutes(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "invalid auth endpoint",
			path: "/login/invalid",
		},
		{
			name: "non-existent path",
			path: "/authenticate",
		},
		{
			name: "malformed refresh path",
			path: "/login/refresh/extra",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMiddleware := &MockJsonWebTokenMiddleware{}

			authRouter := NewAuthenticationRouter(mockMiddleware)
			muxRouter := mux.NewRouter()
			authRouter.RegisterRoutes(muxRouter)

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			muxRouter.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusNotFound, rec.Code)
		})
	}
}

func TestAuthenticationRouter_ConcurrentRequests(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	mockMiddleware.On("GenerateToken", mock.Anything, mock.Anything).Return()

	authRouter := NewAuthenticationRouter(mockMiddleware)
	muxRouter := mux.NewRouter()
	authRouter.RegisterRoutes(muxRouter)

	// Test concurrent login requests
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodPost, "/login", nil)
			rec := httptest.NewRecorder()

			muxRouter.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			done <- true
		}()
	}

	// Wait for all goroutines to complete with timeout
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for concurrent requests")
		}
	}
}

func TestAuthenticationRouter_LoginAndRefreshFlow(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	mockMiddleware.On("GenerateToken", mock.Anything, mock.Anything).Return()
	mockMiddleware.On("RefreshToken", mock.Anything, mock.Anything).Return()

	authRouter := NewAuthenticationRouter(mockMiddleware)
	muxRouter := mux.NewRouter()
	authRouter.RegisterRoutes(muxRouter)

	// First login
	loginReq := httptest.NewRequest(http.MethodPost, "/login", nil)
	loginRec := httptest.NewRecorder()
	muxRouter.ServeHTTP(loginRec, loginReq)

	assert.Equal(t, http.StatusOK, loginRec.Code)
	assert.Contains(t, loginRec.Body.String(), "test-token")

	// Then refresh
	refreshReq := httptest.NewRequest(http.MethodGet, "/login/refresh", nil)
	refreshRec := httptest.NewRecorder()
	muxRouter.ServeHTTP(refreshRec, refreshReq)

	assert.Equal(t, http.StatusOK, refreshRec.Code)
	assert.Contains(t, refreshRec.Body.String(), "refreshed-token")

	mockMiddleware.AssertExpectations(t)
}

func TestAuthenticationRouter_NilMiddleware(t *testing.T) {
	t.Run("constructor accepts nil middleware", func(t *testing.T) {
		router := NewAuthenticationRouter(nil)
		require.NotNil(t, router)

		authRouter, ok := router.(*AuthenticationRouter)
		require.True(t, ok)
		assert.Nil(t, authRouter.middleware)
	})
}

func TestAuthenticationRouter_RouteRegistrationOrder(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	mockMiddleware.On("GenerateToken", mock.Anything, mock.Anything).Return()
	mockMiddleware.On("RefreshToken", mock.Anything, mock.Anything).Return()

	authRouter := NewAuthenticationRouter(mockMiddleware)
	muxRouter := mux.NewRouter()

	// Register routes multiple times should not cause issues
	authRouter.RegisterRoutes(muxRouter)
	authRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rec := httptest.NewRecorder()

	muxRouter.ServeHTTP(rec, req)

	// Should still work
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuthenticationRouter_EmptyCredentials(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	mockMiddleware.On("GenerateToken", mock.Anything, mock.Anything).Return()

	authRouter := NewAuthenticationRouter(mockMiddleware)
	muxRouter := mux.NewRouter()
	authRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rec := httptest.NewRecorder()

	muxRouter.ServeHTTP(rec, req)

	// The router should accept the request and delegate validation to middleware
	mockMiddleware.AssertExpectations(t)
}
