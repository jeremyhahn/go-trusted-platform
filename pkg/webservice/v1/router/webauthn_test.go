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

func TestNewWebAuthnRouter(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	mockHandler := &MockWebAuthnRestHandler{}

	router := NewWebAuthnRouter(mockMiddleware, mockHandler)

	require.NotNil(t, router)
	webAuthnRouter, ok := router.(*WebAuthnRouter)
	require.True(t, ok)
	assert.NotNil(t, webAuthnRouter.middleware)
	assert.NotNil(t, webAuthnRouter.webAuthnRestService)
	assert.Equal(t, mockMiddleware, webAuthnRouter.middleware)
	assert.Equal(t, mockHandler, webAuthnRouter.webAuthnRestService)
}

func TestWebAuthnRouter_RegisterRoutes(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	mockHandler := &MockWebAuthnRestHandler{}

	webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
	muxRouter := mux.NewRouter()

	// RegisterRoutes should not panic
	require.NotPanics(t, func() {
		webAuthnRouter.RegisterRoutes(muxRouter)
	})
}

func TestWebAuthnRouter_BeginRegistration(t *testing.T) {
	t.Run("successful begin registration", func(t *testing.T) {
		mockMiddleware := &MockJsonWebTokenMiddleware{}
		mockHandler := &MockWebAuthnRestHandler{}
		mockHandler.On("BeginRegistration", mock.Anything, mock.Anything).Return()

		webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
		muxRouter := mux.NewRouter()
		webAuthnRouter.RegisterRoutes(muxRouter)

		req := httptest.NewRequest(http.MethodPost, "/webauthn/registration/begin", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "test-challenge")
		mockHandler.AssertExpectations(t)
	})

	t.Run("endpoint is registered", func(t *testing.T) {
		mockMiddleware := &MockJsonWebTokenMiddleware{}
		mockHandler := &MockWebAuthnRestHandler{}
		mockHandler.On("BeginRegistration", mock.Anything, mock.Anything).Return()

		webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
		muxRouter := mux.NewRouter()
		webAuthnRouter.RegisterRoutes(muxRouter)

		req := httptest.NewRequest(http.MethodPost, "/webauthn/registration/begin", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		assert.NotEqual(t, http.StatusNotFound, rec.Code)
	})
}

func TestWebAuthnRouter_FinishRegistration(t *testing.T) {
	t.Run("successful finish registration", func(t *testing.T) {
		mockMiddleware := &MockJsonWebTokenMiddleware{}
		mockHandler := &MockWebAuthnRestHandler{}
		mockHandler.On("FinishRegistration", mock.Anything, mock.Anything).Return()

		webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
		muxRouter := mux.NewRouter()
		webAuthnRouter.RegisterRoutes(muxRouter)

		req := httptest.NewRequest(http.MethodPost, "/webauthn/registration/finish", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "success")
		mockHandler.AssertExpectations(t)
	})
}

func TestWebAuthnRouter_BeginLogin(t *testing.T) {
	t.Run("successful begin login", func(t *testing.T) {
		mockMiddleware := &MockJsonWebTokenMiddleware{}
		mockHandler := &MockWebAuthnRestHandler{}
		mockHandler.On("BeginLogin", mock.Anything, mock.Anything).Return()

		webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
		muxRouter := mux.NewRouter()
		webAuthnRouter.RegisterRoutes(muxRouter)

		req := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "login-challenge")
		mockHandler.AssertExpectations(t)
	})
}

func TestWebAuthnRouter_FinishLogin(t *testing.T) {
	t.Run("successful finish login", func(t *testing.T) {
		mockMiddleware := &MockJsonWebTokenMiddleware{}
		mockHandler := &MockWebAuthnRestHandler{}
		mockHandler.On("FinishLogin", mock.Anything, mock.Anything).Return()

		webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
		muxRouter := mux.NewRouter()
		webAuthnRouter.RegisterRoutes(muxRouter)

		req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "auth-token")
		mockHandler.AssertExpectations(t)
	})
}

func TestWebAuthnRouter_RegistrationStatus(t *testing.T) {
	t.Run("successful registration status", func(t *testing.T) {
		mockMiddleware := &MockJsonWebTokenMiddleware{}
		mockHandler := &MockWebAuthnRestHandler{}
		mockHandler.On("RegistrationStatus", mock.Anything, mock.Anything).Return()

		webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
		muxRouter := mux.NewRouter()
		webAuthnRouter.RegisterRoutes(muxRouter)

		req := httptest.NewRequest(http.MethodGet, "/webauthn/registration/status", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "registered")
		mockHandler.AssertExpectations(t)
	})
}

func TestWebAuthnRouter_NotFoundRoutes(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "invalid webauthn endpoint",
			path: "/webauthn/invalid-endpoint",
		},
		{
			name: "missing path segment",
			path: "/webauthn/registration",
		},
		{
			name: "wrong path structure",
			path: "/webauthn/login/start",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMiddleware := &MockJsonWebTokenMiddleware{}
			mockHandler := &MockWebAuthnRestHandler{}

			webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
			muxRouter := mux.NewRouter()
			webAuthnRouter.RegisterRoutes(muxRouter)

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			muxRouter.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusNotFound, rec.Code)
		})
	}
}

func TestWebAuthnRouter_RegistrationFlow(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	mockHandler := &MockWebAuthnRestHandler{}
	mockHandler.On("BeginRegistration", mock.Anything, mock.Anything).Return()
	mockHandler.On("FinishRegistration", mock.Anything, mock.Anything).Return()

	webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
	muxRouter := mux.NewRouter()
	webAuthnRouter.RegisterRoutes(muxRouter)

	// Begin registration
	beginReq := httptest.NewRequest(http.MethodPost, "/webauthn/registration/begin", nil)
	beginRec := httptest.NewRecorder()
	muxRouter.ServeHTTP(beginRec, beginReq)

	assert.Equal(t, http.StatusOK, beginRec.Code)
	assert.Contains(t, beginRec.Body.String(), "test-challenge")

	// Finish registration
	finishReq := httptest.NewRequest(http.MethodPost, "/webauthn/registration/finish", nil)
	finishRec := httptest.NewRecorder()
	muxRouter.ServeHTTP(finishRec, finishReq)

	assert.Equal(t, http.StatusOK, finishRec.Code)
	assert.Contains(t, finishRec.Body.String(), "success")

	mockHandler.AssertExpectations(t)
}

func TestWebAuthnRouter_LoginFlow(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	mockHandler := &MockWebAuthnRestHandler{}
	mockHandler.On("BeginLogin", mock.Anything, mock.Anything).Return()
	mockHandler.On("FinishLogin", mock.Anything, mock.Anything).Return()

	webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
	muxRouter := mux.NewRouter()
	webAuthnRouter.RegisterRoutes(muxRouter)

	// Begin login
	beginReq := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", nil)
	beginRec := httptest.NewRecorder()
	muxRouter.ServeHTTP(beginRec, beginReq)

	assert.Equal(t, http.StatusOK, beginRec.Code)
	assert.Contains(t, beginRec.Body.String(), "login-challenge")

	// Finish login
	finishReq := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", nil)
	finishRec := httptest.NewRecorder()
	muxRouter.ServeHTTP(finishRec, finishReq)

	assert.Equal(t, http.StatusOK, finishRec.Code)
	assert.Contains(t, finishRec.Body.String(), "auth-token")

	mockHandler.AssertExpectations(t)
}

func TestWebAuthnRouter_ConcurrentRequests(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	mockHandler := &MockWebAuthnRestHandler{}
	mockHandler.On("BeginRegistration", mock.Anything, mock.Anything).Return()

	webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
	muxRouter := mux.NewRouter()
	webAuthnRouter.RegisterRoutes(muxRouter)

	// Test concurrent registration requests
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodPost, "/webauthn/registration/begin", nil)
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

func TestWebAuthnRouter_NilParameters(t *testing.T) {
	t.Run("constructor accepts nil middleware", func(t *testing.T) {
		mockHandler := &MockWebAuthnRestHandler{}

		router := NewWebAuthnRouter(nil, mockHandler)

		require.NotNil(t, router)
		webAuthnRouter, ok := router.(*WebAuthnRouter)
		require.True(t, ok)
		assert.Nil(t, webAuthnRouter.middleware)
		assert.NotNil(t, webAuthnRouter.webAuthnRestService)
	})

	t.Run("constructor accepts nil handler", func(t *testing.T) {
		mockMiddleware := &MockJsonWebTokenMiddleware{}

		router := NewWebAuthnRouter(mockMiddleware, nil)

		require.NotNil(t, router)
		webAuthnRouter, ok := router.(*WebAuthnRouter)
		require.True(t, ok)
		assert.NotNil(t, webAuthnRouter.middleware)
		assert.Nil(t, webAuthnRouter.webAuthnRestService)
	})
}

func TestWebAuthnRouter_MultipleRouteRegistrations(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	mockHandler := &MockWebAuthnRestHandler{}
	mockHandler.On("BeginRegistration", mock.Anything, mock.Anything).Return()

	webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
	muxRouter := mux.NewRouter()

	// Register routes multiple times should not cause issues
	webAuthnRouter.RegisterRoutes(muxRouter)
	webAuthnRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodPost, "/webauthn/registration/begin", nil)
	rec := httptest.NewRecorder()

	muxRouter.ServeHTTP(rec, req)

	// Should still work
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestWebAuthnRouter_CORSHeaders(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	mockHandler := &MockWebAuthnRestHandler{}
	mockHandler.On("RegistrationStatus", mock.Anything, mock.Anything).Return()

	webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
	muxRouter := mux.NewRouter()
	webAuthnRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodGet, "/webauthn/registration/status", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()

	muxRouter.ServeHTTP(rec, req)

	// Test passes if router doesn't break with CORS headers present
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestWebAuthnRouter_PathPrefix(t *testing.T) {
	mockMiddleware := &MockJsonWebTokenMiddleware{}
	mockHandler := &MockWebAuthnRestHandler{}
	mockHandler.On("BeginRegistration", mock.Anything, mock.Anything).Return()

	webAuthnRouter := NewWebAuthnRouter(mockMiddleware, mockHandler)
	muxRouter := mux.NewRouter()
	webAuthnRouter.RegisterRoutes(muxRouter)

	t.Run("webauthn prefix is required", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/registration/begin", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		// Should not match without /webauthn prefix
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("webauthn prefix works correctly", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webauthn/registration/begin", nil)
		rec := httptest.NewRecorder()

		muxRouter.ServeHTTP(rec, req)

		// Should match with /webauthn prefix
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
