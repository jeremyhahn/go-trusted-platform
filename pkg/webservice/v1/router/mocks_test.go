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

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/stretchr/testify/mock"
)

// Mock implementations for all interfaces used by routers

// MockJsonWebTokenMiddleware implements middleware.JsonWebTokenMiddleware for testing
type MockJsonWebTokenMiddleware struct {
	mock.Mock
}

func (m *MockJsonWebTokenMiddleware) CreateSession(w http.ResponseWriter, r *http.Request) (service.Session, error) {
	args := m.Called(w, r)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(service.Session), args.Error(1)
}

func (m *MockJsonWebTokenMiddleware) GenerateToken(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"token":"test-token"}`))
}

func (m *MockJsonWebTokenMiddleware) RefreshToken(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"token":"refreshed-token"}`))
}

func (m *MockJsonWebTokenMiddleware) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	m.Called(w, r, next)
	if next != nil {
		next(w, r)
	}
}

// MockAuthMiddleware implements middleware.AuthMiddleware for testing
type MockAuthMiddleware struct {
	mock.Mock
}

func (m *MockAuthMiddleware) RefreshToken(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
}

func (m *MockAuthMiddleware) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	m.Called(w, r, next)
	if next != nil {
		next(w, r)
	}
}

// MockRestServicer implements handlers.RestServicer for ACME testing
type MockRestServicer struct {
	mock.Mock
}

func (m *MockRestServicer) AccountHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockRestServicer) AuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockRestServicer) CertificateHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockRestServicer) ChallengeHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockRestServicer) DirectoryHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockRestServicer) OrderHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockRestServicer) NewAccountHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusCreated)
}

func (m *MockRestServicer) NewNonceHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.Header().Set("Replay-Nonce", "test-nonce")
	w.WriteHeader(http.StatusNoContent)
}

func (m *MockRestServicer) NewOrderHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusCreated)
}

func (m *MockRestServicer) OrdersListHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockRestServicer) OrderFinalizeHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockRestServicer) RevokeCertHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockRestServicer) KeyChangeHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockRestServicer) CABundleHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockRestServicer) HealthHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockRestServicer) TenantAuthMiddleware(next http.Handler) http.Handler {
	return next
}

// MockWebAuthnRestHandler implements webauthn.RestHandler for testing
// Note: webauthn.RestHandler embeds middleware.AuthMiddleware
type MockWebAuthnRestHandler struct {
	mock.Mock
}

func (m *MockWebAuthnRestHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"challenge":"test-challenge"}`))
}

func (m *MockWebAuthnRestHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"success":true}`))
}

func (m *MockWebAuthnRestHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"challenge":"login-challenge"}`))
}

func (m *MockWebAuthnRestHandler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"token":"auth-token"}`))
}

func (m *MockWebAuthnRestHandler) RegistrationStatus(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"registered":true}`))
}

// AuthMiddleware interface methods
func (m *MockWebAuthnRestHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockWebAuthnRestHandler) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	m.Called(w, r, next)
	if next != nil {
		next(w, r)
	}
}
