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

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// stubAuth is an AuthMiddleware whose Verify either admits or denies.
type stubAuth struct {
	admit  bool
	called bool
}

func (s *stubAuth) RefreshToken(w http.ResponseWriter, req *http.Request) {}

func (s *stubAuth) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	s.called = true
	if !s.admit {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	next(w, r)
}

// TestAuthenticator_NilReturnsNil is the contract callers depend on to
// fail closed: no auth seam means the routes must not be registered.
func TestAuthenticator_NilReturnsNil(t *testing.T) {
	assert.Nil(t, Authenticator(nil))
}

func TestAuthenticator(t *testing.T) {
	tests := []struct {
		name   string
		admit  bool
		status int
	}{
		{"admits an authenticated request", true, http.StatusOK},
		{"denies an unauthenticated request", false, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &stubAuth{admit: tt.admit}
			reached := false
			handler := Authenticator(auth)(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					reached = true
					w.WriteHeader(http.StatusOK)
				}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

			assert.True(t, auth.called)
			assert.Equal(t, tt.status, rec.Code)
			assert.Equal(t, tt.admit, reached)
		})
	}
}
