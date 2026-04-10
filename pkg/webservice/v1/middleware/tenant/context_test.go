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

package tenant

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestMiddleware(t *testing.T, config MiddlewareConfig) *Middleware {
	t.Helper()
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	m, err := NewMiddleware(logger, respWriter, config)
	require.NoError(t, err)
	return m
}

func createValidJWT(t *testing.T, secret []byte, claims *TenantClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secret)
	require.NoError(t, err)
	return tokenString
}

func TestNewMiddleware_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	m, err := NewMiddleware(logger, respWriter, MiddlewareConfig{
		JWTSecret: []byte("test-secret"),
	})

	require.NoError(t, err)
	assert.NotNil(t, m)
}

func TestNewMiddleware_NilLogger(t *testing.T) {
	respWriter := response.NewResponseWriter(logging.DefaultLogger(), nil)

	m, err := NewMiddleware(nil, respWriter, MiddlewareConfig{
		JWTSecret: []byte("test-secret"),
	})

	require.Error(t, err)
	assert.Nil(t, m)
	var configErr ErrInvalidConfig
	assert.ErrorAs(t, err, &configErr)
	assert.Equal(t, "logger", configErr.Field)
}

func TestNewMiddleware_NilResponseWriter(t *testing.T) {
	logger := logging.DefaultLogger()

	m, err := NewMiddleware(logger, nil, MiddlewareConfig{
		JWTSecret: []byte("test-secret"),
	})

	require.Error(t, err)
	assert.Nil(t, m)
	var configErr ErrInvalidConfig
	assert.ErrorAs(t, err, &configErr)
	assert.Equal(t, "responseWriter", configErr.Field)
}

func TestNewMiddleware_NoJWTCredentials(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	m, err := NewMiddleware(logger, respWriter, MiddlewareConfig{})

	require.Error(t, err)
	assert.Nil(t, m)
	var configErr ErrInvalidConfig
	assert.ErrorAs(t, err, &configErr)
	assert.Equal(t, "jwt", configErr.Field)
}

func TestMiddleware_Handler(t *testing.T) {
	secret := []byte("test-secret-key-for-jwt-signing!")
	m := createTestMiddleware(t, MiddlewareConfig{
		JWTSecret:     secret,
		SigningMethod: "HS256",
	})

	claims := &TenantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		TenantID:      "tenant-123",
		UserID:        42,
		Email:         "test@example.com",
		IsTenantOwner: true,
	}
	tokenString := createValidJWT(t, secret, claims)

	var capturedTenantID string
	var capturedUserID uint64
	var capturedIsOwner bool

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenantID = GetTenantID(r.Context())
		capturedUserID = GetUserID(r.Context())
		capturedIsOwner = IsTenantOwner(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "tenant-123", capturedTenantID)
	assert.Equal(t, uint64(42), capturedUserID)
	assert.True(t, capturedIsOwner)
}

func TestMiddleware_MissingAuthorizationHeader(t *testing.T) {
	secret := []byte("test-secret-key-for-jwt-signing!")
	m := createTestMiddleware(t, MiddlewareConfig{
		JWTSecret:     secret,
		SigningMethod: "HS256",
	})

	called := false
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddleware_InvalidBearerFormat(t *testing.T) {
	secret := []byte("test-secret-key-for-jwt-signing!")
	m := createTestMiddleware(t, MiddlewareConfig{
		JWTSecret:     secret,
		SigningMethod: "HS256",
	})

	called := false
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddleware_InvalidToken(t *testing.T) {
	secret := []byte("test-secret-key-for-jwt-signing!")
	m := createTestMiddleware(t, MiddlewareConfig{
		JWTSecret:     secret,
		SigningMethod: "HS256",
	})

	called := false
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-string")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddleware_MissingUserID(t *testing.T) {
	secret := []byte("test-secret-key-for-jwt-signing!")
	m := createTestMiddleware(t, MiddlewareConfig{
		JWTSecret:     secret,
		SigningMethod: "HS256",
	})

	claims := &TenantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		TenantID: "tenant-123",
		UserID:   0, // missing user ID
	}
	tokenString := createValidJWT(t, secret, claims)

	called := false
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddleware_RequireTenantID(t *testing.T) {
	secret := []byte("test-secret-key-for-jwt-signing!")
	m := createTestMiddleware(t, MiddlewareConfig{
		JWTSecret:       secret,
		SigningMethod:   "HS256",
		RequireTenantID: true,
	})

	claims := &TenantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		TenantID: "", // missing tenant ID when required
		UserID:   42,
	}
	tokenString := createValidJWT(t, secret, claims)

	called := false
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddleware_CookieAuth(t *testing.T) {
	secret := []byte("test-secret-key-for-jwt-signing!")
	m := createTestMiddleware(t, MiddlewareConfig{
		JWTSecret:     secret,
		SigningMethod: "HS256",
		AllowCookie:   true,
	})

	claims := &TenantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		TenantID: "tenant-cookie",
		UserID:   99,
	}
	tokenString := createValidJWT(t, secret, claims)

	var capturedTenantID string
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenantID = GetTenantID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  AuthCookieName,
		Value: tokenString,
	})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "tenant-cookie", capturedTenantID)
}

func TestMiddleware_WrongSigningMethod(t *testing.T) {
	secret := []byte("test-secret-key-for-jwt-signing!")
	m := createTestMiddleware(t, MiddlewareConfig{
		JWTSecret:     secret,
		SigningMethod: "HS384", // require HS384
	})

	// Token signed with HS256
	claims := &TenantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		TenantID: "tenant-123",
		UserID:   42,
	}
	tokenString := createValidJWT(t, secret, claims) // uses HS256

	called := false
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// Context helper function tests

func TestGetTenantID(t *testing.T) {
	t.Run("returns tenant ID from context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), TenantIDKey, "tenant-abc")
		assert.Equal(t, "tenant-abc", GetTenantID(ctx))
	})

	t.Run("returns empty string when not set", func(t *testing.T) {
		assert.Equal(t, "", GetTenantID(context.Background()))
	})

	t.Run("returns empty string for wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), TenantIDKey, 123)
		assert.Equal(t, "", GetTenantID(ctx))
	})
}

func TestGetUserID(t *testing.T) {
	t.Run("returns user ID from context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserIDKey, uint64(42))
		assert.Equal(t, uint64(42), GetUserID(ctx))
	})

	t.Run("returns zero when not set", func(t *testing.T) {
		assert.Equal(t, uint64(0), GetUserID(context.Background()))
	})

	t.Run("returns zero for wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserIDKey, "not-a-uint64")
		assert.Equal(t, uint64(0), GetUserID(ctx))
	})
}

func TestIsTenantOwner(t *testing.T) {
	t.Run("returns true when owner", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), IsTenantOwnerKey, true)
		assert.True(t, IsTenantOwner(ctx))
	})

	t.Run("returns false when not owner", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), IsTenantOwnerKey, false)
		assert.False(t, IsTenantOwner(ctx))
	})

	t.Run("returns false when not set", func(t *testing.T) {
		assert.False(t, IsTenantOwner(context.Background()))
	})
}

func TestGetUserEmail(t *testing.T) {
	t.Run("returns email from context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserEmailKey, "test@example.com")
		assert.Equal(t, "test@example.com", GetUserEmail(ctx))
	})

	t.Run("returns empty string when not set", func(t *testing.T) {
		assert.Equal(t, "", GetUserEmail(context.Background()))
	})
}

func TestSetTenantContext(t *testing.T) {
	ctx := SetTenantContext(context.Background(), "tenant-xyz", 77, true)

	assert.Equal(t, "tenant-xyz", GetTenantID(ctx))
	assert.Equal(t, uint64(77), GetUserID(ctx))
	assert.True(t, IsTenantOwner(ctx))
}

func TestSetTenantContext_NonOwner(t *testing.T) {
	ctx := SetTenantContext(context.Background(), "tenant-abc", 1, false)

	assert.Equal(t, "tenant-abc", GetTenantID(ctx))
	assert.Equal(t, uint64(1), GetUserID(ctx))
	assert.False(t, IsTenantOwner(ctx))
}

// Error tests

func TestErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{
			name:     "ErrMissingAuthorizationHeader",
			err:      ErrMissingAuthorizationHeader{},
			contains: "missing authorization header",
		},
		{
			name:     "ErrInvalidAuthorizationFormat with reason",
			err:      ErrInvalidAuthorizationFormat{Reason: "test reason"},
			contains: "test reason",
		},
		{
			name:     "ErrInvalidAuthorizationFormat without reason",
			err:      ErrInvalidAuthorizationFormat{},
			contains: "invalid authorization format",
		},
		{
			name:     "ErrInvalidToken with reason",
			err:      ErrInvalidToken{Reason: "expired"},
			contains: "expired",
		},
		{
			name:     "ErrInvalidToken without reason",
			err:      ErrInvalidToken{},
			contains: "invalid token",
		},
		{
			name:     "ErrTokenExpired",
			err:      ErrTokenExpired{},
			contains: "expired",
		},
		{
			name:     "ErrMissingTenantClaim",
			err:      ErrMissingTenantClaim{},
			contains: "tenant_id",
		},
		{
			name:     "ErrMissingUserClaim",
			err:      ErrMissingUserClaim{},
			contains: "user_id",
		},
		{
			name:     "ErrInvalidConfig with reason",
			err:      ErrInvalidConfig{Field: "jwt", Reason: "missing"},
			contains: "missing",
		},
		{
			name:     "ErrInvalidConfig without reason",
			err:      ErrInvalidConfig{Field: "jwt"},
			contains: "jwt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Contains(t, tt.err.Error(), tt.contains)
		})
	}
}
