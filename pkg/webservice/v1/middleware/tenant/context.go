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

// Package tenant provides middleware for extracting and managing tenant context
// from JWT tokens in HTTP requests.
package tenant

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// contextKey is a typed key for context values to avoid collisions.
type contextKey string

const (
	// TenantIDKey is the context key for storing the tenant ID.
	TenantIDKey contextKey = "tenant_id"

	// UserIDKey is the context key for storing the user ID.
	UserIDKey contextKey = "user_id"

	// IsTenantOwnerKey is the context key for storing the tenant owner flag.
	IsTenantOwnerKey contextKey = "is_tenant_owner"

	// UserEmailKey is the context key for storing the user email.
	UserEmailKey contextKey = "user_email"

	// AuthorizationHeader is the standard HTTP authorization header name.
	AuthorizationHeader = "Authorization"

	// BearerPrefix is the prefix for Bearer token authentication.
	BearerPrefix = "Bearer "

	// AuthCookieName is the name of the cookie that may contain the JWT.
	AuthCookieName = "auth_token"
)

// TenantClaims represents the JWT claims structure with tenant information.
type TenantClaims struct {
	jwt.RegisteredClaims
	TenantID string `json:"tenant_id,omitempty"`
	// UID is the platform user id as a decimal string, as the platform
	// issuer writes it: user ids are xxhash64 values above 2^53, which a
	// JSON number cannot carry exactly (#642). ExtractTenantContext
	// parses it with strconv.ParseUint.
	UID           string   `json:"uid,omitempty"`
	Email         string   `json:"email,omitempty"`
	IsTenantOwner bool     `json:"is_tenant_owner,omitempty"`
	Roles         []string `json:"roles,omitempty"`
}

// MiddlewareConfig holds configuration for the tenant context middleware.
type MiddlewareConfig struct {
	// JWTSecret is the secret key for validating JWT signatures.
	JWTSecret []byte

	// JWTPublicKey is the public key for asymmetric JWT validation.
	JWTPublicKey interface{}

	// SigningMethod specifies the JWT signing method (e.g., HS256, RS256).
	SigningMethod string

	// RequireTenantID requires the tenant_id claim to be present.
	RequireTenantID bool

	// AllowCookie allows JWT to be extracted from a cookie.
	AllowCookie bool
}

// Middleware provides tenant context extraction from JWT tokens.
type Middleware struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	config         MiddlewareConfig
}

// NewMiddleware creates a new tenant context middleware.
func NewMiddleware(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	config MiddlewareConfig,
) (*Middleware, error) {
	if logger == nil {
		return nil, ErrInvalidConfig{Field: "logger", Reason: "logger is required"}
	}
	if responseWriter == nil {
		return nil, ErrInvalidConfig{Field: "responseWriter", Reason: "response writer is required"}
	}
	if len(config.JWTSecret) == 0 && config.JWTPublicKey == nil {
		return nil, ErrInvalidConfig{Field: "jwt", Reason: "either JWTSecret or JWTPublicKey is required"}
	}

	return &Middleware{
		logger:         logger,
		responseWriter: responseWriter,
		config:         config,
	}, nil
}

// Handler returns an http.Handler middleware that extracts tenant context.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.ExtractTenantContext(w, r, next.ServeHTTP)
	})
}

// ExtractTenantContext extracts tenant information from the JWT token
// and adds it to the request context.
func (m *Middleware) ExtractTenantContext(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// Extract token from Authorization header or cookie
	tokenString, err := m.extractToken(r)
	if err != nil {
		m.logger.Debugf("tenant: failed to extract token: %v", err)
		m.responseWriter.Error401(w, r, err)
		return
	}

	// Parse and validate token
	claims, err := m.parseToken(tokenString)
	if err != nil {
		m.logger.Debugf("tenant: failed to parse token: %v", err)
		m.responseWriter.Error401(w, r, err)
		return
	}

	// Validate required claims
	if m.config.RequireTenantID && claims.TenantID == "" {
		m.logger.Debugf("tenant: missing tenant_id claim")
		m.responseWriter.Error401(w, r, ErrMissingTenantClaim{})
		return
	}

	userID, err := strconv.ParseUint(claims.UID, 10, 64)
	if err != nil || userID == 0 {
		m.logger.Debugf("tenant: missing or malformed uid claim")
		m.responseWriter.Error401(w, r, ErrMissingUserClaim{})
		return
	}

	// Add tenant context to request
	ctx := r.Context()
	ctx = context.WithValue(ctx, TenantIDKey, claims.TenantID)
	ctx = context.WithValue(ctx, UserIDKey, userID)
	ctx = context.WithValue(ctx, IsTenantOwnerKey, claims.IsTenantOwner)
	ctx = context.WithValue(ctx, UserEmailKey, claims.Email)

	next(w, r.WithContext(ctx))
}

// extractToken extracts the JWT token from the request.
func (m *Middleware) extractToken(r *http.Request) (string, error) {
	// Try Authorization header first
	authHeader := r.Header.Get(AuthorizationHeader)
	if authHeader != "" {
		if !strings.HasPrefix(authHeader, BearerPrefix) {
			return "", ErrInvalidAuthorizationFormat{Reason: "expected Bearer token"}
		}
		return strings.TrimPrefix(authHeader, BearerPrefix), nil
	}

	// Try cookie if allowed
	if m.config.AllowCookie {
		cookie, err := r.Cookie(AuthCookieName)
		if err == nil && cookie.Value != "" {
			return cookie.Value, nil
		}
	}

	return "", ErrMissingAuthorizationHeader{}
}

// parseToken parses and validates the JWT token.
func (m *Middleware) parseToken(tokenString string) (*TenantClaims, error) {
	claims := &TenantClaims{}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Validate signing method if specified
		if m.config.SigningMethod != "" {
			if token.Method.Alg() != m.config.SigningMethod {
				return nil, ErrInvalidToken{Reason: "unexpected signing method"}
			}
		}

		// Return appropriate key based on configuration
		if m.config.JWTPublicKey != nil {
			return m.config.JWTPublicKey, nil
		}
		return m.config.JWTSecret, nil
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			return nil, ErrTokenExpired{}
		}
		return nil, ErrInvalidToken{Reason: err.Error()}
	}

	if !token.Valid {
		return nil, ErrInvalidToken{Reason: "token validation failed"}
	}

	return claims, nil
}

// GetTenantID retrieves the tenant ID from the request context.
func GetTenantID(ctx context.Context) string {
	tenantID, ok := ctx.Value(TenantIDKey).(string)
	if !ok {
		return ""
	}
	return tenantID
}

// GetUserID retrieves the user ID from the request context.
func GetUserID(ctx context.Context) uint64 {
	userID, ok := ctx.Value(UserIDKey).(uint64)
	if !ok {
		return 0
	}
	return userID
}

// IsTenantOwner checks if the current user is the tenant owner.
func IsTenantOwner(ctx context.Context) bool {
	isOwner, ok := ctx.Value(IsTenantOwnerKey).(bool)
	if !ok {
		return false
	}
	return isOwner
}

// GetUserEmail retrieves the user email from the request context.
func GetUserEmail(ctx context.Context) string {
	email, ok := ctx.Value(UserEmailKey).(string)
	if !ok {
		return ""
	}
	return email
}

// SetTenantContext sets tenant context values in a context.
// This is useful for testing and internal service calls.
func SetTenantContext(ctx context.Context, tenantID string, userID uint64, isOwner bool) context.Context {
	ctx = context.WithValue(ctx, TenantIDKey, tenantID)
	ctx = context.WithValue(ctx, UserIDKey, userID)
	ctx = context.WithValue(ctx, IsTenantOwnerKey, isOwner)
	return ctx
}
