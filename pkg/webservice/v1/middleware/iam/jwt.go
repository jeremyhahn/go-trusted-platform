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

package iam

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// JWTMiddleware handles JWT token validation and extraction.
type JWTMiddleware struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	config         JWTConfig
	iamService     IAMServiceClient
	signingMethod  jwt.SigningMethod
}

// NewJWTMiddleware creates a new JWT middleware instance.
func NewJWTMiddleware(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	config JWTConfig,
	iamService IAMServiceClient,
) (*JWTMiddleware, error) {

	if logger == nil {
		return nil, ErrInvalidConfig{Field: "logger", Reason: "logger is required"}
	}
	if responseWriter == nil {
		return nil, ErrInvalidConfig{Field: "responseWriter", Reason: "response writer is required"}
	}

	// Determine signing method based on key type
	var signingMethod jwt.SigningMethod
	if config.PublicKey != nil {
		switch config.PublicKey.(type) {
		case *rsa.PublicKey:
			signingMethod = jwt.SigningMethodRS256
		case *ecdsa.PublicKey:
			signingMethod = jwt.SigningMethodES256
		case ed25519.PublicKey:
			signingMethod = jwt.SigningMethodEdDSA
		default:
			return nil, ErrInvalidConfig{Field: "publicKey", Reason: "unsupported key type"}
		}
	} else if len(config.SigningKey) > 0 {
		signingMethod = jwt.SigningMethodHS256
	}

	return &JWTMiddleware{
		logger:         logger,
		responseWriter: responseWriter,
		config:         config,
		iamService:     iamService,
		signingMethod:  signingMethod,
	}, nil
}

// Handler returns an http.Handler middleware that validates JWT tokens.
func (m *JWTMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.Verify(w, r, next.ServeHTTP)
	})
}

// Verify validates the JWT token and extracts claims.
func (m *JWTMiddleware) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// Extract token from Authorization header
	tokenString, err := m.extractToken(r)
	if err != nil {
		m.logger.Debugf("jwt: failed to extract token: %v", err)
		m.responseWriter.Error401(w, r, err)
		return
	}

	// Parse and validate the token
	claims, err := m.validateToken(tokenString)
	if err != nil {
		m.logger.Debugf("jwt: token validation failed: %v", err)
		m.responseWriter.Error401(w, r, err)
		return
	}

	// Check MFA requirement
	if m.config.RequireMFA && !claims.MFAVerified {
		m.logger.Debugf("jwt: MFA verification required but not present")
		m.responseWriter.Error401(w, r, ErrMFARequired{})
		return
	}

	// Store claims in context for downstream handlers
	ctx := context.WithValue(r.Context(), jwtClaimsContextKey, claims)

	next(w, r.WithContext(ctx))
}

// extractToken extracts the JWT token from the Authorization header.
func (m *JWTMiddleware) extractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get(AuthorizationHeader)
	if authHeader == "" {
		return "", ErrMissingToken{}
	}

	if !strings.HasPrefix(authHeader, BearerPrefix) {
		return "", ErrTokenInvalid{Reason: "invalid authorization header format"}
	}

	token := strings.TrimPrefix(authHeader, BearerPrefix)
	if token == "" {
		return "", ErrMissingToken{}
	}

	return token, nil
}

// validateToken parses and validates the JWT token.
func (m *JWTMiddleware) validateToken(tokenString string) (*JWTClaims, error) {
	// Parse the token with custom claims
	token, err := jwt.Parse(tokenString, m.keyFunc, jwt.WithValidMethods([]string{m.signingMethod.Alg()}))
	if err != nil {
		return nil, m.translateJWTError(err)
	}

	if !token.Valid {
		return nil, ErrTokenInvalid{Reason: "token is not valid"}
	}

	// Extract claims
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrTokenInvalid{Reason: "invalid claims format"}
	}

	claims, err := m.extractClaims(mapClaims)
	if err != nil {
		return nil, err
	}

	// Validate issuer if configured
	if m.config.Issuer != "" {
		if claims.Issuer != m.config.Issuer {
			return nil, ErrIssuerMismatch{Expected: m.config.Issuer, Actual: claims.Issuer}
		}
	}

	// Validate audience if configured
	if len(m.config.Audience) > 0 {
		if !m.validateAudience(claims.Audience, m.config.Audience) {
			return nil, ErrAudienceMismatch{Expected: m.config.Audience, Actual: claims.Audience}
		}
	}

	// Validate expiration with clock skew
	now := time.Now()
	if !claims.ExpiresAt.IsZero() && claims.ExpiresAt.Add(m.config.ClockSkew).Before(now) {
		return nil, ErrTokenExpired{ExpiredAt: claims.ExpiresAt.Format(time.RFC3339)}
	}

	// Validate not before with clock skew
	if !claims.NotBefore.IsZero() && claims.NotBefore.Add(-m.config.ClockSkew).After(now) {
		return nil, ErrTokenNotYetValid{NotBefore: claims.NotBefore.Format(time.RFC3339)}
	}

	return claims, nil
}

// keyFunc returns the key for validating the token.
func (m *JWTMiddleware) keyFunc(token *jwt.Token) (any, error) {
	// Verify the signing method matches
	if token.Method.Alg() != m.signingMethod.Alg() {
		return nil, ErrTokenInvalid{Reason: "unexpected signing method"}
	}

	if m.config.PublicKey != nil {
		return m.config.PublicKey, nil
	}
	return m.config.SigningKey, nil
}

// extractClaims extracts and converts JWT claims to our JWTClaims structure.
func (m *JWTMiddleware) extractClaims(mapClaims jwt.MapClaims) (*JWTClaims, error) {
	claims := &JWTClaims{
		Custom: make(map[string]any),
	}

	// Standard claims
	if sub, ok := mapClaims["sub"].(string); ok {
		claims.Subject = sub
	}
	if iss, ok := mapClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if email, ok := mapClaims["email"].(string); ok {
		claims.Email = email
	}
	if name, ok := mapClaims["name"].(string); ok {
		claims.Name = name
	}

	// Audience can be string or []string
	switch aud := mapClaims["aud"].(type) {
	case string:
		claims.Audience = []string{aud}
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				claims.Audience = append(claims.Audience, s)
			}
		}
	}

	// Time claims
	if exp, ok := mapClaims["exp"].(float64); ok {
		claims.ExpiresAt = time.Unix(int64(exp), 0)
	}
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.IssuedAt = time.Unix(int64(iat), 0)
	}
	if nbf, ok := mapClaims["nbf"].(float64); ok {
		claims.NotBefore = time.Unix(int64(nbf), 0)
	}

	// Custom claims
	if tenantID, ok := mapClaims["tenant_id"].(string); ok {
		claims.TenantID = tenantID
	}
	if sessionID, ok := mapClaims["session_id"].(string); ok {
		claims.SessionID = sessionID
	}

	// Roles
	switch roles := mapClaims["roles"].(type) {
	case []any:
		for _, r := range roles {
			if s, ok := r.(string); ok {
				claims.Roles = append(claims.Roles, s)
			}
		}
	case []string:
		claims.Roles = roles
	}

	// Groups
	switch groups := mapClaims["groups"].(type) {
	case []any:
		for _, g := range groups {
			if s, ok := g.(string); ok {
				claims.Groups = append(claims.Groups, s)
			}
		}
	case []string:
		claims.Groups = groups
	}

	// MFA status
	if mfaVerified, ok := mapClaims["mfa_verified"].(bool); ok {
		claims.MFAVerified = mfaVerified
	}
	if mfaTimestamp, ok := mapClaims["mfa_timestamp"].(float64); ok {
		claims.MFATimestamp = time.Unix(int64(mfaTimestamp), 0)
	}

	// Store remaining claims as custom
	standardClaims := map[string]struct{}{
		"sub": {}, "iss": {}, "aud": {}, "exp": {}, "iat": {}, "nbf": {},
		"email": {}, "name": {}, "tenant_id": {}, "session_id": {},
		"roles": {}, "groups": {}, "mfa_verified": {}, "mfa_timestamp": {},
	}
	for k, v := range mapClaims {
		if _, isStandard := standardClaims[k]; !isStandard {
			claims.Custom[k] = v
		}
	}

	return claims, nil
}

// validateAudience checks if any of the token audiences match the expected audiences.
func (m *JWTMiddleware) validateAudience(tokenAudiences, expectedAudiences []string) bool {
	for _, tokenAud := range tokenAudiences {
		for _, expectedAud := range expectedAudiences {
			if tokenAud == expectedAud {
				return true
			}
		}
	}
	return false
}

// translateJWTError converts jwt-go errors to our typed errors.
func (m *JWTMiddleware) translateJWTError(err error) error {
	switch {
	case strings.Contains(err.Error(), "token is expired"):
		return ErrTokenExpired{}
	case strings.Contains(err.Error(), "token not valid yet"):
		return ErrTokenNotYetValid{}
	case strings.Contains(err.Error(), "signature is invalid"):
		return ErrTokenInvalid{Reason: "invalid signature"}
	case strings.Contains(err.Error(), "token is malformed"):
		return ErrTokenInvalid{Reason: "malformed token"}
	default:
		return ErrTokenInvalid{Reason: err.Error()}
	}
}

// GenerateToken generates a new JWT token with the provided claims.
func (m *JWTMiddleware) GenerateToken(session IAMSession, ttl time.Duration) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"sub":          session.UserID(),
		"tenant_id":    session.TenantID(),
		"email":        session.Email(),
		"name":         session.Name(),
		"roles":        session.Roles(),
		"groups":       session.Groups(),
		"mfa_verified": session.IsMFAVerified(),
		"iat":          now.Unix(),
		"exp":          now.Add(ttl).Unix(),
	}

	if m.config.Issuer != "" {
		claims["iss"] = m.config.Issuer
	}
	if len(m.config.Audience) > 0 {
		claims["aud"] = m.config.Audience
	}
	if !session.MFATimestamp().IsZero() {
		claims["mfa_timestamp"] = session.MFATimestamp().Unix()
	}

	token := jwt.NewWithClaims(m.signingMethod, claims)

	var key any
	if m.config.PublicKey != nil {
		// For asymmetric algorithms, we need the private key for signing
		// This would typically come from a separate configuration
		return "", ErrInvalidConfig{Field: "signingKey", Reason: "private key required for token generation"}
	}
	key = m.config.SigningKey

	return token.SignedString(key)
}

// RefreshToken generates a new token from an existing valid token.
func (m *JWTMiddleware) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Extract the existing token
	tokenString, err := m.extractToken(r)
	if err != nil {
		m.responseWriter.Error401(w, r, err)
		return
	}

	// Validate the existing token (allowing expired tokens for refresh)
	token, err := jwt.Parse(tokenString, m.keyFunc, jwt.WithValidMethods([]string{m.signingMethod.Alg()}))
	if err != nil && !strings.Contains(err.Error(), "token is expired") {
		m.responseWriter.Error401(w, r, m.translateJWTError(err))
		return
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		m.responseWriter.Error401(w, r, ErrTokenInvalid{Reason: "invalid claims format"})
		return
	}

	claims, err := m.extractClaims(mapClaims)
	if err != nil {
		m.responseWriter.Error401(w, r, err)
		return
	}

	// Look up user in IAM service to ensure they still exist and get updated info
	if m.iamService != nil {
		ctx := r.Context()
		user, err := m.iamService.GetUser(ctx, &iampb.GetUserRequest{
			TenantId: claims.TenantID,
			UserId:   claims.Subject,
		})
		if err != nil {
			m.logger.Debugf("jwt: failed to look up user during refresh: %v", err)
			m.responseWriter.Error401(w, r, ErrUserNotFound{Identifier: claims.Subject})
			return
		}

		// Create new session from fresh user data
		session := NewIAMSessionWithMFA(user, claims.MFAVerified, claims.MFATimestamp)
		newToken, err := m.GenerateToken(session, m.config.AccessTokenTTL)
		if err != nil {
			m.responseWriter.Error500(w, r, err)
			return
		}

		m.responseWriter.Success200(w, r, map[string]any{
			"access_token": newToken,
			"token_type":   "Bearer",
			"expires_in":   int64(m.config.AccessTokenTTL.Seconds()),
		})
		return
	}

	m.responseWriter.Error500(w, r, ErrServiceUnavailable{Service: "IAM"})
}

// GetClaimsFromContext retrieves JWT claims from the request context.
func GetClaimsFromContext(ctx context.Context) (*JWTClaims, bool) {
	claims, ok := ctx.Value(jwtClaimsContextKey).(*JWTClaims)
	return claims, ok
}

// jwtClaimsContextKey is the context key for storing JWT claims.
type jwtClaimsContextKeyType struct{}

var jwtClaimsContextKey = jwtClaimsContextKeyType{}
