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
	"crypto/elliptic"
	"crypto/rsa"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// maxClockSkew is the hard upper bound on clock-skew tolerance accepted during
// token validation. No configuration can exceed this value.
const maxClockSkew = 60 * time.Second

// JWTMiddleware handles JWT token validation and extraction.
type JWTMiddleware struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	config         JWTConfig
	iamService     IAMServiceClient
	signingMethod  jwt.SigningMethod
	// allowedAlgs is the set of algorithm strings accepted during header
	// validation. It is derived from the verification key type and never
	// includes symmetric (HMAC) algorithms.
	allowedAlgs map[string]struct{}
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

	// Symmetric (HMAC) keys are not accepted. Every token must be signed with
	// an asymmetric algorithm whose type is known at construction time.
	if config.PublicKey == nil {
		return nil, ErrInvalidConfig{
			Field:  "publicKey",
			Reason: "asymmetric public key is required; symmetric HMAC signing is not supported",
		}
	}

	// Derive the permitted algorithms from the verification key's actual type.
	// The allowlist is exact: a P-256 key permits only ES256, a P-384 key only
	// ES384, etc. This prevents algorithm confusion (e.g. RS256 token accepted
	// by an EdDSA verifier) regardless of what the token header claims.
	signingMethod, allowedAlgs, err := signingMethodFromKey(config.PublicKey)
	if err != nil {
		return nil, err
	}

	// Cap clock skew so callers cannot accidentally set an unreasonably wide
	// window. The zero value means no skew is tolerated (strict mode).
	skew := config.ClockSkew
	if skew > maxClockSkew {
		skew = maxClockSkew
	}
	config.ClockSkew = skew

	return &JWTMiddleware{
		logger:         logger,
		responseWriter: responseWriter,
		config:         config,
		iamService:     iamService,
		signingMethod:  signingMethod,
		allowedAlgs:    allowedAlgs,
	}, nil
}

// signingMethodFromKey resolves the canonical jwt.SigningMethod and the set of
// allowed algorithm strings for a given public key. Only asymmetric algorithms
// are permitted; the allowlist is derived from the key's concrete type and
// curve so that the JWT header "alg" field cannot be used to confuse the
// verifier into accepting a weaker algorithm.
func signingMethodFromKey(pub any) (jwt.SigningMethod, map[string]struct{}, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		// Map curve to the matching ES* variant so a P-384 key never accepts
		// an ES256 token (which uses a P-256 curve internally).
		switch k.Curve {
		case elliptic.P256():
			return jwt.SigningMethodES256, map[string]struct{}{jwt.SigningMethodES256.Alg(): {}}, nil
		case elliptic.P384():
			return jwt.SigningMethodES384, map[string]struct{}{jwt.SigningMethodES384.Alg(): {}}, nil
		case elliptic.P521():
			return jwt.SigningMethodES512, map[string]struct{}{jwt.SigningMethodES512.Alg(): {}}, nil
		default:
			return nil, nil, ErrInvalidConfig{Field: "publicKey", Reason: "unsupported ECDSA curve"}
		}
	case ed25519.PublicKey:
		return jwt.SigningMethodEdDSA, map[string]struct{}{jwt.SigningMethodEdDSA.Alg(): {}}, nil
	case *rsa.PublicKey:
		// The platform signer issues PS256/PS384/PS512 (RSASSA-PSS) or
		// RS256/RS384/RS512 (PKCS1v15) depending on the key attributes.
		// Accept all RSA algorithms that match the key size; the token
		// header alg will be checked against this allowlist.
		allowed := map[string]struct{}{
			jwt.SigningMethodRS256.Alg(): {},
			jwt.SigningMethodRS384.Alg(): {},
			jwt.SigningMethodRS512.Alg(): {},
			jwt.SigningMethodPS256.Alg(): {},
			jwt.SigningMethodPS384.Alg(): {},
			jwt.SigningMethodPS512.Alg(): {},
		}
		// Default to RS256 as the primary method; the actual alg used by a
		// token is checked against the allowlist in keyFunc.
		return jwt.SigningMethodRS256, allowed, nil
	default:
		return nil, nil, ErrInvalidConfig{Field: "publicKey", Reason: "unsupported key type"}
	}
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
	// Build the set of algorithm strings accepted by the parser. For RSA keys
	// the allowlist covers all RS*/PS* variants; for ECDSA/EdDSA it is a
	// single string. jwt.WithValidMethods rejects tokens whose header "alg"
	// is not in this list before the signature is verified.
	allowedAlgs := make([]string, 0, len(m.allowedAlgs))
	for alg := range m.allowedAlgs {
		allowedAlgs = append(allowedAlgs, alg)
	}

	// Parse the token with the derived allowlist. The parser also validates
	// exp/nbf/iat via the standard claims so basic temporal checks happen
	// before our secondary validation below.
	token, err := jwt.Parse(tokenString, m.keyFunc, jwt.WithValidMethods(allowedAlgs))
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

	// Hard-require the exp claim. A token without exp is never valid — it
	// would otherwise be accepted forever because the zero-value check below
	// would be skipped.
	if _, hasExp := mapClaims["exp"]; !hasExp {
		return nil, ErrTokenMissingExp{}
	}

	claims, err := m.extractClaims(mapClaims)
	if err != nil {
		return nil, err
	}

	// Secondary temporal validation with explicit clock-skew tolerance.
	// These checks are in addition to the parser's built-in validation so
	// that the clock-skew cap (maxClockSkew) is always enforced.
	now := time.Now()

	// exp must be present (enforced above) and must not be in the past
	// beyond the allowed clock skew.
	if claims.ExpiresAt.IsZero() || claims.ExpiresAt.Add(m.config.ClockSkew).Before(now) {
		return nil, ErrTokenExpired{ExpiredAt: claims.ExpiresAt.Format(time.RFC3339)}
	}

	// nbf: if present, the token must not be used before its valid-from time
	// (allowing for clock skew).
	if !claims.NotBefore.IsZero() && now.Add(m.config.ClockSkew).Before(claims.NotBefore) {
		return nil, ErrTokenNotYetValid{NotBefore: claims.NotBefore.Format(time.RFC3339)}
	}

	// iat: if present, it must not be in the future beyond the clock skew.
	// A future iat indicates a clock problem or token forgery.
	if !claims.IssuedAt.IsZero() && claims.IssuedAt.After(now.Add(m.config.ClockSkew)) {
		return nil, ErrTokenInvalid{Reason: "iat claim is in the future"}
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

	return claims, nil
}

// keyFunc returns the public key for validating the token signature.
// It also enforces the algorithm allowlist so a token whose header "alg"
// names a method not derived from the configured key type is rejected even
// if the jwt.Parse WithValidMethods check somehow passed.
func (m *JWTMiddleware) keyFunc(token *jwt.Token) (any, error) {
	if _, ok := m.allowedAlgs[token.Method.Alg()]; !ok {
		return nil, ErrAlgorithmNotAllowed{Algorithm: token.Method.Alg()}
	}
	return m.config.PublicKey, nil
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
// The middleware is verification-only: it holds a public key and cannot sign
// tokens. Token generation is the responsibility of the JWT service
// (pkg/webservice/v1/jwt/service.go) which holds the private signer.
func (m *JWTMiddleware) GenerateToken(session IAMSession, ttl time.Duration) (string, error) {
	// The middleware is configured with a public key for verification only.
	// Private-key signing must be done via the platform JWT service.
	return "", ErrInvalidConfig{
		Field:  "signingKey",
		Reason: "private key required for token generation; use the platform JWT service",
	}
}

// RefreshToken generates a new token from an existing valid token.
func (m *JWTMiddleware) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Extract the existing token
	tokenString, err := m.extractToken(r)
	if err != nil {
		m.responseWriter.Error401(w, r, err)
		return
	}

	// Build the per-instance allowlist so the same algorithm restrictions that
	// apply during regular validation also apply during refresh.
	allowedAlgs := make([]string, 0, len(m.allowedAlgs))
	for alg := range m.allowedAlgs {
		allowedAlgs = append(allowedAlgs, alg)
	}

	// Validate the existing token (allowing expired tokens for refresh)
	token, err := jwt.Parse(tokenString, m.keyFunc, jwt.WithValidMethods(allowedAlgs))
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
		user, err := m.iamService.GetUser(ctx, claims.TenantID, claims.Subject)
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
