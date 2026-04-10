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

package auth

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"
)

// TokenProvider implements token-based authentication.
// It supports both JWT tokens (with expiration checking) and API tokens.
// Thread-safe using atomic operations.
type TokenProvider struct {
	token           atomic.Pointer[string]
	expiration      atomic.Int64
	refreshCallback atomic.Pointer[RefreshCallback]
	tlsConfig       atomic.Pointer[tls.Config]
}

// TokenOption configures a TokenProvider.
type TokenOption func(*TokenProvider)

// WithToken sets the initial authentication token.
func WithToken(token string) TokenOption {
	return func(p *TokenProvider) {
		p.setToken(token)
	}
}

// WithRefreshCallback sets the callback function for token refresh.
func WithRefreshCallback(callback RefreshCallback) TokenOption {
	return func(p *TokenProvider) {
		p.refreshCallback.Store(&callback)
	}
}

// WithTokenTLSConfig sets the TLS configuration for secure connections.
// This allows using tokens over TLS without client certificates.
func WithTokenTLSConfig(config *tls.Config) TokenOption {
	return func(p *TokenProvider) {
		p.tlsConfig.Store(config)
	}
}

// NewTokenProvider creates a new token-based authentication provider.
func NewTokenProvider(opts ...TokenOption) *TokenProvider {
	p := &TokenProvider{}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// GetToken returns the current authentication token.
// Returns ErrNoToken if no token is set.
// Returns ErrTokenExpired if the token has expired.
func (p *TokenProvider) GetToken(ctx context.Context) (string, error) {
	tokenPtr := p.token.Load()
	if tokenPtr == nil || *tokenPtr == "" {
		return "", ErrNoToken
	}

	if p.IsExpired() {
		return "", ErrTokenExpired{ExpiredAt: p.expiration.Load()}
	}

	return *tokenPtr, nil
}

// GetTLSConfig returns the TLS configuration.
// May return nil if no TLS config is set.
func (p *TokenProvider) GetTLSConfig() *tls.Config {
	return p.tlsConfig.Load()
}

// Refresh refreshes the authentication token using the configured callback.
// Returns ErrNoRefreshCallback if no callback is configured.
func (p *TokenProvider) Refresh(ctx context.Context) error {
	callbackPtr := p.refreshCallback.Load()
	if callbackPtr == nil {
		return ErrNoRefreshCallback
	}

	callback := *callbackPtr
	newToken, err := callback(ctx)
	if err != nil {
		return ErrTokenRefreshFailed{Err: err}
	}

	p.setToken(newToken)
	return nil
}

// IsExpired checks if the token has expired.
// Returns false for non-JWT tokens (no expiration).
func (p *TokenProvider) IsExpired() bool {
	exp := p.expiration.Load()
	if exp == 0 {
		// No expiration set (API token or non-JWT)
		return false
	}
	return time.Now().Unix() >= exp
}

// Type returns AuthTypeToken.
func (p *TokenProvider) Type() AuthType {
	return AuthTypeToken
}

// SetToken updates the authentication token.
// This parses JWT tokens to extract expiration time.
func (p *TokenProvider) SetToken(token string) {
	p.setToken(token)
}

// setToken is the internal implementation for setting tokens.
func (p *TokenProvider) setToken(token string) {
	p.token.Store(&token)

	// Try to extract expiration from JWT
	exp := extractJWTExpiration(token)
	p.expiration.Store(exp)
}

// Token returns the current token without expiration checks.
// This is useful for debugging or logging (with appropriate redaction).
func (p *TokenProvider) Token() string {
	tokenPtr := p.token.Load()
	if tokenPtr == nil {
		return ""
	}
	return *tokenPtr
}

// Expiration returns the token expiration time as Unix timestamp.
// Returns 0 if no expiration is set (API token or non-JWT).
func (p *TokenProvider) Expiration() int64 {
	return p.expiration.Load()
}

// ExpiresIn returns the duration until the token expires.
// Returns 0 if no expiration is set or the token is already expired.
func (p *TokenProvider) ExpiresIn() time.Duration {
	exp := p.expiration.Load()
	if exp == 0 {
		return 0
	}

	remaining := exp - time.Now().Unix()
	if remaining <= 0 {
		return 0
	}

	return time.Duration(remaining) * time.Second
}

// extractJWTExpiration extracts the exp claim from a JWT token.
// Returns 0 if the token is not a valid JWT or has no exp claim.
// This does not verify the token signature - server-side verification is expected.
func extractJWTExpiration(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		// Not a JWT
		return 0
	}

	// Decode the payload (second part)
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return 0
	}

	// Parse as JSON
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0
	}

	// Extract exp claim
	expVal, ok := claims["exp"]
	if !ok {
		return 0
	}

	// Handle both float64 (JSON numbers) and int64
	switch v := expVal.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	default:
		return 0
	}
}

// base64URLDecode decodes a base64url-encoded string.
// It handles missing padding.
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	return base64.URLEncoding.DecodeString(s)
}

// Ensure TokenProvider implements Provider interface.
var _ Provider = (*TokenProvider)(nil)
