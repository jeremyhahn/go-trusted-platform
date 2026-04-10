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
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNewTokenProvider(t *testing.T) {
	t.Run("creates provider with default options", func(t *testing.T) {
		p := NewTokenProvider()

		if p == nil {
			t.Fatal("NewTokenProvider returned nil")
		}
		if p.Type() != AuthTypeToken {
			t.Errorf("Type() = %v, want %v", p.Type(), AuthTypeToken)
		}
	})

	t.Run("creates provider with token", func(t *testing.T) {
		token := "test-api-token"
		p := NewTokenProvider(WithToken(token))

		if p.Token() != token {
			t.Errorf("Token() = %v, want %v", p.Token(), token)
		}
	})

	t.Run("creates provider with TLS config", func(t *testing.T) {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
		p := NewTokenProvider(WithTokenTLSConfig(tlsConfig))

		if p.GetTLSConfig() == nil {
			t.Error("GetTLSConfig() should not be nil")
		}
		if p.GetTLSConfig().MinVersion != tls.VersionTLS13 {
			t.Error("TLS config should have TLS 1.3 minimum")
		}
	})
}

func TestTokenProvider_GetToken(t *testing.T) {
	t.Run("returns token when set", func(t *testing.T) {
		token := "test-token"
		p := NewTokenProvider(WithToken(token))

		got, err := p.GetToken(context.Background())
		if err != nil {
			t.Fatalf("GetToken() error = %v", err)
		}
		if got != token {
			t.Errorf("GetToken() = %v, want %v", got, token)
		}
	})

	t.Run("returns ErrNoToken when no token set", func(t *testing.T) {
		p := NewTokenProvider()

		_, err := p.GetToken(context.Background())
		if !errors.Is(err, ErrNoToken) {
			t.Errorf("GetToken() error = %v, want %v", err, ErrNoToken)
		}
	})

	t.Run("returns ErrTokenExpired for expired JWT", func(t *testing.T) {
		// Create an expired JWT
		expiredToken := createTestJWT(t, time.Now().Add(-time.Hour).Unix())
		p := NewTokenProvider(WithToken(expiredToken))

		_, err := p.GetToken(context.Background())
		var expiredErr ErrTokenExpired
		if !errors.As(err, &expiredErr) {
			t.Errorf("GetToken() error = %v, want ErrTokenExpired", err)
		}
	})

	t.Run("returns valid token for non-expired JWT", func(t *testing.T) {
		// Create a valid JWT
		validToken := createTestJWT(t, time.Now().Add(time.Hour).Unix())
		p := NewTokenProvider(WithToken(validToken))

		got, err := p.GetToken(context.Background())
		if err != nil {
			t.Fatalf("GetToken() error = %v", err)
		}
		if got != validToken {
			t.Errorf("GetToken() = %v, want %v", got, validToken)
		}
	})
}

func TestTokenProvider_IsExpired(t *testing.T) {
	t.Run("returns false for API token without exp", func(t *testing.T) {
		p := NewTokenProvider(WithToken("api-token-without-exp"))

		if p.IsExpired() {
			t.Error("IsExpired() should return false for API token")
		}
	})

	t.Run("returns false for valid JWT", func(t *testing.T) {
		validToken := createTestJWT(t, time.Now().Add(time.Hour).Unix())
		p := NewTokenProvider(WithToken(validToken))

		if p.IsExpired() {
			t.Error("IsExpired() should return false for valid JWT")
		}
	})

	t.Run("returns true for expired JWT", func(t *testing.T) {
		expiredToken := createTestJWT(t, time.Now().Add(-time.Hour).Unix())
		p := NewTokenProvider(WithToken(expiredToken))

		if !p.IsExpired() {
			t.Error("IsExpired() should return true for expired JWT")
		}
	})
}

func TestTokenProvider_Refresh(t *testing.T) {
	t.Run("returns ErrNoRefreshCallback when no callback", func(t *testing.T) {
		p := NewTokenProvider(WithToken("old-token"))

		err := p.Refresh(context.Background())
		if !errors.Is(err, ErrNoRefreshCallback) {
			t.Errorf("Refresh() error = %v, want %v", err, ErrNoRefreshCallback)
		}
	})

	t.Run("refreshes token successfully", func(t *testing.T) {
		newToken := "new-refreshed-token"
		callback := func(ctx context.Context) (string, error) {
			return newToken, nil
		}

		p := NewTokenProvider(
			WithToken("old-token"),
			WithRefreshCallback(callback),
		)

		err := p.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}

		if p.Token() != newToken {
			t.Errorf("Token() = %v, want %v", p.Token(), newToken)
		}
	})

	t.Run("returns ErrTokenRefreshFailed on callback error", func(t *testing.T) {
		callbackErr := errors.New("refresh failed")
		callback := func(ctx context.Context) (string, error) {
			return "", callbackErr
		}

		p := NewTokenProvider(
			WithToken("old-token"),
			WithRefreshCallback(callback),
		)

		err := p.Refresh(context.Background())
		var refreshErr ErrTokenRefreshFailed
		if !errors.As(err, &refreshErr) {
			t.Errorf("Refresh() error = %v, want ErrTokenRefreshFailed", err)
		}
		if !errors.Is(err, callbackErr) {
			t.Errorf("Refresh() underlying error should be callback error")
		}
	})
}

func TestTokenProvider_SetToken(t *testing.T) {
	t.Run("updates token value", func(t *testing.T) {
		p := NewTokenProvider(WithToken("initial-token"))

		p.SetToken("updated-token")

		if p.Token() != "updated-token" {
			t.Errorf("Token() = %v, want 'updated-token'", p.Token())
		}
	})

	t.Run("extracts expiration from new JWT", func(t *testing.T) {
		p := NewTokenProvider()

		exp := time.Now().Add(2 * time.Hour).Unix()
		jwt := createTestJWT(t, exp)
		p.SetToken(jwt)

		if p.Expiration() != exp {
			t.Errorf("Expiration() = %v, want %v", p.Expiration(), exp)
		}
	})
}

func TestTokenProvider_Expiration(t *testing.T) {
	t.Run("returns 0 for API token", func(t *testing.T) {
		p := NewTokenProvider(WithToken("api-token"))

		if p.Expiration() != 0 {
			t.Errorf("Expiration() = %v, want 0", p.Expiration())
		}
	})

	t.Run("returns exp claim for JWT", func(t *testing.T) {
		exp := time.Now().Add(time.Hour).Unix()
		jwt := createTestJWT(t, exp)
		p := NewTokenProvider(WithToken(jwt))

		if p.Expiration() != exp {
			t.Errorf("Expiration() = %v, want %v", p.Expiration(), exp)
		}
	})
}

func TestTokenProvider_ExpiresIn(t *testing.T) {
	t.Run("returns 0 for API token", func(t *testing.T) {
		p := NewTokenProvider(WithToken("api-token"))

		if p.ExpiresIn() != 0 {
			t.Errorf("ExpiresIn() = %v, want 0", p.ExpiresIn())
		}
	})

	t.Run("returns positive duration for valid JWT", func(t *testing.T) {
		exp := time.Now().Add(time.Hour).Unix()
		jwt := createTestJWT(t, exp)
		p := NewTokenProvider(WithToken(jwt))

		expiresIn := p.ExpiresIn()
		if expiresIn <= 0 {
			t.Errorf("ExpiresIn() = %v, want positive duration", expiresIn)
		}
		// Should be approximately 1 hour (within a few seconds)
		if expiresIn < 59*time.Minute || expiresIn > 61*time.Minute {
			t.Errorf("ExpiresIn() = %v, expected ~1 hour", expiresIn)
		}
	})

	t.Run("returns 0 for expired JWT", func(t *testing.T) {
		exp := time.Now().Add(-time.Hour).Unix()
		jwt := createTestJWT(t, exp)
		p := NewTokenProvider(WithToken(jwt))

		if p.ExpiresIn() != 0 {
			t.Errorf("ExpiresIn() = %v, want 0", p.ExpiresIn())
		}
	})
}

func TestTokenProvider_Type(t *testing.T) {
	t.Run("returns AuthTypeToken", func(t *testing.T) {
		p := NewTokenProvider()

		if p.Type() != AuthTypeToken {
			t.Errorf("Type() = %v, want %v", p.Type(), AuthTypeToken)
		}
	})
}

func TestTokenProvider_GetTLSConfig(t *testing.T) {
	t.Run("returns nil when no config set", func(t *testing.T) {
		p := NewTokenProvider()

		if p.GetTLSConfig() != nil {
			t.Error("GetTLSConfig() should return nil")
		}
	})

	t.Run("returns configured TLS config", func(t *testing.T) {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: "example.com",
		}
		p := NewTokenProvider(WithTokenTLSConfig(tlsConfig))

		got := p.GetTLSConfig()
		if got == nil {
			t.Fatal("GetTLSConfig() should not be nil")
		}
		if got.MinVersion != tls.VersionTLS13 {
			t.Error("TLS config MinVersion mismatch")
		}
		if got.ServerName != "example.com" {
			t.Error("TLS config ServerName mismatch")
		}
	})
}

func TestTokenProvider_ConcurrentAccess(t *testing.T) {
	t.Run("handles concurrent token updates", func(t *testing.T) {
		p := NewTokenProvider(WithToken("initial"))

		var wg sync.WaitGroup
		iterations := 100

		// Concurrent writers
		for i := range iterations {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				p.SetToken("token-" + string(rune('a'+idx%26)))
			}(i)
		}

		// Concurrent readers
		for range iterations {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = p.Token()
				_ = p.IsExpired()
				_ = p.Expiration()
			}()
		}

		wg.Wait()
		// Test passes if no race condition detected
	})

	t.Run("handles concurrent GetToken calls", func(t *testing.T) {
		jwt := createTestJWT(t, time.Now().Add(time.Hour).Unix())
		p := NewTokenProvider(WithToken(jwt))

		var wg sync.WaitGroup
		iterations := 100

		for range iterations {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = p.GetToken(context.Background())
			}()
		}

		wg.Wait()
		// Test passes if no race condition detected
	})
}

func TestExtractJWTExpiration(t *testing.T) {
	t.Run("extracts exp from valid JWT", func(t *testing.T) {
		exp := time.Now().Add(time.Hour).Unix()
		jwt := createTestJWT(t, exp)

		got := extractJWTExpiration(jwt)
		if got != exp {
			t.Errorf("extractJWTExpiration() = %v, want %v", got, exp)
		}
	})

	t.Run("returns 0 for non-JWT token", func(t *testing.T) {
		got := extractJWTExpiration("not-a-jwt")
		if got != 0 {
			t.Errorf("extractJWTExpiration() = %v, want 0", got)
		}
	})

	t.Run("returns 0 for JWT without exp claim", func(t *testing.T) {
		jwt := createTestJWTWithoutExp(t)
		got := extractJWTExpiration(jwt)
		if got != 0 {
			t.Errorf("extractJWTExpiration() = %v, want 0", got)
		}
	})

	t.Run("returns 0 for malformed payload", func(t *testing.T) {
		// JWT with invalid base64 in payload
		got := extractJWTExpiration("header.!!!invalid!!!.signature")
		if got != 0 {
			t.Errorf("extractJWTExpiration() = %v, want 0", got)
		}
	})

	t.Run("returns 0 for non-JSON payload", func(t *testing.T) {
		// JWT with valid base64 but non-JSON payload
		payload := base64.URLEncoding.EncodeToString([]byte("not json"))
		got := extractJWTExpiration("header." + payload + ".signature")
		if got != 0 {
			t.Errorf("extractJWTExpiration() = %v, want 0", got)
		}
	})
}

func TestBase64URLDecode(t *testing.T) {
	t.Run("decodes standard base64url", func(t *testing.T) {
		input := base64.URLEncoding.EncodeToString([]byte("hello"))
		got, err := base64URLDecode(input)
		if err != nil {
			t.Fatalf("base64URLDecode() error = %v", err)
		}
		if string(got) != "hello" {
			t.Errorf("base64URLDecode() = %v, want 'hello'", string(got))
		}
	})

	t.Run("handles missing padding", func(t *testing.T) {
		// Base64 without padding
		input := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte("test"))
		got, err := base64URLDecode(input)
		if err != nil {
			t.Fatalf("base64URLDecode() error = %v", err)
		}
		if string(got) != "test" {
			t.Errorf("base64URLDecode() = %v, want 'test'", string(got))
		}
	})
}

// createTestJWT creates a test JWT with the given expiration time.
// This creates a minimal JWT for testing without cryptographic signing.
func createTestJWT(t *testing.T, exp int64) string {
	t.Helper()

	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(headerJSON)

	payload := map[string]any{
		"sub": "1234567890",
		"exp": exp,
		"iat": time.Now().Unix(),
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(payloadJSON)

	// Fake signature (not cryptographically valid, but sufficient for testing)
	signature := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte("test-signature"))

	return headerB64 + "." + payloadB64 + "." + signature
}

// createTestJWTWithoutExp creates a test JWT without an exp claim.
func createTestJWTWithoutExp(t *testing.T) string {
	t.Helper()

	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(headerJSON)

	payload := map[string]any{
		"sub": "1234567890",
		"iat": time.Now().Unix(),
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(payloadJSON)

	signature := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte("test-signature"))

	return headerB64 + "." + payloadB64 + "." + signature
}
