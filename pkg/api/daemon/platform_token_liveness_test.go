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

package daemon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

// =============================================================================
// STAGE 4(a) — config validation (authz-mode + liveness)
// =============================================================================

func TestNewPlatformTokenValidator_AuthzModeConfig(t *testing.T) {
	const (
		issuer  = "https://broker.test"
		jwksURL = "https://broker.test/jwks"
		introsp = "https://broker.test/introspect"
	)

	t.Run("hybrid without introspection URL fails closed", func(t *testing.T) {
		_, err := newPlatformTokenValidator(PlatformTokenConfig{
			Enabled: true, Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "hybrid",
		}, nil, nil)
		var cfgErr ErrPlatformTokenConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "introspection-url" {
			t.Fatalf("expected introspection-url config error, got %v", err)
		}
	})

	t.Run("online without introspection URL fails closed", func(t *testing.T) {
		_, err := newPlatformTokenValidator(PlatformTokenConfig{
			Enabled: true, Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "online",
		}, nil, nil)
		var cfgErr ErrPlatformTokenConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "introspection-url" {
			t.Fatalf("expected introspection-url config error, got %v", err)
		}
	})

	t.Run("empty mode defaults to hybrid and also requires URL", func(t *testing.T) {
		_, err := newPlatformTokenValidator(PlatformTokenConfig{
			Enabled: true, Issuer: issuer, JWKSURL: jwksURL,
		}, nil, nil)
		var cfgErr ErrPlatformTokenConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "introspection-url" {
			t.Fatalf("empty mode should default to hybrid and require URL, got %v", err)
		}
	})

	t.Run("offline without introspection URL succeeds", func(t *testing.T) {
		v, err := newPlatformTokenValidator(PlatformTokenConfig{
			Enabled: true, Issuer: issuer, JWKSURL: jwksURL, AuthzMode: "offline",
		}, nil, nil)
		if err != nil {
			t.Fatalf("offline mode must not require an introspection URL: %v", err)
		}
		if v == nil {
			t.Fatal("expected validator")
		}
	})

	t.Run("hybrid with introspection URL succeeds", func(t *testing.T) {
		v, err := newPlatformTokenValidator(PlatformTokenConfig{
			Enabled: true, Issuer: issuer, JWKSURL: jwksURL,
			AuthzMode: "hybrid", IntrospectionURL: introsp,
		}, nil, nil)
		if err != nil {
			t.Fatalf("hybrid with URL must succeed: %v", err)
		}
		if v == nil {
			t.Fatal("expected validator")
		}
	})

	t.Run("bad authz-mode string fails", func(t *testing.T) {
		_, err := newPlatformTokenValidator(PlatformTokenConfig{
			Enabled: true, Issuer: issuer, JWKSURL: jwksURL,
			AuthzMode: "sometimes", IntrospectionURL: introsp,
		}, nil, nil)
		var modeErr ErrInvalidAuthzMode
		if !errors.As(err, &modeErr) {
			t.Fatalf("expected ErrInvalidAuthzMode, got %T: %v", err, err)
		}
	})
}

// =============================================================================
// STAGE 4(b) — adapter pipeline: scope + liveness
// =============================================================================

// newLivenessValidator builds an adapter whose validator verifies tokens against
// the in-memory JWKS and confirms liveness against the supplied RFC 7662
// introspection endpoint. mode selects online or hybrid.
func newLivenessValidator(t *testing.T, jwksURL, introspectionURL, mode string) *platformTokenValidator {
	t.Helper()
	v, err := newPlatformTokenValidator(PlatformTokenConfig{
		Enabled:          true,
		Issuer:           testPTIssuer,
		JWKSURL:          jwksURL,
		Audience:         testPTAudience,
		AllowBearer:      true,
		AuthzMode:        mode,
		IntrospectionURL: introspectionURL,
	}, nil, nil)
	if err != nil {
		t.Fatalf("newPlatformTokenValidator: %v", err)
	}
	return v
}

// introspectionServer returns an httptest server whose RFC 7662 response is
// driven by active/status. It records the number of POSTs received.
func introspectionServer(t *testing.T, active bool, status int) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if active {
			_, _ = w.Write([]byte(`{"active":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// TestIntrospectionChecker_AuthVariants exercises the Bearer and Basic-auth
// credential branches of the introspection-checker builder by asserting the
// constructed validator confirms liveness against an endpoint that requires the
// matching credentials.
func TestIntrospectionChecker_AuthVariants(t *testing.T) {
	key := newPTIssuerKey(t)
	jwks := key.jwksHandler(t)
	tok := key.sign(t, "user-1", "tenant-a", []string{"dns:write"})

	t.Run("bearer credential", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer introspect-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"active":true}`))
		}))
		defer srv.Close()

		v, err := newPlatformTokenValidator(PlatformTokenConfig{
			Enabled: true, Issuer: testPTIssuer, JWKSURL: jwks.URL, Audience: testPTAudience,
			AllowBearer: true, AuthzMode: "online", IntrospectionURL: srv.URL,
			IntrospectionBearerToken: "introspect-secret",
		}, nil, nil)
		if err != nil {
			t.Fatalf("construct: %v", err)
		}
		if _, err := v.AuthorizeToken(context.Background(), tok, "dns:write", "", "", ""); err != nil {
			t.Fatalf("bearer-authenticated introspection failed: %v", err)
		}
	})

	t.Run("basic credential", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok || user != "rs-client" || pass != "rs-pw" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"active":true}`))
		}))
		defer srv.Close()

		v, err := newPlatformTokenValidator(PlatformTokenConfig{
			Enabled: true, Issuer: testPTIssuer, JWKSURL: jwks.URL, Audience: testPTAudience,
			AllowBearer: true, AuthzMode: "online", IntrospectionURL: srv.URL,
			IntrospectionClientID: "rs-client", IntrospectionClientSecret: "rs-pw",
		}, nil, nil)
		if err != nil {
			t.Fatalf("construct: %v", err)
		}
		if _, err := v.AuthorizeToken(context.Background(), tok, "dns:write", "", "", ""); err != nil {
			t.Fatalf("basic-authenticated introspection failed: %v", err)
		}
	})
}

func TestErrInvalidAuthzMode_Error(t *testing.T) {
	if (ErrInvalidAuthzMode{Value: "weekly"}).Error() == "" {
		t.Error("ErrInvalidAuthzMode.Error() must not be empty")
	}
}

func TestAuthorizeToken_RequiredPerm_ScopeDecision(t *testing.T) {
	key := newPTIssuerKey(t)
	jwks := key.jwksHandler(t)
	introsp, _ := introspectionServer(t, true, http.StatusOK)
	v := newLivenessValidator(t, jwks.URL, introsp.URL, "hybrid")

	tok := key.sign(t, "user-1", "tenant-a", []string{"dns:write"})

	// Granted scope -> allowed.
	if _, err := v.AuthorizeToken(context.Background(), tok, "dns:write", "", "", ""); err != nil {
		t.Fatalf("granted scope denied: %v", err)
	}

	// Missing scope -> ScopeDeniedError (the validator denies before liveness).
	_, err := v.AuthorizeToken(context.Background(), tok, "dns:delete", "", "", "")
	var scopeErr *platformtoken.ScopeDeniedError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("expected ScopeDeniedError for ungranted scope, got %T: %v", err, err)
	}
}

func TestAuthorizeToken_EmptyPerm_SkipsScopeRunsLiveness(t *testing.T) {
	key := newPTIssuerKey(t)
	jwks := key.jwksHandler(t)
	introsp, calls := introspectionServer(t, true, http.StatusOK)
	v := newLivenessValidator(t, jwks.URL, introsp.URL, "online")

	// A token with NO scopes: requiredPerm="" must skip the scope check but still
	// run the online liveness check (one introspection POST).
	tok := key.sign(t, "user-1", "tenant-a", nil)
	if _, err := v.AuthorizeToken(context.Background(), tok, "", "", "", ""); err != nil {
		t.Fatalf("scope-free authenticated request denied: %v", err)
	}
	if atomic.LoadInt32(calls) != 1 {
		t.Fatalf("expected exactly one introspection call, got %d", atomic.LoadInt32(calls))
	}
}

func TestAuthorizeToken_InactiveIntrospection_TokenInactive(t *testing.T) {
	key := newPTIssuerKey(t)
	jwks := key.jwksHandler(t)
	introsp, _ := introspectionServer(t, false, http.StatusOK)
	v := newLivenessValidator(t, jwks.URL, introsp.URL, "online")

	tok := key.sign(t, "user-1", "tenant-a", []string{"dns:write"})
	_, err := v.AuthorizeToken(context.Background(), tok, "dns:write", "", "", "")
	var inactive *platformtoken.TokenInactiveError
	if !errors.As(err, &inactive) {
		t.Fatalf("expected TokenInactiveError for inactive introspection, got %T: %v", err, err)
	}
}

func TestAuthorizeToken_IntrospectionServerError_LivenessFailClosed(t *testing.T) {
	key := newPTIssuerKey(t)
	jwks := key.jwksHandler(t)
	introsp, _ := introspectionServer(t, true, http.StatusInternalServerError)
	v := newLivenessValidator(t, jwks.URL, introsp.URL, "online")

	tok := key.sign(t, "user-1", "tenant-a", []string{"dns:write"})
	_, err := v.AuthorizeToken(context.Background(), tok, "dns:write", "", "", "")
	var live *platformtoken.LivenessCheckError
	if !errors.As(err, &live) {
		t.Fatalf("expected LivenessCheckError (fail-closed) on 5xx, got %T: %v", err, err)
	}
}
