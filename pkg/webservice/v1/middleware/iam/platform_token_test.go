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
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

const (
	testBrokerIssuer   = "https://broker.test"
	testBrokerAudience = "api://platform"
	testBrokerKID      = "broker-kid-1"
)

// brokerKey is a test broker signing key plus its published JWKS.
type brokerKey struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func newBrokerKey(t *testing.T) *brokerKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("broker key: %v", err)
	}
	return &brokerKey{priv: priv, kid: testBrokerKID}
}

func (k *brokerKey) jwks() *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       k.priv.Public(),
		KeyID:     k.kid,
		Algorithm: "ES256",
		Use:       "sig",
	}}}
}

// brokerClaims is the platform-token claim set a test signs.
type brokerClaims struct {
	iss   string
	aud   []string
	sub   string
	tid   string
	scp   []string
	roles []string
	exp   time.Time
	iat   time.Time
	jkt   string
}

func (k *brokerKey) sign(t *testing.T, c brokerClaims) string {
	t.Helper()
	m := jwt.MapClaims{
		"iss": c.iss,
		"aud": c.aud,
		"sub": c.sub,
		"exp": c.exp.Unix(),
		"iat": c.iat.Unix(),
		"jti": "jti-" + c.sub,
	}
	if c.tid != "" {
		m["tenant_id"] = c.tid
	}
	if len(c.scp) > 0 {
		m["scp"] = c.scp
	}
	if len(c.roles) > 0 {
		m["roles"] = c.roles
	}
	if c.jkt != "" {
		m["cnf"] = map[string]interface{}{"jkt": c.jkt}
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, m)
	tok.Header["kid"] = k.kid
	// RFC 9068: access tokens must carry typ "at+jwt"; the validator
	// rejects plain "JWT".
	tok.Header["typ"] = "at+jwt"
	s, err := tok.SignedString(k.priv)
	if err != nil {
		t.Fatalf("sign broker token: %v", err)
	}
	return s
}

// newRealValidator builds a real platformtoken.Validator over an in-memory JWKS
// so the middleware tests exercise the production validation path (signature by
// kid + iss + aud + exp + DPoP cnf) without an HTTP key source.
func newRealValidator(t *testing.T, key *brokerKey) *platformtoken.Validator {
	t.Helper()
	v, err := platformtoken.NewValidator(platformtoken.Options{
		Issuer:   testBrokerIssuer,
		Audience: testBrokerAudience,
		JWKS:     key.jwks(),
		// Offline mode: these middleware tests exercise the signature / iss /
		// aud / exp / DPoP path, not online liveness, so no liveness backend is
		// required and the scope-free Validate path returns the projected
		// context without a network round trip.
		ModeResolver: func(string) platformtoken.AuthzMode { return platformtoken.AuthzModeOffline },
		ReplayCache:  quicbaas.NewDPoPMemoryReplayCache(quicbaas.DPoPSystemClock{}),
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

func newTestPlatformMiddleware(t *testing.T, validator platformTokenValidator, allowBearer bool) (*PlatformTokenMiddleware, *mockHttpWriter) {
	t.Helper()
	writer := newMockHttpWriter()
	mw, err := NewPlatformTokenMiddleware(createTestLogger(), writer, validator, PlatformTokenConfig{
		AllowBearer: allowBearer,
	})
	if err != nil {
		t.Fatalf("NewPlatformTokenMiddleware: %v", err)
	}
	return mw, writer
}

func TestNewPlatformTokenMiddleware(t *testing.T) {
	t.Parallel()
	key := newBrokerKey(t)
	validator := newRealValidator(t, key)

	t.Run("valid construction", func(t *testing.T) {
		mw, err := NewPlatformTokenMiddleware(createTestLogger(), newMockHttpWriter(), validator, PlatformTokenConfig{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mw == nil {
			t.Fatal("expected middleware, got nil")
		}
	})

	t.Run("nil logger rejected", func(t *testing.T) {
		_, err := NewPlatformTokenMiddleware(nil, newMockHttpWriter(), validator, PlatformTokenConfig{})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) {
			t.Fatalf("expected ErrInvalidConfig, got %v", err)
		}
	})

	t.Run("nil response writer rejected", func(t *testing.T) {
		_, err := NewPlatformTokenMiddleware(createTestLogger(), nil, validator, PlatformTokenConfig{})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) {
			t.Fatalf("expected ErrInvalidConfig, got %v", err)
		}
	})

	t.Run("nil validator rejected", func(t *testing.T) {
		_, err := NewPlatformTokenMiddleware(createTestLogger(), newMockHttpWriter(), nil, PlatformTokenConfig{})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) {
			t.Fatalf("expected ErrInvalidConfig, got %v", err)
		}
	})
}

func TestPlatformTokenMiddleware_Verify_BearerAllowed(t *testing.T) {
	t.Parallel()
	now := time.Now()
	key := newBrokerKey(t)
	validator := newRealValidator(t, key)
	mw, writer := newTestPlatformMiddleware(t, validator, true)

	token := key.sign(t, brokerClaims{
		iss: testBrokerIssuer, aud: []string{testBrokerAudience},
		sub: "user-1", tid: "tenant-1", scp: []string{"platform.read"},
		exp: now.Add(10 * time.Minute), iat: now,
	})

	var nextCalled bool
	var capturedAuthCtx *platformtoken.AuthorizedContext
	next := func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		capturedAuthCtx, _ = AuthorizedContextFromRequest(r)
	}

	req := httptest.NewRequest(http.MethodGet, "https://platform.test/api/v1/system", nil)
	req.Header.Set(AuthorizationHeader, BearerPrefix+token)
	rec := httptest.NewRecorder()

	mw.Verify(rec, req, next)

	if !nextCalled {
		t.Fatal("expected next to be called for a valid bearer token")
	}
	if writer.getError401Count() != 0 {
		t.Fatalf("expected no 401, got %d", writer.getError401Count())
	}
	if capturedAuthCtx == nil {
		t.Fatal("expected AuthorizedContext in request context")
	}
	if capturedAuthCtx.Subject != "user-1" || capturedAuthCtx.TenantID != "tenant-1" {
		t.Fatalf("unexpected authorized context: %+v", capturedAuthCtx)
	}
	if !capturedAuthCtx.HasScope("platform.read") {
		t.Fatal("expected platform.read scope")
	}

	// The IAMSession must also be populated for tenant RLS + AuthzMiddleware.
	session, ok := GetSessionFromContext(req.Context())
	_ = session
	_ = ok
}

func TestPlatformTokenMiddleware_Verify_BearerRejectedWhenDPoPRequired(t *testing.T) {
	t.Parallel()
	now := time.Now()
	key := newBrokerKey(t)
	validator := newRealValidator(t, key)
	mw, writer := newTestPlatformMiddleware(t, validator, false) // bearer tokens not allowed; DPoP required

	token := key.sign(t, brokerClaims{
		iss: testBrokerIssuer, aud: []string{testBrokerAudience},
		sub: "user-1", tid: "tenant-1", scp: []string{"platform.read"},
		exp: now.Add(10 * time.Minute), iat: now,
	})

	next := func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not be called when DPoP is required but missing")
	}

	req := httptest.NewRequest(http.MethodGet, "https://platform.test/api/v1/system", nil)
	req.Header.Set(AuthorizationHeader, BearerPrefix+token)
	rec := httptest.NewRecorder()

	mw.Verify(rec, req, next)

	if writer.getError401Count() != 1 {
		t.Fatalf("expected one 401, got %d", writer.getError401Count())
	}
}

func TestPlatformTokenMiddleware_Verify_DPoPBound(t *testing.T) {
	t.Parallel()
	now := time.Now()
	key := newBrokerKey(t)
	validator := newRealValidator(t, key)
	mw, writer := newTestPlatformMiddleware(t, validator, false)

	// DPoP key whose thumbprint is bound into the token cnf.jkt.
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("dpop key: %v", err)
	}
	jkt, err := quicbaas.DPoPThumbprint(dpopKey.Public())
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	token := key.sign(t, brokerClaims{
		iss: testBrokerIssuer, aud: []string{testBrokerAudience},
		sub: "svc-1", tid: "tenant-9", scp: []string{"platform.admin"},
		exp: now.Add(10 * time.Minute), iat: now, jkt: jkt,
	})

	const htu = "https://platform.test/api/v1/system"
	proof, err := quicbaas.NewDPoPProof(dpopKey, http.MethodGet, htu)
	if err != nil {
		t.Fatalf("dpop proof: %v", err)
	}

	var nextCalled bool
	var capturedAuthCtx *platformtoken.AuthorizedContext
	next := func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		capturedAuthCtx, _ = AuthorizedContextFromRequest(r)
	}

	req := httptest.NewRequest(http.MethodGet, htu, nil)
	req.Header.Set(AuthorizationHeader, BearerPrefix+token)
	req.Header.Set(DPoPHeader, proof)
	rec := httptest.NewRecorder()

	mw.Verify(rec, req, next)

	if !nextCalled {
		t.Fatal("expected next to be called for a valid DPoP-bound token")
	}
	if writer.getError401Count() != 0 {
		t.Fatalf("expected no 401, got %d", writer.getError401Count())
	}
	if capturedAuthCtx == nil || capturedAuthCtx.Confirmation == nil {
		t.Fatal("expected cnf-bound authorized context")
	}
	if capturedAuthCtx.Confirmation.Jkt != jkt {
		t.Fatalf("cnf.jkt mismatch: want %q got %q", jkt, capturedAuthCtx.Confirmation.Jkt)
	}
}

func TestPlatformTokenMiddleware_Verify_DPoPMismatchRejected(t *testing.T) {
	t.Parallel()
	now := time.Now()
	key := newBrokerKey(t)
	validator := newRealValidator(t, key)
	mw, writer := newTestPlatformMiddleware(t, validator, false)

	legitKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jkt, _ := quicbaas.DPoPThumbprint(legitKey.Public())

	token := key.sign(t, brokerClaims{
		iss: testBrokerIssuer, aud: []string{testBrokerAudience},
		sub: "svc-1", tid: "tenant-9", scp: []string{"platform.read"},
		exp: now.Add(10 * time.Minute), iat: now, jkt: jkt,
	})

	// Attacker holds a different key.
	attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const htu = "https://platform.test/api/v1/system"
	attackerProof, _ := quicbaas.NewDPoPProof(attackerKey, http.MethodGet, htu)

	next := func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not be called on a cnf.jkt mismatch")
	}

	req := httptest.NewRequest(http.MethodGet, htu, nil)
	req.Header.Set(AuthorizationHeader, BearerPrefix+token)
	req.Header.Set(DPoPHeader, attackerProof)
	rec := httptest.NewRecorder()

	mw.Verify(rec, req, next)

	if writer.getError401Count() != 1 {
		t.Fatalf("expected one 401 for cnf mismatch, got %d", writer.getError401Count())
	}
}

func TestPlatformTokenMiddleware_Verify_RejectsBadToken(t *testing.T) {
	t.Parallel()
	now := time.Now()
	key := newBrokerKey(t)
	otherKey := newBrokerKey(t)
	validator := newRealValidator(t, key)
	mw, writer := newTestPlatformMiddleware(t, validator, true)

	cases := []struct {
		name  string
		token string
	}{
		{
			name: "wrong signing key",
			token: otherKey.sign(t, brokerClaims{
				iss: testBrokerIssuer, aud: []string{testBrokerAudience},
				sub: "user-1", exp: now.Add(10 * time.Minute), iat: now,
			}),
		},
		{
			name: "wrong issuer",
			token: key.sign(t, brokerClaims{
				iss: "https://evil.test", aud: []string{testBrokerAudience},
				sub: "user-1", exp: now.Add(10 * time.Minute), iat: now,
			}),
		},
		{
			name: "wrong audience",
			token: key.sign(t, brokerClaims{
				iss: testBrokerIssuer, aud: []string{"api://other"},
				sub: "user-1", exp: now.Add(10 * time.Minute), iat: now,
			}),
		},
		{
			name: "expired token",
			token: key.sign(t, brokerClaims{
				iss: testBrokerIssuer, aud: []string{testBrokerAudience},
				sub: "user-1", exp: now.Add(-1 * time.Minute), iat: now.Add(-10 * time.Minute),
			}),
		},
		{
			name:  "garbage token",
			token: "not-a-jwt",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := writer.getError401Count()
			next := func(w http.ResponseWriter, r *http.Request) {
				t.Fatalf("next must not be called for %s", tc.name)
			}
			req := httptest.NewRequest(http.MethodGet, "https://platform.test/api/v1/system", nil)
			req.Header.Set(AuthorizationHeader, BearerPrefix+tc.token)
			rec := httptest.NewRecorder()

			mw.Verify(rec, req, next)

			if writer.getError401Count() != before+1 {
				t.Fatalf("%s: expected a 401", tc.name)
			}
		})
	}
}

func TestPlatformTokenMiddleware_Verify_MissingToken(t *testing.T) {
	t.Parallel()
	key := newBrokerKey(t)
	validator := newRealValidator(t, key)
	mw, writer := newTestPlatformMiddleware(t, validator, true)

	next := func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not be called without a token")
	}
	req := httptest.NewRequest(http.MethodGet, "https://platform.test/api/v1/system", nil)
	rec := httptest.NewRecorder()

	mw.Verify(rec, req, next)

	if writer.getError401Count() != 1 {
		t.Fatalf("expected one 401 for missing token, got %d", writer.getError401Count())
	}
}

func TestPlatformTokenMiddleware_RequireScope(t *testing.T) {
	t.Parallel()
	now := time.Now()
	key := newBrokerKey(t)
	validator := newRealValidator(t, key)
	mw, writer := newTestPlatformMiddleware(t, validator, true)

	token := key.sign(t, brokerClaims{
		iss: testBrokerIssuer, aud: []string{testBrokerAudience},
		sub: "user-1", tid: "tenant-1", scp: []string{"platform.read"},
		exp: now.Add(10 * time.Minute), iat: now,
	})

	protected := func(scope string) http.Handler {
		final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		// Verify -> RequireScope -> final
		return mw.Handler(mw.RequireScope(scope)(final))
	}

	t.Run("granted scope allows", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://platform.test/api/v1/system", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+token)
		rec := httptest.NewRecorder()

		protected("platform.read").ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("missing scope denies with 403", func(t *testing.T) {
		before := writer.getError403Count()
		req := httptest.NewRequest(http.MethodGet, "https://platform.test/api/v1/system", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+token)
		rec := httptest.NewRecorder()

		protected("platform.admin").ServeHTTP(rec, req)

		if writer.getError403Count() != before+1 {
			t.Fatal("expected a 403 for the missing scope")
		}
	})
}

func TestPlatformTokenMiddleware_RequireRole(t *testing.T) {
	t.Parallel()
	now := time.Now()
	key := newBrokerKey(t)
	validator := newRealValidator(t, key)
	mw, writer := newTestPlatformMiddleware(t, validator, true)

	token := key.sign(t, brokerClaims{
		iss: testBrokerIssuer, aud: []string{testBrokerAudience},
		sub: "user-1", tid: "tenant-1", roles: []string{"operator"},
		exp: now.Add(10 * time.Minute), iat: now,
	})

	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("granted role allows", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://platform.test/api/v1/system", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+token)
		rec := httptest.NewRecorder()

		mw.Handler(mw.RequireRole("operator")(final)).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("missing role denies with 403", func(t *testing.T) {
		before := writer.getError403Count()
		req := httptest.NewRequest(http.MethodGet, "https://platform.test/api/v1/system", nil)
		req.Header.Set(AuthorizationHeader, BearerPrefix+token)
		rec := httptest.NewRecorder()

		mw.Handler(mw.RequireRole("admin")(final)).ServeHTTP(rec, req)

		if writer.getError403Count() != before+1 {
			t.Fatal("expected a 403 for the missing role")
		}
	})
}

func TestPlatformTokenMiddleware_RequireScope_NoContext(t *testing.T) {
	t.Parallel()
	key := newBrokerKey(t)
	validator := newRealValidator(t, key)
	mw, writer := newTestPlatformMiddleware(t, validator, true)

	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("final must not run without an authorized context")
	})

	// Call RequireScope directly without Verify having run first.
	req := httptest.NewRequest(http.MethodGet, "https://platform.test/api/v1/system", nil)
	rec := httptest.NewRecorder()
	mw.RequireScope("platform.read")(final).ServeHTTP(rec, req)

	if writer.getError401Count() != 1 {
		t.Fatalf("expected a 401 when no authorized context is present, got %d", writer.getError401Count())
	}
}

func TestPlatformTokenMiddleware_RefreshTokenAlwaysFails(t *testing.T) {
	t.Parallel()
	key := newBrokerKey(t)
	validator := newRealValidator(t, key)
	mw, writer := newTestPlatformMiddleware(t, validator, true)

	req := httptest.NewRequest(http.MethodPost, "https://platform.test/login/refresh", nil)
	rec := httptest.NewRecorder()
	mw.RefreshToken(rec, req)

	if writer.getError401Count() != 1 {
		t.Fatalf("expected refresh to return 401, got %d", writer.getError401Count())
	}
}

func TestRequestURL(t *testing.T) {
	t.Parallel()
	t.Run("tls request yields https htu", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://platform.test/api/v1/system?x=1", nil)
		got := requestURL(req)
		want := "https://platform.test/api/v1/system"
		if got != want {
			t.Fatalf("want %q got %q", want, got)
		}
	})

	t.Run("forwarded proto honored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://platform.test/api/v1/system", nil)
		req.TLS = nil
		req.Header.Set("X-Forwarded-Proto", "https")
		got := requestURL(req)
		want := "https://platform.test/api/v1/system"
		if got != want {
			t.Fatalf("want %q got %q", want, got)
		}
	})
}

func TestNewPlatformTokenValidator(t *testing.T) {
	t.Parallel()
	t.Run("valid params with defaults", func(t *testing.T) {
		// Offline mode needs no introspection URL: a minimal valid config builds.
		v, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer:    testBrokerIssuer,
			JWKSURL:   "https://broker.test/.well-known/jwks.json",
			AuthzMode: string(platformtoken.AuthzModeOffline),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v == nil {
			t.Fatal("expected validator, got nil")
		}
	})

	t.Run("missing issuer rejected", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			JWKSURL: "https://broker.test/.well-known/jwks.json",
		})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) {
			t.Fatalf("expected ErrInvalidConfig, got %v", err)
		}
	})

	t.Run("missing jwks url rejected", func(t *testing.T) {
		_, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer: testBrokerIssuer,
		})
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) {
			t.Fatalf("expected ErrInvalidConfig, got %v", err)
		}
	})

	t.Run("explicit audience and ttl honored", func(t *testing.T) {
		v, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
			Issuer:    testBrokerIssuer,
			JWKSURL:   "https://broker.test/.well-known/jwks.json",
			Audience:  "api://custom",
			CacheTTL:  5 * time.Minute,
			AuthzMode: string(platformtoken.AuthzModeOffline),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v == nil {
			t.Fatal("expected validator, got nil")
		}
	})
}

// fakeValidator lets a test drive arbitrary validator outcomes without crafting
// tokens; used to assert the middleware maps an arbitrary validator error to 401.
type fakeValidator struct {
	claims *platformtoken.Claims
	err    error
}

func (f *fakeValidator) Validate(ctx context.Context, token, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.claims == nil {
		return nil, errors.New("fakeValidator: no claims configured")
	}
	return platformtoken.Authorize(f.claims), nil
}

func TestPlatformTokenMiddleware_Verify_ValidatorErrorMapsTo401(t *testing.T) {
	t.Parallel()
	mw, writer := newTestPlatformMiddleware(t, &fakeValidator{err: errors.New("boom")}, true)

	next := func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not run on validator error")
	}
	req := httptest.NewRequest(http.MethodGet, "https://platform.test/api/v1/system", nil)
	req.Header.Set(AuthorizationHeader, BearerPrefix+"opaque")
	rec := httptest.NewRecorder()

	mw.Verify(rec, req, next)

	if writer.getError401Count() != 1 {
		t.Fatalf("expected one 401, got %d", writer.getError401Count())
	}
}

// TestPlatformTokenMiddleware_RemoteJWKS exercises the production builder path:
// the validator fetches the broker JWKS over HTTP by kid (NewPlatformTokenValidator
// with a JWKSURL) and a DPoP-bound token issued by that broker key validates at
// the middleware. This mirrors the go-quicbaas integration dpop_test.go contract
// (a broker-issued, cnf.jkt-bound token validating at a downstream service) but
// runs fully in-memory via httptest so it stays a fast unit test.
func TestPlatformTokenMiddleware_RemoteJWKS(t *testing.T) {
	t.Parallel()
	now := time.Now()
	key := newBrokerKey(t)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(key.jwks()); err != nil {
			t.Errorf("encode jwks: %v", err)
		}
	}))
	defer jwksServer.Close()

	validator, err := NewPlatformTokenValidator(PlatformTokenValidatorParams{
		Issuer:     testBrokerIssuer,
		JWKSURL:    jwksServer.URL,
		Audience:   testBrokerAudience,
		HTTPClient: jwksServer.Client(),
		// Offline mode: this test exercises the JWKS-by-kid + DPoP path, not
		// online liveness, so no introspection endpoint is required.
		AuthzMode: string(platformtoken.AuthzModeOffline),
	})
	if err != nil {
		t.Fatalf("NewPlatformTokenValidator: %v", err)
	}
	mw, writer := newTestPlatformMiddleware(t, validator, false)

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("dpop key: %v", err)
	}
	jkt, err := quicbaas.DPoPThumbprint(dpopKey.Public())
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	token := key.sign(t, brokerClaims{
		iss: testBrokerIssuer, aud: []string{testBrokerAudience},
		sub: "svc-remote", tid: "tenant-remote", scp: []string{"platform.read"},
		exp: now.Add(10 * time.Minute), iat: now, jkt: jkt,
	})

	const htu = "https://platform.test/api/v1/system"
	proof, err := quicbaas.NewDPoPProof(dpopKey, http.MethodGet, htu)
	if err != nil {
		t.Fatalf("dpop proof: %v", err)
	}

	var capturedAuthCtx *platformtoken.AuthorizedContext
	next := func(w http.ResponseWriter, r *http.Request) {
		capturedAuthCtx, _ = AuthorizedContextFromRequest(r)
	}

	req := httptest.NewRequest(http.MethodGet, htu, nil)
	req.Header.Set(AuthorizationHeader, BearerPrefix+token)
	req.Header.Set(DPoPHeader, proof)
	rec := httptest.NewRecorder()

	mw.Verify(rec, req, next)

	if writer.getError401Count() != 0 {
		t.Fatalf("expected no 401 for a valid remote-JWKS DPoP token, got %d", writer.getError401Count())
	}
	if capturedAuthCtx == nil || capturedAuthCtx.TenantID != "tenant-remote" {
		t.Fatalf("unexpected authorized context: %+v", capturedAuthCtx)
	}
}
