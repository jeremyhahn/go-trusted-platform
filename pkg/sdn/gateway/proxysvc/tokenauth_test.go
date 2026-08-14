// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package proxysvc

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

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

const (
	testIssuer = "https://broker.example.gov"
	testKID    = "proxy-test-kid"
)

// tokenIssuer is an in-test ES256 platform-token issuer with a JWKS
// endpoint.
type tokenIssuer struct {
	key    *ecdsa.PrivateKey
	server *httptest.Server
}

func newTokenIssuer(t *testing.T) *tokenIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key.Public(),
		KeyID:     testKID,
		Algorithm: "ES256",
		Use:       "sig",
	}}}
	body, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(body); err != nil {
			t.Errorf("write jwks: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return &tokenIssuer{key: key, server: server}
}

// issuedToken describes one test token.
type issuedToken struct {
	subject  string
	tenantID string
	scopes   []string
	roles    []string
	audience string
	jkt      string
	expired  bool
}

func (ti *tokenIssuer) sign(t *testing.T, tok issuedToken) string {
	t.Helper()
	if tok.audience == "" {
		tok.audience = DefaultTokenAudience
	}
	now := time.Now()
	exp := now.Add(5 * time.Minute)
	if tok.expired {
		exp = now.Add(-time.Hour)
	}
	claims := jwt.MapClaims{
		"iss": testIssuer,
		"aud": []string{tok.audience},
		"sub": tok.subject,
		"exp": exp.Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"jti": "jti-" + tok.subject,
	}
	if tok.tenantID != "" {
		claims["tenant_id"] = tok.tenantID
	}
	if len(tok.scopes) > 0 {
		claims["scp"] = tok.scopes
	}
	if len(tok.roles) > 0 {
		claims["roles"] = tok.roles
	}
	if tok.jkt != "" {
		claims["cnf"] = map[string]any{"jkt": tok.jkt}
	}
	jwtTok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	jwtTok.Header["kid"] = testKID
	jwtTok.Header["typ"] = "at+jwt"
	s, err := jwtTok.SignedString(ti.key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

// offlineConfig returns a valid offline-mode token-auth section against the
// in-test issuer.
func offlineConfig(ti *tokenIssuer, allowBearer bool) *TokenAuthConfig {
	return &TokenAuthConfig{
		Enabled:     true,
		Issuer:      testIssuer,
		JWKSURL:     ti.server.URL,
		AuthzMode:   AuthzModeOffline,
		AllowBearer: allowBearer,
	}
}

func TestTokenAuthConfigValidate(t *testing.T) {
	tests := []struct {
		name string
		cfg  TokenAuthConfig
		ok   bool
	}{
		{"disabled skips validation", TokenAuthConfig{}, true},
		{"missing issuer", TokenAuthConfig{Enabled: true, JWKSURL: "https://x/jwks"}, false},
		{"missing jwks", TokenAuthConfig{Enabled: true, Issuer: "https://x"}, false},
		{"bad mode", TokenAuthConfig{Enabled: true, Issuer: "https://x", JWKSURL: "https://x/jwks", AuthzMode: "sometimes"}, false},
		{"hybrid without introspection", TokenAuthConfig{Enabled: true, Issuer: "https://x", JWKSURL: "https://x/jwks"}, false},
		{"online without introspection", TokenAuthConfig{Enabled: true, Issuer: "https://x", JWKSURL: "https://x/jwks", AuthzMode: AuthzModeOnline}, false},
		{"offline ok", TokenAuthConfig{Enabled: true, Issuer: "https://x", JWKSURL: "https://x/jwks", AuthzMode: AuthzModeOffline}, true},
		{"hybrid with introspection ok", TokenAuthConfig{Enabled: true, Issuer: "https://x", JWKSURL: "https://x/jwks", IntrospectionURL: "https://x/introspect"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.ok && err != nil {
				t.Fatalf("Validate: %v, want nil", err)
			}
			if !tc.ok {
				var cfgErr *ErrTokenAuthConfig
				if !errors.As(err, &cfgErr) {
					t.Fatalf("Validate = %v, want *ErrTokenAuthConfig", err)
				}
			}
		})
	}
}

func TestNewPlatformTokenAuthenticatorErrors(t *testing.T) {
	if _, err := NewPlatformTokenAuthenticator(nil); err == nil {
		t.Error("nil config must fail")
	}
	if _, err := NewPlatformTokenAuthenticator(&TokenAuthConfig{Issuer: "x", JWKSURL: "y", AuthzMode: AuthzModeOffline}); err == nil {
		t.Error("disabled section must fail")
	}
	if _, err := NewPlatformTokenAuthenticator(&TokenAuthConfig{Enabled: true}); err == nil {
		t.Error("invalid section must fail")
	}
}

func TestPlatformTokenAuthenticatorBearer(t *testing.T) {
	issuer := newTokenIssuer(t)
	authn, err := NewPlatformTokenAuthenticator(offlineConfig(issuer, true))
	if err != nil {
		t.Fatalf("NewPlatformTokenAuthenticator: %v", err)
	}
	ctx := context.Background()

	t.Run("valid token without scope requirement", func(t *testing.T) {
		token := issuer.sign(t, issuedToken{
			subject:  "svc-1",
			tenantID: "default",
			scopes:   []string{"proxy:read"},
			roles:    []string{"reader"},
		})
		p, err := authn.Authorize(ctx, &proxy.TokenAuthRequest{Token: token})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if p.Subject != "svc-1" || p.TenantID != "default" {
			t.Errorf("principal = %+v", p)
		}
		if len(p.Scopes) != 1 || p.Scopes[0] != "proxy:read" {
			t.Errorf("scopes = %v", p.Scopes)
		}
		if len(p.Roles) != 1 || p.Roles[0] != "reader" {
			t.Errorf("roles = %v", p.Roles)
		}
	})

	t.Run("required scope granted", func(t *testing.T) {
		token := issuer.sign(t, issuedToken{subject: "svc-2", scopes: []string{"proxy:read", "proxy:list"}})
		if _, err := authn.Authorize(ctx, &proxy.TokenAuthRequest{
			Token:          token,
			RequiredScopes: []string{"proxy:read", "proxy:list"},
		}); err != nil {
			t.Fatalf("Authorize: %v", err)
		}
	})

	t.Run("wildcard grant satisfies scope", func(t *testing.T) {
		token := issuer.sign(t, issuedToken{subject: "svc-3", scopes: []string{"*:*"}})
		if _, err := authn.Authorize(ctx, &proxy.TokenAuthRequest{
			Token:          token,
			RequiredScopes: []string{"proxy:admin"},
		}); err != nil {
			t.Fatalf("Authorize with wildcard grant: %v", err)
		}
	})

	t.Run("first scope denied", func(t *testing.T) {
		token := issuer.sign(t, issuedToken{subject: "svc-4", scopes: []string{"proxy:read"}})
		_, err := authn.Authorize(ctx, &proxy.TokenAuthRequest{
			Token:          token,
			RequiredScopes: []string{"proxy:admin"},
		})
		if !errors.Is(err, proxy.ErrTokenScopeDenied) {
			t.Fatalf("Authorize = %v, want wrapping proxy.ErrTokenScopeDenied", err)
		}
	})

	t.Run("secondary scope denied", func(t *testing.T) {
		token := issuer.sign(t, issuedToken{subject: "svc-5", scopes: []string{"proxy:read"}})
		_, err := authn.Authorize(ctx, &proxy.TokenAuthRequest{
			Token:          token,
			RequiredScopes: []string{"proxy:read", "proxy:admin"},
		})
		if !errors.Is(err, proxy.ErrTokenScopeDenied) {
			t.Fatalf("Authorize = %v, want wrapping proxy.ErrTokenScopeDenied", err)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		token := issuer.sign(t, issuedToken{subject: "svc-6", expired: true})
		if _, err := authn.Authorize(ctx, &proxy.TokenAuthRequest{Token: token}); err == nil {
			t.Fatal("expired token must fail")
		} else if errors.Is(err, proxy.ErrTokenScopeDenied) {
			t.Fatal("expired token must not classify as scope denial")
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		token := issuer.sign(t, issuedToken{subject: "svc-7", audience: "api://other"})
		if _, err := authn.Authorize(ctx, &proxy.TokenAuthRequest{Token: token}); err == nil {
			t.Fatal("wrong audience must fail")
		}
	})

	t.Run("garbage token", func(t *testing.T) {
		if _, err := authn.Authorize(ctx, &proxy.TokenAuthRequest{Token: "not-a-jwt"}); err == nil {
			t.Fatal("garbage token must fail")
		}
	})

	t.Run("nil request", func(t *testing.T) {
		var nilErr *ErrNilTokenRequest
		if _, err := authn.Authorize(ctx, nil); !errors.As(err, &nilErr) {
			t.Fatalf("nil request error = %v, want *ErrNilTokenRequest", err)
		}
	})
}

func TestPlatformTokenAuthenticatorBearerGate(t *testing.T) {
	issuer := newTokenIssuer(t)
	authn, err := NewPlatformTokenAuthenticator(offlineConfig(issuer, false))
	if err != nil {
		t.Fatalf("NewPlatformTokenAuthenticator: %v", err)
	}
	token := issuer.sign(t, issuedToken{subject: "svc-1"})
	var bearerErr *ErrBearerNotAllowed
	if _, err := authn.Authorize(context.Background(), &proxy.TokenAuthRequest{Token: token}); !errors.As(err, &bearerErr) {
		t.Fatalf("Authorize without proof = %v, want *ErrBearerNotAllowed", err)
	}
}

func TestPlatformTokenAuthenticatorDPoP(t *testing.T) {
	issuer := newTokenIssuer(t)
	authn, err := NewPlatformTokenAuthenticator(offlineConfig(issuer, false))
	if err != nil {
		t.Fatalf("NewPlatformTokenAuthenticator: %v", err)
	}
	ctx := context.Background()

	// The client's DPoP key: the token is bound to its RFC 7638 thumbprint.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("client dpop key: %v", err)
	}
	jkt, err := quicbaas.DPoPThumbprint(clientKey.Public())
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	const (
		htm = http.MethodGet
		htu = "https://gw.example.com/api/thing"
	)
	token := issuer.sign(t, issuedToken{subject: "svc-dpop", scopes: []string{"proxy:read"}, jkt: jkt})

	t.Run("bound token with valid proof", func(t *testing.T) {
		proof, err := quicbaas.NewDPoPProof(clientKey, htm, htu)
		if err != nil {
			t.Fatalf("build proof: %v", err)
		}
		p, err := authn.Authorize(ctx, &proxy.TokenAuthRequest{
			Token:          token,
			DPoPProof:      proof,
			HTM:            htm,
			HTU:            htu,
			RequiredScopes: []string{"proxy:read"},
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if p.Subject != "svc-dpop" {
			t.Errorf("principal = %+v", p)
		}
	})

	t.Run("proof bound to a different htu", func(t *testing.T) {
		proof, err := quicbaas.NewDPoPProof(clientKey, htm, "https://evil.example.org/api/thing")
		if err != nil {
			t.Fatalf("build proof: %v", err)
		}
		if _, err := authn.Authorize(ctx, &proxy.TokenAuthRequest{
			Token:     token,
			DPoPProof: proof,
			HTM:       htm,
			HTU:       htu,
		}); err == nil {
			t.Fatal("htu mismatch must fail")
		}
	})

	t.Run("proof from the wrong key", func(t *testing.T) {
		wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("wrong key: %v", err)
		}
		proof, err := quicbaas.NewDPoPProof(wrongKey, htm, htu)
		if err != nil {
			t.Fatalf("build proof: %v", err)
		}
		if _, err := authn.Authorize(ctx, &proxy.TokenAuthRequest{
			Token:     token,
			DPoPProof: proof,
			HTM:       htm,
			HTU:       htu,
		}); err == nil {
			t.Fatal("jkt mismatch must fail")
		}
	})

	t.Run("proof replay is rejected", func(t *testing.T) {
		proof, err := quicbaas.NewDPoPProof(clientKey, htm, htu)
		if err != nil {
			t.Fatalf("build proof: %v", err)
		}
		req := &proxy.TokenAuthRequest{Token: token, DPoPProof: proof, HTM: htm, HTU: htu}
		if _, err := authn.Authorize(ctx, req); err != nil {
			t.Fatalf("first use: %v", err)
		}
		if _, err := authn.Authorize(ctx, req); err == nil {
			t.Fatal("replayed proof must fail")
		}
	})
}

func TestNewPlatformTokenAuthenticatorLivenessModes(t *testing.T) {
	issuer := newTokenIssuer(t)

	t.Run("hybrid with introspection credentials", func(t *testing.T) {
		cfg := &TokenAuthConfig{
			Enabled:                   true,
			Issuer:                    testIssuer,
			JWKSURL:                   issuer.server.URL,
			IntrospectionURL:          issuer.server.URL + "/introspect",
			IntrospectionClientID:     "gw",
			IntrospectionClientSecret: "secret",
		}
		if _, err := NewPlatformTokenAuthenticator(cfg); err != nil {
			t.Fatalf("hybrid constructor: %v", err)
		}
	})

	t.Run("online with bearer credential", func(t *testing.T) {
		cfg := &TokenAuthConfig{
			Enabled:                  true,
			Issuer:                   testIssuer,
			JWKSURL:                  issuer.server.URL,
			AuthzMode:                AuthzModeOnline,
			IntrospectionURL:         issuer.server.URL + "/introspect",
			IntrospectionBearerToken: "svc-token",
		}
		if _, err := NewPlatformTokenAuthenticator(cfg); err != nil {
			t.Fatalf("online constructor: %v", err)
		}
	})

	t.Run("online liveness fails closed", func(t *testing.T) {
		// The introspection endpoint here returns the JWKS document, not an
		// RFC 7662 result; the checker must deny rather than allow.
		cfg := &TokenAuthConfig{
			Enabled:          true,
			Issuer:           testIssuer,
			JWKSURL:          issuer.server.URL,
			AuthzMode:        AuthzModeOnline,
			IntrospectionURL: "http://127.0.0.1:1/introspect",
			AllowBearer:      true,
		}
		authn, err := NewPlatformTokenAuthenticator(cfg)
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}
		token := issuer.sign(t, issuedToken{subject: "svc-live"})
		if _, err := authn.Authorize(context.Background(), &proxy.TokenAuthRequest{Token: token}); err == nil {
			t.Fatal("unreachable introspection endpoint must deny (fail closed)")
		}
	})
}
