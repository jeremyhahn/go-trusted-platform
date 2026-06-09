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
)

const (
	testPTIssuer   = "https://broker.test"
	testPTAudience = "api://platform"
	testPTKID      = "kid-1"
)

// ptIssuerKey is an ES256 signing key plus a JWKS HTTP server, used to mint and
// publish tokens the shared validator can verify end to end.
type ptIssuerKey struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func newPTIssuerKey(t *testing.T) *ptIssuerKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	return &ptIssuerKey{priv: priv, kid: testPTKID}
}

func (k *ptIssuerKey) jwksHandler(t *testing.T) *httptest.Server {
	t.Helper()
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       k.priv.Public(),
		KeyID:     k.kid,
		Algorithm: "ES256",
		Use:       "sig",
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(set); err != nil {
			t.Errorf("encode jwks: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (k *ptIssuerKey) sign(t *testing.T, sub, tid string, scp []string) string {
	t.Helper()
	now := time.Now()
	m := jwt.MapClaims{
		"iss": testPTIssuer,
		"aud": []string{testPTAudience},
		"sub": sub,
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": "jti-" + sub,
	}
	if tid != "" {
		m["tenant_id"] = tid
	}
	if len(scp) > 0 {
		m["scp"] = scp
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, m)
	tok.Header["kid"] = k.kid
	s, err := tok.SignedString(k.priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func newSharedValidator(t *testing.T, jwksURL string, allowBearer bool) *platformTokenValidator {
	t.Helper()
	v, err := newPlatformTokenValidator(PlatformTokenConfig{
		Enabled:     true,
		Issuer:      testPTIssuer,
		JWKSURL:     jwksURL,
		Audience:    testPTAudience,
		AllowBearer: allowBearer,
	}, nil)
	if err != nil {
		t.Fatalf("newPlatformTokenValidator: %v", err)
	}
	return v
}

func TestPlatformTokenValidator_AuthorizeToken_Valid(t *testing.T) {
	key := newPTIssuerKey(t)
	srv := key.jwksHandler(t)
	v := newSharedValidator(t, srv.URL, true)

	tok := key.sign(t, "user-1", "tenant-a", []string{"dns:write", "keys:get"})
	authCtx, err := v.AuthorizeToken(context.Background(), tok, "", "/svc/Method", "")
	if err != nil {
		t.Fatalf("AuthorizeToken: %v", err)
	}
	if authCtx.Subject != "user-1" || authCtx.TenantID != "tenant-a" {
		t.Fatalf("unexpected authCtx: %+v", authCtx)
	}
	if err := authCtx.RequireScope("dns:write"); err != nil {
		t.Errorf("granted scope denied: %v", err)
	}
	if err := authCtx.RequireScope("dns:delete"); err == nil {
		t.Error("ungranted scope should be denied")
	}
}

func TestPlatformTokenValidator_AuthorizeToken_InvalidSignature(t *testing.T) {
	key := newPTIssuerKey(t)
	srv := key.jwksHandler(t)
	v := newSharedValidator(t, srv.URL, true)

	// Sign with a different (untrusted) key; the published JWKS will not verify it.
	attacker := newPTIssuerKey(t)
	tok := attacker.sign(t, "mallory", "tenant-a", []string{"dns:write"})

	if _, err := v.AuthorizeToken(context.Background(), tok, "", "/svc/Method", ""); err == nil {
		t.Fatal("expected verification failure for token signed by untrusted key")
	}
}

func TestPlatformTokenValidator_AuthorizeToken_BearerGate(t *testing.T) {
	key := newPTIssuerKey(t)
	srv := key.jwksHandler(t)
	// allowBearer=false: a bearer (no DPoP proof) must be rejected.
	v := newSharedValidator(t, srv.URL, false)

	tok := key.sign(t, "user-1", "tenant-a", []string{"dns:write"})
	_, err := v.AuthorizeToken(context.Background(), tok, "", "/svc/Method", "")
	if err == nil {
		t.Fatal("expected bearer rejection when AllowBearer is false")
	}
	var dpopErr ErrDPoPProofRequired
	if !errors.As(err, &dpopErr) {
		t.Errorf("expected ErrDPoPProofRequired, got %T: %v", err, err)
	}
}

func TestPlatformTokenValidator_ValidateToken_Bool(t *testing.T) {
	key := newPTIssuerKey(t)
	srv := key.jwksHandler(t)
	v := newSharedValidator(t, srv.URL, true)

	tok := key.sign(t, "user-1", "", nil)
	ok, err := v.ValidateToken(context.Background(), tok)
	if err != nil || !ok {
		t.Fatalf("ValidateToken: ok=%v err=%v", ok, err)
	}

	bad, err := v.ValidateToken(context.Background(), "not-a-token")
	if err == nil || bad {
		t.Fatal("expected ValidateToken to reject a malformed token")
	}
}

func TestPlatformTokenValidator_CheckPermission(t *testing.T) {
	key := newPTIssuerKey(t)
	srv := key.jwksHandler(t)
	v := newSharedValidator(t, srv.URL, true)

	tok := key.sign(t, "user-1", "tenant-a", []string{"dns:write"})

	allowed, err := v.CheckPermission(context.Background(), tok, "dns", "write")
	if err != nil || !allowed {
		t.Fatalf("CheckPermission granted scope: allowed=%v err=%v", allowed, err)
	}
	denied, err := v.CheckPermission(context.Background(), tok, "dns", "delete")
	if err != nil {
		t.Fatalf("CheckPermission error: %v", err)
	}
	if denied {
		t.Error("CheckPermission should deny an ungranted scope")
	}
}

func TestPlatformTokenValidator_GetTokenClaims(t *testing.T) {
	key := newPTIssuerKey(t)
	srv := key.jwksHandler(t)
	v := newSharedValidator(t, srv.URL, true)

	tok := key.sign(t, "user-1", "tenant-a", []string{"dns:write"})
	claims, err := v.GetTokenClaims(context.Background(), tok)
	if err != nil {
		t.Fatalf("GetTokenClaims: %v", err)
	}
	if claims["sub"] != "user-1" || claims["tenant_id"] != "tenant-a" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestNewPlatformTokenValidator_MissingConfig(t *testing.T) {
	if _, err := newPlatformTokenValidator(PlatformTokenConfig{Enabled: true}, nil); err == nil {
		t.Fatal("expected error for missing issuer")
	}
	if _, err := newPlatformTokenValidator(PlatformTokenConfig{Enabled: true, Issuer: testPTIssuer}, nil); err == nil {
		t.Fatal("expected error for missing JWKS URL")
	}
}

func TestPlatformTokenValidator_ErrorBranches(t *testing.T) {
	key := newPTIssuerKey(t)
	srv := key.jwksHandler(t)
	v := newSharedValidator(t, srv.URL, true)

	// GetTokenClaims and CheckPermission must surface validation errors.
	if _, err := v.GetTokenClaims(context.Background(), "garbage"); err == nil {
		t.Error("GetTokenClaims should error on invalid token")
	}
	if _, err := v.CheckPermission(context.Background(), "garbage", "dns", "write"); err == nil {
		t.Error("CheckPermission should error on invalid token")
	}

	// CheckPermission with empty resource/action allows (no scope required).
	tok := key.sign(t, "user-1", "", nil)
	allowed, err := v.CheckPermission(context.Background(), tok, "", "")
	if err != nil || !allowed {
		t.Errorf("empty resource/action should allow: allowed=%v err=%v", allowed, err)
	}

	// AuthorizeToken surfaces validation errors on the bearer path.
	if _, err := v.AuthorizeToken(context.Background(), "garbage", "", "", ""); err == nil {
		t.Error("AuthorizeToken should error on invalid token")
	}
}

func TestPlatformTokenErrorTypes(t *testing.T) {
	cfgErr := ErrPlatformTokenConfig{Field: "issuer", Reason: "required"}
	if cfgErr.Error() == "" {
		t.Error("ErrPlatformTokenConfig.Error() empty")
	}
	if (ErrDPoPProofRequired{}).Error() == "" {
		t.Error("ErrDPoPProofRequired.Error() empty")
	}
}
