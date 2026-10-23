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
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
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
	return k.signExpiring(t, sub, tid, scp, time.Now().Add(10*time.Minute))
}

// signExpiring mints a token like sign whose exp is exp, issued ten minutes
// before it, so a past exp yields an expired but otherwise valid token.
func (k *ptIssuerKey) signExpiring(t *testing.T, sub, tid string, scp []string, exp time.Time) string {
	t.Helper()
	m := jwt.MapClaims{
		"iss": testPTIssuer,
		"aud": []string{testPTAudience},
		"sub": sub,
		"exp": exp.Unix(),
		"iat": exp.Add(-10 * time.Minute).Unix(),
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
	tok.Header["typ"] = "at+jwt"
	s, err := tok.SignedString(k.priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func newSharedValidator(t *testing.T, jwksURL string, allowBearer bool) *platformTokenValidator {
	t.Helper()
	return newSharedValidatorWithPEP(t, jwksURL, allowBearer, allowingPEP())
}

// newSharedValidatorWithPEP builds the shared validator with pep deciding
// CheckPermission.
func newSharedValidatorWithPEP(t *testing.T, jwksURL string, allowBearer bool, pep quicbaas.IAMPEPClient) *platformTokenValidator {
	t.Helper()
	v, err := newPlatformTokenValidator(PlatformTokenConfig{
		Enabled:     true,
		Issuer:      testPTIssuer,
		JWKSURL:     jwksURL,
		Audience:    testPTAudience,
		AllowBearer: allowBearer,
		// Offline mode: these tests exercise signature / scope projection, not
		// online liveness, so no introspection endpoint is required.
		AuthzMode: "offline",
	}, pep, nil)
	if err != nil {
		t.Fatalf("newPlatformTokenValidator: %v", err)
	}
	return v
}

// allowingPEP is a policy enforcement point that grants every check.
func allowingPEP() *mockSDKPEPClient {
	return &mockSDKPEPClient{checkFunc: func(context.Context, *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		return &sdkiam.CheckResponse{Allowed: true}, nil
	}}
}

func TestPlatformTokenValidator_AuthorizeToken_Valid(t *testing.T) {
	key := newPTIssuerKey(t)
	srv := key.jwksHandler(t)
	v := newSharedValidator(t, srv.URL, true)

	tok := key.sign(t, "user-1", "tenant-a", []string{"dns:write", "keys:get"})
	authCtx, err := v.AuthorizeToken(context.Background(), tok, "", "", "/svc/Method", "")
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

	if _, err := v.AuthorizeToken(context.Background(), tok, "", "", "/svc/Method", ""); err == nil {
		t.Fatal("expected verification failure for token signed by untrusted key")
	}
}

func TestPlatformTokenValidator_AuthorizeToken_BearerGate(t *testing.T) {
	key := newPTIssuerKey(t)
	srv := key.jwksHandler(t)
	// allowBearer=false: a bearer (no DPoP proof) must be rejected.
	v := newSharedValidator(t, srv.URL, false)

	tok := key.sign(t, "user-1", "tenant-a", []string{"dns:write"})
	_, err := v.AuthorizeToken(context.Background(), tok, "", "", "/svc/Method", "")
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

// TestPlatformTokenValidator_CheckPermissionThroughPEP pins #926: an empty
// permission is refused, the PEP decides a scoped permission for the token's
// principal, and a PEP that cannot answer — or is absent — fails closed.
func TestPlatformTokenValidator_CheckPermissionThroughPEP(t *testing.T) {
	key := newPTIssuerKey(t)
	srv := key.jwksHandler(t)
	tok := key.sign(t, "user-1", "tenant-a", []string{"dns:write"})

	t.Run("empty resource is denied", func(t *testing.T) {
		v := newSharedValidator(t, srv.URL, true)
		allowed, err := v.CheckPermission(context.Background(), tok, "", "write")
		var want ErrEmptyPermission
		if allowed || !errors.As(err, &want) {
			t.Fatalf("empty resource: allowed=%v err=%v, want ErrEmptyPermission", allowed, err)
		}
	})
	t.Run("empty action is denied", func(t *testing.T) {
		v := newSharedValidator(t, srv.URL, true)
		allowed, err := v.CheckPermission(context.Background(), tok, "dns", " ")
		var want ErrEmptyPermission
		if allowed || !errors.As(err, &want) {
			t.Fatalf("empty action: allowed=%v err=%v, want ErrEmptyPermission", allowed, err)
		}
	})
	t.Run("PEP is asked for the token principal", func(t *testing.T) {
		var got *sdkiam.CheckRequest
		pep := &mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			got = req
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}}
		v := newSharedValidatorWithPEP(t, srv.URL, true, pep)
		allowed, err := v.CheckPermission(context.Background(), tok, "dns", "write")
		if err != nil || !allowed {
			t.Fatalf("granted permission: allowed=%v err=%v", allowed, err)
		}
		if got == nil || got.Subject.ID != "user-1" || got.Subject.TenantID != "tenant-a" || got.Resource != "dns" || got.Action != "write" {
			t.Fatalf("PEP request = %+v, want user-1@tenant-a dns:write", got)
		}
	})
	t.Run("PEP denial denies", func(t *testing.T) {
		v := newSharedValidatorWithPEP(t, srv.URL, true, &mockSDKPEPClient{})
		allowed, err := v.CheckPermission(context.Background(), tok, "dns", "write")
		if err != nil || allowed {
			t.Fatalf("PEP denial: allowed=%v err=%v", allowed, err)
		}
	})
	t.Run("PEP error fails closed", func(t *testing.T) {
		pepErr := errors.New("pep unreachable")
		pep := &mockSDKPEPClient{checkFunc: func(context.Context, *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return nil, pepErr
		}}
		v := newSharedValidatorWithPEP(t, srv.URL, true, pep)
		allowed, err := v.CheckPermission(context.Background(), tok, "dns", "write")
		var want ErrIAMPermissionCheckFailed
		if allowed || !errors.As(err, &want) || !errors.Is(err, pepErr) {
			t.Fatalf("PEP error: allowed=%v err=%v, want ErrIAMPermissionCheckFailed", allowed, err)
		}
	})
	t.Run("no PEP fails closed", func(t *testing.T) {
		v := newSharedValidatorWithPEP(t, srv.URL, true, nil)
		allowed, err := v.CheckPermission(context.Background(), tok, "dns", "write")
		var want ErrPEPClientNotAvailable
		if allowed || !errors.As(err, &want) {
			t.Fatalf("no PEP: allowed=%v err=%v, want ErrPEPClientNotAvailable", allowed, err)
		}
	})
	t.Run("token without a tenant is denied", func(t *testing.T) {
		v := newSharedValidator(t, srv.URL, true)
		untenanted := key.sign(t, "user-1", "", []string{"dns:write"})
		allowed, err := v.CheckPermission(context.Background(), untenanted, "dns", "write")
		if err != nil || allowed {
			t.Fatalf("untenanted token: allowed=%v err=%v", allowed, err)
		}
	})
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
	if _, err := newPlatformTokenValidator(PlatformTokenConfig{Enabled: true}, nil, nil); err == nil {
		t.Fatal("expected error for missing issuer")
	}
	if _, err := newPlatformTokenValidator(PlatformTokenConfig{Enabled: true, Issuer: testPTIssuer}, nil, nil); err == nil {
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

	// AuthorizeToken surfaces validation errors on the bearer path.
	if _, err := v.AuthorizeToken(context.Background(), "garbage", "", "", "", ""); err == nil {
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
