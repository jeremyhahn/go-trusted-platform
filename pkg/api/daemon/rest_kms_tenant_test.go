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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	qbiam "github.com/jeremyhahn/go-quicbaas/pkg/iam"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	sdktransport "github.com/jeremyhahn/go-quicbaas/sdk/go/transport"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// tenantTokenValidator accepts every token, grants it every scope, and makes
// the bearer token the caller's tenant ("none" is a caller with no tenant).
type tenantTokenValidator struct{}

func (tenantTokenValidator) ValidateToken(ctx context.Context, token string) (bool, error) {
	return true, nil
}

func (tenantTokenValidator) AuthorizeToken(ctx context.Context, token, requiredPerm, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	tenant := token
	if token == "none" {
		tenant = ""
	}
	return &platformtoken.AuthorizedContext{Subject: "u", TenantID: tenant, Scopes: []string{"*:*"}}, nil
}

// tenantRecordingSecrets records the SDK tenant each List call carries, and
// the tenant the embedded go-quicbaas services read (pkg/iam), which is a
// different context key.
type tenantRecordingSecrets struct {
	secretsclient.Client
	tenants    []string
	iamTenants []string
}

func (f *tenantRecordingSecrets) List(ctx context.Context, prefix string) (*secretsclient.ListSecretsResponse, error) {
	f.tenants = append(f.tenants, sdktransport.TenantFromContext(ctx))
	f.iamTenants = append(f.iamTenants, qbiam.TenantFromContext(ctx))
	return &secretsclient.ListSecretsResponse{}, nil
}

// TestKMSRouter_BindsTheCallersTenant: the KMS router's shared SDK clients
// read the tenant from the request context, and an empty tenant is
// system-wide, so the daemon binds the verified caller's tenant before
// dispatch and refuses a caller without one (#2030 Codex round 1 P1).
func TestKMSRouter_BindsTheCallersTenant(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.Default())
	require.NoError(t, err)
	secrets := &tenantRecordingSecrets{}
	s.SetKMSRouter(nil, nil, nil, secrets, restapi.NewScopeGuard(tenantTokenValidator{}, nil, nil))

	list := func(token string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/kms/secrets", strings.NewReader(""))
		r.Header.Set("Authorization", "Bearer "+token)
		s.Router().ServeHTTP(w, r)
		return w
	}

	w := list("tenant-a")
	require.Equal(t, http.StatusOK, w.Code, "tenant-a: body %s", w.Body.String())
	require.Equal(t, []string{"tenant-a"}, secrets.tenants, "tenant-a's list must reach the SDK bound to tenant-a")

	w = list("tenant-b")
	require.Equal(t, http.StatusOK, w.Code, "tenant-b: body %s", w.Body.String())
	require.Equal(t, []string{"tenant-a", "tenant-b"}, secrets.tenants, "tenant-b's list must reach the SDK bound to tenant-b")
	require.Equal(t, []string{"tenant-a", "tenant-b"}, secrets.iamTenants, "the embedded services read pkg/iam's tenant: it must be the caller's too")

	w = list("none")
	require.Equal(t, http.StatusForbidden, w.Code, "no tenant: body %s", w.Body.String())
	require.Len(t, secrets.tenants, 2, "a caller with no tenant must never reach the secrets client")
}

// TestKMSRouter_DEKRoutesServeThePlatformTenantOnly: the embedded go-quicbaas
// DEK store is keyed by path alone and ignores the tenant, so binding the
// caller's tenant does not isolate DEKs; the daemon refuses the DEK routes to
// every tenant but the platform's (#2030 Codex P0).
func TestKMSRouter_DEKRoutesServeThePlatformTenantOnly(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	cfg.PlatformTenantID = "platform"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.Default())
	require.NoError(t, err)
	s.SetKMSRouter(nil, nil, nil, nil, restapi.NewScopeGuard(tenantTokenValidator{}, nil, nil))

	do := func(method, path, token string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		s.Router().ServeHTTP(w, r)
		return w
	}

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/kms/deks"},
		{http.MethodPost, "/api/v1/kms/deks"},
		{http.MethodPost, "/api/v1/kms/deks/a/rotate"},
	} {
		w := do(c.method, c.path, "tenant-a")
		require.Equal(t, http.StatusForbidden, w.Code, "tenant-a %s %s: body %s", c.method, c.path, w.Body.String())
	}

	w := do(http.MethodGet, "/api/v1/kms/deks", "platform")
	require.NotEqual(t, http.StatusForbidden, w.Code, "platform tenant: body %s", w.Body.String())
}

// TestKMSRouter_KeyPolicyAndMetadataRoutesServeThePlatformTenantOnly pins
// that the key policy and metadata routes serve the platform tenant only: the
// pinned upstream SetKeyPolicy, UpdateKeyMetadata and GetKeyMetadata look the
// key up by ID without tenant scoping.
func TestKMSRouter_KeyPolicyAndMetadataRoutesServeThePlatformTenantOnly(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	cfg.PlatformTenantID = "platform"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.Default())
	require.NoError(t, err)
	s.SetKMSRouter(nil, nil, nil, nil, restapi.NewScopeGuard(tenantTokenValidator{}, nil, nil))

	do := func(method, path, token string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		s.Router().ServeHTTP(w, r)
		return w
	}

	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/kms/keys/k1/policy"},
		{http.MethodPut, "/api/v1/kms/keys/k1/policy"},
		{http.MethodGet, "/api/v1/kms/keys/k1/metadata"},
		{http.MethodPut, "/api/v1/kms/keys/k1/metadata"},
	}
	for _, c := range cases {
		w := do(c.method, c.path, "tenant-a")
		require.Equal(t, http.StatusForbidden, w.Code, "tenant-a %s %s: body %s", c.method, c.path, w.Body.String())
	}
	for _, c := range cases {
		w := do(c.method, c.path, "platform")
		require.NotEqual(t, http.StatusForbidden, w.Code, "platform tenant %s %s: body %s", c.method, c.path, w.Body.String())
	}
}
