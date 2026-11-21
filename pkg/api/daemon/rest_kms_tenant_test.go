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

// tenantRecordingSecrets records the SDK tenant each List call carries.
type tenantRecordingSecrets struct {
	secretsclient.Client
	tenants []string
}

func (f *tenantRecordingSecrets) List(ctx context.Context, prefix string) (*secretsclient.ListSecretsResponse, error) {
	f.tenants = append(f.tenants, sdktransport.TenantFromContext(ctx))
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

	w = list("none")
	require.Equal(t, http.StatusForbidden, w.Code, "no tenant: body %s", w.Body.String())
	require.Len(t, secrets.tenants, 2, "a caller with no tenant must never reach the secrets client")
}
