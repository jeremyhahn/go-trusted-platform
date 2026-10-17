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

//go:build codec_msgpack

package daemon

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restkms "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"

	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

func TestRESTServer_SetKMSHandlers_EveryRouteRequiresAScope(t *testing.T) {
	t.Parallel()
	logger := logging.DefaultLogger()
	router := restkms.NewKMSRouter(logger, nil, nil, nil, nil, response.NewResponseWriter(logger, nil))

	for _, route := range router.Routes() {
		assert.NotEmpty(t, grpcapi.ScopeForMethod(route.RPC), "%s %s", route.Method, route.Path)
	}
}

func TestRESTServer_SetKMSHandlers_NilGuardRefuses(t *testing.T) {
	t.Parallel()
	server := newTPMTestRESTServer(t)
	server.SetKMSHandlers(KMSRESTClients{}, nil)

	w := serveTPMRoute(server, http.MethodGet, "/api/v1/kms/keys", "")
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

func TestRESTServer_SetKMSHandlers_GuardsByScope(t *testing.T) {
	t.Parallel()
	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	listScope := grpcapi.ScopeForMethod("/quicbaas.kms.v1.KeyManagement/ListKeys")
	scoped := key.sign(t, "operator", "", []string{listScope})
	unscoped := key.sign(t, "operator", "", []string{"dns:read"})

	server := newTPMTestRESTServer(t)
	server.SetKMSHandlers(KMSRESTClients{}, restapi.NewScopeGuard(validator, nil, slog.Default()))

	t.Run("a token with the ListKeys scope reaches the handler", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodGet, "/api/v1/kms/keys", scoped)
		assert.NotEqual(t, http.StatusForbidden, w.Code, w.Body.String())
		assert.NotEqual(t, http.StatusNotFound, w.Code, w.Body.String())
	})

	t.Run("a token without it is refused", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodGet, "/api/v1/kms/keys", unscoped)
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	})
}

// recordingSecretsClient counts the secrets reads that reach the SDK, which
// would serve them from the system namespace (requireSystemScopeCaller).
type recordingSecretsClient struct {
	secretsclient.Client
	reads atomic.Int32
}

func (c *recordingSecretsClient) Get(_ context.Context, path string, _ ...secretsclient.GetOption) (*secretsclient.Secret, error) {
	c.reads.Add(1)
	return &secretsclient.Secret{Path: path}, nil
}

func (c *recordingSecretsClient) List(_ context.Context, _ string) (*secretsclient.ListSecretsResponse, error) {
	c.reads.Add(1)
	return &secretsclient.ListSecretsResponse{}, nil
}

func TestRESTServer_SetKMSHandlers_TenantBoundCallerNeverReachesTheSystemNamespace(t *testing.T) {
	t.Parallel()
	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	scopes := []string{
		grpcapi.ScopeForMethod("/quicbaas.kms.v1.SecretsManagement/GetSecret"),
		grpcapi.ScopeForMethod("/quicbaas.kms.v1.SecretsManagement/ListSecrets"),
	}
	const systemTenant = "system"

	secrets := &recordingSecretsClient{}
	server := newTPMTestRESTServer(t)
	server.SetKMSHandlers(KMSRESTClients{Secrets: secrets, SystemTenantID: systemTenant},
		restapi.NewScopeGuard(validator, nil, slog.Default()))

	for _, path := range []string{"/api/v1/kms/secrets/db-password", "/api/v1/kms/secrets"} {
		t.Run("a tenant-bound token is refused on "+path, func(t *testing.T) {
			w := serveTPMRoute(server, http.MethodGet, path, key.sign(t, "alice", "tenant-a", scopes))
			assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), ErrKMSRESTTenantBound{TenantID: "tenant-a"}.Error())
		})
	}
	assert.Zero(t, secrets.reads.Load(), "a tenant-bound read reached the SDK's system namespace")

	t.Run("a system-tenant token reaches the SDK", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodGet, "/api/v1/kms/secrets/db-password", key.sign(t, "operator", systemTenant, scopes))
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})
	t.Run("a token bound to no tenant reaches the SDK", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodGet, "/api/v1/kms/secrets", key.sign(t, "operator", "", scopes))
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})
	assert.Equal(t, int32(2), secrets.reads.Load())
}

func TestRequireSystemScopeCaller(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		system   string
		tenantID string
		wantErr  bool
	}{
		{name: "unbound caller", system: "system", tenantID: ""},
		{name: "system tenant", system: "system", tenantID: "system"},
		{name: "other tenant", system: "system", tenantID: "tenant-a", wantErr: true},
		{name: "no system tenant configured fails closed", system: "", tenantID: "system", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireSystemScopeCaller(tt.system, &platformtoken.AuthorizedContext{TenantID: tt.tenantID})
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			var bound ErrKMSRESTTenantBound
			assert.ErrorAs(t, err, &bound)
			assert.Equal(t, tt.tenantID, bound.TenantID)
		})
	}
}
