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

package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// featureTenantServer reports which tenant backends the daemon wired, as
// TenantGRPCServer does over its tenant.Manager.
type featureTenantServer struct {
	platformv1.UnimplementedTenantServiceServer
	barrier bool
	dek     bool
}

func (s *featureTenantServer) BarrierConfigured() bool { return s.barrier }
func (s *featureTenantServer) DEKConfigured() bool     { return s.dek }

// plainTenantServer has no feature methods: the router cannot tell which
// backends it has, so it mounts every route as before.
type plainTenantServer struct {
	platformv1.UnimplementedTenantServiceServer
}

var (
	tenantBarrierOps = []string{
		"GET /api/v1/tenants/{id}/barrier",
		"POST /api/v1/tenants/{id}/barrier/init",
		"POST /api/v1/tenants/{id}/barrier/unseal",
		"POST /api/v1/tenants/{id}/barrier/seal",
	}
	tenantDEKOps = []string{
		"POST /api/v1/tenants/{id}/dek/rotate",
		"GET /api/v1/tenants/{id}/dek",
	}
)

func tenantFeatureRouter(t *testing.T, server platformv1.TenantServiceServer) *mux.Router {
	t.Helper()
	return newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler:  &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "tenant-a"},
		tenantService: server,
	})
}

func serveTenant(router http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func requireCapability(t *testing.T, caps map[string]Capability, op string) Capability {
	t.Helper()
	c, ok := caps[op]
	require.True(t, ok, "capabilities must list %s", op)
	return c
}

func TestTenantRoutes_BarrierAndDEKDarkWithoutBackends(t *testing.T) {
	router := tenantFeatureRouter(t, &featureTenantServer{})

	seal := serveTenant(router, http.MethodPost, "/api/v1/tenants/tenant-a/barrier/seal")
	assert.Equal(t, http.StatusServiceUnavailable, seal.Code, seal.Body.String())
	assert.Contains(t, seal.Body.String(), "tenant-barrier")

	dek := serveTenant(router, http.MethodGet, "/api/v1/tenants/tenant-a/dek")
	assert.Equal(t, http.StatusServiceUnavailable, dek.Code, dek.Body.String())
	assert.Contains(t, dek.Body.String(), "tenant-dek")

	caps := getCapabilities(t, router)
	for _, op := range tenantBarrierOps {
		c := requireCapability(t, caps, op)
		assert.False(t, c.Enabled, op)
		assert.Equal(t, "not-configured: tenant-barrier", c.Reason, op)
	}
	for _, op := range tenantDEKOps {
		c := requireCapability(t, caps, op)
		assert.False(t, c.Enabled, op)
		assert.Equal(t, "not-configured: tenant-dek", c.Reason, op)
	}
	quotas := requireCapability(t, caps, "GET /api/v1/tenants/{id}/quotas")
	assert.True(t, quotas.Enabled, "the quotas route has no missing backend")
	assert.Empty(t, quotas.Reason)
}

func TestTenantRoutes_BarrierAndDEKLiveWithBackends(t *testing.T) {
	router := tenantFeatureRouter(t, &featureTenantServer{barrier: true, dek: true})

	seal := serveTenant(router, http.MethodPost, "/api/v1/tenants/tenant-a/barrier/seal")
	assert.NotEqual(t, http.StatusServiceUnavailable, seal.Code, seal.Body.String())

	caps := getCapabilities(t, router)
	for _, op := range append(append([]string{}, tenantBarrierOps...), tenantDEKOps...) {
		c := requireCapability(t, caps, op)
		assert.True(t, c.Enabled, op)
		assert.Empty(t, c.Reason, op)
	}
}

func TestTenantRoutes_ServerWithoutFeatureMethodsKeepsRoutes(t *testing.T) {
	router := tenantFeatureRouter(t, &plainTenantServer{})

	caps := getCapabilities(t, router)
	for _, op := range append(append([]string{
		"GET /api/v1/tenants/{id}/quotas",
	}, tenantBarrierOps...), tenantDEKOps...) {
		c := requireCapability(t, caps, op)
		assert.True(t, c.Enabled, op)
		assert.Empty(t, c.Reason, op)
	}
}
