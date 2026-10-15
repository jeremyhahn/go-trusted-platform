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

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

// The callers the tenant route tests authenticate: the system tenant, an
// ordinary tenant, and a tenant holding tenant:read only.
const (
	tenantSystemID    = "tenant-system"
	tenantSystemToken = "system-token"
	tenantAID         = "tenant-a"
	tenantAName       = "alpha"
	tenantAToken      = "tenant-a-token"
	tenantBID         = "tenant-b"
	tenantBName       = "bravo"
	tenantReaderToken = "tenant-a-reader-token"
)

// tenantCallers authenticates a bearer token to the caller it names.
type tenantCallers map[string]*platformtoken.AuthorizedContext

func (c tenantCallers) AuthorizeToken(_ context.Context, token, _, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	caller, ok := c[token]
	if !ok {
		return nil, errors.New("token invalid")
	}
	return caller, nil
}

// tenantTestGuard authenticates the system tenant, tenant A, and tenant A
// with tenant:read only.
func tenantTestGuard() *ScopeGuard {
	return NewScopeGuard(tenantCallers{
		tenantSystemToken: {Subject: "system-operator", TenantID: tenantSystemID, Scopes: []string{"*:*"}},
		tenantAToken:      {Subject: "a-operator", TenantID: tenantAID, Scopes: []string{"*:*"}},
		tenantReaderToken: {Subject: "a-reader", TenantID: tenantAID, Scopes: []string{scopeTenantRead}},
	}, nil, nil)
}

// tenantAuthzRouter serves tenant A, tenant B and the system tenant behind
// tenantTestGuard.
func tenantAuthzRouter(t *testing.T) *mux.Router {
	t.Helper()
	mgr := newMockTenantManager()
	mgr.tenants[tenantSystemID] = createTestTenantEntity(tenantSystemID, "system")
	mgr.tenants[tenantAID] = createTestTenantEntity(tenantAID, tenantAName)
	mgr.tenants[tenantBID] = createTestTenantEntity(tenantBID, tenantBName)
	router := mux.NewRouter()
	newTestTenantHandlersWithMock(mgr).RegisterRoutes(router)
	return router
}

// serveTenant sends one request as the caller holding token ("" sends none)
// and returns the response.
func serveTenant(t *testing.T, router *mux.Router, token, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&payload).Encode(body))
	}
	req := httptest.NewRequest(method, path, &payload)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// tenantErrorText decodes the error a refused tenant route answered with.
func tenantErrorText(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var resp TenantErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp), "body: %s", rr.Body.String())
	return resp.Error
}

// tenantIDRoute is a route naming one tenant by {id}; path has one %s.
type tenantIDRoute struct {
	method string
	path   string
	body   any
}

func tenantIDRoutes() []tenantIDRoute {
	return []tenantIDRoute{
		{http.MethodGet, "/api/v1/tenants/%s", nil},
		{http.MethodPut, "/api/v1/tenants/%s", UpdateTenantRequest{}},
		{http.MethodDelete, "/api/v1/tenants/%s", nil},
		{http.MethodPost, "/api/v1/tenants/%s/suspend", nil},
		{http.MethodPost, "/api/v1/tenants/%s/resume", nil},
		{http.MethodGet, "/api/v1/tenants/%s/quotas", nil},
		{http.MethodPut, "/api/v1/tenants/%s/quotas", UpdateQuotasRequest{}},
		{http.MethodGet, "/api/v1/tenants/%s/usage", nil},
		{http.MethodPost, "/api/v1/tenants/%s/check-quota", CheckQuotaRequest{Resource: "vms", Amount: 1}},
		{http.MethodPost, "/api/v1/tenants/%s/dek/rotate", RotateDEKRequest{}},
		{http.MethodGet, "/api/v1/tenants/%s/dek/status", nil},
		{http.MethodPost, "/api/v1/tenants/%s/barrier/init", nil},
		{http.MethodPost, "/api/v1/tenants/%s/barrier/unseal", UnsealTenantBarrierRequest{Key: []byte("unseal-key")}},
		{http.MethodPost, "/api/v1/tenants/%s/barrier/seal", nil},
		{http.MethodGet, "/api/v1/tenants/%s/barrier/status", nil},
	}
}

// tenantSystemRoute is a route that acts across tenants, with the
// TenantService method its refusal names.
type tenantSystemRoute struct {
	method string
	path   string
	body   any
	op     string
}

func tenantSystemRoutes() []tenantSystemRoute {
	return []tenantSystemRoute{
		{http.MethodGet, "/api/v1/tenants", nil, "ListTenants"},
		{http.MethodPost, "/api/v1/tenants", CreateTenantRequest{Name: "charlie"}, "CreateTenant"},
		{http.MethodPost, "/api/v1/tenants/sync", nil, "Sync"},
	}
}

// TestTenantRoutes_OwnOrSystem: a route naming a tenant admits that tenant
// and the system tenant, and refuses another tenant with 403 and
// tenant.ErrTenantForbidden — the tenant gRPC server's rule (#304).
func TestTenantRoutes_OwnOrSystem(t *testing.T) {
	for _, route := range tenantIDRoutes() {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			own := serveTenant(t, tenantAuthzRouter(t), tenantAToken, route.method, fmt.Sprintf(route.path, tenantAID), route.body)
			assert.NotContains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, own.Code, "own tenant: %s", own.Body.String())

			system := serveTenant(t, tenantAuthzRouter(t), tenantSystemToken, route.method, fmt.Sprintf(route.path, tenantAID), route.body)
			assert.NotContains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, system.Code, "system tenant: %s", system.Body.String())

			other := serveTenant(t, tenantAuthzRouter(t), tenantAToken, route.method, fmt.Sprintf(route.path, tenantBID), route.body)
			require.Equal(t, http.StatusForbidden, other.Code, "another tenant: %s", other.Body.String())
			assert.Equal(t, tenant.ErrTenantForbidden{Requested: tenantBID}.Error(), tenantErrorText(t, other))
		})
	}
}

// TestTenantRoutes_SystemOnly: list, create and sync admit the system tenant
// only; any other tenant gets 403 and tenant.ErrTenantSystemOnly naming the
// TenantService method.
func TestTenantRoutes_SystemOnly(t *testing.T) {
	for _, route := range tenantSystemRoutes() {
		t.Run(route.op, func(t *testing.T) {
			system := serveTenant(t, tenantAuthzRouter(t), tenantSystemToken, route.method, route.path, route.body)
			assert.NotContains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, system.Code, "system tenant: %s", system.Body.String())

			other := serveTenant(t, tenantAuthzRouter(t), tenantAToken, route.method, route.path, route.body)
			require.Equal(t, http.StatusForbidden, other.Code, "tenant A: %s", other.Body.String())
			assert.Equal(t, tenant.ErrTenantSystemOnly{Method: route.op}.Error(), tenantErrorText(t, other))
		})
	}
}

// TestTenantRoutes_GetByName applies tenant.AuthorizeNameLookup to the
// caller the guard verified: its own name, or any as the system tenant; an
// unknown name is refused exactly like another tenant's.
func TestTenantRoutes_GetByName(t *testing.T) {
	router := tenantAuthzRouter(t)
	byName := func(token, name string) *httptest.ResponseRecorder {
		return serveTenant(t, router, token, http.MethodGet, "/api/v1/tenants/name/"+name, nil)
	}

	t.Run("own name", func(t *testing.T) {
		rr := byName(tenantAToken, tenantAName)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var resp TenantResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, tenantAID, resp.ID)
	})

	t.Run("the system tenant resolves another tenant's name", func(t *testing.T) {
		rr := byName(tenantSystemToken, tenantBName)
		assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	})

	t.Run("the system tenant learns an unknown name is missing", func(t *testing.T) {
		rr := byName(tenantSystemToken, "no-such-tenant")
		assert.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	})

	t.Run("another tenant's name and an unknown name get one refusal", func(t *testing.T) {
		other := byName(tenantAToken, tenantBName)
		ghost := byName(tenantAToken, "no-such-tenant")
		require.Equal(t, http.StatusForbidden, other.Code, other.Body.String())
		require.Equal(t, http.StatusForbidden, ghost.Code, ghost.Body.String())
		assert.Equal(t, tenant.ErrNameLookupDenied{}.Error(), tenantErrorText(t, other))
		assert.Equal(t, tenantErrorText(t, other), tenantErrorText(t, ghost))
	})
}

// TestTenantRoutes_GuardRefusals: every tenant route is behind the guard, so
// a caller with no credential gets 401, a caller without the route's scope
// 403, and handlers built without a guard refuse with 403.
func TestTenantRoutes_GuardRefusals(t *testing.T) {
	t.Run("no credential", func(t *testing.T) {
		router := tenantAuthzRouter(t)
		for _, route := range tenantIDRoutes() {
			rr := serveTenant(t, router, "", route.method, fmt.Sprintf(route.path, tenantAID), route.body)
			assert.Equal(t, http.StatusUnauthorized, rr.Code, "%s %s", route.method, route.path)
		}
		for _, route := range tenantSystemRoutes() {
			rr := serveTenant(t, router, "", route.method, route.path, route.body)
			assert.Equal(t, http.StatusUnauthorized, rr.Code, route.op)
		}
		rr := serveTenant(t, router, "", http.MethodGet, "/api/v1/tenants/name/"+tenantAName, nil)
		assert.Equal(t, http.StatusUnauthorized, rr.Code, "by name")
	})

	t.Run("an invalid token", func(t *testing.T) {
		rr := serveTenant(t, tenantAuthzRouter(t), "forged", http.MethodGet, "/api/v1/tenants/"+tenantAID, nil)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("a read-only caller on its own tenant may read, not write or delete", func(t *testing.T) {
		router := tenantAuthzRouter(t)
		read := serveTenant(t, router, tenantReaderToken, http.MethodGet, "/api/v1/tenants/"+tenantAID, nil)
		assert.Equal(t, http.StatusOK, read.Code, read.Body.String())

		write := serveTenant(t, router, tenantReaderToken, http.MethodPost, "/api/v1/tenants/"+tenantAID+"/suspend", nil)
		assert.Equal(t, http.StatusForbidden, write.Code, write.Body.String())

		del := serveTenant(t, router, tenantReaderToken, http.MethodDelete, "/api/v1/tenants/"+tenantAID, nil)
		assert.Equal(t, http.StatusForbidden, del.Code, del.Body.String())
	})

	t.Run("handlers without a guard refuse every caller", func(t *testing.T) {
		mgr := newMockTenantManager()
		mgr.tenants[tenantAID] = createTestTenantEntity(tenantAID, tenantAName)
		router := mux.NewRouter()
		NewTenantHandlers(WithTenantManager(mgr), WithTenantSystemTenant(tenantSystemID)).RegisterRoutes(router)

		rr := serveTenant(t, router, tenantSystemToken, http.MethodGet, "/api/v1/tenants/"+tenantAID, nil)
		assert.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	})

	t.Run("without a system tenant no caller is the system tenant", func(t *testing.T) {
		mgr := newMockTenantManager()
		mgr.tenants[tenantAID] = createTestTenantEntity(tenantAID, tenantAName)
		router := mux.NewRouter()
		NewTenantHandlers(WithTenantManager(mgr), WithTenantGuard(tenantTestGuard())).RegisterRoutes(router)

		list := serveTenant(t, router, tenantSystemToken, http.MethodGet, "/api/v1/tenants", nil)
		assert.Equal(t, http.StatusForbidden, list.Code, list.Body.String())
		other := serveTenant(t, router, tenantSystemToken, http.MethodGet, "/api/v1/tenants/"+tenantAID, nil)
		assert.Equal(t, http.StatusForbidden, other.Code, other.Body.String())
	})
}
