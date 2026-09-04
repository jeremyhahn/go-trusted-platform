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

package tenant

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// passthroughAuthorization builds guards that admit everything, so the
// existing route-registration tests keep measuring registration rather than
// authorization. The guards' own behaviour is asserted in
// pkg/webservice/v1/middleware/iam and end to end in pkg/webservice/v1.
func passthroughAuthorization() Authorization {
	pass := func(next http.Handler) http.Handler { return next }
	return Authorization{
		RequireOwnTenantOrSystem: pass,
		RequireSystemTenant:      pass,
	}
}

func newRouter() (*TenantRouter, *mux.Router) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r, err := NewTenantRouter(
		logging.NewLogger(slog.LevelError, io.Discard), nil, w, passthroughAuthorization())
	if err != nil {
		panic(err)
	}
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return r, parent
}

// TestNewTenantRouter_FailsClosedWithoutItsGuards is the construction
// contract: this surface takes its target tenant from the URL, so publishing
// it without the guards would let any "admin" act on any tenant by changing a
// path segment. Refusing to build is the only safe response.
func TestNewTenantRouter_FailsClosedWithoutItsGuards(t *testing.T) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	pass := func(next http.Handler) http.Handler { return next }

	for name, authz := range map[string]Authorization{
		"no own-or-system guard": {RequireSystemTenant: pass},
		"no system guard":        {RequireOwnTenantOrSystem: pass},
		"neither":                {},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := NewTenantRouter(logger, nil, w, authz)
			assert.Error(t, err)
			assert.Nil(t, r)
		})
	}
}

func TestTenantRouter_RoutesRegistered(t *testing.T) {
	_, parent := newRouter()
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/tenants"},
		{http.MethodPost, "/api/v1/tenants"},
		{http.MethodPost, "/api/v1/tenants/sync"},
		{http.MethodGet, "/api/v1/tenants/by-name/foo"},
		{http.MethodGet, "/api/v1/tenants/t1"},
		{http.MethodPut, "/api/v1/tenants/t1"},
		{http.MethodDelete, "/api/v1/tenants/t1"},
		{http.MethodPost, "/api/v1/tenants/t1/suspend"},
		{http.MethodPost, "/api/v1/tenants/t1/resume"},
		{http.MethodGet, "/api/v1/tenants/t1/quotas"},
		{http.MethodPut, "/api/v1/tenants/t1/quotas"},
		{http.MethodGet, "/api/v1/tenants/t1/usage"},
		{http.MethodPost, "/api/v1/tenants/t1/quota-check"},
		{http.MethodPost, "/api/v1/tenants/t1/vlan/validate"},
		{http.MethodGet, "/api/v1/tenants/t1/bridge"},
		{http.MethodPost, "/api/v1/tenants/t1/dek/rotate"},
		{http.MethodGet, "/api/v1/tenants/t1/dek"},
		{http.MethodPost, "/api/v1/tenants/t1/barrier/init"},
		{http.MethodPost, "/api/v1/tenants/t1/barrier/unseal"},
		{http.MethodPost, "/api/v1/tenants/t1/barrier/seal"},
		{http.MethodGet, "/api/v1/tenants/t1/barrier"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			assert.True(t, parent.Match(req, &match))
		})
	}
}

func TestTenantRouter_NilServer(t *testing.T) {
	_, parent := newRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "tenant service is not available")
}
