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

package pxe

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

// newRouter mounts BOTH halves, the way v1Router.pxeRoutes does, so the
// existing behavioural tests keep exercising every route. Which half
// production hands to the gated router is asserted by the split tests below.
func newRouter() (*PXERouter, *mux.Router) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewPXERouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)
	parent := mux.NewRouter()
	sub := parent.PathPrefix("/api/v1").Subrouter()
	r.RegisterMachineFacingRoutes(sub)
	r.RegisterRoutes(sub)
	return r, parent
}

// registeredPXEPaths returns the "METHOD /path" set one registration method
// installs.
func registeredPXEPaths(register func(*mux.Router)) map[string]bool {
	m := mux.NewRouter()
	register(m.PathPrefix("/api/v1").Subrouter())

	out := map[string]bool{}
	_ = m.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil
		}
		for _, meth := range methods {
			out[meth+" "+path] = true
		}
		return nil
	})
	return out
}

// TestRegisterMachineFacingRoutes_IsOnlyTheWebhook pins the boundary of what
// #165 could close on this router. The webhook is the ONE PXE route with a
// non-operator caller, and it is ungated because that caller is a booting
// node — not because the route is safe. It presents no credential and the
// server checks none (#238). Any other route drifting in here would be
// published to anonymous callers with no issue tracking it.
func TestRegisterMachineFacingRoutes_IsOnlyTheWebhook(t *testing.T) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewPXERouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)

	assert.Equal(t, map[string]bool{
		"POST /api/v1/pxe/webhook/complete": true,
	}, registeredPXEPaths(r.RegisterMachineFacingRoutes))
}

// TestRegisterRoutes_CarriesTheOperatorLifecycle asserts the gated half holds
// the routes that decide whether a machine is admitted to the fleet.
func TestRegisterRoutes_CarriesTheOperatorLifecycle(t *testing.T) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewPXERouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)

	operator := registeredPXEPaths(r.RegisterRoutes)

	for _, route := range []string{
		"POST /api/v1/pxe/devices/{id}/authorize",
		"POST /api/v1/pxe/devices/{id}/quarantine",
		"POST /api/v1/pxe/devices/{id}/retry",
		"PUT /api/v1/pxe/devices/{id}/state",
		"DELETE /api/v1/pxe/devices/{id}",
		"POST /api/v1/pxe/start",
		"POST /api/v1/pxe/stop",
	} {
		assert.True(t, operator[route], "%s must be on the gated half", route)
	}

	assert.False(t, operator["POST /api/v1/pxe/webhook/complete"],
		"the webhook was registered on the gated half; a booting node cannot hold an operator session")
}

func TestPXERouter_RoutesRegistered(t *testing.T) {
	_, parent := newRouter()
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/pxe/status"},
		{http.MethodPost, "/api/v1/pxe/start"},
		{http.MethodPost, "/api/v1/pxe/stop"},
		{http.MethodPost, "/api/v1/pxe/webhook/complete"},
		{http.MethodGet, "/api/v1/pxe/devices"},
		{http.MethodPost, "/api/v1/pxe/devices"},
		{http.MethodGet, "/api/v1/pxe/devices/mac/aa:bb:cc:dd:ee:ff"},
		{http.MethodGet, "/api/v1/pxe/devices/d1"},
		{http.MethodDelete, "/api/v1/pxe/devices/d1"},
		{http.MethodPut, "/api/v1/pxe/devices/d1/state"},
		{http.MethodPost, "/api/v1/pxe/devices/d1/enrolled"},
		{http.MethodPost, "/api/v1/pxe/devices/d1/authorize"},
		{http.MethodPost, "/api/v1/pxe/devices/d1/quarantine"},
		{http.MethodPost, "/api/v1/pxe/devices/d1/retry"},
		{http.MethodGet, "/api/v1/pxe/devices/d1/events"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			assert.True(t, parent.Match(req, &match))
		})
	}
}

func TestPXERouter_NilServer(t *testing.T) {
	_, parent := newRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/status", nil)
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "pxe service is not available")
}
