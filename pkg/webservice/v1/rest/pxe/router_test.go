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

func newRouter() (*PXERouter, *mux.Router) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewPXERouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return r, parent
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
