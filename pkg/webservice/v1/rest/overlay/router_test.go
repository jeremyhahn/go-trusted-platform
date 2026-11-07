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

package overlay

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

func newRouter() (*OverlayRouter, *mux.Router) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewOverlayRouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return r, parent
}

// overlayRoutes is every route RegisterRoutes mounts.
var overlayRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/overlay/status"},
	{http.MethodGet, "/api/v1/overlay/vteps"},
	{http.MethodGet, "/api/v1/overlay/vteps/n1"},
	{http.MethodGet, "/api/v1/overlay/vnis"},
	{http.MethodPost, "/api/v1/overlay/vnis"},
	{http.MethodDelete, "/api/v1/overlay/vnis/100"},
	{http.MethodGet, "/api/v1/overlay/tunnels"},
	{http.MethodGet, "/api/v1/overlay/tunnels/stats"},
	{http.MethodGet, "/api/v1/overlay/macs"},
	{http.MethodDelete, "/api/v1/overlay/macs"},
}

func TestOverlayRouter_NilServer(t *testing.T) {
	_, parent := newRouter()
	for _, tc := range overlayRoutes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			parent.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
			assert.Contains(t, rec.Body.String(), "overlay service is not available")
		})
	}
}
