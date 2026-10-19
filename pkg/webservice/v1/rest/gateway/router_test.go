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

package gateway

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

func newRouter() (*GatewayRouter, *mux.Router) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewGatewayRouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return r, parent
}

func TestGatewayRouter_RoutesRegistered(t *testing.T) {
	_, parent := newRouter()
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/gateway/status"},
		{http.MethodPost, "/api/v1/gateway/mode"},
		{http.MethodGet, "/api/v1/gateway/bgp/status"},
		{http.MethodGet, "/api/v1/gateway/bgp/peers"},
		{http.MethodGet, "/api/v1/gateway/bgp/prefixes"},
		{http.MethodPost, "/api/v1/gateway/bgp/prefixes"},
		{http.MethodDelete, "/api/v1/gateway/bgp/prefixes"},
		{http.MethodGet, "/api/v1/gateway/ipam/pools"},
		{http.MethodGet, "/api/v1/gateway/ipam/allocations"},
		{http.MethodPost, "/api/v1/gateway/ipam/allocations"},
		{http.MethodDelete, "/api/v1/gateway/ipam/allocations"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			assert.True(t, parent.Match(req, &match))
		})
	}
}
