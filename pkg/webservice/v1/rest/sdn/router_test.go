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

package sdn

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestNewSDNRouter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, nil)
	mock := &mockSDNService{}
	respWriter := &mockResponseWriter{}

	router := NewSDNRouter(logger, mock, respWriter)

	require.NotNil(t, router)
	require.NotNil(t, router.handlers)
}

func TestRegisterRoutes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, nil)
	mock := &mockSDNService{}
	respWriter := &mockResponseWriter{}

	sdnRouter := NewSDNRouter(logger, mock, respWriter)
	router := mux.NewRouter()

	sdnRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

	// Test that routes are registered by checking if they match

	tests := []struct {
		name   string
		method string
		path   string
	}{
		// Bridge routes
		{"CreateBridge", http.MethodPost, "/api/v1/sdn/bridges"},
		{"ListBridges", http.MethodGet, "/api/v1/sdn/bridges"},
		{"GetBridge", http.MethodGet, "/api/v1/sdn/bridges/br0"},
		{"DeleteBridge", http.MethodDelete, "/api/v1/sdn/bridges/br0"},

		// Port routes
		{"AddPort", http.MethodPost, "/api/v1/sdn/bridges/br0/ports"},
		{"DeletePort", http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/port0"},
		{"GetPortState", http.MethodGet, "/api/v1/sdn/bridges/br0/ports/port0/state"},
		{"SetPortState", http.MethodPut, "/api/v1/sdn/bridges/br0/ports/port0/state"},
		{"GetPortStats", http.MethodGet, "/api/v1/sdn/bridges/br0/ports/port0/stats"},

		// Flow routes
		{"AddFlow", http.MethodPost, "/api/v1/sdn/flows"},
		{"DeleteFlow", http.MethodDelete, "/api/v1/sdn/flows"},
		{"ListFlows", http.MethodGet, "/api/v1/sdn/flows"},

		// Policy routes
		{"ApplyPolicy", http.MethodPost, "/api/v1/sdn/policies"},
		{"ListPolicies", http.MethodGet, "/api/v1/sdn/policies"},
		{"GetPolicy", http.MethodGet, "/api/v1/sdn/policies/policy-1"},

		// VLAN routes
		{"CreateVLAN", http.MethodPost, "/api/v1/sdn/vlans"},
		{"ListVLANs", http.MethodGet, "/api/v1/sdn/vlans"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.True(t, matched, "Route %s %s should match", tt.method, tt.path)
		})
	}
}

func TestRouterHandlerExecution(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, nil)
	mock := &mockSDNService{}
	respWriter := &mockResponseWriter{}

	sdnRouter := NewSDNRouter(logger, mock, respWriter)
	router := mux.NewRouter()
	sdnRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

	// Test that a route can actually be executed
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/policies", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// ListPolicies returns 200 with empty list
	assert.Equal(t, http.StatusOK, w.Code)
}
