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

package dns

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestNewDNSRouter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	service := newMockDNSService()
	writer := &mockHttpWriter{}

	router := NewDNSRouter(logger, service, writer)

	require.NotNil(t, router)
	assert.NotNil(t, router.handlers)
}

func TestDNSRouter_RegisterRoutes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	service := newMockDNSService()
	writer := &mockHttpWriter{}
	dnsRouter := NewDNSRouter(logger, service, writer)

	router := mux.NewRouter()
	dnsRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

	// Test that routes are registered by walking the router
	routeCount := 0
	err := router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		routeCount++
		return nil
	})
	require.NoError(t, err)

	// Should have multiple routes registered
	assert.Greater(t, routeCount, 0)
}

// TestDNSRouter_RoutesNameTheirRPC checks the route table both listeners
// mount: every route has a handler and names the DNSService RPC whose scope
// the daemon listener requires, and no method and path is mounted twice.
func TestDNSRouter_RoutesNameTheirRPC(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	routes := NewDNSRouter(logger, newMockDNSService(), &mockHttpWriter{}).Routes()

	require.Len(t, routes, 13)
	seen := make(map[string]bool, len(routes))
	for _, route := range routes {
		key := route.Method + " " + route.Path
		assert.False(t, seen[key], "mounted twice: %s", key)
		seen[key] = true
		assert.NotNil(t, route.Handler, key)
		assert.True(t, strings.HasPrefix(route.RPC, "/platform.v1.DNSService/"), "%s names %q", key, route.RPC)
	}
}

func TestDNSRouter_ZoneRoutes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	service := newMockDNSService()
	writer := &mockHttpWriter{}
	dnsRouter := NewDNSRouter(logger, service, writer)

	router := mux.NewRouter()
	dnsRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"CreateZone", http.MethodPost, "/api/v1/dns/zones"},
		{"ListZones", http.MethodGet, "/api/v1/dns/zones"},
		{"GetZone", http.MethodGet, "/api/v1/dns/zones/example.com."},
		{"UpdateZone", http.MethodPut, "/api/v1/dns/zones/example.com."},
		{"DeleteZone", http.MethodDelete, "/api/v1/dns/zones/example.com."},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)

			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.True(t, matched, "Route should match: %s %s", tc.method, tc.path)
		})
	}
}

func TestDNSRouter_RecordRoutes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	service := newMockDNSService()
	writer := &mockHttpWriter{}
	dnsRouter := NewDNSRouter(logger, service, writer)

	router := mux.NewRouter()
	dnsRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"AddRecord", http.MethodPost, "/api/v1/dns/zones/example.com./records"},
		{"ListRecords", http.MethodGet, "/api/v1/dns/zones/example.com./records"},
		{"GetRecord", http.MethodGet, "/api/v1/dns/zones/example.com./records/A/www"},
		{"DeleteRecord", http.MethodDelete, "/api/v1/dns/zones/example.com./records/A/www"},
		{"Resolve", http.MethodGet, "/api/v1/dns/resolve?fqdn=www.example.com.&type=A"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)

			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.True(t, matched, "Route should match: %s %s", tc.method, tc.path)
		})
	}
}

// TestDNSRouter_GetAndListRecordsAnswerDistinctly serves both record reads
// through the router: one record by type and name, and the zone's list.
func TestDNSRouter_GetAndListRecordsAnswerDistinctly(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	service := newMockDNSService()
	service.zones["example.com."] = recordLookupZone()
	writer := &mockHttpWriter{}
	router := mux.NewRouter()
	NewDNSRouter(logger, service, writer).RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones/example.com./records/A/api", nil))
	require.Equal(t, http.StatusOK, writer.lastStatus)
	assert.Equal(t, RecordResponse{Type: "A", A: &AResponse{Name: "api", Value: "192.168.1.9", TTL: 300}}, writer.lastPayload)

	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones/example.com./records", nil))
	require.Equal(t, http.StatusOK, writer.lastStatus)
	list, ok := writer.lastPayload.(ListRecordsResponse)
	require.True(t, ok, "the collection route answered %T", writer.lastPayload)
	assert.Len(t, list.Records, 4)
}

func TestDNSRouter_DNSSECRoutes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	service := newMockDNSService()
	writer := &mockHttpWriter{}
	dnsRouter := NewDNSRouter(logger, service, writer)

	router := mux.NewRouter()
	dnsRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"SignZone", http.MethodPost, "/api/v1/dns/zones/example.com./sign"},
		{"GetDNSSECStatus", http.MethodGet, "/api/v1/dns/zones/example.com./dnssec"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)

			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.True(t, matched, "Route should match: %s %s", tc.method, tc.path)
		})
	}
}

func TestDNSRouter_RegistrationRoutes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	service := newMockDNSService()
	writer := &mockHttpWriter{}
	dnsRouter := NewDNSRouter(logger, service, writer)

	router := mux.NewRouter()
	dnsRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/register", nil)

	var match mux.RouteMatch
	matched := router.Match(req, &match)
	assert.True(t, matched, "Route should match: POST /api/v1/dns/register")
}

func TestDNSRouter_MethodNotAllowed(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	service := newMockDNSService()
	writer := &mockHttpWriter{}
	dnsRouter := NewDNSRouter(logger, service, writer)

	router := mux.NewRouter()
	dnsRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

	// Test that incorrect methods don't match
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"PUT_zones", http.MethodPut, "/api/v1/dns/zones"},
		{"DELETE_zones", http.MethodDelete, "/api/v1/dns/zones"},
		{"POST_zone", http.MethodPost, "/api/v1/dns/zones/example.com."},
		{"GET_register", http.MethodGet, "/api/v1/dns/register"},
		{"POST_resolve", http.MethodPost, "/api/v1/dns/resolve"},
		{"PUT_record", http.MethodPut, "/api/v1/dns/zones/example.com./records/A/www"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)

			var match mux.RouteMatch
			matched := router.Match(req, &match)
			// Should either not match or match with MethodNotAllowed
			if matched && match.MatchErr == nil {
				// Check that handler is nil (method mismatch)
				assert.Nil(t, match.Handler, "Should not have handler for wrong method: %s %s", tc.method, tc.path)
			}
		})
	}
}
