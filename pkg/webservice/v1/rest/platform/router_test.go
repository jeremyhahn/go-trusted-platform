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

package platform

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// newTestRouter creates a mux.Router with an /api/v1 subrouter, mirroring
// the production mount point in webserver_v1.go. It returns both the root
// router (for ServeHTTP) and the API subrouter (for RegisterRoutes).
func newTestRouter() (root *mux.Router, apiRouter *mux.Router) {
	root = mux.NewRouter()
	apiRouter = root.PathPrefix("/api/v1").Subrouter()
	return root, apiRouter
}

func TestNewPlatformRouter(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	router := NewPlatformRouter(logger, respWriter)
	if router == nil {
		t.Fatal("expected router to be created")
	}

	if router.handlers == nil {
		t.Fatal("expected handlers to be created")
	}
}

func TestPlatformRouter_RegisterRoutes(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	platformRouter := NewPlatformRouter(logger, respWriter)

	// Set up config for protocols endpoint
	config := &ProtocolConfig{
		EnableREST:     true,
		RESTListenAddr: "0.0.0.0:8443",
		RESTTLSEnabled: true,
		EnableGRPCTCP:  true,
		GRPCListenAddr: "0.0.0.0:10443",
		GRPCTLSEnabled: false,
		SocketPath:     "/run/platformd.sock",
		EnableQUIC:     true,
		QUICListenAddr: "0.0.0.0:9444",
		EnableMCP:      true,
		MCPHTTPAddr:    "127.0.0.1:9445",
	}
	platformRouter.SetProtocolConfig(config)

	root, apiRouter := newTestRouter()
	platformRouter.RegisterRoutes(apiRouter)

	// Test that routes are registered by making requests
	tests := []struct {
		name     string
		method   string
		path     string
		wantCode int
	}{
		{
			name:     "health endpoint",
			method:   http.MethodGet,
			path:     "/api/v1/platform/health",
			wantCode: http.StatusOK,
		},
		{
			name:     "status endpoint",
			method:   http.MethodGet,
			path:     "/api/v1/platform/status",
			wantCode: http.StatusOK,
		},
		{
			name:     "version endpoint",
			method:   http.MethodGet,
			path:     "/api/v1/platform/version",
			wantCode: http.StatusOK,
		},
		{
			name:     "protocols endpoint",
			method:   http.MethodGet,
			path:     "/api/v1/platform/protocols",
			wantCode: http.StatusOK,
		},
		{
			name:     "services endpoint without daemon service",
			method:   http.MethodGet,
			path:     "/api/v1/platform/services",
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()

			root.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Errorf("expected status %d, got %d", tc.wantCode, rec.Code)
			}
		})
	}
}

func TestPlatformRouter_SetHealthRegistry(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	platformRouter := NewPlatformRouter(logger, respWriter)
	root, apiRouter := newTestRouter()
	platformRouter.RegisterRoutes(apiRouter)

	// Create a mock health registry with a healthy component
	registry := health.NewRegistry()
	registry.Register(&mockHealthChecker{
		name:   "test-component",
		status: health.StatusHealthy,
	})
	platformRouter.SetHealthRegistry(registry)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/health", nil)
	rec := httptest.NewRecorder()

	root.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp response.WebServiceResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}

	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatal("expected payload to be a map")
	}

	components, ok := payload["components"].([]interface{})
	if !ok {
		t.Fatal("expected components to be an array")
	}

	if len(components) != 1 {
		t.Errorf("expected 1 component, got %d", len(components))
	}
}

func TestPlatformRouter_Handlers(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	platformRouter := NewPlatformRouter(logger, respWriter)

	handlers := platformRouter.Handlers()
	if handlers == nil {
		t.Fatal("expected handlers to not be nil")
	}

	if handlers != platformRouter.handlers {
		t.Error("expected Handlers() to return the same handlers instance")
	}
}

func TestPlatformRouter_SetRESTServerRunningFunc(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	platformRouter := NewPlatformRouter(logger, respWriter)

	// Set up config for protocols endpoint
	config := &ProtocolConfig{
		EnableREST:     true,
		RESTListenAddr: "0.0.0.0:8443",
		RESTTLSEnabled: true,
		EnableGRPCTCP:  true,
		GRPCListenAddr: "0.0.0.0:10443",
		GRPCTLSEnabled: false,
		SocketPath:     "/run/platformd.sock",
		EnableQUIC:     true,
		QUICListenAddr: "0.0.0.0:9444",
		EnableMCP:      true,
		MCPHTTPAddr:    "127.0.0.1:9445",
	}
	platformRouter.SetProtocolConfig(config)

	// Set the REST server running function
	called := false
	platformRouter.SetRESTServerRunningFunc(func() bool {
		called = true
		return true
	})

	root, apiRouter := newTestRouter()
	platformRouter.RegisterRoutes(apiRouter)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/protocols", nil)
	rec := httptest.NewRecorder()

	root.ServeHTTP(rec, req)

	if !called {
		t.Error("expected REST server running function to be called")
	}
}

func TestPlatformRouter_ServiceEndpoints(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	platformRouter := NewPlatformRouter(logger, respWriter)
	root, apiRouter := newTestRouter()
	platformRouter.RegisterRoutes(apiRouter)

	// Test service-related endpoints (should fail without daemon service)
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "list services",
			method: http.MethodGet,
			path:   "/api/v1/platform/services",
		},
		{
			name:   "get service",
			method: http.MethodGet,
			path:   "/api/v1/platform/services/tpm",
		},
		{
			name:   "start service",
			method: http.MethodPost,
			path:   "/api/v1/platform/services/tpm/start",
		},
		{
			name:   "stop service",
			method: http.MethodPost,
			path:   "/api/v1/platform/services/tpm/stop",
		},
		{
			name:   "restart service",
			method: http.MethodPost,
			path:   "/api/v1/platform/services/tpm/restart",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()

			root.ServeHTTP(rec, req)

			// Should return 500 since no daemon service is configured
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
			}
		})
	}
}
