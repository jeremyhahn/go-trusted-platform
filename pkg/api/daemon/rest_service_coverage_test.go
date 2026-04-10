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

package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
)

// mockHealthRegistry implements health.Registry for testing
type mockHealthRegistry struct {
	checkFunc          func(ctx context.Context) health.SystemHealth
	checkComponentFunc func(ctx context.Context, name string) (health.ComponentHealth, error)
	registerFunc       func(checker health.HealthChecker) error
	unregisterFunc     func(name string) error
	listFunc           func() []string
	countFunc          func() int
	closeFunc          func() error
}

func (m *mockHealthRegistry) Check(ctx context.Context) health.SystemHealth {
	if m.checkFunc != nil {
		return m.checkFunc(ctx)
	}
	return health.SystemHealth{
		Status:    health.StatusHealthy,
		Timestamp: time.Now().UTC(),
	}
}

func (m *mockHealthRegistry) CheckComponent(ctx context.Context, name string) (health.ComponentHealth, error) {
	if m.checkComponentFunc != nil {
		return m.checkComponentFunc(ctx, name)
	}
	return health.ComponentHealth{}, nil
}

func (m *mockHealthRegistry) Register(checker health.HealthChecker) error {
	if m.registerFunc != nil {
		return m.registerFunc(checker)
	}
	return nil
}

func (m *mockHealthRegistry) Unregister(name string) error {
	if m.unregisterFunc != nil {
		return m.unregisterFunc(name)
	}
	return nil
}

func (m *mockHealthRegistry) List() []string {
	if m.listFunc != nil {
		return m.listFunc()
	}
	return nil
}

func (m *mockHealthRegistry) Count() int {
	if m.countFunc != nil {
		return m.countFunc()
	}
	return 0
}

func (m *mockHealthRegistry) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

var _ health.Registry = (*mockHealthRegistry)(nil)

func TestHandleHealth_WithHealthRegistry_Healthy(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	mockRegistry := &mockHealthRegistry{
		checkFunc: func(ctx context.Context) health.SystemHealth {
			return health.SystemHealth{
				Status:    health.StatusHealthy,
				Timestamp: time.Now().UTC(),
				Components: []health.ComponentHealth{
					{
						Name:        "database",
						Status:      health.StatusHealthy,
						Message:     "connected",
						LastChecked: time.Now().UTC(),
					},
				},
			}
		},
	}
	service.SetHealthRegistry(mockRegistry)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var healthResp HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if healthResp.Status != "healthy" {
		t.Errorf("expected status 'healthy', got '%s'", healthResp.Status)
	}
}

func TestHandleHealth_WithHealthRegistry_Degraded(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	mockRegistry := &mockHealthRegistry{
		checkFunc: func(ctx context.Context) health.SystemHealth {
			return health.SystemHealth{
				Status:    health.StatusDegraded,
				Timestamp: time.Now().UTC(),
			}
		},
	}
	service.SetHealthRegistry(mockRegistry)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	var healthResp HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if healthResp.Status != "degraded" {
		t.Errorf("expected status 'degraded', got '%s'", healthResp.Status)
	}
}

func TestHandleHealth_WithHealthRegistry_Unhealthy(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	mockRegistry := &mockHealthRegistry{
		checkFunc: func(ctx context.Context) health.SystemHealth {
			return health.SystemHealth{
				Status:    health.StatusUnhealthy,
				Timestamp: time.Now().UTC(),
			}
		},
	}
	service.SetHealthRegistry(mockRegistry)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	var healthResp HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if healthResp.Status != "unhealthy" {
		t.Errorf("expected status 'unhealthy', got '%s'", healthResp.Status)
	}
}

func TestHandleHealth_WithHealthRegistry_Unknown(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	mockRegistry := &mockHealthRegistry{
		checkFunc: func(ctx context.Context) health.SystemHealth {
			return health.SystemHealth{
				Status:    health.StatusUnknown,
				Timestamp: time.Now().UTC(),
			}
		},
	}
	service.SetHealthRegistry(mockRegistry)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	var healthResp HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if healthResp.Status != "unknown" {
		t.Errorf("expected status 'unknown', got '%s'", healthResp.Status)
	}
}

func TestRESTServerStart_AlreadyRunning(t *testing.T) {
	config := DefaultConfig()
	config.RESTListenAddr = "127.0.0.1:0"
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	// Start the server
	if err := server.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Try to start again - should return error
	err = server.Start()
	if err == nil {
		t.Error("expected error for already running server")
	}

	var alreadyRunningErr ErrRESTServerAlreadyRunning
	if _, ok := err.(ErrRESTServerAlreadyRunning); !ok {
		t.Errorf("expected ErrRESTServerAlreadyRunning, got %T", err)
	}
	_ = alreadyRunningErr

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Stop(ctx)
}

func TestRESTServerStart_InvalidTLSCerts(t *testing.T) {
	config := DefaultConfig()
	config.RESTListenAddr = "127.0.0.1:0"
	config.RESTTLSCertFile = "/nonexistent/cert.pem"
	config.RESTTLSKeyFile = "/nonexistent/key.pem"

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	err = server.Start()
	if err == nil {
		t.Error("expected error for invalid TLS certs")
	}

	if server.IsRunning() {
		t.Error("server should not be running")
	}
}

func TestRESTServerStart_WithoutTLS(t *testing.T) {
	config := DefaultConfig()
	config.RESTListenAddr = "127.0.0.1:0"

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	if !server.IsRunning() {
		t.Error("server should be running")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Stop(ctx)
}

func TestWriteJSON_Success(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	w := httptest.NewRecorder()

	data := map[string]string{"message": "success"}
	server.writeJSON(w, http.StatusOK, data)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json content type")
	}

	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result["message"] != "success" {
		t.Errorf("expected message 'success', got '%s'", result["message"])
	}
}

func TestWriteJSON_DifferentStatusCodes(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	tests := []struct {
		name       string
		statusCode int
		data       interface{}
	}{
		{"created", http.StatusCreated, map[string]string{"id": "123"}},
		{"accepted", http.StatusAccepted, map[string]bool{"processing": true}},
		{"bad_request", http.StatusBadRequest, map[string]string{"error": "invalid input"}},
		{"internal_error", http.StatusInternalServerError, map[string]string{"error": "fail"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			server.writeJSON(w, tt.statusCode, tt.data)
			if w.Code != tt.statusCode {
				t.Errorf("expected status %d, got %d", tt.statusCode, w.Code)
			}
		})
	}
}

func TestHandleGetService_NotFound(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/services/nonexistent-service", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", resp.StatusCode)
	}
}

func TestHandleGetService_AllStatuses(t *testing.T) {
	tests := []struct {
		name           string
		statusValue    int32
		expectedStatus string
	}{
		{"unspecified", int32(platformv1.ServiceStatus_SERVICE_STATUS_UNSPECIFIED), "unspecified"},
		{"stopped", int32(platformv1.ServiceStatus_SERVICE_STATUS_STOPPED), "stopped"},
		{"starting", int32(platformv1.ServiceStatus_SERVICE_STATUS_STARTING), "starting"},
		{"running", int32(platformv1.ServiceStatus_SERVICE_STATUS_RUNNING), "running"},
		{"stopping", int32(platformv1.ServiceStatus_SERVICE_STATUS_STOPPING), "stopping"},
		{"error", int32(platformv1.ServiceStatus_SERVICE_STATUS_ERROR), "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			service, err := NewService(config)
			if err != nil {
				t.Fatalf("NewService failed: %v", err)
			}

			mockSvc := newMockService("test-service")
			if err := service.RegisterService(mockSvc); err != nil {
				t.Fatalf("RegisterService failed: %v", err)
			}

			service.mu.Lock()
			if state, ok := service.services["test-service"]; ok {
				state.status.Store(tt.statusValue)
			}
			service.mu.Unlock()

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			server, err := NewRESTServer(config, service, logger)
			if err != nil {
				t.Fatalf("NewRESTServer failed: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/api/v1/services/test-service", nil)
			w := httptest.NewRecorder()

			server.router.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status 200, got %d", resp.StatusCode)
			}

			var svcResp ServiceInfoResponse
			if err := json.NewDecoder(resp.Body).Decode(&svcResp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if svcResp.Status != tt.expectedStatus {
				t.Errorf("expected status '%s', got '%s'", tt.expectedStatus, svcResp.Status)
			}
		})
	}
}

func TestRESTServerStop_NotRunning(t *testing.T) {
	config := DefaultConfig()
	config.RESTListenAddr = "127.0.0.1:0"

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	ctx := context.Background()
	err = server.Stop(ctx)
	if err == nil {
		t.Error("expected error for server not running")
	}

	if _, ok := err.(ErrRESTServerNotRunning); !ok {
		t.Errorf("expected ErrRESTServerNotRunning, got %T", err)
	}
}

func TestRESTServerForceStop_NotRunning(t *testing.T) {
	config := DefaultConfig()
	config.RESTListenAddr = "127.0.0.1:0"

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	err = server.ForceStop()
	if err == nil {
		t.Error("expected error for server not running")
	}

	if _, ok := err.(ErrRESTServerNotRunning); !ok {
		t.Errorf("expected ErrRESTServerNotRunning, got %T", err)
	}
}

func TestRESTCov_ServerRouter(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	if err != nil {
		t.Fatalf("NewRESTServer failed: %v", err)
	}

	router := server.Router()
	if router == nil {
		t.Error("expected non-nil router")
	}
}

func TestExtractPort(t *testing.T) {
	tests := []struct {
		addr     string
		expected int
	}{
		{"0.0.0.0:8443", 8443},
		{"127.0.0.1:9443", 9443},
		{":8080", 8080},
		{"localhost:3000", 3000},
		{"invalid", 0},
		{"no-port-here", 0},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			result := extractPort(tt.addr)
			if result != tt.expected {
				t.Errorf("extractPort(%q) = %d, want %d", tt.addr, result, tt.expected)
			}
		})
	}
}

func TestBoolToStatus(t *testing.T) {
	if boolToStatus(true) != "running" {
		t.Errorf("boolToStatus(true) should return 'running'")
	}
	if boolToStatus(false) != "stopped" {
		t.Errorf("boolToStatus(false) should return 'stopped'")
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID(1)
	id2 := generateRequestID(2)

	if id1 == "" || id2 == "" {
		t.Error("generateRequestID should not return empty string")
	}
	if id1 == id2 {
		t.Error("generateRequestID should return unique IDs")
	}
}

func TestGetMCPAddress(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		config := &Config{MCPConfig: nil}
		if getMCPAddress(config) != "" {
			t.Error("expected empty string for nil MCPConfig")
		}
	})

	t.Run("with config", func(t *testing.T) {
		config := &Config{
			MCPConfig: &MCPConfig{
				HTTPAddr: "127.0.0.1:9445",
			},
		}
		if getMCPAddress(config) != "127.0.0.1:9445" {
			t.Error("expected correct HTTP address")
		}
	})
}
