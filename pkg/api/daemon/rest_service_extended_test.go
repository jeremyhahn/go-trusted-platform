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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: Uses mockManagedService from daemon_test.go and newMockService helper

// =============================================================================
// Service Lifecycle Handler Tests
// =============================================================================

func TestRESTHandlerGetService_ExistingService(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	// Register a mock service
	mockSvc := newMockService("test-service")
	service.RegisterService(mockSvc)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	// Test getting existing service
	req := httptest.NewRequest(http.MethodGet, "/api/v1/services/test-service", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var svcResp ServiceInfoResponse
	err = json.NewDecoder(resp.Body).Decode(&svcResp)
	require.NoError(t, err)
	assert.Equal(t, "test-service", svcResp.Name)
	// RegisterService stores SERVICE_STATUS_STOPPED (value 1),
	// which correctly maps to "stopped" in the REST status mapping
	assert.Equal(t, "stopped", svcResp.Status)
}

func TestRESTHandlerGetService_ServiceStates(t *testing.T) {
	tests := []struct {
		name           string
		setupService   func(*mockManagedService)
		expectedStatus string
	}{
		{
			name:           "newly registered service",
			setupService:   func(m *mockManagedService) {},
			expectedStatus: "stopped", // SERVICE_STATUS_STOPPED (1) maps to "stopped"
		},
		{
			name: "running service flag set on mock",
			setupService: func(m *mockManagedService) {
				m.running.Store(true)
			},
			expectedStatus: "stopped", // Status is determined by state.status, not IsRunning
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			service, err := NewService(config)
			require.NoError(t, err)

			mockSvc := newMockService("test-service")
			tt.setupService(mockSvc)
			service.RegisterService(mockSvc)

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			server, err := NewRESTServer(config, service, logger)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/services/test-service", nil)
			w := httptest.NewRecorder()

			server.router.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var svcResp ServiceInfoResponse
			err = json.NewDecoder(resp.Body).Decode(&svcResp)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, svcResp.Status)
		})
	}
}

func TestRESTHandlerStartService_Success(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	mockSvc := newMockService("test-service")
	service.RegisterService(mockSvc)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/test-service/start", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var actionResp ServiceActionResponse
	err = json.NewDecoder(resp.Body).Decode(&actionResp)
	require.NoError(t, err)
	assert.True(t, actionResp.Success)
	assert.Equal(t, "start", actionResp.Action)
	assert.Equal(t, "test-service", actionResp.Service)
	assert.True(t, mockSvc.IsRunning())
}

func TestRESTHandlerStartService_NotFound(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/nonexistent/start", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestRESTHandlerStartService_AlreadyRunning(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	mockSvc := newMockService("test-service")
	mockSvc.running.Store(true)
	service.RegisterService(mockSvc)

	// Set service state to running (SERVICE_STATUS_RUNNING = 3)
	service.mu.Lock()
	if state, ok := service.services["test-service"]; ok {
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_RUNNING))
	}
	service.mu.Unlock()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/test-service/start", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestRESTHandlerStartService_StartFailed(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	mockSvc := newMockService("test-service")
	mockSvc.startErr = ErrServiceStartFailed{ServiceName: "test-service", Reason: "simulated error"}
	service.RegisterService(mockSvc)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/test-service/start", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestRESTHandlerStopService_Success(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	mockSvc := newMockService("test-service")
	mockSvc.running.Store(true)
	service.RegisterService(mockSvc)

	// Set service state to running (SERVICE_STATUS_RUNNING = 3)
	service.mu.Lock()
	if state, ok := service.services["test-service"]; ok {
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_RUNNING))
	}
	service.mu.Unlock()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/test-service/stop", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var actionResp ServiceActionResponse
	err = json.NewDecoder(resp.Body).Decode(&actionResp)
	require.NoError(t, err)
	assert.True(t, actionResp.Success)
	assert.Equal(t, "stop", actionResp.Action)
	assert.False(t, mockSvc.IsRunning())
}

func TestRESTHandlerStopService_NotFound(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/nonexistent/stop", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestRESTHandlerStopService_NotRunning(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	mockSvc := newMockService("test-service")
	service.RegisterService(mockSvc)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/test-service/stop", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestRESTHandlerStopService_StopFailed(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	mockSvc := newMockService("test-service")
	mockSvc.running.Store(true)
	mockSvc.stopErr = ErrServiceStopFailed{ServiceName: "test-service", Reason: "simulated error"}
	service.RegisterService(mockSvc)

	// Set service state to running (SERVICE_STATUS_RUNNING = 3)
	service.mu.Lock()
	if state, ok := service.services["test-service"]; ok {
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_RUNNING))
	}
	service.mu.Unlock()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/test-service/stop", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestRESTHandlerRestartService_Success(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	mockSvc := newMockService("test-service")
	service.RegisterService(mockSvc)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/test-service/restart", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var actionResp ServiceActionResponse
	err = json.NewDecoder(resp.Body).Decode(&actionResp)
	require.NoError(t, err)
	assert.True(t, actionResp.Success)
	assert.Equal(t, "restart", actionResp.Action)
}

func TestRESTHandlerRestartService_NotFound(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/nonexistent/restart", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestRESTHandlerRestartService_RunningThenRestart(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	mockSvc := newMockService("test-service")
	mockSvc.running.Store(true)
	service.RegisterService(mockSvc)

	// Set service state to running (SERVICE_STATUS_RUNNING = 3)
	service.mu.Lock()
	if state, ok := service.services["test-service"]; ok {
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_RUNNING))
	}
	service.mu.Unlock()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/test-service/restart", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var actionResp ServiceActionResponse
	err = json.NewDecoder(resp.Body).Decode(&actionResp)
	require.NoError(t, err)
	assert.True(t, actionResp.Success)
	assert.Equal(t, int32(1), mockSvc.stopCount.Load())
	assert.Equal(t, int32(1), mockSvc.startCount.Load())
}

func TestRESTHandlerRestartService_StopFailed(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	mockSvc := newMockService("test-service")
	mockSvc.running.Store(true)
	mockSvc.stopErr = ErrServiceStopFailed{ServiceName: "test-service", Reason: "simulated error"}
	service.RegisterService(mockSvc)

	// Set service state to running (SERVICE_STATUS_RUNNING = 3)
	service.mu.Lock()
	if state, ok := service.services["test-service"]; ok {
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_RUNNING))
	}
	service.mu.Unlock()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/test-service/restart", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestRESTHandlerRestartService_StartFailed(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	mockSvc := newMockService("test-service")
	mockSvc.startErr = ErrServiceStartFailed{ServiceName: "test-service", Reason: "simulated error"}
	service.RegisterService(mockSvc)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/services/test-service/restart", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// =============================================================================
// Service List with Multiple Services Tests
// =============================================================================

func TestRESTHandlerListServices_MultipleServices(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	// Register multiple mock services
	svc1 := newMockService("service-a")
	svc2 := newMockService("service-b")
	svc3 := newMockService("service-c")
	svc3.running.Store(true)

	service.RegisterService(svc1)
	service.RegisterService(svc2)
	service.RegisterService(svc3)

	// Set svc3 to running state (SERVICE_STATUS_RUNNING = 3)
	service.mu.Lock()
	if state, ok := service.services["service-c"]; ok {
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_RUNNING))
		state.startedAt = time.Now()
	}
	service.mu.Unlock()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/services", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var servicesResp ServicesListResponse
	err = json.NewDecoder(resp.Body).Decode(&servicesResp)
	require.NoError(t, err)
	assert.Equal(t, 3, servicesResp.Count)
	assert.Len(t, servicesResp.Services, 3)
}

// =============================================================================
// Health Endpoint with Registry Tests
// =============================================================================

func TestRESTHandlerHealth_WithoutRegistry(t *testing.T) {
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var healthResp HealthResponse
	err = json.NewDecoder(resp.Body).Decode(&healthResp)
	require.NoError(t, err)
	assert.Equal(t, "healthy", healthResp.Status)
}

// =============================================================================
// Server Lifecycle Tests
// =============================================================================

func TestRESTServerForceStop_Success(t *testing.T) {
	config := DefaultConfig()
	config.SkipIAMValidation = true // lifecycle test: the REST auth gate (#550) is not under test here
	config.RESTListenAddr = "127.0.0.1:0"
	cert := sharedTestTLSCertificate()
	config.TLSCertificate = &cert
	service, err := NewService(config)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	// Start the server
	err = server.Start()
	require.NoError(t, err)
	assert.True(t, server.IsRunning())

	// Force stop
	err = server.ForceStop()
	require.NoError(t, err)
	assert.False(t, server.IsRunning())
}

func TestRESTServerStartWithTLS_InvalidCert(t *testing.T) {
	config := DefaultConfig()
	config.SkipIAMValidation = true // lifecycle test: the REST auth gate (#550) is not under test here
	config.RESTListenAddr = "127.0.0.1:0"
	config.RESTTLSCertFile = "/nonexistent/cert.pem"
	config.RESTTLSKeyFile = "/nonexistent/key.pem"

	service, err := NewService(config)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	err = server.Start()
	assert.Error(t, err)
	assert.False(t, server.IsRunning())

	var startErr ErrRESTServerStartFailed
	assert.ErrorAs(t, err, &startErr)
}

// =============================================================================
// Response Type Tests
// =============================================================================

func TestRESTResponseTypes_JSONMarshal(t *testing.T) {
	t.Run("HealthResponse", func(t *testing.T) {
		resp := HealthResponse{
			Status:    "healthy",
			Timestamp: time.Now().UTC(),
			Components: []ComponentHealthResponse{
				{
					Name:      "db",
					Status:    "healthy",
					Message:   "connected",
					LastCheck: time.Now().UTC(),
				},
			},
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.Contains(t, string(data), "healthy")
	})

	t.Run("StatusResponse", func(t *testing.T) {
		resp := StatusResponse{
			Status:    "ready",
			Version:   "1.0.0",
			BuildTime: "2025-01-01",
			GitCommit: "abc123",
			GoVersion: "go1.21",
			System: SystemInfoResponse{
				OS:                "linux",
				Arch:              "amd64",
				NumCPUs:           4,
				TotalMemoryMB:     8192,
				AvailableMemoryMB: 4096,
				Uptime:            "1h30m",
			},
			Timestamp: time.Now().UTC(),
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.Contains(t, string(data), "ready")
		assert.Contains(t, string(data), "linux")
	})

	t.Run("VersionResponse", func(t *testing.T) {
		resp := VersionResponse{
			Version:   "1.0.0",
			BuildTime: "2025-01-01",
			GitCommit: "abc123",
			GoVersion: "go1.21",
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.Contains(t, string(data), "1.0.0")
	})

	t.Run("ServiceInfoResponse", func(t *testing.T) {
		resp := ServiceInfoResponse{
			Name:       "test-service",
			Status:     "running",
			StartedAt:  time.Now().UTC(),
			Uptime:     "5m",
			StartCount: 1,
			StopCount:  0,
			LastError:  "",
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.Contains(t, string(data), "test-service")
	})

	t.Run("ServicesListResponse", func(t *testing.T) {
		resp := ServicesListResponse{
			Services: []ServiceInfoResponse{
				{Name: "svc1"},
				{Name: "svc2"},
			},
			Count:     2,
			Timestamp: time.Now().UTC(),
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.Contains(t, string(data), "svc1")
		assert.Contains(t, string(data), "svc2")
	})

	t.Run("ServiceActionResponse", func(t *testing.T) {
		resp := ServiceActionResponse{
			Service: "test-service",
			Action:  "start",
			Success: true,
			Message: "started successfully",
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.Contains(t, string(data), "start")
		assert.Contains(t, string(data), "true")
	})

	t.Run("ProtocolsResponse", func(t *testing.T) {
		resp := ProtocolsResponse{
			Protocols: []ProtocolStatusResponse{
				{
					Name:    "REST",
					Enabled: true,
					Address: "0.0.0.0:8443",
					Port:    8443,
					Status:  "running",
					TLS:     true,
				},
			},
			Timestamp: time.Now().UTC(),
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.Contains(t, string(data), "REST")
		assert.Contains(t, string(data), "8443")
	})

	t.Run("ErrorResponse", func(t *testing.T) {
		resp := ErrorResponse{
			Error:     "something went wrong",
			Code:      500,
			Timestamp: time.Now().UTC(),
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.Contains(t, string(data), "something went wrong")
		assert.Contains(t, string(data), "500")
	})
}

// =============================================================================
// CORS Configuration Tests
// =============================================================================

func TestRESTCORSMiddleware_AllowedOrigins(t *testing.T) {
	tests := []struct {
		name           string
		allowedOrigins []string
		requestOrigin  string
		expectCORS     bool
	}{
		{
			name:           "exact match",
			allowedOrigins: []string{"https://example.com"},
			requestOrigin:  "https://example.com",
			expectCORS:     true,
		},
		{
			name:           "wildcard",
			allowedOrigins: []string{"*"},
			requestOrigin:  "https://any-origin.com",
			expectCORS:     true,
		},
		{
			name:           "not allowed",
			allowedOrigins: []string{"https://allowed.com"},
			requestOrigin:  "https://notallowed.com",
			expectCORS:     false,
		},
		{
			name:           "no origin header",
			allowedOrigins: []string{"https://example.com"},
			requestOrigin:  "",
			expectCORS:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.RESTConfig.EnableCORS = true
			config.RESTConfig.AllowedOrigins = tt.allowedOrigins

			service, err := NewService(config)
			require.NoError(t, err)

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			server, err := NewRESTServer(config, service, logger)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
			if tt.requestOrigin != "" {
				req.Header.Set("Origin", tt.requestOrigin)
			}
			w := httptest.NewRecorder()

			handler := server.applyMiddleware(server.router)
			handler.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			corsHeader := resp.Header.Get("Access-Control-Allow-Origin")
			if tt.expectCORS {
				assert.NotEmpty(t, corsHeader)
			} else {
				assert.Empty(t, corsHeader)
			}
		})
	}
}

func TestRESTCORSMiddleware_DisabledCORS(t *testing.T) {
	config := DefaultConfig()
	config.RESTConfig.EnableCORS = false

	service, err := NewService(config)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewRESTServer(config, service, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	handler := server.applyMiddleware(server.router)
	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// CORS header should not be set when CORS is disabled
	corsHeader := resp.Header.Get("Access-Control-Allow-Origin")
	assert.Empty(t, corsHeader)
}

// =============================================================================
// gzipResponseWriter Tests
// =============================================================================

func TestGzipResponseWriter(t *testing.T) {
	t.Run("Header returns correct headers", func(t *testing.T) {
		w := httptest.NewRecorder()
		w.Header().Set("Content-Type", "application/json")
		// gzipResponseWriter wraps the ResponseWriter
		gzw := &gzipResponseWriter{ResponseWriter: w}
		assert.Equal(t, "application/json", gzw.Header().Get("Content-Type"))
	})
}

// =============================================================================
// statusWriter Tests
// =============================================================================

func TestStatusWriter(t *testing.T) {
	t.Run("WriteHeader captures status code", func(t *testing.T) {
		w := httptest.NewRecorder()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		sw.WriteHeader(http.StatusNotFound)
		assert.Equal(t, http.StatusNotFound, sw.status)
	})

	t.Run("Write defaults to 200 if WriteHeader not called", func(t *testing.T) {
		w := httptest.NewRecorder()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		_, err := sw.Write([]byte("test"))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, sw.status)
	})
}
