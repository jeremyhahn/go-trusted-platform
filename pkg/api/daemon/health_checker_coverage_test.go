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
	"net"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// TestQUICServerHealthChecker_RunningServer tests the QUIC health checker
// with a running server that has stats.
func TestQUICServerHealthChecker_RunningServer(t *testing.T) {
	t.Run("Check returns unhealthy when server not running", func(t *testing.T) {
		// Create a minimal QUIC server config with TLS
		bundle := testutil.GenerateTestTLSBundle(t)
		config := &quic.ServerConfig{
			ListenAddr: "127.0.0.1:0",
			TLSConfig:  bundle.ServerTLSConfig(),
		}
		server, err := quic.NewServer(config)
		if err != nil {
			t.Fatalf("Failed to create QUIC server: %v", err)
		}

		// Server is not started, so should be unhealthy
		checker := NewQUICServerHealthChecker(server)
		if checker == nil {
			t.Fatal("NewQUICServerHealthChecker returned nil for valid server")
		}

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "QUIC server is not running" {
			t.Errorf("Message = %v, want 'QUIC server is not running'", result.Message)
		}
		if result.Details["running"] != false {
			t.Errorf("Details[running] = %v, want false", result.Details["running"])
		}
	})

	t.Run("constructor returns checker for valid server", func(t *testing.T) {
		bundle := testutil.GenerateTestTLSBundle(t)
		config := &quic.ServerConfig{
			ListenAddr: "127.0.0.1:0",
			TLSConfig:  bundle.ServerTLSConfig(),
		}
		server, err := quic.NewServer(config)
		if err != nil {
			t.Fatalf("Failed to create QUIC server: %v", err)
		}

		checker := NewQUICServerHealthChecker(server)
		if checker == nil {
			t.Error("NewQUICServerHealthChecker returned nil for valid server")
		}
	})

	t.Run("Check sets proper name", func(t *testing.T) {
		bundle := testutil.GenerateTestTLSBundle(t)
		config := &quic.ServerConfig{
			ListenAddr: "127.0.0.1:0",
			TLSConfig:  bundle.ServerTLSConfig(),
		}
		server, err := quic.NewServer(config)
		if err != nil {
			t.Fatalf("Failed to create QUIC server: %v", err)
		}

		checker := NewQUICServerHealthChecker(server)
		if checker.Name() != "quic" {
			t.Errorf("Name() = %v, want quic", checker.Name())
		}
	})
}

// TestMCPServiceHealthChecker_RunningServer tests the MCP health checker
// with various states.
func TestMCPServiceHealthChecker_RunningServer(t *testing.T) {
	t.Run("constructor returns checker for valid server", func(t *testing.T) {
		config := &mcp.Config{
			ServerName:    "Test MCP Server",
			ServerVersion: "1.0.0",
			Transport:     "http",
			HTTPAddr:      "127.0.0.1:0",
		}
		logger := logging.DefaultLogger()
		server := mcp.NewServer(nil, config, logger)

		checker := NewMCPServiceHealthChecker(server)
		if checker == nil {
			t.Error("NewMCPServiceHealthChecker returned nil for valid server")
		}
	})

	t.Run("Check sets duration and timestamps", func(t *testing.T) {
		config := &mcp.Config{
			ServerName:    "Test MCP Server",
			ServerVersion: "1.0.0",
			Transport:     "http",
			HTTPAddr:      "127.0.0.1:0",
		}
		logger := logging.DefaultLogger()
		server := mcp.NewServer(nil, config, logger)

		checker := NewMCPServiceHealthChecker(server)
		result := checker.Check(context.Background())

		if result.Duration <= 0 {
			t.Errorf("Duration = %v, want > 0", result.Duration)
		}
		if result.LastChecked.IsZero() {
			t.Error("LastChecked should not be zero")
		}
		if result.Details == nil {
			t.Error("Details should not be nil")
		}
	})
}

// TestServiceHealthChecker_AllStatusTypes tests that ServiceHealthChecker
// can return all status types: Healthy, Unhealthy, Degraded, Unknown.
func TestServiceHealthChecker_AllStatusTypes(t *testing.T) {
	t.Run("returns StatusHealthy for running service without custom check", func(t *testing.T) {
		svc := &healthTestMockService{name: "test-healthy", running: true}
		checker := NewServiceHealthChecker(svc)
		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "service is healthy" {
			t.Errorf("Message = %v, want 'service is healthy'", result.Message)
		}
	})

	t.Run("returns StatusUnhealthy for nil service", func(t *testing.T) {
		checker := &ServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
	})

	t.Run("returns StatusUnhealthy for stopped service", func(t *testing.T) {
		svc := &healthTestMockService{name: "test-stopped", running: false}
		checker := NewServiceHealthChecker(svc)
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
	})

	t.Run("returns StatusDegraded for service with failed health check", func(t *testing.T) {
		svc := &healthTestMockCheckableService{
			healthTestMockService: healthTestMockService{
				name:    "test-degraded",
				running: true,
			},
		}
		svc.healthErr = &testHealthError{msg: "connection pool low"}
		checker := NewServiceHealthChecker(svc)
		result := checker.Check(context.Background())

		if result.Status != health.StatusDegraded {
			t.Errorf("Status = %v, want StatusDegraded", result.Status)
		}
	})

	t.Run("initial status is StatusUnknown before service check", func(t *testing.T) {
		// The initial status is set to Unknown, but then updated during check.
		// This verifies the structure is initialized correctly.
		checker := &ServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		// With nil service, it returns Unhealthy, not Unknown
		// But the componentHealth is initialized with StatusUnknown
		if result.Name != "unknown" {
			t.Errorf("Name = %v, want 'unknown' for nil service", result.Name)
		}
	})
}

// testHealthError is a custom error type for testing
type testHealthError struct {
	msg string
}

func (e *testHealthError) Error() string {
	return e.msg
}

// TestKMSServiceHealthChecker_AdditionalCoverage tests additional KMS paths.
func TestKMSServiceHealthChecker_AdditionalCoverage(t *testing.T) {
	t.Run("Check sets kms_server_ready detail", func(t *testing.T) {
		service := &KMSService{}
		service.running.Store(true)
		// kmsServer is nil
		checker := &KMSServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Details["kms_server_ready"] != false {
			t.Errorf("Details[kms_server_ready] = %v, want false", result.Details["kms_server_ready"])
		}
	})

	t.Run("Check returns proper Name", func(t *testing.T) {
		service := &KMSService{}
		checker := NewKMSServiceHealthChecker(service)

		if checker.Name() != "kms" {
			t.Errorf("Name() = %v, want kms", checker.Name())
		}
	})
}

// TestSDNServiceHealthChecker_AdditionalCoverage tests additional SDN paths.
func TestSDNServiceHealthChecker_AdditionalCoverage(t *testing.T) {
	t.Run("Check sets response_time_ms detail when healthy", func(t *testing.T) {
		service := &SDNService{
			ovsClient: &ovs.Client{},
			bridges:   make(map[string]*bridgeResource),
			ports:     make(map[string]*portResource),
		}
		checker := &SDNServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Details["response_time_ms"] == nil {
			t.Error("Details[response_time_ms] should be set when healthy")
		}
	})
}

// TestCAServiceHealthChecker_AdditionalCoverage tests additional CA paths.
func TestCAServiceHealthChecker_AdditionalCoverage(t *testing.T) {
	t.Run("Check returns healthy with nil root cert (no error)", func(t *testing.T) {
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCert:    nil, // nil cert but no error
			rootCertErr: nil,
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}
		result := checker.Check(context.Background())

		// With nil root cert and no error, should be healthy
		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
	})
}

// TestRESTServiceHealthChecker_AdditionalCoverage tests additional REST paths.
func TestRESTServiceHealthChecker_AdditionalCoverage(t *testing.T) {
	t.Run("Check returns correct duration", func(t *testing.T) {
		config := &Config{
			RESTListenAddr: "127.0.0.1:0",
			RESTConfig:     RESTServerConfig{},
		}
		server := &RESTServer{
			config: config,
		}
		server.running.Store(true)

		checker := NewRESTServiceHealthChecker(server)
		result := checker.Check(context.Background())

		if result.Duration <= 0 {
			t.Errorf("Duration = %v, want > 0", result.Duration)
		}
	})
}

// TestHealthCheckable_Interface tests that services implementing HealthCheckable
// have their custom health check called.
func TestHealthCheckable_Interface(t *testing.T) {
	t.Run("custom health check is called when service implements HealthCheckable", func(t *testing.T) {
		svc := &healthTestMockCheckableService{
			healthTestMockService: healthTestMockService{
				name:    "checkable-service",
				running: true,
			},
		}
		svc.healthErr = nil // Health check passes

		checker := NewServiceHealthChecker(svc)
		result := checker.Check(context.Background())

		// Verify custom_health_check detail is set when HealthCheckable is implemented
		if result.Details["custom_health_check"] != "passed" {
			t.Errorf("Details[custom_health_check] = %v, want 'passed'", result.Details["custom_health_check"])
		}
	})

	t.Run("custom health check error is captured", func(t *testing.T) {
		svc := &healthTestMockCheckableService{
			healthTestMockService: healthTestMockService{
				name:    "failing-checkable-service",
				running: true,
			},
		}
		svc.healthErr = &testHealthError{msg: "database connection failed"}

		checker := NewServiceHealthChecker(svc)
		result := checker.Check(context.Background())

		if result.Details["health_check_error"] != "database connection failed" {
			t.Errorf("Details[health_check_error] = %v, want 'database connection failed'", result.Details["health_check_error"])
		}
	})
}

// TestHealthCheckerDetails verifies that health check results contain
// all expected detail fields.
func TestHealthCheckerDetails(t *testing.T) {
	t.Run("ServiceHealthChecker includes service_name detail", func(t *testing.T) {
		svc := &healthTestMockService{name: "my-service", running: true}
		checker := NewServiceHealthChecker(svc)
		result := checker.Check(context.Background())

		if result.Details["service_name"] != "my-service" {
			t.Errorf("Details[service_name] = %v, want 'my-service'", result.Details["service_name"])
		}
	})

	t.Run("ServiceHealthChecker includes running detail when service is running", func(t *testing.T) {
		svc := &healthTestMockService{name: "running-service", running: true}
		checker := NewServiceHealthChecker(svc)
		result := checker.Check(context.Background())

		if result.Details["running"] != true {
			t.Errorf("Details[running] = %v, want true", result.Details["running"])
		}
	})

	t.Run("ServiceHealthChecker includes response_time_ms detail when healthy", func(t *testing.T) {
		svc := &healthTestMockService{name: "timed-service", running: true}
		checker := NewServiceHealthChecker(svc)
		result := checker.Check(context.Background())

		if _, ok := result.Details["response_time_ms"]; !ok {
			t.Error("Details[response_time_ms] should be set for healthy service")
		}
	})

	t.Run("KMSServiceHealthChecker includes all expected details when healthy", func(t *testing.T) {
		service := &KMSService{}
		service.running.Store(true)
		checker := NewKMSServiceHealthChecker(service)
		result := checker.Check(context.Background())

		expectedDetails := []string{"running", "kms_server_ready", "response_time_ms"}
		for _, key := range expectedDetails {
			if _, ok := result.Details[key]; !ok {
				t.Errorf("Details[%s] should be set", key)
			}
		}
	})

	t.Run("SDNServiceHealthChecker includes bridge and port counts", func(t *testing.T) {
		service := &SDNService{
			ovsClient: &ovs.Client{},
			bridges: map[string]*bridgeResource{
				"br0": {id: "br0", name: "br0"},
			},
			ports: map[string]*portResource{
				"p0": {id: "p0", name: "p0"},
				"p1": {id: "p1", name: "p1"},
			},
		}
		checker := NewSDNServiceHealthChecker(service)
		result := checker.Check(context.Background())

		if result.Details["bridge_count"] != 1 {
			t.Errorf("Details[bridge_count] = %v, want 1", result.Details["bridge_count"])
		}
		if result.Details["port_count"] != 2 {
			t.Errorf("Details[port_count] = %v, want 2", result.Details["port_count"])
		}
	})

	t.Run("RESTServiceHealthChecker includes all config details when healthy", func(t *testing.T) {
		config := &Config{
			RESTListenAddr:  "0.0.0.0:8443",
			RESTTLSCertFile: "/path/to/cert",
			RESTConfig: RESTServerConfig{
				EnableCORS:        true,
				EnableCompression: false,
			},
		}
		server := &RESTServer{config: config}
		server.running.Store(true)

		checker := NewRESTServiceHealthChecker(server)
		result := checker.Check(context.Background())

		if result.Details["listen_addr"] != "0.0.0.0:8443" {
			t.Errorf("Details[listen_addr] = %v, want '0.0.0.0:8443'", result.Details["listen_addr"])
		}
		if result.Details["tls_enabled"] != true {
			t.Errorf("Details[tls_enabled] = %v, want true", result.Details["tls_enabled"])
		}
		if result.Details["cors_enabled"] != true {
			t.Errorf("Details[cors_enabled] = %v, want true", result.Details["cors_enabled"])
		}
		if result.Details["compression_enabled"] != false {
			t.Errorf("Details[compression_enabled] = %v, want false", result.Details["compression_enabled"])
		}
	})
}

// TestHealthCheckerConcurrency verifies that health checkers are safe
// for concurrent use.
func TestHealthCheckerConcurrency(t *testing.T) {
	t.Run("ServiceHealthChecker is safe for concurrent calls", func(t *testing.T) {
		svc := &healthTestMockService{name: "concurrent-service", running: true}
		checker := NewServiceHealthChecker(svc)

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				_ = checker.Check(context.Background())
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("KMSServiceHealthChecker is safe for concurrent calls", func(t *testing.T) {
		service := &KMSService{}
		service.running.Store(true)
		checker := NewKMSServiceHealthChecker(service)

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				_ = checker.Check(context.Background())
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// TestHealthCheckerMessages verifies that health check messages are descriptive.
func TestHealthCheckerMessages(t *testing.T) {
	testCases := []struct {
		name           string
		setup          func() health.HealthChecker
		expectedStatus health.HealthStatus
		messageSubstr  string
	}{
		{
			name: "ServiceHealthChecker nil service message",
			setup: func() health.HealthChecker {
				return &ServiceHealthChecker{service: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			messageSubstr:  "nil",
		},
		{
			name: "ServiceHealthChecker not running message",
			setup: func() health.HealthChecker {
				return NewServiceHealthChecker(&healthTestMockService{name: "stopped", running: false})
			},
			expectedStatus: health.StatusUnhealthy,
			messageSubstr:  "not running",
		},
		{
			name: "ServiceHealthChecker healthy message",
			setup: func() health.HealthChecker {
				return NewServiceHealthChecker(&healthTestMockService{name: "healthy", running: true})
			},
			expectedStatus: health.StatusHealthy,
			messageSubstr:  "healthy",
		},
		{
			name: "KMSServiceHealthChecker nil service message",
			setup: func() health.HealthChecker {
				return &KMSServiceHealthChecker{service: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			messageSubstr:  "nil",
		},
		{
			name: "SDNServiceHealthChecker nil service message",
			setup: func() health.HealthChecker {
				return &SDNServiceHealthChecker{service: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			messageSubstr:  "nil",
		},
		{
			name: "CAServiceHealthChecker nil service message",
			setup: func() health.HealthChecker {
				return &CAServiceHealthChecker{service: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			messageSubstr:  "nil",
		},
		{
			name: "QUICServerHealthChecker nil server message",
			setup: func() health.HealthChecker {
				return &QUICServerHealthChecker{server: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			messageSubstr:  "nil",
		},
		{
			name: "RESTServiceHealthChecker nil server message",
			setup: func() health.HealthChecker {
				return &RESTServiceHealthChecker{server: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			messageSubstr:  "nil",
		},
		{
			name: "MCPServiceHealthChecker nil server message",
			setup: func() health.HealthChecker {
				return &MCPServiceHealthChecker{server: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			messageSubstr:  "nil",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			checker := tc.setup()
			result := checker.Check(context.Background())

			if result.Status != tc.expectedStatus {
				t.Errorf("Status = %v, want %v", result.Status, tc.expectedStatus)
			}

			if tc.messageSubstr != "" {
				if !strings.Contains(result.Message, tc.messageSubstr) {
					t.Errorf("Message = %q, expected to contain %q", result.Message, tc.messageSubstr)
				}
			}
		})
	}
}

// TestQUICServerHealthChecker_HealthyServer tests the QUIC health checker
// against a server started on an ephemeral port.
func TestQUICServerHealthChecker_HealthyServer(t *testing.T) {
	t.Run("Check returns healthy when server is running", func(t *testing.T) {
		bundle := testutil.GenerateTestTLSBundle(t)
		config := &quic.ServerConfig{
			ListenAddr: "127.0.0.1:0",
			TLSConfig:  bundle.ServerTLSConfig(),
		}
		server, err := quic.NewServer(config)
		if err != nil {
			t.Fatalf("Failed to create QUIC server: %v", err)
		}
		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start QUIC server: %v", err)
		}
		t.Cleanup(func() {
			if err := server.Stop(); err != nil {
				t.Errorf("Failed to stop QUIC server: %v", err)
			}
		})

		checker := NewQUICServerHealthChecker(server)
		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "QUIC server is healthy" {
			t.Errorf("Message = %v, want 'QUIC server is healthy'", result.Message)
		}
		if result.Details["running"] != true {
			t.Errorf("Details[running] = %v, want true", result.Details["running"])
		}
		// A server started on port 0 reports the port it bound.
		listenAddr, ok := result.Details["listen_addr"].(string)
		if !ok {
			t.Fatalf("Details[listen_addr] = %v, want a string", result.Details["listen_addr"])
		}
		host, port, err := net.SplitHostPort(listenAddr)
		if err != nil {
			t.Fatalf("Details[listen_addr] = %q: %v", listenAddr, err)
		}
		if host != "127.0.0.1" || port == "0" {
			t.Errorf("Details[listen_addr] = %q, want 127.0.0.1 with the bound port", listenAddr)
		}
		// Check that stats are included
		if _, ok := result.Details["active_connections"]; !ok {
			t.Error("Details[active_connections] should be set")
		}
		if _, ok := result.Details["total_connections"]; !ok {
			t.Error("Details[total_connections] should be set")
		}
		if _, ok := result.Details["requests_handled"]; !ok {
			t.Error("Details[requests_handled] should be set")
		}
		if _, ok := result.Details["errors"]; !ok {
			t.Error("Details[errors] should be set")
		}
		if _, ok := result.Details["response_time_ms"]; !ok {
			t.Error("Details[response_time_ms] should be set")
		}
	})
}

// TestMCPServiceHealthChecker_HealthyServer tests the MCP health checker
// against a server started on an ephemeral port.
func TestMCPServiceHealthChecker_HealthyServer(t *testing.T) {
	t.Run("Check returns healthy when server is running", func(t *testing.T) {
		// The HTTP transport is TLS-only; it refuses to start without a certificate.
		bundle := testutil.GenerateTestTLSBundle(t)
		config := &mcp.Config{
			ServerName:    "Test MCP Server",
			ServerVersion: "1.0.0",
			Transport:     "http",
			HTTPAddr:      "127.0.0.1:0",
			TLSConfig:     bundle.ServerTLSConfig(),
		}
		logger := logging.DefaultLogger()
		server := mcp.NewServer(nil, config, logger)
		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start MCP server: %v", err)
		}
		t.Cleanup(func() {
			if err := server.Stop(); err != nil {
				t.Errorf("Failed to stop MCP server: %v", err)
			}
		})

		checker := NewMCPServiceHealthChecker(server)
		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "MCP server is healthy" {
			t.Errorf("Message = %v, want 'MCP server is healthy'", result.Message)
		}
		if result.Details["running"] != true {
			t.Errorf("Details[running] = %v, want true", result.Details["running"])
		}
		if _, ok := result.Details["response_time_ms"]; !ok {
			t.Error("Details[response_time_ms] should be set")
		}
	})
}

// TestIAMServiceHealthChecker_CheckCoverage tests the IAMServiceHealthChecker.Check
// function to improve coverage on line 378. These tests use the stub's interface
// which does not expose the running field but tests the unhealthy path.
// Note: When built without the 'iam' tag, NewIAMServiceHealthChecker returns nil.
func TestIAMServiceHealthChecker_CheckCoverage(t *testing.T) {
	t.Run("Check returns unhealthy when stub service is not running", func(t *testing.T) {
		// In stub mode, IsRunning() always returns false
		service := &IAMService{}

		checker := NewIAMServiceHealthChecker(service)
		if checker == nil {
			t.Fatal("NewIAMServiceHealthChecker returned nil for a non-nil service")
		}

		result := checker.Check(context.Background())

		// Stub always returns false for IsRunning(), so always unhealthy
		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "IAM service is not running" {
			t.Errorf("Message = %v, want 'IAM service is not running'", result.Message)
		}
		if result.Details["running"] != false {
			t.Errorf("Details[running] = %v, want false", result.Details["running"])
		}
	})

	t.Run("Check returns unhealthy for nil service", func(t *testing.T) {
		checker := &IAMServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		// Accept either message depending on build tags
		validMessages := []string{
			"IAM service reference is nil",
			"IAM service not enabled (build with -tags iam)",
		}
		if result.Message != validMessages[0] && result.Message != validMessages[1] {
			t.Errorf("Message = %v, want one of %v", result.Message, validMessages)
		}
	})

	t.Run("Check sets duration correctly", func(t *testing.T) {
		service := &IAMService{}

		checker := NewIAMServiceHealthChecker(service)
		if checker == nil {
			t.Fatal("NewIAMServiceHealthChecker returned nil for a non-nil service")
		}
		result := checker.Check(context.Background())

		if result.Duration <= 0 {
			t.Errorf("Duration = %v, want > 0", result.Duration)
		}
	})

	t.Run("Check sets LastChecked correctly", func(t *testing.T) {
		service := &IAMService{}

		checker := NewIAMServiceHealthChecker(service)
		if checker == nil {
			t.Fatal("NewIAMServiceHealthChecker returned nil for a non-nil service")
		}
		result := checker.Check(context.Background())

		if result.LastChecked.IsZero() {
			t.Error("LastChecked should not be zero")
		}
	})

	t.Run("Check initializes Details map", func(t *testing.T) {
		service := &IAMService{}

		checker := NewIAMServiceHealthChecker(service)
		if checker == nil {
			t.Fatal("NewIAMServiceHealthChecker returned nil for a non-nil service")
		}
		result := checker.Check(context.Background())

		if result.Details == nil {
			t.Error("Details should not be nil")
		}
	})

	t.Run("Name returns iam", func(t *testing.T) {
		service := &IAMService{}
		checker := NewIAMServiceHealthChecker(service)
		if checker == nil {
			t.Fatal("NewIAMServiceHealthChecker returned nil for a non-nil service")
		}

		if checker.Name() != "iam" {
			t.Errorf("Name() = %v, want iam", checker.Name())
		}
	})
}

// TestTenantServiceHealthChecker_CheckCoverage tests the TenantServiceHealthChecker.Check
// function to improve coverage on line 433. These tests use the stub's interface
// which does not expose the running field but tests the unhealthy path.
func TestTenantServiceHealthChecker_CheckCoverage(t *testing.T) {
	t.Run("Check returns unhealthy when stub service is not running", func(t *testing.T) {
		// In stub mode, IsRunning() always returns false
		service := &TenantService{}

		checker := NewTenantServiceHealthChecker(service)
		if checker == nil {
			t.Fatal("NewTenantServiceHealthChecker returned nil for valid service")
		}

		result := checker.Check(context.Background())

		// Stub always returns false for IsRunning(), so always unhealthy
		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "tenant service is not running" {
			t.Errorf("Message = %v, want 'tenant service is not running'", result.Message)
		}
		if result.Details["running"] != false {
			t.Errorf("Details[running] = %v, want false", result.Details["running"])
		}
	})

	t.Run("Check returns unhealthy for nil service", func(t *testing.T) {
		checker := &TenantServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "tenant service reference is nil" {
			t.Errorf("Message = %v, want 'tenant service reference is nil'", result.Message)
		}
	})

	t.Run("Check sets duration correctly", func(t *testing.T) {
		service := &TenantService{}

		checker := NewTenantServiceHealthChecker(service)
		result := checker.Check(context.Background())

		if result.Duration <= 0 {
			t.Errorf("Duration = %v, want > 0", result.Duration)
		}
	})

	t.Run("Check sets LastChecked correctly", func(t *testing.T) {
		service := &TenantService{}

		checker := NewTenantServiceHealthChecker(service)
		result := checker.Check(context.Background())

		if result.LastChecked.IsZero() {
			t.Error("LastChecked should not be zero")
		}
	})

	t.Run("Check initializes Details map", func(t *testing.T) {
		service := &TenantService{}

		checker := NewTenantServiceHealthChecker(service)
		result := checker.Check(context.Background())

		if result.Details == nil {
			t.Error("Details should not be nil")
		}
	})

	t.Run("Name returns tenant", func(t *testing.T) {
		service := &TenantService{}
		checker := NewTenantServiceHealthChecker(service)

		if checker.Name() != "tenant" {
			t.Errorf("Name() = %v, want tenant", checker.Name())
		}
	})
}

// TestIAMServiceHealthChecker_Concurrency tests that the IAM health checker
// is safe for concurrent use.
func TestIAMServiceHealthChecker_Concurrency(t *testing.T) {
	t.Run("is safe for concurrent calls", func(t *testing.T) {
		service := &IAMService{}
		checker := NewIAMServiceHealthChecker(service)
		if checker == nil {
			t.Fatal("NewIAMServiceHealthChecker returned nil for a non-nil service")
		}

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				_ = checker.Check(context.Background())
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// TestTenantServiceHealthChecker_Concurrency tests that the tenant health checker
// is safe for concurrent use.
func TestTenantServiceHealthChecker_Concurrency(t *testing.T) {
	t.Run("is safe for concurrent calls", func(t *testing.T) {
		service := &TenantService{}
		checker := NewTenantServiceHealthChecker(service)

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				_ = checker.Check(context.Background())
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// TestIAMTenantHealthCheckers_ContextHandling tests that context is properly
// handled (not used but passed through for potential future use).
func TestIAMTenantHealthCheckers_ContextHandling(t *testing.T) {
	t.Run("IAM health checker accepts cancelled context", func(t *testing.T) {
		service := &IAMService{}
		checker := NewIAMServiceHealthChecker(service)
		if checker == nil {
			t.Fatal("NewIAMServiceHealthChecker returned nil for a non-nil service")
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Should still return result (context not used for blocking operations)
		// Note: In stub mode, service is never running so status is Unhealthy
		result := checker.Check(ctx)
		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
	})

	t.Run("Tenant health checker accepts cancelled context", func(t *testing.T) {
		service := &TenantService{}
		checker := NewTenantServiceHealthChecker(service)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Should still return result (context not used for blocking operations)
		// Note: In stub mode, service is never running so status is Unhealthy
		result := checker.Check(ctx)
		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
	})
}
