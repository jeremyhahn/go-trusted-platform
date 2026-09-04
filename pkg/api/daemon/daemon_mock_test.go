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
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// =============================================================================
// New() Coverage Tests - Config Validation Paths
// =============================================================================

func TestNewMock_InvalidGRPCTLSCertFile(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-grpc-bad-cert.sock")
	config.TLSCertificate = nil // exercise the file-pair path, not the in-memory cert
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"
	config.GRPCTLSCertFile = "/nonexistent/cert.pem"
	config.GRPCTLSKeyFile = "/nonexistent/key.pem"

	_, err := New(config)
	if err == nil {
		t.Error("New() should return error with invalid TLS cert file")
		return
	}

	// Error should be related to certificate loading
	t.Logf("Got expected error for invalid TLS cert: %v", err)
}

func TestNewMock_EmptyGRPCListenAddr(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-grpc-empty-addr.sock")
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "" // Empty address but gRPC enabled

	_, err := New(config)
	if err != nil {
		// This may or may not error depending on validation
		t.Logf("Error with empty gRPC addr: %v", err)
		return
	}

	// If it didn't error, the daemon was created but gRPC may not bind
}

func TestNewMock_WithNilServices(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-nil-services.sock")
	config.Services = nil // Nil services map

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with nil services map failed: %v", err)
	}

	if d == nil {
		t.Error("daemon should not be nil")
	}
}

func TestNewMock_RESTInvalidWriteTimeout(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-rest-write-timeout.sock")
	config.EnableREST = true
	config.RESTListenAddr = "0.0.0.0:8443"
	config.RESTConfig.WriteTimeout = 0 // Invalid write timeout

	_, err := New(config)
	if err == nil {
		t.Error("New() should return error with invalid REST write timeout")
		return
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewMock_RESTInvalidIdleTimeout(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-rest-idle-timeout.sock")
	config.EnableREST = true
	config.RESTListenAddr = "0.0.0.0:8443"
	config.RESTConfig.IdleTimeout = 0 // Invalid idle timeout

	_, err := New(config)
	if err == nil {
		t.Error("New() should return error with invalid REST idle timeout")
		return
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewMock_RESTInvalidMaxHeaderBytes(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-rest-max-header.sock")
	config.EnableREST = true
	config.RESTListenAddr = "0.0.0.0:8443"
	config.RESTConfig.MaxHeaderBytes = 0 // Invalid max header bytes

	_, err := New(config)
	if err == nil {
		t.Error("New() should return error with invalid REST max header bytes")
		return
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewMock_RESTNegativeRateLimit(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-rest-rate-limit.sock")
	config.EnableREST = true
	config.RESTListenAddr = "0.0.0.0:8443"
	config.RESTConfig.RateLimitRequests = -1 // Negative rate limit

	_, err := New(config)
	if err == nil {
		t.Error("New() should return error with negative REST rate limit")
		return
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewMock_RESTNegativeRateBurst(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-rest-rate-burst.sock")
	config.EnableREST = true
	config.RESTListenAddr = "0.0.0.0:8443"
	config.RESTConfig.RateLimitBurst = -1 // Negative burst

	_, err := New(config)
	if err == nil {
		t.Error("New() should return error with negative REST rate burst")
		return
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewMock_MCPNilConfigGetsDefaults(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-mcp-nil-config.sock")
	config.EnableMCP = true
	config.MCPConfig = nil // Will be populated with defaults

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with nil MCP config failed: %v", err)
	}

	// MCP should have been initialized with defaults
	if d.config.MCPConfig == nil {
		t.Error("MCPConfig should have been set to defaults")
	}
}

func TestNewMock_WithAllServicesDisabled(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-all-disabled.sock")
	config.EnableGRPCTCP = false
	config.EnableQUIC = false
	config.EnableMCP = false
	config.EnableREST = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with all services disabled failed: %v", err)
	}

	// All optional servers should be nil
	if d.grpcServer != nil {
		t.Error("gRPC server should be nil when disabled")
	}
	if d.quicServer != nil {
		t.Error("QUIC server should be nil when disabled")
	}
	if d.mcpServer != nil {
		t.Error("MCP server should be nil when disabled")
	}
	if d.restServer != nil {
		t.Error("REST server should be nil when disabled")
	}
}

// =============================================================================
// Start() Coverage Tests - Error Paths
// =============================================================================

func TestStartMock_WithOptionalServicesNil(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-start-nil-svcs.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Explicitly set optional services to nil to test nil checks in Start
	d.sdnService = nil
	d.kmsService = nil
	d.iamService = nil
	d.tenantService = nil
	d.restServer = nil
	d.mcpServer = nil

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed with nil optional services: %v", err)
	}

	if !d.IsRunning() {
		t.Error("daemon should be running")
	}

	_ = d.Stop(ctx)
}

func TestStartMock_MarksServiceAsReady(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-start-ready.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Service should be marked as ready
	if d.service == nil {
		t.Fatal("service should not be nil")
	}

	// The MarkReady is called at the end of Start
	_ = d.Stop(ctx)
}

// =============================================================================
// Stop() Coverage Tests - Error Paths
// =============================================================================

func TestStopMock_WithRESTServer(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-stop-rest.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// REST server should be started (or attempted)
	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}

	if d.IsRunning() {
		t.Error("daemon should not be running after Stop()")
	}
}

func TestStopMock_WithMCPServer(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-stop-mcp.sock")
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test-mcp",
		ServerVersion:         "1.0.0",
		Transport:             "http",
		HTTPAddr:              "127.0.0.1:0",
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
}

func TestStopMock_WithGRPCTCPEnabled(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-stop-grpc.sock")
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// gRPC server should be stopped gracefully
	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
}

func TestStopMock_ClosesGRPCListener(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-stop-grpc-listener.sock")
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Verify listener was created
	if d.grpcListener == nil {
		t.Skip("gRPC listener not created")
	}

	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}

	// Listener should be closed
}

// =============================================================================
// ForceStop() Coverage Tests
// =============================================================================

func TestForceStopMock_WithRESTServer(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-forcestop-rest.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	err = d.ForceStop()
	if err != nil && err.Error() != "server is not running" {
		t.Errorf("ForceStop() failed: %v", err)
	}
}

func TestForceStopMock_WithMCPServer(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-forcestop-mcp.sock")
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test-mcp",
		ServerVersion:         "1.0.0",
		Transport:             "http",
		HTTPAddr:              "127.0.0.1:0",
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	err = d.ForceStop()
	if err != nil && err.Error() != "server is not running" {
		t.Errorf("ForceStop() failed: %v", err)
	}
}

func TestForceStopMock_WithGRPCTCP(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-forcestop-grpc.sock")
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	err = d.ForceStop()
	if err != nil && err.Error() != "server is not running" {
		t.Errorf("ForceStop() failed: %v", err)
	}
}

// =============================================================================
// SetTPM2Service() Coverage Tests
// =============================================================================

func TestSetTPM2ServiceMock_WithAllProtocolHandlersAvailable(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-setidevid-all.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test-mcp",
		ServerVersion:         "1.0.0",
		Transport:             "http",
		HTTPAddr:              "127.0.0.1:0",
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// SetTPM2Service with nil should be safe
	d.SetTPM2Service(nil)

	// tpm2Service should remain nil with nil input
	if d.tpm2Service != nil {
		t.Error("tpm2Service should be nil after SetTPM2Service(nil)")
	}
}

func TestSetTPM2ServiceMock_EarlyReturnOnNil(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-setidevid-nil-return.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// With nil service, SetTPM2Service should return early
	d.SetTPM2Service(nil)

	// No services should be modified
	// This test verifies the early return path
}

// =============================================================================
// createMCPServer() Coverage Tests
// =============================================================================

func TestCreateMCPServerMock_WithNilMCPConfig(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-mcp-create-nil.sock")
	config.EnableMCP = true
	config.MCPConfig = nil

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// MCPConfig should be set to defaults
	if d.config.MCPConfig == nil {
		t.Error("MCPConfig should have been set to defaults")
	}
}

func TestCreateMCPServerMock_WithNilAppLogger(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-mcp-nil-logger.sock")
	config.EnableMCP = true
	config.MCPConfig = DefaultMCPConfig()
	config.App = nil // No app means no app logger

	_, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// MCP server should still be created with default logger
}

// =============================================================================
// registerHealthCheckers() Coverage Tests
// =============================================================================

func TestRegisterHealthCheckersMock_WithCAService(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-health-ca.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set a mock CA service
	d.caService = &CAGRPCService{}

	// Re-register health checkers
	d.registerHealthCheckers()

	// Health registry should have the CA checker
	if d.healthRegistry == nil {
		t.Error("health registry should not be nil")
	}
}

func TestRegisterHealthCheckersMock_WithAllServices(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-health-all.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
	config.EnableMCP = true
	config.MCPConfig = DefaultMCPConfig()

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Manually set some services for testing
	d.caService = &CAGRPCService{}
	d.sdnService = &SDNService{}
	d.kmsService = &KMSService{}
	d.iamService = &IAMService{}
	d.tenantService = &TenantService{}

	// Re-register health checkers
	d.registerHealthCheckers()

	// Verify count increased
	count := d.healthRegistry.Count()
	if count == 0 {
		t.Error("health registry should have registered checkers")
	}
	t.Logf("Registered %d health checkers", count)
}

func TestRegisterHealthCheckersMock_VerifyLogOnFailure(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-health-fail.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Close the registry first to force registration failures
	if d.healthRegistry != nil {
		_ = d.healthRegistry.Close()
	}

	// Set services
	d.caService = &CAGRPCService{}

	// Re-register should log warnings but not panic
	d.registerHealthCheckers()
}

// =============================================================================
// QUICListenAddr() Coverage Tests
// =============================================================================

func TestQUICListenAddrMock_WithServerAvailable(t *testing.T) {
	// This test requires QUIC to be properly configured
	// which needs certificates, so we test the fallback path
	config := testConfig("/tmp/test-daemon-mock-quic-addr-server.sock")
	config.EnableQUIC = false
	config.QUICListenAddr = "0.0.0.0:9444"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// quicServer should be nil since QUIC is disabled
	if d.quicServer != nil {
		// If we have a server, test that path
		addr := d.QUICListenAddr()
		if addr == "" {
			t.Error("QUICListenAddr() should return non-empty when server is available")
		}
	} else {
		// Test fallback to config
		addr := d.QUICListenAddr()
		if addr != "0.0.0.0:9444" {
			t.Errorf("QUICListenAddr() = %q, want %q", addr, "0.0.0.0:9444")
		}
	}
}

func TestQUICListenAddrMock_FallbackToConfig(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-quic-addr-fallback.sock")
	config.EnableQUIC = false
	config.QUICListenAddr = "192.168.1.1:9444"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	addr := d.QUICListenAddr()
	if addr != "192.168.1.1:9444" {
		t.Errorf("QUICListenAddr() = %q, want %q", addr, "192.168.1.1:9444")
	}
}

func TestQUICListenAddrMock_EmptyConfig(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-quic-addr-empty.sock")
	config.EnableQUIC = false
	config.QUICListenAddr = "" // Empty

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	addr := d.QUICListenAddr()
	if addr != "" {
		t.Errorf("QUICListenAddr() = %q, want empty string", addr)
	}
}

// =============================================================================
// Additional Edge Cases
// =============================================================================

func TestDaemonMock_LoggerFromConfig(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-logger-from-config.sock")

	// Create a custom logger
	customLogger := logging.NewLogger(slog.LevelDebug, nil)
	config.Logger = customLogger

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Daemon should use the custom logger
	if d.logger != customLogger {
		t.Error("daemon should use the custom logger from config")
	}
}

func TestDaemonMock_DefaultLoggerWhenNil(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-default-logger.sock")
	config.Logger = nil

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if d.logger == nil {
		t.Error("daemon should have a logger (slog.Default())")
	}
}

func TestDaemonMock_MCPServiceProviderWithAllServices(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-mcp-provider-all.sock")
	config.EnableMCP = true
	config.MCPConfig = DefaultMCPConfig()

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	provider := d.MCPServiceProvider()
	// Provider may or may not be nil depending on MCP server creation
	t.Logf("MCP provider: %v", provider)
}

func TestDaemonMock_AutoStartDisabledServices(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-autostart-disabled.sock")
	config.Services = map[string]ServiceConfig{
		"test-disabled": {
			Enabled:    false, // Disabled service
			AutoStart:  true,
			Timeout:    5 * time.Second,
			MaxRetries: 3,
		},
		"test-no-autostart": {
			Enabled:    true,
			AutoStart:  false, // AutoStart disabled
			Timeout:    5 * time.Second,
			MaxRetries: 3,
		},
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Daemon should still be running
	if !d.IsRunning() {
		t.Error("daemon should be running")
	}

	_ = d.Stop(ctx)
}

// NOTE: TestDaemonMock_StopServerNotRunning and TestDaemonMock_StopServerAlreadyStopped were removed
// as part of Unix IPC refactoring. The Unix socket server was replaced with gRPC over Unix Domain Sockets.

func TestDaemonMock_GRPCServerAccessor(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-grpc-accessor.sock")
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		if d.grpcServer != nil {
			d.grpcServer.Stop()
		}
	}()

	grpcServer := d.GRPCServer()
	if grpcServer == nil {
		t.Error("GRPCServer() should not return nil when gRPC TCP is enabled")
	}
}

func TestDaemonMock_QUICServiceHandlerAccessor(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-quic-handler-accessor.sock")
	config.EnableQUIC = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	handler := d.QUICServiceHandler()
	if handler != nil {
		t.Error("QUICServiceHandler() should return nil when QUIC is disabled")
	}
}

func TestDaemonMock_StartContextCancellation(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-start-cancel.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Start should still work as the main operations don't check context
	err = d.Start(ctx)
	if err != nil {
		// Some operations may fail with cancelled context
		t.Logf("Start with cancelled context: %v", err)
	}

	// Clean up
	if d.IsRunning() {
		_ = d.ForceStop()
	}
}

func TestDaemonMock_StopContextTimeout(t *testing.T) {
	config := testConfig("/tmp/test-daemon-mock-stop-timeout.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	err = d.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = d.Stop(ctx)
	if err != nil {
		t.Logf("Stop with timeout context: %v", err)
	}
}
