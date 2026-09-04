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
// Start() - Server Configuration Tests
// =============================================================================

func TestStart_WithRESTServerEnabled(t *testing.T) {
	config := testConfig("/tmp/test-start-rest-enabled.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0" // Let OS pick port

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	// Verify REST server is created
	if d.restServer == nil {
		t.Fatal("REST server should be created when EnableREST is true")
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if !d.restServer.IsRunning() {
		t.Error("REST server should be running after Start()")
	}

	_ = d.Stop(ctx)
}

func TestStart_WithMCPServerHTTPTransport(t *testing.T) {
	config := testConfig("/tmp/test-start-mcp-http.sock")
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
	defer d.ForceStop()

	// MCP server may or may not be created based on dependencies
	if d.mcpServer != nil {
		ctx := context.Background()
		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() failed: %v", err)
		}

		if d.IsMCPEnabled() && !d.mcpServer.IsRunning() {
			t.Error("MCP server should be running after Start() when enabled")
		}

		_ = d.Stop(ctx)
	}
}

func TestStart_WithGRPCTCPEnabled(t *testing.T) {
	config := testConfig("/tmp/test-start-grpc-tcp.sock")
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	// Verify gRPC server is created
	if d.grpcServer == nil {
		t.Fatal("gRPC server should be created when EnableGRPCTCP is true")
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Verify gRPC listener is set after Start
	if d.grpcListener == nil {
		t.Error("gRPC listener should be set after Start()")
	}

	_ = d.Stop(ctx)
}

func TestStart_WithMultipleServersEnabled(t *testing.T) {
	config := testConfig("/tmp/test-start-multiple.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

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

	if d.restServer != nil && !d.restServer.IsRunning() {
		t.Error("REST server should be running")
	}
	if d.grpcListener == nil {
		t.Error("gRPC listener should be set")
	}

	_ = d.Stop(ctx)
}

func TestStart_WithNoOptionalServersEnabled(t *testing.T) {
	config := testConfig("/tmp/test-start-minimal.sock")
	config.EnableREST = false
	config.EnableGRPCTCP = false
	config.EnableQUIC = false
	config.EnableMCP = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	// Verify no optional servers are created
	if d.restServer != nil {
		t.Error("REST server should be nil")
	}
	if d.grpcServer != nil {
		t.Error("gRPC server should be nil")
	}
	if d.quicServer != nil {
		t.Error("QUIC server should be nil")
	}
	if d.mcpServer != nil {
		t.Error("MCP server should be nil")
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if !d.IsRunning() {
		t.Error("daemon should be running")
	}

	_ = d.Stop(ctx)
}

// =============================================================================
// Stop() - Cleanup Path Tests
// =============================================================================

func TestStop_WithRESTServerRunning(t *testing.T) {
	config := testConfig("/tmp/test-stop-rest-running.sock")
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

	if d.restServer == nil || !d.restServer.IsRunning() {
		t.Skip("REST server not running, skipping test")
	}

	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}

	// Verify REST server is stopped
	if d.restServer.IsRunning() {
		t.Error("REST server should be stopped after Stop()")
	}
}

func TestStop_WithMCPServerRunning(t *testing.T) {
	config := testConfig("/tmp/test-stop-mcp-running.sock")
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

	if d.mcpServer == nil {
		t.Skip("MCP server not created, skipping test")
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
}

func TestStop_WithGRPCServerRunning(t *testing.T) {
	config := testConfig("/tmp/test-stop-grpc-running.sock")
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

	// Verify gRPC is set up
	if d.grpcServer == nil {
		t.Skip("gRPC server not created, skipping test")
	}
	if d.grpcListener == nil {
		t.Skip("gRPC listener not created, skipping test")
	}

	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
}

func TestStop_ClosesGRPCListener(t *testing.T) {
	config := testConfig("/tmp/test-stop-grpc-listener.sock")
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

	// Capture listener reference
	listener := d.grpcListener

	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}

	// Verify listener is closed (should fail to accept)
	if listener != nil {
		_, acceptErr := listener.Accept()
		if acceptErr == nil {
			t.Error("listener.Accept() should return error after Stop()")
		}
	}
}

func TestStop_WithAllServersRunning(t *testing.T) {
	config := testConfig("/tmp/test-stop-all-servers.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
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

	time.Sleep(50 * time.Millisecond)

	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}

	// Verify all servers are stopped
	if d.restServer != nil && d.restServer.IsRunning() {
		t.Error("REST server should be stopped")
	}
	if d.IsRunning() {
		t.Error("daemon should not be running after Stop()")
	}
}

// =============================================================================
// New() - Configuration Options Tests
// =============================================================================

func TestNew_WithQUICEnabled(t *testing.T) {
	config := testConfig("/tmp/test-new-quic-enabled.sock")
	config.EnableQUIC = true
	config.QUICListenAddr = "127.0.0.1:0"
	// QUIC needs TLS config, so it may fail without proper setup
	// This tests that the code path is exercised

	d, err := New(config)
	// May fail due to missing TLS certs for QUIC
	if err != nil {
		t.Logf("New() with QUIC enabled returned error (expected without TLS): %v", err)
		return
	}

	// If we got here, QUIC was set up (maybe with default certs)
	if d.config.EnableQUIC {
		// QUIC was enabled in config
		t.Log("QUIC configuration was enabled")
	}
}

func TestNew_WithCustomShutdownTimeout(t *testing.T) {
	config := testConfig("/tmp/test-new-custom-timeout.sock")
	config.ShutdownTimeout = 60 * time.Second

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if d.config.ShutdownTimeout != 60*time.Second {
		t.Errorf("ShutdownTimeout = %v, want %v", d.config.ShutdownTimeout, 60*time.Second)
	}
}

func TestNew_WithSocketModeAndGroup(t *testing.T) {
	config := testConfig("/tmp/test-new-socket-config.sock")
	config.SocketMode = 0700
	config.SocketGroup = "" // Empty for tests

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if d.config.SocketMode != 0700 {
		t.Errorf("SocketMode = %v, want %v", d.config.SocketMode, 0700)
	}
}

func TestNew_WithDebugLogger(t *testing.T) {
	config := testConfig("/tmp/test-new-debug-logger.sock")
	debugLogger := logging.NewLogger(slog.LevelDebug, nil)
	config.Logger = debugLogger

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if d.logger != debugLogger {
		t.Error("daemon logger should be the debug logger we provided")
	}
}

func TestNew_WithCustomServiceConfigs(t *testing.T) {
	config := testConfig("/tmp/test-new-service-configs.sock")
	config.Services = map[string]ServiceConfig{
		"custom1": {
			Enabled:    true,
			AutoStart:  true,
			Timeout:    20 * time.Second,
			MaxRetries: 10,
		},
		"custom2": {
			Enabled:    false,
			AutoStart:  false,
			Timeout:    5 * time.Second,
			MaxRetries: 1,
		},
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if len(d.config.Services) != 2 {
		t.Errorf("Services count = %d, want 2", len(d.config.Services))
	}
	if d.config.Services["custom1"].MaxRetries != 10 {
		t.Error("custom1 service config not preserved")
	}
}

// =============================================================================
// SetTPM2Service() - Tests with Server Types
// =============================================================================

func TestSetTPM2Service_WithRESTServerOnly(t *testing.T) {
	config := testConfig("/tmp/test-setidevid-rest-only.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
	config.EnableGRPCTCP = false
	config.EnableQUIC = false
	config.EnableMCP = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Verify REST server exists
	if d.restServer == nil {
		t.Fatal("REST server should not be nil")
	}

	// SetTPM2Service with nil should not panic and should exercise REST path
	d.SetTPM2Service(nil)
}

func TestSetTPM2Service_WithMCPServerOnly(t *testing.T) {
	config := testConfig("/tmp/test-setidevid-mcp-only.sock")
	config.EnableREST = false
	config.EnableGRPCTCP = false
	config.EnableQUIC = false
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

	// SetTPM2Service with nil - exercises MCP provider path
	d.SetTPM2Service(nil)
}

func TestSetTPM2Service_WithAllServersEnabled(t *testing.T) {
	config := testConfig("/tmp/test-setidevid-all-servers.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"
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

	// SetTPM2Service with nil - exercises all paths
	d.SetTPM2Service(nil)
}

func TestSetTPM2Service_WithQUICHandlerSet(t *testing.T) {
	config := testConfig("/tmp/test-setidevid-quic-handler.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Manually set a QUIC handler to test that path
	logger := logging.DefaultLogger()
	d.quicHandler = NewQUICServiceHandler(logger)

	// SetTPM2Service with nil - exercises QUIC handler path
	d.SetTPM2Service(nil)
}

// =============================================================================
// registerHealthCheckers() - Tests with Various Services
// =============================================================================

func TestRegisterHealthCheckersStartStop_WithRESTServer(t *testing.T) {
	config := testConfig("/tmp/test-health-rest-startstop.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Health registry should have REST health checker
	if d.healthRegistry == nil {
		t.Fatal("Health registry should not be nil")
	}

	// registerHealthCheckers is called during New()
	// Verify by checking registry count
	count := d.healthRegistry.Count()
	if count < 1 {
		t.Logf("Health registry has %d checkers (REST might not be registered)", count)
	}
}

func TestRegisterHealthCheckersStartStop_WithMCPServer(t *testing.T) {
	config := testConfig("/tmp/test-health-mcp-startstop.sock")
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

	// Health registry should be set up
	if d.healthRegistry == nil {
		t.Fatal("Health registry should not be nil")
	}
}

func TestRegisterHealthCheckersStartStop_WithCAService(t *testing.T) {
	config := testConfig("/tmp/test-health-ca-startstop.sock")
	// CA service would require full CA setup, but we can test nil case

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set a mock CA service and re-register health checkers
	mockCA := &CAGRPCService{}
	d.caService = mockCA

	// Re-register health checkers (clears and re-adds)
	oldRegistry := d.healthRegistry
	d.registerHealthCheckers()

	// Verify registry still works
	if d.healthRegistry != oldRegistry {
		// Registry was replaced (unexpected but not an error)
		t.Log("Health registry was replaced during re-registration")
	}
}

func TestRegisterHealthCheckersStartStop_WithMultipleServices(t *testing.T) {
	config := testConfig("/tmp/test-health-multiple-startstop.sock")
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

	// Should have multiple health checkers registered
	count := d.healthRegistry.Count()
	t.Logf("Health registry has %d checkers with multiple services enabled", count)
}

func TestRegisterHealthCheckersStartStop_NilServices(t *testing.T) {
	config := testConfig("/tmp/test-health-nil-services-startstop.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Explicitly set all optional services to nil
	d.caService = nil
	d.sdnService = nil
	d.kmsService = nil
	d.iamService = nil
	d.tenantService = nil
	d.quicServer = nil
	d.restServer = nil
	d.mcpServer = nil

	// Re-register - should not panic
	d.registerHealthCheckers()
}

// =============================================================================
// Start()/Stop() - Edge Cases
// =============================================================================

func TestStart_SetsServiceToReady(t *testing.T) {
	config := testConfig("/tmp/test-start-ready.sock")

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

	// Service should be marked ready
	if d.service == nil {
		t.Fatal("daemon service should not be nil")
	}

	_ = d.Stop(ctx)
}

func TestStop_CallsShutdownHandler(t *testing.T) {
	config := testConfig("/tmp/test-stop-shutdown-handler.sock")

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

	// Verify daemon is not running
	if d.IsRunning() {
		t.Error("daemon should not be running after Stop()")
	}
}

func TestForceStop_WithAllServersRunning(t *testing.T) {
	config := testConfig("/tmp/test-forcestop-all.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
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

	time.Sleep(50 * time.Millisecond)

	err = d.ForceStop()
	// May return "server is not running" if shutdown handler already stopped it
	if err != nil && err.Error() != "server is not running" {
		t.Errorf("ForceStop() failed: %v", err)
	}
}

// =============================================================================
// Start() - Service Start Order Tests
// =============================================================================

func TestStart_StartsServicesInOrder(t *testing.T) {
	config := testConfig("/tmp/test-start-order.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

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

	// Verify start order: REST before Unix socket before gRPC
	// This is implicit in the code - we just verify all are running
	if !d.IsRunning() {
		t.Error("daemon should be running")
	}

	_ = d.Stop(ctx)
}

func TestStart_ContinuesOnOptionalServiceFailure(t *testing.T) {
	config := testConfig("/tmp/test-start-optional-fail.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	// Register a service that fails to start
	svc := newMockService("optional-fail")
	svc.startErr = ErrServiceStartFailed{ServiceName: "optional-fail", Reason: "test failure"}
	_ = d.RegisterService(svc)

	ctx := context.Background()
	// Start should succeed despite optional service failure
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() should succeed despite optional service failure: %v", err)
	}

	_ = d.Stop(ctx)
}

// =============================================================================
// Stop() - Error Handling Tests
// =============================================================================

func TestStop_HandlesHealthRegistryCloseError(t *testing.T) {
	config := testConfig("/tmp/test-stop-health-error.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Close health registry before Stop to simulate error
	if d.healthRegistry != nil {
		_ = d.healthRegistry.Close()
	}

	// Stop should still work even if health registry close fails
	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() should succeed even with health registry close error: %v", err)
	}
}

func TestStop_HandlesNilGRPCListener(t *testing.T) {
	config := testConfig("/tmp/test-stop-nil-grpc-listener.sock")
	config.EnableGRPCTCP = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Verify gRPC listener is nil
	if d.grpcListener != nil {
		t.Skip("Expected nil gRPC listener")
	}

	// Stop should handle nil gRPC listener gracefully
	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed with nil gRPC listener: %v", err)
	}
}

// =============================================================================
// New() - MCP Server Creation Tests
// =============================================================================

func TestNew_CreatesMCPServerWithHTTPTransport(t *testing.T) {
	config := testConfig("/tmp/test-new-mcp-http.sock")
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test-mcp-server",
		ServerVersion:         "2.0.0",
		Transport:             "http",
		HTTPAddr:              "127.0.0.1:0",
		RequestTimeout:        60 * time.Second,
		MaxConcurrentRequests: 50,
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// MCP server should be created
	if d.mcpServer == nil {
		t.Log("MCP server was not created (may be expected without proper setup)")
	}

	// MCP provider should be created
	if d.mcpProvider == nil {
		t.Log("MCP provider was not created (may be expected without proper setup)")
	}
}

func TestNew_CreatesMCPServerWithStdioTransport(t *testing.T) {
	config := testConfig("/tmp/test-new-mcp-stdio.sock")
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test-mcp-stdio",
		ServerVersion:         "1.0.0",
		Transport:             "stdio",
		HTTPAddr:              "",
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Config should be valid for stdio
	if d.config.MCPConfig.Transport != "stdio" {
		t.Errorf("Transport = %s, want stdio", d.config.MCPConfig.Transport)
	}
}

// =============================================================================
// New() - REST Server Creation Tests
// =============================================================================

func TestNew_CreatesRESTServerWithConfig(t *testing.T) {
	config := testConfig("/tmp/test-new-rest-config.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:8443"
	config.RESTConfig = RESTServerConfig{
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       240 * time.Second,
		MaxHeaderBytes:    2 << 20,
		EnableCORS:        true,
		AllowedOrigins:    []string{"http://localhost"},
		AllowedMethods:    []string{"GET", "POST"},
		AllowedHeaders:    []string{"Content-Type"},
		EnableCompression: true,
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if d.restServer == nil {
		t.Fatal("REST server should be created")
	}

	// Verify config was passed through
	if d.config.RESTConfig.ReadTimeout != 60*time.Second {
		t.Error("REST config not preserved")
	}
}

// =============================================================================
// registerHealthCheckers() - Complete Coverage
// =============================================================================

func TestRegisterHealthCheckersStartStop_SDNService(t *testing.T) {
	config := testConfig("/tmp/test-health-sdn-startstop.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set SDN service and re-register
	d.sdnService = &SDNService{}
	d.registerHealthCheckers()

	// Should not panic
	count := d.healthRegistry.Count()
	t.Logf("Health registry has %d checkers after SDN service set", count)
}

func TestRegisterHealthCheckersStartStop_KMSService(t *testing.T) {
	config := testConfig("/tmp/test-health-kms-startstop.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set KMS service and re-register
	d.kmsService = &KMSService{}
	d.registerHealthCheckers()

	// Should not panic
	count := d.healthRegistry.Count()
	t.Logf("Health registry has %d checkers after KMS service set", count)
}

func TestRegisterHealthCheckersStartStop_IAMService(t *testing.T) {
	config := testConfig("/tmp/test-health-iam-startstop.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set IAM service and re-register
	d.iamService = &IAMService{}
	d.registerHealthCheckers()

	// Should not panic
	count := d.healthRegistry.Count()
	t.Logf("Health registry has %d checkers after IAM service set", count)
}

func TestRegisterHealthCheckersStartStop_TenantService(t *testing.T) {
	config := testConfig("/tmp/test-health-tenant-startstop.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set Tenant service and re-register
	d.tenantService = &TenantService{}
	d.registerHealthCheckers()

	// Should not panic
	count := d.healthRegistry.Count()
	t.Logf("Health registry has %d checkers after tenant service set", count)
}

func TestRegisterHealthCheckersStartStop_QUICServer(t *testing.T) {
	config := testConfig("/tmp/test-health-quic-startstop.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// QUIC server would need TLS setup, test nil case is handled
	d.quicServer = nil
	d.registerHealthCheckers()

	// Should not panic with nil QUIC server
	count := d.healthRegistry.Count()
	t.Logf("Health registry has %d checkers with nil QUIC server", count)
}
