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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// New() Tests - Configuration and Initialization
// =============================================================================

func TestNewDaemon_ValidConfig(t *testing.T) {
	// Test that New() works with a valid config
	config := testConfig("/tmp/test-lifecycle-nil-config.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with valid config failed: %v", err)
	}

	// Verify daemon initialized properly
	if d == nil {
		t.Fatal("New() returned nil daemon")
	}
	if d.service == nil {
		t.Error("daemon service should not be nil")
	}
	// NOTE: Unix socket server was removed, now using gRPC over UDS
	if d.healthRegistry == nil {
		t.Error("daemon health registry should not be nil")
	}
}

func TestNewDaemon_WithGRPCTCPEnabled(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-grpc-enabled.sock")
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0" // Use port 0 to let OS assign

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with gRPC TCP enabled failed: %v", err)
	}
	defer func() {
		if d != nil && d.grpcServer != nil {
			d.grpcServer.Stop()
		}
	}()

	if d.grpcServer == nil {
		t.Error("gRPC server should not be nil when EnableGRPCTCP is true")
	}
	if !d.config.EnableGRPCTCP {
		t.Error("config.EnableGRPCTCP should be true")
	}
}

func TestNewDaemon_WithGRPCTCPDisabled(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-grpc-disabled.sock")
	config.EnableGRPCTCP = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with gRPC TCP disabled failed: %v", err)
	}

	if d.grpcServer != nil {
		t.Error("gRPC server should be nil when EnableGRPCTCP is false")
	}
}

func TestNewDaemon_WithRESTEnabled(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-rest-enabled.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with REST enabled failed: %v", err)
	}

	if d.restServer == nil {
		t.Error("REST server should not be nil when EnableREST is true")
	}
	if !d.IsRESTEnabled() {
		t.Error("IsRESTEnabled() should return true")
	}
}

func TestNewDaemon_WithRESTDisabled(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-rest-disabled.sock")
	config.EnableREST = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with REST disabled failed: %v", err)
	}

	if d.restServer != nil {
		t.Error("REST server should be nil when EnableREST is false")
	}
	if d.IsRESTEnabled() {
		t.Error("IsRESTEnabled() should return false")
	}
}

func TestNewDaemon_WithMCPEnabled_StdioTransport(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-mcp-stdio.sock")
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test-mcp",
		ServerVersion:         "1.0.0",
		Transport:             "stdio",
		HTTPAddr:              "",
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with MCP stdio enabled failed: %v", err)
	}

	// MCP server created but may not be fully initialized for stdio
	// since stdio requires actual stdin/stdout connections
	if d.config.EnableMCP != true {
		t.Error("config.EnableMCP should be true")
	}
}

func TestNewDaemon_WithMCPDisabled(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-mcp-disabled.sock")
	config.EnableMCP = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with MCP disabled failed: %v", err)
	}

	if d.mcpServer != nil {
		t.Error("MCP server should be nil when EnableMCP is false")
	}
	if d.IsMCPEnabled() {
		t.Error("IsMCPEnabled() should return false")
	}
}

func TestNewDaemon_WithQUICDisabled(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-quic-disabled.sock")
	config.EnableQUIC = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with QUIC disabled failed: %v", err)
	}

	if d.quicServer != nil {
		t.Error("QUIC server should be nil when EnableQUIC is false")
	}
	if d.quicHandler != nil {
		t.Error("QUIC handler should be nil when EnableQUIC is false")
	}
	if d.IsQUICEnabled() {
		t.Error("IsQUICEnabled() should return false")
	}
}

func TestNewDaemon_WithCustomLoggerLifecycle(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-custom-logger.sock")

	// Create custom logger
	customLogger := logging.NewLogger(slog.LevelDebug, nil)
	config.Logger = customLogger

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with custom logger failed: %v", err)
	}

	if d.logger == nil {
		t.Error("daemon logger should not be nil")
	}
	// The logger should be the custom one we provided
	if d.logger != customLogger {
		t.Error("daemon logger should be the custom logger we provided")
	}
}

func TestNewDaemon_WithNilLogger(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-nil-logger.sock")
	config.Logger = nil

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with nil logger failed: %v", err)
	}

	if d.logger == nil {
		t.Error("daemon logger should not be nil - should use slog.Default()")
	}
}

func TestNewDaemon_ServiceConfiguration(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-services.sock")
	config.Services = map[string]ServiceConfig{
		"custom-service": {
			Enabled:    true,
			AutoStart:  true,
			Timeout:    15 * time.Second,
			MaxRetries: 5,
		},
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() with custom services failed: %v", err)
	}

	if d.config.Services["custom-service"].Timeout != 15*time.Second {
		t.Error("service config should preserve custom timeout")
	}
	if d.config.Services["custom-service"].MaxRetries != 5 {
		t.Error("service config should preserve custom max retries")
	}
}

// =============================================================================
// Start() Tests - Daemon Startup
// =============================================================================

func TestStartDaemon_BasicStartup(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-start-basic.sock")

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

	if !d.IsRunning() {
		t.Error("daemon should be running after Start()")
	}

	// Give time for autostart goroutine
	time.Sleep(50 * time.Millisecond)

	// Stop cleanly
	_ = d.Stop(ctx)
}

func TestStartDaemon_AlreadyRunningError(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-start-already-running.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	ctx := context.Background()

	// First start should succeed
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("First Start() failed: %v", err)
	}

	// Second start should fail with ErrDaemonAlreadyRunning
	err = d.Start(ctx)
	if err == nil {
		t.Fatal("Second Start() should return error")
	}

	var alreadyRunningErr ErrDaemonAlreadyRunning
	if _, ok := err.(ErrDaemonAlreadyRunning); !ok {
		t.Errorf("Expected ErrDaemonAlreadyRunning, got %T: %v", err, alreadyRunningErr)
	}
}

func TestStartDaemon_WithAutoStartServices(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-start-autostart.sock")
	config.Services = map[string]ServiceConfig{
		"tpm": {
			Enabled:    true,
			AutoStart:  true,
			Timeout:    5 * time.Second,
			MaxRetries: 3,
		},
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	// Register a mock service
	svc := newMockService("tpm")
	err = d.RegisterService(svc)
	if err != nil {
		t.Fatalf("RegisterService() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Wait for the auto-start goroutine to start it. The count is the real
	// condition; 150ms was a guess at how long that takes.
	svc.awaitStarts(t, 1)

	if svc.startCount.Load() < 1 {
		t.Error("auto-start service should have been started")
	}

	_ = d.Stop(ctx)
}

func TestStartDaemon_WithServiceStartFailure(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-start-svc-fail.sock")
	config.Services = map[string]ServiceConfig{
		"tpm": {
			Enabled:    true,
			AutoStart:  true,
			Timeout:    5 * time.Second,
			MaxRetries: 3,
		},
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	// Register a service that fails to start
	svc := newMockService("tpm")
	svc.startErr = ErrServiceStartFailed{ServiceName: "tpm", Reason: "test error"}
	err = d.RegisterService(svc)
	if err != nil {
		t.Fatalf("RegisterService() failed: %v", err)
	}

	ctx := context.Background()
	// Start should succeed even if service autostart fails
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed despite service error: %v", err)
	}

	// Wait for the attempt. startCount is incremented on ENTRY to Start, before
	// the configured error is returned, so it records the attempt this test is
	// about rather than a success.
	svc.awaitStarts(t, 1)

	// Service should have been attempted
	if svc.startCount.Load() < 1 {
		t.Error("service should have been attempted")
	}

	// Daemon should still be running
	if !d.IsRunning() {
		t.Error("daemon should still be running despite service failure")
	}

	_ = d.Stop(ctx)
}

func TestStartDaemon_SetsRunningState(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-start-running-state.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	// Initially not running
	if d.IsRunning() {
		t.Error("daemon should not be running before Start()")
	}
	if d.running.Load() {
		t.Error("running atomic should be false before Start()")
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if !d.IsRunning() {
		t.Error("daemon should be running after Start()")
	}
	if !d.running.Load() {
		t.Error("running atomic should be true after Start()")
	}

	_ = d.Stop(ctx)
}

func TestStartDaemon_DaemonReadyAfterStart(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-start-ready.sock")

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

	// Daemon should be running after Start
	if !d.IsRunning() {
		t.Error("daemon should be running after Start()")
	}

	_ = d.Stop(ctx)
}

// =============================================================================
// Stop() Tests - Graceful Shutdown
// =============================================================================

func TestStopDaemon_BasicStop(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-stop-basic.sock")

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

	if d.IsRunning() {
		t.Error("daemon should not be running after Stop()")
	}
}

func TestStopDaemon_NotRunningError(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-stop-not-running.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	// Stop without starting should fail
	err = d.Stop(ctx)
	if err == nil {
		t.Fatal("Stop() on non-running daemon should return error")
	}

	if _, ok := err.(ErrDaemonNotRunning); !ok {
		t.Errorf("Expected ErrDaemonNotRunning, got %T: %v", err, err)
	}
}

func TestStopDaemon_ClosesHealthRegistry(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-stop-health.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Capture registry reference
	registry := d.healthRegistry

	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}

	// Trying to register on closed registry should fail
	svc := newMockService("test")
	checker := NewServiceHealthChecker(svc)
	regErr := registry.Register(checker)
	if regErr == nil {
		t.Error("Register() on closed registry should return error")
	}
}

func TestStopDaemon_StopsGRPCServer(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-stop-grpc.sock")
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
		t.Error("gRPC server should exist after Start() with gRPC TCP enabled")
	}

	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}

	// gRPC server should be gracefully stopped
	// (we can't easily verify this without trying to connect)
}

func TestStopDaemon_StopsRegisteredServices(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-stop-services.sock")
	config.Services = map[string]ServiceConfig{
		"tpm": {
			Enabled:    true,
			AutoStart:  true,
			Timeout:    5 * time.Second,
			MaxRetries: 3,
		},
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	svc := newMockService("tpm")
	err = d.RegisterService(svc)
	if err != nil {
		t.Fatalf("RegisterService() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Wait for autostart
	time.Sleep(100 * time.Millisecond)

	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}

	// Service should have been stopped
	if svc.stopCount.Load() < 1 {
		t.Error("registered service should have been stopped")
	}
}

func TestStopDaemon_HandlesNilServices(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-stop-nil-svc.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Ensure optional services are nil
	d.sdnService = nil
	d.kmsService = nil
	d.iamService = nil
	d.tenantService = nil
	d.quicServer = nil
	d.restServer = nil
	d.mcpServer = nil

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Stop should not panic with nil services
	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() with nil services failed: %v", err)
	}
}

func TestStopDaemon_SetsRunningStateFalse(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-stop-state.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if !d.running.Load() {
		t.Error("running should be true after Start()")
	}

	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}

	if d.running.Load() {
		t.Error("running should be false after Stop()")
	}
}

// =============================================================================
// ForceStop() Tests - Immediate Shutdown
// =============================================================================

func TestForceStopDaemon_BasicForceStop(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-forcestop-basic.sock")

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
	// May return "server is not running" if shutdown handler already stopped it
	if err != nil && err.Error() != "server is not running" {
		t.Errorf("ForceStop() failed: %v", err)
	}
}

func TestForceStopDaemon_NotRunningError(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-forcestop-not-running.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// ForceStop without starting should fail
	err = d.ForceStop()
	if err == nil {
		t.Fatal("ForceStop() on non-running daemon should return error")
	}

	if _, ok := err.(ErrDaemonNotRunning); !ok {
		t.Errorf("Expected ErrDaemonNotRunning, got %T: %v", err, err)
	}
}

func TestForceStopDaemon_ClosesHealthRegistry(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-forcestop-health.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	registry := d.healthRegistry

	err = d.ForceStop()
	// May return server error
	if err != nil && err.Error() != "server is not running" {
		t.Errorf("ForceStop() failed: %v", err)
	}

	// Registry should be closed
	svc := newMockService("test")
	checker := NewServiceHealthChecker(svc)
	regErr := registry.Register(checker)
	if regErr == nil {
		t.Error("Register() on closed registry should return error")
	}
}

func TestForceStopDaemon_HandlesNilServices(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-forcestop-nil-svc.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Ensure optional services are nil
	d.sdnService = nil
	d.kmsService = nil
	d.iamService = nil
	d.tenantService = nil
	d.quicServer = nil
	d.restServer = nil
	d.mcpServer = nil

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// ForceStop should not panic with nil services
	err = d.ForceStop()
	if err != nil && err.Error() != "server is not running" {
		t.Errorf("ForceStop() with nil services failed: %v", err)
	}
}

func TestForceStopDaemon_QuickerThanGracefulStop(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-forcestop-fast.sock")
	config.Services = map[string]ServiceConfig{
		"tpm": {
			Enabled:    true,
			AutoStart:  true,
			Timeout:    5 * time.Second,
			MaxRetries: 3,
		},
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Register a slow service
	svc := newMockService("tpm")
	svc.stopDelay = 2 * time.Second
	err = d.RegisterService(svc)
	if err != nil {
		t.Fatalf("RegisterService() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Wait for autostart
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	err = d.ForceStop()
	elapsed := time.Since(start)

	// May return server error
	if err != nil && err.Error() != "server is not running" {
		t.Errorf("ForceStop() failed: %v", err)
	}

	// ForceStop should complete faster than the slow service would take
	if elapsed > 3*time.Second {
		t.Errorf("ForceStop() took too long: %v", elapsed)
	}
}

// =============================================================================
// MCPServiceProvider() Tests
// =============================================================================

func TestMCPServiceProviderDaemon_ReturnsNilWhenMCPDisabled(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-mcp-provider-nil.sock")
	config.EnableMCP = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	provider := d.MCPServiceProvider()
	if provider != nil {
		t.Error("MCPServiceProvider() should return nil when MCP is disabled")
	}
}

func TestMCPServiceProviderDaemon_ReturnsNilWhenMCPServerNil(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-mcp-provider-server-nil.sock")
	config.EnableMCP = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Ensure mcpServer is nil
	d.mcpServer = nil
	d.mcpProvider = nil

	provider := d.MCPServiceProvider()
	if provider != nil {
		t.Error("MCPServiceProvider() should return nil when mcpProvider is nil")
	}
}

func TestMCPServiceProviderDaemon_WithMCPEnabled(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-mcp-provider-enabled.sock")
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

	provider := d.MCPServiceProvider()
	// Provider should be created (may be nil if MCP server creation failed)
	// The test verifies the accessor works
	_ = provider
}

// =============================================================================
// SetTPM2Service() Tests
// =============================================================================

func TestSetTPM2ServiceDaemon_NilService(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-setidevid-nil.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// SetTPM2Service with nil should not panic
	d.SetTPM2Service(nil)

	// tpm2Service should remain nil
	if d.tpm2Service != nil {
		t.Error("tpm2Service should be nil after SetTPM2Service(nil)")
	}
}

func TestSetTPM2ServiceDaemon_WithNilRESTServer(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-setidevid-nil-rest.sock")
	config.EnableREST = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Ensure REST server is nil
	if d.restServer != nil {
		t.Fatal("REST server should be nil when REST is disabled")
	}

	// SetTPM2Service should not panic with nil REST server
	// We can't easily create a real idevid.Service without TPM dependencies,
	// but we can test that nil input is handled correctly
	d.SetTPM2Service(nil)
}

func TestSetTPM2ServiceDaemon_WithNilQUICHandler(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-setidevid-nil-quic.sock")
	config.EnableQUIC = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Ensure QUIC handler is nil
	if d.quicHandler != nil {
		t.Fatal("QUIC handler should be nil when QUIC is disabled")
	}

	// SetTPM2Service should not panic with nil QUIC handler
	d.SetTPM2Service(nil)
}

func TestSetTPM2ServiceDaemon_WithNilMCPProvider(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-setidevid-nil-mcp.sock")
	config.EnableMCP = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Ensure MCP provider is nil
	if d.mcpProvider != nil {
		t.Fatal("MCP provider should be nil when MCP is disabled")
	}

	// SetTPM2Service should not panic with nil MCP provider
	d.SetTPM2Service(nil)
}

func TestSetTPM2ServiceDaemon_MutexProtection(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-setidevid-mutex.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Call SetTPM2Service concurrently to test mutex protection
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			d.SetTPM2Service(nil)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Test passes if no race conditions detected
}

// =============================================================================
// Additional Edge Cases
// =============================================================================

func TestDaemonLifecycle_StartStopCycle(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-cycle.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	ctx := context.Background()

	// Multiple start/stop cycles
	for i := 0; i < 3; i++ {
		// Need to recreate daemon after stop since socket server may not restart
		if i > 0 {
			d, err = New(config)
			if err != nil {
				t.Fatalf("New() cycle %d failed: %v", i, err)
			}
		}

		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() cycle %d failed: %v", i, err)
		}

		if !d.IsRunning() {
			t.Errorf("Cycle %d: daemon should be running after Start()", i)
		}

		err = d.Stop(ctx)
		if err != nil {
			t.Errorf("Stop() cycle %d failed: %v", i, err)
		}

		if d.IsRunning() {
			t.Errorf("Cycle %d: daemon should not be running after Stop()", i)
		}
	}
}

func TestDaemonLifecycle_ConcurrentAccessDuringLifecycle(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-concurrent.sock")

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

	// Concurrent reads during running state
	done := make(chan bool, 20)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				_ = d.IsRunning()
				_ = d.SocketPath()
				_ = d.GRPCListenAddr()
				_ = d.HealthRegistry()
				_ = d.Service()
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				_ = d.IsRESTEnabled()
				_ = d.IsMCPEnabled()
				_ = d.IsQUICEnabled()
				_ = d.IsGRPCTCPEnabled()
			}
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		<-done
	}

	_ = d.Stop(ctx)
}

func TestDaemonLifecycle_ServiceTypeFromName(t *testing.T) {
	// Test the serviceTypeFromName helper function (internal)
	tests := []struct {
		name     string
		expected platformv1.ServiceType
	}{
		{"tpm", platformv1.ServiceType_SERVICE_TYPE_TPM},
		{"sdn", platformv1.ServiceType_SERVICE_TYPE_SDN},
		{"compute", platformv1.ServiceType_SERVICE_TYPE_COMPUTE},
		{"dns", platformv1.ServiceType_SERVICE_TYPE_DNS},
		{"acme", platformv1.ServiceType_SERVICE_TYPE_ACME},
		{"webservice", platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE},
		{"attestation", platformv1.ServiceType_SERVICE_TYPE_ATTESTATION},
		{"unknown", platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := serviceTypeFromName(tt.name)
			if result != tt.expected {
				t.Errorf("serviceTypeFromName(%q) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

// NOTE: TestDaemonLifecycle_StopServerMethod was removed as part of Unix IPC refactoring.
// The Unix socket server was replaced with gRPC over Unix Domain Sockets.

func TestDaemonLifecycle_AutoStartServicesEdgeCases(t *testing.T) {
	t.Run("empty services map", func(t *testing.T) {
		config := testConfig("/tmp/test-lifecycle-autostart-empty.sock")
		config.Services = map[string]ServiceConfig{}

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

		if !d.IsRunning() {
			t.Error("daemon should be running")
		}

		_ = d.Stop(ctx)
	})

	t.Run("service not registered", func(t *testing.T) {
		config := testConfig("/tmp/test-lifecycle-autostart-notreg.sock")
		config.Services = map[string]ServiceConfig{
			"unregistered": {
				Enabled:    true,
				AutoStart:  true,
				Timeout:    5 * time.Second,
				MaxRetries: 3,
			},
		}

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		defer d.ForceStop()

		// Do NOT register the service
		ctx := context.Background()
		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() failed: %v", err)
		}

		// Daemon should still be running (autostart skips unregistered)
		if !d.IsRunning() {
			t.Error("daemon should be running despite unregistered service")
		}

		_ = d.Stop(ctx)
	})
}

func TestDaemonLifecycle_RegisterHealthCheckersWithNilRegistry(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-reghealth-nil.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set registry to nil
	d.healthRegistry = nil

	// Should not panic
	d.registerHealthCheckers()
}

func TestDaemonLifecycle_HealthCheckWithNilRegistry(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-healthcheck-nil.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set registry to nil
	d.healthRegistry = nil

	ctx := context.Background()
	_, err = d.HealthCheck(ctx)
	if err == nil {
		t.Error("HealthCheck() with nil registry should return error")
	}

	if _, ok := err.(ErrHealthRegistryNotConfigured); !ok {
		t.Errorf("Expected ErrHealthRegistryNotConfigured, got %T", err)
	}
}

func TestDaemonLifecycle_HealthCheckComponentWithNilRegistry(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-healthcomp-nil.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set registry to nil
	d.healthRegistry = nil

	ctx := context.Background()
	_, err = d.HealthCheckComponent(ctx, "test")
	if err == nil {
		t.Error("HealthCheckComponent() with nil registry should return error")
	}

	if _, ok := err.(ErrHealthRegistryNotConfigured); !ok {
		t.Errorf("Expected ErrHealthRegistryNotConfigured, got %T", err)
	}
}

func TestDaemonLifecycle_RegisterHealthCheckerWithNilRegistry(t *testing.T) {
	config := testConfig("/tmp/test-lifecycle-reghealthchecker-nil.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set registry to nil
	d.healthRegistry = nil

	svc := newMockService("test")
	checker := NewServiceHealthChecker(svc)
	err = d.RegisterHealthChecker(checker)
	if err == nil {
		t.Error("RegisterHealthChecker() with nil registry should return error")
	}

	if _, ok := err.(ErrHealthRegistryNotConfigured); !ok {
		t.Errorf("Expected ErrHealthRegistryNotConfigured, got %T", err)
	}
}
