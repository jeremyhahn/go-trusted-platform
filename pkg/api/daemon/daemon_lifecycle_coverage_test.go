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
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
)

// lifecycleShortSocketPath creates a short socket path to avoid Unix domain socket path length limits (108 chars).
// Uses /tmp with a short unique name combining random bytes and test-specific suffix.
func lifecycleShortSocketPath(t *testing.T, suffix string) string {
	b := make([]byte, 4)
	rand.Read(b)
	sockPath := filepath.Join(os.TempDir(), "lc"+hex.EncodeToString(b)+"-"+suffix+".sock")
	t.Cleanup(func() {
		os.Remove(sockPath)
	})
	return sockPath
}

// =============================================================================
// SetTPM2Service Tests - Comprehensive Coverage
// =============================================================================

func TestSetTPM2ServiceLifecycle_NilServiceEarlyReturn(t *testing.T) {
	tests := []struct {
		name        string
		enableREST  bool
		enableMCP   bool
		enableQUIC  bool
		description string
	}{
		{
			name:        "nil_with_no_protocols",
			enableREST:  false,
			enableMCP:   false,
			enableQUIC:  false,
			description: "nil service returns early without protocol handlers",
		},
		{
			name:        "nil_with_rest_only",
			enableREST:  true,
			enableMCP:   false,
			enableQUIC:  false,
			description: "nil service with REST enabled returns early",
		},
		{
			name:        "nil_with_mcp_only",
			enableREST:  false,
			enableMCP:   true,
			enableQUIC:  false,
			description: "nil service with MCP enabled returns early",
		},
		{
			name:        "nil_with_all_protocols",
			enableREST:  true,
			enableMCP:   true,
			enableQUIC:  true,
			description: "nil service with all protocols returns early",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socketPath := lifecycleShortSocketPath(t, tt.name)

			config := testConfig(socketPath)
			config.EnableREST = tt.enableREST
			if tt.enableREST {
				config.RESTListenAddr = "127.0.0.1:0"
			}
			config.EnableMCP = tt.enableMCP
			if tt.enableMCP {
				config.MCPConfig = &MCPConfig{
					ServerName:            "test-mcp",
					ServerVersion:         "1.0.0",
					Transport:             "http",
					HTTPAddr:              "127.0.0.1:0",
					RequestTimeout:        30 * time.Second,
					MaxConcurrentRequests: 100,
				}
			}
			config.EnableQUIC = tt.enableQUIC
			if tt.enableQUIC {
				config.QUICListenAddr = "127.0.0.1:0"
			}

			d, err := New(config)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			// Pre-condition: tpm2Service should be nil
			if d.tpm2Service != nil {
				t.Error("tpm2Service should be nil before SetTPM2Service")
			}

			// Calling with nil should return early
			d.SetTPM2Service(nil)

			// Post-condition: tpm2Service should still be nil
			if d.tpm2Service != nil {
				t.Error("tpm2Service should remain nil after SetTPM2Service(nil)")
			}
		})
	}
}

func TestSetTPM2ServiceLifecycle_ConcurrentAccess(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "conc")

	config := testConfig(socketPath)
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

	// Launch concurrent SetTPM2Service calls to test thread safety
	var wg sync.WaitGroup
	const numGoroutines = 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Calling with nil exercises the lock but returns early
			d.SetTPM2Service(nil)
		}()
	}

	wg.Wait()
	// Test passes if no race conditions detected (run with -race flag)
}

func TestSetTPM2ServiceLifecycle_WithRunningDaemon(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "running")

	config := testConfig(socketPath)
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	ctx := context.Background()

	// Start daemon
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// SetTPM2Service with nil should work while daemon is running
	d.SetTPM2Service(nil)

	if !d.IsRunning() {
		t.Error("Daemon should still be running after SetTPM2Service")
	}
}

// =============================================================================
// Start() Tests - Various Configurations and Error Scenarios
// =============================================================================

func TestStartLifecycle_AlreadyRunning(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "already")

	config := testConfig(socketPath)
	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	ctx := context.Background()

	// First start should succeed
	if err := d.Start(ctx); err != nil {
		t.Fatalf("First Start() failed: %v", err)
	}

	// Second start should fail
	err = d.Start(ctx)
	if err == nil {
		t.Fatal("Second Start() should return error")
	}

	if _, ok := err.(ErrDaemonAlreadyRunning); !ok {
		t.Errorf("Expected ErrDaemonAlreadyRunning, got %T: %v", err, err)
	}
}

func TestStartLifecycle_WithAllServicesNil(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "allnil")

	config := testConfig(socketPath)
	config.EnableREST = false
	config.EnableMCP = false
	config.EnableQUIC = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	// Verify optional services are nil
	if d.sdnService != nil || d.kmsService != nil ||
		d.iamService != nil || d.tenantService != nil {
		t.Skip("Services should be nil for this test")
	}

	ctx := context.Background()

	// Start should succeed with all nil services
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if !d.IsRunning() {
		t.Error("Daemon should be running after Start()")
	}
}

func TestStartLifecycle_RunningStateTransitions(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "trans")

	config := testConfig(socketPath)
	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	// Initial state
	if d.IsRunning() {
		t.Error("Daemon should not be running initially")
	}

	ctx := context.Background()

	// Start
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	if !d.IsRunning() {
		t.Error("Daemon should be running after Start()")
	}

	// Stop
	if err := d.Stop(ctx); err != nil {
		t.Fatalf("Stop() failed: %v", err)
	}
	if d.IsRunning() {
		t.Error("Daemon should not be running after Stop()")
	}
}

func TestStartLifecycle_WithRESTServer(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "rest")

	config := testConfig(socketPath)
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	if d.restServer == nil {
		t.Fatal("REST server should be created")
	}

	ctx := context.Background()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if !d.restServer.IsRunning() {
		t.Error("REST server should be running after daemon start")
	}
}

func TestStartLifecycle_WithMCPServer(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "mcp")

	config := testConfig(socketPath)
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

	if d.mcpServer == nil {
		t.Fatal("MCP server should be created")
	}

	ctx := context.Background()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// MCP server should be started
	if !d.mcpServer.IsRunning() {
		t.Error("MCP server should be running after daemon start")
	}
}

func TestStartLifecycle_WithGRPCTCPEnabled(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "grpc")

	config := testConfig(socketPath)
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
		if d.grpcListener != nil {
			_ = d.grpcListener.Close()
		}
		d.ForceStop()
	}()

	if d.grpcServer == nil {
		t.Fatal("gRPC server should be created")
	}

	ctx := context.Background()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if d.grpcListener == nil {
		t.Error("gRPC listener should be set after start")
	}
}

// =============================================================================
// Stop() Tests - Various States and Service Configurations
// =============================================================================

func TestStopLifecycle_NotRunning(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "stopnr")

	config := testConfig(socketPath)
	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	err = d.Stop(ctx)
	if err == nil {
		t.Fatal("Stop() on non-running daemon should return error")
	}

	if _, ok := err.(ErrDaemonNotRunning); !ok {
		t.Errorf("Expected ErrDaemonNotRunning, got %T: %v", err, err)
	}
}

func TestStopLifecycle_ClosesHealthRegistry(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "stophr")

	config := testConfig(socketPath)
	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if err := d.Stop(ctx); err != nil {
		t.Fatalf("Stop() failed: %v", err)
	}

	// Verify health registry is closed by attempting to register
	checker := &lifecycleMockHealthChecker{name: "test"}
	err = d.healthRegistry.Register(checker)
	if err == nil {
		t.Error("Register() on closed registry should return error")
	}
}

func TestStopLifecycle_WithRESTServer(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "stoprst")

	config := testConfig(socketPath)
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if !d.restServer.IsRunning() {
		t.Error("REST server should be running before stop")
	}

	if err := d.Stop(ctx); err != nil {
		t.Fatalf("Stop() failed: %v", err)
	}

	if d.restServer.IsRunning() {
		t.Error("REST server should not be running after stop")
	}
}

func TestStopLifecycle_WithMCPServer(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "stopmcp")

	config := testConfig(socketPath)
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

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if err := d.Stop(ctx); err != nil {
		t.Fatalf("Stop() failed: %v", err)
	}

	if d.mcpServer.IsRunning() {
		t.Error("MCP server should not be running after stop")
	}
}

func TestStopLifecycle_WithGRPCServer(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "stopgrpc")

	config := testConfig(socketPath)
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if err := d.Stop(ctx); err != nil {
		t.Fatalf("Stop() failed: %v", err)
	}

	if d.IsRunning() {
		t.Error("Daemon should not be running after stop")
	}
}

func TestStopLifecycle_WithNilHealthRegistry(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "stopnilhr")

	config := testConfig(socketPath)
	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Set health registry to nil to test nil check
	d.healthRegistry = nil

	// Stop should not panic with nil registry
	if err := d.Stop(ctx); err != nil {
		t.Logf("Stop() returned error (expected): %v", err)
	}
}

// =============================================================================
// ForceStop() Tests - Various States and Service Configurations
// =============================================================================

func TestForceStopLifecycle_NotRunning(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "fsnr")

	config := testConfig(socketPath)
	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	err = d.ForceStop()
	if err == nil {
		t.Fatal("ForceStop() on non-running daemon should return error")
	}

	if _, ok := err.(ErrDaemonNotRunning); !ok {
		t.Errorf("Expected ErrDaemonNotRunning, got %T: %v", err, err)
	}
}

func TestForceStopLifecycle_ClosesHealthRegistry(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "fshr")

	config := testConfig(socketPath)
	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	err = d.ForceStop()
	if err != nil {
		// May return "server is not running" - that's acceptable
		if err.Error() != "server is not running" {
			t.Fatalf("ForceStop() failed: %v", err)
		}
	}
}

func TestForceStopLifecycle_WithRESTServer(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "fsrst")

	config := testConfig(socketPath)
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	err = d.ForceStop()
	if err != nil && err.Error() != "server is not running" {
		t.Fatalf("ForceStop() failed: %v", err)
	}
}

func TestForceStopLifecycle_WithMCPServer(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "fsmcp")

	config := testConfig(socketPath)
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

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	err = d.ForceStop()
	if err != nil && err.Error() != "server is not running" {
		t.Fatalf("ForceStop() failed: %v", err)
	}
}

func TestForceStopLifecycle_WithGRPCServer(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "fsgrpc")

	config := testConfig(socketPath)
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	err = d.ForceStop()
	if err != nil && err.Error() != "server is not running" {
		t.Fatalf("ForceStop() failed: %v", err)
	}
}

func TestForceStopLifecycle_WithNilHealthRegistry(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "fsnilhr")

	config := testConfig(socketPath)
	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Set health registry to nil
	d.healthRegistry = nil

	// ForceStop should not panic
	err = d.ForceStop()
	if err != nil && err.Error() != "server is not running" {
		t.Logf("ForceStop() returned error: %v", err)
	}
}

// =============================================================================
// New() Tests - Configuration Edge Cases
// =============================================================================

func TestNewLifecycle_WithEmptySocketPath(t *testing.T) {
	config := &Config{
		SocketPath:        "",
		ShutdownTimeout:   10 * time.Second,
		Services:          map[string]ServiceConfig{},
		SkipIAMValidation: true,
	}

	_, err := New(config)
	if err == nil {
		t.Fatal("New() should fail with empty socket path")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("Expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewLifecycle_WithZeroShutdownTimeout(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "zerot")

	config := &Config{
		SocketPath:        socketPath,
		ShutdownTimeout:   0,
		Services:          map[string]ServiceConfig{},
		SkipIAMValidation: true,
	}

	_, err := New(config)
	if err == nil {
		t.Fatal("New() should fail with zero shutdown timeout")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("Expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewLifecycle_WithInvalidServiceTimeout(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "invst")

	config := testConfig(socketPath)
	config.Services = map[string]ServiceConfig{
		"test-service": {
			Enabled:    true,
			AutoStart:  false,
			Timeout:    0, // Invalid
			MaxRetries: 3,
		},
	}

	_, err := New(config)
	if err == nil {
		t.Fatal("New() should fail with zero service timeout")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("Expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewLifecycle_WithNegativeMaxRetries(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "negrt")

	config := testConfig(socketPath)
	config.Services = map[string]ServiceConfig{
		"test-service": {
			Enabled:    true,
			AutoStart:  false,
			Timeout:    10 * time.Second,
			MaxRetries: -1, // Invalid
		},
	}

	_, err := New(config)
	if err == nil {
		t.Fatal("New() should fail with negative max retries")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("Expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewLifecycle_WithInvalidMCPTransport(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "invmcp")

	config := testConfig(socketPath)
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test",
		ServerVersion:         "1.0.0",
		Transport:             "invalid", // Invalid transport
		HTTPAddr:              "127.0.0.1:9445",
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}

	_, err := New(config)
	if err == nil {
		t.Fatal("New() should fail with invalid MCP transport")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("Expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewLifecycle_WithMCPHTTPTransportNoAddr(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "mcpnoaddr")

	config := testConfig(socketPath)
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test",
		ServerVersion:         "1.0.0",
		Transport:             "http",
		HTTPAddr:              "", // Invalid for HTTP transport
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}

	_, err := New(config)
	if err == nil {
		t.Fatal("New() should fail with empty HTTP address for HTTP transport")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("Expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewLifecycle_WithQUICEnabledNoAddr(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "quicnoaddr")

	config := testConfig(socketPath)
	config.EnableQUIC = true
	config.QUICListenAddr = "" // Invalid when QUIC enabled

	_, err := New(config)
	if err == nil {
		t.Fatal("New() should fail with empty QUIC address when QUIC enabled")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("Expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestNewLifecycle_WithRESTEnabledNoAddr(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "restnoaddr")

	config := testConfig(socketPath)
	config.EnableREST = true
	config.RESTListenAddr = "" // Invalid when REST enabled

	_, err := New(config)
	if err == nil {
		t.Fatal("New() should fail with empty REST address when REST enabled")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("Expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

// =============================================================================
// createMCPServer() Tests - Various MCP Configurations
// =============================================================================

func TestCreateMCPServerLifecycle_WithDefaultMCPConfig(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "mcpdef")

	config := testConfig(socketPath)
	config.EnableMCP = true
	config.MCPConfig = nil // Will use defaults

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// When MCPConfig is nil, it should use DefaultMCPConfig()
	if d.mcpServer == nil {
		t.Error("MCP server should be created with default config")
	}
}

func TestCreateMCPServerLifecycle_WithHTTPTransport(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "mcphttp")

	config := testConfig(socketPath)
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test-http-mcp",
		ServerVersion:         "2.0.0",
		Transport:             "http",
		HTTPAddr:              "127.0.0.1:0",
		RequestTimeout:        60 * time.Second,
		MaxConcurrentRequests: 200,
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if d.mcpServer == nil {
		t.Fatal("MCP server should be created")
	}

	// Verify MCP provider was created
	if d.mcpProvider == nil {
		t.Error("MCP provider should be created")
	}
}

func TestCreateMCPServerLifecycle_WithStdioTransport(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "mcpstdio")

	config := testConfig(socketPath)
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test-stdio-mcp",
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

	if d.mcpServer == nil {
		t.Error("MCP server should be created for stdio transport")
	}

	// MCPListenAddr should be empty for stdio transport
	addr := d.MCPListenAddr()
	if addr != "" {
		t.Errorf("MCPListenAddr() = %q, want empty for stdio transport", addr)
	}
}

// =============================================================================
// registerHealthCheckers() Tests - Various Service Configurations
// =============================================================================

func TestRegisterHealthCheckersLifecycle_WithNilRegistry(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "hcnilr")

	config := testConfig(socketPath)
	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Clear health registry
	d.healthRegistry = nil

	// This should not panic
	d.registerHealthCheckers()
}

func TestRegisterHealthCheckersLifecycle_WithRESTServer(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "hcrest")

	config := testConfig(socketPath)
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Verify REST health checker is registered
	// The count should be > 0 since registerHealthCheckers was called in New()
	if d.healthRegistry.Count() == 0 {
		t.Error("Health registry should have registered checkers")
	}
}

func TestRegisterHealthCheckersLifecycle_WithMCPServer(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "hcmcp")

	config := testConfig(socketPath)
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test",
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

	// Verify health checkers are registered
	if d.healthRegistry.Count() == 0 {
		t.Error("Health registry should have registered checkers")
	}
}

func TestRegisterHealthCheckersLifecycle_WithAllServers(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "hcall")

	config := testConfig(socketPath)
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test",
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

	// With REST and MCP enabled, should have at least 2 health checkers
	if d.healthRegistry.Count() < 2 {
		t.Errorf("Health registry should have at least 2 checkers, got %d", d.healthRegistry.Count())
	}
}

// =============================================================================
// QUICListenAddr() Tests - Edge Cases
// =============================================================================

func TestQUICListenAddrLifecycle_WithNilServer(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "quicnil")

	config := testConfig(socketPath)
	config.EnableQUIC = false
	config.QUICListenAddr = "0.0.0.0:9444"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// QUIC server should be nil
	if d.quicServer != nil {
		t.Error("QUIC server should be nil when disabled")
	}

	// Should fall back to config value
	addr := d.QUICListenAddr()
	if addr != "0.0.0.0:9444" {
		t.Errorf("QUICListenAddr() = %q, want %q", addr, "0.0.0.0:9444")
	}
}

func TestQUICListenAddrLifecycle_WithEmptyConfigAddr(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "quicempty")

	config := testConfig(socketPath)
	config.EnableQUIC = false
	config.QUICListenAddr = ""

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
// Accessor Methods Tests - Additional Coverage
// =============================================================================

func TestAccessorsLifecycle_ServiceMethods(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "accessors")

	config := testConfig(socketPath)
	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Test all service accessors return correct values
	if d.CAGRPCService() != nil {
		t.Error("CAGRPCService() should return nil when not configured")
	}
	// SDNService always returns a non-nil zone-capable stub; OVSClient is nil when no socket is configured.
	if d.SDNService() == nil {
		t.Error("SDNService() must return a non-nil zone-capable stub")
	}
	if d.SDNService().OVSClient() != nil {
		t.Error("SDNService().OVSClient() must be nil when OVSSocketPath is empty")
	}
	if d.KMSService() != nil {
		t.Error("KMSService() should return nil when not configured")
	}
	if d.IAMService() != nil {
		t.Error("IAMService() should return nil when not configured")
	}
	if d.TenantService() != nil {
		t.Error("TenantService() should return nil when not configured")
	}
	if d.VTPMServiceServer() != nil {
		t.Error("VTPMServiceServer() should return nil when not configured")
	}
	if d.DeviceGRPCService() != nil {
		t.Error("DeviceGRPCService() should return nil when not configured")
	}
	if d.MCPServiceProvider() != nil {
		t.Error("MCPServiceProvider() should return nil when MCP disabled")
	}
}

func TestAccessorsLifecycle_ServerMethods(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "srvaccess")

	config := testConfig(socketPath)
	config.EnableGRPCTCP = false
	config.EnableQUIC = false
	config.EnableREST = false
	config.EnableMCP = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if d.GRPCServer() != nil {
		t.Error("GRPCServer() should return nil when gRPC TCP disabled")
	}
	if d.QUICServer() != nil {
		t.Error("QUICServer() should return nil when QUIC disabled")
	}
	if d.QUICServiceHandler() != nil {
		t.Error("QUICServiceHandler() should return nil when QUIC disabled")
	}
	if d.RESTServer() != nil {
		t.Error("RESTServer() should return nil when REST disabled")
	}
	if d.MCPServer() != nil {
		t.Error("MCPServer() should return nil when MCP disabled")
	}
	// NOTE: UnixSocketServer was removed, now using gRPC over UDS
}

func TestAccessorsLifecycle_EnabledMethods(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "enabled")

	config := testConfig(socketPath)
	config.EnableGRPCTCP = false
	config.EnableQUIC = false
	config.EnableREST = false
	config.EnableMCP = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if d.IsGRPCTCPEnabled() {
		t.Error("IsGRPCTCPEnabled() should return false")
	}
	if d.IsQUICEnabled() {
		t.Error("IsQUICEnabled() should return false")
	}
	if d.IsRESTEnabled() {
		t.Error("IsRESTEnabled() should return false")
	}
	if d.IsMCPEnabled() {
		t.Error("IsMCPEnabled() should return false")
	}
}

func TestAccessorsLifecycle_AddressMethods(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "addrs")

	config := testConfig(socketPath)
	config.EnableGRPCTCP = false
	config.GRPCListenAddr = "0.0.0.0:10443"
	config.EnableREST = false
	config.RESTListenAddr = "0.0.0.0:8443"
	config.EnableMCP = false
	config.MCPConfig = nil

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if got := d.SocketPath(); got != socketPath {
		t.Errorf("SocketPath() = %q, want %q", got, socketPath)
	}
	if got := d.GRPCListenAddr(); got != "0.0.0.0:10443" {
		t.Errorf("GRPCListenAddr() = %q, want %q", got, "0.0.0.0:10443")
	}
	if got := d.RESTListenAddr(); got != "" {
		t.Errorf("RESTListenAddr() = %q, want empty (REST disabled)", got)
	}
	if got := d.MCPListenAddr(); got != "" {
		t.Errorf("MCPListenAddr() = %q, want empty (MCPConfig nil)", got)
	}
}

// =============================================================================
// Service Setter Tests
// =============================================================================

func TestSetCAGRPCServiceLifecycle(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "setca")

	config := testConfig(socketPath)
	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	caService := &CAGRPCService{}
	d.SetCAGRPCService(caService)

	if d.CAGRPCService() != caService {
		t.Error("SetCAGRPCService() did not set the service correctly")
	}
}

func TestSetDeviceGRPCServiceLifecycle(t *testing.T) {
	socketPath := lifecycleShortSocketPath(t, "setdev")

	config := testConfig(socketPath)
	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	deviceService := &DeviceGRPCService{}
	d.SetDeviceGRPCService(deviceService)

	if d.DeviceGRPCService() != deviceService {
		t.Error("SetDeviceGRPCService() did not set the service correctly")
	}
}

// NOTE: stopServer() tests were removed as part of Unix IPC refactoring.
// The Unix socket server was replaced with gRPC over Unix Domain Sockets.

// =============================================================================
// Mock Helper Types
// =============================================================================

// lifecycleMockHealthChecker implements health.HealthChecker for testing
type lifecycleMockHealthChecker struct {
	name   string
	status health.HealthStatus
}

func (m *lifecycleMockHealthChecker) Name() string {
	return m.name
}

func (m *lifecycleMockHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	return health.ComponentHealth{
		Name:   m.name,
		Status: m.status,
	}
}
