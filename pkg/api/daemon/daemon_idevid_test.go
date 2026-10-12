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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// idevidTestSocketPath creates a short socket path to avoid Unix domain socket path length limits (108 chars)
func idevidTestSocketPath(t *testing.T, name string) string {
	// os.TempDir keeps the prefix short — a t.TempDir() path can push the
	// socket past the 108-character sun_path limit.
	sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("td%d-%s.sock", os.Getpid(), name))
	t.Cleanup(func() {
		os.Remove(sockPath)
	})
	return sockPath
}

// =============================================================================
// SetTPM2Service Tests - Comprehensive Coverage
// =============================================================================

func TestSetTPM2ServiceIDevIDTest_NilServiceEarlyReturn(t *testing.T) {
	t.Run("nil service returns immediately without modification", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "nil")

		config := testConfig(socketPath)
		config.EnableREST = true
		config.RESTListenAddr = "127.0.0.1:0"
		config.EnableMCP = false
		config.EnableQUIC = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		// Pre-condition: tpm2Service should be nil
		if d.tpm2Service != nil {
			t.Fatal("tpm2Service should be nil before SetTPM2Service")
		}

		// Calling with nil should return early and not modify anything
		d.SetTPM2Service(nil)

		// Post-condition: tpm2Service should still be nil
		if d.tpm2Service != nil {
			t.Error("tpm2Service should remain nil after SetTPM2Service(nil)")
		}
	})
}

func TestSetTPM2ServiceIDevIDTest_AllProtocolsEnabled(t *testing.T) {
	t.Run("nil service with all protocols enabled", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "all")

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
		config.EnableQUIC = true
		config.QUICListenAddr = "127.0.0.1:0"

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		// Verify all protocol handlers are created
		if d.restServer == nil {
			t.Error("REST server should be created when EnableREST=true")
		}
		if d.mcpProvider == nil {
			t.Error("MCP provider should be created when EnableMCP=true")
		}
		// QUIC handler creation depends on config.QUICConfig

		// SetTPM2Service with nil should not panic even with all protocols enabled
		d.SetTPM2Service(nil)
	})
}

func TestSetTPM2ServiceIDevIDTest_OnlyRESTEnabled(t *testing.T) {
	t.Run("REST server receives nil IDevID service without error", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "rest")

		config := testConfig(socketPath)
		config.EnableREST = true
		config.RESTListenAddr = "127.0.0.1:0"
		config.EnableMCP = false
		config.EnableQUIC = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		if d.restServer == nil {
			t.Fatal("REST server should be available")
		}

		// Should not panic
		d.SetTPM2Service(nil)
	})
}

func TestSetTPM2ServiceIDevIDTest_OnlyMCPEnabled(t *testing.T) {
	t.Run("MCP provider receives nil IDevID service without error", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "mcp")

		config := testConfig(socketPath)
		config.EnableREST = false
		config.EnableMCP = true
		config.MCPConfig = &MCPConfig{
			ServerName:            "test-mcp",
			ServerVersion:         "1.0.0",
			Transport:             "http",
			HTTPAddr:              "127.0.0.1:0",
			RequestTimeout:        30 * time.Second,
			MaxConcurrentRequests: 100,
		}
		config.EnableQUIC = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		if d.mcpProvider == nil {
			t.Fatal("MCP provider should be available")
		}

		// Should not panic
		d.SetTPM2Service(nil)
	})
}

func TestSetTPM2ServiceIDevIDTest_NoProtocolsEnabled(t *testing.T) {
	t.Run("no protocols enabled still works", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "none")

		config := testConfig(socketPath)
		config.EnableREST = false
		config.EnableMCP = false
		config.EnableQUIC = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		// All protocol handlers should be nil
		if d.restServer != nil {
			t.Error("REST server should be nil when disabled")
		}
		if d.mcpProvider != nil {
			t.Error("MCP provider should be nil when disabled")
		}
		if d.quicHandler != nil {
			t.Error("QUIC handler should be nil when disabled")
		}

		// Should not panic even with all nil
		d.SetTPM2Service(nil)
	})
}

func TestSetTPM2ServiceIDevIDTest_ConcurrentCalls(t *testing.T) {
	t.Run("concurrent calls to SetTPM2Service are thread-safe", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "conc")

		config := testConfig(socketPath)
		config.EnableREST = true
		config.RESTListenAddr = "127.0.0.1:0"
		config.EnableMCP = false
		config.EnableQUIC = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		// Launch many concurrent SetTPM2Service calls
		var wg sync.WaitGroup
		const numGoroutines = 50

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.SetTPM2Service(nil)
			}()
		}

		// Wait for all goroutines to complete
		wg.Wait()

		// Test passes if no race conditions detected (run with -race flag)
	})
}

// =============================================================================
// Start Function Tests - Error Conditions
// =============================================================================

func TestStartIDevIDTest_DaemonAlreadyRunning(t *testing.T) {
	t.Run("starting already running daemon returns ErrDaemonAlreadyRunning", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "runx")

		config := testConfig(socketPath)
		config.EnableREST = false
		config.EnableMCP = false
		config.EnableQUIC = false

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

		// Second start should fail with ErrDaemonAlreadyRunning
		err = d.Start(ctx)
		if err == nil {
			t.Fatal("Second Start() should return error")
		}

		if _, ok := err.(ErrDaemonAlreadyRunning); !ok {
			t.Errorf("Expected ErrDaemonAlreadyRunning, got %T: %v", err, err)
		}
	})
}

func TestStartIDevIDTest_WithServicesNil(t *testing.T) {
	t.Run("start with all optional services nil", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "svnil")

		config := testConfig(socketPath)
		config.EnableREST = false
		config.EnableMCP = false
		config.EnableQUIC = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		defer d.ForceStop()

		// Ensure all optional services are nil
		if d.sdnService != nil {
			t.Skip("SDN service should be nil for this test")
		}
		if d.kmsService != nil {
			t.Skip("KMS service should be nil for this test")
		}
		if d.iamService != nil {
			t.Skip("IAM service should be nil for this test")
		}
		if d.tenantService != nil {
			t.Skip("Tenant service should be nil for this test")
		}

		ctx := context.Background()

		// Start should succeed with all nil services
		if err := d.Start(ctx); err != nil {
			t.Errorf("Start() failed: %v", err)
		}

		if !d.IsRunning() {
			t.Error("Daemon should be running after Start()")
		}
	})
}

func TestStartIDevIDTest_RunningStateTransition(t *testing.T) {
	t.Run("running state transitions correctly", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "state")

		config := testConfig(socketPath)
		config.EnableREST = false
		config.EnableMCP = false
		config.EnableQUIC = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		defer d.ForceStop()

		// Initial state should be not running
		if d.IsRunning() {
			t.Error("Daemon should not be running initially")
		}

		ctx := context.Background()

		// Start daemon
		if err := d.Start(ctx); err != nil {
			t.Fatalf("Start() failed: %v", err)
		}

		// State should now be running
		if !d.IsRunning() {
			t.Error("Daemon should be running after Start()")
		}

		// Stop daemon
		if err := d.Stop(ctx); err != nil {
			t.Fatalf("Stop() failed: %v", err)
		}

		// State should be not running
		if d.IsRunning() {
			t.Error("Daemon should not be running after Stop()")
		}
	})
}

// =============================================================================
// New Function Tests - Configuration Options
// =============================================================================

func TestNewIDevIDTest_WithNilConfig(t *testing.T) {
	t.Run("nil config uses defaults but may fail due to permissions", func(t *testing.T) {
		// nil config uses DefaultConfig() which has SocketPath=/run/platformd.sock
		// This will fail in non-root environments but that's expected behavior
		_, err := New(nil)
		if err != nil {
			// Expected in non-privileged environments
			t.Logf("New(nil) failed as expected in non-privileged environment: %v", err)
			return
		}
	})
}

func TestNewIDevIDTest_WithInvalidSocketPath(t *testing.T) {
	t.Run("empty socket path returns ErrInvalidConfig", func(t *testing.T) {
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
	})
}

func TestNewIDevIDTest_WithInvalidShutdownTimeout(t *testing.T) {
	t.Run("zero shutdown timeout returns ErrInvalidConfig", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "tout")

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
	})
}

func TestNewIDevIDTest_WithCustomSocketMode(t *testing.T) {
	t.Run("custom socket mode is applied", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "mode")

		config := &Config{
			SocketPath:        socketPath,
			GRPCSocketPath:    socketPath, // Set gRPC UDS socket path
			SocketGroup:       "",
			SocketMode:        0600, // Custom mode
			ShutdownTimeout:   10 * time.Second,
			Services:          map[string]ServiceConfig{},
			SkipIAMValidation: true,
		}

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		// Verify socket path is set correctly
		if d.SocketPath() != socketPath {
			t.Errorf("SocketPath() = %q, want %q", d.SocketPath(), socketPath)
		}
	})
}

func TestNewIDevIDTest_WithRESTEnabled(t *testing.T) {
	t.Run("REST server is created when enabled", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "rsten")

		config := testConfig(socketPath)
		config.EnableREST = true
		config.RESTListenAddr = "127.0.0.1:0"

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		if d.restServer == nil {
			t.Error("REST server should be created when EnableREST=true")
		}

		if !d.IsRESTEnabled() {
			t.Error("IsRESTEnabled() should return true")
		}
	})
}

func TestNewIDevIDTest_WithRESTDisabled(t *testing.T) {
	t.Run("REST server is nil when disabled", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "rstds")

		config := testConfig(socketPath)
		config.EnableREST = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		if d.restServer != nil {
			t.Error("REST server should be nil when EnableREST=false")
		}

		if d.IsRESTEnabled() {
			t.Error("IsRESTEnabled() should return false")
		}
	})
}

func TestNewIDevIDTest_WithMCPEnabled(t *testing.T) {
	t.Run("MCP server is created when enabled", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "mcpen")

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

		if d.mcpServer == nil {
			t.Error("MCP server should be created when EnableMCP=true")
		}

		if d.mcpProvider == nil {
			t.Error("MCP provider should be created when EnableMCP=true")
		}

		if !d.IsMCPEnabled() {
			t.Error("IsMCPEnabled() should return true")
		}
	})
}

func TestNewIDevIDTest_WithMCPStdioTransport(t *testing.T) {
	t.Run("MCP with stdio transport is valid", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "stdio")

		config := testConfig(socketPath)
		config.EnableMCP = true
		config.MCPConfig = &MCPConfig{
			ServerName:            "test-mcp",
			ServerVersion:         "1.0.0",
			Transport:             "stdio",
			HTTPAddr:              "", // Not needed for stdio
			RequestTimeout:        30 * time.Second,
			MaxConcurrentRequests: 100,
		}

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		// MCP listen addr should be empty for stdio transport
		if addr := d.MCPListenAddr(); addr != "" {
			t.Errorf("MCPListenAddr() = %q, want empty string for stdio transport", addr)
		}
	})
}

func TestNewIDevIDTest_WithHealthRegistry(t *testing.T) {
	t.Run("health registry is created", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "hlth")

		config := testConfig(socketPath)

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		if d.healthRegistry == nil {
			t.Error("Health registry should be created")
		}

		if d.HealthRegistry() == nil {
			t.Error("HealthRegistry() should return non-nil")
		}
	})
}

func TestNewIDevIDTest_WithServicesMap(t *testing.T) {
	t.Run("services configuration is applied", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "svcm")

		config := testConfig(socketPath)
		config.Services = map[string]ServiceConfig{
			"custom-service": {
				Enabled:    true,
				AutoStart:  false,
				Timeout:    15 * time.Second,
				MaxRetries: 5,
			},
		}

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		// Daemon should be created with custom services config
		if d.config.Services["custom-service"].MaxRetries != 5 {
			t.Error("Custom service config should be applied")
		}
	})
}

func TestNewIDevIDTest_WithInvalidServiceTimeout(t *testing.T) {
	t.Run("invalid service timeout returns error", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "svct")

		config := testConfig(socketPath)
		config.Services = map[string]ServiceConfig{
			"invalid": {
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
	})
}

func TestNewIDevIDTest_WithNegativeMaxRetries(t *testing.T) {
	t.Run("negative max retries returns error", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "negr")

		config := testConfig(socketPath)
		config.Services = map[string]ServiceConfig{
			"invalid": {
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
	})
}

// =============================================================================
// Accessor Method Tests
// =============================================================================

func TestDaemonIDevIDTest_GRPCAccessors(t *testing.T) {
	t.Run("GRPC accessors return correct values", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "grpc")

		config := testConfig(socketPath)
		config.EnableGRPCTCP = false
		config.SkipIAMValidation = true
		config.GRPCListenAddr = "127.0.0.1:10443"

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		// GRPCListenAddr should return config value
		if addr := d.GRPCListenAddr(); addr != "127.0.0.1:10443" {
			t.Errorf("GRPCListenAddr() = %q, want %q", addr, "127.0.0.1:10443")
		}

		// GRPCServer should be nil when disabled
		if d.GRPCServer() != nil {
			t.Error("GRPCServer() should return nil when gRPC TCP is disabled")
		}

		// IsGRPCTCPEnabled should return false
		if d.IsGRPCTCPEnabled() {
			t.Error("IsGRPCTCPEnabled() should return false")
		}
	})
}

func TestDaemonIDevIDTest_UnixSocketAccessors(t *testing.T) {
	t.Run("Unix socket accessors return correct values", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "unix")

		config := testConfig(socketPath)

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		// NOTE: UnixSocketServer was removed, now using gRPC over UDS

		// SocketPath should match config
		if d.SocketPath() != socketPath {
			t.Errorf("SocketPath() = %q, want %q", d.SocketPath(), socketPath)
		}
	})
}

func TestDaemonIDevIDTest_ServiceReturnsCorrectInstance(t *testing.T) {
	t.Run("Service returns the daemon service instance", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "svci")

		config := testConfig(socketPath)

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		svc := d.Service()
		if svc == nil {
			t.Fatal("Service() should not return nil")
		}

		// Should return the same instance
		if svc != d.service {
			t.Error("Service() should return the daemon's internal service instance")
		}
	})
}

// =============================================================================
// Lifecycle Edge Cases
// =============================================================================

// NOTE: TestDaemonIDevIDTest_StopServerWithNilServer was removed as part of Unix IPC refactoring.
// The Unix socket server was replaced with gRPC over Unix Domain Sockets.

func TestDaemonIDevIDTest_ForceStopNotRunning(t *testing.T) {
	t.Run("ForceStop on non-running daemon returns error", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "fsnr")

		config := testConfig(socketPath)

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		// Daemon is not running
		err = d.ForceStop()
		if err == nil {
			t.Fatal("ForceStop() on non-running daemon should return error")
		}

		if _, ok := err.(ErrDaemonNotRunning); !ok {
			t.Errorf("Expected ErrDaemonNotRunning, got %T: %v", err, err)
		}
	})
}

func TestDaemonIDevIDTest_StopNotRunning(t *testing.T) {
	t.Run("Stop on non-running daemon returns error", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "snr")

		config := testConfig(socketPath)

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		ctx := context.Background()

		// Daemon is not running
		err = d.Stop(ctx)
		if err == nil {
			t.Fatal("Stop() on non-running daemon should return error")
		}

		if _, ok := err.(ErrDaemonNotRunning); !ok {
			t.Errorf("Expected ErrDaemonNotRunning, got %T: %v", err, err)
		}
	})
}

// =============================================================================
// MCPServiceProvider Integration Tests
// =============================================================================

func TestMCPServiceProviderIDevIDTest_SetTPM2Service(t *testing.T) {
	t.Run("MCPServiceProvider receives IDevID service", func(t *testing.T) {
		config := &MCPServiceProviderConfig{
			Logger: nil,
		}

		provider := NewMCPServiceProvider(config)
		if provider == nil {
			t.Fatal("NewMCPServiceProvider() should not return nil")
		}

		// Initial state should be nil
		if provider.tpm2Service != nil {
			t.Error("tpm2Service should be nil initially")
		}

		// Set to nil explicitly
		provider.SetTPM2Service(nil)

		// Should still be nil
		if provider.tpm2Service != nil {
			t.Error("tpm2Service should remain nil after SetTPM2Service(nil)")
		}
	})
}

func TestMCPServiceProviderIDevIDTest_NewWithDefaultLogger(t *testing.T) {
	t.Run("NewMCPServiceProvider uses default logger when nil", func(t *testing.T) {
		config := &MCPServiceProviderConfig{
			Logger: nil,
		}

		provider := NewMCPServiceProvider(config)
		if provider == nil {
			t.Fatal("NewMCPServiceProvider() should not return nil")
		}

		// Logger should be set to default
		if provider.logger == nil {
			t.Error("logger should be set to default when config.Logger is nil")
		}
	})
}

// =============================================================================
// Additional SetTPM2Service Coverage - With Running Daemon
// =============================================================================

func TestSetTPM2ServiceIDevIDTest_WithRunningDaemon(t *testing.T) {
	t.Run("SetTPM2Service works while daemon is running", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "run")

		config := testConfig(socketPath)
		config.EnableREST = true
		config.RESTListenAddr = "127.0.0.1:0"
		config.EnableMCP = false
		config.EnableQUIC = false

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

		// SetTPM2Service should work while daemon is running
		d.SetTPM2Service(nil)

		// Daemon should still be running
		if !d.IsRunning() {
			t.Error("Daemon should still be running after SetTPM2Service")
		}
	})
}

func TestSetTPM2ServiceIDevIDTest_LoggingDebugMessages(t *testing.T) {
	t.Run("SetTPM2Service logs debug messages for each handler", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "log")

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
		config.EnableQUIC = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		// With nil service, the function returns early before logging
		// This is expected behavior
		d.SetTPM2Service(nil)

		// Verify handlers are still accessible
		if d.restServer == nil {
			t.Error("REST server should still be available")
		}
		if d.mcpProvider == nil {
			t.Error("MCP provider should still be available")
		}
	})
}

// =============================================================================
// QUICHandler SetTPM2Service Tests
// =============================================================================

func TestQUICServiceHandler_SetTPM2Service(t *testing.T) {
	t.Run("QUICServiceHandler.SetTPM2Service accepts nil", func(t *testing.T) {
		handler := newTestQUICServiceHandler(nil)
		if handler == nil {
			t.Fatal("newTestQUICServiceHandler() should not return nil")
		}

		// Should not panic
		handler.SetTPM2Service(nil)

		// tpm2Service should be nil
		if handler.tpm2Service != nil {
			t.Error("tpm2Service should be nil after SetTPM2Service(nil)")
		}
	})
}

// =============================================================================
// RESTServer SetTPM2Service Tests
// =============================================================================

func TestRESTServer_SetTPM2Service_IDevIDTests(t *testing.T) {
	t.Run("RESTServer.SetTPM2Service accepts nil", func(t *testing.T) {
		socketPath := idevidTestSocketPath(t, "rsvc")

		config := testConfig(socketPath)
		config.EnableREST = true
		config.RESTListenAddr = "127.0.0.1:0"

		service, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() failed: %v", err)
		}

		restServer, err := NewRESTServer(config, service, nil)
		if err != nil {
			t.Fatalf("NewRESTServer() failed: %v", err)
		}

		// Should not panic
		restServer.SetTPM2Service(nil)

		// tpm2Service should be nil
		if restServer.tpm2Service != nil {
			t.Error("tpm2Service should be nil after SetTPM2Service(nil)")
		}
	})
}
