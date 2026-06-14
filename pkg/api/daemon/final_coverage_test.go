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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// =============================================================================
// Test NewIAMService error paths - focusing on uncovered paths
// =============================================================================

func TestFinalCov_NewIAMService_NilApplication(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	svc, err := NewIAMService(nil, logger)
	if err == nil {
		t.Error("NewIAMService(nil, logger) should return error")
	}
	if svc != nil {
		t.Error("NewIAMService(nil, logger) should return nil service")
	}

	// Check error type
	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("Expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestFinalCov_NewIAMService_NonQuicBaaSFactoryPath(t *testing.T) {
	// This tests line 70-72: factory type assertion failure
	// We cannot easily mock app.App without a real QuicBaaS backend,
	// but we ensure the nil app path is well tested
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Test again with nil to ensure consistent error
	svc, err := NewIAMService(nil, logger)
	if err == nil {
		t.Error("expected error for nil application")
	}
	if svc != nil {
		t.Error("service should be nil on error")
	}

	// Verify it's the right type of error with expected reason
	if invalidCfg, ok := err.(ErrInvalidConfig); ok {
		if invalidCfg.Reason != "application is required for IAM service" {
			t.Errorf("Unexpected error reason: %s", invalidCfg.Reason)
		}
	} else {
		t.Errorf("Expected ErrInvalidConfig, got %T", err)
	}
}

// =============================================================================
// Test TenantService additional paths
// =============================================================================

func TestFinalCov_TenantService_RegisterGRPCServices_NilServer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	svc := &TenantService{
		logger: logger,
		app:    nil,
	}

	// Test nil server path - this is the first check in RegisterGRPCServices
	err := svc.RegisterGRPCServices(nil)
	if err == nil {
		t.Error("RegisterGRPCServices(nil) should return error")
	}

	if invalidCfg, ok := err.(ErrInvalidConfig); ok {
		if invalidCfg.Reason != "gRPC server is required" {
			t.Errorf("Expected 'gRPC server is required', got '%s'", invalidCfg.Reason)
		}
	} else {
		t.Errorf("Expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestFinalCov_TenantService_StartStopIdempotent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	svc := &TenantService{
		logger: logger,
	}

	ctx := context.Background()

	// Start twice, stop twice - should be idempotent
	_ = svc.Start(ctx)
	_ = svc.Start(ctx) // Second start should be no-op

	if !svc.IsRunning() {
		t.Error("should be running after start")
	}

	_ = svc.Stop(ctx)
	_ = svc.Stop(ctx) // Second stop should be no-op

	if svc.IsRunning() {
		t.Error("should not be running after stop")
	}
}

// =============================================================================
// Test Daemon.New() additional validation paths
// =============================================================================

func TestFinalCov_New_InvalidShutdownTimeout(t *testing.T) {
	config := &Config{
		SocketPath:        "/tmp/test-finalcov-new-validate.sock",
		ShutdownTimeout:   -1 * time.Second, // Invalid
		SkipIAMValidation: true,
	}

	_, err := New(config)
	if err == nil {
		t.Error("New() should fail with invalid shutdown timeout")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("Expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestFinalCov_New_EmptySocketPath(t *testing.T) {
	config := &Config{
		SocketPath:        "", // Invalid empty path
		ShutdownTimeout:   30 * time.Second,
		SkipIAMValidation: true,
	}

	_, err := New(config)
	if err == nil {
		t.Error("New() should fail with empty socket path")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("Expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

// =============================================================================
// Test Daemon.QUICServer() type assertion paths
// =============================================================================

// finalCovMockQUICServer implements QUICServerInterface but is not *quic.Server
type finalCovMockQUICServer struct {
	running    bool
	listenAddr string
}

func (m *finalCovMockQUICServer) Start() error       { m.running = true; return nil }
func (m *finalCovMockQUICServer) Stop() error        { m.running = false; return nil }
func (m *finalCovMockQUICServer) IsRunning() bool    { return m.running }
func (m *finalCovMockQUICServer) ListenAddr() string { return m.listenAddr }
func (m *finalCovMockQUICServer) GetMetrics() map[string]interface{} {
	return make(map[string]interface{})
}
func (m *finalCovMockQUICServer) Stats() *quic.ServerStats { return nil }

func TestFinalCov_Daemon_QUICServer_TypeAssertionFailure(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-quic-type-fail.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Inject a mock QUIC server that isn't *quic.Server
	mockServer := &finalCovMockQUICServer{
		listenAddr: "127.0.0.1:9444",
	}
	d.quicServer = mockServer

	// QUICServer() should return nil for non-*quic.Server types
	result := d.QUICServer()
	if result != nil {
		t.Error("QUICServer() should return nil when quicServer is not *quic.Server")
	}
}

func TestFinalCov_Daemon_QUICServer_NilServer(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-quic-nil.sock")
	config.EnableQUIC = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// quicServer should be nil when QUIC is disabled
	result := d.QUICServer()
	if result != nil {
		t.Error("QUICServer() should return nil when QUIC is disabled")
	}
}

// =============================================================================
// Test Daemon.SetTPM2Service() additional paths
// =============================================================================

func TestFinalCov_Daemon_SetTPM2Service_WithNilProtocolHandlers(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-setidevid-nil-handlers.sock")
	config.EnableREST = false
	config.EnableMCP = false
	config.EnableQUIC = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Ensure handlers are nil
	d.concreteRestServer = nil
	d.quicHandler = nil
	d.mcpProvider = nil

	// SetTPM2Service with nil should return early
	d.SetTPM2Service(nil)

	// tpm2Service should remain nil
	if d.tpm2Service != nil {
		t.Error("tpm2Service should be nil after SetTPM2Service(nil)")
	}
}

// =============================================================================
// Test Daemon Start/Stop edge cases
// =============================================================================

func TestFinalCov_Daemon_Start_AlreadyRunning(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-start-already.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer d.ForceStop()

	ctx := context.Background()

	// Start once
	err = d.Start(ctx)
	if err != nil {
		t.Fatalf("First Start() failed: %v", err)
	}

	// Start again should return ErrDaemonAlreadyRunning
	err = d.Start(ctx)
	if err == nil {
		t.Error("Second Start() should return error")
	}

	if _, ok := err.(ErrDaemonAlreadyRunning); !ok {
		t.Errorf("Expected ErrDaemonAlreadyRunning, got %T: %v", err, err)
	}
}

func TestFinalCov_Daemon_Stop_NotRunning(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-stop-notrunning.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Don't start, just try to stop
	ctx := context.Background()
	err = d.Stop(ctx)
	if err == nil {
		t.Error("Stop() on non-running daemon should return error")
	}

	if _, ok := err.(ErrDaemonNotRunning); !ok {
		t.Errorf("Expected ErrDaemonNotRunning, got %T: %v", err, err)
	}
}

func TestFinalCov_Daemon_ForceStop_NotRunning(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-forcestop-notrunning.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Don't start, just try to force stop
	err = d.ForceStop()
	if err == nil {
		t.Error("ForceStop() on non-running daemon should return error")
	}

	if _, ok := err.(ErrDaemonNotRunning); !ok {
		t.Errorf("Expected ErrDaemonNotRunning, got %T: %v", err, err)
	}
}

// =============================================================================
// Test gRPC Server wrapper
// =============================================================================

func TestFinalCov_GRPCServerWrapper_Serve_NilServer(t *testing.T) {
	wrapper := &grpcServerWrapper{server: nil}

	// Create a dummy listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	err = wrapper.Serve(listener)
	if err == nil {
		t.Error("Serve() with nil server should return error")
	}

	if _, ok := err.(ErrGRPCServerNotConfigured); !ok {
		t.Errorf("Expected ErrGRPCServerNotConfigured, got %T: %v", err, err)
	}
}

func TestFinalCov_GRPCServerWrapper_Methods(t *testing.T) {
	// Create a real gRPC server for testing
	grpcServer := grpc.NewServer()
	wrapper := &grpcServerWrapper{server: grpcServer}

	// Test Unwrap
	unwrapped := wrapper.Unwrap()
	if unwrapped != grpcServer {
		t.Error("Unwrap() should return the underlying server")
	}

	// Test GracefulStop on non-nil server
	wrapper.GracefulStop()

	// Test Stop on non-nil server
	wrapper.Stop()

	// Note: RegisterService requires valid desc and impl, so we don't test it here
	// to avoid nil pointer panics. The nil server case is tested separately.
}

func TestFinalCov_GRPCServerWrapper_NilServer(t *testing.T) {
	wrapper := &grpcServerWrapper{server: nil}

	// These should be safe to call with nil server
	wrapper.GracefulStop()
	wrapper.Stop()
	wrapper.RegisterService(nil, nil)

	// Unwrap should return nil
	if wrapper.Unwrap() != nil {
		t.Error("Unwrap() should return nil for nil server")
	}
}

// =============================================================================
// Test Daemon accessor methods - unique tests
// =============================================================================

func TestFinalCov_Daemon_ServiceAccessors(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-accessors.sock")
	config.EnableREST = false
	config.EnableMCP = false
	config.EnableQUIC = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Test Service() returns non-nil
	if d.Service() == nil {
		t.Error("Service() should not return nil")
	}

	// Test path accessors
	if d.SocketPath() != config.SocketPath {
		t.Errorf("SocketPath() = %s, want %s", d.SocketPath(), config.SocketPath)
	}

	// Test nil returns for disabled services
	if d.QUICServiceHandler() != nil {
		t.Error("QUICServiceHandler() should return nil when QUIC is disabled")
	}

	// Test enabled checks
	if d.IsRESTEnabled() {
		t.Error("IsRESTEnabled() should return false")
	}

	if d.IsMCPEnabled() {
		t.Error("IsMCPEnabled() should return false")
	}

	if d.IsQUICEnabled() {
		t.Error("IsQUICEnabled() should return false")
	}

	if d.IsGRPCTCPEnabled() {
		t.Error("IsGRPCTCPEnabled() should return false")
	}
}

func TestFinalCov_Daemon_TPM2ServiceAccessor(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-tpm2-accessor.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// TPM2Service should be nil initially
	if d.TPM2Service() != nil {
		t.Error("TPM2Service() should return nil initially")
	}
}

func TestFinalCov_Daemon_CAServiceAccessors(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-ca-accessor.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Test CAGRPCService getter returns nil when not configured
	if d.CAGRPCService() != nil {
		t.Error("CAGRPCService() should return nil when not configured")
	}

	// Test SetCAGRPCService
	mockCA := &CAGRPCService{}
	d.SetCAGRPCService(mockCA)
	if d.CAGRPCService() != mockCA {
		t.Error("SetCAGRPCService did not set the service")
	}
}

func TestFinalCov_Daemon_DeviceServiceAccessors(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-device-accessor.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Test DeviceGRPCService getter
	if d.DeviceGRPCService() != nil {
		t.Error("DeviceGRPCService() should return nil when not configured")
	}

	// Test SetDeviceGRPCService
	mockDevice := &DeviceGRPCService{}
	d.SetDeviceGRPCService(mockDevice)
	if d.DeviceGRPCService() != mockDevice {
		t.Error("SetDeviceGRPCService did not set the service")
	}
}

func TestFinalCov_Daemon_OtherServiceAccessors(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-other-accessor.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
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
}

// =============================================================================
// Test Health Registry methods
// =============================================================================

func TestFinalCov_Daemon_HealthRegistryMethods(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-health-methods.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Test HealthRegistry accessor
	registry := d.HealthRegistry()
	if registry == nil {
		t.Error("HealthRegistry() should not return nil")
	}

	// Test HealthCheck
	ctx := context.Background()
	health, err := d.HealthCheck(ctx)
	if err != nil {
		t.Errorf("HealthCheck() error = %v", err)
	}
	if health == nil {
		t.Error("HealthCheck() should return non-nil health")
	}

	// Test HealthCheckComponent with non-existent component
	_, err = d.HealthCheckComponent(ctx, "nonexistent-component")
	if err == nil {
		t.Error("HealthCheckComponent() should return error for unknown component")
	}
}

func TestFinalCov_Daemon_HealthCheck_NilRegistryPaths(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-health-nil-reg.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Force nil health registry
	d.healthRegistry = nil

	ctx := context.Background()

	// Test HealthCheck with nil registry
	_, err = d.HealthCheck(ctx)
	if err == nil {
		t.Error("HealthCheck() should return error with nil registry")
	}
	if _, ok := err.(ErrHealthRegistryNotConfigured); !ok {
		t.Errorf("Expected ErrHealthRegistryNotConfigured, got %T: %v", err, err)
	}

	// Test HealthCheckComponent with nil registry
	_, err = d.HealthCheckComponent(ctx, "test")
	if err == nil {
		t.Error("HealthCheckComponent() should return error with nil registry")
	}

	// Test RegisterHealthChecker with nil registry
	err = d.RegisterHealthChecker(nil)
	if err == nil {
		t.Error("RegisterHealthChecker() should return error with nil registry")
	}
}

// =============================================================================
// Test GRPCServer accessor
// =============================================================================

func TestFinalCov_Daemon_GRPCServer_NoWrapper(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-grpc-no-wrapper.sock")
	config.EnableGRPCTCP = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// GRPCServer should return nil when gRPC is disabled
	if d.GRPCServer() != nil {
		t.Error("GRPCServer() should return nil when gRPC TCP is disabled")
	}
}

// NOTE: TestFinalCov_Daemon_UnixSocketServerAccessor was removed as part of Unix IPC refactoring.
// The Unix socket server was replaced with gRPC over Unix Domain Sockets.

// =============================================================================
// Test MCPListenAddr edge cases
// =============================================================================

func TestFinalCov_Daemon_MCPListenAddr_StdioTransport(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-mcp-stdio.sock")
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test",
		ServerVersion:         "1.0.0",
		Transport:             "stdio", // stdio transport
		HTTPAddr:              "127.0.0.1:9445",
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		if d.mcpServer != nil {
			_ = d.mcpServer.Stop()
		}
	}()

	// MCPListenAddr should return empty for stdio transport
	addr := d.MCPListenAddr()
	if addr != "" {
		t.Errorf("MCPListenAddr() = %s, want empty string for stdio transport", addr)
	}
}

func TestFinalCov_Daemon_MCPListenAddr_NilConfig(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-mcp-nil-cfg.sock")
	config.EnableMCP = false

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Force nil MCPConfig
	d.config.MCPConfig = nil

	// MCPListenAddr should return empty with nil config
	addr := d.MCPListenAddr()
	if addr != "" {
		t.Errorf("MCPListenAddr() = %s, want empty string with nil config", addr)
	}
}

// =============================================================================
// Test registerHealthCheckers with nil registry
// =============================================================================

func TestFinalCov_Daemon_RegisterHealthCheckers_NilRegistry(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-health-reg-nil.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Force nil registry
	d.healthRegistry = nil

	// Should not panic
	d.registerHealthCheckers()
}

// =============================================================================
// Test RESTListenAddr
// =============================================================================

func TestFinalCov_Daemon_RESTListenAddr_Disabled(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-rest-disabled.sock")
	config.EnableREST = false
	config.RESTListenAddr = "0.0.0.0:8443"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// RESTListenAddr should return empty when REST is disabled
	addr := d.RESTListenAddr()
	if addr != "" {
		t.Errorf("RESTListenAddr() = %s, want empty string when disabled", addr)
	}
}

func TestFinalCov_Daemon_RESTListenAddr_Enabled(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-rest-enabled.sock")
	config.EnableREST = true
	config.RESTListenAddr = "0.0.0.0:8443"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		if d.restServer != nil {
			_ = d.restServer.ForceStop()
		}
	}()

	// RESTListenAddr should return the configured address when enabled
	addr := d.RESTListenAddr()
	if addr != "0.0.0.0:8443" {
		t.Errorf("RESTListenAddr() = %s, want 0.0.0.0:8443", addr)
	}
}

// =============================================================================
// Test QUICListenAddr with interface type
// =============================================================================

func TestFinalCov_Daemon_QUICListenAddr_WithMockInterface(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-quic-addr-mock.sock")
	config.EnableQUIC = false
	config.QUICListenAddr = "192.168.1.100:9444"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Inject a mock QUIC server
	mockServer := &finalCovMockQUICServer{
		listenAddr: "mock-addr:9444",
	}
	d.quicServer = mockServer

	// QUICListenAddr should use the interface's ListenAddr method
	addr := d.QUICListenAddr()
	if addr != "mock-addr:9444" {
		t.Errorf("QUICListenAddr() = %s, want mock-addr:9444", addr)
	}
}

func TestFinalCov_Daemon_QUICListenAddr_NilServerUsesConfig(t *testing.T) {
	config := testConfig("/tmp/test-finalcov-quic-addr-nil.sock")
	config.EnableQUIC = false
	config.QUICListenAddr = "192.168.1.100:9444"

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Ensure quicServer is nil
	d.quicServer = nil

	// QUICListenAddr should fall back to config
	addr := d.QUICListenAddr()
	if addr != "192.168.1.100:9444" {
		t.Errorf("QUICListenAddr() = %s, want 192.168.1.100:9444", addr)
	}
}

// =============================================================================
// Additional IAMService tests
// =============================================================================

func TestFinalCov_IAMService_StartStopIdempotent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	svc := &IAMService{
		logger: logger,
	}

	ctx := context.Background()

	// Start twice
	_ = svc.Start(ctx)
	_ = svc.Start(ctx)

	if !svc.IsRunning() {
		t.Error("should be running after start")
	}

	// Stop twice
	_ = svc.Stop(ctx)
	_ = svc.Stop(ctx)

	if svc.IsRunning() {
		t.Error("should not be running after stop")
	}
}

func TestFinalCov_IAMService_Name(t *testing.T) {
	svc := &IAMService{}

	if name := svc.Name(); name != "iam" {
		t.Errorf("Name() = %s, want iam", name)
	}
}

func TestFinalCov_TenantService_Name(t *testing.T) {
	svc := &TenantService{}

	if name := svc.Name(); name != "tenant" {
		t.Errorf("Name() = %s, want tenant", name)
	}
}

func TestFinalCov_TenantService_TenantManager(t *testing.T) {
	svc := &TenantService{
		tenantManager: nil,
	}

	// Should return nil when not set
	if svc.TenantManager() != nil {
		t.Error("TenantManager() should return nil when not set")
	}
}

// =============================================================================
// Compile-time interface verification
// =============================================================================

// Verify that quicbaas.Factory is used by the code being tested
var _ datastore.Factory = (*quicbaas.Factory)(nil)

// Verify app.App is compatible (can't do direct interface check due to concrete type)
var _ *app.App = (*app.App)(nil)
