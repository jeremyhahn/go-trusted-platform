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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// =============================================================================
// Start() - Extended Coverage Tests
// =============================================================================

func TestStartExtended_WithoutOptionalServices(t *testing.T) {
	config := testConfig("/tmp/test-start-no-optional.sock")

	d, err := New(config)
	require.NoError(t, err)

	// Verify daemon can start without optional services
	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)
	assert.True(t, d.IsRunning())

	// SDN service is always a non-nil zone-capable stub; only OVS ops need the socket.
	assert.NotNil(t, d.sdnService)
	assert.Nil(t, d.sdnService.OVSClient(), "OVSClient must be nil when OVSSocketPath is empty")
	assert.Nil(t, d.kmsService)
	assert.Nil(t, d.iamService)
	assert.Nil(t, d.tenantService)

	_ = d.Stop(ctx)
}

func TestStartExtended_RESTServerStartWithZeroPort(t *testing.T) {
	config := testConfig("/tmp/test-start-rest-zero.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	assert.True(t, d.IsRunning())
	assert.NotNil(t, d.restServer)

	_ = d.Stop(ctx)
}

func TestStartExtended_MCPServerStartSuccess(t *testing.T) {
	config := testConfig("/tmp/test-start-mcp-success.sock")
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
	require.NoError(t, err)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	assert.True(t, d.IsRunning())

	_ = d.Stop(ctx)
}

func TestStartExtended_QUICServerNilWithoutTLS(t *testing.T) {
	config := testConfig("/tmp/test-start-quic-no-tls.sock")
	config.EnableQUIC = true
	config.QUICListenAddr = "127.0.0.1:0"

	d, err := New(config)
	require.NoError(t, err)

	// QUIC server should be nil since no TLS config
	assert.Nil(t, d.quicServer)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	assert.True(t, d.IsRunning())

	_ = d.Stop(ctx)
}

func TestStartExtended_GRPCTCPServerCreated(t *testing.T) {
	config := testConfig("/tmp/test-start-grpc-tcp.sock")
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config)
	require.NoError(t, err)

	// Server should be created
	assert.NotNil(t, d.grpcServer)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	assert.True(t, d.IsRunning())

	_ = d.Stop(ctx)
}

// =============================================================================
// Stop() - Extended Coverage Tests
// =============================================================================

func TestStopExtended_WithoutOptionalServices(t *testing.T) {
	config := testConfig("/tmp/test-stop-no-optional.sock")

	d, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	err = d.Stop(ctx)
	require.NoError(t, err)

	assert.False(t, d.IsRunning())
}

func TestStopExtended_WithQUICServerNotConfigured(t *testing.T) {
	config := testConfig("/tmp/test-stop-quic-not-conf.sock")
	config.EnableQUIC = true
	config.QUICListenAddr = "127.0.0.1:0"

	d, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	// QUIC server is nil (no TLS)
	assert.Nil(t, d.quicServer)

	err = d.Stop(ctx)
	require.NoError(t, err)

	assert.False(t, d.IsRunning())
}

func TestStopExtended_WithRESTServerPreviouslyStopped(t *testing.T) {
	config := testConfig("/tmp/test-stop-rest-prev-stop.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	// Manually stop the REST server before daemon stop
	if d.restServer != nil && d.restServer.IsRunning() {
		_ = d.restServer.ForceStop()
	}

	err = d.Stop(ctx)
	require.NoError(t, err)

	assert.False(t, d.IsRunning())
}

func TestStopExtended_WithMCPServerPreviouslyStopped(t *testing.T) {
	config := testConfig("/tmp/test-stop-mcp-prev-stop.sock")
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
	require.NoError(t, err)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	// Manually stop the MCP server before daemon stop
	if d.mcpServer != nil && d.mcpServer.IsRunning() {
		_ = d.mcpServer.Stop()
	}

	err = d.Stop(ctx)
	require.NoError(t, err)

	assert.False(t, d.IsRunning())
}

func TestStopExtended_WithGRPCListenerClosed(t *testing.T) {
	config := testConfig("/tmp/test-stop-grpc-closed.sock")
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	// Close the listener manually before daemon stop
	if d.grpcListener != nil {
		_ = d.grpcListener.Close()
		d.grpcListener = nil
	}

	err = d.Stop(ctx)
	require.NoError(t, err)

	assert.False(t, d.IsRunning())
}

// =============================================================================
// New() - Extended Coverage Tests
// =============================================================================

func TestNewExtended_WithNilCAService(t *testing.T) {
	config := testConfig("/tmp/test-new-nil-ca.sock")
	config.CAService = nil

	d, err := New(config)
	require.NoError(t, err)

	assert.Nil(t, d.caService)
}

func TestNewExtended_WithNilVTPMService(t *testing.T) {
	config := testConfig("/tmp/test-new-nil-vtpm.sock")
	config.VTPMService = nil

	d, err := New(config)
	require.NoError(t, err)

	assert.Nil(t, d.vtpmService)
}

func TestNewExtended_WithNilDeviceService(t *testing.T) {
	config := testConfig("/tmp/test-new-nil-device.sock")
	config.DeviceService = nil

	d, err := New(config)
	require.NoError(t, err)

	assert.Nil(t, d.deviceService)
}

func TestNewExtended_WithQUICEnabled_NilQUICConfig(t *testing.T) {
	config := testConfig("/tmp/test-new-quic-nil-cfg.sock")
	config.EnableQUIC = true
	config.QUICListenAddr = "127.0.0.1:0"
	config.QUICConfig = nil

	d, err := New(config)
	require.NoError(t, err)

	assert.NotNil(t, d.config)
}

func TestNewExtended_WithQUICEnabled_CustomConfig_NoTLS(t *testing.T) {
	config := testConfig("/tmp/test-new-quic-custom.sock")
	config.EnableQUIC = true
	config.QUICListenAddr = "127.0.0.1:9444"
	config.QUICConfig = quic.DefaultServerConfig()
	config.QUICConfig.ListenAddr = "127.0.0.1:9445"

	// QUIC requires TLS configuration, so this should fail
	_, err := New(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS")
}

func TestNewExtended_WithQUICEnabled_AddrOverride_NoTLS(t *testing.T) {
	config := testConfig("/tmp/test-new-quic-override.sock")
	config.EnableQUIC = true
	config.QUICListenAddr = "10.0.0.1:9999"
	config.QUICConfig = quic.DefaultServerConfig()
	config.QUICConfig.ListenAddr = "192.168.1.1:8888"

	// QUIC requires TLS configuration, so this should fail
	_, err := New(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS")
}

func TestNewExtended_WithNilLogger(t *testing.T) {
	config := testConfig("/tmp/test-new-nil-logger.sock")
	config.Logger = nil

	d, err := New(config)
	require.NoError(t, err)

	assert.NotNil(t, d.logger)
}

func TestNewExtended_WithCustomLogger(t *testing.T) {
	customLogger := logging.NewLogger(slog.LevelWarn, nil)

	config := testConfig("/tmp/test-new-custom-logger.sock")
	config.Logger = customLogger

	d, err := New(config)
	require.NoError(t, err)

	assert.Equal(t, customLogger, d.logger)
}

func TestNewExtended_ServiceCreated(t *testing.T) {
	config := testConfig("/tmp/test-new-svc-created.sock")

	d, err := New(config)
	require.NoError(t, err)

	assert.NotNil(t, d.service)
}

// =============================================================================
// SetTPM2Service() - Extended Coverage Tests
// =============================================================================

func TestSetTPM2ServiceExtended_WithNilService(t *testing.T) {
	config := testConfig("/tmp/test-setidevid-nil.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	require.NoError(t, err)

	// Calling with nil should return early without panic
	d.SetTPM2Service(nil)
}

func TestSetTPM2ServiceExtended_WithRESTOnly(t *testing.T) {
	config := testConfig("/tmp/test-setidevid-rest.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
	config.EnableMCP = false
	config.EnableQUIC = false

	d, err := New(config)
	require.NoError(t, err)

	assert.NotNil(t, d.restServer)
	assert.Nil(t, d.quicHandler)

	d.SetTPM2Service(nil)
}

func TestSetTPM2ServiceExtended_WithMCPOnly(t *testing.T) {
	config := testConfig("/tmp/test-setidevid-mcp.sock")
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
	require.NoError(t, err)

	assert.Nil(t, d.restServer)
	assert.NotNil(t, d.mcpProvider)

	d.SetTPM2Service(nil)
}

func TestSetTPM2ServiceExtended_WithQUICOnly(t *testing.T) {
	config := testConfig("/tmp/test-setidevid-quic.sock")
	config.EnableREST = false
	config.EnableMCP = false
	config.EnableQUIC = true
	config.QUICListenAddr = "127.0.0.1:0"

	d, err := New(config)
	require.NoError(t, err)

	assert.Nil(t, d.restServer)
	assert.Nil(t, d.mcpProvider)

	d.SetTPM2Service(nil)
}

// =============================================================================
// registerHealthCheckers() - Extended Coverage Tests
// =============================================================================

func TestRegisterHealthCheckersExtended_WithCAService(t *testing.T) {
	config := testConfig("/tmp/test-reg-health-ca.sock")

	d, err := New(config)
	require.NoError(t, err)

	d.healthRegistry = health.NewRegistry()
	d.caService = &CAGRPCService{
		logger: logging.DefaultLogger(),
	}

	d.registerHealthCheckers()

	assert.Greater(t, d.healthRegistry.Count(), 0)
}

func TestRegisterHealthCheckersExtended_WithRESTServer(t *testing.T) {
	config := testConfig("/tmp/test-reg-health-rest.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"

	d, err := New(config)
	require.NoError(t, err)

	d.healthRegistry = health.NewRegistry()

	d.registerHealthCheckers()

	assert.Greater(t, d.healthRegistry.Count(), 0)
}

func TestRegisterHealthCheckersExtended_WithMCPServer(t *testing.T) {
	config := testConfig("/tmp/test-reg-health-mcp.sock")
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
	require.NoError(t, err)

	d.healthRegistry = health.NewRegistry()

	d.registerHealthCheckers()

	assert.Greater(t, d.healthRegistry.Count(), 0)
}

func TestRegisterHealthCheckersExtended_WithAllServers(t *testing.T) {
	config := testConfig("/tmp/test-reg-health-all.sock")
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
	require.NoError(t, err)

	d.caService = &CAGRPCService{logger: logging.DefaultLogger()}
	d.healthRegistry = health.NewRegistry()

	d.registerHealthCheckers()

	assert.GreaterOrEqual(t, d.healthRegistry.Count(), 2)
}

// =============================================================================
// ForceStop() - Extended Coverage Tests
// =============================================================================

func TestForceStopExtended_WithoutOptionalServices(t *testing.T) {
	config := testConfig("/tmp/test-forcestop-no-opt.sock")

	d, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	err = d.ForceStop()
	if err != nil && err.Error() != "server is not running" {
		t.Errorf("ForceStop() unexpected error: %v", err)
	}
}

func TestForceStopExtended_WithGRPCServer(t *testing.T) {
	config := testConfig("/tmp/test-forcestop-grpc.sock")
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	assert.NotNil(t, d.grpcServer)

	err = d.ForceStop()
	if err != nil && err.Error() != "server is not running" {
		t.Errorf("ForceStop() unexpected error: %v", err)
	}
}

func TestForceStopExtended_WithGRPCListenerClosed(t *testing.T) {
	config := testConfig("/tmp/test-forcestop-grpc-closed.sock")
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	if d.grpcListener != nil {
		_ = d.grpcListener.Close()
		d.grpcListener = nil
	}

	err = d.ForceStop()
	if err != nil && err.Error() != "server is not running" {
		t.Errorf("ForceStop() unexpected error: %v", err)
	}
}

func TestForceStopExtended_AllServersNil(t *testing.T) {
	config := testConfig("/tmp/test-forcestop-all-nil.sock")

	d, err := New(config)
	require.NoError(t, err)

	d.restServer = nil
	d.mcpServer = nil
	d.quicServer = nil
	d.grpcServer = nil
	d.grpcListener = nil

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	err = d.ForceStop()
	if err != nil && err.Error() != "server is not running" {
		t.Errorf("ForceStop() unexpected error: %v", err)
	}
}

// =============================================================================
// QUICListenAddr() - Extended Coverage Tests
// =============================================================================

func TestQUICListenAddrExtended_WithEmptyAddr(t *testing.T) {
	config := testConfig("/tmp/test-quic-addr-empty.sock")
	config.EnableQUIC = false
	config.QUICListenAddr = ""

	d, err := New(config)
	require.NoError(t, err)

	addr := d.QUICListenAddr()
	assert.Equal(t, "", addr)
}

func TestQUICListenAddrExtended_ServerNilWithConfigAddr(t *testing.T) {
	config := testConfig("/tmp/test-quic-addr-cfg.sock")
	config.EnableQUIC = false
	config.QUICListenAddr = "192.168.1.100:9444"

	d, err := New(config)
	require.NoError(t, err)

	assert.Nil(t, d.quicServer)

	addr := d.QUICListenAddr()
	assert.Equal(t, "192.168.1.100:9444", addr)
}

// =============================================================================
// createMCPServer() - Coverage Tests
// =============================================================================

func TestCreateMCPServerExtended_WithNilConfig(t *testing.T) {
	config := testConfig("/tmp/test-mcp-nil-cfg.sock")
	config.EnableMCP = true
	config.MCPConfig = nil

	d, err := New(config)
	require.NoError(t, err)

	assert.NotNil(t, d.mcpServer)
	assert.NotNil(t, d.mcpProvider)
}

func TestCreateMCPServerExtended_WithStdioTransport(t *testing.T) {
	config := testConfig("/tmp/test-mcp-stdio.sock")
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
	require.NoError(t, err)

	assert.NotNil(t, d.mcpServer)
	assert.NotNil(t, d.mcpProvider)
}

func TestCreateMCPServerExtended_WithHTTPTransport(t *testing.T) {
	config := testConfig("/tmp/test-mcp-http.sock")
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test-mcp-http",
		ServerVersion:         "1.0.0",
		Transport:             "http",
		HTTPAddr:              "127.0.0.1:0",
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}

	d, err := New(config)
	require.NoError(t, err)

	assert.NotNil(t, d.mcpServer)
	assert.NotNil(t, d.mcpProvider)
}

// =============================================================================
// Configuration Error Tests
// =============================================================================

func TestNewExtended_GRPCTLSFilesInvalid(t *testing.T) {
	config := testConfig("/tmp/test-new-grpc-tls-invalid.sock")
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"
	config.GRPCTLSCertFile = "/nonexistent/cert.pem"
	config.GRPCTLSKeyFile = "/nonexistent/key.pem"

	_, err := New(config)
	require.Error(t, err)
}

func TestNewExtended_RESTConfigInvalidTimeout(t *testing.T) {
	config := testConfig("/tmp/test-new-rest-invalid.sock")
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
	config.RESTConfig.ReadTimeout = -1 * time.Second

	_, err := New(config)
	require.Error(t, err)
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestDaemonExtended_IsRunning_Concurrent(t *testing.T) {
	config := testConfig("/tmp/test-isrunning-conc.sock")

	d, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = d.Start(ctx)
	require.NoError(t, err)

	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			_ = d.IsRunning()
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	_ = d.Stop(ctx)
}

func TestDaemonExtended_Accessors_Concurrent(t *testing.T) {
	config := testConfig("/tmp/test-accessors-conc.sock")
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
	require.NoError(t, err)

	done := make(chan bool, 50)
	for i := 0; i < 50; i++ {
		go func() {
			_ = d.SocketPath()
			_ = d.GRPCListenAddr()
			_ = d.RESTListenAddr()
			_ = d.MCPListenAddr()
			_ = d.QUICListenAddr()
			_ = d.IsRESTEnabled()
			_ = d.IsMCPEnabled()
			_ = d.IsQUICEnabled()
			_ = d.IsGRPCTCPEnabled()
			done <- true
		}()
	}

	for i := 0; i < 50; i++ {
		<-done
	}
}

func TestDaemonExtended_SetServices_Concurrent(t *testing.T) {
	config := testConfig("/tmp/test-set-svc-conc.sock")

	d, err := New(config)
	require.NoError(t, err)

	done := make(chan bool, 20)

	for i := 0; i < 10; i++ {
		go func() {
			d.SetCAGRPCService(&CAGRPCService{})
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		go func() {
			d.SetDeviceGRPCService(&DeviceGRPCService{})
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestDaemonExtended_HealthRegistry_Concurrent(t *testing.T) {
	config := testConfig("/tmp/test-health-conc.sock")

	d, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	done := make(chan bool, 30)

	for i := 0; i < 10; i++ {
		go func() {
			_, _ = d.HealthCheck(ctx)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		go func() {
			_, _ = d.HealthCheckComponent(ctx, "nonexistent")
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		go func(idx int) {
			svc := newMockService("concurrent-svc-" + string(rune('a'+idx)))
			checker := NewServiceHealthChecker(svc)
			_ = d.RegisterHealthChecker(checker)
			done <- true
		}(i)
	}

	for i := 0; i < 30; i++ {
		<-done
	}
}

// =============================================================================
// Default Logger Tests
// =============================================================================

func TestNewExtended_ServiceWithNilApp(t *testing.T) {
	config := testConfig("/tmp/test-new-nil-app.sock")
	config.App = nil

	d, err := New(config)
	require.NoError(t, err)

	assert.NotNil(t, d.service)
}

func TestNewExtended_MCPServerWithNilApp(t *testing.T) {
	config := testConfig("/tmp/test-mcp-nil-app.sock")
	config.EnableMCP = true
	config.MCPConfig = &MCPConfig{
		ServerName:            "test-mcp",
		ServerVersion:         "1.0.0",
		Transport:             "http",
		HTTPAddr:              "127.0.0.1:0",
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}
	config.App = nil

	d, err := New(config)
	require.NoError(t, err)

	assert.NotNil(t, d.mcpServer)
}

func TestNewExtended_QUICHandlerWithNilApp(t *testing.T) {
	config := testConfig("/tmp/test-quic-nil-app.sock")
	config.EnableQUIC = true
	config.QUICListenAddr = "127.0.0.1:0"
	config.App = nil

	d, err := New(config)
	require.NoError(t, err)

	assert.NotNil(t, d.config)
}
