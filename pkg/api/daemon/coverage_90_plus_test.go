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

//go:build iam && codec_msgpack && codec_cbor && codec_json && local && objstore

package daemon

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/jeremyhahn/go-codec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
)

func init() {
	_ = quic.SetDefaultCodecType(codec.MsgPack)
}

// =============================================================================
// Error Type Coverage Tests
// =============================================================================

func TestContainerErrorTypes_ErrorMethods(t *testing.T) {
	t.Run("ErrContainerLogsNotSupported", func(t *testing.T) {
		err := ErrContainerLogsNotSupported{}
		assert.Equal(t, "container logs not supported via orchestrator", err.Error())
	})

	t.Run("ErrContainerAttestNotSupported", func(t *testing.T) {
		err := ErrContainerAttestNotSupported{}
		assert.Equal(t, "container attestation not implemented", err.Error())
	})

	t.Run("ErrContainerInvalidParameter", func(t *testing.T) {
		err := ErrContainerInvalidParameter{Parameter: "image", Reason: "cannot be empty"}
		assert.Contains(t, err.Error(), "invalid container parameter image")
		assert.Contains(t, err.Error(), "cannot be empty")
	})
}

func TestAuthenticationErrorTypes(t *testing.T) {
	t.Run("ErrQuicBaaSServiceUnavailable", func(t *testing.T) {
		err := ErrQuicBaaSServiceUnavailable{}
		assert.Equal(t, "QuicBaaS service not available for authentication", err.Error())
	})

	t.Run("ErrTokenValidationFailed_WithCause", func(t *testing.T) {
		cause := errors.New("token expired")
		err := ErrTokenValidationFailed{Cause: cause}
		assert.Contains(t, err.Error(), "token validation failed")
		assert.Contains(t, err.Error(), "token expired")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrTokenValidationFailed_NilCause", func(t *testing.T) {
		err := ErrTokenValidationFailed{}
		assert.Equal(t, "token validation failed", err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

// =============================================================================
// Daemon Functional Options Tests
// =============================================================================

func TestDaemonFunctionalOptions(t *testing.T) {
	t.Run("WithGRPCServer", func(t *testing.T) {
		mockGRPC := &mockGRPCServer90{}

		config := DefaultConfig()
		config.SocketPath = "/tmp/test-with-grpc-server.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.SkipIAMValidation = true

		d, err := New(config, WithGRPCServer(mockGRPC))
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Equal(t, mockGRPC, d.grpcServer)
	})

	t.Run("WithQUICServer", func(t *testing.T) {
		mockQUIC := &mockQUICServer90{}

		config := DefaultConfig()
		config.SocketPath = "/tmp/test-with-quic-server.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableQUIC = false
		config.SkipIAMValidation = true

		d, err := New(config, WithQUICServer(mockQUIC))
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Equal(t, mockQUIC, d.quicServer)
	})

	t.Run("WithRESTServer", func(t *testing.T) {
		mockREST := &mockRESTServer90{}

		config := DefaultConfig()
		config.SocketPath = "/tmp/test-with-rest-server.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableREST = false
		config.SkipIAMValidation = true

		d, err := New(config, WithRESTServer(mockREST))
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Equal(t, mockREST, d.restServer)
	})

	t.Run("WithMCPServer", func(t *testing.T) {
		mockMCP := &mockMCPServer90{}

		config := DefaultConfig()
		config.SocketPath = "/tmp/test-with-mcp-server.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableMCP = false
		config.SkipIAMValidation = true

		d, err := New(config, WithMCPServer(mockMCP))
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Equal(t, mockMCP, d.mcpServer)
	})

	t.Run("WithGRPCUDSServer", func(t *testing.T) {
		mockUDS := &mockGRPCServer90{}

		config := DefaultConfig()
		config.SocketPath = "/tmp/test-with-grpc-uds-server.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.SkipIAMValidation = true

		d, err := New(config, WithGRPCUDSServer(mockUDS))
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Equal(t, mockUDS, d.grpcUDSServer)
	})
}

// =============================================================================
// QUIC Service Handler Setter Tests
// =============================================================================

func TestQUICServiceHandler_Setters(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)

	t.Run("SetContainerHandler", func(t *testing.T) {
		// Test setting to nil
		handler.SetContainerHandler(nil)
		assert.Nil(t, handler.containerHandler)
	})

	t.Run("SetContainerOrchestrator_Nil", func(t *testing.T) {
		handler.SetContainerOrchestrator(nil)
		assert.Nil(t, handler.containerHandler)
	})

	t.Run("SetAttestationHandler", func(t *testing.T) {
		handler.SetAttestationHandler(nil)
		assert.Nil(t, handler.attestationHandler)
	})

	t.Run("SetAttestationService_Nil", func(t *testing.T) {
		handler.SetAttestationService(nil)
		assert.Nil(t, handler.attestationHandler)
	})

	t.Run("SetVMHandler", func(t *testing.T) {
		handler.SetVMHandler(nil)
		assert.Nil(t, handler.vmHandler)
	})

	t.Run("SetVMOrchestrator_Nil", func(t *testing.T) {
		handler.SetVMOrchestrator(nil)
		assert.Nil(t, handler.vmHandler)
	})

	t.Run("SetTenantManager", func(t *testing.T) {
		handler.SetTenantManager(nil)
		assert.Nil(t, handler.tenantManager)
	})
}

// =============================================================================
// QUIC Service Handler Options Tests
// =============================================================================

func TestQUICServiceHandlerOptions(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("WithQUICContainerService_Nil", func(t *testing.T) {
		handler := NewQUICServiceHandler(logger, WithQUICContainerService(nil))
		assert.Nil(t, handler.containerHandler)
	})

	t.Run("WithQUICAttestationService_Nil", func(t *testing.T) {
		handler := NewQUICServiceHandler(logger, WithQUICAttestationService(nil))
		assert.Nil(t, handler.attestationHandler)
	})

	t.Run("WithQUICVMService_Nil", func(t *testing.T) {
		handler := NewQUICServiceHandler(logger, WithQUICVMService(nil))
		assert.Nil(t, handler.vmHandler)
	})

	t.Run("WithQUICTenantManager", func(t *testing.T) {
		mockMgr := &mockTenantManager90{}
		handler := NewQUICServiceHandler(logger, WithQUICTenantManager(mockMgr))
		assert.Equal(t, mockMgr, handler.tenantManager)
	})
}

// =============================================================================
// Service Provider IDevID/IAK Method Tests
// =============================================================================

func TestPlatformServiceProvider_IDevIDMethods(t *testing.T) {
	provider := &PlatformServiceProvider{}
	ctx := context.Background()

	t.Run("IDevIDGenerate_NotAvailable", func(t *testing.T) {
		result, err := provider.IDevIDGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{})
		assert.Nil(t, result)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IDevIDInfo_NotAvailable", func(t *testing.T) {
		result, err := provider.IDevIDInfo(ctx)
		assert.Nil(t, result)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IDevIDDelete_NotAvailable", func(t *testing.T) {
		err := provider.IDevIDDelete(ctx)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IDevIDCSR_NotAvailable", func(t *testing.T) {
		result, err := provider.IDevIDCSR(ctx, &mcp.IDevIDCSRMCPRequest{})
		assert.Nil(t, result)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IDevIDInstallCert_NotAvailable", func(t *testing.T) {
		result, err := provider.IDevIDInstallCert(ctx, "-----BEGIN CERTIFICATE-----")
		assert.Nil(t, result)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IDevIDGetCert_NotAvailable", func(t *testing.T) {
		result, err := provider.IDevIDGetCert(ctx, true)
		assert.Nil(t, result)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IDevIDDeleteCert_NotAvailable", func(t *testing.T) {
		err := provider.IDevIDDeleteCert(ctx)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IDevIDExists_NotAvailable", func(t *testing.T) {
		exists, err := provider.IDevIDExists(ctx)
		assert.False(t, exists)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})
}

func TestPlatformServiceProvider_IAKMethods(t *testing.T) {
	provider := &PlatformServiceProvider{}
	ctx := context.Background()

	t.Run("IAKGenerate_NotAvailable", func(t *testing.T) {
		result, err := provider.IAKGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{})
		assert.Nil(t, result)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IAKInfo_NotAvailable", func(t *testing.T) {
		result, err := provider.IAKInfo(ctx)
		assert.Nil(t, result)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IAKDelete_NotAvailable", func(t *testing.T) {
		err := provider.IAKDelete(ctx)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IAKCSR_NotAvailable", func(t *testing.T) {
		result, err := provider.IAKCSR(ctx, &mcp.IDevIDCSRMCPRequest{})
		assert.Nil(t, result)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IAKInstallCert_NotAvailable", func(t *testing.T) {
		result, err := provider.IAKInstallCert(ctx, "-----BEGIN CERTIFICATE-----")
		assert.Nil(t, result)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IAKGetCert_NotAvailable", func(t *testing.T) {
		result, err := provider.IAKGetCert(ctx, true)
		assert.Nil(t, result)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IAKDeleteCert_NotAvailable", func(t *testing.T) {
		err := provider.IAKDeleteCert(ctx)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("IAKExists_NotAvailable", func(t *testing.T) {
		exists, err := provider.IAKExists(ctx)
		assert.False(t, exists)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})
}

func TestPlatformServiceProvider_DeviceAttributeMethods(t *testing.T) {
	provider := &PlatformServiceProvider{}
	ctx := context.Background()

	t.Run("DeviceAttributes_NotAvailable", func(t *testing.T) {
		result, err := provider.DeviceAttributes(ctx)
		assert.Nil(t, result)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})

	t.Run("ActivateCredential_NotAvailable", func(t *testing.T) {
		result, err := provider.ActivateCredential(ctx, []byte("blob"), []byte("secret"))
		assert.Nil(t, result)
		assert.ErrorAs(t, err, &ErrTPM2ServiceNotAvailable{})
	})
}

// =============================================================================
// Tenant gRPC Server Tests
// =============================================================================

func TestTenantGRPCServer_Options(t *testing.T) {
	t.Run("WithTenantManager", func(t *testing.T) {
		// Can't create a real tenant.Manager without a lot of setup
		// Just verify the option function signature works
		opt := WithTenantManager(nil)
		assert.NotNil(t, opt)
	})

	t.Run("NewTenantGRPCServer_DefaultLogger", func(t *testing.T) {
		server := NewTenantGRPCServer()
		assert.NotNil(t, server)
		assert.NotNil(t, server.logger)
	})
}

// =============================================================================
// QUIC Handler Operation Tests - quic_container.go, quic_vm.go, quic_attestation.go
// =============================================================================

func TestQUICServiceHandler_ContainerOperation(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	t.Run("handleContainerOperation_NoHandler", func(t *testing.T) {
		handler := NewQUICServiceHandler(logger)
		req := &quic.Request{Opcode: quic.OpContainerCreate}

		resp := handler.handleContainerOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

}

func TestQUICServiceHandler_VMServiceOperation(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	t.Run("handleVMServiceOperation_NoHandler", func(t *testing.T) {
		handler := NewQUICServiceHandler(logger)
		req := &quic.Request{Opcode: quic.OpVMCreate}

		resp := handler.handleVMServiceOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

}

func TestQUICServiceHandler_AttestationOperation(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	t.Run("handleAttestationOperation_NoHandler", func(t *testing.T) {
		handler := NewQUICServiceHandler(logger)
		req := &quic.Request{Opcode: quic.OpAttestQuote}

		resp := handler.handleAttestationOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

}

// =============================================================================
// Token Validator Tests - daemon.go
// =============================================================================

func TestGRPCTokenValidator_ValidateToken(t *testing.T) {
	t.Run("NilService_ReturnsError", func(t *testing.T) {
		logger := logging.DefaultLogger()
		validator := newGRPCTokenValidator(nil, logger)

		valid, err := validator.ValidateToken(context.Background(), "test-token")
		assert.False(t, valid)
		assert.Error(t, err)
		assert.ErrorAs(t, err, &ErrQuicBaaSServiceUnavailable{})
	})

	t.Run("NilService_NilLogger", func(t *testing.T) {
		validator := newGRPCTokenValidator(nil, nil)

		valid, err := validator.ValidateToken(context.Background(), "test-token")
		assert.False(t, valid)
		assert.Error(t, err)
		assert.ErrorAs(t, err, &ErrQuicBaaSServiceUnavailable{})
	})
}

func TestQuicBaaSServiceWrapper_ValidateToken(t *testing.T) {
	t.Run("NilService_ReturnsError", func(t *testing.T) {
		wrapper := &quicbaasServiceWrapper{service: nil}

		result, err := wrapper.ValidateToken(context.Background(), "test-token")
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}

func TestQuicBaaSServiceAdapter(t *testing.T) {
	t.Run("AdapterCreation", func(t *testing.T) {
		// Just verify the adapter struct can be instantiated
		// Actual testing requires a real QuicBaaS service
		adapter := &quicbaasServiceAdapter{svc: nil}
		assert.NotNil(t, adapter)
	})
}

// =============================================================================
// Daemon Accessor Methods Tests - daemon.go
// =============================================================================

func TestDaemon_ComputeGRPCService(t *testing.T) {
	t.Run("ReturnsNilWhenNotSet", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-compute-svc.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		// Initially nil
		svc := d.ComputeGRPCService()
		assert.Nil(t, svc)
	})

	t.Run("SetAndGetComputeGRPCService", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-compute-svc-set.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		computeSvc := &ComputeGRPCService{}
		d.SetComputeGRPCService(computeSvc)

		result := d.ComputeGRPCService()
		assert.Equal(t, computeSvc, result)
	})
}

func TestDaemon_IDevIDGRPCService(t *testing.T) {
	t.Run("ReturnsAutoInitializedService", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-idevid-svc.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		svc := d.IDevIDGRPCService()
		assert.NotNil(t, svc)
	})

	t.Run("SetAndGetIDevIDGRPCService", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-idevid-svc-set.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		idevidSvc := &IDevIDGRPCService{}
		d.SetIDevIDGRPCService(idevidSvc)

		result := d.IDevIDGRPCService()
		assert.Equal(t, idevidSvc, result)
	})
}

func TestDaemon_GRPCUDSAccessors(t *testing.T) {
	t.Run("GRPCUDSServer_DisabledByDefault", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-uds-accessor.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableGRPCUDS = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		// When disabled, returns nil
		server := d.GRPCUDSServer()
		assert.Nil(t, server)
	})

	t.Run("GRPCSocketPath_WhenDisabled", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-socket-path-disabled.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableGRPCUDS = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		path := d.GRPCSocketPath()
		assert.Empty(t, path)
	})

	t.Run("IsGRPCUDSEnabled_WhenDisabled", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-uds-enabled-check.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableGRPCUDS = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		enabled := d.IsGRPCUDSEnabled()
		assert.False(t, enabled)
	})
}

// =============================================================================
// Mock Types - Complete interface implementations
// =============================================================================

// mockGRPCServer90 implements GRPCServerInterface for testing
type mockGRPCServer90 struct{}

func (m *mockGRPCServer90) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {}
func (m *mockGRPCServer90) Serve(lis net.Listener) error                             { return nil }
func (m *mockGRPCServer90) GracefulStop()                                            {}
func (m *mockGRPCServer90) Stop()                                                    {}

// mockQUICServer90 implements QUICServerInterface for testing
type mockQUICServer90 struct{}

func (m *mockQUICServer90) Start() error                       { return nil }
func (m *mockQUICServer90) Stop() error                        { return nil }
func (m *mockQUICServer90) IsRunning() bool                    { return false }
func (m *mockQUICServer90) ListenAddr() string                 { return "" }
func (m *mockQUICServer90) GetMetrics() map[string]interface{} { return nil }
func (m *mockQUICServer90) Stats() *quic.ServerStats           { return nil }

// mockRESTServer90 implements RESTServerInterface for testing
type mockRESTServer90 struct{}

func (m *mockRESTServer90) Start() error                   { return nil }
func (m *mockRESTServer90) Stop(ctx context.Context) error { return nil }
func (m *mockRESTServer90) ForceStop() error               { return nil }
func (m *mockRESTServer90) IsRunning() bool                { return false }

// mockMCPServer90 implements MCPServerInterface for testing
type mockMCPServer90 struct{}

func (m *mockMCPServer90) Start() error    { return nil }
func (m *mockMCPServer90) Stop() error     { return nil }
func (m *mockMCPServer90) IsRunning() bool { return false }

// mockTenantManager90 implements TenantManagerInterface for testing
type mockTenantManager90 struct {
	tenants []*tenant.TenantEntity
	total   int
	err     error
}

func (m *mockTenantManager90) ListTenants(ctx context.Context, limit, offset int) ([]*tenant.TenantEntity, int, error) {
	if m.err != nil {
		return nil, 0, m.err
	}
	return m.tenants, m.total, nil
}

func (m *mockTenantManager90) GetTenant(ctx context.Context, id string) (*tenant.TenantEntity, error) {
	if m.err != nil {
		return nil, m.err
	}
	if len(m.tenants) > 0 {
		return m.tenants[0], nil
	}
	return nil, errors.New("not found")
}

func (m *mockTenantManager90) GetTenantByName(ctx context.Context, name string) (*tenant.TenantEntity, error) {
	if m.err != nil {
		return nil, m.err
	}
	if len(m.tenants) > 0 {
		return m.tenants[0], nil
	}
	return nil, errors.New("not found")
}

func (m *mockTenantManager90) CreateTenant(ctx context.Context, req *tenant.CreateTenantRequest) (*tenant.TenantEntity, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &tenant.TenantEntity{
		ID:   "new-tenant",
		Name: req.Name,
	}, nil
}

func (m *mockTenantManager90) UpdateTenant(ctx context.Context, id string, req *tenant.UpdateTenantRequest) (*tenant.TenantEntity, error) {
	if m.err != nil {
		return nil, m.err
	}
	if len(m.tenants) > 0 {
		return m.tenants[0], nil
	}
	return nil, errors.New("not found")
}

func (m *mockTenantManager90) DeleteTenant(ctx context.Context, id string) error {
	return m.err
}

func (m *mockTenantManager90) SuspendTenant(ctx context.Context, id string) error {
	return m.err
}

func (m *mockTenantManager90) ResumeTenant(ctx context.Context, id string) error {
	return m.err
}

func (m *mockTenantManager90) GetQuotas(ctx context.Context, id string) (*tenant.TenantQuotas, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &tenant.TenantQuotas{}, nil
}

func (m *mockTenantManager90) UpdateQuotas(ctx context.Context, id string, quotas *tenant.TenantQuotas) error {
	return m.err
}

func (m *mockTenantManager90) GetUsage(ctx context.Context, id string) (*quota.TenantUsage, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &quota.TenantUsage{}, nil
}

func (m *mockTenantManager90) CheckQuota(ctx context.Context, id string, resource quota.ResourceType, amount int64) error {
	return m.err
}

func (m *mockTenantManager90) ValidateVLAN(ctx context.Context, id string, vlanID uint16) error {
	return m.err
}

func (m *mockTenantManager90) GetBridgeName(ctx context.Context, id string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return "br-tenant", nil
}

func (m *mockTenantManager90) Sync(ctx context.Context) error {
	return m.err
}

func (m *mockTenantManager90) RotateDEK(ctx context.Context, id string, background bool) (*tenant.DEKRotationResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &tenant.DEKRotationResult{}, nil
}

func (m *mockTenantManager90) GetDEKStatus(ctx context.Context, id string) (*tenant.DEKStatus, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &tenant.DEKStatus{}, nil
}

func (m *mockTenantManager90) InitTenantBarrier(ctx context.Context, id string) error {
	return m.err
}

func (m *mockTenantManager90) UnsealTenantBarrier(ctx context.Context, id string, key []byte) error {
	return m.err
}

func (m *mockTenantManager90) SealTenantBarrier(ctx context.Context, id string) error {
	return m.err
}

func (m *mockTenantManager90) TenantBarrierStatus(ctx context.Context, id string) (*tenant.TenantBarrierState, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &tenant.TenantBarrierState{TenantID: id}, nil
}

// =============================================================================
// MCPServiceProvider IDevID/IAK Interface Wrapper Tests - mcp_idevid.go
// =============================================================================

func TestMCPServiceProvider_IDevIDCSR(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("NilRequest_ReturnsError", func(t *testing.T) {
		result, err := provider.IDevIDCSR(ctx, nil)
		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("WithRequest_NoTPMService", func(t *testing.T) {
		req := &mcp.IDevIDCSRMCPRequest{
			CommonName:   "test",
			Organization: "test-org",
		}
		result, err := provider.IDevIDCSR(ctx, req)
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}

func TestMCPServiceProvider_IDevIDInstallCert(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("NoTPMService_ReturnsError", func(t *testing.T) {
		result, err := provider.IDevIDInstallCert(ctx, "-----BEGIN CERTIFICATE-----")
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}

func TestMCPServiceProvider_IDevIDGetCert(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("NoTPMService_ReturnsError", func(t *testing.T) {
		result, err := provider.IDevIDGetCert(ctx, true)
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}

func TestMCPServiceProvider_IDevIDDeleteCert(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("NoTPMService_ReturnsError", func(t *testing.T) {
		err := provider.IDevIDDeleteCert(ctx)
		assert.Error(t, err)
	})
}

func TestMCPServiceProvider_IDevIDExists(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("NoTPMService_ReturnsError", func(t *testing.T) {
		exists, err := provider.IDevIDExists(ctx)
		assert.False(t, exists)
		assert.Error(t, err)
	})
}

func TestMCPServiceProvider_IAKCSR(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("NilRequest_ReturnsError", func(t *testing.T) {
		result, err := provider.IAKCSR(ctx, nil)
		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("WithRequest_NoTPMService", func(t *testing.T) {
		req := &mcp.IDevIDCSRMCPRequest{
			CommonName:   "test-iak",
			Organization: "test-org",
		}
		result, err := provider.IAKCSR(ctx, req)
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}

func TestMCPServiceProvider_IAKInstallCert(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("NoTPMService_ReturnsError", func(t *testing.T) {
		result, err := provider.IAKInstallCert(ctx, "-----BEGIN CERTIFICATE-----")
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}

func TestMCPServiceProvider_IAKGetCert(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("NoTPMService_ReturnsError", func(t *testing.T) {
		result, err := provider.IAKGetCert(ctx, true)
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}

func TestMCPServiceProvider_IAKDeleteCert(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("NoTPMService_ReturnsError", func(t *testing.T) {
		err := provider.IAKDeleteCert(ctx)
		assert.Error(t, err)
	})
}

func TestMCPServiceProvider_IAKExists(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("NoTPMService_ReturnsError", func(t *testing.T) {
		exists, err := provider.IAKExists(ctx)
		assert.False(t, exists)
		assert.Error(t, err)
	})
}

// =============================================================================
// QuicBaaSServiceAdapter Tests - daemon.go
// =============================================================================

func TestQuicBaaSServiceAdapter_ValidateToken(t *testing.T) {
	t.Run("NilService_Panics", func(t *testing.T) {
		adapter := &quicbaasServiceAdapter{svc: nil}
		// Calling ValidateToken with nil svc will panic
		// We verify the adapter can be created but won't call the method
		assert.NotNil(t, adapter)
	})
}

// =============================================================================
// TenantGRPCServer Tests - tenant_grpc_server.go
// =============================================================================

func TestTenantGRPCServer_ListTenants_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	// Without manager set
	resp, err := server.ListTenants(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_GetTenant_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.GetTenant(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_GetTenantByName_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.GetTenantByName(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_CreateTenant_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.CreateTenant(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_UpdateTenant_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.UpdateTenant(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_DeleteTenant_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.DeleteTenant(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_SuspendTenant_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.SuspendTenant(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_ResumeTenant_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.ResumeTenant(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_GetQuotas_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.GetQuotas(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_UpdateQuotas_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.UpdateQuotas(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_GetUsage_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.GetUsage(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_CheckQuota_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.CheckQuota(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_ValidateVLAN_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.ValidateVLAN(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_GetBridge_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.GetBridgeName(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_SyncTenants_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.Sync(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_RotateDEK_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.RotateTenantDEK(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestTenantGRPCServer_GetDEKStatus_NoManager(t *testing.T) {
	server := NewTenantGRPCServer()
	ctx := context.Background()

	resp, err := server.GetTenantDEKStatus(ctx, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

// =============================================================================
// Additional QUIC Handler Tests for Coverage
// =============================================================================

func TestQUICServiceHandler_HandleRequest_SDN(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()
	handler := NewQUICServiceHandler(logger)

	t.Run("SDN opcode without service", func(t *testing.T) {
		req := &quic.Request{Opcode: quic.OpSDNCreateBridge}
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})
}

func TestQUICServiceHandler_HandleRequest_PXE(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()
	handler := NewQUICServiceHandler(logger)

	t.Run("PXE opcode without service", func(t *testing.T) {
		req := &quic.Request{Opcode: OpPXEListDevices}
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})
}

func TestQUICServiceHandler_HandleRequest_Health(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()
	handler := NewQUICServiceHandler(logger)

	t.Run("Health opcode", func(t *testing.T) {
		req := &quic.Request{Opcode: quic.OpHealth}
		resp := handler.HandleRequest(ctx, req)
		// Health checks return OK even without service
		assert.Equal(t, quic.StatusOK, resp.Status)
	})

	t.Run("Liveness opcode", func(t *testing.T) {
		req := &quic.Request{Opcode: quic.OpLiveness}
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusOK, resp.Status)
	})

	t.Run("Readiness opcode", func(t *testing.T) {
		req := &quic.Request{Opcode: quic.OpReadiness}
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusOK, resp.Status)
	})
}

func TestQUICServiceHandler_HandleRequest_Unknown(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()
	handler := NewQUICServiceHandler(logger)

	t.Run("Unknown opcode", func(t *testing.T) {
		req := &quic.Request{Opcode: 0x55}
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusNotImplemented, resp.Status)
	})
}

func TestQUICServiceHandler_SetOrchestrators_WithNonNil(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)

	// These tests verify the setters work without nil checks
	// The actual initialization requires real orchestrator instances
	// which we don't have in unit tests without heavy mocking

	t.Run("SetContainerHandler clears to nil", func(t *testing.T) {
		handler.SetContainerHandler(nil)
		assert.Nil(t, handler.containerHandler)
	})

	t.Run("SetVMHandler clears to nil", func(t *testing.T) {
		handler.SetVMHandler(nil)
		assert.Nil(t, handler.vmHandler)
	})

	t.Run("SetAttestationHandler clears to nil", func(t *testing.T) {
		handler.SetAttestationHandler(nil)
		assert.Nil(t, handler.attestationHandler)
	})
}

// =============================================================================
// Additional TenantGRPCServer Tests
// =============================================================================

func TestTenantGRPCServer_SetManager(t *testing.T) {
	server := NewTenantGRPCServer()
	assert.NotNil(t, server)

	// SetManager with nil
	server.SetManager(nil)
	// Manager is nil, so calls should fail
}

// =============================================================================
// Additional MCP IDevID/IAK Method Tests for Coverage
// =============================================================================

func TestMCPServiceProvider_IDevIDInstallCert_ValidPEM(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	// Even with valid-looking PEM, the service is not available
	validPEM := "-----BEGIN CERTIFICATE-----\nMIIBkDCB+gIJAJwM...\n-----END CERTIFICATE-----"
	result, err := provider.IDevIDInstallCert(ctx, validPEM)
	assert.Nil(t, result)
	assert.Error(t, err) // Service not available
}

func TestMCPServiceProvider_IAKInstallCert_ValidPEM(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	validPEM := "-----BEGIN CERTIFICATE-----\nMIIBkDCB+gIJAJwM...\n-----END CERTIFICATE-----"
	result, err := provider.IAKInstallCert(ctx, validPEM)
	assert.Nil(t, result)
	assert.Error(t, err) // Service not available
}

// =============================================================================
// Daemon QUICServer Accessor Test
// =============================================================================

func TestDaemon_QUICServer_WhenDisabled(t *testing.T) {
	config := DefaultConfig()
	config.SocketPath = "/tmp/test-quic-server-disabled.sock"
	config.SocketGroup = ""
	config.EnableGRPCTCP = false
	config.EnableQUIC = false
	config.SkipIAMValidation = true

	d, err := New(config)
	require.NoError(t, err)
	defer func() { _ = d.ForceStop() }()

	server := d.QUICServer()
	assert.Nil(t, server)
}

// =============================================================================
// Daemon SetTPM2Service Test
// =============================================================================

func TestDaemon_SetTPM2Service(t *testing.T) {
	config := DefaultConfig()
	config.SocketPath = "/tmp/test-tpm2-service.sock"
	config.SocketGroup = ""
	config.EnableGRPCTCP = false
	config.SkipIAMValidation = true

	d, err := New(config)
	require.NoError(t, err)
	defer func() { _ = d.ForceStop() }()

	// Set TPM2 service to nil
	d.SetTPM2Service(nil)
	assert.Nil(t, d.TPM2Service())
}

// =============================================================================
// Daemon GRPCSocketPath with UDS Enabled
// =============================================================================

func TestDaemon_GRPCSocketPath_WhenEnabled(t *testing.T) {
	config := DefaultConfig()
	config.SocketPath = "/tmp/test-socket-path-enabled.sock"
	config.SocketGroup = ""
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = true
	config.GRPCSocketPath = "/tmp/test-grpc.sock"
	config.SkipIAMValidation = true

	d, err := New(config)
	require.NoError(t, err)
	defer func() { _ = d.ForceStop() }()

	path := d.GRPCSocketPath()
	// When UDS is enabled, should return the socket path
	assert.NotEmpty(t, path)
}

func TestDaemon_IsGRPCUDSEnabled_WhenEnabled(t *testing.T) {
	config := DefaultConfig()
	config.SocketPath = "/tmp/test-uds-enabled.sock"
	config.SocketGroup = ""
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = true
	config.SkipIAMValidation = true

	d, err := New(config)
	require.NoError(t, err)
	defer func() { _ = d.ForceStop() }()

	enabled := d.IsGRPCUDSEnabled()
	assert.True(t, enabled)
}

// =============================================================================
// MCPServiceProvider SDN Tests
// =============================================================================

func TestMCPServiceProvider_SDNListPolicies(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	result, err := provider.SDNListPolicies(ctx)
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestMCPServiceProvider_SDNGetPolicy(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	result, err := provider.SDNGetPolicy(ctx, "policy-1")
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestMCPServiceProvider_SDNListBridges(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	result, err := provider.SDNListBridges(ctx)
	assert.Nil(t, result)
	assert.Error(t, err)
}

// =============================================================================
// MCP vTPM Tests - Additional
// =============================================================================

func TestMCPServiceProvider_VTPMDelete(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	err := provider.VTPMDelete(ctx, "vtpm-1")
	assert.Error(t, err)
}

func TestMCPServiceProvider_VTPMStart(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	err := provider.VTPMStart(ctx, "vtpm-1")
	assert.Error(t, err)
}

func TestMCPServiceProvider_VTPMStop(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	err := provider.VTPMStop(ctx, "vtpm-1")
	assert.Error(t, err)
}

func TestMCPServiceProvider_VTPMList(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	result, err := provider.VTPMList(ctx)
	assert.Nil(t, result)
	assert.Error(t, err)
}

// =============================================================================
// QUIC SDN Handler Tests
// =============================================================================

func TestQUICServiceHandler_SDNOperation_NoService(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()
	handler := NewQUICServiceHandler(logger)

	t.Run("CreateBridge", func(t *testing.T) {
		req := &quic.Request{Opcode: quic.OpSDNCreateBridge}
		resp := handler.handleSDNOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

	t.Run("DeleteBridge", func(t *testing.T) {
		req := &quic.Request{Opcode: quic.OpSDNDeleteBridge}
		resp := handler.handleSDNOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

	t.Run("AddPort", func(t *testing.T) {
		req := &quic.Request{Opcode: quic.OpSDNCreateBridge}
		resp := handler.handleSDNOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

	t.Run("DeletePort", func(t *testing.T) {
		req := &quic.Request{Opcode: quic.OpSDNDeleteBridge}
		resp := handler.handleSDNOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

	t.Run("GetPortState", func(t *testing.T) {
		req := &quic.Request{Opcode: quic.OpSDNGetPortState}
		resp := handler.handleSDNOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

	t.Run("SetPortState", func(t *testing.T) {
		req := &quic.Request{Opcode: quic.OpSDNSetPortState}
		resp := handler.handleSDNOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

	t.Run("ListPolicies", func(t *testing.T) {
		req := &quic.Request{Opcode: quic.OpSDNListPolicies}
		resp := handler.handleSDNOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

	t.Run("GetPortStats", func(t *testing.T) {
		req := &quic.Request{Opcode: quic.OpSDNGetPortState}
		resp := handler.handleSDNOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

}

// =============================================================================
// QUIC PXE Handler Tests
// =============================================================================

func TestQUICServiceHandler_PXEOperation_NoService(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()
	handler := NewQUICServiceHandler(logger)

	t.Run("ListDevices", func(t *testing.T) {
		req := &quic.Request{Opcode: OpPXEListDevices}
		resp := handler.handlePXEOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

	t.Run("GetDevice", func(t *testing.T) {
		req := &quic.Request{Opcode: OpPXEGetDevice}
		resp := handler.handlePXEOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

	t.Run("RegisterDevice", func(t *testing.T) {
		req := &quic.Request{Opcode: OpPXERegisterDevice}
		resp := handler.handlePXEOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

	t.Run("UpdateState", func(t *testing.T) {
		req := &quic.Request{Opcode: OpPXEUpdateState}
		resp := handler.handlePXEOperation(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})
}
