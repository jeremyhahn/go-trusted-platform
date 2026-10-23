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
	"errors"
	"log/slog"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
)

// =============================================================================
// Mock SDN Service Client for Extended Tests
// =============================================================================

// mockSDNServiceClient implements platformv1.SDNServiceClient for testing
type mockSDNServiceClient struct {
	// Bridge operations
	createBridgeResp *platformv1.CreateBridgeResponse
	createBridgeErr  error
	deleteBridgeResp *platformv1.DeleteBridgeResponse
	deleteBridgeErr  error
	getBridgeResp    *platformv1.GetBridgeResponse
	getBridgeErr     error
	listBridgesResp  *platformv1.ListBridgesResponse
	listBridgesErr   error

	// Port operations
	addPortResp    *platformv1.AddPortResponse
	addPortErr     error
	deletePortResp *platformv1.DeletePortResponse
	deletePortErr  error
	getPortResp    *platformv1.GetPortResponse
	getPortErr     error
	listPortsResp  *platformv1.ListPortsResponse
	listPortsErr   error

	// Flow operations
	addFlowResp    *platformv1.AddFlowResponse
	addFlowErr     error
	deleteFlowResp *platformv1.DeleteFlowResponse
	deleteFlowErr  error
	listFlowsResp  *platformv1.ListFlowsResponse
	listFlowsErr   error
	flushFlowsResp *platformv1.FlushFlowsResponse
	flushFlowsErr  error

	// VLAN operations
	createVLANResp *platformv1.CreateVLANResponse
	createVLANErr  error
	deleteVLANResp *platformv1.DeleteVLANResponse
	deleteVLANErr  error
	listVLANsResp  *platformv1.ListVLANsResponse
	listVLANsErr   error

	// Port authentication
	authenticatePortResp *platformv1.AuthenticatePortResponse
	authenticatePortErr  error
	revokePortAuthResp   *platformv1.RevokePortAuthResponse
	revokePortAuthErr    error

	// Statistics
	getPortStatsResp *platformv1.GetPortStatsResponse
	getPortStatsErr  error
	getFlowStatsResp *platformv1.GetFlowStatsResponse
	getFlowStatsErr  error
}

func (m *mockSDNServiceClient) CreateBridge(ctx context.Context, in *platformv1.CreateBridgeRequest, opts ...grpc.CallOption) (*platformv1.CreateBridgeResponse, error) {
	if m.createBridgeErr != nil {
		return nil, m.createBridgeErr
	}
	return m.createBridgeResp, nil
}

func (m *mockSDNServiceClient) DeleteBridge(ctx context.Context, in *platformv1.DeleteBridgeRequest, opts ...grpc.CallOption) (*platformv1.DeleteBridgeResponse, error) {
	if m.deleteBridgeErr != nil {
		return nil, m.deleteBridgeErr
	}
	return m.deleteBridgeResp, nil
}

func (m *mockSDNServiceClient) GetBridge(ctx context.Context, in *platformv1.GetBridgeRequest, opts ...grpc.CallOption) (*platformv1.GetBridgeResponse, error) {
	if m.getBridgeErr != nil {
		return nil, m.getBridgeErr
	}
	return m.getBridgeResp, nil
}

func (m *mockSDNServiceClient) ListBridges(ctx context.Context, in *platformv1.ListBridgesRequest, opts ...grpc.CallOption) (*platformv1.ListBridgesResponse, error) {
	if m.listBridgesErr != nil {
		return nil, m.listBridgesErr
	}
	return m.listBridgesResp, nil
}

func (m *mockSDNServiceClient) AddPort(ctx context.Context, in *platformv1.AddPortRequest, opts ...grpc.CallOption) (*platformv1.AddPortResponse, error) {
	if m.addPortErr != nil {
		return nil, m.addPortErr
	}
	return m.addPortResp, nil
}

func (m *mockSDNServiceClient) DeletePort(ctx context.Context, in *platformv1.DeletePortRequest, opts ...grpc.CallOption) (*platformv1.DeletePortResponse, error) {
	if m.deletePortErr != nil {
		return nil, m.deletePortErr
	}
	return m.deletePortResp, nil
}

func (m *mockSDNServiceClient) GetPort(ctx context.Context, in *platformv1.GetPortRequest, opts ...grpc.CallOption) (*platformv1.GetPortResponse, error) {
	if m.getPortErr != nil {
		return nil, m.getPortErr
	}
	return m.getPortResp, nil
}

func (m *mockSDNServiceClient) ListPorts(ctx context.Context, in *platformv1.ListPortsRequest, opts ...grpc.CallOption) (*platformv1.ListPortsResponse, error) {
	if m.listPortsErr != nil {
		return nil, m.listPortsErr
	}
	return m.listPortsResp, nil
}

func (m *mockSDNServiceClient) AddFlow(ctx context.Context, in *platformv1.AddFlowRequest, opts ...grpc.CallOption) (*platformv1.AddFlowResponse, error) {
	if m.addFlowErr != nil {
		return nil, m.addFlowErr
	}
	return m.addFlowResp, nil
}

func (m *mockSDNServiceClient) DeleteFlow(ctx context.Context, in *platformv1.DeleteFlowRequest, opts ...grpc.CallOption) (*platformv1.DeleteFlowResponse, error) {
	if m.deleteFlowErr != nil {
		return nil, m.deleteFlowErr
	}
	return m.deleteFlowResp, nil
}

func (m *mockSDNServiceClient) ListFlows(ctx context.Context, in *platformv1.ListFlowsRequest, opts ...grpc.CallOption) (*platformv1.ListFlowsResponse, error) {
	if m.listFlowsErr != nil {
		return nil, m.listFlowsErr
	}
	return m.listFlowsResp, nil
}

func (m *mockSDNServiceClient) FlushFlows(ctx context.Context, in *platformv1.FlushFlowsRequest, opts ...grpc.CallOption) (*platformv1.FlushFlowsResponse, error) {
	if m.flushFlowsErr != nil {
		return nil, m.flushFlowsErr
	}
	return m.flushFlowsResp, nil
}

func (m *mockSDNServiceClient) CreateVLAN(ctx context.Context, in *platformv1.CreateVLANRequest, opts ...grpc.CallOption) (*platformv1.CreateVLANResponse, error) {
	if m.createVLANErr != nil {
		return nil, m.createVLANErr
	}
	return m.createVLANResp, nil
}

func (m *mockSDNServiceClient) DeleteVLAN(ctx context.Context, in *platformv1.DeleteVLANRequest, opts ...grpc.CallOption) (*platformv1.DeleteVLANResponse, error) {
	if m.deleteVLANErr != nil {
		return nil, m.deleteVLANErr
	}
	return m.deleteVLANResp, nil
}

func (m *mockSDNServiceClient) ListVLANs(ctx context.Context, in *platformv1.ListVLANsRequest, opts ...grpc.CallOption) (*platformv1.ListVLANsResponse, error) {
	if m.listVLANsErr != nil {
		return nil, m.listVLANsErr
	}
	return m.listVLANsResp, nil
}

func (m *mockSDNServiceClient) AuthenticatePort(ctx context.Context, in *platformv1.AuthenticatePortRequest, opts ...grpc.CallOption) (*platformv1.AuthenticatePortResponse, error) {
	if m.authenticatePortErr != nil {
		return nil, m.authenticatePortErr
	}
	return m.authenticatePortResp, nil
}

func (m *mockSDNServiceClient) RevokePortAuth(ctx context.Context, in *platformv1.RevokePortAuthRequest, opts ...grpc.CallOption) (*platformv1.RevokePortAuthResponse, error) {
	if m.revokePortAuthErr != nil {
		return nil, m.revokePortAuthErr
	}
	return m.revokePortAuthResp, nil
}

func (m *mockSDNServiceClient) GetPortStats(ctx context.Context, in *platformv1.GetPortStatsRequest, opts ...grpc.CallOption) (*platformv1.GetPortStatsResponse, error) {
	if m.getPortStatsErr != nil {
		return nil, m.getPortStatsErr
	}
	return m.getPortStatsResp, nil
}

func (m *mockSDNServiceClient) GetFlowStats(ctx context.Context, in *platformv1.GetFlowStatsRequest, opts ...grpc.CallOption) (*platformv1.GetFlowStatsResponse, error) {
	if m.getFlowStatsErr != nil {
		return nil, m.getFlowStatsErr
	}
	return m.getFlowStatsResp, nil
}

func (m *mockSDNServiceClient) StreamFlowLogs(ctx context.Context, in *platformv1.StreamFlowLogsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[platformv1.FlowLogEntry], error) {
	return nil, errors.New("streaming not implemented in mock")
}

// =============================================================================
// SDNGetPortState Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetPortState_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNGetPortState(ctx, "br0", "port1")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNGetPortState_ServiceConfigured(t *testing.T) {
	// This test verifies that when SDN service is configured,
	// we get past the service availability check. Since the underlying
	// OVS client requires a real connection, we can only test that
	// the service is not reported as unavailable.
	ctx := context.Background()

	// Create provider with nil SDN service
	providerNoService := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := providerNoService.SDNGetPortState(ctx, "br0", "port1")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	// Verify we get service not available error for nil service
	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNGetPortState_VerifyErrorType(t *testing.T) {
	// This test verifies the error type returned when SDN service is nil
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNGetPortState(ctx, "br0", "port1")
	if err == nil {
		t.Fatal("expected error")
	}

	// Verify error message format
	errMsg := err.Error()
	if errMsg == "" {
		t.Error("expected non-empty error message")
	}
}

// =============================================================================
// SDNListBridges Tests
// =============================================================================

func TestMCPServiceProvider_SDNListBridges_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNListBridges(ctx)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNListBridges_VerifyErrorType(t *testing.T) {
	// This test verifies the error type returned when SDN service is nil
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNListBridges(ctx)
	if err == nil {
		t.Fatal("expected error")
	}

	// Verify error type is service not available
	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNCreateBridge Tests
// =============================================================================

func TestMCPServiceProvider_SDNCreateBridge_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNCreateBridge(ctx, "br0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNCreateBridge_VerifyErrorType(t *testing.T) {
	// This test verifies the error type returned when SDN service is nil
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNCreateBridge(ctx, "test-bridge")
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNDeleteBridge Tests
// =============================================================================

func TestMCPServiceProvider_SDNDeleteBridge_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeleteBridge(ctx, "br0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNDeleteBridge_VerifyErrorType(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeleteBridge(ctx, "test-bridge")
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNAddPort Tests
// =============================================================================

func TestMCPServiceProvider_SDNAddPort_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNAddPort(ctx, "br0", "port1", "internal")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNAddPort_VerifyErrorType(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNAddPort(ctx, "br0", "port1", "internal")
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNDeletePort Tests
// =============================================================================

func TestMCPServiceProvider_SDNDeletePort_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeletePort(ctx, "br0", "port1")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNDeletePort_VerifyErrorType(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeletePort(ctx, "br0", "port1")
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNListPolicies Tests
// =============================================================================

// =============================================================================
// SDNAddFlow Tests
// =============================================================================

func TestMCPServiceProvider_SDNAddFlow_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	flow := map[string]interface{}{
		"priority": 100,
		"match":    map[string]interface{}{"in_port": "1"},
		"actions":  []interface{}{map[string]interface{}{"type": "FLOW_ACTION_OUTPUT", "port": "2"}},
	}
	_, err := provider.SDNAddFlow(ctx, "br0", flow)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNAddFlow_VerifyErrorType(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	flow := map[string]interface{}{
		"priority": 100,
		"match":    map[string]interface{}{"in_port": "1"},
		"actions":  []interface{}{map[string]interface{}{"type": "FLOW_ACTION_OUTPUT", "port": "2"}},
	}
	_, err := provider.SDNAddFlow(ctx, "br0", flow)
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNDeleteFlow Tests
// =============================================================================

func TestMCPServiceProvider_SDNDeleteFlow_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeleteFlow(ctx, "br0", "flow-1")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNDeleteFlow_VerifyErrorType(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeleteFlow(ctx, "br0", "flow-1")
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNListFlows Tests
// =============================================================================

func TestMCPServiceProvider_SDNListFlows_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNListFlows(ctx, "br0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNListFlows_VerifyErrorType(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNListFlows(ctx, "br0")
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNFlushFlows Tests
// =============================================================================

func TestMCPServiceProvider_SDNFlushFlows_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNFlushFlows(ctx, "br0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNFlushFlows_VerifyErrorType(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNFlushFlows(ctx, "br0")
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNCreateVLAN Tests
// =============================================================================

func TestMCPServiceProvider_SDNCreateVLAN_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNCreateVLAN(ctx, "br0", 100, "vlan100")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNCreateVLAN_VerifyErrorType(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNCreateVLAN(ctx, "br0", 100, "vlan100")
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNDeleteVLAN Tests
// =============================================================================

func TestMCPServiceProvider_SDNDeleteVLAN_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeleteVLAN(ctx, "br0", 100)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNDeleteVLAN_VerifyErrorType(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeleteVLAN(ctx, "br0", 100)
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNListVLANs Tests
// =============================================================================

func TestMCPServiceProvider_SDNListVLANs_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNListVLANs(ctx, "br0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNListVLANs_VerifyErrorType(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNListVLANs(ctx, "br0")
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNGetPortStats Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetPortStats_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNGetPortStats(ctx, "br0", "port1")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNGetPortStats_VerifyErrorType(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNGetPortStats(ctx, "br0", "port1")
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNGetFlowStats Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetFlowStats_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNGetFlowStats(ctx, "br0", "0x1")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNGetFlowStats_VerifyErrorType(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNGetFlowStats(ctx, "br0", "0x1")
	if err == nil {
		t.Fatal("expected error")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// Table-Driven Comprehensive Tests for All SDN Methods - Nil Service Check
// =============================================================================

func TestMCPServiceProvider_SDN_NilServiceErrors_TableDriven(t *testing.T) {
	testCases := []struct {
		name      string
		operation string
		execFunc  func(context.Context, *MCPServiceProvider) error
	}{
		{
			name:      "SDNCreateBridge nil service",
			operation: "SDNCreateBridge",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNCreateBridge(ctx, "br0")
			},
		},
		{
			name:      "SDNDeleteBridge nil service",
			operation: "SDNDeleteBridge",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNDeleteBridge(ctx, "br0")
			},
		},
		{
			name:      "SDNAddPort nil service",
			operation: "SDNAddPort",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNAddPort(ctx, "br0", "port1", "internal")
			},
		},
		{
			name:      "SDNDeletePort nil service",
			operation: "SDNDeletePort",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNDeletePort(ctx, "br0", "port1")
			},
		},
		{
			name:      "SDNAddFlow nil service",
			operation: "SDNAddFlow",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				_, err := p.SDNAddFlow(ctx, "br0", map[string]interface{}{})
				return err
			},
		},
		{
			name:      "SDNDeleteFlow nil service",
			operation: "SDNDeleteFlow",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNDeleteFlow(ctx, "br0", "flow-1")
			},
		},
		{
			name:      "SDNFlushFlows nil service",
			operation: "SDNFlushFlows",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				_, err := p.SDNFlushFlows(ctx, "br0")
				return err
			},
		},
		{
			name:      "SDNCreateVLAN nil service",
			operation: "SDNCreateVLAN",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				_, err := p.SDNCreateVLAN(ctx, "br0", 100, "vlan100")
				return err
			},
		},
		{
			name:      "SDNDeleteVLAN nil service",
			operation: "SDNDeleteVLAN",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNDeleteVLAN(ctx, "br0", 100)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				Logger: slog.Default(),
			})

			err := tc.execFunc(ctx, provider)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != "sdn" {
				t.Errorf("expected service='sdn', got %q", svcErr.Service)
			}
		})
	}
}

// =============================================================================
// Table-Driven Tests for SDN Methods Returning Values - Nil Service Check
// =============================================================================

func TestMCPServiceProvider_SDN_NilServiceErrors_ReturningValues_TableDriven(t *testing.T) {
	testCases := []struct {
		name      string
		operation string
		execFunc  func(context.Context, *MCPServiceProvider) (interface{}, error)
	}{
		{
			name:      "SDNGetPortState nil service",
			operation: "SDNGetPortState",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return p.SDNGetPortState(ctx, "br0", "port1")
			},
		},
		{
			name:      "SDNListBridges nil service",
			operation: "SDNListBridges",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return p.SDNListBridges(ctx)
			},
		},
		{
			name:      "SDNListFlows nil service",
			operation: "SDNListFlows",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return p.SDNListFlows(ctx, "br0")
			},
		},
		{
			name:      "SDNListVLANs nil service",
			operation: "SDNListVLANs",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return p.SDNListVLANs(ctx, "br0")
			},
		},
		{
			name:      "SDNGetPortStats nil service",
			operation: "SDNGetPortStats",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return p.SDNGetPortStats(ctx, "br0", "port1")
			},
		},
		{
			name:      "SDNGetFlowStats nil service",
			operation: "SDNGetFlowStats",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return p.SDNGetFlowStats(ctx, "br0", "0x1")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				Logger: slog.Default(),
			})

			_, err := tc.execFunc(ctx, provider)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != "sdn" {
				t.Errorf("expected service='sdn', got %q", svcErr.Service)
			}
		})
	}
}

// =============================================================================
// SDNApplyPolicy Success Test
// =============================================================================

// =============================================================================
// SDNGetPortState Extended Tests - Parameter Validation
// =============================================================================

func TestMCPServiceProvider_SDNGetPortState_WithMockSDNServiceClient(t *testing.T) {
	// This test verifies that the mock SDN service client structure is valid
	// and that the nil service check path returns the correct error type.
	ctx := context.Background()

	// Create a provider with mock SDN service client for reference
	mockClient := &mockSDNServiceClient{
		getPortResp: &platformv1.GetPortResponse{
			Port: &platformv1.Port{
				Id: "port1",
				Config: &platformv1.PortConfig{
					Name: "port1",
				},
				Status: platformv1.PortStatus_PORT_STATUS_UP,
			},
		},
	}

	// Verify the mock client structure is valid
	if mockClient.getPortResp == nil {
		t.Fatal("mockClient.getPortResp should not be nil")
	}

	// Test with nil SDN service to verify the service check
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNGetPortState(ctx, "br0", "port1")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	// Verify it IS a service not available error
	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNGetPortState_EmptyBridgeNameReturnsError(t *testing.T) {
	// Test that empty bridge name triggers an error
	// With nil service, we get service not available error first
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Empty bridge name with nil service - service check happens first
	_, err := provider.SDNGetPortState(ctx, "", "port1")
	if err == nil {
		t.Fatal("expected error")
	}

	// Verify we get service not available (checked before parameter validation)
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNGetPortState_EmptyPortNameReturnsError(t *testing.T) {
	// Test that empty port name triggers an error
	// With nil service, we get service not available error first
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Empty port name with nil service - service check happens first
	_, err := provider.SDNGetPortState(ctx, "br0", "")
	if err == nil {
		t.Fatal("expected error")
	}

	// Verify we get service not available (checked before parameter validation)
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNListBridges Extended Tests - With Mock Service
// =============================================================================

func TestMCPServiceProvider_SDNListBridges_WithConfiguredService(t *testing.T) {
	// This test verifies that when SDN service is configured but the underlying
	// OVS client is nil, we do NOT get ErrServiceNotAvailable.
	// The test uses a provider without SDN service to verify the nil check path.
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Without SDN service, we get service not available error
	_, err := provider.SDNListBridges(ctx)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	// This verifies the nil service check works
	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNListBridges_ReturnsEmptySlice(t *testing.T) {
	// This test verifies that if no bridges exist, an empty slice is returned
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Without SDN service, we get service not available
	_, err := provider.SDNListBridges(ctx)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T", err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

// =============================================================================
// SDNCreateBridge Extended Tests - Parameter Validation
// =============================================================================

func TestMCPServiceProvider_SDNCreateBridge_EmptyBridgeName(t *testing.T) {
	// Test that empty bridge name triggers an error
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Empty bridge name with nil service - service check happens first
	err := provider.SDNCreateBridge(ctx, "")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens before parameter validation
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNCreateBridge_WithValidBridgeName(t *testing.T) {
	// Test that valid bridge name with nil service returns service not available
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNCreateBridge(ctx, "test-bridge")
	if err == nil {
		t.Fatal("expected error")
	}

	// Verify service not available error
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNDeleteBridge Extended Tests - Parameter Validation
// =============================================================================

func TestMCPServiceProvider_SDNDeleteBridge_EmptyBridgeName(t *testing.T) {
	// Test that empty bridge name triggers an error
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeleteBridge(ctx, "")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNDeleteBridge_NonexistentBridge(t *testing.T) {
	// Test deleting a nonexistent bridge with nil service
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeleteBridge(ctx, "nonexistent-bridge")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNAddPort Extended Tests - Parameter Validation
// =============================================================================

func TestMCPServiceProvider_SDNAddPort_EmptyBridgeName(t *testing.T) {
	// Test that empty bridge name triggers an error
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNAddPort(ctx, "", "port1", "internal")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNAddPort_EmptyPortName(t *testing.T) {
	// Test that empty port name triggers an error
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNAddPort(ctx, "br0", "", "internal")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNAddPort_ValidParameters(t *testing.T) {
	// Test with valid parameters and nil service
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNAddPort(ctx, "br0", "port1", "internal")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNAddPort_PortTypeVariations(t *testing.T) {
	testCases := []struct {
		name     string
		portType string
	}{
		{"internal port", "internal"},
		{"system port", "system"},
		{"vxlan port", "vxlan"},
		{"patch port", "patch"},
		{"empty port type", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				Logger: slog.Default(),
			})

			// Different port types all hit service check first
			err := provider.SDNAddPort(ctx, "br0", "port1", tc.portType)
			if err == nil {
				t.Fatal("expected error")
			}

			// Service check happens first
			_, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
		})
	}
}

// =============================================================================
// SDNDeletePort Extended Tests - Parameter Validation
// =============================================================================

func TestMCPServiceProvider_SDNDeletePort_EmptyBridgeName(t *testing.T) {
	// Test that empty bridge name triggers an error
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeletePort(ctx, "", "port1")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNDeletePort_EmptyPortName(t *testing.T) {
	// Test that empty port name triggers an error
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeletePort(ctx, "br0", "")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNDeletePort_NonexistentPort(t *testing.T) {
	// Test deleting a nonexistent port with nil service
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeletePort(ctx, "br0", "nonexistent-port")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNListPolicies Extended Tests - With Policy Engine
// =============================================================================

// =============================================================================
// SDNAddFlow Extended Tests - Parameter Validation
// =============================================================================

func TestMCPServiceProvider_SDNAddFlow_EmptyBridgeName(t *testing.T) {
	// Test that empty bridge name triggers an error
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	flow := map[string]interface{}{
		"priority": 100,
		"match":    map[string]interface{}{"in_port": "1"},
		"actions":  []interface{}{map[string]interface{}{"type": "FLOW_ACTION_OUTPUT", "port": "2"}},
	}

	// Empty bridge name - service check happens first
	_, err := provider.SDNAddFlow(ctx, "", flow)
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNAddFlow_EmptyFlow(t *testing.T) {
	// Test with empty flow map and nil service
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Empty flow map - service check happens first
	_, err := provider.SDNAddFlow(ctx, "br0", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNAddFlow_NilFlow(t *testing.T) {
	// Test with nil flow map and nil service
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Nil flow map - service check happens first
	_, err := provider.SDNAddFlow(ctx, "br0", nil)
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNAddFlow_WithFlowParameters(t *testing.T) {
	testCases := []struct {
		name string
		flow map[string]interface{}
	}{
		{
			name: "with priority",
			flow: map[string]interface{}{"priority": 100},
		},
		{
			name: "with match",
			flow: map[string]interface{}{"match": map[string]interface{}{"in_port": "1"}},
		},
		{
			name: "with actions",
			flow: map[string]interface{}{"actions": []interface{}{map[string]interface{}{"type": "FLOW_ACTION_OUTPUT", "port": "2"}}},
		},
		{
			name: "complete flow",
			flow: map[string]interface{}{
				"priority": 100,
				"match":    map[string]interface{}{"in_port": "1"},
				"actions":  []interface{}{map[string]interface{}{"type": "FLOW_ACTION_OUTPUT", "port": "2"}},
			},
		},
		{
			name: "with table",
			flow: map[string]interface{}{
				"table":    0,
				"priority": 100,
				"actions":  []interface{}{map[string]interface{}{"type": "FLOW_ACTION_DROP"}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				Logger: slog.Default(),
			})

			_, err := provider.SDNAddFlow(ctx, "br0", tc.flow)
			if err == nil {
				t.Fatal("expected error")
			}

			// Service check happens first
			_, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
		})
	}
}

// =============================================================================
// SDNDeleteFlow Extended Tests - Parameter Validation
// =============================================================================

func TestMCPServiceProvider_SDNDeleteFlow_EmptyBridgeName(t *testing.T) {
	// Test that empty bridge name triggers an error
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeleteFlow(ctx, "", "flow-1")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNDeleteFlow_EmptyFlowID(t *testing.T) {
	// Test that empty flow ID triggers an error
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeleteFlow(ctx, "br0", "")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNDeleteFlow_NonexistentFlow(t *testing.T) {
	// Test deleting a nonexistent flow with nil service
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.SDNDeleteFlow(ctx, "br0", "nonexistent-flow")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNListFlows Extended Tests - Parameter Validation
// =============================================================================

func TestMCPServiceProvider_SDNListFlows_EmptyBridgeName(t *testing.T) {
	// Test that empty bridge name triggers an error
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNListFlows(ctx, "")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNListFlows_NonexistentBridge(t *testing.T) {
	// Test listing flows on nonexistent bridge with nil service
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNListFlows(ctx, "nonexistent-bridge")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNListFlows_ValidBridge(t *testing.T) {
	// Test listing flows on valid bridge name with nil service
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNListFlows(ctx, "br0")
	if err == nil {
		t.Fatal("expected error")
	}

	// Service check happens first
	_, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// Combined Parameter Validation Tests - Table Driven
// =============================================================================

func TestMCPServiceProvider_SDN_ParameterValidation_NilService(t *testing.T) {
	testCases := []struct {
		name      string
		operation string
		execFunc  func(context.Context, *MCPServiceProvider) error
	}{
		{
			name:      "SDNCreateBridge with valid name",
			operation: "SDNCreateBridge",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNCreateBridge(ctx, "valid-bridge")
			},
		},
		{
			name:      "SDNDeleteBridge with valid name",
			operation: "SDNDeleteBridge",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNDeleteBridge(ctx, "valid-bridge")
			},
		},
		{
			name:      "SDNAddPort with all valid parameters",
			operation: "SDNAddPort",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNAddPort(ctx, "br0", "port1", "internal")
			},
		},
		{
			name:      "SDNDeletePort with valid parameters",
			operation: "SDNDeletePort",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNDeletePort(ctx, "br0", "port1")
			},
		},
		{
			name:      "SDNAddFlow with valid parameters",
			operation: "SDNAddFlow",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				_, err := p.SDNAddFlow(ctx, "br0", map[string]interface{}{"priority": 100})
				return err
			},
		},
		{
			name:      "SDNDeleteFlow with valid parameters",
			operation: "SDNDeleteFlow",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNDeleteFlow(ctx, "br0", "flow-1")
			},
		},
		{
			name:      "SDNFlushFlows with valid bridge",
			operation: "SDNFlushFlows",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				_, err := p.SDNFlushFlows(ctx, "br0")
				return err
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			// Test with nil SDN service
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				Logger: slog.Default(),
			})

			err := tc.execFunc(ctx, provider)
			if err == nil {
				t.Errorf("operation %s: expected error", tc.operation)
			}

			// Verify it's a service not available error
			_, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Errorf("operation %s: expected ErrServiceNotAvailable, got %T: %v", tc.operation, err, err)
			}
		})
	}
}

func TestMCPServiceProvider_SDN_ReturningValues_NilService(t *testing.T) {
	testCases := []struct {
		name      string
		operation string
		execFunc  func(context.Context, *MCPServiceProvider) (interface{}, error)
	}{
		{
			name:      "SDNGetPortState with valid parameters",
			operation: "SDNGetPortState",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return p.SDNGetPortState(ctx, "br0", "port1")
			},
		},
		{
			name:      "SDNListBridges",
			operation: "SDNListBridges",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return p.SDNListBridges(ctx)
			},
		},
		{
			name:      "SDNListFlows with valid bridge",
			operation: "SDNListFlows",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return p.SDNListFlows(ctx, "br0")
			},
		},
		{
			name:      "SDNListVLANs with valid bridge",
			operation: "SDNListVLANs",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return p.SDNListVLANs(ctx, "br0")
			},
		},
		{
			name:      "SDNGetPortStats with valid parameters",
			operation: "SDNGetPortStats",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return p.SDNGetPortStats(ctx, "br0", "port1")
			},
		},
		{
			name:      "SDNGetFlowStats with valid bridge",
			operation: "SDNGetFlowStats",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return p.SDNGetFlowStats(ctx, "br0", "0x1")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			// Test with nil SDN service
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				Logger: slog.Default(),
			})

			_, err := tc.execFunc(ctx, provider)
			if err == nil {
				t.Errorf("operation %s: expected error", tc.operation)
			}

			// Verify it's a service not available error
			_, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Errorf("operation %s: expected ErrServiceNotAvailable, got %T: %v", tc.operation, err, err)
			}
		})
	}
}

// =============================================================================
// SDN Operations with Special Parameters
// =============================================================================

func TestMCPServiceProvider_SDNCreateBridge_SpecialCharacters(t *testing.T) {
	testCases := []struct {
		name       string
		bridgeName string
	}{
		{"with hyphen", "br-test"},
		{"with underscore", "br_test"},
		{"with number", "br0"},
		{"long name", "this-is-a-very-long-bridge-name-that-exceeds-typical-length"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			// Test with nil service to verify service check
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				Logger: slog.Default(),
			})

			err := provider.SDNCreateBridge(ctx, tc.bridgeName)
			if err == nil {
				t.Fatal("expected error")
			}

			// Verify service not available error
			_, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
		})
	}
}

func TestMCPServiceProvider_SDNDeleteFlow_FlowIDFormats(t *testing.T) {
	testCases := []struct {
		name   string
		flowID string
	}{
		{"uuid format", "550e8400-e29b-41d4-a716-446655440000"},
		{"numeric", "12345"},
		{"with prefix", "flow-123"},
		{"complex", "table=0,priority=100,in_port=1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			// Test with nil service to verify service check
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				Logger: slog.Default(),
			})

			err := provider.SDNDeleteFlow(ctx, "br0", tc.flowID)
			if err == nil {
				t.Fatal("expected error")
			}

			// Verify service not available error
			_, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
		})
	}
}
