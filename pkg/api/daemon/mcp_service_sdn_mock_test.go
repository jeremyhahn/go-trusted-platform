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
	"crypto/x509"
	"errors"
	"log/slog"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// =============================================================================
// Helper Functions
// =============================================================================

// createMCPTestSDNService creates an SDNService with a mock OVS client for testing
func createMCPTestSDNService(mockOVS *ConfigurableMockOVSClient) *SDNService {
	return &SDNService{
		ovsClient: mockOVS,
		bridges:   make(map[string]*bridgeResource),
		ports:     make(map[string]*portResource),
		taps:      make(map[string]*tapResource),
		vlans:     make(map[string]*vlanResource),
		portAuths: make(map[string]*portAuthResource),
	}
}

// mcpTestMockPolicyEngine implements policy.PolicyEngine for MCP SDN tests
type mcpTestMockPolicyEngine struct {
	// Policy storage
	policies map[string]*policy.PortPolicy
	// Port state storage
	portStates map[string]policy.PortState
	// Port info storage
	portInfos map[string]*policy.PortInfo

	// Error injection
	getPolicyErr     error
	applyPolicyErr   error
	getPortStateErr  error
	setPortStateErr  error
	getPortInfoErr   error
	getOFPortErr     error
	getPortVLANErr   error
	authenticateErr  error
	removePolicyErr  error
	blockPortErr     error
	unblockPortErr   error
	setPortVLANErr   error
	onCertExpiredErr error
	onCertRevokedErr error
}

func newMCPTestMockPolicyEngine() *mcpTestMockPolicyEngine {
	return &mcpTestMockPolicyEngine{
		policies:   make(map[string]*policy.PortPolicy),
		portStates: make(map[string]policy.PortState),
		portInfos:  make(map[string]*policy.PortInfo),
	}
}

func (m *mcpTestMockPolicyEngine) GetPolicy(portID string) (*policy.PortPolicy, error) {
	if m.getPolicyErr != nil {
		return nil, m.getPolicyErr
	}
	if p, ok := m.policies[portID]; ok {
		return p, nil
	}
	return nil, errors.New("policy not found")
}

func (m *mcpTestMockPolicyEngine) ApplyPolicy(portID string, pol *policy.PortPolicy) error {
	if m.applyPolicyErr != nil {
		return m.applyPolicyErr
	}
	m.policies[portID] = pol
	return nil
}

func (m *mcpTestMockPolicyEngine) RemovePolicy(portID string) error {
	if m.removePolicyErr != nil {
		return m.removePolicyErr
	}
	delete(m.policies, portID)
	return nil
}

func (m *mcpTestMockPolicyEngine) GetPortState(portID string) (policy.PortState, error) {
	if m.getPortStateErr != nil {
		return policy.PortStateUnconnected, m.getPortStateErr
	}
	if state, ok := m.portStates[portID]; ok {
		return state, nil
	}
	return policy.PortStateUnconnected, nil
}

func (m *mcpTestMockPolicyEngine) SetPortState(portID string, state policy.PortState) error {
	if m.setPortStateErr != nil {
		return m.setPortStateErr
	}
	m.portStates[portID] = state
	return nil
}

func (m *mcpTestMockPolicyEngine) GetPortInfo(portID string) (*policy.PortInfo, error) {
	if m.getPortInfoErr != nil {
		return nil, m.getPortInfoErr
	}
	if info, ok := m.portInfos[portID]; ok {
		return info, nil
	}
	return nil, errors.New("port info not found")
}

func (m *mcpTestMockPolicyEngine) GetOFPort(portID string) (int32, error) {
	if m.getOFPortErr != nil {
		return 0, m.getOFPortErr
	}
	return 1, nil
}

func (m *mcpTestMockPolicyEngine) GetPortVLAN(portID string) (uint16, error) {
	if m.getPortVLANErr != nil {
		return 0, m.getPortVLANErr
	}
	return 100, nil
}

func (m *mcpTestMockPolicyEngine) SetPortVLAN(portID string, vlan uint16) error {
	return m.setPortVLANErr
}

func (m *mcpTestMockPolicyEngine) BlockPort(portID string) error {
	return m.blockPortErr
}

func (m *mcpTestMockPolicyEngine) UnblockPort(portID string) error {
	return m.unblockPortErr
}

func (m *mcpTestMockPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	return m.authenticateErr
}

func (m *mcpTestMockPolicyEngine) OnCertificateExpired(portID string) error {
	return m.onCertExpiredErr
}

func (m *mcpTestMockPolicyEngine) OnCertificateRevoked(portID string) error {
	return m.onCertRevokedErr
}

func (m *mcpTestMockPolicyEngine) GetMonitor() *policy.CertificateMonitor {
	return nil
}

// =============================================================================
// SDNGetPortState Tests - With Mock SDN Service
// =============================================================================

func TestMCPServiceProvider_SDNGetPortState_Success(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnGetPort(func(ctx context.Context, name string) (*ovs.Port, error) {
		return &ovs.Port{
			UUID: "port-uuid-123",
			Name: name,
		}, nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	// Pre-populate ports map for GetPort lookup
	sdnService.ports["port1"] = &portResource{
		id:       "port-uuid-123",
		name:     "port1",
		bridgeID: "br0",
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	result, err := provider.SDNGetPortState(ctx, "br0", "port1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestMCPServiceProvider_SDNGetPortState_ServiceError(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	expectedErr := errors.New("OVS connection failed")
	mockOVS.OnGetPort(func(ctx context.Context, name string) (*ovs.Port, error) {
		return nil, expectedErr
	})

	sdnService := createMCPTestSDNService(mockOVS)
	// Pre-populate ports map so we get past the lookup check
	sdnService.ports["port1"] = &portResource{
		id:       "port-uuid-123",
		name:     "port1",
		bridgeID: "br0",
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	_, err := provider.SDNGetPortState(ctx, "br0", "port1")
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

func TestMCPServiceProvider_SDNGetPortState_VariousInputs(t *testing.T) {
	testCases := []struct {
		name       string
		bridgeName string
		portName   string
	}{
		{"standard_input", "br0", "eth0"},
		{"long_names", "my-long-bridge-name", "my-long-port-name"},
		{"underscores", "br_int", "port_1"},
		{"mixed_case", "BrInt", "Port1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockOVS := NewConfigurableMockOVSClient()
			mockOVS.OnGetPort(func(ctx context.Context, name string) (*ovs.Port, error) {
				return &ovs.Port{UUID: "uuid-" + name, Name: name}, nil
			})

			sdnService := createMCPTestSDNService(mockOVS)
			// Pre-populate port for lookup
			sdnService.ports[tc.portName] = &portResource{
				id:       "uuid-" + tc.portName,
				name:     tc.portName,
				bridgeID: tc.bridgeName,
			}

			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: sdnService,
				Logger:     slog.Default(),
			})

			result, err := provider.SDNGetPortState(ctx, tc.bridgeName, tc.portName)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
		})
	}
}

// =============================================================================
// SDNListBridges Tests - With Mock SDN Service
// =============================================================================

func TestMCPServiceProvider_SDNListBridges_Success_EmptyList(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return []*ovs.Bridge{}, nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	result, err := provider.SDNListBridges(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result) != 0 {
		t.Errorf("expected empty list, got %d items", len(result))
	}
}

func TestMCPServiceProvider_SDNListBridges_Success_MultipleBridges(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return []*ovs.Bridge{
			{UUID: "br0-uuid", Name: "br0"},
			{UUID: "br1-uuid", Name: "br1"},
			{UUID: "br-int-uuid", Name: "br-int"},
		}, nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	result, err := provider.SDNListBridges(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("expected 3 bridges, got %d", len(result))
	}
}

func TestMCPServiceProvider_SDNListBridges_ServiceError(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return nil, errors.New("OVSDB connection failed")
	})

	sdnService := createMCPTestSDNService(mockOVS)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	_, err := provider.SDNListBridges(ctx)
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

// =============================================================================
// SDNCreateBridge Tests - With Mock SDN Service
// =============================================================================

func TestMCPServiceProvider_SDNCreateBridge_Success(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnCreateBridge(func(ctx context.Context, name string) (*ovs.Bridge, error) {
		return &ovs.Bridge{
			UUID: "new-bridge-uuid",
			Name: name,
		}, nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNCreateBridge(ctx, "test-bridge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the mock was called
	if mockOVS.GetCallCount("CreateBridge") != 1 {
		t.Errorf("expected CreateBridge to be called once, got %d calls", mockOVS.GetCallCount("CreateBridge"))
	}
}

func TestMCPServiceProvider_SDNCreateBridge_ServiceError(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnCreateBridge(func(ctx context.Context, name string) (*ovs.Bridge, error) {
		return nil, errors.New("bridge already exists")
	})

	sdnService := createMCPTestSDNService(mockOVS)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNCreateBridge(ctx, "existing-bridge")
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

func TestMCPServiceProvider_SDNCreateBridge_VariousNames(t *testing.T) {
	testCases := []struct {
		name       string
		bridgeName string
	}{
		{"simple_name", "br0"},
		{"with_dashes", "br-int"},
		{"with_underscores", "br_ext"},
		{"long_name", "my-very-long-bridge-name-for-testing"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockOVS := NewConfigurableMockOVSClient()
			sdnService := createMCPTestSDNService(mockOVS)
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: sdnService,
				Logger:     slog.Default(),
			})

			err := provider.SDNCreateBridge(ctx, tc.bridgeName)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// =============================================================================
// SDNDeleteBridge Tests - With Mock SDN Service
// =============================================================================

func TestMCPServiceProvider_SDNDeleteBridge_Success(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnDeleteBridge(func(ctx context.Context, name string) error {
		return nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	// Pre-populate bridge for deletion
	sdnService.bridges["test-bridge"] = &bridgeResource{
		id:   "bridge-uuid",
		name: "test-bridge",
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNDeleteBridge(ctx, "test-bridge")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_SDNDeleteBridge_ServiceError(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnDeleteBridge(func(ctx context.Context, name string) error {
		return errors.New("bridge not found")
	})

	sdnService := createMCPTestSDNService(mockOVS)
	// Note: Without pre-populating, the bridge won't be found
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNDeleteBridge(ctx, "nonexistent-bridge")
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

// =============================================================================
// SDNAddPort Tests - With Mock SDN Service
// =============================================================================

func TestMCPServiceProvider_SDNAddPort_Success(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnAddPort(func(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
		return &ovs.Port{
			UUID: "port-uuid-" + portName,
			Name: portName,
		}, nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	// Pre-populate bridge
	sdnService.bridges["br0"] = &bridgeResource{
		id:   "br0-uuid",
		name: "br0",
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNAddPort(ctx, "br0", "eth0", "internal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_SDNAddPort_ServiceError(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnAddPort(func(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
		return nil, errors.New("port already exists")
	})

	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNAddPort(ctx, "br0", "eth0", "internal")
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

func TestMCPServiceProvider_SDNAddPort_BridgeNotFound(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	sdnService := createMCPTestSDNService(mockOVS)
	// Don't pre-populate any bridges

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNAddPort(ctx, "nonexistent", "eth0", "internal")
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

// =============================================================================
// SDNDeletePort Tests - With Mock SDN Service
// =============================================================================

func TestMCPServiceProvider_SDNDeletePort_Success(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnDeletePort(func(ctx context.Context, bridgeName, portName string) error {
		return nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}
	sdnService.ports["eth0"] = &portResource{id: "port-uuid", name: "eth0", bridgeID: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNDeletePort(ctx, "br0", "eth0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_SDNDeletePort_ServiceError(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnDeletePort(func(ctx context.Context, bridgeName, portName string) error {
		return errors.New("port not found")
	})

	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNDeletePort(ctx, "br0", "nonexistent")
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

// =============================================================================
// SDNListPolicies Tests - With Mock Policy Engine
// =============================================================================

func TestMCPServiceProvider_SDNListPolicies_WithPolicies(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return []*ovs.Bridge{
			{UUID: "br0-uuid", Name: "br0"},
		}, nil
	})
	mockOVS.OnListPorts(func(ctx context.Context, bridgeName string) ([]*ovs.Port, error) {
		return []*ovs.Port{
			{UUID: "port1-uuid", Name: "port1"},
		}, nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	mockEngine := newMCPTestMockPolicyEngine()
	mockEngine.policies["port1"] = &policy.PortPolicy{
		TenantID: "tenant-123",
		VLAN:     100,
		IssuedAt: time.Now(),
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService:   sdnService,
		PolicyEngine: mockEngine,
		Logger:       slog.Default(),
	})

	result, err := provider.SDNListPolicies(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestMCPServiceProvider_SDNListPolicies_NoPolicies(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return []*ovs.Bridge{}, nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	mockEngine := newMCPTestMockPolicyEngine()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService:   sdnService,
		PolicyEngine: mockEngine,
		Logger:       slog.Default(),
	})

	result, err := provider.SDNListPolicies(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result) != 0 {
		t.Errorf("expected empty list, got %d items", len(result))
	}
}

func TestMCPServiceProvider_SDNListPolicies_ListBridgesError(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return nil, errors.New("OVSDB error")
	})

	sdnService := createMCPTestSDNService(mockOVS)
	mockEngine := newMCPTestMockPolicyEngine()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService:   sdnService,
		PolicyEngine: mockEngine,
		Logger:       slog.Default(),
	})

	// Should return empty list on error, not fail
	result, err := provider.SDNListPolicies(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// =============================================================================
// SDNAddFlow Tests - With Mock SDN Service
// =============================================================================

func TestMCPServiceProvider_SDNAddFlow_Success(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		return nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	flow := map[string]interface{}{
		"priority": 100,
		"match":    "in_port=1",
		"actions":  "output:2",
	}

	err := provider.SDNAddFlow(ctx, "br0", flow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_SDNAddFlow_ServiceError(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		return errors.New("OpenFlow error")
	})

	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNAddFlow(ctx, "br0", map[string]interface{}{"priority": 100})
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

// =============================================================================
// SDNDeleteFlow Tests - With Mock SDN Service
// =============================================================================

func TestMCPServiceProvider_SDNDeleteFlow_Success(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnDeleteFlow(func(ctx context.Context, bridgeName string, match string) error {
		return nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNDeleteFlow(ctx, "br0", "flow-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_SDNDeleteFlow_ServiceError(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnDeleteFlow(func(ctx context.Context, bridgeName string, match string) error {
		return errors.New("flow not found")
	})

	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNDeleteFlow(ctx, "br0", "nonexistent")
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

func TestMCPServiceProvider_SDNDeleteFlow_VariousFlowIDs(t *testing.T) {
	testCases := []struct {
		name        string
		flowID      string
		expectError bool
	}{
		{"simple_id", "flow-1", false},
		{"numeric_id", "12345", false},
		{"uuid_id", "550e8400-e29b-41d4-a716-446655440000", false},
		// Empty flowID will fail validation in the SDN service
		{"empty_id", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockOVS := NewConfigurableMockOVSClient()
			sdnService := createMCPTestSDNService(mockOVS)
			sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}

			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: sdnService,
				Logger:     slog.Default(),
			})

			err := provider.SDNDeleteFlow(ctx, "br0", tc.flowID)
			if tc.expectError && err == nil {
				t.Fatal("expected error but got nil")
			}
			if !tc.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// =============================================================================
// SDNListFlows Tests - With Mock SDN Service
// =============================================================================

func TestMCPServiceProvider_SDNListFlows_Success_EmptyList(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return []*ovs.Flow{}, nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	result, err := provider.SDNListFlows(ctx, "br0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result) != 0 {
		t.Errorf("expected empty list, got %d items", len(result))
	}
}

func TestMCPServiceProvider_SDNListFlows_Success_MultipleFlows(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return []*ovs.Flow{
			{Cookie: "flow-1", Priority: 100},
			{Cookie: "flow-2", Priority: 200},
			{Cookie: "flow-3", Priority: 50},
		}, nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	result, err := provider.SDNListFlows(ctx, "br0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("expected 3 flows, got %d", len(result))
	}
}

func TestMCPServiceProvider_SDNListFlows_ServiceError(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return nil, errors.New("OpenFlow connection failed")
	})

	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	_, err := provider.SDNListFlows(ctx, "br0")
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

func TestMCPServiceProvider_SDNListFlows_VariousBridgeNames(t *testing.T) {
	testCases := []struct {
		name       string
		bridgeName string
	}{
		{"simple_bridge", "br0"},
		{"dashed_bridge", "br-int"},
		{"underscored_bridge", "br_ext"},
		{"long_bridge", "my-very-long-bridge-name"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockOVS := NewConfigurableMockOVSClient()
			mockOVS.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
				return []*ovs.Flow{}, nil
			})

			sdnService := createMCPTestSDNService(mockOVS)
			sdnService.bridges[tc.bridgeName] = &bridgeResource{id: "uuid", name: tc.bridgeName}

			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: sdnService,
				Logger:     slog.Default(),
			})

			result, err := provider.SDNListFlows(ctx, tc.bridgeName)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
		})
	}
}

// =============================================================================
// Context Cancellation Tests
// =============================================================================

func TestMCPServiceProvider_SDN_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	mockOVS := NewConfigurableMockOVSClient()
	sdnService := createMCPTestSDNService(mockOVS)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Test that context cancellation is passed through
	// The mock doesn't check context, so these should succeed
	// In a real implementation, these would fail with context.Canceled

	_, err := provider.SDNListBridges(ctx)
	if err != nil {
		t.Logf("SDNListBridges with cancelled context: %v", err)
	}

	_, err = provider.SDNListFlows(ctx, "br0")
	if err != nil {
		t.Logf("SDNListFlows with cancelled context: %v", err)
	}
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestMCPServiceProvider_SDN_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Run multiple operations concurrently
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			_, _ = provider.SDNListBridges(ctx)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// =============================================================================
// Error Type Verification Tests
// =============================================================================

func TestMCPServiceProvider_SDN_ErrorTypes(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService:   nil,
		PolicyEngine: nil,
		Logger:       slog.Default(),
	})

	testCases := []struct {
		name        string
		callFunc    func() error
		expectedErr interface{}
	}{
		{
			name: "SDNListBridges_nil_service",
			callFunc: func() error {
				_, err := provider.SDNListBridges(ctx)
				return err
			},
			expectedErr: ErrServiceNotAvailable{},
		},
		{
			name: "SDNListFlows_nil_service",
			callFunc: func() error {
				_, err := provider.SDNListFlows(ctx, "br0")
				return err
			},
			expectedErr: ErrServiceNotAvailable{},
		},
		{
			name: "SDNListPolicies_nil_engine",
			callFunc: func() error {
				_, err := provider.SDNListPolicies(ctx)
				return err
			},
			expectedErr: ErrSDNPolicyEngineNotConfigured{},
		},
		{
			name: "SDNGetPortState_nil_service",
			callFunc: func() error {
				_, err := provider.SDNGetPortState(ctx, "br0", "port1")
				return err
			},
			expectedErr: ErrServiceNotAvailable{},
		},
		{
			name: "SDNCreateBridge_nil_service",
			callFunc: func() error {
				return provider.SDNCreateBridge(ctx, "br0")
			},
			expectedErr: ErrServiceNotAvailable{},
		},
		{
			name: "SDNDeleteBridge_nil_service",
			callFunc: func() error {
				return provider.SDNDeleteBridge(ctx, "br0")
			},
			expectedErr: ErrServiceNotAvailable{},
		},
		{
			name: "SDNAddPort_nil_service",
			callFunc: func() error {
				return provider.SDNAddPort(ctx, "br0", "eth0", "internal")
			},
			expectedErr: ErrServiceNotAvailable{},
		},
		{
			name: "SDNDeletePort_nil_service",
			callFunc: func() error {
				return provider.SDNDeletePort(ctx, "br0", "eth0")
			},
			expectedErr: ErrServiceNotAvailable{},
		},
		{
			name: "SDNAddFlow_nil_service",
			callFunc: func() error {
				return provider.SDNAddFlow(ctx, "br0", nil)
			},
			expectedErr: ErrServiceNotAvailable{},
		},
		{
			name: "SDNDeleteFlow_nil_service",
			callFunc: func() error {
				return provider.SDNDeleteFlow(ctx, "br0", "flow-1")
			},
			expectedErr: ErrServiceNotAvailable{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.callFunc()
			if err == nil {
				t.Fatal("expected error but got nil")
			}

			switch tc.expectedErr.(type) {
			case ErrServiceNotAvailable:
				if _, ok := err.(ErrServiceNotAvailable); !ok {
					t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
				}
			case ErrSDNPolicyEngineNotConfigured:
				if _, ok := err.(ErrSDNPolicyEngineNotConfigured); !ok {
					t.Errorf("expected ErrSDNPolicyEngineNotConfigured, got %T: %v", err, err)
				}
			}
		})
	}
}

// =============================================================================
// SDNService Method Call Verification Tests
// =============================================================================

func TestMCPServiceProvider_SDN_MethodCallVerification(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}
	sdnService.ports["port1"] = &portResource{id: "port1-uuid", name: "port1", bridgeID: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Call various methods and verify OVS client was invoked
	_, _ = provider.SDNListBridges(ctx)
	if mockOVS.GetCallCount("ListBridges") != 1 {
		t.Errorf("expected ListBridges to be called once, got %d", mockOVS.GetCallCount("ListBridges"))
	}

	_, _ = provider.SDNListFlows(ctx, "br0")
	if mockOVS.GetCallCount("ListFlows") != 1 {
		t.Errorf("expected ListFlows to be called once, got %d", mockOVS.GetCallCount("ListFlows"))
	}

	_ = provider.SDNAddFlow(ctx, "br0", map[string]interface{}{"priority": 100})
	if mockOVS.GetCallCount("AddFlow") != 1 {
		t.Errorf("expected AddFlow to be called once, got %d", mockOVS.GetCallCount("AddFlow"))
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestMCPServiceProvider_SDN_EdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("empty_bridge_name", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
			SDNService: nil,
			Logger:     slog.Default(),
		})

		err := provider.SDNCreateBridge(ctx, "")
		if err == nil {
			t.Fatal("expected error for empty bridge name")
		}
	})

	t.Run("nil_logger", func(t *testing.T) {
		mockOVS := NewConfigurableMockOVSClient()
		sdnService := createMCPTestSDNService(mockOVS)

		// Should not panic with nil logger
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
			SDNService: sdnService,
			Logger:     nil,
		})

		_, err := provider.SDNListBridges(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("very_long_bridge_name", func(t *testing.T) {
		mockOVS := NewConfigurableMockOVSClient()
		sdnService := createMCPTestSDNService(mockOVS)

		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
			SDNService: sdnService,
			Logger:     slog.Default(),
		})

		longName := "a-very-long-bridge-name-that-exceeds-typical-length-limits-for-network-interfaces"
		err := provider.SDNCreateBridge(ctx, longName)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// =============================================================================
// Integration between SDN functions
// =============================================================================

func TestMCPServiceProvider_SDN_IntegrationFlow(t *testing.T) {
	ctx := context.Background()

	mockOVS := NewConfigurableMockOVSClient()
	sdnService := createMCPTestSDNService(mockOVS)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// 1. Create a bridge
	err := provider.SDNCreateBridge(ctx, "test-br")
	if err != nil {
		t.Fatalf("failed to create bridge: %v", err)
	}

	// Simulate bridge creation in the SDNService state
	sdnService.bridges["test-br"] = &bridgeResource{
		id:        "test-br-uuid",
		name:      "test-br",
		createdAt: time.Now(),
	}

	// 2. List bridges to verify
	bridges, err := provider.SDNListBridges(ctx)
	if err != nil {
		t.Fatalf("failed to list bridges: %v", err)
	}
	_ = bridges // Would verify in real implementation

	// 3. Add a port
	err = provider.SDNAddPort(ctx, "test-br", "eth0", "internal")
	if err != nil {
		t.Fatalf("failed to add port: %v", err)
	}

	// 4. Add a flow
	flow := map[string]interface{}{
		"priority": 100,
		"match":    "in_port=1",
		"actions":  "output:2",
	}
	err = provider.SDNAddFlow(ctx, "test-br", flow)
	if err != nil {
		t.Fatalf("failed to add flow: %v", err)
	}

	// 5. List flows
	flows, err := provider.SDNListFlows(ctx, "test-br")
	if err != nil {
		t.Fatalf("failed to list flows: %v", err)
	}
	_ = flows

	// 6. Delete the flow
	err = provider.SDNDeleteFlow(ctx, "test-br", "flow-1")
	if err != nil {
		t.Fatalf("failed to delete flow: %v", err)
	}

	// 7. Delete the port
	err = provider.SDNDeletePort(ctx, "test-br", "eth0")
	if err != nil {
		t.Fatalf("failed to delete port: %v", err)
	}

	// 8. Delete the bridge
	err = provider.SDNDeleteBridge(ctx, "test-br")
	if err != nil {
		t.Fatalf("failed to delete bridge: %v", err)
	}
}

// =============================================================================
// Table-Driven Comprehensive Tests
// =============================================================================

func TestMCPServiceProvider_SDN_TableDrivenScenarios(t *testing.T) {
	testCases := []struct {
		name        string
		setupMock   func(*ConfigurableMockOVSClient)
		setupPorts  func(*SDNService)
		operation   func(*MCPServiceProvider, context.Context) error
		expectError bool
	}{
		{
			name: "list_bridges_success",
			setupMock: func(m *ConfigurableMockOVSClient) {
				m.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
					return []*ovs.Bridge{{UUID: "br0", Name: "br0"}}, nil
				})
			},
			setupPorts: func(s *SDNService) {},
			operation: func(p *MCPServiceProvider, ctx context.Context) error {
				_, err := p.SDNListBridges(ctx)
				return err
			},
			expectError: false,
		},
		{
			name: "list_bridges_error",
			setupMock: func(m *ConfigurableMockOVSClient) {
				m.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
					return nil, errors.New("connection refused")
				})
			},
			setupPorts: func(s *SDNService) {},
			operation: func(p *MCPServiceProvider, ctx context.Context) error {
				_, err := p.SDNListBridges(ctx)
				return err
			},
			expectError: true,
		},
		{
			name: "create_bridge_success",
			setupMock: func(m *ConfigurableMockOVSClient) {
				m.OnCreateBridge(func(ctx context.Context, name string) (*ovs.Bridge, error) {
					return &ovs.Bridge{UUID: "new-uuid", Name: name}, nil
				})
			},
			setupPorts: func(s *SDNService) {},
			operation: func(p *MCPServiceProvider, ctx context.Context) error {
				return p.SDNCreateBridge(ctx, "new-bridge")
			},
			expectError: false,
		},
		{
			name: "create_bridge_already_exists",
			setupMock: func(m *ConfigurableMockOVSClient) {
				m.OnCreateBridge(func(ctx context.Context, name string) (*ovs.Bridge, error) {
					return nil, errors.New("bridge already exists")
				})
			},
			setupPorts: func(s *SDNService) {},
			operation: func(p *MCPServiceProvider, ctx context.Context) error {
				return p.SDNCreateBridge(ctx, "existing-bridge")
			},
			expectError: true,
		},
		{
			name: "list_flows_success",
			setupMock: func(m *ConfigurableMockOVSClient) {
				m.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
					return []*ovs.Flow{{Cookie: "flow1", Priority: 100}}, nil
				})
			},
			setupPorts: func(s *SDNService) {},
			operation: func(p *MCPServiceProvider, ctx context.Context) error {
				_, err := p.SDNListFlows(ctx, "br0")
				return err
			},
			expectError: false,
		},
		{
			name: "list_flows_error",
			setupMock: func(m *ConfigurableMockOVSClient) {
				m.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
					return nil, errors.New("bridge not found")
				})
			},
			setupPorts: func(s *SDNService) {},
			operation: func(p *MCPServiceProvider, ctx context.Context) error {
				_, err := p.SDNListFlows(ctx, "nonexistent")
				return err
			},
			expectError: true,
		},
		{
			name: "add_flow_success",
			setupMock: func(m *ConfigurableMockOVSClient) {
				m.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
					return nil
				})
			},
			setupPorts: func(s *SDNService) {},
			operation: func(p *MCPServiceProvider, ctx context.Context) error {
				return p.SDNAddFlow(ctx, "br0", map[string]interface{}{"priority": 100})
			},
			expectError: false,
		},
		{
			name: "delete_flow_success",
			setupMock: func(m *ConfigurableMockOVSClient) {
				m.OnDeleteFlow(func(ctx context.Context, bridgeName string, match string) error {
					return nil
				})
			},
			setupPorts: func(s *SDNService) {},
			operation: func(p *MCPServiceProvider, ctx context.Context) error {
				return p.SDNDeleteFlow(ctx, "br0", "flow-1")
			},
			expectError: false,
		},
		{
			name: "get_port_state_success",
			setupMock: func(m *ConfigurableMockOVSClient) {
				m.OnGetPort(func(ctx context.Context, name string) (*ovs.Port, error) {
					return &ovs.Port{UUID: "port-uuid", Name: name}, nil
				})
			},
			setupPorts: func(s *SDNService) {
				s.ports["port1"] = &portResource{id: "port-uuid", name: "port1", bridgeID: "br0"}
			},
			operation: func(p *MCPServiceProvider, ctx context.Context) error {
				_, err := p.SDNGetPortState(ctx, "br0", "port1")
				return err
			},
			expectError: false,
		},
		{
			name: "get_port_state_port_not_in_map",
			setupMock: func(m *ConfigurableMockOVSClient) {
				m.OnGetPort(func(ctx context.Context, name string) (*ovs.Port, error) {
					return nil, errors.New("port not found")
				})
			},
			setupPorts: func(s *SDNService) {
				// Don't add port to map - this will cause "port not found"
			},
			operation: func(p *MCPServiceProvider, ctx context.Context) error {
				_, err := p.SDNGetPortState(ctx, "br0", "nonexistent")
				return err
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockOVS := NewConfigurableMockOVSClient()
			tc.setupMock(mockOVS)

			sdnService := createMCPTestSDNService(mockOVS)
			sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}
			tc.setupPorts(sdnService)

			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: sdnService,
				Logger:     slog.Default(),
			})

			err := tc.operation(provider, ctx)
			if tc.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// =============================================================================
// Verify interface compliance
// =============================================================================

// Ensure mcpTestMockPolicyEngine implements policy.PolicyEngine
var _ policy.PolicyEngine = (*mcpTestMockPolicyEngine)(nil)

// Verify the mock Port response from SDNService GetPort
func TestMCPServiceProvider_SDNGetPortState_ResponseContent(t *testing.T) {
	ctx := context.Background()

	expectedPort := &platformv1.Port{
		Id: "test-port-id",
		Config: &platformv1.PortConfig{
			Name: "eth0",
		},
	}

	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnGetPort(func(ctx context.Context, name string) (*ovs.Port, error) {
		return &ovs.Port{
			UUID: expectedPort.Id,
			Name: expectedPort.Config.Name,
		}, nil
	})

	sdnService := createMCPTestSDNService(mockOVS)
	// Pre-populate port for lookup
	sdnService.ports["eth0"] = &portResource{
		id:       expectedPort.Id,
		name:     "eth0",
		bridgeID: "br0",
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	result, err := provider.SDNGetPortState(ctx, "br0", "eth0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// The result should be a *platformv1.Port from SDNService.GetPort
	port, ok := result.(*platformv1.Port)
	if !ok {
		// Result might be the raw OVS port type
		t.Logf("result type: %T", result)
	} else {
		if port.Id != expectedPort.Id {
			t.Errorf("expected port ID %q, got %q", expectedPort.Id, port.Id)
		}
	}
}
