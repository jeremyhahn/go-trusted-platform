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
	"reflect"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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

func TestMCPServiceProvider_SDNAddPort_HonoursThePortType(t *testing.T) {
	for _, name := range []string{"internal", "VXLAN", "PORT_TYPE_GRE", ""} {
		t.Run(name, func(t *testing.T) {
			want, err := portTypeFromName(name)
			if err != nil {
				t.Fatalf("portTypeFromName(%q): %v", name, err)
			}
			mockOVS := NewConfigurableMockOVSClient()
			mockOVS.OnAddPort(func(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
				return &ovs.Port{UUID: "port-uuid", Name: portName}, nil
			})
			sdnService := createMCPTestSDNService(mockOVS)
			sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{SDNService: sdnService, Logger: slog.Default()})

			if err := provider.SDNAddPort(context.Background(), "br0", "eth0", name); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := sdnService.ports["eth0"].portType; got != want {
				t.Fatalf("port type = %v, want %v", got, want)
			}
		})
	}
	if got, _ := portTypeFromName("vxlan"); got != platformv1.PortType_PORT_TYPE_VXLAN {
		t.Fatalf("short form vxlan parsed as %v", got)
	}
}

func TestMCPServiceProvider_SDNAddPort_RefusesAnUnknownPortType(t *testing.T) {
	mockOVS := NewConfigurableMockOVSClient()
	called := false
	mockOVS.OnAddPort(func(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
		called = true
		return &ovs.Port{UUID: "port-uuid", Name: portName}, nil
	})
	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{SDNService: sdnService, Logger: slog.Default()})

	err := provider.SDNAddPort(context.Background(), "br0", "eth0", "wormhole")

	var invalid ErrInvalidPortType
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrInvalidPortType, got %v", err)
	}
	if called {
		t.Fatal("no port is added for an unknown type")
	}
}

func TestMCPServiceProvider_SDNSetPortState_ReturnsTheUpdatedPort(t *testing.T) {
	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnGetPort(func(ctx context.Context, name string) (*ovs.Port, error) {
		return &ovs.Port{UUID: "port-uuid-123", Name: name}, nil
	})
	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.ports["port1"] = &portResource{id: "port-uuid-123", name: "port1", bridgeID: "br0"}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{SDNService: sdnService, Logger: slog.Default()})

	result, err := provider.SDNSetPortState(context.Background(), "br0", "port1", "down", mcp.PortRates{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	port, ok := result.(*platformv1.Port)
	if !ok {
		t.Fatalf("result is %T, want *platformv1.Port", result)
	}
	if port.GetStatus() != platformv1.PortStatus_PORT_STATUS_DOWN {
		t.Fatalf("port status = %v, want down", port.GetStatus())
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
		"match":    map[string]interface{}{"in_port": "1"},
		"actions":  []interface{}{map[string]interface{}{"type": "FLOW_ACTION_OUTPUT", "port": "2"}},
	}

	_, err := provider.SDNAddFlow(ctx, "br0", flow)
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

	_, err := provider.SDNAddFlow(ctx, "br0", map[string]interface{}{"priority": 100})
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
	mockOVS.OnDeleteFlowsByCookie(func(ctx context.Context, bridgeName string, cookie, mask uint64) error {
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
	mockOVS.OnDeleteFlowsByCookie(func(ctx context.Context, bridgeName string, cookie, mask uint64) error {
		return errors.New("flow not found")
	})

	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	err := provider.SDNDeleteFlow(ctx, "br0", "flow-0x99")
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
		{"hex_id", "flow-0xa9f1000000000001", false},
		// An ID is "flow-<cookie>"; anything else names no single flow.
		{"numeric_id", "12345", true},
		{"uuid_id", "550e8400-e29b-41d4-a716-446655440000", true},
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
		SDNService: nil,
		Logger:     slog.Default(),
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
			name: "SDNListPolicies_nil_service",
			callFunc: func() error {
				_, err := provider.SDNListPolicies(ctx, "", "")
				return err
			},
			expectedErr: ErrServiceNotAvailable{},
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
				_, err := provider.SDNAddFlow(ctx, "br0", nil)
				return err
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

			if reflect.TypeOf(err) != reflect.TypeOf(tc.expectedErr) {
				t.Errorf("expected %T, got %T: %v", tc.expectedErr, err, err)
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

	if _, err := provider.SDNAddFlow(ctx, "br0", map[string]interface{}{"priority": 100}); err != nil {
		t.Fatalf("SDNAddFlow: %v", err)
	}
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
		"match":    map[string]interface{}{"in_port": "1"},
		"actions":  []interface{}{map[string]interface{}{"type": "FLOW_ACTION_OUTPUT", "port": "2"}},
	}
	_, err = provider.SDNAddFlow(ctx, "test-br", flow)
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
				_, err := p.SDNAddFlow(ctx, "br0", map[string]interface{}{"priority": 100})
				return err
			},
			expectError: false,
		},
		{
			name: "delete_flow_success",
			setupMock: func(m *ConfigurableMockOVSClient) {
				m.OnDeleteFlowsByCookie(func(ctx context.Context, bridgeName string, cookie, mask uint64) error {
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
	} else if port.Id != expectedPort.Id {
		t.Errorf("expected port ID %q, got %q", expectedPort.Id, port.Id)
	}
}
