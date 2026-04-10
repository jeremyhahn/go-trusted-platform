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
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// setupSDNCoverageProvider creates an SDN service with mock and returns provider
func setupSDNCoverageProvider(mockClient *ConfigurableMockOVSClient) (*SDNService, *PlatformServiceProvider) {
	sdnService := &SDNService{
		ovsClient:      mockClient,
		netlinkManager: nil,
		bridges:        make(map[string]*bridgeResource),
		ports:          make(map[string]*portResource),
		taps:           make(map[string]*tapResource),
		vlans:          make(map[string]*vlanResource),
		portAuths:      make(map[string]*portAuthResource),
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		SDNService: sdnService,
	})
	return sdnService, provider
}

// setupSDNCoverageProviderWithBridge creates an SDN service with a pre-registered bridge
func setupSDNCoverageProviderWithBridge(mockClient *ConfigurableMockOVSClient, bridgeName string) (*SDNService, *PlatformServiceProvider) {
	sdnService, provider := setupSDNCoverageProvider(mockClient)
	sdnService.bridges[bridgeName] = &bridgeResource{
		id:         "uuid-" + bridgeName,
		name:       bridgeName,
		bridgeType: platformv1.BridgeType_BRIDGE_TYPE_OVS,
		createdAt:  time.Now(),
	}
	return sdnService, provider
}

// setupSDNCoverageProviderWithBridgeAndPort creates an SDN service with bridge and port
func setupSDNCoverageProviderWithBridgeAndPort(mockClient *ConfigurableMockOVSClient, bridgeName, portName string) (*SDNService, *PlatformServiceProvider) {
	sdnService, provider := setupSDNCoverageProviderWithBridge(mockClient, bridgeName)
	sdnService.ports[portName] = &portResource{
		id:        "uuid-" + portName,
		name:      portName,
		bridgeID:  "uuid-" + bridgeName,
		portType:  platformv1.PortType_PORT_TYPE_INTERNAL,
		createdAt: time.Now(),
	}
	return sdnService, provider
}

// setupSDNCoverageProviderWithVLAN creates an SDN service with VLAN
func setupSDNCoverageProviderWithVLAN(mockClient *ConfigurableMockOVSClient, bridgeName string, vlanID uint32) (*SDNService, *PlatformServiceProvider) {
	sdnService, provider := setupSDNCoverageProviderWithBridge(mockClient, bridgeName)
	vlanKey := bridgeName + ":100"
	sdnService.vlans[vlanKey] = &vlanResource{
		id:        "vlan-" + bridgeName + "-100",
		vlanID:    vlanID,
		bridgeID:  "uuid-" + bridgeName,
		name:      "test-vlan",
		ports:     []string{"eth0"},
		createdAt: time.Now(),
	}
	return sdnService, provider
}

func TestSPSDNCov_ListBridges_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return []*ovs.Bridge{
			{UUID: "uuid-br0", Name: "br0", ExternalIDs: map[string]string{}, OtherConfig: map[string]string{}},
			{UUID: "uuid-br1", Name: "br1", ExternalIDs: map[string]string{}, OtherConfig: map[string]string{}},
		}, nil
	})

	_, provider := setupSDNCoverageProvider(mockClient)

	result, err := provider.SDNListBridges(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 bridges, got %d", len(result))
	}
}

func TestSPSDNCov_ListBridges_Empty(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return []*ovs.Bridge{}, nil
	})

	_, provider := setupSDNCoverageProvider(mockClient)

	result, err := provider.SDNListBridges(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 bridges, got %d", len(result))
	}
}

func TestSPSDNCov_ListBridges_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return nil, errors.New("connection failed")
	})

	_, provider := setupSDNCoverageProvider(mockClient)

	_, err := provider.SDNListBridges(ctx)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSPSDNCov_ListFlows_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return []*ovs.Flow{
			{Table: 0, Priority: 100, Cookie: "flow-1", Actions: "output:1"},
			{Table: 0, Priority: 50, Cookie: "flow-2", Actions: "drop"},
		}, nil
	})

	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	result, err := provider.SDNListFlows(ctx, "br0")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 flows, got %d", len(result))
	}
}

func TestSPSDNCov_ListFlows_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProvider(mockClient)

	_, err := provider.SDNListFlows(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent bridge")
	}
}

func TestSPSDNCov_ListFlows_OVSError(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return nil, errors.New("OVS error")
	})

	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	_, err := provider.SDNListFlows(ctx, "br0")
	if err == nil {
		t.Fatal("expected error from OVS")
	}
}

func TestSPSDNCov_ListVLANs_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProviderWithVLAN(mockClient, "br0", 100)

	result, err := provider.SDNListVLANs(ctx, "br0")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 VLAN, got %d", len(result))
	}
}

func TestSPSDNCov_ListVLANs_Empty(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	result, err := provider.SDNListVLANs(ctx, "br0")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 VLANs, got %d", len(result))
	}
}

func TestSPSDNCov_ListVLANs_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProvider(mockClient)

	_, err := provider.SDNListVLANs(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent bridge")
	}
}

func TestSPSDNCov_AddFlow_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		return nil
	})

	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	flow := map[string]interface{}{
		"priority":     100,
		"table":        "FLOW_TABLE_CLASSIFICATION",
		"idle_timeout": 300,
		"hard_timeout": 600,
		"match": map[string]interface{}{
			"in_port":  "eth0",
			"vlan_id":  100,
			"eth_src":  "00:11:22:33:44:55",
			"eth_dst":  "66:77:88:99:aa:bb",
			"eth_type": 0x0800,
			"ip_src":   "192.168.1.1",
			"ip_dst":   "192.168.1.2",
			"ip_proto": 6,
			"tcp_src":  80,
			"tcp_dst":  443,
			"metadata": map[string]string{"key": "value"},
		},
		"actions": []interface{}{
			map[string]interface{}{
				"type":     "FLOW_ACTION_OUTPUT",
				"port":     "eth1",
				"vlan_id":  200,
				"field":    "dst_ip",
				"value":    "10.0.0.1",
				"table_id": 5,
			},
		},
	}

	err := provider.SDNAddFlow(ctx, "br0", flow)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSPSDNCov_AddFlow_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProvider(mockClient)

	err := provider.SDNAddFlow(ctx, "nonexistent", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for nonexistent bridge")
	}
}

func TestSPSDNCov_AddFlow_OVSError(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		return errors.New("OVS rejected flow")
	})

	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	err := provider.SDNAddFlow(ctx, "br0", map[string]interface{}{"priority": 100})
	if err == nil {
		t.Fatal("expected error from OVS")
	}
}

func TestSPSDNCov_DeleteFlow_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnDeleteFlow(func(ctx context.Context, bridgeName, match string) error {
		return nil
	})

	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	err := provider.SDNDeleteFlow(ctx, "br0", "flow-123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSPSDNCov_DeleteFlow_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProvider(mockClient)

	err := provider.SDNDeleteFlow(ctx, "nonexistent", "flow-123")
	if err == nil {
		t.Fatal("expected error for nonexistent bridge")
	}
}

func TestSPSDNCov_FlushFlows_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return []*ovs.Flow{{Cookie: "flow-1"}, {Cookie: "flow-2"}}, nil
	})
	mockClient.OnDeleteAllFlows(func(ctx context.Context, bridgeName string) error {
		return nil
	})

	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	err := provider.SDNFlushFlows(ctx, "br0")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSPSDNCov_FlushFlows_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProvider(mockClient)

	err := provider.SDNFlushFlows(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent bridge")
	}
}

func TestSPSDNCov_CreateVLAN_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	err := provider.SDNCreateVLAN(ctx, "br0", 100, "test-vlan")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSPSDNCov_CreateVLAN_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProvider(mockClient)

	err := provider.SDNCreateVLAN(ctx, "nonexistent", 100, "test-vlan")
	if err == nil {
		t.Fatal("expected error for nonexistent bridge")
	}
}

func TestSPSDNCov_CreateVLAN_InvalidZero(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	err := provider.SDNCreateVLAN(ctx, "br0", 0, "test-vlan")
	if err == nil {
		t.Fatal("expected error for VLAN ID 0")
	}
}

func TestSPSDNCov_CreateVLAN_InvalidTooHigh(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	err := provider.SDNCreateVLAN(ctx, "br0", 5000, "test-vlan")
	if err == nil {
		t.Fatal("expected error for VLAN ID > 4095")
	}
}

func TestSPSDNCov_DeleteVLAN_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnSetPortVLAN(func(ctx context.Context, portName string, tag int64) error {
		return nil
	})
	_, provider := setupSDNCoverageProviderWithVLAN(mockClient, "br0", 100)

	err := provider.SDNDeleteVLAN(ctx, "br0", 100)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSPSDNCov_DeleteVLAN_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProvider(mockClient)

	err := provider.SDNDeleteVLAN(ctx, "nonexistent", 100)
	if err == nil {
		t.Fatal("expected error for nonexistent bridge")
	}
}

func TestSPSDNCov_AuthenticatePort_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProvider(mockClient)

	creds := map[string]string{"certificate": "test"}
	err := provider.SDNAuthenticatePort(ctx, "nonexistent", "eth0", creds)
	if err == nil {
		t.Fatal("expected error for nonexistent bridge")
	}
}

func TestSPSDNCov_AuthenticatePort_PortNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	creds := map[string]string{"certificate": "test"}
	err := provider.SDNAuthenticatePort(ctx, "br0", "nonexistent", creds)
	if err == nil {
		t.Fatal("expected error for nonexistent port")
	}
}

func TestSPSDNCov_AuthenticatePort_EmptyCert(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProviderWithBridgeAndPort(mockClient, "br0", "eth0")

	creds := map[string]string{"certificate": ""}
	err := provider.SDNAuthenticatePort(ctx, "br0", "eth0", creds)
	if err == nil {
		t.Fatal("expected error for empty certificate")
	}
}

func TestSPSDNCov_RevokePortAuth_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	sdnService, provider := setupSDNCoverageProviderWithBridgeAndPort(mockClient, "br0", "eth0")
	sdnService.portAuths["br0:eth0"] = &portAuthResource{
		portID:        "uuid-eth0",
		bridgeID:      "uuid-br0",
		certificateCN: "test-cn",
	}

	err := provider.SDNRevokePortAuth(ctx, "br0", "eth0")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSPSDNCov_RevokePortAuth_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProvider(mockClient)

	err := provider.SDNRevokePortAuth(ctx, "nonexistent", "eth0")
	if err == nil {
		t.Fatal("expected error for nonexistent bridge")
	}
}

func TestSPSDNCov_GetPortState_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnGetPort(func(ctx context.Context, name string) (*ovs.Port, error) {
		return &ovs.Port{
			UUID:        "uuid-" + name,
			Name:        name,
			Tag:         100,
			ExternalIDs: map[string]string{},
		}, nil
	})

	_, provider := setupSDNCoverageProviderWithBridgeAndPort(mockClient, "br0", "eth0")

	result, err := provider.SDNGetPortState(ctx, "br0", "eth0")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestSPSDNCov_GetPortState_PortNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	_, err := provider.SDNGetPortState(ctx, "br0", "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent port")
	}
}

func TestSPSDNCov_GetPortStats_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnGetInterface(func(ctx context.Context, name string) (*ovs.Interface, error) {
		return &ovs.Interface{
			UUID: "uuid-" + name,
			Name: name,
			Statistics: map[string]int64{
				"rx_packets": 1000,
				"tx_packets": 2000,
				"rx_bytes":   100000,
				"tx_bytes":   200000,
			},
		}, nil
	})

	_, provider := setupSDNCoverageProviderWithBridgeAndPort(mockClient, "br0", "eth0")

	result, err := provider.SDNGetPortStats(ctx, "br0", "eth0")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestSPSDNCov_GetPortStats_PortNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	_, err := provider.SDNGetPortStats(ctx, "br0", "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent port")
	}
}

func TestSPSDNCov_GetFlowStats_MissingFlowID(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()

	_, provider := setupSDNCoverageProviderWithBridge(mockClient, "br0")

	// The service_provider.SDNGetFlowStats doesn't pass flow_id, so it will always fail
	_, err := provider.SDNGetFlowStats(ctx, "br0")
	if err == nil {
		t.Fatal("expected error due to missing flow_id")
	}
}

func TestSPSDNCov_GetFlowStats_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := NewConfigurableMockOVSClient()
	_, provider := setupSDNCoverageProvider(mockClient)

	_, err := provider.SDNGetFlowStats(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent bridge")
	}
}

func TestSPSDNCov_BuildFlowMatch_AllFields(t *testing.T) {
	matchMap := map[string]interface{}{
		"in_port":  "eth0",
		"vlan_id":  100,
		"eth_src":  "00:11:22:33:44:55",
		"eth_dst":  "66:77:88:99:aa:bb",
		"eth_type": 0x0800,
		"ip_src":   "192.168.1.1",
		"ip_dst":   "192.168.1.2",
		"ip_proto": 6,
		"tcp_src":  80,
		"tcp_dst":  443,
		"metadata": map[string]string{"key": "value"},
	}

	match := buildFlowMatch(matchMap)
	if match == nil {
		t.Fatal("expected non-nil match")
	}
	if match.InPort != "eth0" {
		t.Errorf("expected InPort=eth0, got %s", match.InPort)
	}
}

func TestSPSDNCov_BuildFlowActions_AllFields(t *testing.T) {
	actionsSlice := []interface{}{
		map[string]interface{}{
			"type":     "FLOW_ACTION_OUTPUT",
			"port":     "eth1",
			"vlan_id":  200,
			"field":    "dst_ip",
			"value":    "10.0.0.1",
			"table_id": 5,
		},
		map[string]interface{}{
			"type": "FLOW_ACTION_DROP",
		},
	}

	actions := buildFlowActions(actionsSlice)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(actions))
	}
}
