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
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Test Helpers
// =============================================================================

func newTestSDNService(mockClient *ConfigurableMockOVSClient) *SDNService {
	return &SDNService{
		ovsClient:      mockClient,
		netlinkManager: nil, // Not used in mock tests
		bridges:        make(map[string]*bridgeResource),
		ports:          make(map[string]*portResource),
		taps:           make(map[string]*tapResource),
		vlans:          make(map[string]*vlanResource),
		policies:       make(map[string]*policyResource),
		portAuths:      make(map[string]*portAuthResource),
	}
}

// =============================================================================
// CreateBridge Tests
// =============================================================================

func TestSDNServiceUnit_CreateBridge_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnCreateBridge(func(ctx context.Context, name string) (*ovs.Bridge, error) {
		return &ovs.Bridge{
			UUID:        "uuid-" + name,
			Name:        name,
			ExternalIDs: map[string]string{},
			OtherConfig: map[string]string{},
		}, nil
	})

	svc := newTestSDNService(mockClient)
	ctx := context.Background()

	req := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{
			Name: "br0",
			Type: platformv1.BridgeType_BRIDGE_TYPE_OVS,
		},
	}

	resp, err := svc.CreateBridge(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "bridge created successfully", resp.Status.Message)
	assert.NotNil(t, resp.Bridge)
	assert.Equal(t, "uuid-br0", resp.Bridge.Id)
	assert.Equal(t, "br0", resp.Bridge.Config.Name)

	// Verify bridge was tracked
	assert.Contains(t, svc.bridges, "br0")
	assert.Equal(t, "uuid-br0", svc.bridges["br0"].id)

	// Verify mock was called
	assert.Equal(t, 1, mockClient.GetCallCount("CreateBridge"))
}

func TestSDNServiceUnit_CreateBridge_WithFailMode(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	setBridgeFailModeCalled := false
	mockClient.OnCreateBridge(func(ctx context.Context, name string) (*ovs.Bridge, error) {
		return &ovs.Bridge{UUID: "uuid-" + name, Name: name}, nil
	})
	mockClient.OnSetBridgeFailMode(func(ctx context.Context, name string, failMode string) error {
		setBridgeFailModeCalled = true
		assert.Equal(t, "br0", name)
		assert.Equal(t, "standalone", failMode)
		return nil
	})

	svc := newTestSDNService(mockClient)
	ctx := context.Background()

	req := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{
			Name: "br0",
			Options: map[string]string{
				"fail_mode": "standalone",
			},
		},
	}

	resp, err := svc.CreateBridge(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.True(t, setBridgeFailModeCalled)
}

func TestSDNServiceUnit_CreateBridge_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnCreateBridge(func(ctx context.Context, name string) (*ovs.Bridge, error) {
		return nil, errors.New("OVS connection failed")
	})

	svc := newTestSDNService(mockClient)
	ctx := context.Background()

	req := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{
			Name: "br0",
		},
	}

	resp, err := svc.CreateBridge(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to create bridge")
	assert.Contains(t, err.Error(), "OVS connection failed")

	// Verify bridge was not tracked
	assert.NotContains(t, svc.bridges, "br0")
}

func TestSDNServiceUnit_CreateBridge_AlreadyExists(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)

	// Pre-populate with existing bridge
	svc.bridges["br0"] = &bridgeResource{
		id:   "existing-uuid",
		name: "br0",
	}

	ctx := context.Background()
	req := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{
			Name: "br0",
		},
	}

	resp, err := svc.CreateBridge(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "already exists")

	// Verify OVS client was not called
	assert.Equal(t, 0, mockClient.GetCallCount("CreateBridge"))
}

// =============================================================================
// DeleteBridge Tests
// =============================================================================

func TestSDNServiceUnit_DeleteBridge_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)

	// Add bridge to track
	svc.bridges["br0"] = &bridgeResource{
		id:   "uuid-br0",
		name: "br0",
	}

	ctx := context.Background()
	req := &platformv1.DeleteBridgeRequest{
		Id: "br0",
	}

	resp, err := svc.DeleteBridge(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "bridge deleted successfully", resp.Status.Message)

	// Verify bridge was removed from tracking
	assert.NotContains(t, svc.bridges, "br0")

	// Verify mock was called
	assert.Equal(t, 1, mockClient.GetCallCount("DeleteBridge"))
}

func TestSDNServiceUnit_DeleteBridge_ByUUID(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)

	// Add bridge to track
	svc.bridges["br0"] = &bridgeResource{
		id:   "uuid-br0",
		name: "br0",
	}

	ctx := context.Background()
	req := &platformv1.DeleteBridgeRequest{
		Id: "uuid-br0", // Delete by UUID instead of name
	}

	resp, err := svc.DeleteBridge(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.NotContains(t, svc.bridges, "br0")
}

func TestSDNServiceUnit_DeleteBridge_NotFound(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)

	ctx := context.Background()
	req := &platformv1.DeleteBridgeRequest{
		Id: "nonexistent",
	}

	resp, err := svc.DeleteBridge(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "bridge not found")

	// Verify OVS client was not called
	assert.Equal(t, 0, mockClient.GetCallCount("DeleteBridge"))
}

func TestSDNServiceUnit_DeleteBridge_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnDeleteBridge(func(ctx context.Context, name string) error {
		return errors.New("OVS delete failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.DeleteBridgeRequest{Id: "br0"}

	resp, err := svc.DeleteBridge(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to delete bridge")

	// Bridge should still be tracked (not removed on error)
	assert.Contains(t, svc.bridges, "br0")
}

// =============================================================================
// GetBridge Tests
// =============================================================================

func TestSDNServiceUnit_GetBridge_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnGetBridge(func(ctx context.Context, name string) (*ovs.Bridge, error) {
		return &ovs.Bridge{
			UUID:        "uuid-" + name,
			Name:        name,
			STP:         true,
			ExternalIDs: map[string]string{"key": "value"},
			OtherConfig: map[string]string{"option": "optvalue"},
		}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.GetBridgeRequest{Id: "br0"}

	resp, err := svc.GetBridge(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Bridge)
	assert.Equal(t, "uuid-br0", resp.Bridge.Id)
	assert.Equal(t, "br0", resp.Bridge.Config.Name)
	assert.True(t, resp.Bridge.Config.StpEnabled)
	assert.Equal(t, "value", resp.Bridge.Config.Labels["key"])
}

func TestSDNServiceUnit_GetBridge_NotFound(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)

	ctx := context.Background()
	req := &platformv1.GetBridgeRequest{Id: "nonexistent"}

	resp, err := svc.GetBridge(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "bridge not found")
}

func TestSDNServiceUnit_GetBridge_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnGetBridge(func(ctx context.Context, name string) (*ovs.Bridge, error) {
		return nil, errors.New("OVS query failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.GetBridgeRequest{Id: "br0"}

	resp, err := svc.GetBridge(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to get bridge")
}

// =============================================================================
// ListBridges Tests
// =============================================================================

func TestSDNServiceUnit_ListBridges_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return []*ovs.Bridge{
			{UUID: "uuid-br0", Name: "br0"},
			{UUID: "uuid-br1", Name: "br1"},
		}, nil
	})

	svc := newTestSDNService(mockClient)
	ctx := context.Background()
	req := &platformv1.ListBridgesRequest{}

	resp, err := svc.ListBridges(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Bridges, 2)
	assert.Equal(t, "uuid-br0", resp.Bridges[0].Id)
	assert.Equal(t, "uuid-br1", resp.Bridges[1].Id)
}

func TestSDNServiceUnit_ListBridges_Empty(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return []*ovs.Bridge{}, nil
	})

	svc := newTestSDNService(mockClient)
	ctx := context.Background()
	req := &platformv1.ListBridgesRequest{}

	resp, err := svc.ListBridges(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Bridges, 0)
}

func TestSDNServiceUnit_ListBridges_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return nil, errors.New("OVS list failed")
	})

	svc := newTestSDNService(mockClient)
	ctx := context.Background()
	req := &platformv1.ListBridgesRequest{}

	resp, err := svc.ListBridges(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to list bridges")
}

// =============================================================================
// AddPort Tests
// =============================================================================

func TestSDNServiceUnit_AddPort_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnAddPort(func(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
		return &ovs.Port{
			UUID:        "uuid-" + portName,
			Name:        portName,
			ExternalIDs: map[string]string{},
		}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.AddPortRequest{
		BridgeId: "br0",
		Config: &platformv1.PortConfig{
			Name: "port0",
			Type: platformv1.PortType_PORT_TYPE_INTERNAL,
		},
	}

	resp, err := svc.AddPort(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "port added successfully", resp.Status.Message)
	assert.NotNil(t, resp.Port)
	assert.Equal(t, "uuid-port0", resp.Port.Id)

	// Verify port was tracked
	assert.Contains(t, svc.ports, "port0")
}

func TestSDNServiceUnit_AddPort_WithVLAN(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	setPortVLANCalled := false
	mockClient.OnAddPort(func(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
		return &ovs.Port{UUID: "uuid-" + portName, Name: portName, ExternalIDs: map[string]string{}}, nil
	})
	mockClient.OnSetPortVLAN(func(ctx context.Context, portName string, tag int64) error {
		setPortVLANCalled = true
		assert.Equal(t, "port0", portName)
		assert.Equal(t, int64(100), tag)
		return nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.AddPortRequest{
		BridgeId: "br0",
		Config: &platformv1.PortConfig{
			Name: "port0",
			Vlan: 100,
		},
	}

	resp, err := svc.AddPort(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, setPortVLANCalled)
}

func TestSDNServiceUnit_AddPort_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnAddPort(func(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
		return nil, errors.New("OVS add port failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.AddPortRequest{
		BridgeId: "br0",
		Config: &platformv1.PortConfig{
			Name: "port0",
		},
	}

	resp, err := svc.AddPort(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to add port")

	// Verify port was not tracked
	assert.NotContains(t, svc.ports, "port0")
}

func TestSDNServiceUnit_AddPort_BridgeNotFound(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)

	ctx := context.Background()
	req := &platformv1.AddPortRequest{
		BridgeId: "nonexistent",
		Config: &platformv1.PortConfig{
			Name: "port0",
		},
	}

	resp, err := svc.AddPort(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "bridge not found")
}

// =============================================================================
// DeletePort Tests
// =============================================================================

func TestSDNServiceUnit_DeletePort_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	svc.ports["port0"] = &portResource{
		id:       "uuid-port0",
		name:     "port0",
		bridgeID: "br0",
		portType: platformv1.PortType_PORT_TYPE_INTERNAL,
	}

	ctx := context.Background()
	req := &platformv1.DeletePortRequest{
		BridgeId: "br0",
		PortId:   "port0",
	}

	resp, err := svc.DeletePort(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "port deleted successfully", resp.Status.Message)

	// Verify port was removed from tracking
	assert.NotContains(t, svc.ports, "port0")
}

func TestSDNServiceUnit_DeletePort_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnDeletePort(func(ctx context.Context, bridgeName, portName string) error {
		return errors.New("OVS delete port failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	svc.ports["port0"] = &portResource{id: "uuid-port0", name: "port0", bridgeID: "br0"}

	ctx := context.Background()
	req := &platformv1.DeletePortRequest{BridgeId: "br0", PortId: "port0"}

	resp, err := svc.DeletePort(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to delete port")

	// Port should still be tracked
	assert.Contains(t, svc.ports, "port0")
}

// =============================================================================
// GetPort Tests
// =============================================================================

func TestSDNServiceUnit_GetPort_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnGetPort(func(ctx context.Context, name string) (*ovs.Port, error) {
		return &ovs.Port{
			UUID:        "uuid-" + name,
			Name:        name,
			Tag:         100,
			ExternalIDs: map[string]string{"label": "value"},
		}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	svc.ports["port0"] = &portResource{id: "uuid-port0", name: "port0", bridgeID: "br0"}

	ctx := context.Background()
	req := &platformv1.GetPortRequest{BridgeId: "br0", PortId: "port0"}

	resp, err := svc.GetPort(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Port)
	assert.Equal(t, "uuid-port0", resp.Port.Id)
	assert.Equal(t, uint32(100), resp.Port.Config.Vlan)
}

func TestSDNServiceUnit_GetPort_NotFound(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.GetPortRequest{BridgeId: "br0", PortId: "nonexistent"}

	resp, err := svc.GetPort(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "port not found")
}

func TestSDNServiceUnit_GetPort_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnGetPort(func(ctx context.Context, name string) (*ovs.Port, error) {
		return nil, errors.New("OVS get port failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	svc.ports["port0"] = &portResource{id: "uuid-port0", name: "port0", bridgeID: "br0"}

	ctx := context.Background()
	req := &platformv1.GetPortRequest{BridgeId: "br0", PortId: "port0"}

	resp, err := svc.GetPort(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to get port")
}

func newSetPortStateTestService(mockClient *ConfigurableMockOVSClient) *SDNService {
	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	svc.ports["port0"] = &portResource{id: "uuid-port0", name: "port0", bridgeID: "br0"}
	return svc
}

func TestSDNServiceUnit_SetPortState_AppliesIngressPolicing(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newSetPortStateTestService(mockClient)

	resp, err := svc.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
		BridgeId: "br0", PortId: "port0", AdminState: "up",
		IngressRate: 10_000_000, IngressBurst: 1_000_000,
	})
	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())

	calls := mockClient.GetCalls("SetIngressPolicing")
	require.Len(t, calls, 1)
	assert.Equal(t, []interface{}{"port0", uint64(10_000_000), uint64(1_000_000)}, calls[0].Args)
}

func TestSDNServiceUnit_SetPortState_ZeroRateLeavesPolicing(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newSetPortStateTestService(mockClient)

	_, err := svc.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
		BridgeId: "br0", PortId: "port0", AdminState: "down",
	})
	require.NoError(t, err)
	assert.Empty(t, mockClient.GetCalls("SetIngressPolicing"))
	assert.Empty(t, mockClient.GetCalls("SetEgressShaping"))
}

func TestSDNServiceUnit_SetPortState_InvalidIngressPolicing(t *testing.T) {
	tests := []struct {
		name  string
		rate  uint64
		burst uint64
	}{
		{name: "rate below 1 kbps", rate: 999},
		{name: "rate not a whole kbps", rate: 1500},
		{name: "burst not a whole kb", rate: 1000, burst: 1},
		{name: "burst without a rate", burst: 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := NewConfigurableMockOVSClient()
			svc := newSetPortStateTestService(mockClient)

			_, err := svc.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
				BridgeId: "br0", PortId: "port0", AdminState: "up",
				IngressRate: tt.rate, IngressBurst: tt.burst,
			})
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Contains(t, err.Error(), "invalid ingress policing")
			// Nothing is applied when the request is refused.
			assert.Empty(t, mockClient.GetCalls("SetPortState"))
			assert.Empty(t, mockClient.GetCalls("SetIngressPolicing"))
		})
	}
}

func TestSDNServiceUnit_SetPortState_IngressPolicingErrors(t *testing.T) {
	tests := []struct {
		name     string
		ovsErr   error
		wantCode codes.Code
	}{
		{name: "interface gone", ovsErr: ovs.ErrInterfaceNotFound, wantCode: codes.NotFound},
		{name: "transaction failed", ovsErr: errors.New("ovsdb down"), wantCode: codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := NewConfigurableMockOVSClient()
			mockClient.OnSetIngressPolicing(func(context.Context, string, uint64, uint64) error {
				return tt.ovsErr
			})
			svc := newSetPortStateTestService(mockClient)

			_, err := svc.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
				BridgeId: "br0", PortId: "port0", AdminState: "up", IngressRate: 1000,
			})
			assert.Equal(t, tt.wantCode, status.Code(err))
		})
	}
}

func TestSDNServiceUnit_SetPortState_AppliesEgressShaping(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newSetPortStateTestService(mockClient)

	resp, err := svc.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
		BridgeId: "br0", PortId: "port0", AdminState: "up",
		EgressRate: 20_000_000, EgressBurst: 2_000_000,
	})
	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())

	calls := mockClient.GetCalls("SetEgressShaping")
	require.Len(t, calls, 1)
	assert.Equal(t, []interface{}{"port0", uint64(20_000_000), uint64(2_000_000)}, calls[0].Args)
	assert.Empty(t, mockClient.GetCalls("SetIngressPolicing"), "an egress rate is not an ingress rate")
}

func TestSDNServiceUnit_SetPortState_InvalidEgressShaping(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newSetPortStateTestService(mockClient)

	_, err := svc.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
		BridgeId: "br0", PortId: "port0", AdminState: "up", EgressBurst: 1000,
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "invalid egress shaping")
	// Nothing is applied when the request is refused.
	assert.Empty(t, mockClient.GetCalls("SetPortState"))
	assert.Empty(t, mockClient.GetCalls("SetEgressShaping"))
}

func TestSDNServiceUnit_SetPortState_EgressShapingErrors(t *testing.T) {
	tests := []struct {
		name     string
		ovsErr   error
		wantCode codes.Code
	}{
		{name: "port gone", ovsErr: ovs.ErrPortNotFound, wantCode: codes.NotFound},
		{name: "transaction failed", ovsErr: errors.New("ovsdb down"), wantCode: codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := NewConfigurableMockOVSClient()
			mockClient.OnSetEgressShaping(func(context.Context, string, uint64, uint64) error {
				return tt.ovsErr
			})
			svc := newSetPortStateTestService(mockClient)

			_, err := svc.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
				BridgeId: "br0", PortId: "port0", AdminState: "up", EgressRate: 1000,
			})
			assert.Equal(t, tt.wantCode, status.Code(err))
		})
	}
}

// =============================================================================
// ListPorts Tests
// =============================================================================

func TestSDNServiceUnit_ListPorts_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListPorts(func(ctx context.Context, bridgeName string) ([]*ovs.Port, error) {
		return []*ovs.Port{
			{UUID: "uuid-port0", Name: "port0", ExternalIDs: map[string]string{}},
			{UUID: "uuid-port1", Name: "port1", ExternalIDs: map[string]string{}},
		}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.ListPortsRequest{BridgeId: "br0"}

	resp, err := svc.ListPorts(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Ports, 2)
}

func TestSDNServiceUnit_ListPorts_Empty(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListPorts(func(ctx context.Context, bridgeName string) ([]*ovs.Port, error) {
		return []*ovs.Port{}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.ListPortsRequest{BridgeId: "br0"}

	resp, err := svc.ListPorts(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Ports, 0)
}

func TestSDNServiceUnit_ListPorts_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListPorts(func(ctx context.Context, bridgeName string) ([]*ovs.Port, error) {
		return nil, errors.New("OVS list ports failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.ListPortsRequest{BridgeId: "br0"}

	resp, err := svc.ListPorts(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to list ports")
}

// =============================================================================
// SetPortVLAN Tests
// =============================================================================

func TestSDNServiceUnit_CreateVLAN_WithSetPortVLANSuccess(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	setVLANCalls := []string{}
	mockClient.OnSetPortVLAN(func(ctx context.Context, portName string, tag int64) error {
		setVLANCalls = append(setVLANCalls, portName)
		return nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			BridgeId: "br0",
			VlanId:   100,
			Name:     "TestVLAN",
			Ports:    []string{"port0", "port1"},
		},
	}

	resp, err := svc.CreateVLAN(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Len(t, setVLANCalls, 2)
	assert.Contains(t, setVLANCalls, "port0")
	assert.Contains(t, setVLANCalls, "port1")
}

func TestSDNServiceUnit_CreateVLAN_SetPortVLANError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnSetPortVLAN(func(ctx context.Context, portName string, tag int64) error {
		return errors.New("set VLAN failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			BridgeId: "br0",
			VlanId:   100,
			Ports:    []string{"port0"},
		},
	}

	resp, err := svc.CreateVLAN(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to set VLAN")
}

// =============================================================================
// SetPortState Tests (via DeleteVLAN which clears VLAN tags)
// =============================================================================

func TestSDNServiceUnit_DeleteVLAN_ClearsPortVLANs(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	clearedPorts := []string{}
	mockClient.OnSetPortVLAN(func(ctx context.Context, portName string, tag int64) error {
		if tag == 0 {
			clearedPorts = append(clearedPorts, portName)
		}
		return nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	svc.vlans["br0:100"] = &vlanResource{
		id:       "vlan-1",
		vlanID:   100,
		bridgeID: "br0",
		ports:    []string{"port0", "port1"},
	}

	ctx := context.Background()
	req := &platformv1.DeleteVLANRequest{BridgeId: "br0", VlanId: 100}

	resp, err := svc.DeleteVLAN(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Len(t, clearedPorts, 2)
}

// =============================================================================
// AddFlow Tests
// =============================================================================

func TestSDNServiceUnit_AddFlow_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	var capturedFlow *ovs.FlowMod
	mockClient.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		capturedFlow = flow
		return nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.AddFlowRequest{
		Config: &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 100,
			Table:    platformv1.FlowTable_FLOW_TABLE_0,
			Match: &platformv1.FlowMatch{
				InPort: "1",
				VlanId: 100,
			},
			Actions: []*platformv1.FlowAction{
				{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: "2"},
			},
		},
	}

	resp, err := svc.AddFlow(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "flow added successfully", resp.Status.Message)
	require.NotNil(t, capturedFlow)
	assert.Equal(t, 100, capturedFlow.Priority)
	assert.Contains(t, capturedFlow.Match, "in_port=1")
	assert.Contains(t, capturedFlow.Actions, "output:2")
}

func TestSDNServiceUnit_AddFlow_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		return errors.New("OVS add flow failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.AddFlowRequest{
		Config: &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 100,
		},
	}

	resp, err := svc.AddFlow(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to add flow")
}

// =============================================================================
// DeleteFlow Tests
// =============================================================================

func TestSDNServiceUnit_DeleteFlow_Success(t *testing.T) {
	// The ID is the flow's cookie: the delete is an exact-cookie delete,
	// never a match handed to OVS.
	mockClient := NewConfigurableMockOVSClient()
	var capturedCookie, capturedMask uint64
	mockClient.OnDeleteFlowsByCookie(func(ctx context.Context, bridgeName string, cookie, mask uint64) error {
		capturedCookie, capturedMask = cookie, mask
		return nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.DeleteFlowRequest{BridgeId: "br0", FlowId: "flow-0xa9f1000000000123"}

	resp, err := svc.DeleteFlow(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, uint64(0xa9f1000000000123), capturedCookie)
	assert.Equal(t, ^uint64(0), capturedMask)
	assert.Empty(t, mockClient.calls["DeleteFlow"], "a flow ID is never a match")
}

func TestSDNServiceUnit_DeleteFlow_RefusesAnIDThatNamesNoFlow(t *testing.T) {
	// "flow-to-delete" used to reach OVS as a match the encoder emptied,
	// and the empty-match delete removed every flow on the bridge.
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	for _, id := range []string{"flow-to-delete", "flow-0", "12345"} {
		resp, err := svc.DeleteFlow(context.Background(), &platformv1.DeleteFlowRequest{BridgeId: "br0", FlowId: id})
		assert.Nil(t, resp)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "id %q", id)
	}
	assert.Empty(t, mockClient.calls["DeleteFlowsByCookie"])
	assert.Empty(t, mockClient.calls["DeleteFlow"])
}

func TestSDNServiceUnit_AddFlow_TheIDIsTheCookie(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	var installed *ovs.FlowMod
	mockClient.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		installed = flow
		return nil
	})
	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	resp, err := svc.AddFlow(context.Background(), &platformv1.AddFlowRequest{
		Config: &platformv1.FlowConfig{BridgeId: "br0", Priority: 100},
	})
	require.NoError(t, err)
	require.NotNil(t, installed)
	assert.Equal(t, "flow-"+installed.Cookie, resp.Flow.Id, "the listing renders the same ID from the cookie")
	cookie, err := ovs.ParseFlowID(resp.Flow.Id)
	require.NoError(t, err)
	assert.Equal(t, ovs.APIFlowCookieOwner, cookie&(0xFFFF<<48))
}

func TestSDNServiceUnit_DeleteFlow_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnDeleteFlowsByCookie(func(ctx context.Context, bridgeName string, cookie, mask uint64) error {
		return errors.New("OVS delete flow failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.DeleteFlowRequest{BridgeId: "br0", FlowId: "flow-123"}

	resp, err := svc.DeleteFlow(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to delete flow")
}

// =============================================================================
// ListFlows Tests
// =============================================================================

func TestSDNServiceUnit_ListFlows_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return []*ovs.Flow{
			{Table: 0, Priority: 100, Cookie: "cookie1", Match: "in_port=1", Actions: "output:2"},
			{Table: 0, Priority: 50, Cookie: "cookie2", Match: "in_port=2", Actions: "drop"},
		}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.ListFlowsRequest{BridgeId: "br0"}

	resp, err := svc.ListFlows(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Flows, 2)
}

func TestSDNServiceUnit_ListFlows_Empty(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return []*ovs.Flow{}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.ListFlowsRequest{BridgeId: "br0"}

	resp, err := svc.ListFlows(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Flows, 0)
}

func TestSDNServiceUnit_ListFlows_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return nil, errors.New("OVS list flows failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.ListFlowsRequest{BridgeId: "br0"}

	resp, err := svc.ListFlows(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to list flows")
}

// =============================================================================
// FlushFlows Tests
// =============================================================================

func TestSDNServiceUnit_FlushFlows_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return []*ovs.Flow{{}, {}, {}}, nil // 3 flows
	})
	mockClient.OnDeleteAllFlows(func(ctx context.Context, bridgeName string) error {
		return nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.FlushFlowsRequest{BridgeId: "br0"}

	resp, err := svc.FlushFlows(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, uint32(3), resp.DeletedCount)
}

func TestSDNServiceUnit_FlushFlows_ListError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return nil, errors.New("list failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.FlushFlowsRequest{BridgeId: "br0"}

	resp, err := svc.FlushFlows(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestSDNServiceUnit_FlushFlows_DeleteError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return []*ovs.Flow{{}}, nil
	})
	mockClient.OnDeleteAllFlows(func(ctx context.Context, bridgeName string) error {
		return errors.New("delete failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.FlushFlowsRequest{BridgeId: "br0"}

	resp, err := svc.FlushFlows(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to flush flows")
}

// =============================================================================
// Connect and Disconnect Tests
// =============================================================================

func TestSDNServiceUnit_Connect_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)

	ctx := context.Background()
	err := svc.Connect(ctx)

	require.NoError(t, err)
	assert.Equal(t, 1, mockClient.GetCallCount("Connect"))
}

func TestSDNServiceUnit_Connect_Error(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnConnect(func(ctx context.Context) error {
		return errors.New("connection refused")
	})

	svc := newTestSDNService(mockClient)
	ctx := context.Background()

	err := svc.Connect(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to OVS")
}

func TestSDNServiceUnit_Disconnect_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)

	err := svc.Disconnect()

	require.NoError(t, err)
	assert.Equal(t, 1, mockClient.GetCallCount("Disconnect"))
}

func TestSDNServiceUnit_Disconnect_Error(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnDisconnect(func() error {
		return errors.New("disconnect failed")
	})

	svc := newTestSDNService(mockClient)

	err := svc.Disconnect()

	assert.Error(t, err)
	assert.Equal(t, "disconnect failed", err.Error())
}

// =============================================================================
// GetPortStats Tests
// =============================================================================

func TestSDNServiceUnit_GetPortStats_Success(t *testing.T) {
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
				"rx_errors":  5,
				"tx_errors":  10,
				"rx_dropped": 1,
				"tx_dropped": 2,
			},
		}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	svc.ports["port0"] = &portResource{id: "uuid-port0", name: "port0", bridgeID: "br0"}

	ctx := context.Background()
	req := &platformv1.GetPortStatsRequest{BridgeId: "br0", PortId: "port0"}

	resp, err := svc.GetPortStats(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Stats)
	assert.Equal(t, uint64(1000), resp.Stats.PacketsReceived)
	assert.Equal(t, uint64(2000), resp.Stats.PacketsSent)
	assert.Equal(t, uint64(100000), resp.Stats.BytesReceived)
	assert.Equal(t, uint64(200000), resp.Stats.BytesSent)
	assert.Equal(t, uint64(15), resp.Stats.Errors) // 5 + 10
	assert.Equal(t, uint64(3), resp.Stats.Dropped) // 1 + 2
}

func TestSDNServiceUnit_GetPortStats_PortNotFound(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.GetPortStatsRequest{BridgeId: "br0", PortId: "nonexistent"}

	resp, err := svc.GetPortStats(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "port not found")
}

func TestSDNServiceUnit_GetPortStats_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnGetInterface(func(ctx context.Context, name string) (*ovs.Interface, error) {
		return nil, errors.New("interface not found")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	svc.ports["port0"] = &portResource{id: "uuid-port0", name: "port0", bridgeID: "br0"}

	ctx := context.Background()
	req := &platformv1.GetPortStatsRequest{BridgeId: "br0", PortId: "port0"}

	resp, err := svc.GetPortStats(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to get interface")
}

// =============================================================================
// GetFlowStats Tests
// =============================================================================

func TestSDNServiceUnit_GetFlowStats_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	var query string
	mockClient.OnGetFlowStats(func(ctx context.Context, bridgeName string, match string) ([]*ovs.Flow, error) {
		query = match
		return []*ovs.Flow{
			{
				Cookie:      "0x7b",
				PacketCount: 5000,
				ByteCount:   500000,
				Duration:    7200,
			},
		}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.GetFlowStatsRequest{BridgeId: "br0", FlowId: "flow-123"}

	resp, err := svc.GetFlowStats(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Stats)
	assert.Equal(t, uint64(5000), resp.Stats.PacketCount)
	assert.Equal(t, uint64(500000), resp.Stats.ByteCount)
	assert.Equal(t, uint32(7200), resp.Stats.DurationSeconds)
	assert.Equal(t, "cookie=0x7b/0xffffffffffffffff", query, "the request is scoped to the flow's own cookie")
}

func TestSDNServiceUnit_GetFlowStats_RefusesAnIDThatNamesNoFlow(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	resp, err := svc.GetFlowStats(context.Background(), &platformv1.GetFlowStatsRequest{BridgeId: "br0", FlowId: "in_port=1"})
	assert.Nil(t, resp)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, mockClient.calls["GetFlowStats"])
}

func TestSDNServiceUnit_GetFlowStats_NotFound(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnGetFlowStats(func(ctx context.Context, bridgeName string, match string) ([]*ovs.Flow, error) {
		return []*ovs.Flow{}, nil // Empty result
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.GetFlowStatsRequest{BridgeId: "br0", FlowId: "flow-0x99"}

	resp, err := svc.GetFlowStats(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "flow not found")
}

func TestSDNServiceUnit_GetFlowStats_OVSError(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnGetFlowStats(func(ctx context.Context, bridgeName string, match string) ([]*ovs.Flow, error) {
		return nil, errors.New("stats query failed")
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.GetFlowStatsRequest{BridgeId: "br0", FlowId: "flow-123"}

	resp, err := svc.GetFlowStats(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to get flow stats")
}

// =============================================================================
// StreamFlowLogs Tests
// =============================================================================

type mockFlowLogsServer struct {
	platformv1.SDNService_StreamFlowLogsServer
	ctx       context.Context
	cancel    context.CancelFunc
	entries   []*platformv1.FlowLogEntry
	mu        sync.Mutex
	sendCount int
}

func newMockFlowLogsServer() *mockFlowLogsServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &mockFlowLogsServer{
		ctx:     ctx,
		cancel:  cancel,
		entries: make([]*platformv1.FlowLogEntry, 0),
	}
}

func (m *mockFlowLogsServer) Send(entry *platformv1.FlowLogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, entry)
	m.sendCount++
	if m.sendCount >= 3 { // Cancel after receiving a few entries
		m.cancel()
	}
	return nil
}

func (m *mockFlowLogsServer) Context() context.Context {
	return m.ctx
}

func TestSDNServiceUnit_StreamFlowLogs_Success(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		return []*ovs.Flow{
			{Cookie: "flow-1", Actions: "output:1", ByteCount: 1000},
			{Cookie: "flow-2", Actions: "output:2", ByteCount: 2000},
		}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	req := &platformv1.StreamFlowLogsRequest{BridgeId: "br0"}
	stream := newMockFlowLogsServer()

	// Run StreamFlowLogs in a goroutine since it blocks
	done := make(chan error, 1)
	go func() {
		done <- svc.StreamFlowLogs(req, stream)
	}()

	// Wait for stream to complete or timeout
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("StreamFlowLogs timed out")
	}

	// Verify entries were sent
	stream.mu.Lock()
	assert.GreaterOrEqual(t, len(stream.entries), 2)
	stream.mu.Unlock()
}

func TestSDNServiceUnit_StreamFlowLogs_BridgeNotFound(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)

	req := &platformv1.StreamFlowLogsRequest{BridgeId: "nonexistent"}

	err := svc.StreamFlowLogs(req, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bridge not found")
}

// =============================================================================
// WithOVSClient Option Tests
// =============================================================================

func TestSDNServiceUnit_WithOVSClient(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	opt := WithOVSClient(mockClient)

	svc := &SDNService{
		bridges:   make(map[string]*bridgeResource),
		ports:     make(map[string]*portResource),
		taps:      make(map[string]*tapResource),
		vlans:     make(map[string]*vlanResource),
		portAuths: make(map[string]*portAuthResource),
	}
	opt(svc)

	assert.Equal(t, mockClient, svc.ovsClient)
}

func TestSDNServiceUnit_OVSClient_Getter(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)

	client := svc.OVSClient()

	assert.Equal(t, mockClient, client)
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestSDNServiceUnit_ConcurrentBridgeAccess(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnCreateBridge(func(ctx context.Context, name string) (*ovs.Bridge, error) {
		return &ovs.Bridge{UUID: "uuid-" + name, Name: name}, nil
	})
	mockClient.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return []*ovs.Bridge{}, nil
	})

	svc := newTestSDNService(mockClient)
	ctx := context.Background()

	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent creates
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := &platformv1.CreateBridgeRequest{
				Config: &platformv1.BridgeConfig{
					Name: "br" + string(rune('0'+idx)),
				},
			}
			_, _ = svc.CreateBridge(ctx, req)
		}(i)
	}

	// Concurrent lists
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &platformv1.ListBridgesRequest{}
			_, _ = svc.ListBridges(ctx, req)
		}()
	}

	wg.Wait()

	// Verify no panics occurred and some bridges were created
	assert.GreaterOrEqual(t, len(svc.bridges), 1)
}

func TestSDNServiceUnit_ConcurrentPortAccess(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnAddPort(func(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
		return &ovs.Port{UUID: "uuid-" + portName, Name: portName, ExternalIDs: map[string]string{}}, nil
	})
	mockClient.OnListPorts(func(ctx context.Context, bridgeName string) ([]*ovs.Port, error) {
		return []*ovs.Port{}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	ctx := context.Background()

	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent port adds
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := &platformv1.AddPortRequest{
				BridgeId: "br0",
				Config: &platformv1.PortConfig{
					Name: "port" + string(rune('0'+idx)),
				},
			}
			_, _ = svc.AddPort(ctx, req)
		}(i)
	}

	// Concurrent port lists
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &platformv1.ListPortsRequest{BridgeId: "br0"}
			_, _ = svc.ListPorts(ctx, req)
		}()
	}

	wg.Wait()

	// Verify no panics occurred
	assert.GreaterOrEqual(t, len(svc.ports), 1)
}

// =============================================================================
// Mock Client Tests
// =============================================================================

func TestMockOVSClient_RecordsCalls(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	ctx := context.Background()

	mock.CreateBridge(ctx, "br0")
	mock.CreateBridge(ctx, "br1")
	mock.GetBridge(ctx, "br0")
	mock.ListBridges(ctx)

	assert.Equal(t, 2, mock.GetCallCount("CreateBridge"))
	assert.Equal(t, 1, mock.GetCallCount("GetBridge"))
	assert.Equal(t, 1, mock.GetCallCount("ListBridges"))
	assert.Equal(t, 0, mock.GetCallCount("DeleteBridge"))

	calls := mock.GetCalls("CreateBridge")
	assert.Len(t, calls, 2)
	assert.Equal(t, "br0", calls[0].Args[0])
	assert.Equal(t, "br1", calls[1].Args[0])
}

func TestMockOVSClient_Reset(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	ctx := context.Background()

	mock.CreateBridge(ctx, "br0")
	mock.Connect(ctx)

	assert.Equal(t, 1, mock.GetCallCount("CreateBridge"))
	assert.True(t, mock.IsConnected())

	mock.Reset()

	assert.Equal(t, 0, mock.GetCallCount("CreateBridge"))
	assert.False(t, mock.IsConnected())
}

func TestMockOVSClient_ConnectionState(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	ctx := context.Background()

	assert.False(t, mock.IsConnected())

	mock.Connect(ctx)
	assert.True(t, mock.IsConnected())

	mock.Disconnect()
	assert.False(t, mock.IsConnected())

	mock.Connect(ctx)
	assert.True(t, mock.IsConnected())

	mock.Close()
	assert.False(t, mock.IsConnected())
}

func TestMockOVSClient_ConcurrentSafe(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			mock.CreateBridge(ctx, "br"+string(rune('0'+idx%10)))
			mock.GetCallCount("CreateBridge")
			mock.GetCalls("CreateBridge")
		}(i)
	}

	wg.Wait()

	assert.Equal(t, 100, mock.GetCallCount("CreateBridge"))
}

// =============================================================================
// Additional Edge Cases
// =============================================================================

func TestSDNServiceUnit_DeleteBridge_WithByName(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)
	svc.bridges["br-test"] = &bridgeResource{id: "uuid-br-test", name: "br-test"}

	ctx := context.Background()
	req := &platformv1.DeleteBridgeRequest{Id: "br-test"} // Using name as ID

	resp, err := svc.DeleteBridge(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.NotContains(t, svc.bridges, "br-test")
}

func TestSDNServiceUnit_AddPort_ByBridgeUUID(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnAddPort(func(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
		return &ovs.Port{UUID: "uuid-" + portName, Name: portName, ExternalIDs: map[string]string{}}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.AddPortRequest{
		BridgeId: "uuid-br0", // Using UUID instead of name
		Config: &platformv1.PortConfig{
			Name: "port0",
		},
	}

	resp, err := svc.AddPort(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
}

func TestSDNServiceUnit_GetBridge_ByUUID(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	mockClient.OnGetBridge(func(ctx context.Context, name string) (*ovs.Bridge, error) {
		return &ovs.Bridge{UUID: "uuid-" + name, Name: name}, nil
	})

	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	ctx := context.Background()
	req := &platformv1.GetBridgeRequest{Id: "uuid-br0"} // Using UUID

	resp, err := svc.GetBridge(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestSDNServiceUnit_DeletePort_ByUUID(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	svc.ports["port0"] = &portResource{
		id:       "uuid-port0",
		name:     "port0",
		bridgeID: "uuid-br0",
	}

	ctx := context.Background()
	req := &platformv1.DeletePortRequest{
		BridgeId: "uuid-br0",
		PortId:   "uuid-port0", // Using UUID
	}

	resp, err := svc.DeletePort(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
}
