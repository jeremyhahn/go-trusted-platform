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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewSDNService(t *testing.T) {
	tests := []struct {
		name          string
		socketPath    string
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid socket path",
			socketPath:  "unix:/var/run/openvswitch/db.sock",
			expectError: false,
		},
		{
			name:          "invalid socket path",
			socketPath:    "",
			expectError:   true,
			errorContains: "socket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := NewSDNService(tt.socketPath)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, svc)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, svc)
				assert.NotNil(t, svc.ovsClient)
				assert.NotNil(t, svc.netlinkManager)
				assert.NotNil(t, svc.bridges)
				assert.NotNil(t, svc.ports)
				assert.NotNil(t, svc.taps)
			}
		})
	}
}

func TestSDNService_CreateBridge_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
	}

	tests := []struct {
		name          string
		req           *platformv1.CreateBridgeRequest
		errorContains string
	}{
		{
			name:          "nil config",
			req:           &platformv1.CreateBridgeRequest{},
			errorContains: "config is required",
		},
		{
			name: "empty bridge name",
			req: &platformv1.CreateBridgeRequest{
				Config: &platformv1.BridgeConfig{
					Name: "",
				},
			},
			errorContains: "bridge name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := svc.CreateBridge(ctx, tt.req)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_CreateBridge_AlreadyExists(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}

	// Add existing bridge
	svc.bridges["br0"] = &bridgeResource{
		id:         "uuid-1",
		name:       "br0",
		bridgeType: platformv1.BridgeType_BRIDGE_TYPE_OVS,
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
}

func TestSDNService_DeleteBridge_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
	}

	tests := []struct {
		name          string
		req           *platformv1.DeleteBridgeRequest
		errorContains string
	}{
		{
			name:          "empty id",
			req:           &platformv1.DeleteBridgeRequest{Id: ""},
			errorContains: "bridge id or name is required",
		},
		{
			name:          "bridge not found",
			req:           &platformv1.DeleteBridgeRequest{Id: "nonexistent"},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := svc.DeleteBridge(ctx, tt.req)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_GetBridge_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
	}

	tests := []struct {
		name          string
		req           *platformv1.GetBridgeRequest
		errorContains string
	}{
		{
			name:          "empty id",
			req:           &platformv1.GetBridgeRequest{Id: ""},
			errorContains: "bridge id or name is required",
		},
		{
			name:          "bridge not found",
			req:           &platformv1.GetBridgeRequest{Id: "nonexistent"},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := svc.GetBridge(ctx, tt.req)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_AddPort_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
	}

	tests := []struct {
		name          string
		req           *platformv1.AddPortRequest
		errorContains string
	}{
		{
			name:          "empty bridge id",
			req:           &platformv1.AddPortRequest{BridgeId: ""},
			errorContains: "bridge_id is required",
		},
		{
			name: "nil config",
			req: &platformv1.AddPortRequest{
				BridgeId: "br0",
				Config:   nil,
			},
			errorContains: "config is required",
		},
		{
			name: "empty port name",
			req: &platformv1.AddPortRequest{
				BridgeId: "br0",
				Config: &platformv1.PortConfig{
					Name: "",
				},
			},
			errorContains: "port name is required",
		},
		{
			name: "bridge not found",
			req: &platformv1.AddPortRequest{
				BridgeId: "nonexistent",
				Config: &platformv1.PortConfig{
					Name: "port0",
				},
			},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := svc.AddPort(ctx, tt.req)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_DeletePort_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
	}

	tests := []struct {
		name          string
		req           *platformv1.DeletePortRequest
		errorContains string
	}{
		{
			name:          "empty bridge id",
			req:           &platformv1.DeletePortRequest{BridgeId: ""},
			errorContains: "bridge_id is required",
		},
		{
			name: "empty port id",
			req: &platformv1.DeletePortRequest{
				BridgeId: "br0",
				PortId:   "",
			},
			errorContains: "port_id is required",
		},
		{
			name: "bridge not found",
			req: &platformv1.DeletePortRequest{
				BridgeId: "nonexistent",
				PortId:   "port0",
			},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := svc.DeletePort(ctx, tt.req)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_DeletePort_PortNotFound(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}

	// Add a bridge but no ports
	svc.bridges["br0"] = &bridgeResource{
		id:         "uuid-1",
		name:       "br0",
		bridgeType: platformv1.BridgeType_BRIDGE_TYPE_OVS,
	}

	ctx := context.Background()

	req := &platformv1.DeletePortRequest{
		BridgeId: "br0",
		PortId:   "nonexistent-port",
	}

	resp, err := svc.DeletePort(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "port not found")
}

func TestSDNService_GetPort_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
	}

	tests := []struct {
		name          string
		req           *platformv1.GetPortRequest
		errorContains string
	}{
		{
			name:          "empty bridge id",
			req:           &platformv1.GetPortRequest{BridgeId: ""},
			errorContains: "bridge_id is required",
		},
		{
			name: "empty port id",
			req: &platformv1.GetPortRequest{
				BridgeId: "br0",
				PortId:   "",
			},
			errorContains: "port_id is required",
		},
		{
			name: "port not found",
			req: &platformv1.GetPortRequest{
				BridgeId: "br0",
				PortId:   "nonexistent",
			},
			errorContains: "port not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := svc.GetPort(ctx, tt.req)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_ListPorts_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
	}

	tests := []struct {
		name          string
		req           *platformv1.ListPortsRequest
		errorContains string
	}{
		{
			name:          "empty bridge id",
			req:           &platformv1.ListPortsRequest{BridgeId: ""},
			errorContains: "bridge_id is required",
		},
		{
			name:          "bridge not found",
			req:           &platformv1.ListPortsRequest{BridgeId: "nonexistent"},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := svc.ListPorts(ctx, tt.req)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_AddFlow_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
	}

	tests := []struct {
		name          string
		req           *platformv1.AddFlowRequest
		errorContains string
	}{
		{
			name:          "nil config",
			req:           &platformv1.AddFlowRequest{},
			errorContains: "config is required",
		},
		{
			name: "empty bridge id",
			req: &platformv1.AddFlowRequest{
				Config: &platformv1.FlowConfig{
					BridgeId: "",
				},
			},
			errorContains: "bridge_id is required",
		},
		{
			name: "bridge not found",
			req: &platformv1.AddFlowRequest{
				Config: &platformv1.FlowConfig{
					BridgeId: "nonexistent",
				},
			},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := svc.AddFlow(ctx, tt.req)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_DeleteFlow_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
	}

	tests := []struct {
		name          string
		req           *platformv1.DeleteFlowRequest
		errorContains string
	}{
		{
			name:          "empty bridge id",
			req:           &platformv1.DeleteFlowRequest{BridgeId: ""},
			errorContains: "bridge_id is required",
		},
		{
			name: "empty flow id",
			req: &platformv1.DeleteFlowRequest{
				BridgeId: "br0",
				FlowId:   "",
			},
			errorContains: "flow_id is required",
		},
		{
			name: "bridge not found",
			req: &platformv1.DeleteFlowRequest{
				BridgeId: "nonexistent",
				FlowId:   "flow0",
			},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := svc.DeleteFlow(ctx, tt.req)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_ListFlows_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
	}

	tests := []struct {
		name          string
		req           *platformv1.ListFlowsRequest
		errorContains string
	}{
		{
			name:          "empty bridge id",
			req:           &platformv1.ListFlowsRequest{BridgeId: ""},
			errorContains: "bridge_id is required",
		},
		{
			name:          "bridge not found",
			req:           &platformv1.ListFlowsRequest{BridgeId: "nonexistent"},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := svc.ListFlows(ctx, tt.req)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_FlushFlows_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}

	ctx := context.Background()

	tests := []struct {
		name          string
		req           *platformv1.FlushFlowsRequest
		errorContains string
	}{
		{
			name:          "empty bridge id",
			req:           &platformv1.FlushFlowsRequest{BridgeId: ""},
			errorContains: "bridge_id is required",
		},
		{
			name:          "bridge not found",
			req:           &platformv1.FlushFlowsRequest{BridgeId: "nonexistent"},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.FlushFlows(ctx, tt.req)
			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_CreateVLAN_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}

	ctx := context.Background()

	tests := []struct {
		name          string
		req           *platformv1.CreateVLANRequest
		errorContains string
	}{
		{
			name:          "nil config",
			req:           &platformv1.CreateVLANRequest{},
			errorContains: "config is required",
		},
		{
			name: "empty bridge id",
			req: &platformv1.CreateVLANRequest{
				Config: &platformv1.VLANConfig{
					BridgeId: "",
					VlanId:   100,
				},
			},
			errorContains: "bridge_id is required",
		},
		{
			name: "invalid vlan id zero",
			req: &platformv1.CreateVLANRequest{
				Config: &platformv1.VLANConfig{
					BridgeId: "br0",
					VlanId:   0,
				},
			},
			errorContains: "vlan_id must be between 1 and 4095",
		},
		{
			name: "invalid vlan id too high",
			req: &platformv1.CreateVLANRequest{
				Config: &platformv1.VLANConfig{
					BridgeId: "br0",
					VlanId:   5000,
				},
			},
			errorContains: "vlan_id must be between 1 and 4095",
		},
		{
			name: "bridge not found",
			req: &platformv1.CreateVLANRequest{
				Config: &platformv1.VLANConfig{
					BridgeId: "nonexistent",
					VlanId:   100,
				},
			},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.CreateVLAN(ctx, tt.req)
			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_DeleteVLAN_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}

	ctx := context.Background()

	tests := []struct {
		name          string
		req           *platformv1.DeleteVLANRequest
		errorContains string
	}{
		{
			name:          "empty bridge id",
			req:           &platformv1.DeleteVLANRequest{BridgeId: "", VlanId: 100},
			errorContains: "bridge_id is required",
		},
		{
			name:          "invalid vlan id zero",
			req:           &platformv1.DeleteVLANRequest{BridgeId: "br0", VlanId: 0},
			errorContains: "vlan_id must be between 1 and 4095",
		},
		{
			name:          "bridge not found",
			req:           &platformv1.DeleteVLANRequest{BridgeId: "nonexistent", VlanId: 100},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.DeleteVLAN(ctx, tt.req)
			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_ListVLANs_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}

	ctx := context.Background()

	tests := []struct {
		name          string
		req           *platformv1.ListVLANsRequest
		errorContains string
	}{
		{
			name:          "empty bridge id",
			req:           &platformv1.ListVLANsRequest{BridgeId: ""},
			errorContains: "bridge_id is required",
		},
		{
			name:          "bridge not found",
			req:           &platformv1.ListVLANsRequest{BridgeId: "nonexistent"},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.ListVLANs(ctx, tt.req)
			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_ListVLANs_Success(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}

	// Add a bridge
	svc.bridges["br0"] = &bridgeResource{
		id:         "uuid-1",
		name:       "br0",
		bridgeType: platformv1.BridgeType_BRIDGE_TYPE_OVS,
	}

	// Add VLANs
	svc.vlans["br0:100"] = &vlanResource{
		id:        "vlan-1",
		vlanID:    100,
		bridgeID:  "br0",
		name:      "Engineering",
		ports:     []string{"port1", "port2"},
		createdAt: time.Now(),
	}
	svc.vlans["br0:200"] = &vlanResource{
		id:        "vlan-2",
		vlanID:    200,
		bridgeID:  "br0",
		name:      "Marketing",
		ports:     []string{"port3"},
		createdAt: time.Now(),
	}

	ctx := context.Background()

	req := &platformv1.ListVLANsRequest{
		BridgeId: "br0",
	}

	resp, err := svc.ListVLANs(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.Vlans, 2)
}

// TestSDNService_PortAuthRefused pins port authentication to a typed
// FailedPrecondition refusal (#304). Before it, a self-signed certificate on a
// known port answered "port authenticated successfully" and the switch never
// admitted or blocked the port.
func TestSDNService_PortAuthRefused(t *testing.T) {
	svc := &SDNService{
		bridges: map[string]*bridgeResource{"br0": {id: "uuid-1", name: "br0"}},
		ports:   map[string]*portResource{"port0": {id: "uuid-2", name: "port0", bridgeID: "br0"}},
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}
	selfSigned := generateTestCertificate(t, time.Now().Add(-24*time.Hour), time.Now().Add(24*time.Hour))

	calls := map[string]func() (interface{}, error){
		"AuthenticatePort": func() (interface{}, error) {
			return svc.AuthenticatePort(context.Background(), &platformv1.AuthenticatePortRequest{
				BridgeId: "br0", PortId: "port0", Certificate: selfSigned,
			})
		},
		"RevokePortAuth": func() (interface{}, error) {
			return svc.RevokePortAuth(context.Background(), &platformv1.RevokePortAuthRequest{
				BridgeId: "br0", PortId: "port0",
			})
		},
	}

	for operation, call := range calls {
		t.Run(operation, func(t *testing.T) {
			resp, err := call()
			var refusal policy.ErrPortAuthNotEnforced
			require.ErrorAs(t, err, &refusal)
			assert.Equal(t, operation, refusal.Operation)
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.Nil(t, resp)
		})
	}
}

func TestSDNService_GetPortStats_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}

	ctx := context.Background()

	tests := []struct {
		name          string
		req           *platformv1.GetPortStatsRequest
		errorContains string
	}{
		{
			name:          "empty bridge id",
			req:           &platformv1.GetPortStatsRequest{BridgeId: "", PortId: "port0"},
			errorContains: "bridge_id is required",
		},
		{
			name:          "empty port id",
			req:           &platformv1.GetPortStatsRequest{BridgeId: "br0", PortId: ""},
			errorContains: "port_id is required",
		},
		{
			name:          "port not found",
			req:           &platformv1.GetPortStatsRequest{BridgeId: "br0", PortId: "nonexistent"},
			errorContains: "port not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.GetPortStats(ctx, tt.req)
			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_GetFlowStats_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}

	ctx := context.Background()

	tests := []struct {
		name          string
		req           *platformv1.GetFlowStatsRequest
		errorContains string
	}{
		{
			name:          "empty bridge id",
			req:           &platformv1.GetFlowStatsRequest{BridgeId: "", FlowId: "flow0"},
			errorContains: "bridge_id is required",
		},
		{
			name:          "empty flow id",
			req:           &platformv1.GetFlowStatsRequest{BridgeId: "br0", FlowId: ""},
			errorContains: "flow_id is required",
		},
		{
			name:          "bridge not found",
			req:           &platformv1.GetFlowStatsRequest{BridgeId: "nonexistent", FlowId: "flow0"},
			errorContains: "bridge not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.GetFlowStats(ctx, tt.req)
			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSDNService_StreamFlowLogs_ValidationErrors(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}

	t.Run("empty bridge id", func(t *testing.T) {
		req := &platformv1.StreamFlowLogsRequest{BridgeId: ""}
		err := svc.StreamFlowLogs(req, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bridge_id is required")
	})

	t.Run("bridge not found", func(t *testing.T) {
		req := &platformv1.StreamFlowLogsRequest{BridgeId: "nonexistent"}
		err := svc.StreamFlowLogs(req, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bridge not found")
	})
}

func TestSDNService_VLANAlreadyExists(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}

	// Add a bridge
	svc.bridges["br0"] = &bridgeResource{
		id:         "uuid-1",
		name:       "br0",
		bridgeType: platformv1.BridgeType_BRIDGE_TYPE_OVS,
	}

	// Add existing VLAN
	svc.vlans["br0:100"] = &vlanResource{
		id:       "vlan-1",
		vlanID:   100,
		bridgeID: "br0",
	}

	ctx := context.Background()

	req := &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			BridgeId: "br0",
			VlanId:   100,
		},
	}

	resp, err := svc.CreateVLAN(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "VLAN already exists")
}

func TestSDNService_DeleteVLAN_NotFound(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}

	// Add a bridge
	svc.bridges["br0"] = &bridgeResource{
		id:         "uuid-1",
		name:       "br0",
		bridgeType: platformv1.BridgeType_BRIDGE_TYPE_OVS,
	}

	ctx := context.Background()

	req := &platformv1.DeleteVLANRequest{
		BridgeId: "br0",
		VlanId:   100,
	}

	resp, err := svc.DeleteVLAN(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "VLAN not found")
}

func TestSDNService_ConversionHelpers(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
	}

	t.Run("pbToOvsFlowMod", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 100,
			Table:    platformv1.FlowTable_FLOW_TABLE_0,
			Match: &platformv1.FlowMatch{
				InPort: "1",
				VlanId: 10,
				EthSrc: "00:11:22:33:44:55",
				EthDst: "66:77:88:99:aa:bb",
			},
			Actions: []*platformv1.FlowAction{
				{
					Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT,
					Port: "2",
				},
				{
					Type:   platformv1.FlowActionType_FLOW_ACTION_SET_VLAN,
					VlanId: 20,
				},
				{
					Type: platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN,
				},
				{
					Type: platformv1.FlowActionType_FLOW_ACTION_DROP,
				},
			},
		}

		flowMod, err := svc.pbToOvsFlowMod(config)
		require.NoError(t, err)

		require.NotNil(t, flowMod)
		assert.Equal(t, 100, flowMod.Priority)
		assert.Equal(t, int(platformv1.FlowTable_FLOW_TABLE_0), flowMod.Table)
		assert.Contains(t, flowMod.Match, "in_port=1")
		assert.Contains(t, flowMod.Match, "dl_vlan=10")
		assert.Contains(t, flowMod.Match, "dl_src=00:11:22:33:44:55")
		assert.Contains(t, flowMod.Match, "dl_dst=66:77:88:99:aa:bb")
		assert.Contains(t, flowMod.Actions, "output:2")
		assert.Contains(t, flowMod.Actions, "mod_vlan_vid:20")
		assert.Contains(t, flowMod.Actions, "strip_vlan")
		assert.Contains(t, flowMod.Actions, "drop")
	})

	t.Run("pbToOvsFlowMod with nil match", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 100,
		}

		flowMod, err := svc.pbToOvsFlowMod(config)
		require.NoError(t, err)

		require.NotNil(t, flowMod)
		assert.Equal(t, 100, flowMod.Priority)
	})
}

func TestSDNService_ResourceTracking(t *testing.T) {
	svc := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
		taps:    make(map[string]*tapResource),
	}

	t.Run("track bridge", func(t *testing.T) {
		svc.bridges["br0"] = &bridgeResource{
			id:         "uuid-1",
			name:       "br0",
			bridgeType: platformv1.BridgeType_BRIDGE_TYPE_OVS,
		}

		assert.Len(t, svc.bridges, 1)
		assert.Contains(t, svc.bridges, "br0")
		assert.Equal(t, "uuid-1", svc.bridges["br0"].id)
	})

	t.Run("track port", func(t *testing.T) {
		svc.ports["port0"] = &portResource{
			id:       "uuid-2",
			name:     "port0",
			bridgeID: "br0",
			portType: platformv1.PortType_PORT_TYPE_TAP,
		}

		assert.Len(t, svc.ports, 1)
		assert.Contains(t, svc.ports, "port0")
		assert.Equal(t, "uuid-2", svc.ports["port0"].id)
	})

	t.Run("track tap", func(t *testing.T) {
		svc.taps["tap0"] = &tapResource{
			name: "tap0",
		}

		assert.Len(t, svc.taps, 1)
		assert.Contains(t, svc.taps, "tap0")
	})
}

// generateTestCertificate generates a self-signed certificate for testing
func generateTestCertificate(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM
}
