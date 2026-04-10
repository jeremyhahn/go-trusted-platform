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

package main

import (
	"log/slog"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

// SDNBinding exposes SDN service methods to the Wails frontend.
type SDNBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewSDNBinding creates a new SDNBinding.
func NewSDNBinding(logger *slog.Logger, conn *ConnectionBinding) *SDNBinding {
	return &SDNBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *SDNBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// CreateBridge creates a new OVS bridge with the given name and MTU.
func (b *SDNBinding) CreateBridge(name string, mtu uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().CreateBridge(b.conn.ctx, &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{
			Name: name,
			Mtu:  mtu,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteBridge deletes a bridge by ID.
func (b *SDNBinding) DeleteBridge(id string, force bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().DeleteBridge(b.conn.ctx, &platformv1.DeleteBridgeRequest{
		Id:    id,
		Force: force,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetBridge returns a bridge by ID.
func (b *SDNBinding) GetBridge(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().GetBridge(b.conn.ctx, &platformv1.GetBridgeRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListBridges returns all bridges.
func (b *SDNBinding) ListBridges() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().ListBridges(b.conn.ctx, &platformv1.ListBridgesRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// AddPort adds a port to a bridge.
func (b *SDNBinding) AddPort(bridgeID, portName string, vlan uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().AddPort(b.conn.ctx, &platformv1.AddPortRequest{
		BridgeId: bridgeID,
		Config: &platformv1.PortConfig{
			Name: portName,
			Vlan: vlan,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeletePort removes a port from a bridge.
func (b *SDNBinding) DeletePort(bridgeID, portID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().DeletePort(b.conn.ctx, &platformv1.DeletePortRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetPort returns a port by bridge and port ID.
func (b *SDNBinding) GetPort(bridgeID, portID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().GetPort(b.conn.ctx, &platformv1.GetPortRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListPorts returns all ports on a bridge.
func (b *SDNBinding) ListPorts(bridgeID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().ListPorts(b.conn.ctx, &platformv1.ListPortsRequest{
		BridgeId: bridgeID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// AddFlow adds a flow rule to a bridge.
func (b *SDNBinding) AddFlow(bridgeID string, table int32, priority uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().AddFlow(b.conn.ctx, &platformv1.AddFlowRequest{
		Config: &platformv1.FlowConfig{
			BridgeId: bridgeID,
			Table:    platformv1.FlowTable(table),
			Priority: priority,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteFlow removes a flow rule from a bridge.
func (b *SDNBinding) DeleteFlow(bridgeID, flowID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().DeleteFlow(b.conn.ctx, &platformv1.DeleteFlowRequest{
		BridgeId: bridgeID,
		FlowId:   flowID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListFlows returns all flows on a bridge, optionally filtered by table.
func (b *SDNBinding) ListFlows(bridgeID string, table int32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().ListFlows(b.conn.ctx, &platformv1.ListFlowsRequest{
		BridgeId: bridgeID,
		Table:    platformv1.FlowTable(table),
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// FlushFlows removes all flows from a bridge table.
func (b *SDNBinding) FlushFlows(bridgeID string, table int32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().FlushFlows(b.conn.ctx, &platformv1.FlushFlowsRequest{
		BridgeId: bridgeID,
		Table:    platformv1.FlowTable(table),
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// CreateVLAN creates a VLAN on a bridge.
func (b *SDNBinding) CreateVLAN(bridgeID, name string, vlanID uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().CreateVLAN(b.conn.ctx, &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			BridgeId: bridgeID,
			Name:     name,
			VlanId:   vlanID,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteVLAN removes a VLAN from a bridge.
func (b *SDNBinding) DeleteVLAN(bridgeID string, vlanID uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().DeleteVLAN(b.conn.ctx, &platformv1.DeleteVLANRequest{
		BridgeId: bridgeID,
		VlanId:   vlanID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListVLANs returns all VLANs on a bridge.
func (b *SDNBinding) ListVLANs(bridgeID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().ListVLANs(b.conn.ctx, &platformv1.ListVLANsRequest{
		BridgeId: bridgeID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// AuthenticatePort authenticates a port using an x509 certificate.
func (b *SDNBinding) AuthenticatePort(bridgeID, portID string, certificate []byte, format string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().AuthenticatePort(b.conn.ctx, &platformv1.AuthenticatePortRequest{
		BridgeId:    bridgeID,
		PortId:      portID,
		Certificate: certificate,
		Format:      format,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// RevokePortAuth revokes authentication for a port.
func (b *SDNBinding) RevokePortAuth(bridgeID, portID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().RevokePortAuth(b.conn.ctx, &platformv1.RevokePortAuthRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetPortStats returns statistics for a port.
func (b *SDNBinding) GetPortStats(bridgeID, portID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().GetPortStats(b.conn.ctx, &platformv1.GetPortStatsRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetFlowStats returns statistics for a flow.
func (b *SDNBinding) GetFlowStats(bridgeID, flowID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.SDN().GetFlowStats(b.conn.ctx, &platformv1.GetFlowStatsRequest{
		BridgeId: bridgeID,
		FlowId:   flowID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}
