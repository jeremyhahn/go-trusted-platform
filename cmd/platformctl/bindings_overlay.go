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

// OverlayBinding exposes overlay network service methods to the Wails frontend.
type OverlayBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewOverlayBinding creates a new OverlayBinding.
func NewOverlayBinding(logger *slog.Logger, conn *ConnectionBinding) *OverlayBinding {
	return &OverlayBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *OverlayBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// ListVTEPs returns all VXLAN Tunnel Endpoints.
func (b *OverlayBinding) ListVTEPs() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Overlay().ListVTEPs(b.conn.ctx, &platformv1.ListVTEPsRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetVTEP returns a VTEP by node ID.
func (b *OverlayBinding) GetVTEP(nodeID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Overlay().GetVTEP(b.conn.ctx, &platformv1.GetVTEPRequest{
		NodeId: nodeID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// CreateVNI creates a new VXLAN Network Identifier.
func (b *OverlayBinding) CreateVNI(vni, vlan uint32, name string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Overlay().CreateVNI(b.conn.ctx, &platformv1.CreateVNIRequest{
		Config: &platformv1.VNIConfig{
			Vni:  vni,
			Vlan: vlan,
			Name: name,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteVNI removes a VXLAN Network Identifier.
func (b *OverlayBinding) DeleteVNI(vni uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Overlay().DeleteVNI(b.conn.ctx, &platformv1.DeleteVNIRequest{
		Vni: vni,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListVNIs returns all VXLAN Network Identifiers.
func (b *OverlayBinding) ListVNIs() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Overlay().ListVNIs(b.conn.ctx, &platformv1.ListVNIsRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListTunnels returns all VXLAN tunnels, optionally filtered by VNI.
// Pass vni=0 to list tunnels for all VNIs.
func (b *OverlayBinding) ListTunnels(vni uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Overlay().ListTunnels(b.conn.ctx, &platformv1.ListTunnelsRequest{
		Vni: vni,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetTunnelStats returns statistics for a tunnel to a remote VTEP.
func (b *OverlayBinding) GetTunnelStats(remoteVtep string, vni uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Overlay().GetTunnelStats(b.conn.ctx, &platformv1.GetTunnelStatsRequest{
		RemoteVtep: remoteVtep,
		Vni:        vni,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListRemoteMACs returns all learned remote MAC addresses.
// Pass vni=0 to list MACs for all VNIs.
func (b *OverlayBinding) ListRemoteMACs(vni uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Overlay().ListRemoteMACs(b.conn.ctx, &platformv1.ListRemoteMACsRequest{
		Vni: vni,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ForgetMAC removes a learned MAC address from the overlay table.
func (b *OverlayBinding) ForgetMAC(mac string, vni uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Overlay().ForgetMAC(b.conn.ctx, &platformv1.ForgetMACRequest{
		Mac: mac,
		Vni: vni,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetOverlayStatus returns the overall overlay network status.
func (b *OverlayBinding) GetOverlayStatus() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Overlay().GetOverlayStatus(b.conn.ctx, &platformv1.GetOverlayStatusRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}
