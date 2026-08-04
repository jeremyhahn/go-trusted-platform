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

// Package overlay provides a client for overlay network service operations.
package overlay

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to overlay network service operations.
type Client struct {
	grpc platformv1.OverlayServiceClient
}

// NewClient creates a new overlay service client from a transport adapter.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewOverlayServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new overlay service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.OverlayServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// VTEP Operations

// ListVTEPs lists all Virtual Tunnel Endpoints.
func (c *Client) ListVTEPs(ctx context.Context) ([]*platformv1.VTEPInfo, error) {
	resp, err := c.grpc.ListVTEPs(ctx, &platformv1.ListVTEPsRequest{})
	if err != nil {
		return nil, &ErrListVTEPsFailed{Cause: err}
	}
	return resp.Vteps, nil
}

// GetVTEP retrieves a VTEP by node ID.
func (c *Client) GetVTEP(ctx context.Context, nodeID string) (*platformv1.VTEPInfo, error) {
	resp, err := c.grpc.GetVTEP(ctx, &platformv1.GetVTEPRequest{NodeId: nodeID})
	if err != nil {
		return nil, &ErrGetVTEPFailed{NodeID: nodeID, Cause: err}
	}
	return resp.Vtep, nil
}

// VNI Operations

// CreateVNI creates a new Virtual Network Identifier.
func (c *Client) CreateVNI(ctx context.Context, config *platformv1.VNIConfig) (*platformv1.VNI, error) {
	resp, err := c.grpc.CreateVNI(ctx, &platformv1.CreateVNIRequest{Config: config})
	if err != nil {
		return nil, &ErrCreateVNIFailed{VNI: config.Vni, Cause: err}
	}
	return resp.Vni, nil
}

// DeleteVNI deletes a VNI.
func (c *Client) DeleteVNI(ctx context.Context, vni uint32) error {
	_, err := c.grpc.DeleteVNI(ctx, &platformv1.DeleteVNIRequest{Vni: vni})
	if err != nil {
		return &ErrDeleteVNIFailed{VNI: vni, Cause: err}
	}
	return nil
}

// ListVNIs lists all VNIs.
func (c *Client) ListVNIs(ctx context.Context) ([]*platformv1.VNI, error) {
	resp, err := c.grpc.ListVNIs(ctx, &platformv1.ListVNIsRequest{})
	if err != nil {
		return nil, &ErrListVNIsFailed{Cause: err}
	}
	return resp.Vnis, nil
}

// Tunnel Operations

// ListTunnels lists overlay tunnels.
func (c *Client) ListTunnels(ctx context.Context, vni uint32) ([]*platformv1.TunnelInfo, error) {
	resp, err := c.grpc.ListTunnels(ctx, &platformv1.ListTunnelsRequest{Vni: vni})
	if err != nil {
		return nil, &ErrListTunnelsFailed{Cause: err}
	}
	return resp.Tunnels, nil
}

// GetTunnelStats retrieves statistics for a tunnel.
func (c *Client) GetTunnelStats(ctx context.Context, remoteVTEP string, vni uint32) (*platformv1.TunnelInfo, error) {
	resp, err := c.grpc.GetTunnelStats(ctx, &platformv1.GetTunnelStatsRequest{
		RemoteVtep: remoteVTEP,
		Vni:        vni,
	})
	if err != nil {
		return nil, &ErrGetTunnelStatsFailed{RemoteVTEP: remoteVTEP, VNI: vni, Cause: err}
	}
	return resp.Tunnel, nil
}

// MAC Learning

// ListRemoteMACs lists remote MAC addresses learned via the overlay.
func (c *Client) ListRemoteMACs(ctx context.Context, vni uint32) ([]*platformv1.RemoteMACEntry, error) {
	resp, err := c.grpc.ListRemoteMACs(ctx, &platformv1.ListRemoteMACsRequest{Vni: vni})
	if err != nil {
		return nil, &ErrListRemoteMACsFailed{Cause: err}
	}
	return resp.Macs, nil
}

// ForgetMAC removes a remote MAC from the learning table.
func (c *Client) ForgetMAC(ctx context.Context, mac string, vni uint32) error {
	_, err := c.grpc.ForgetMAC(ctx, &platformv1.ForgetMACRequest{
		Mac: mac,
		Vni: vni,
	})
	if err != nil {
		return &ErrForgetMACFailed{MAC: mac, VNI: vni, Cause: err}
	}
	return nil
}

// Status

// GetStatus retrieves the overlay network status.
func (c *Client) GetStatus(ctx context.Context) (*platformv1.OverlayStatus, error) {
	resp, err := c.grpc.GetOverlayStatus(ctx, &platformv1.GetOverlayStatusRequest{})
	if err != nil {
		return nil, &ErrGetStatusFailed{Cause: err}
	}
	return resp.Status, nil
}
