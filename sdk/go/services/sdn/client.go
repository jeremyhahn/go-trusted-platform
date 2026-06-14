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

// Package sdn provides a client for Software-Defined Networking service operations.
package sdn

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to SDN service operations.
type Client struct {
	grpc platformv1.SDNServiceClient
}

// NewClient creates a new SDN service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewSDNServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new SDN service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.SDNServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// Bridge Operations

// CreateBridge creates a new bridge.
func (c *Client) CreateBridge(ctx context.Context, config *platformv1.BridgeConfig) (*platformv1.Bridge, error) {
	resp, err := c.grpc.CreateBridge(ctx, &platformv1.CreateBridgeRequest{Config: config})
	if err != nil {
		return nil, &ErrCreateBridgeFailed{Cause: err}
	}
	return resp.Bridge, nil
}

// DeleteBridge deletes a bridge.
func (c *Client) DeleteBridge(ctx context.Context, id string, force bool) error {
	_, err := c.grpc.DeleteBridge(ctx, &platformv1.DeleteBridgeRequest{Id: id, Force: force})
	if err != nil {
		return &ErrDeleteBridgeFailed{ID: id, Cause: err}
	}
	return nil
}

// GetBridge retrieves a bridge by ID.
func (c *Client) GetBridge(ctx context.Context, id string) (*platformv1.Bridge, error) {
	resp, err := c.grpc.GetBridge(ctx, &platformv1.GetBridgeRequest{Id: id})
	if err != nil {
		return nil, &ErrGetBridgeFailed{ID: id, Cause: err}
	}
	return resp.Bridge, nil
}

// ListBridges lists bridges with optional filtering.
func (c *Client) ListBridges(ctx context.Context, selector *platformv1.LabelSelector, pagination *platformv1.PaginationRequest) ([]*platformv1.Bridge, *common.PageResult, error) {
	resp, err := c.grpc.ListBridges(ctx, &platformv1.ListBridgesRequest{
		Selector:   selector,
		Pagination: pagination,
	})
	if err != nil {
		return nil, nil, &ErrListBridgesFailed{Cause: err}
	}
	var pageResult *common.PageResult
	if resp.Pagination != nil {
		pageResult = &common.PageResult{
			Page:       resp.Pagination.Page,
			PageSize:   resp.Pagination.PageSize,
			TotalPages: resp.Pagination.TotalPages,
			TotalItems: resp.Pagination.TotalItems,
		}
	}
	return resp.Bridges, pageResult, nil
}

// Port Operations

// AddPort adds a port to a bridge.
func (c *Client) AddPort(ctx context.Context, bridgeID string, config *platformv1.PortConfig) (*platformv1.Port, error) {
	resp, err := c.grpc.AddPort(ctx, &platformv1.AddPortRequest{
		BridgeId: bridgeID,
		Config:   config,
	})
	if err != nil {
		return nil, &ErrAddPortFailed{BridgeID: bridgeID, Cause: err}
	}
	return resp.Port, nil
}

// DeletePort removes a port from a bridge.
func (c *Client) DeletePort(ctx context.Context, bridgeID, portID string) error {
	_, err := c.grpc.DeletePort(ctx, &platformv1.DeletePortRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	})
	if err != nil {
		return &ErrDeletePortFailed{BridgeID: bridgeID, PortID: portID, Cause: err}
	}
	return nil
}

// GetPort retrieves a port.
func (c *Client) GetPort(ctx context.Context, bridgeID, portID string) (*platformv1.Port, error) {
	resp, err := c.grpc.GetPort(ctx, &platformv1.GetPortRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	})
	if err != nil {
		return nil, &ErrGetPortFailed{BridgeID: bridgeID, PortID: portID, Cause: err}
	}
	return resp.Port, nil
}

// ListPorts lists ports on a bridge.
func (c *Client) ListPorts(ctx context.Context, bridgeID string, selector *platformv1.LabelSelector, pagination *platformv1.PaginationRequest) ([]*platformv1.Port, *common.PageResult, error) {
	resp, err := c.grpc.ListPorts(ctx, &platformv1.ListPortsRequest{
		BridgeId:   bridgeID,
		Selector:   selector,
		Pagination: pagination,
	})
	if err != nil {
		return nil, nil, &ErrListPortsFailed{BridgeID: bridgeID, Cause: err}
	}
	var pageResult *common.PageResult
	if resp.Pagination != nil {
		pageResult = &common.PageResult{
			Page:       resp.Pagination.Page,
			PageSize:   resp.Pagination.PageSize,
			TotalPages: resp.Pagination.TotalPages,
			TotalItems: resp.Pagination.TotalItems,
		}
	}
	return resp.Ports, pageResult, nil
}

// Flow Operations

// AddFlow adds a flow rule.
func (c *Client) AddFlow(ctx context.Context, config *platformv1.FlowConfig) (*platformv1.Flow, error) {
	resp, err := c.grpc.AddFlow(ctx, &platformv1.AddFlowRequest{Config: config})
	if err != nil {
		return nil, &ErrAddFlowFailed{Cause: err}
	}
	return resp.Flow, nil
}

// DeleteFlow removes a flow rule.
func (c *Client) DeleteFlow(ctx context.Context, bridgeID, flowID string) error {
	_, err := c.grpc.DeleteFlow(ctx, &platformv1.DeleteFlowRequest{
		BridgeId: bridgeID,
		FlowId:   flowID,
	})
	if err != nil {
		return &ErrDeleteFlowFailed{BridgeID: bridgeID, FlowID: flowID, Cause: err}
	}
	return nil
}

// ListFlows lists flows on a bridge.
func (c *Client) ListFlows(ctx context.Context, bridgeID string, table platformv1.FlowTable, pagination *platformv1.PaginationRequest) ([]*platformv1.Flow, *common.PageResult, error) {
	resp, err := c.grpc.ListFlows(ctx, &platformv1.ListFlowsRequest{
		BridgeId:   bridgeID,
		Table:      table,
		Pagination: pagination,
	})
	if err != nil {
		return nil, nil, &ErrListFlowsFailed{BridgeID: bridgeID, Cause: err}
	}
	var pageResult *common.PageResult
	if resp.Pagination != nil {
		pageResult = &common.PageResult{
			Page:       resp.Pagination.Page,
			PageSize:   resp.Pagination.PageSize,
			TotalPages: resp.Pagination.TotalPages,
			TotalItems: resp.Pagination.TotalItems,
		}
	}
	return resp.Flows, pageResult, nil
}

// FlushFlows removes all flows from a bridge or table.
func (c *Client) FlushFlows(ctx context.Context, bridgeID string, table platformv1.FlowTable) (uint32, error) {
	resp, err := c.grpc.FlushFlows(ctx, &platformv1.FlushFlowsRequest{
		BridgeId: bridgeID,
		Table:    table,
	})
	if err != nil {
		return 0, &ErrFlushFlowsFailed{BridgeID: bridgeID, Cause: err}
	}
	return resp.DeletedCount, nil
}

// VLAN Operations

// CreateVLAN creates a new VLAN.
func (c *Client) CreateVLAN(ctx context.Context, config *platformv1.VLANConfig) (*platformv1.VLAN, error) {
	resp, err := c.grpc.CreateVLAN(ctx, &platformv1.CreateVLANRequest{Config: config})
	if err != nil {
		return nil, &ErrCreateVLANFailed{Cause: err}
	}
	return resp.Vlan, nil
}

// DeleteVLAN removes a VLAN.
func (c *Client) DeleteVLAN(ctx context.Context, bridgeID string, vlanID uint32) error {
	_, err := c.grpc.DeleteVLAN(ctx, &platformv1.DeleteVLANRequest{
		BridgeId: bridgeID,
		VlanId:   vlanID,
	})
	if err != nil {
		return &ErrDeleteVLANFailed{BridgeID: bridgeID, VlanID: vlanID, Cause: err}
	}
	return nil
}

// ListVLANs lists VLANs on a bridge.
func (c *Client) ListVLANs(ctx context.Context, bridgeID string, selector *platformv1.LabelSelector) ([]*platformv1.VLAN, error) {
	resp, err := c.grpc.ListVLANs(ctx, &platformv1.ListVLANsRequest{
		BridgeId: bridgeID,
		Selector: selector,
	})
	if err != nil {
		return nil, &ErrListVLANsFailed{BridgeID: bridgeID, Cause: err}
	}
	return resp.Vlans, nil
}

// Port Authentication

// AuthenticatePort authenticates a port using x509 certificate.
func (c *Client) AuthenticatePort(ctx context.Context, bridgeID, portID string, certificate []byte, format string) (*platformv1.PortAuth, error) {
	resp, err := c.grpc.AuthenticatePort(ctx, &platformv1.AuthenticatePortRequest{
		BridgeId:    bridgeID,
		PortId:      portID,
		Certificate: certificate,
		Format:      format,
	})
	if err != nil {
		return nil, &ErrAuthenticatePortFailed{BridgeID: bridgeID, PortID: portID, Cause: err}
	}
	return resp.Auth, nil
}

// RevokePortAuth revokes port authentication.
func (c *Client) RevokePortAuth(ctx context.Context, bridgeID, portID string) error {
	_, err := c.grpc.RevokePortAuth(ctx, &platformv1.RevokePortAuthRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	})
	if err != nil {
		return &ErrRevokePortAuthFailed{BridgeID: bridgeID, PortID: portID, Cause: err}
	}
	return nil
}

// Statistics

// GetPortStats retrieves port statistics.
func (c *Client) GetPortStats(ctx context.Context, bridgeID, portID string) (*platformv1.PortStats, error) {
	resp, err := c.grpc.GetPortStats(ctx, &platformv1.GetPortStatsRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	})
	if err != nil {
		return nil, &ErrGetPortStatsFailed{BridgeID: bridgeID, PortID: portID, Cause: err}
	}
	return resp.Stats, nil
}

// GetFlowStats retrieves flow statistics.
func (c *Client) GetFlowStats(ctx context.Context, bridgeID, flowID string) (*platformv1.FlowStats, error) {
	resp, err := c.grpc.GetFlowStats(ctx, &platformv1.GetFlowStatsRequest{
		BridgeId: bridgeID,
		FlowId:   flowID,
	})
	if err != nil {
		return nil, &ErrGetFlowStatsFailed{BridgeID: bridgeID, FlowID: flowID, Cause: err}
	}
	return resp.Stats, nil
}

// ApplyPolicy applies a network policy.
func (c *Client) ApplyPolicy(ctx context.Context, policyID string, config *platformv1.PolicyConfig) (*platformv1.Policy, error) {
	resp, err := c.grpc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		PolicyId: policyID,
		Config:   config,
	})
	if err != nil {
		return nil, &ErrApplyPolicyFailed{PolicyID: policyID, Cause: err}
	}
	return resp.Policy, nil
}

// GetPolicy retrieves a policy by ID.
func (c *Client) GetPolicy(ctx context.Context, policyID string) (*platformv1.Policy, error) {
	resp, err := c.grpc.GetPolicy(ctx, &platformv1.GetPolicyRequest{
		PolicyId: policyID,
	})
	if err != nil {
		return nil, &ErrGetPolicyFailed{PolicyID: policyID, Cause: err}
	}
	return resp.Policy, nil
}

// ListPolicies lists policies with optional filtering.
func (c *Client) ListPolicies(ctx context.Context, policyType, targetID string, pagination *platformv1.PaginationRequest) ([]*platformv1.Policy, error) {
	resp, err := c.grpc.ListPolicies(ctx, &platformv1.ListPoliciesRequest{
		Type:       policyType,
		TargetId:   targetID,
		Pagination: pagination,
	})
	if err != nil {
		return nil, &ErrListPoliciesFailed{Cause: err}
	}
	return resp.Policies, nil
}

// Network Zone Operations

// CreateNetworkZone creates a new SDN network trust zone.
func (c *Client) CreateNetworkZone(ctx context.Context, req *platformv1.CreateNetworkZoneRequest) (*platformv1.NetworkZone, error) {
	resp, err := c.grpc.CreateNetworkZone(ctx, req)
	if err != nil {
		return nil, &ErrCreateNetworkZoneFailed{Cause: err}
	}
	return resp.Zone, nil
}

// UpdateNetworkZone updates an existing SDN network trust zone.
func (c *Client) UpdateNetworkZone(ctx context.Context, req *platformv1.UpdateNetworkZoneRequest) (*platformv1.NetworkZone, error) {
	resp, err := c.grpc.UpdateNetworkZone(ctx, req)
	if err != nil {
		return nil, &ErrUpdateNetworkZoneFailed{Name: req.GetName(), Cause: err}
	}
	return resp.Zone, nil
}

// DeleteNetworkZone deletes an SDN network trust zone.
func (c *Client) DeleteNetworkZone(ctx context.Context, name string) (bool, error) {
	resp, err := c.grpc.DeleteNetworkZone(ctx, &platformv1.DeleteNetworkZoneRequest{Name: name})
	if err != nil {
		return false, &ErrDeleteNetworkZoneFailed{Name: name, Cause: err}
	}
	return resp.RestartRequired, nil
}

// ListNetworkZones lists SDN network trust zones with an optional lifecycle role filter.
func (c *Client) ListNetworkZones(ctx context.Context, lifecycleRole string) ([]*platformv1.NetworkZone, error) {
	resp, err := c.grpc.ListNetworkZones(ctx, &platformv1.ListNetworkZonesRequest{
		LifecycleRole: lifecycleRole,
	})
	if err != nil {
		return nil, &ErrListNetworkZonesFailed{Cause: err}
	}
	return resp.Zones, nil
}

// AssignNetworkZone assigns a named network segment to a trust zone.
func (c *Client) AssignNetworkZone(ctx context.Context, network, zoneName string) (bool, error) {
	resp, err := c.grpc.AssignNetworkZone(ctx, &platformv1.AssignNetworkZoneRequest{
		Network: network,
		Zone:    zoneName,
	})
	if err != nil {
		return false, &ErrAssignNetworkZoneFailed{Network: network, Zone: zoneName, Cause: err}
	}
	return resp.RestartRequired, nil
}
