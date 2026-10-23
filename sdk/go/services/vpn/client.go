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

// Package vpn provides a client for the platform's management-VPN control
// plane: peer enrolment, tenant posture policies and gateway session status.
// The client speaks the platform.v1 VPNService surface over any
// transport.Adapter (gRPC, Unix, REST, QUIC, MCP, embedded), so `platformctl
// vpn ...` behaves identically on every protocol.
package vpn

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to the VPN control plane.
type Client struct {
	grpc platformv1.VPNServiceClient
}

// NewClient creates a new VPN client from a transport adapter.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{grpc: platformv1.NewVPNServiceClient(grpcConn)}, nil
}

// NewClientFromGRPC creates a client from an existing gRPC client, which is
// how the CLI reuses the protocol selected by the global --protocol flag.
func NewClientFromGRPC(grpcClient platformv1.VPNServiceClient) *Client {
	return &Client{grpc: grpcClient}
}

// EnrolPeer enrols a device as a VPN peer of a tenant, or replaces the zones
// of an existing enrolment. Empty zones means every zone the gateway allows.
func (c *Client) EnrolPeer(ctx context.Context, tenantID, deviceID string, zones []string) (*platformv1.VPNPeer, error) {
	resp, err := c.grpc.EnrolPeer(ctx, &platformv1.EnrolVPNPeerRequest{
		Peer: &platformv1.VPNPeer{TenantId: tenantID, DeviceId: deviceID, Zones: zones},
	})
	if err != nil {
		return nil, &ErrCallFailed{Op: OpEnrolPeer, Cause: err}
	}
	return resp.GetPeer(), nil
}

// ListPeers lists the enrolled peers of one tenant, or of all when tenantID
// is empty.
func (c *Client) ListPeers(ctx context.Context, tenantID string) ([]*platformv1.VPNPeer, error) {
	resp, err := c.grpc.ListPeers(ctx, &platformv1.ListVPNPeersRequest{TenantId: tenantID})
	if err != nil {
		return nil, &ErrCallFailed{Op: OpListPeers, Cause: err}
	}
	return resp.GetPeers(), nil
}

// RevokePeer removes an enrolment. The gateways revoke the device's leases
// when the change reaches them.
func (c *Client) RevokePeer(ctx context.Context, tenantID, deviceID string) error {
	if _, err := c.grpc.RevokePeer(ctx, &platformv1.RevokeVPNPeerRequest{TenantId: tenantID, DeviceId: deviceID}); err != nil {
		return &ErrCallFailed{Op: OpRevokePeer, Cause: err}
	}
	return nil
}

// Status returns the session state the gateways last reported, of one
// gateway or of all when gatewayID is empty.
func (c *Client) Status(ctx context.Context, gatewayID string) ([]*platformv1.VPNGatewayStatus, error) {
	resp, err := c.grpc.GetStatus(ctx, &platformv1.GetVPNStatusRequest{GatewayId: gatewayID})
	if err != nil {
		return nil, &ErrCallFailed{Op: OpStatus, Cause: err}
	}
	return resp.GetGateways(), nil
}

// GetPosturePolicy returns one tenant posture policy.
func (c *Client) GetPosturePolicy(ctx context.Context, tenantID, name string) (*platformv1.VPNPosturePolicy, error) {
	resp, err := c.grpc.GetPosturePolicy(ctx, &platformv1.GetVPNPosturePolicyRequest{TenantId: tenantID, Name: name})
	if err != nil {
		return nil, &ErrCallFailed{Op: OpGetPosturePolicy, Cause: err}
	}
	return resp.GetPolicy(), nil
}

// SetPosturePolicy creates or replaces a tenant posture policy. The module
// must compile as package vpn.posture; an invalid module is refused and
// nothing is stored.
func (c *Client) SetPosturePolicy(ctx context.Context, tenantID, name, module string) (*platformv1.VPNPosturePolicy, error) {
	resp, err := c.grpc.SetPosturePolicy(ctx, &platformv1.SetVPNPosturePolicyRequest{
		Policy: &platformv1.VPNPosturePolicy{TenantId: tenantID, Name: name, Module: module},
	})
	if err != nil {
		return nil, &ErrCallFailed{Op: OpSetPosturePolicy, Cause: err}
	}
	return resp.GetPolicy(), nil
}

// DeletePosturePolicy removes a tenant posture policy.
func (c *Client) DeletePosturePolicy(ctx context.Context, tenantID, name string) error {
	if _, err := c.grpc.DeletePosturePolicy(ctx, &platformv1.DeleteVPNPosturePolicyRequest{TenantId: tenantID, Name: name}); err != nil {
		return &ErrCallFailed{Op: OpDeletePosturePolicy, Cause: err}
	}
	return nil
}

// ListPosturePolicies lists the posture policies of one tenant, or of all
// when tenantID is empty.
func (c *Client) ListPosturePolicies(ctx context.Context, tenantID string) ([]*platformv1.VPNPosturePolicy, error) {
	resp, err := c.grpc.ListPosturePolicies(ctx, &platformv1.ListVPNPosturePoliciesRequest{TenantId: tenantID})
	if err != nil {
		return nil, &ErrCallFailed{Op: OpListPosturePolicies, Cause: err}
	}
	return resp.GetPolicies(), nil
}
