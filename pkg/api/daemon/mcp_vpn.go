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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// MCP VPN control-plane operations
// =============================================================================
//
// Both MCP service providers delegate to the SAME in-process VPNServiceServer
// that backs REST, gRPC, QUIC, and the Unix socket, and return the generated
// platform.v1 response messages verbatim, so the tool JSON and the pb wire
// shape stay in lockstep by construction.

// vpnMCPOperations runs the MCP tool calls against one VPNServiceServer. A
// nil server makes every call return the typed service-unavailable error.
type vpnMCPOperations struct {
	server platformv1.VPNServiceServer
}

func (o vpnMCPOperations) require() (platformv1.VPNServiceServer, error) {
	if o.server == nil {
		return nil, ErrServiceNotAvailable{Service: vpnServiceName}
	}
	return o.server, nil
}

func (o vpnMCPOperations) enrolPeer(ctx context.Context, tenantID, deviceID string, zones []string) (interface{}, error) {
	server, err := o.require()
	if err != nil {
		return nil, err
	}
	return server.EnrolPeer(ctx, &platformv1.EnrolVPNPeerRequest{
		Peer: &platformv1.VPNPeer{TenantId: tenantID, DeviceId: deviceID, Zones: zones},
	})
}

func (o vpnMCPOperations) listPeers(ctx context.Context, tenantID string) (interface{}, error) {
	server, err := o.require()
	if err != nil {
		return nil, err
	}
	return server.ListPeers(ctx, &platformv1.ListVPNPeersRequest{TenantId: tenantID})
}

func (o vpnMCPOperations) revokePeer(ctx context.Context, tenantID, deviceID string) (interface{}, error) {
	server, err := o.require()
	if err != nil {
		return nil, err
	}
	return server.RevokePeer(ctx, &platformv1.RevokeVPNPeerRequest{TenantId: tenantID, DeviceId: deviceID})
}

func (o vpnMCPOperations) status(ctx context.Context, gatewayID string) (interface{}, error) {
	server, err := o.require()
	if err != nil {
		return nil, err
	}
	return server.GetStatus(ctx, &platformv1.GetVPNStatusRequest{GatewayId: gatewayID})
}

func (o vpnMCPOperations) posturePolicyGet(ctx context.Context, tenantID, name string) (interface{}, error) {
	server, err := o.require()
	if err != nil {
		return nil, err
	}
	return server.GetPosturePolicy(ctx, &platformv1.GetVPNPosturePolicyRequest{TenantId: tenantID, Name: name})
}

func (o vpnMCPOperations) posturePolicySet(ctx context.Context, tenantID, name, module string) (interface{}, error) {
	server, err := o.require()
	if err != nil {
		return nil, err
	}
	return server.SetPosturePolicy(ctx, &platformv1.SetVPNPosturePolicyRequest{
		Policy: &platformv1.VPNPosturePolicy{TenantId: tenantID, Name: name, Module: module},
	})
}

func (o vpnMCPOperations) posturePolicyDelete(ctx context.Context, tenantID, name string) (interface{}, error) {
	server, err := o.require()
	if err != nil {
		return nil, err
	}
	return server.DeletePosturePolicy(ctx, &platformv1.DeleteVPNPosturePolicyRequest{TenantId: tenantID, Name: name})
}

func (o vpnMCPOperations) posturePolicyList(ctx context.Context, tenantID string) (interface{}, error) {
	server, err := o.require()
	if err != nil {
		return nil, err
	}
	return server.ListPosturePolicies(ctx, &platformv1.ListVPNPosturePoliciesRequest{TenantId: tenantID})
}

// SetVPNService wires the VPN control plane into the MCP service provider. A
// nil server leaves every vpn_* tool returning the typed service-unavailable
// error.
func (m *MCPServiceProvider) SetVPNService(server platformv1.VPNServiceServer) {
	m.vpnService = server
}

func (m *MCPServiceProvider) vpn() vpnMCPOperations {
	return vpnMCPOperations{server: m.vpnService}
}

// VPNEnrolPeer enrols a device as a VPN peer of a tenant.
func (m *MCPServiceProvider) VPNEnrolPeer(ctx context.Context, tenantID, deviceID string, zones []string) (interface{}, error) {
	return m.vpn().enrolPeer(ctx, tenantID, deviceID, zones)
}

// VPNListPeers lists the enrolled VPN peers.
func (m *MCPServiceProvider) VPNListPeers(ctx context.Context, tenantID string) (interface{}, error) {
	return m.vpn().listPeers(ctx, tenantID)
}

// VPNRevokePeer revokes a VPN peer enrolment.
func (m *MCPServiceProvider) VPNRevokePeer(ctx context.Context, tenantID, deviceID string) (interface{}, error) {
	return m.vpn().revokePeer(ctx, tenantID, deviceID)
}

// VPNStatus reports the VPN session state from gateway telemetry.
func (m *MCPServiceProvider) VPNStatus(ctx context.Context, gatewayID string) (interface{}, error) {
	return m.vpn().status(ctx, gatewayID)
}

// VPNPosturePolicyGet returns one tenant posture policy.
func (m *MCPServiceProvider) VPNPosturePolicyGet(ctx context.Context, tenantID, name string) (interface{}, error) {
	return m.vpn().posturePolicyGet(ctx, tenantID, name)
}

// VPNPosturePolicySet creates or replaces a tenant posture policy.
func (m *MCPServiceProvider) VPNPosturePolicySet(ctx context.Context, tenantID, name, module string) (interface{}, error) {
	return m.vpn().posturePolicySet(ctx, tenantID, name, module)
}

// VPNPosturePolicyDelete deletes a tenant posture policy.
func (m *MCPServiceProvider) VPNPosturePolicyDelete(ctx context.Context, tenantID, name string) (interface{}, error) {
	return m.vpn().posturePolicyDelete(ctx, tenantID, name)
}

// VPNPosturePolicyList lists the VPN posture policies.
func (m *MCPServiceProvider) VPNPosturePolicyList(ctx context.Context, tenantID string) (interface{}, error) {
	return m.vpn().posturePolicyList(ctx, tenantID)
}
