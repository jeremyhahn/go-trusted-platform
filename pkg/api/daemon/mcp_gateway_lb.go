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
	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
)

// SetGatewayLoadBalancer wires the gateway load balancer backend into the
// MCP service provider. A nil backend leaves every gateway_lb_* tool
// returning ErrServiceNotAvailable.
func (m *MCPServiceProvider) SetGatewayLoadBalancer(lb GatewayLoadBalancerInterface) {
	m.gatewayLB = lb
}

// requireGatewayLB returns the load balancer backend or the typed
// service-unavailable error.
func (m *MCPServiceProvider) requireGatewayLB() (GatewayLoadBalancerInterface, error) {
	if m.gatewayLB == nil {
		return nil, ErrServiceNotAvailable{Service: "load-balancer"}
	}
	return m.gatewayLB, nil
}

// mcpLBTarget parses the protocol/address/port triple of keyed VIP tools.
func mcpLBTarget(protocol, address string, port uint16) (string, netip.AddrPort, error) {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return "", netip.AddrPort{}, mcp.ErrLBVIPTargetRequired
	}
	if protocol == "" || port == 0 {
		return "", netip.AddrPort{}, mcp.ErrLBVIPTargetRequired
	}
	return protocol, netip.AddrPortFrom(addr, port), nil
}

// mcpLBBackends converts MCP backends to service backends.
func mcpLBBackends(backends []*mcp.LBBackendRequest) ([]loadbalancer.Backend, error) {
	out := make([]loadbalancer.Backend, 0, len(backends))
	for _, b := range backends {
		if b == nil {
			return nil, mcp.ErrLBBackendsRequired
		}
		addr, err := netip.ParseAddr(b.Address)
		if err != nil {
			return nil, mcp.ErrLBBackendsRequired
		}
		out = append(out, loadbalancer.Backend{Address: addr, Port: b.Port, Weight: b.Weight})
	}
	return out, nil
}

// GatewayLBVIPAdd installs a load-balanced virtual IP.
func (m *MCPServiceProvider) GatewayLBVIPAdd(ctx context.Context, req *mcp.LBVIPAddRequest) (interface{}, error) {
	lb, err := m.requireGatewayLB()
	if err != nil {
		return nil, err
	}
	return gatewayLBVIPAdd(ctx, lb, req)
}

// gatewayLBVIPAdd implements the shared MCP VIP add path for every
// mcp.ServiceProvider implementation.
func gatewayLBVIPAdd(ctx context.Context, lb GatewayLoadBalancerInterface, req *mcp.LBVIPAddRequest) (interface{}, error) {
	if req == nil {
		return nil, mcp.ErrLBVIPTargetRequired
	}
	protocol, target, err := mcpLBTarget(req.Protocol, req.Address, req.Port)
	if err != nil {
		return nil, err
	}
	backends, err := mcpLBBackends(req.Backends)
	if err != nil {
		return nil, err
	}

	vip := loadbalancer.VIP{
		Address:   target.Addr(),
		Port:      target.Port(),
		Protocol:  protocol,
		Algorithm: req.Algorithm,
		Backends:  backends,
	}
	if err := lb.AddVIP(ctx, vip); err != nil {
		return nil, err
	}

	created, err := lb.GetVIP(ctx, protocol, target)
	if err != nil {
		return nil, err
	}
	return vipStatusToREST(created), nil
}

// GatewayLBVIPRemove tears down a load-balanced virtual IP.
func (m *MCPServiceProvider) GatewayLBVIPRemove(ctx context.Context, protocol, address string, port uint16) error {
	lb, err := m.requireGatewayLB()
	if err != nil {
		return err
	}
	return gatewayLBVIPRemove(ctx, lb, protocol, address, port)
}

// gatewayLBVIPRemove implements the shared MCP VIP remove path.
func gatewayLBVIPRemove(ctx context.Context, lb GatewayLoadBalancerInterface, protocol, address string, port uint16) error {
	protocol, target, err := mcpLBTarget(protocol, address, port)
	if err != nil {
		return err
	}
	return lb.RemoveVIP(ctx, protocol, target)
}

// GatewayLBVIPGet returns one VIP's status.
func (m *MCPServiceProvider) GatewayLBVIPGet(ctx context.Context, protocol, address string, port uint16) (interface{}, error) {
	lb, err := m.requireGatewayLB()
	if err != nil {
		return nil, err
	}
	return gatewayLBVIPGet(ctx, lb, protocol, address, port)
}

// gatewayLBVIPGet implements the shared MCP VIP get path.
func gatewayLBVIPGet(ctx context.Context, lb GatewayLoadBalancerInterface, protocol, address string, port uint16) (interface{}, error) {
	protocol, target, err := mcpLBTarget(protocol, address, port)
	if err != nil {
		return nil, err
	}
	vip, err := lb.GetVIP(ctx, protocol, target)
	if err != nil {
		return nil, err
	}
	return vipStatusToREST(vip), nil
}

// GatewayLBVIPList returns every VIP's status.
func (m *MCPServiceProvider) GatewayLBVIPList(ctx context.Context) ([]interface{}, error) {
	lb, err := m.requireGatewayLB()
	if err != nil {
		return nil, err
	}
	return gatewayLBVIPList(ctx, lb)
}

// gatewayLBVIPList implements the shared MCP VIP list path.
func gatewayLBVIPList(ctx context.Context, lb GatewayLoadBalancerInterface) ([]interface{}, error) {
	vips, err := lb.ListVIPs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(vips))
	for _, vip := range vips {
		out = append(out, vipStatusToREST(vip))
	}
	return out, nil
}

// GatewayLBVIPSetBackends replaces a VIP's backend set.
func (m *MCPServiceProvider) GatewayLBVIPSetBackends(ctx context.Context, protocol, address string, port uint16, backends []*mcp.LBBackendRequest) (interface{}, error) {
	lb, err := m.requireGatewayLB()
	if err != nil {
		return nil, err
	}
	return gatewayLBVIPSetBackends(ctx, lb, protocol, address, port, backends)
}

// gatewayLBVIPSetBackends implements the shared MCP backend replacement path.
func gatewayLBVIPSetBackends(ctx context.Context, lb GatewayLoadBalancerInterface, protocol, address string, port uint16, backends []*mcp.LBBackendRequest) (interface{}, error) {
	protocol, target, err := mcpLBTarget(protocol, address, port)
	if err != nil {
		return nil, err
	}
	serviceBackends, err := mcpLBBackends(backends)
	if err != nil {
		return nil, err
	}
	if err := lb.SetVIPBackends(ctx, protocol, target, serviceBackends); err != nil {
		return nil, err
	}
	vip, err := lb.GetVIP(ctx, protocol, target)
	if err != nil {
		return nil, err
	}
	return vipStatusToREST(vip), nil
}

// GatewayLBStatus returns the load balancer service health snapshot.
func (m *MCPServiceProvider) GatewayLBStatus(ctx context.Context) (interface{}, error) {
	lb, err := m.requireGatewayLB()
	if err != nil {
		return nil, err
	}
	return gatewayLBStatus(ctx, lb)
}

// gatewayLBStatus implements the shared MCP LB status path.
func gatewayLBStatus(ctx context.Context, lb GatewayLoadBalancerInterface) (interface{}, error) {
	health, err := lb.LBStatus(ctx)
	if err != nil {
		return nil, err
	}
	return &rest.LBStatusResponse{
		Active:          health.Active,
		VIPCount:        health.VIPCount,
		HealthyBackends: health.HealthyBackends,
		TotalBackends:   health.TotalBackends,
		LastReconcile:   health.LastReconcile,
	}, nil
}
