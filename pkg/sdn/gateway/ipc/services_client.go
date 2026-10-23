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

package ipc

import (
	"context"
	"encoding/json"
	"math"
	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
)

// The GatewayServicesService calls: *Client is platformd's live backend
// for the datapath child's load-balancer, NAT64 and perf services. A
// refusal comes back as the service's own typed error; a call the child
// did not answer is an *ErrServiceUnreachable.

// unreachable wraps an RPC failure.
func (c *Client) unreachable(service string, err error) error {
	return &ErrServiceUnreachable{Socket: c.path, Service: service, Cause: err}
}

// decodeResult rebuilds a call's refusal, or decodes its JSON result.
func decodeResult[T any](body []byte, refusal *ipcv1.ServiceRefusal, document string) (T, error) {
	var result T
	if err := errorForRefusal(refusal); err != nil {
		return result, err
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return result, &ErrDocument{Document: document, Cause: err}
	}
	return result, nil
}

func vipKey(protocol string, addr netip.AddrPort) *ipcv1.VIPKey {
	return &ipcv1.VIPKey{Protocol: protocol, Address: addr.String()}
}

// LBStatus returns the load balancer's health.
func (c *Client) LBStatus(ctx context.Context) (loadbalancer.Health, error) {
	resp, err := c.services.LBStatus(ctx, &ipcv1.LBStatusRequest{})
	if err != nil {
		return loadbalancer.Health{}, c.unreachable(gateway.ServiceLoadBalancer, err)
	}
	return decodeResult[loadbalancer.Health](resp.GetHealthJson(), resp.GetRefusal(), "load-balancer health")
}

// ListVIPs returns every VIP's status.
func (c *Client) ListVIPs(ctx context.Context) ([]loadbalancer.VIPStatus, error) {
	resp, err := c.services.ListVIPs(ctx, &ipcv1.ListVIPsRequest{})
	if err != nil {
		return nil, c.unreachable(gateway.ServiceLoadBalancer, err)
	}
	return decodeResult[[]loadbalancer.VIPStatus](resp.GetVipsJson(), resp.GetRefusal(), "VIP list")
}

// GetVIP returns one VIP's status.
func (c *Client) GetVIP(ctx context.Context, protocol string, addr netip.AddrPort) (loadbalancer.VIPStatus, error) {
	resp, err := c.services.GetVIP(ctx, &ipcv1.GetVIPRequest{Vip: vipKey(protocol, addr)})
	if err != nil {
		return loadbalancer.VIPStatus{}, c.unreachable(gateway.ServiceLoadBalancer, err)
	}
	return decodeResult[loadbalancer.VIPStatus](resp.GetVipJson(), resp.GetRefusal(), "VIP status")
}

// AddVIP adds a VIP.
func (c *Client) AddVIP(ctx context.Context, vip loadbalancer.VIP) error {
	body, err := json.Marshal(vip)
	if err != nil {
		return &ErrDocument{Document: "VIP", Cause: err}
	}
	resp, err := c.services.AddVIP(ctx, &ipcv1.AddVIPRequest{VipJson: body})
	if err != nil {
		return c.unreachable(gateway.ServiceLoadBalancer, err)
	}
	return errorForRefusal(resp.GetRefusal())
}

// RemoveVIP removes a VIP.
func (c *Client) RemoveVIP(ctx context.Context, protocol string, addr netip.AddrPort) error {
	resp, err := c.services.RemoveVIP(ctx, &ipcv1.RemoveVIPRequest{Vip: vipKey(protocol, addr)})
	if err != nil {
		return c.unreachable(gateway.ServiceLoadBalancer, err)
	}
	return errorForRefusal(resp.GetRefusal())
}

// SetVIPBackends replaces a VIP's backends.
func (c *Client) SetVIPBackends(ctx context.Context, protocol string, addr netip.AddrPort, backends []loadbalancer.Backend) error {
	body, err := json.Marshal(backends)
	if err != nil {
		return &ErrDocument{Document: "VIP backends", Cause: err}
	}
	resp, err := c.services.SetVIPBackends(ctx, &ipcv1.SetVIPBackendsRequest{Vip: vipKey(protocol, addr), BackendsJson: body})
	if err != nil {
		return c.unreachable(gateway.ServiceLoadBalancer, err)
	}
	return errorForRefusal(resp.GetRefusal())
}

// NAT64Status returns the translator's health.
func (c *Client) NAT64Status(ctx context.Context) (nat64.Health, error) {
	resp, err := c.services.NAT64Status(ctx, &ipcv1.NAT64StatusRequest{})
	if err != nil {
		return nat64.Health{}, c.unreachable(gateway.ServiceNAT64, err)
	}
	wire, err := decodeResult[nat64Health](resp.GetHealthJson(), resp.GetRefusal(), "nat64 health")
	if err != nil {
		return nat64.Health{}, err
	}
	return wire.health(), nil
}

// Flows runs the flow-install measurement on a bridge. A count the wire
// cannot carry is refused here as the perf service would refuse it.
func (c *Client) Flows(ctx context.Context, bridge string, count int, batch bool) (perf.FlowsResult, error) {
	if count < math.MinInt32 || count > math.MaxInt32 {
		return perf.FlowsResult{}, &perf.ErrInvalidFlowCount{Count: count, Max: perf.MaxFlowCount}
	}
	resp, err := c.services.PerfFlows(ctx, &ipcv1.PerfFlowsRequest{Bridge: bridge, Count: int32(count), Batch: batch})
	if err != nil {
		return perf.FlowsResult{}, c.unreachable(PerfService, err)
	}
	return decodeResult[perf.FlowsResult](resp.GetResultJson(), resp.GetRefusal(), "perf flows result")
}

// Datapath reads a bridge's datapath counters.
func (c *Client) Datapath(ctx context.Context, bridge string) (perf.DatapathResult, error) {
	resp, err := c.services.PerfDatapath(ctx, &ipcv1.PerfDatapathRequest{Bridge: bridge})
	if err != nil {
		return perf.DatapathResult{}, c.unreachable(PerfService, err)
	}
	return decodeResult[perf.DatapathResult](resp.GetResultJson(), resp.GetRefusal(), "perf datapath result")
}

// Conntrack reads the conntrack entry counts; zone 0 is every zone. A zone
// the wire cannot carry is refused with *ErrConntrackZone.
func (c *Client) Conntrack(ctx context.Context, zone int) (perf.ConntrackResult, error) {
	if zone < math.MinInt32 || zone > math.MaxInt32 {
		return perf.ConntrackResult{}, &ErrConntrackZone{Zone: zone}
	}
	resp, err := c.services.PerfConntrack(ctx, &ipcv1.PerfConntrackRequest{Zone: int32(zone)})
	if err != nil {
		return perf.ConntrackResult{}, c.unreachable(PerfService, err)
	}
	return decodeResult[perf.ConntrackResult](resp.GetResultJson(), resp.GetRefusal(), "perf conntrack result")
}
