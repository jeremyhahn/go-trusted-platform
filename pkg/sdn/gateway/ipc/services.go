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
	"net/netip"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
)

// PerfService names the perf measurements in a refusal and an
// ErrServiceUnreachable. Perf is not a gateway service constant: no
// configuration section enables it, it runs on whatever bridge the
// datapath child programs.
const PerfService = "perf"

// LoadBalancer is the load-balancer service GatewayServicesService reads
// and drives; *gateway.Gateway implements it.
type LoadBalancer interface {
	AddVIP(ctx context.Context, vip loadbalancer.VIP) error
	RemoveVIP(ctx context.Context, protocol string, addr netip.AddrPort) error
	GetVIP(ctx context.Context, protocol string, addr netip.AddrPort) (loadbalancer.VIPStatus, error)
	ListVIPs(ctx context.Context) ([]loadbalancer.VIPStatus, error)
	SetVIPBackends(ctx context.Context, protocol string, addr netip.AddrPort, backends []loadbalancer.Backend) error
	LBStatus(ctx context.Context) (loadbalancer.Health, error)
}

// NAT64 is the translator GatewayServicesService reads; *gateway.Gateway
// implements it.
type NAT64 interface {
	NAT64Status(ctx context.Context) (nat64.Health, error)
}

// Perf is the measurement service GatewayServicesService runs;
// *perf.Service implements it.
type Perf interface {
	Flows(ctx context.Context, bridge string, count int, batch bool) (perf.FlowsResult, error)
	Datapath(ctx context.Context, bridge string) (perf.DatapathResult, error)
	Conntrack(ctx context.Context, zone int) (perf.ConntrackResult, error)
}

// Services are what GatewayServicesService reaches. A nil member is a
// service the process does not host: its calls refuse with
// gateway.ErrServiceNotActive.
type Services struct {
	LoadBalancer LoadBalancer
	NAT64        NAT64
	Perf         Perf
}

// nat64Health is nat64.Health on the wire: LastError, an error, travels as
// its text.
type nat64Health struct {
	Active          bool      `json:"active"`
	InstancePresent bool      `json:"instance_present"`
	Prefix          string    `json:"prefix"`
	Instance        string    `json:"instance"`
	Sessions        uint64    `json:"sessions"`
	Pool4Used       uint64    `json:"pool4_used"`
	ModuleVersion   string    `json:"module_version"`
	FlowCount       int       `json:"flow_count"`
	LastReconcile   time.Time `json:"last_reconcile"`
	LastError       string    `json:"last_error,omitempty"`
}

func nat64HealthToWire(h nat64.Health) nat64Health {
	return nat64Health{
		Active:          h.Active,
		InstancePresent: h.InstancePresent,
		Prefix:          h.Prefix,
		Instance:        h.Instance,
		Sessions:        h.Sessions,
		Pool4Used:       h.Pool4Used,
		ModuleVersion:   h.ModuleVersion,
		FlowCount:       h.FlowCount,
		LastReconcile:   h.LastReconcile,
		LastError:       errorText(h.LastError),
	}
}

func (w nat64Health) health() nat64.Health {
	h := nat64.Health{
		Active:          w.Active,
		InstancePresent: w.InstancePresent,
		Prefix:          w.Prefix,
		Instance:        w.Instance,
		Sessions:        w.Sessions,
		Pool4Used:       w.Pool4Used,
		ModuleVersion:   w.ModuleVersion,
		FlowCount:       w.FlowCount,
		LastReconcile:   w.LastReconcile,
	}
	if w.LastError != "" {
		h.LastError = &ErrRemoteService{Message: w.LastError}
	}
	return h
}

// SetServices installs the services GatewayServicesService reaches. Only
// the kernel-class datapath child hosts them; every other process answers
// with gateway.ErrServiceNotActive.
func (s *Server) SetServices(services Services) {
	s.services.Store(&services)
}

func (s *Server) loadServices() Services {
	if services := s.services.Load(); services != nil {
		return *services
	}
	return Services{}
}

// notHosted is the refusal for a service the process does not host.
func notHosted(service string) *ipcv1.ServiceRefusal {
	return refusalFor(&gateway.ErrServiceNotActive{Service: service})
}

// encodeResult is a service call's JSON result, or the refusal it returned.
func encodeResult[T any](result T, err error) ([]byte, *ipcv1.ServiceRefusal) {
	if err != nil {
		return nil, refusalFor(err)
	}
	body, err := json.Marshal(result)
	if err != nil {
		return nil, refusalFor(&ErrDocument{Document: "service result", Cause: err})
	}
	return body, nil
}

// vipTarget parses a VIP key.
func vipTarget(key *ipcv1.VIPKey) (string, netip.AddrPort, error) {
	addr, err := netip.ParseAddrPort(key.GetAddress())
	if err != nil {
		return "", netip.AddrPort{}, &ErrVIPKey{Address: key.GetAddress(), Cause: err}
	}
	return key.GetProtocol(), addr, nil
}

// LBStatus returns the load balancer's health.
func (s *Server) LBStatus(ctx context.Context, _ *ipcv1.LBStatusRequest) (*ipcv1.LBStatusResponse, error) {
	lb := s.loadServices().LoadBalancer
	if lb == nil {
		return &ipcv1.LBStatusResponse{Refusal: notHosted(gateway.ServiceLoadBalancer)}, nil
	}
	body, refusal := encodeResult(lb.LBStatus(ctx))
	return &ipcv1.LBStatusResponse{HealthJson: body, Refusal: refusal}, nil
}

// ListVIPs returns every VIP's status.
func (s *Server) ListVIPs(ctx context.Context, _ *ipcv1.ListVIPsRequest) (*ipcv1.ListVIPsResponse, error) {
	lb := s.loadServices().LoadBalancer
	if lb == nil {
		return &ipcv1.ListVIPsResponse{Refusal: notHosted(gateway.ServiceLoadBalancer)}, nil
	}
	body, refusal := encodeResult(lb.ListVIPs(ctx))
	return &ipcv1.ListVIPsResponse{VipsJson: body, Refusal: refusal}, nil
}

// GetVIP returns one VIP's status.
func (s *Server) GetVIP(ctx context.Context, req *ipcv1.GetVIPRequest) (*ipcv1.GetVIPResponse, error) {
	lb := s.loadServices().LoadBalancer
	if lb == nil {
		return &ipcv1.GetVIPResponse{Refusal: notHosted(gateway.ServiceLoadBalancer)}, nil
	}
	protocol, addr, err := vipTarget(req.GetVip())
	if err != nil {
		return &ipcv1.GetVIPResponse{Refusal: refusalFor(err)}, nil
	}
	body, refusal := encodeResult(lb.GetVIP(ctx, protocol, addr))
	return &ipcv1.GetVIPResponse{VipJson: body, Refusal: refusal}, nil
}

// AddVIP adds a VIP.
func (s *Server) AddVIP(ctx context.Context, req *ipcv1.AddVIPRequest) (*ipcv1.AddVIPResponse, error) {
	lb := s.loadServices().LoadBalancer
	if lb == nil {
		return &ipcv1.AddVIPResponse{Refusal: notHosted(gateway.ServiceLoadBalancer)}, nil
	}
	var vip loadbalancer.VIP
	if err := json.Unmarshal(req.GetVipJson(), &vip); err != nil {
		return &ipcv1.AddVIPResponse{Refusal: refusalFor(&ErrDocument{Document: "VIP", Cause: err})}, nil
	}
	return &ipcv1.AddVIPResponse{Refusal: refusalFor(lb.AddVIP(ctx, vip))}, nil
}

// RemoveVIP removes a VIP.
func (s *Server) RemoveVIP(ctx context.Context, req *ipcv1.RemoveVIPRequest) (*ipcv1.RemoveVIPResponse, error) {
	lb := s.loadServices().LoadBalancer
	if lb == nil {
		return &ipcv1.RemoveVIPResponse{Refusal: notHosted(gateway.ServiceLoadBalancer)}, nil
	}
	protocol, addr, err := vipTarget(req.GetVip())
	if err != nil {
		return &ipcv1.RemoveVIPResponse{Refusal: refusalFor(err)}, nil
	}
	return &ipcv1.RemoveVIPResponse{Refusal: refusalFor(lb.RemoveVIP(ctx, protocol, addr))}, nil
}

// SetVIPBackends replaces a VIP's backends.
func (s *Server) SetVIPBackends(ctx context.Context, req *ipcv1.SetVIPBackendsRequest) (*ipcv1.SetVIPBackendsResponse, error) {
	lb := s.loadServices().LoadBalancer
	if lb == nil {
		return &ipcv1.SetVIPBackendsResponse{Refusal: notHosted(gateway.ServiceLoadBalancer)}, nil
	}
	protocol, addr, err := vipTarget(req.GetVip())
	if err != nil {
		return &ipcv1.SetVIPBackendsResponse{Refusal: refusalFor(err)}, nil
	}
	var backends []loadbalancer.Backend
	if err := json.Unmarshal(req.GetBackendsJson(), &backends); err != nil {
		return &ipcv1.SetVIPBackendsResponse{Refusal: refusalFor(&ErrDocument{Document: "VIP backends", Cause: err})}, nil
	}
	return &ipcv1.SetVIPBackendsResponse{Refusal: refusalFor(lb.SetVIPBackends(ctx, protocol, addr, backends))}, nil
}

// NAT64Status returns the translator's health.
func (s *Server) NAT64Status(ctx context.Context, _ *ipcv1.NAT64StatusRequest) (*ipcv1.NAT64StatusResponse, error) {
	translator := s.loadServices().NAT64
	if translator == nil {
		return &ipcv1.NAT64StatusResponse{Refusal: notHosted(gateway.ServiceNAT64)}, nil
	}
	health, err := translator.NAT64Status(ctx)
	if err != nil {
		return &ipcv1.NAT64StatusResponse{Refusal: refusalFor(err)}, nil
	}
	body, refusal := encodeResult(nat64HealthToWire(health), nil)
	return &ipcv1.NAT64StatusResponse{HealthJson: body, Refusal: refusal}, nil
}

// PerfFlows runs the flow-install measurement.
func (s *Server) PerfFlows(ctx context.Context, req *ipcv1.PerfFlowsRequest) (*ipcv1.PerfFlowsResponse, error) {
	measure := s.loadServices().Perf
	if measure == nil {
		return &ipcv1.PerfFlowsResponse{Refusal: notHosted(PerfService)}, nil
	}
	body, refusal := encodeResult(measure.Flows(ctx, req.GetBridge(), int(req.GetCount()), req.GetBatch()))
	return &ipcv1.PerfFlowsResponse{ResultJson: body, Refusal: refusal}, nil
}

// PerfDatapath reads a bridge's datapath counters.
func (s *Server) PerfDatapath(ctx context.Context, req *ipcv1.PerfDatapathRequest) (*ipcv1.PerfDatapathResponse, error) {
	measure := s.loadServices().Perf
	if measure == nil {
		return &ipcv1.PerfDatapathResponse{Refusal: notHosted(PerfService)}, nil
	}
	body, refusal := encodeResult(measure.Datapath(ctx, req.GetBridge()))
	return &ipcv1.PerfDatapathResponse{ResultJson: body, Refusal: refusal}, nil
}

// PerfConntrack reads the conntrack entry counts.
func (s *Server) PerfConntrack(ctx context.Context, req *ipcv1.PerfConntrackRequest) (*ipcv1.PerfConntrackResponse, error) {
	measure := s.loadServices().Perf
	if measure == nil {
		return &ipcv1.PerfConntrackResponse{Refusal: notHosted(PerfService)}, nil
	}
	body, refusal := encodeResult(measure.Conntrack(ctx, int(req.GetZone())))
	return &ipcv1.PerfConntrackResponse{ResultJson: body, Refusal: refusal}, nil
}
