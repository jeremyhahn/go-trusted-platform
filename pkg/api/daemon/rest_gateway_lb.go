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
	"errors"
	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
)

// SetLoadBalancer wires the gateway load balancer backend into the REST
// gateway service. A nil backend leaves every VIP operation returning
// rest.ErrLBNotConfigured (503).
func (s *gatewayRESTService) SetLoadBalancer(lb GatewayLoadBalancerInterface) {
	s.lb = lb
}

// requireLB resolves the load balancer backend or returns the typed REST
// not-configured error.
func (s *gatewayRESTService) requireLB() (GatewayLoadBalancerInterface, error) {
	if s.lb == nil {
		return nil, rest.ErrLBNotConfigured{}
	}
	return s.lb, nil
}

// mapLBError converts load balancer errors to typed REST errors.
func mapLBError(err error) error {
	if err == nil {
		return nil
	}
	var notActive *gateway.ErrServiceNotActive
	switch {
	case errors.As(err, &notActive), errors.Is(err, loadbalancer.ErrNotStarted):
		return rest.ErrLBNotConfigured{}
	case errors.Is(err, loadbalancer.ErrVIPNotFound), errors.Is(err, loadbalancer.ErrBackendNotFound):
		return rest.ErrLBVIPNotFound{}
	case errors.Is(err, loadbalancer.ErrVIPExists):
		return rest.ErrLBVIPAlreadyExists{}
	case errors.Is(err, loadbalancer.ErrAlgorithmUnsupported),
		errors.Is(err, loadbalancer.ErrInvalidVIPAddress),
		errors.Is(err, loadbalancer.ErrInvalidVIPPort),
		errors.Is(err, loadbalancer.ErrInvalidProtocol),
		errors.Is(err, loadbalancer.ErrNoBackends),
		errors.Is(err, loadbalancer.ErrTooManyBackends),
		errors.Is(err, loadbalancer.ErrInvalidBackend),
		errors.Is(err, loadbalancer.ErrDuplicateBackend):
		return rest.ErrLBInvalidVIP{Reason: err.Error()}
	default:
		return err
	}
}

// restLBTarget parses the protocol/address/port triple of keyed VIP routes.
func restLBTarget(protocol, address string, port uint16) (string, netip.AddrPort, error) {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return "", netip.AddrPort{}, rest.ErrLBInvalidVIP{Reason: "invalid address"}
	}
	if port == 0 {
		return "", netip.AddrPort{}, rest.ErrLBInvalidVIP{Reason: "port must be 1-65535"}
	}
	return protocol, netip.AddrPortFrom(addr, port), nil
}

// restLBBackends converts REST backends to service backends.
func restLBBackends(backends []rest.LBBackend) ([]loadbalancer.Backend, error) {
	out := make([]loadbalancer.Backend, 0, len(backends))
	for _, b := range backends {
		addr, err := netip.ParseAddr(b.Address)
		if err != nil {
			return nil, rest.ErrLBInvalidVIP{Reason: "invalid backend address"}
		}
		out = append(out, loadbalancer.Backend{Address: addr, Port: b.Port, Weight: b.Weight})
	}
	return out, nil
}

// vipStatusToREST converts a service VIP status to the REST response shape.
func vipStatusToREST(s loadbalancer.VIPStatus) *rest.LBVIPResponse {
	out := &rest.LBVIPResponse{
		Address:   s.VIP.Address.String(),
		Port:      s.VIP.Port,
		Protocol:  s.VIP.Protocol,
		Algorithm: s.VIP.Algorithm,
		CTZone:    s.CTZone,
		GroupID:   s.GroupID,
		Backends:  make([]rest.LBBackendStatus, 0, len(s.Backends)),
	}
	for _, b := range s.Backends {
		out.Backends = append(out.Backends, rest.LBBackendStatus{
			Backend: rest.LBBackend{
				Address: b.Backend.Address.String(),
				Port:    b.Backend.Port,
				Weight:  b.Backend.Weight,
			},
			Healthy: b.Healthy,
		})
	}
	return out
}

// AddVIP installs a load-balanced virtual IP.
func (s *gatewayRESTService) AddVIP(ctx context.Context, req *rest.LBVIPRequest) (*rest.LBVIPResponse, error) {
	lb, err := s.requireLB()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, rest.ErrLBInvalidVIP{Reason: "request body is required"}
	}
	protocol, target, err := restLBTarget(req.Protocol, req.Address, req.Port)
	if err != nil {
		return nil, err
	}
	backends, err := restLBBackends(req.Backends)
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
		return nil, mapLBError(err)
	}

	created, err := lb.GetVIP(ctx, protocol, target)
	if err != nil {
		return nil, mapLBError(err)
	}
	return vipStatusToREST(created), nil
}

// GetVIP returns the status of one VIP.
func (s *gatewayRESTService) GetVIP(ctx context.Context, protocol, address string, port uint16) (*rest.LBVIPResponse, error) {
	lb, err := s.requireLB()
	if err != nil {
		return nil, err
	}
	protocol, target, err := restLBTarget(protocol, address, port)
	if err != nil {
		return nil, err
	}
	vip, err := lb.GetVIP(ctx, protocol, target)
	if err != nil {
		return nil, mapLBError(err)
	}
	return vipStatusToREST(vip), nil
}

// ListVIPs returns the status of every VIP.
func (s *gatewayRESTService) ListVIPs(ctx context.Context) ([]rest.LBVIPResponse, error) {
	lb, err := s.requireLB()
	if err != nil {
		return nil, err
	}
	vips, err := lb.ListVIPs(ctx)
	if err != nil {
		return nil, mapLBError(err)
	}
	out := make([]rest.LBVIPResponse, 0, len(vips))
	for _, vip := range vips {
		out = append(out, *vipStatusToREST(vip))
	}
	return out, nil
}

// RemoveVIP tears down a VIP.
func (s *gatewayRESTService) RemoveVIP(ctx context.Context, protocol, address string, port uint16) error {
	lb, err := s.requireLB()
	if err != nil {
		return err
	}
	protocol, target, err := restLBTarget(protocol, address, port)
	if err != nil {
		return err
	}
	return mapLBError(lb.RemoveVIP(ctx, protocol, target))
}

// SetVIPBackends replaces the backend set of a VIP.
func (s *gatewayRESTService) SetVIPBackends(ctx context.Context, protocol, address string, port uint16, backends []rest.LBBackend) (*rest.LBVIPResponse, error) {
	lb, err := s.requireLB()
	if err != nil {
		return nil, err
	}
	protocol, target, err := restLBTarget(protocol, address, port)
	if err != nil {
		return nil, err
	}
	serviceBackends, err := restLBBackends(backends)
	if err != nil {
		return nil, err
	}
	if err := lb.SetVIPBackends(ctx, protocol, target, serviceBackends); err != nil {
		return nil, mapLBError(err)
	}
	vip, err := lb.GetVIP(ctx, protocol, target)
	if err != nil {
		return nil, mapLBError(err)
	}
	return vipStatusToREST(vip), nil
}

// GetLBStatus returns the load balancer service health snapshot.
func (s *gatewayRESTService) GetLBStatus(ctx context.Context) (*rest.LBStatusResponse, error) {
	lb, err := s.requireLB()
	if err != nil {
		return nil, err
	}
	health, err := lb.LBStatus(ctx)
	if err != nil {
		return nil, mapLBError(err)
	}
	return &rest.LBStatusResponse{
		Active:          health.Active,
		VIPCount:        health.VIPCount,
		HealthyBackends: health.HealthyBackends,
		TotalBackends:   health.TotalBackends,
		LastReconcile:   health.LastReconcile,
	}, nil
}
