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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GatewayLoadBalancerInterface abstracts the gateway load balancer VIP
// operations for the API layers. *gateway.Gateway implements it by
// delegating to its running load balancer service.
type GatewayLoadBalancerInterface interface {
	AddVIP(ctx context.Context, vip loadbalancer.VIP) error
	RemoveVIP(ctx context.Context, protocol string, addr netip.AddrPort) error
	GetVIP(ctx context.Context, protocol string, addr netip.AddrPort) (loadbalancer.VIPStatus, error)
	ListVIPs(ctx context.Context) ([]loadbalancer.VIPStatus, error)
	SetVIPBackends(ctx context.Context, protocol string, addr netip.AddrPort, backends []loadbalancer.Backend) error
	LBStatus(ctx context.Context) (loadbalancer.Health, error)
}

// Ensure gateway.Gateway implements GatewayLoadBalancerInterface.
var _ GatewayLoadBalancerInterface = (*gateway.Gateway)(nil)

// WithLoadBalancer sets the load balancer backend for the service.
func WithLoadBalancer(lb GatewayLoadBalancerInterface) GatewayServiceOption {
	return func(s *GatewayService) {
		s.lb = lb
	}
}

// LoadBalancer returns the load balancer backend for testing purposes.
func (s *GatewayService) LoadBalancer() GatewayLoadBalancerInterface {
	return s.lb
}

// SetLoadBalancer sets the load balancer backend (useful for testing).
func (s *GatewayService) SetLoadBalancer(lb GatewayLoadBalancerInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lb = lb
}

// requireLB returns an error when the load balancer backend is not
// configured.
func (s *GatewayService) requireLB() error {
	if s.lb == nil {
		return status.Error(codes.Unavailable, "load balancer not configured")
	}
	return nil
}

// parseVIPTarget validates the protocol/address/port triple every keyed VIP
// RPC carries.
func parseVIPTarget(protocol, address string, port uint32) (string, netip.AddrPort, error) {
	if protocol == "" {
		return "", netip.AddrPort{}, status.Error(codes.InvalidArgument, "protocol is required")
	}
	if address == "" {
		return "", netip.AddrPort{}, status.Error(codes.InvalidArgument, "address is required")
	}
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return "", netip.AddrPort{}, status.Errorf(codes.InvalidArgument, "invalid address: %v", err)
	}
	if port == 0 || port > 65535 {
		return "", netip.AddrPort{}, status.Error(codes.InvalidArgument, "port must be 1-65535")
	}
	return protocol, netip.AddrPortFrom(addr, uint16(port)), nil
}

// vipBackendsFromProto converts proto backends to service backends.
func vipBackendsFromProto(backends []*platformv1.VIPBackend) ([]loadbalancer.Backend, error) {
	out := make([]loadbalancer.Backend, 0, len(backends))
	for _, b := range backends {
		if b.GetAddress() == "" {
			return nil, status.Error(codes.InvalidArgument, "backend address is required")
		}
		addr, err := netip.ParseAddr(b.GetAddress())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid backend address: %v", err)
		}
		if b.GetPort() == 0 || b.GetPort() > 65535 {
			return nil, status.Error(codes.InvalidArgument, "backend port must be 1-65535")
		}
		if b.GetWeight() > 65535 {
			return nil, status.Error(codes.InvalidArgument, "backend weight must be 0-65535")
		}
		out = append(out, loadbalancer.Backend{
			Address: addr,
			Port:    uint16(b.GetPort()),
			Weight:  uint16(b.GetWeight()),
		})
	}
	return out, nil
}

// vipFromProto converts a proto VIPConfig to a service VIP.
func vipFromProto(cfg *platformv1.VIPConfig) (loadbalancer.VIP, error) {
	if cfg == nil {
		return loadbalancer.VIP{}, status.Error(codes.InvalidArgument, "vip is required")
	}
	protocol, target, err := parseVIPTarget(cfg.GetProtocol(), cfg.GetAddress(), cfg.GetPort())
	if err != nil {
		return loadbalancer.VIP{}, err
	}
	backends, err := vipBackendsFromProto(cfg.GetBackends())
	if err != nil {
		return loadbalancer.VIP{}, err
	}
	return loadbalancer.VIP{
		Address:   target.Addr(),
		Port:      target.Port(),
		Protocol:  protocol,
		Algorithm: cfg.GetAlgorithm(),
		Backends:  backends,
	}, nil
}

// vipStatusToProto converts a service VIP status to its proto form.
func vipStatusToProto(s loadbalancer.VIPStatus) *platformv1.VIPStatus {
	cfg := &platformv1.VIPConfig{
		Address:   s.VIP.Address.String(),
		Port:      uint32(s.VIP.Port),
		Protocol:  s.VIP.Protocol,
		Algorithm: s.VIP.Algorithm,
		Backends:  make([]*platformv1.VIPBackend, 0, len(s.VIP.Backends)),
	}
	for _, b := range s.VIP.Backends {
		cfg.Backends = append(cfg.Backends, &platformv1.VIPBackend{
			Address: b.Address.String(),
			Port:    uint32(b.Port),
			Weight:  uint32(b.Weight),
		})
	}
	out := &platformv1.VIPStatus{
		Vip:      cfg,
		CtZone:   uint32(s.CTZone),
		GroupId:  s.GroupID,
		Backends: make([]*platformv1.VIPBackendStatus, 0, len(s.Backends)),
	}
	for _, b := range s.Backends {
		out.Backends = append(out.Backends, &platformv1.VIPBackendStatus{
			Backend: &platformv1.VIPBackend{
				Address: b.Backend.Address.String(),
				Port:    uint32(b.Backend.Port),
				Weight:  uint32(b.Backend.Weight),
			},
			Healthy: b.Healthy,
		})
	}
	return out
}

// lbErrToGRPC maps load balancer errors to gRPC status codes.
func lbErrToGRPC(err error) error {
	if err == nil {
		return nil
	}
	var notActive *gateway.ErrServiceNotActive
	switch {
	case errors.As(err, &notActive), errors.Is(err, loadbalancer.ErrNotStarted):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, loadbalancer.ErrVIPNotFound), errors.Is(err, loadbalancer.ErrBackendNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, loadbalancer.ErrVIPExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, loadbalancer.ErrAlgorithmUnsupported),
		errors.Is(err, loadbalancer.ErrInvalidVIPAddress),
		errors.Is(err, loadbalancer.ErrInvalidVIPPort),
		errors.Is(err, loadbalancer.ErrInvalidProtocol),
		errors.Is(err, loadbalancer.ErrNoBackends),
		errors.Is(err, loadbalancer.ErrTooManyBackends),
		errors.Is(err, loadbalancer.ErrInvalidBackend),
		errors.Is(err, loadbalancer.ErrDuplicateBackend):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Errorf(codes.Internal, "load balancer operation failed: %v", err)
	}
}

// AddVIP installs a load-balanced virtual IP.
func (s *GatewayService) AddVIP(ctx context.Context, req *platformv1.AddVIPRequest) (*platformv1.AddVIPResponse, error) {
	vip, err := vipFromProto(req.GetVip())
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireLB(); err != nil {
		return nil, err
	}
	if err := s.lb.AddVIP(ctx, vip); err != nil {
		return nil, lbErrToGRPC(err)
	}

	created, err := s.lb.GetVIP(ctx, vip.Protocol, netip.AddrPortFrom(vip.Address, vip.Port))
	if err != nil {
		return nil, lbErrToGRPC(err)
	}

	return &platformv1.AddVIPResponse{
		Status: &platformv1.Status{Success: true, Message: "VIP added successfully"},
		Vip:    vipStatusToProto(created),
	}, nil
}

// RemoveVIP tears down a load-balanced virtual IP.
func (s *GatewayService) RemoveVIP(ctx context.Context, req *platformv1.RemoveVIPRequest) (*platformv1.RemoveVIPResponse, error) {
	protocol, target, err := parseVIPTarget(req.GetProtocol(), req.GetAddress(), req.GetPort())
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireLB(); err != nil {
		return nil, err
	}
	if err := s.lb.RemoveVIP(ctx, protocol, target); err != nil {
		return nil, lbErrToGRPC(err)
	}

	return &platformv1.RemoveVIPResponse{
		Status: &platformv1.Status{Success: true, Message: "VIP removed successfully"},
	}, nil
}

// GetVIP returns the status of one load-balanced virtual IP.
func (s *GatewayService) GetVIP(ctx context.Context, req *platformv1.GetVIPRequest) (*platformv1.GetVIPResponse, error) {
	protocol, target, err := parseVIPTarget(req.GetProtocol(), req.GetAddress(), req.GetPort())
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.requireLB(); err != nil {
		return nil, err
	}
	vip, err := s.lb.GetVIP(ctx, protocol, target)
	if err != nil {
		return nil, lbErrToGRPC(err)
	}

	return &platformv1.GetVIPResponse{Vip: vipStatusToProto(vip)}, nil
}

// ListVIPs returns the status of every load-balanced virtual IP.
func (s *GatewayService) ListVIPs(ctx context.Context, req *platformv1.ListVIPsRequest) (*platformv1.ListVIPsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.requireLB(); err != nil {
		return nil, err
	}
	vips, err := s.lb.ListVIPs(ctx)
	if err != nil {
		return nil, lbErrToGRPC(err)
	}

	out := make([]*platformv1.VIPStatus, 0, len(vips))
	for _, vip := range vips {
		out = append(out, vipStatusToProto(vip))
	}
	return &platformv1.ListVIPsResponse{Vips: out}, nil
}

// SetVIPBackends replaces the backend set of a load-balanced virtual IP.
func (s *GatewayService) SetVIPBackends(ctx context.Context, req *platformv1.SetVIPBackendsRequest) (*platformv1.SetVIPBackendsResponse, error) {
	protocol, target, err := parseVIPTarget(req.GetProtocol(), req.GetAddress(), req.GetPort())
	if err != nil {
		return nil, err
	}
	backends, err := vipBackendsFromProto(req.GetBackends())
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireLB(); err != nil {
		return nil, err
	}
	if err := s.lb.SetVIPBackends(ctx, protocol, target, backends); err != nil {
		return nil, lbErrToGRPC(err)
	}

	updated, err := s.lb.GetVIP(ctx, protocol, target)
	if err != nil {
		return nil, lbErrToGRPC(err)
	}

	return &platformv1.SetVIPBackendsResponse{
		Status: &platformv1.Status{Success: true, Message: "VIP backends updated successfully"},
		Vip:    vipStatusToProto(updated),
	}, nil
}

// GetLBStatus returns the load balancer service health snapshot.
func (s *GatewayService) GetLBStatus(ctx context.Context, req *platformv1.GetLBStatusRequest) (*platformv1.GetLBStatusResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.requireLB(); err != nil {
		return nil, err
	}
	health, err := s.lb.LBStatus(ctx)
	if err != nil {
		return nil, lbErrToGRPC(err)
	}

	resp := &platformv1.GetLBStatusResponse{
		Status: &platformv1.LBStatus{
			Active:          health.Active,
			VipCount:        uint32(health.VIPCount),
			HealthyBackends: uint32(health.HealthyBackends),
			TotalBackends:   uint32(health.TotalBackends),
		},
	}
	if !health.LastReconcile.IsZero() {
		resp.Status.LastReconcile = timestamppb.New(health.LastReconcile)
	}
	return resp, nil
}
