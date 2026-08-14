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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
)

// =============================================================================
// zoneGatewayAdapter — no load balancer backing
// =============================================================================

func (a *zoneGatewayAdapter) AddVIP(_ context.Context, _ *quic.LBVIPSpec) (*quic.LBVIPInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) RemoveVIP(_ context.Context, _, _ string, _ uint16) error {
	return errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) GetVIP(_ context.Context, _, _ string, _ uint16) (*quic.LBVIPInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) ListVIPs(_ context.Context) ([]*quic.LBVIPInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) SetVIPBackends(_ context.Context, _, _ string, _ uint16, _ []*quic.LBBackendSpec) (*quic.LBVIPInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) LBStatus(_ context.Context) (*quic.LBStatusInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

// =============================================================================
// fullGatewayQUICAdapter — backed by the gateway load balancer when wired
// =============================================================================

// SetLoadBalancer wires the gateway load balancer backend into the QUIC
// gateway adapter. A nil backend leaves every VIP operation returning
// errGatewayFeatureNotConfigured (StatusUnavailable on the wire).
func (a *fullGatewayQUICAdapter) SetLoadBalancer(lb GatewayLoadBalancerInterface) {
	a.lb = lb
}

// requireLB resolves the load balancer backend or reports not-configured.
func (a *fullGatewayQUICAdapter) requireLB() (GatewayLoadBalancerInterface, error) {
	if a.lb == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	return a.lb, nil
}

// mapLBToQUICError translates load balancer errors to the sentinel errors
// recognised by quic.GatewayHandler.gatewayErrorResponse.
func mapLBToQUICError(err error) error {
	if err == nil {
		return nil
	}
	var notActive *gateway.ErrServiceNotActive
	switch {
	case errors.As(err, &notActive), errors.Is(err, loadbalancer.ErrNotStarted):
		return quic.ErrGatewayFeatureNotConfigured
	case errors.Is(err, loadbalancer.ErrVIPNotFound), errors.Is(err, loadbalancer.ErrBackendNotFound):
		return quic.ErrGatewayVIPNotFound
	case errors.Is(err, loadbalancer.ErrVIPExists):
		return quic.ErrGatewayVIPAlreadyExists
	case errors.Is(err, loadbalancer.ErrAlgorithmUnsupported),
		errors.Is(err, loadbalancer.ErrInvalidVIPAddress),
		errors.Is(err, loadbalancer.ErrInvalidVIPPort),
		errors.Is(err, loadbalancer.ErrInvalidProtocol),
		errors.Is(err, loadbalancer.ErrNoBackends),
		errors.Is(err, loadbalancer.ErrTooManyBackends),
		errors.Is(err, loadbalancer.ErrInvalidBackend),
		errors.Is(err, loadbalancer.ErrDuplicateBackend):
		return quic.ErrGatewayInvalidVIP
	default:
		return err
	}
}

// quicLBTarget parses the protocol/address/port triple of keyed VIP calls.
func quicLBTarget(protocol, address string, port uint16) (string, netip.AddrPort, error) {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return "", netip.AddrPort{}, quic.ErrGatewayMissingVIPTarget
	}
	if protocol == "" || port == 0 {
		return "", netip.AddrPort{}, quic.ErrGatewayMissingVIPTarget
	}
	return protocol, netip.AddrPortFrom(addr, port), nil
}

// quicLBBackends converts QUIC wire backends to service backends.
func quicLBBackends(backends []*quic.LBBackendSpec) ([]loadbalancer.Backend, error) {
	out := make([]loadbalancer.Backend, 0, len(backends))
	for _, b := range backends {
		if b == nil {
			return nil, quic.ErrGatewayInvalidVIP
		}
		addr, err := netip.ParseAddr(b.Address)
		if err != nil {
			return nil, quic.ErrGatewayInvalidVIP
		}
		out = append(out, loadbalancer.Backend{Address: addr, Port: b.Port, Weight: b.Weight})
	}
	return out, nil
}

// vipStatusToQUICInfo converts a service VIP status to the QUIC wire shape.
func vipStatusToQUICInfo(s loadbalancer.VIPStatus) *quic.LBVIPInfo {
	info := &quic.LBVIPInfo{
		Address:   s.VIP.Address.String(),
		Port:      s.VIP.Port,
		Protocol:  s.VIP.Protocol,
		Algorithm: s.VIP.Algorithm,
		CTZone:    s.CTZone,
		GroupID:   s.GroupID,
		Backends:  make([]*quic.LBBackendInfo, 0, len(s.Backends)),
	}
	for _, b := range s.Backends {
		info.Backends = append(info.Backends, &quic.LBBackendInfo{
			Backend: &quic.LBBackendSpec{
				Address: b.Backend.Address.String(),
				Port:    b.Backend.Port,
				Weight:  b.Backend.Weight,
			},
			Healthy: b.Healthy,
		})
	}
	return info
}

// AddVIP installs a load-balanced virtual IP.
func (a *fullGatewayQUICAdapter) AddVIP(ctx context.Context, spec *quic.LBVIPSpec) (*quic.LBVIPInfo, error) {
	lb, err := a.requireLB()
	if err != nil {
		return nil, err
	}
	if spec == nil {
		return nil, quic.ErrGatewayMissingVIPTarget
	}
	protocol, target, err := quicLBTarget(spec.Protocol, spec.Address, spec.Port)
	if err != nil {
		return nil, err
	}
	backends, err := quicLBBackends(spec.Backends)
	if err != nil {
		return nil, err
	}

	vip := loadbalancer.VIP{
		Address:   target.Addr(),
		Port:      target.Port(),
		Protocol:  protocol,
		Algorithm: spec.Algorithm,
		Backends:  backends,
	}
	if err := lb.AddVIP(ctx, vip); err != nil {
		return nil, mapLBToQUICError(err)
	}

	created, err := lb.GetVIP(ctx, protocol, target)
	if err != nil {
		return nil, mapLBToQUICError(err)
	}
	return vipStatusToQUICInfo(created), nil
}

// RemoveVIP tears down a load-balanced virtual IP.
func (a *fullGatewayQUICAdapter) RemoveVIP(ctx context.Context, protocol, address string, port uint16) error {
	lb, err := a.requireLB()
	if err != nil {
		return err
	}
	protocol, target, err := quicLBTarget(protocol, address, port)
	if err != nil {
		return err
	}
	return mapLBToQUICError(lb.RemoveVIP(ctx, protocol, target))
}

// GetVIP returns one VIP's status.
func (a *fullGatewayQUICAdapter) GetVIP(ctx context.Context, protocol, address string, port uint16) (*quic.LBVIPInfo, error) {
	lb, err := a.requireLB()
	if err != nil {
		return nil, err
	}
	protocol, target, err := quicLBTarget(protocol, address, port)
	if err != nil {
		return nil, err
	}
	vip, err := lb.GetVIP(ctx, protocol, target)
	if err != nil {
		return nil, mapLBToQUICError(err)
	}
	return vipStatusToQUICInfo(vip), nil
}

// ListVIPs returns every VIP's status.
func (a *fullGatewayQUICAdapter) ListVIPs(ctx context.Context) ([]*quic.LBVIPInfo, error) {
	lb, err := a.requireLB()
	if err != nil {
		return nil, err
	}
	vips, err := lb.ListVIPs(ctx)
	if err != nil {
		return nil, mapLBToQUICError(err)
	}
	out := make([]*quic.LBVIPInfo, 0, len(vips))
	for _, vip := range vips {
		out = append(out, vipStatusToQUICInfo(vip))
	}
	return out, nil
}

// SetVIPBackends replaces a VIP's backend set.
func (a *fullGatewayQUICAdapter) SetVIPBackends(ctx context.Context, protocol, address string, port uint16, backends []*quic.LBBackendSpec) (*quic.LBVIPInfo, error) {
	lb, err := a.requireLB()
	if err != nil {
		return nil, err
	}
	protocol, target, err := quicLBTarget(protocol, address, port)
	if err != nil {
		return nil, err
	}
	serviceBackends, err := quicLBBackends(backends)
	if err != nil {
		return nil, err
	}
	if err := lb.SetVIPBackends(ctx, protocol, target, serviceBackends); err != nil {
		return nil, mapLBToQUICError(err)
	}
	vip, err := lb.GetVIP(ctx, protocol, target)
	if err != nil {
		return nil, mapLBToQUICError(err)
	}
	return vipStatusToQUICInfo(vip), nil
}

// LBStatus returns the load balancer service health snapshot.
func (a *fullGatewayQUICAdapter) LBStatus(ctx context.Context) (*quic.LBStatusInfo, error) {
	lb, err := a.requireLB()
	if err != nil {
		return nil, err
	}
	health, err := lb.LBStatus(ctx)
	if err != nil {
		return nil, mapLBToQUICError(err)
	}
	info := &quic.LBStatusInfo{
		Active:          health.Active,
		VIPCount:        health.VIPCount,
		HealthyBackends: health.HealthyBackends,
		TotalBackends:   health.TotalBackends,
	}
	if !health.LastReconcile.IsZero() {
		info.LastReconcile = health.LastReconcile.Unix()
	}
	return info, nil
}
