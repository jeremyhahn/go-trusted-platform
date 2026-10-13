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

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sort"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// VPNRuntime is what the management VPN service needs from the gatewayd
// assembly (docs/vpn/engineering.md §1): the admission pipeline's
// collaborators and the data planes this host can run. The service runs the
// planes its configuration lists; a listed plane the assembly does not
// provide refuses the service.
type VPNRuntime struct {
	Identity vpn.IdentityPolicy
	Verifier vpn.Verifier
	Posture  vpn.PostureEvaluator
	Factors  vpn.FactorVerifier
	IPAM     ipam.Allocator
	// DataPlanes build the planes the host can run, keyed by kind. The
	// WireGuard plane exists only in non-FIPS builds.
	DataPlanes map[vpn.DataPlaneKind]VPNDataPlaneFactory
	// Leases is the lease store; nil keeps leases in memory.
	Leases vpn.LeaseStore
	Audit  calleradmission.Auditor
}

// VPNDataPlaneFactory builds a data plane. Every service start builds its
// planes afresh: a stopped MASQUE plane has closed its host device and cannot
// be started again.
type VPNDataPlaneFactory func(logger *slog.Logger) (vpn.ManagedDataPlane, error)

// buildManagementVPN builds the VPN service over the runtime's
// collaborators and the configured data planes.
func buildManagementVPN(g *Gateway) (backedService, error) {
	runtime := g.config.Runtime
	if runtime == nil || runtime.VPN == nil {
		return nil, &ErrRuntimeMissing{Service: ServiceManagementVPN}
	}
	cfg := g.config.ManagementVPN
	if cfg == nil {
		return nil, &ErrServiceUnavailable{Service: ServiceManagementVPN, Reason: "the management VPN needs a gateway.management_vpn section"}
	}
	rt := runtime.VPN
	logger := runtime.Logger
	if logger == nil {
		logger = slog.Default()
	}
	leases := rt.Leases
	if leases == nil {
		leases = vpn.NewMemoryLeaseStore()
	}

	// A kind with no factory is left out; vpn.New refuses the gap by name.
	planes := make(map[vpn.DataPlaneKind]vpn.DataPlane)
	var managed []vpn.ManagedDataPlane
	for _, kind := range cfg.Config.WithDefaults().DataPlanes {
		build := rt.DataPlanes[kind]
		if build == nil {
			continue
		}
		plane, err := build(logger)
		if err != nil {
			return nil, &ErrServiceStartFailed{Service: ServiceManagementVPN,
				Cause: errors.Join(err, stopPlanes(context.Background(), managed))}
		}
		planes[kind] = plane
		managed = append(managed, plane)
	}
	svc, err := vpn.New(vpn.Deps{
		Identity:   rt.Identity,
		Verifier:   rt.Verifier,
		Posture:    rt.Posture,
		Factors:    rt.Factors,
		IPAM:       rt.IPAM,
		DataPlanes: planes,
		Leases:     leases,
		Audit:      rt.Audit,
		Logger:     logger,
	}, cfg.Config)
	if err != nil {
		return nil, &ErrServiceStartFailed{Service: ServiceManagementVPN,
			Cause: errors.Join(err, stopPlanes(context.Background(), managed))}
	}
	return &vpnBackend{gateway: g, svc: svc, planes: managed, logger: logger}, nil
}

// vpnBackend runs the VPN service and the data planes it admits onto.
type vpnBackend struct {
	gateway *Gateway
	svc     *vpn.Service
	planes  []vpn.ManagedDataPlane
	logger  *slog.Logger
}

// Start brings the planes up, then the service, then applies the last vpn
// desired-config section. Until a section is applied nobody is enrolled, so
// the service admits nobody. A section that does not apply cleanly does not
// fail the start: the peers and tenants it refuses stay refused.
func (b *vpnBackend) Start(ctx context.Context) error {
	for i, plane := range b.planes {
		if err := plane.Start(ctx); err != nil {
			return errors.Join(err, stopPlanes(ctx, b.planes[:i]))
		}
	}
	if err := b.svc.Start(ctx); err != nil {
		return errors.Join(err, stopPlanes(ctx, b.planes))
	}

	g := b.gateway
	g.vpnMu.Lock()
	defer g.vpnMu.Unlock()
	if err := b.apply(ctx, g.desiredVPN); err != nil {
		b.logger.Warn("vpn: the desired configuration did not apply cleanly", slog.Any("error", err))
	}
	g.vpn = b
	return nil
}

// Stop revokes every lease, so the addresses return to the pool, then stops
// the service and the planes in reverse order.
func (b *vpnBackend) Stop(ctx context.Context) error {
	g := b.gateway
	g.vpnMu.Lock()
	if g.vpn == b {
		g.vpn = nil
	}
	g.vpnMu.Unlock()

	var errs []error
	leases, err := b.svc.Leases(ctx)
	if err != nil {
		errs = append(errs, err)
	}
	for _, l := range leases {
		if err := b.svc.Revoke(ctx, l.ID, vpn.RevokeOperator); err != nil {
			errs = append(errs, err)
		}
	}
	if err := b.svc.Stop(ctx); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs, stopPlanes(ctx, b.planes))
	return errors.Join(errs...)
}

// Active reports whether the admission service is running.
func (b *vpnBackend) Active() bool { return b.svc.Active() }

// Healthy is Active: the planes report failures through admission.
func (b *vpnBackend) Healthy() bool { return b.svc.Active() }

// apply hands a vpn desired-config section to the service: the tenant
// posture policies first, so a newly enrolled peer is never judged by a
// policy its tenant has replaced, then the enrolment set.
func (b *vpnBackend) apply(ctx context.Context, section *gwstate.DesiredVPN) error {
	if section == nil {
		return nil
	}
	policies := make([]vpn.PosturePolicy, 0, len(section.PosturePolicies))
	for _, p := range section.PosturePolicies {
		policies = append(policies, vpn.PosturePolicy{TenantID: p.TenantID, Name: p.Name, Module: p.Module})
	}
	enrolments := make([]vpn.Enrolment, 0, len(section.Peers))
	for _, p := range section.Peers {
		enrolments = append(enrolments, vpn.Enrolment{TenantID: p.TenantID, DeviceID: p.DeviceID, Zones: slices.Clone(p.Zones)})
	}
	return errors.Join(b.svc.SetPosturePolicies(ctx, policies), b.svc.SetEnrolments(ctx, enrolments))
}

// state is the backend's telemetry snapshot section.
func (b *vpnBackend) state(ctx context.Context) (*gwstate.VPNState, error) {
	health := b.svc.Health()
	out := &gwstate.VPNState{
		Running:             health.Active,
		Admissions:          health.Admissions,
		Refusals:            health.Refusals,
		LastRefusal:         health.LastRefusal,
		EnrolledPeers:       len(b.svc.Enrolments()),
		PosturePolicyErrors: b.svc.PosturePolicyErrors(),
	}
	for _, r := range b.svc.RejectedEnrolments() {
		out.RejectedPeers = append(out.RejectedPeers, gwstate.VPNRejectedPeer{TenantID: r.TenantID, DeviceID: r.DeviceID, Reason: r.Reason})
	}
	if len(health.LeasesByDataPlane) > 0 {
		out.LeasesByDataPlane = make(map[string]int, len(health.LeasesByDataPlane))
		for kind, n := range health.LeasesByDataPlane {
			out.LeasesByDataPlane[string(kind)] = n
		}
	}
	leases, err := b.svc.Leases(ctx)
	if err != nil {
		return out, err
	}
	for _, l := range leases {
		out.Leases = append(out.Leases, gwstate.VPNLeaseState{
			ID:        string(l.ID),
			TenantID:  l.TenantID,
			DeviceID:  l.DeviceID,
			Address:   l.Address.String(),
			DataPlane: string(l.DataPlane),
			Zones:     slices.Clone(l.Zones),
			IssuedAt:  l.IssuedAt,
			ExpiresAt: l.ExpiresAt,
			Renewals:  l.Renewals,
		})
	}
	sort.Slice(out.Leases, func(i, j int) bool { return out.Leases[i].ID < out.Leases[j].ID })
	return out, nil
}

// stopPlanes stops the planes in reverse order and joins the failures.
func stopPlanes(ctx context.Context, planes []vpn.ManagedDataPlane) error {
	var errs []error
	for i := len(planes) - 1; i >= 0; i-- {
		if err := planes[i].Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// applyVPN records the vpn desired-config section and applies it to the
// running VPN service. A gateway that does not run the VPN ignores the
// section: the control plane delivers one enrolment set to every gateway. A
// service still starting picks the recorded section up as it starts.
func (g *Gateway) applyVPN(ctx context.Context, section *gwstate.DesiredVPN) error {
	if section == nil || g.config.ManagementVPN == nil || !g.config.ManagementVPN.Enabled {
		return nil
	}
	if g.supervises(ServiceManagementVPN) {
		return &ErrServiceUnavailable{Service: ServiceManagementVPN,
			Reason: "the supervised vpn process does not receive the desired configuration"}
	}
	g.vpnMu.Lock()
	defer g.vpnMu.Unlock()
	g.desiredVPN = section
	if g.vpn == nil {
		return nil
	}
	return g.vpn.apply(ctx, section)
}

// collectVPN is the snapshot's vpn section; nil when the service is not
// running here.
func (g *Gateway) collectVPN(ctx context.Context) *gwstate.VPNState {
	g.vpnMu.Lock()
	backend := g.vpn
	g.vpnMu.Unlock()
	if backend == nil {
		return nil
	}
	out, err := backend.state(ctx)
	if err != nil {
		g.logSnapshot("vpn leases unavailable for the snapshot", err)
	}
	return out
}
