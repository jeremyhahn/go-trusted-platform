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
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/firewall"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
)

// Service name constants used as keys in the service handler registry.
const (
	ServiceOverlay      = "overlay"
	ServiceEdge         = "edge"
	ServiceTransit      = "transit"
	ServiceFirewall     = "firewall"
	ServiceBGP          = "bgp"
	ServiceDHCP         = "dhcp"
	ServicePXE          = "pxe"
	ServiceLoadBalancer = "load-balancer"
	ServiceNAT          = "nat"
	// ServiceNAT64 is the stateful NAT64 translator (#601, ruling R6).
	ServiceNAT64   = "nat64"
	ServiceTunnels = "tunnels"
	ServiceProxy   = "proxy"
	// ServiceHostFW is the nftables host packet filter (#569).
	ServiceHostFW = "hostfw"
	// ServiceManagementVPN is the attested remote-access VPN; a design
	// (docs/vpn/) with no implementation, so enabling it is refused.
	ServiceManagementVPN = "management-vpn"
)

// Gateway manages the lifecycle and operations of a gateway node.
type Gateway struct {
	config *GatewayConfig
	node   *GatewayNode

	// Service handlers keyed by service name
	serviceHandlers map[string]ServiceHandler

	// serviceOrder is the registration order of serviceHandlers: the
	// config-driven sections in enabledServices order, then externally
	// registered handlers. Start walks it so the datapath services come up
	// in a fixed order rather than map order.
	serviceOrder []string

	// Ordered list of active service names for deterministic start/stop
	activeOrder []string

	// State
	state     atomic.Uint32
	startedAt time.Time
	mu        sync.RWMutex

	// Channels for coordination
	stopCh chan struct{}

	// desired records desired-config reconciliation (reconcile.go, #555).
	// Its zero value is usable so a Gateway built as a struct literal
	// reconciles without initialisation.
	desired desiredState
}

// NewGateway creates a new gateway with the given configuration.
func NewGateway(config *GatewayConfig) (*Gateway, error) {
	if config == nil {
		return nil, ErrConfigNil
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}

	node := &GatewayNode{
		ID:             config.ID,
		NodeID:         config.NodeID,
		ActiveServices: make(map[string]bool),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	g := &Gateway{
		config:          config,
		node:            node,
		serviceHandlers: make(map[string]ServiceHandler),
		stopCh:          make(chan struct{}),
	}

	// Register one handler per enabled config section: a real, backed
	// handler where a builder exists, a typed refusal where none does
	// (#568). Nothing is registered as a bool that reports itself running.
	g.registerConfiguredServices()

	g.state.Store(uint32(GatewayStateStopped))

	return g, nil
}

// RegisterServiceHandler registers an externally constructed service
// handler (e.g. the proxysvc reverse-proxy handler assembled by gatewayd).
// Registration is only permitted while the gateway is stopped; registered
// handlers participate in Start/Stop ordering and health like the built-in
// config-driven handlers.
func (g *Gateway) RegisterServiceHandler(handler ServiceHandler) error {
	if handler == nil {
		return &ErrNilServiceHandler{}
	}
	name := handler.Name()
	if name == "" {
		return &ErrNilServiceHandler{}
	}
	if GatewayState(g.state.Load()) != GatewayStateStopped {
		return &ErrInvalidState{Expected: GatewayStateStopped, Actual: GatewayState(g.state.Load())}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.serviceHandlers[name]; exists {
		return &ErrServiceAlreadyExists{ServiceID: name}
	}
	g.serviceHandlers[name] = handler
	g.serviceOrder = append(g.serviceOrder, name)
	return nil
}

// Start starts the gateway and activates all configured services.
func (g *Gateway) Start(ctx context.Context) error {
	if !g.state.CompareAndSwap(uint32(GatewayStateStopped), uint32(GatewayStateInitializing)) {
		currentState := GatewayState(g.state.Load())
		if currentState == GatewayStateRunning || currentState == GatewayStateInitializing {
			return ErrGatewayAlreadyRunning
		}
		return &ErrInvalidState{Expected: GatewayStateStopped, Actual: currentState}
	}

	// Check requirements
	if err := g.MeetsRequirements(); err != nil {
		g.state.Store(uint32(GatewayStateStopped))
		return &ErrStartupFailed{GatewayID: g.config.ID, Phase: "requirements-check", Cause: err}
	}

	// The base pipeline goes in before any service handler: every datapath
	// service gates out of table 10, and handler iteration is map-random,
	// so the hand-off from table 0 must already exist (#567). A gateway
	// with no datapath service enabled has no runtime and installs nothing.
	if g.config.needsPipeline() {
		if err := g.config.Runtime.EnsurePipeline(ctx, g.config.ID, g.config.pipelineTerminal()); err != nil {
			g.state.Store(uint32(GatewayStateError))
			return &ErrStartupFailed{GatewayID: g.config.ID, Phase: "pipeline", Cause: err}
		}
	}

	// Start every registered service handler, in registration order.
	g.mu.RLock()
	order := append([]string(nil), g.serviceOrder...)
	g.mu.RUnlock()
	for _, name := range order {
		handler := g.serviceHandlers[name]
		if err := handler.Start(ctx); err != nil {
			// Rollback: stop already started services
			g.rollbackStartedServices(ctx)
			g.state.Store(uint32(GatewayStateError))
			startErr := namedStartError(name, err)
			if rmErr := g.removePipeline(ctx); rmErr != nil {
				// The service failure is the cause the operator acts on; the
				// pipeline left behind is reported beside it, not instead.
				return &ErrStartupFailed{GatewayID: g.config.ID, Phase: "service-start", Cause: &ErrRollbackIncomplete{Cause: startErr, Rollback: rmErr}}
			}
			return &ErrStartupFailed{GatewayID: g.config.ID, Phase: "service-start", Cause: startErr}
		}
		g.mu.Lock()
		g.node.ActiveServices[name] = true
		g.activeOrder = append(g.activeOrder, name)
		g.node.UpdatedAt = time.Now()
		g.mu.Unlock()
	}

	g.mu.Lock()
	g.startedAt = time.Now()
	g.stopCh = make(chan struct{})
	g.mu.Unlock()

	g.state.Store(uint32(GatewayStateRunning))
	return nil
}

// namedStartError attributes a handler's start error to its service once:
// a handler that already reports ErrServiceStartFailed is passed through so
// the operator does not read the same service name twice.
func namedStartError(name string, err error) error {
	var failed *ErrServiceStartFailed
	if errors.As(err, &failed) {
		return err
	}
	return &ErrServiceStartFailed{Service: name, Cause: err}
}

// rollbackStartedServices stops any services that were already started during a failed Start.
func (g *Gateway) rollbackStartedServices(ctx context.Context) {
	g.mu.Lock()
	order := make([]string, len(g.activeOrder))
	copy(order, g.activeOrder)
	g.mu.Unlock()

	// Stop in reverse order. The start error is what the caller sees; a
	// backend that will not stop during rollback is logged so the failure is
	// still visible.
	logger := g.config.hostRuntime().Logger
	for i := len(order) - 1; i >= 0; i-- {
		name := order[i]
		if handler, ok := g.serviceHandlers[name]; ok {
			if err := handler.Stop(ctx); err != nil {
				logger.Warn("gateway: rollback stop failed", slog.String("service", name), slog.Any("error", err))
			}
		}
	}

	g.mu.Lock()
	g.node.ActiveServices = make(map[string]bool)
	g.activeOrder = nil
	g.mu.Unlock()
}

// Stop gracefully shuts down the gateway.
func (g *Gateway) Stop(ctx context.Context) error {
	currentState := GatewayState(g.state.Load())
	if currentState == GatewayStateStopped || currentState == GatewayStateStopping {
		return nil
	}

	if !g.state.CompareAndSwap(uint32(currentState), uint32(GatewayStateStopping)) {
		return &ErrInvalidState{Expected: currentState, Actual: GatewayState(g.state.Load())}
	}

	// Close stop channel to signal shutdown
	g.mu.Lock()
	select {
	case <-g.stopCh:
		// Already closed
	default:
		close(g.stopCh)
	}
	order := make([]string, len(g.activeOrder))
	copy(order, g.activeOrder)
	g.mu.Unlock()

	// Stop services in reverse order
	for i := len(order) - 1; i >= 0; i-- {
		name := order[i]
		handler, ok := g.serviceHandlers[name]
		if !ok {
			continue
		}
		if err := handler.Stop(ctx); err != nil {
			g.state.Store(uint32(GatewayStateError))
			return &ErrShutdownFailed{GatewayID: g.config.ID, Phase: "service-stop", Cause: &ErrServiceStopFailed{Service: name, Cause: err}}
		}
	}

	// The pipeline comes out after the last service gate is gone, so no
	// packet is ever routed into a table whose rules have been deleted.
	if err := g.removePipeline(ctx); err != nil {
		g.state.Store(uint32(GatewayStateError))
		return &ErrShutdownFailed{GatewayID: g.config.ID, Phase: "pipeline", Cause: err}
	}

	g.mu.Lock()
	g.node.ActiveServices = make(map[string]bool)
	g.activeOrder = nil
	g.node.UpdatedAt = time.Now()
	g.mu.Unlock()

	g.state.Store(uint32(GatewayStateStopped))
	return nil
}

// removePipeline tears the base pipeline down when this gateway installed
// one; it is safe to call when none is installed.
func (g *Gateway) removePipeline(ctx context.Context) error {
	if g.config.Runtime == nil {
		return nil
	}
	return g.config.Runtime.RemovePipeline(ctx)
}

// GetStatus returns the current gateway status.
func (g *Gateway) GetStatus() *GatewayStatus {
	g.mu.RLock()
	defer g.mu.RUnlock()

	state := GatewayState(g.state.Load())
	status := &GatewayStatus{
		ID:    g.config.ID,
		State: state,
	}

	// Copy active service names and populate deprecated ActiveModes
	for name := range g.node.ActiveServices {
		status.ActiveServiceNames = append(status.ActiveServiceNames, name)
		if mode, ok := serviceToMode[name]; ok {
			status.ActiveModes |= mode
		}
	}

	if state.IsOperational() && !g.startedAt.IsZero() {
		status.Uptime = time.Since(g.startedAt)
		status.StartedAt = g.startedAt
	}

	// Copy service states if active
	if g.node.OverlayState != nil {
		stateCopy := *g.node.OverlayState
		status.OverlayState = &stateCopy
	}
	if g.node.EdgeState != nil {
		stateCopy := *g.node.EdgeState
		status.EdgeState = &stateCopy
	}
	if g.node.TransitState != nil {
		stateCopy := *g.node.TransitState
		status.TransitState = &stateCopy
	}

	return status
}

// MeetsRequirements checks if the node meets all gateway requirements.
func (g *Gateway) MeetsRequirements() error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var checks []RequirementCheck

	// Check reputation
	minRep := g.config.MinReputation
	if minRep == 0 {
		minRep = MinReputation
	}
	if g.node.Reputation < minRep {
		checks = append(checks, RequirementCheck{
			Name:     "reputation",
			Required: formatFloat(minRep),
			Actual:   formatFloat(g.node.Reputation),
			Passed:   false,
		})
	}

	// Check age
	minAgeDays := g.config.MinAgeDays
	if minAgeDays == 0 {
		minAgeDays = MinAgeDays
	}
	minAge := time.Duration(minAgeDays) * 24 * time.Hour
	actualDays := int(g.node.Age.Hours() / 24)
	if g.node.Age < minAge {
		checks = append(checks, RequirementCheck{
			Name:     "age",
			Required: formatDays(minAgeDays),
			Actual:   formatDays(actualDays),
			Passed:   false,
		})
	}

	// Check uptime
	minUptime := g.config.MinUptimePct
	if minUptime == 0 {
		minUptime = MinUptimePct
	}
	if g.node.Uptime < minUptime {
		checks = append(checks, RequirementCheck{
			Name:     "uptime",
			Required: formatPercent(minUptime),
			Actual:   formatPercent(g.node.Uptime),
			Passed:   false,
		})
	}

	if len(checks) > 0 {
		return &ErrRequirementsNotMet{GatewayID: g.config.ID, Checks: checks}
	}
	return nil
}

// IsRunning returns true if the gateway is running.
func (g *Gateway) IsRunning() bool {
	state := GatewayState(g.state.Load())
	return state == GatewayStateRunning
}

// IsOperational returns true if the gateway is operational (running or degraded).
func (g *Gateway) IsOperational() bool {
	state := GatewayState(g.state.Load())
	return state.IsOperational()
}

// GetState returns the current gateway state.
func (g *Gateway) GetState() GatewayState {
	return GatewayState(g.state.Load())
}

// GetNode returns a copy of the gateway node.
func (g *Gateway) GetNode() GatewayNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	nodeCopy := *g.node
	// Deep copy the active services map
	nodeCopy.ActiveServices = make(map[string]bool, len(g.node.ActiveServices))
	for k, v := range g.node.ActiveServices {
		nodeCopy.ActiveServices[k] = v
	}
	return nodeCopy
}

// GetConfig returns the gateway configuration.
func (g *Gateway) GetConfig() *GatewayConfig {
	return g.config
}

// HasService returns true if the specified service is active.
func (g *Gateway) HasService(name string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.node.ActiveServices[name]
}

// ActiveServices returns the names of currently active services.
func (g *Gateway) ActiveServices() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	// activeOrder is the start order, which is the declared order of the
	// config sections followed by externally registered handlers.
	result := make([]string, 0, len(g.activeOrder))
	for _, name := range g.activeOrder {
		if g.node.ActiveServices[name] {
			result = append(result, name)
		}
	}
	return result
}

// SetNodeMetrics updates the node metrics used for requirement checks.
func (g *Gateway) SetNodeMetrics(reputation float64, age time.Duration, uptime float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.node.Reputation = reputation
	g.node.Age = age
	g.node.Uptime = uptime
	g.node.UpdatedAt = time.Now()
}

// Uptime returns how long the gateway has been running.
func (g *Gateway) Uptime() time.Duration {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.IsOperational() || g.startedAt.IsZero() {
		return 0
	}
	return time.Since(g.startedAt)
}

// formatFloat formats a float64 with 2 decimal places.
func formatFloat(v float64) string {
	return formatPercent(v * 100)[0 : len(formatPercent(v*100))-1]
}

// formatDays formats days as a string.
func formatDays(days int) string {
	return string(rune('0'+days/100)) + string(rune('0'+(days%100)/10)) + string(rune('0'+days%10)) + " days"
}

// formatPercent formats a percentage.
func formatPercent(pct float64) string {
	whole := int(pct)
	frac := int((pct - float64(whole)) * 10)
	if frac < 0 {
		frac = -frac
	}
	result := ""
	if whole == 0 {
		result = "0"
	} else {
		for whole > 0 {
			result = string(rune('0'+whole%10)) + result
			whole /= 10
		}
	}
	return result + "." + string(rune('0'+frac)) + "%"
}

// FirewallHealth returns the firewall service health snapshot, or false
// when the firewall service is not registered or not started.
func (g *Gateway) FirewallHealth() (firewall.Health, bool) {
	svc, ok := g.firewallService()
	if !ok {
		return firewall.Health{}, false
	}
	return svc.Health(), true
}

// ReconcileFirewall recompiles the firewall rule set from the current zone
// state and converges the datapath.
func (g *Gateway) ReconcileFirewall(ctx context.Context) error {
	svc, ok := g.firewallService()
	if !ok {
		return &ErrServiceNotActive{Service: ServiceFirewall}
	}
	return svc.Reconcile(ctx)
}

// firewallService returns the running firewall service, or false.
func (g *Gateway) firewallService() (*firewall.Service, bool) {
	b, ok := g.backend(ServiceFirewall)
	if !ok {
		return nil, false
	}
	fw, ok := b.(firewallBackend)
	if !ok {
		return nil, false
	}
	return fw.Service, true
}

// LBHealth returns the load balancer service health snapshot, or false when
// the load balancer service is not registered or not started.
func (g *Gateway) LBHealth() (loadbalancer.Health, bool) {
	svc, ok := g.LBService()
	if !ok {
		return loadbalancer.Health{}, false
	}
	return svc.Health(), true
}

// LBService returns the running load balancer service for VIP management,
// or false when the load balancer service is not registered or started.
func (g *Gateway) LBService() (*loadbalancer.Service, bool) {
	b, ok := g.backend(ServiceLoadBalancer)
	if !ok {
		return nil, false
	}
	lb, ok := b.(loadBalancerBackend)
	if !ok {
		return nil, false
	}
	return lb.Service, true
}

// lbService resolves the running load balancer service or returns the typed
// not-active error used by the VIP management API surface.
func (g *Gateway) lbService() (*loadbalancer.Service, error) {
	svc, ok := g.LBService()
	if !ok {
		return nil, &ErrServiceNotActive{Service: ServiceLoadBalancer}
	}
	return svc, nil
}

// AddVIP installs a load-balanced virtual IP on the running load balancer.
func (g *Gateway) AddVIP(ctx context.Context, vip loadbalancer.VIP) error {
	svc, err := g.lbService()
	if err != nil {
		return err
	}
	return svc.AddVIP(ctx, vip)
}

// RemoveVIP tears down a load-balanced virtual IP.
func (g *Gateway) RemoveVIP(ctx context.Context, protocol string, addr netip.AddrPort) error {
	svc, err := g.lbService()
	if err != nil {
		return err
	}
	return svc.RemoveVIP(ctx, protocol, addr)
}

// GetVIP returns the status of one load-balanced virtual IP.
func (g *Gateway) GetVIP(ctx context.Context, protocol string, addr netip.AddrPort) (loadbalancer.VIPStatus, error) {
	svc, err := g.lbService()
	if err != nil {
		return loadbalancer.VIPStatus{}, err
	}
	return svc.GetVIP(protocol, addr)
}

// ListVIPs returns the status of every load-balanced virtual IP.
func (g *Gateway) ListVIPs(ctx context.Context) ([]loadbalancer.VIPStatus, error) {
	svc, err := g.lbService()
	if err != nil {
		return nil, err
	}
	return svc.ListVIPs(), nil
}

// SetVIPBackends replaces the backend set of a load-balanced virtual IP.
func (g *Gateway) SetVIPBackends(ctx context.Context, protocol string, addr netip.AddrPort, backends []loadbalancer.Backend) error {
	svc, err := g.lbService()
	if err != nil {
		return err
	}
	return svc.SetBackends(ctx, protocol, addr, backends)
}

// LBStatus returns the load balancer health snapshot, or the typed
// not-active error when the service is not running.
func (g *Gateway) LBStatus(ctx context.Context) (loadbalancer.Health, error) {
	svc, err := g.lbService()
	if err != nil {
		return loadbalancer.Health{}, err
	}
	return svc.Health(), nil
}

// NATHealth returns the NAT service health snapshot, or false when the NAT
// service is not registered or not started.
func (g *Gateway) NATHealth() (firewall.NATHealth, bool) {
	svc, ok := g.NATService()
	if !ok {
		return firewall.NATHealth{}, false
	}
	return svc.Health(), true
}

// NATService returns the running NAT service for SNAT/DNAT rule
// management, or false when the NAT service is not registered or started.
func (g *Gateway) NATService() (*firewall.NAT, bool) {
	b, ok := g.backend(ServiceNAT)
	if !ok {
		return nil, false
	}
	nat, ok := b.(natBackend)
	if !ok {
		return nil, false
	}
	return nat.NAT, true
}

// NAT64Service returns the running NAT64 translator service, or false when
// the section is not registered, is refused, or has not started.
func (g *Gateway) NAT64Service() (*nat64.Service, bool) {
	b, ok := g.backend(ServiceNAT64)
	if !ok {
		return nil, false
	}
	svc, ok := b.(nat64Backend)
	if !ok {
		return nil, false
	}
	return svc.Service, true
}

// NAT64Status returns the NAT64 service health snapshot. It is the API
// layers' entry point, so an unregistered or unstarted section is a typed
// error rather than a zero value that reads as a healthy translator.
func (g *Gateway) NAT64Status(ctx context.Context) (nat64.Health, error) {
	svc, ok := g.NAT64Service()
	if !ok {
		return nat64.Health{}, &ErrServiceNotActive{Service: ServiceNAT64}
	}
	return svc.Health(), nil
}

// HostFWService returns the running host packet filter, or false when the
// hostfw service is not registered or started.
func (g *Gateway) HostFWService() (*hostfw.Service, bool) {
	b, ok := g.backend(ServiceHostFW)
	if !ok {
		return nil, false
	}
	h, ok := b.(hostFWBackend)
	if !ok {
		return nil, false
	}
	return h.Service, true
}

// ReconcileHostFW re-renders the host filter from the current listener
// inventory and applies it atomically.
func (g *Gateway) ReconcileHostFW(ctx context.Context) error {
	svc, ok := g.HostFWService()
	if !ok {
		return &ErrServiceNotActive{Service: ServiceHostFW}
	}
	return svc.Reconcile(ctx)
}

// BGPSpeaker returns the running transit BGP speaker, or false when the
// transit service is not registered or started.
func (g *Gateway) BGPSpeaker() (*bgp.Speaker, bool) {
	b, ok := g.backend(ServiceTransit)
	if !ok {
		return nil, false
	}
	t, ok := b.(*transitBackend)
	if !ok {
		return nil, false
	}
	speaker := t.Speaker()
	if speaker == nil {
		return nil, false
	}
	return speaker, true
}

func (g *Gateway) GetAdmittedVTEP(ctx context.Context, vtep netip.Addr) (*AdmittedVTEP, error) {
	b, ok := g.backend(ServiceOverlay)
	if !ok {
		return nil, &ErrServiceUnavailable{Service: ServiceOverlay, Reason: "overlay service is not running"}
	}
	overlay, ok := b.(interface {
		GetAdmittedVTEP(context.Context, netip.Addr) (*AdmittedVTEP, error)
	})
	if !ok {
		return nil, &ErrServiceUnavailable{Service: ServiceOverlay, Reason: "overlay admission is not available"}
	}
	return overlay.GetAdmittedVTEP(ctx, vtep)
}

func (g *Gateway) ListAdmittedVTEPs(ctx context.Context) ([]AdmittedVTEP, error) {
	b, ok := g.backend(ServiceOverlay)
	if !ok {
		return nil, &ErrServiceUnavailable{Service: ServiceOverlay, Reason: "overlay service is not running"}
	}
	overlay, ok := b.(interface {
		ListAdmittedVTEPs(context.Context) ([]AdmittedVTEP, error)
	})
	if !ok {
		return nil, &ErrServiceUnavailable{Service: ServiceOverlay, Reason: "overlay admission is not available"}
	}
	return overlay.ListAdmittedVTEPs(ctx)
}
