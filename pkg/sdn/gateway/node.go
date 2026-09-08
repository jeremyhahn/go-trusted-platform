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
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/firewall"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
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
	ServiceTunnels      = "tunnels"
	ServiceProxy        = "proxy"
)

// Gateway manages the lifecycle and operations of a gateway node.
type Gateway struct {
	config *GatewayConfig
	node   *GatewayNode

	// Service handlers keyed by service name
	serviceHandlers map[string]ServiceHandler

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

	// Register config-driven service handlers.
	// Each handler is only registered if its config section exists.
	if config.Overlay != nil && config.Overlay.Enabled {
		g.serviceHandlers[ServiceOverlay] = newOverlayServiceHandler(g)
	}
	if config.Edge != nil && config.Edge.Enabled {
		g.serviceHandlers[ServiceEdge] = newEdgeServiceHandler(g)
	}
	if config.BGP != nil {
		g.serviceHandlers[ServiceTransit] = newTransitServiceHandler(g)
	}
	if config.Firewall != nil && config.Firewall.Enabled {
		g.serviceHandlers[ServiceFirewall] = newFirewallServiceHandler(g)
	}
	if config.DHCP != nil && config.DHCP.Enabled {
		g.serviceHandlers[ServiceDHCP] = newDHCPServiceHandler(g)
	}
	if config.PXE != nil && config.PXE.Enabled {
		g.serviceHandlers[ServicePXE] = newPXEServiceHandler(g)
	}
	if config.LoadBalancer != nil && config.LoadBalancer.Enabled {
		g.serviceHandlers[ServiceLoadBalancer] = newLoadBalancerServiceHandler(g)
	}
	if config.NAT != nil && config.NAT.Enabled {
		g.serviceHandlers[ServiceNAT] = newNATServiceHandler(g)
	}
	if len(config.Tunnels) > 0 {
		g.serviceHandlers[ServiceTunnels] = newTunnelServiceHandler(g)
	}

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

	// Start all registered service handlers
	for name, handler := range g.serviceHandlers {
		if err := handler.Start(ctx); err != nil {
			// Rollback: stop already started services
			g.rollbackStartedServices(ctx)
			g.state.Store(uint32(GatewayStateError))
			return &ErrStartupFailed{GatewayID: g.config.ID, Phase: "service-start", Cause: &ErrServiceStartFailed{Service: name, Cause: err}}
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

// rollbackStartedServices stops any services that were already started during a failed Start.
func (g *Gateway) rollbackStartedServices(ctx context.Context) {
	g.mu.Lock()
	order := make([]string, len(g.activeOrder))
	copy(order, g.activeOrder)
	g.mu.Unlock()

	// Stop in reverse order
	for i := len(order) - 1; i >= 0; i-- {
		name := order[i]
		if handler, ok := g.serviceHandlers[name]; ok {
			handler.Stop(ctx)
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

	g.mu.Lock()
	g.node.ActiveServices = make(map[string]bool)
	g.activeOrder = nil
	g.node.UpdatedAt = time.Now()
	g.mu.Unlock()

	g.state.Store(uint32(GatewayStateStopped))
	return nil
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
	result := make([]string, 0, len(g.node.ActiveServices))
	for name := range g.node.ActiveServices {
		result = append(result, name)
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

// overlayServiceHandler implements ServiceHandler for the overlay service.
type overlayServiceHandler struct {
	gateway *Gateway
	active  atomic.Bool
}

func newOverlayServiceHandler(g *Gateway) *overlayServiceHandler {
	return &overlayServiceHandler{gateway: g}
}

func (h *overlayServiceHandler) Name() string { return ServiceOverlay }

func (h *overlayServiceHandler) Start(ctx context.Context) error {
	if h.active.Load() {
		return &ErrServiceAlreadyActive{Service: ServiceOverlay}
	}
	h.gateway.node.OverlayState = &OverlayGatewayState{
		LastBGPUpdate: time.Now(),
	}
	h.active.Store(true)
	return nil
}

func (h *overlayServiceHandler) Stop(ctx context.Context) error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceOverlay}
	}
	h.gateway.node.OverlayState = nil
	h.active.Store(false)
	return nil
}

func (h *overlayServiceHandler) IsActive() bool {
	return h.active.Load()
}

func (h *overlayServiceHandler) Health() error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceOverlay}
	}
	return nil
}

// edgeServiceHandler implements ServiceHandler for the edge service.
type edgeServiceHandler struct {
	gateway *Gateway
	active  atomic.Bool
}

func newEdgeServiceHandler(g *Gateway) *edgeServiceHandler {
	return &edgeServiceHandler{gateway: g}
}

func (h *edgeServiceHandler) Name() string { return ServiceEdge }

func (h *edgeServiceHandler) Start(ctx context.Context) error {
	if h.active.Load() {
		return &ErrServiceAlreadyActive{Service: ServiceEdge}
	}
	h.gateway.node.EdgeState = &EdgeGatewayState{
		LastHealthCheck: time.Now(),
	}
	h.active.Store(true)
	return nil
}

func (h *edgeServiceHandler) Stop(ctx context.Context) error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceEdge}
	}
	h.gateway.node.EdgeState = nil
	h.active.Store(false)
	return nil
}

func (h *edgeServiceHandler) IsActive() bool {
	return h.active.Load()
}

func (h *edgeServiceHandler) Health() error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceEdge}
	}
	return nil
}

// transitServiceHandler implements ServiceHandler for the transit service.
type transitServiceHandler struct {
	gateway *Gateway
	active  atomic.Bool
}

func newTransitServiceHandler(g *Gateway) *transitServiceHandler {
	return &transitServiceHandler{gateway: g}
}

func (h *transitServiceHandler) Name() string { return ServiceTransit }

func (h *transitServiceHandler) Start(ctx context.Context) error {
	if h.active.Load() {
		return &ErrServiceAlreadyActive{Service: ServiceTransit}
	}
	h.gateway.node.TransitState = &TransitGatewayState{
		LastRouteUpdate: time.Now(),
	}
	h.active.Store(true)
	return nil
}

func (h *transitServiceHandler) Stop(ctx context.Context) error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceTransit}
	}
	h.gateway.node.TransitState = nil
	h.active.Store(false)
	return nil
}

func (h *transitServiceHandler) IsActive() bool {
	return h.active.Load()
}

func (h *transitServiceHandler) Health() error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceTransit}
	}
	return nil
}

// firewallServiceHandler implements ServiceHandler for the firewall service.
// It drives the OVS-native conntrack firewall in
// pkg/sdn/gateway/services/firewall using the daemon-injected runtime
// dependencies.
type firewallServiceHandler struct {
	gateway *Gateway

	mu  sync.Mutex
	svc *firewall.Service
}

func newFirewallServiceHandler(g *Gateway) *firewallServiceHandler {
	return &firewallServiceHandler{gateway: g}
}

func (h *firewallServiceHandler) Name() string { return ServiceFirewall }

// firewallDeps builds the firewall service dependency set from the injected
// gateway runtime and the firewall config section.
func (h *firewallServiceHandler) firewallDeps() (firewall.Deps, error) {
	runtime := h.gateway.config.Runtime
	if runtime == nil {
		return firewall.Deps{}, &ErrRuntimeMissing{Service: ServiceFirewall}
	}

	cfg := h.gateway.config.Firewall
	bridge := runtime.Bridge
	if cfg.Bridge != "" {
		bridge = cfg.Bridge
	}

	return firewall.Deps{
		Controller: runtime.Controller,
		OVS:        runtime.OVS,
		Config: firewall.Config{
			DefaultPolicy: cfg.DefaultPolicy,
			Bridge:        bridge,
		},
		Zones:     runtime.Zones,
		Networks:  runtime.Networks,
		Allocator: runtime.CTZones,
		Logger:    runtime.Logger,
	}, nil
}

func (h *firewallServiceHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.svc != nil {
		return &ErrServiceAlreadyActive{Service: ServiceFirewall}
	}

	deps, err := h.firewallDeps()
	if err != nil {
		return err
	}

	svc, err := firewall.New(deps)
	if err != nil {
		return &ErrServiceStartFailed{Service: ServiceFirewall, Cause: err}
	}
	if err := svc.Start(ctx); err != nil {
		return &ErrServiceStartFailed{Service: ServiceFirewall, Cause: err}
	}

	h.svc = svc
	return nil
}

func (h *firewallServiceHandler) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.svc == nil {
		return &ErrServiceNotActive{Service: ServiceFirewall}
	}

	if err := h.svc.Stop(ctx); err != nil {
		return &ErrServiceStopFailed{Service: ServiceFirewall, Cause: err}
	}

	h.svc = nil
	return nil
}

func (h *firewallServiceHandler) IsActive() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.svc != nil && h.svc.Active()
}

func (h *firewallServiceHandler) Health() error {
	h.mu.Lock()
	svc := h.svc
	h.mu.Unlock()

	if svc == nil || !svc.Health().Active {
		return &ErrServiceNotActive{Service: ServiceFirewall}
	}
	return nil
}

// FirewallHealth returns the firewall service health snapshot, or false
// when the firewall service is not registered or not started.
func (g *Gateway) FirewallHealth() (firewall.Health, bool) {
	handler, ok := g.serviceHandlers[ServiceFirewall]
	if !ok {
		return firewall.Health{}, false
	}
	fw, ok := handler.(*firewallServiceHandler)
	if !ok {
		return firewall.Health{}, false
	}

	fw.mu.Lock()
	svc := fw.svc
	fw.mu.Unlock()

	if svc == nil {
		return firewall.Health{}, false
	}
	return svc.Health(), true
}

// ReconcileFirewall recompiles the firewall rule set from the current zone
// state and converges the datapath.
func (g *Gateway) ReconcileFirewall(ctx context.Context) error {
	handler, ok := g.serviceHandlers[ServiceFirewall]
	if !ok {
		return &ErrServiceNotActive{Service: ServiceFirewall}
	}
	fw, ok := handler.(*firewallServiceHandler)
	if !ok {
		return &ErrServiceNotActive{Service: ServiceFirewall}
	}

	fw.mu.Lock()
	svc := fw.svc
	fw.mu.Unlock()

	if svc == nil {
		return &ErrServiceNotActive{Service: ServiceFirewall}
	}
	return svc.Reconcile(ctx)
}

// dhcpServiceHandler implements ServiceHandler for the DHCP service.
type dhcpServiceHandler struct {
	gateway *Gateway
	active  atomic.Bool
}

func newDHCPServiceHandler(g *Gateway) *dhcpServiceHandler {
	return &dhcpServiceHandler{gateway: g}
}

func (h *dhcpServiceHandler) Name() string { return ServiceDHCP }

func (h *dhcpServiceHandler) Start(ctx context.Context) error {
	if h.active.Load() {
		return &ErrServiceAlreadyActive{Service: ServiceDHCP}
	}
	h.active.Store(true)
	return nil
}

func (h *dhcpServiceHandler) Stop(ctx context.Context) error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceDHCP}
	}
	h.active.Store(false)
	return nil
}

func (h *dhcpServiceHandler) IsActive() bool {
	return h.active.Load()
}

func (h *dhcpServiceHandler) Health() error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceDHCP}
	}
	return nil
}

// loadBalancerServiceHandler implements ServiceHandler for the load
// balancer service. It drives the OVS-native group-select + conntrack load
// balancer in pkg/sdn/gateway/services/loadbalancer using the
// daemon-injected runtime dependencies.
type loadBalancerServiceHandler struct {
	gateway *Gateway

	mu  sync.Mutex
	svc *loadbalancer.Service
}

func newLoadBalancerServiceHandler(g *Gateway) *loadBalancerServiceHandler {
	return &loadBalancerServiceHandler{gateway: g}
}

func (h *loadBalancerServiceHandler) Name() string { return ServiceLoadBalancer }

// lbDeps builds the load balancer service dependency set from the injected
// gateway runtime and the load-balancer config section.
func (h *loadBalancerServiceHandler) lbDeps() (loadbalancer.Deps, error) {
	runtime := h.gateway.config.Runtime
	if runtime == nil || runtime.Groups == nil {
		return loadbalancer.Deps{}, &ErrRuntimeMissing{Service: ServiceLoadBalancer}
	}

	cfg := h.gateway.config.LoadBalancer
	bridge := runtime.Bridge
	if cfg.Bridge != "" {
		bridge = cfg.Bridge
	}

	vips := make([]loadbalancer.VIP, 0, len(cfg.VIPs))
	for i := range cfg.VIPs {
		vip, err := cfg.VIPs[i].ServiceVIP()
		if err != nil {
			return loadbalancer.Deps{}, err
		}
		vips = append(vips, vip)
	}

	return loadbalancer.Deps{
		Controller: runtime.Controller,
		OVS:        runtime.OVS,
		Groups:     runtime.Groups,
		Config: loadbalancer.Config{
			Bridge:              bridge,
			Algorithm:           cfg.Algorithm,
			HealthCheckInterval: cfg.HealthCheckInterval,
			HealthCheckTimeout:  cfg.HealthCheckTimeout,
			Rise:                cfg.HealthCheckRise,
			Fall:                cfg.HealthCheckFall,
			MaxBackends:         cfg.MaxBackends,
			VIPs:                vips,
		},
		Allocator: runtime.CTZones,
		Logger:    runtime.Logger,
	}, nil
}

func (h *loadBalancerServiceHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.svc != nil {
		return &ErrServiceAlreadyActive{Service: ServiceLoadBalancer}
	}

	deps, err := h.lbDeps()
	if err != nil {
		return err
	}

	svc, err := loadbalancer.New(deps)
	if err != nil {
		return &ErrServiceStartFailed{Service: ServiceLoadBalancer, Cause: err}
	}
	if err := svc.Start(ctx); err != nil {
		return &ErrServiceStartFailed{Service: ServiceLoadBalancer, Cause: err}
	}

	h.svc = svc
	return nil
}

func (h *loadBalancerServiceHandler) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.svc == nil {
		return &ErrServiceNotActive{Service: ServiceLoadBalancer}
	}

	if err := h.svc.Stop(ctx); err != nil {
		return &ErrServiceStopFailed{Service: ServiceLoadBalancer, Cause: err}
	}

	h.svc = nil
	return nil
}

func (h *loadBalancerServiceHandler) IsActive() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.svc != nil && h.svc.Active()
}

func (h *loadBalancerServiceHandler) Health() error {
	h.mu.Lock()
	svc := h.svc
	h.mu.Unlock()

	if svc == nil || !svc.Health().Active {
		return &ErrServiceNotActive{Service: ServiceLoadBalancer}
	}
	return nil
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
	handler, ok := g.serviceHandlers[ServiceLoadBalancer]
	if !ok {
		return nil, false
	}
	lb, ok := handler.(*loadBalancerServiceHandler)
	if !ok {
		return nil, false
	}

	lb.mu.Lock()
	defer lb.mu.Unlock()
	if lb.svc == nil {
		return nil, false
	}
	return lb.svc, true
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

// natServiceHandler implements ServiceHandler for the NAT service. It
// drives the OVS-native ct(nat(...)) NAT gateway in
// pkg/sdn/gateway/services/firewall using the daemon-injected runtime
// dependencies.
type natServiceHandler struct {
	gateway *Gateway

	mu  sync.Mutex
	svc *firewall.NAT
}

func newNATServiceHandler(g *Gateway) *natServiceHandler {
	return &natServiceHandler{gateway: g}
}

func (h *natServiceHandler) Name() string { return ServiceNAT }

// natDeps builds the NAT service dependency set and configuration from the
// injected gateway runtime and the nat config section.
func (h *natServiceHandler) natDeps() (firewall.Deps, firewall.NATConfig, error) {
	runtime := h.gateway.config.Runtime
	if runtime == nil {
		return firewall.Deps{}, firewall.NATConfig{}, &ErrRuntimeMissing{Service: ServiceNAT}
	}

	cfg := h.gateway.config.NAT
	bridge := runtime.Bridge
	if cfg.Bridge != "" {
		bridge = cfg.Bridge
	}

	uplink := cfg.UplinkPort
	if uplink == "" && len(h.gateway.config.Uplinks) > 0 {
		uplink = h.gateway.config.Uplinks[0].Name
	}

	deps := firewall.Deps{
		Controller: runtime.Controller,
		OVS:        runtime.OVS,
		Allocator:  runtime.CTZones,
		Logger:     runtime.Logger,
	}

	natCfg := firewall.NATConfig{
		ExternalIP:     cfg.ExternalIP,
		PortRangeStart: cfg.PortRangeStart,
		PortRangeEnd:   cfg.PortRangeEnd,
		InternalCIDR:   cfg.InternalCIDR,
		UplinkPort:     uplink,
		Bridge:         bridge,
	}

	return deps, natCfg, nil
}

func (h *natServiceHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.svc != nil {
		return &ErrServiceAlreadyActive{Service: ServiceNAT}
	}

	deps, natCfg, err := h.natDeps()
	if err != nil {
		return err
	}

	svc, err := firewall.NewNAT(deps, natCfg)
	if err != nil {
		return &ErrServiceStartFailed{Service: ServiceNAT, Cause: err}
	}
	if err := svc.Start(ctx); err != nil {
		return &ErrServiceStartFailed{Service: ServiceNAT, Cause: err}
	}

	h.svc = svc
	return nil
}

func (h *natServiceHandler) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.svc == nil {
		return &ErrServiceNotActive{Service: ServiceNAT}
	}

	if err := h.svc.Stop(ctx); err != nil {
		return &ErrServiceStopFailed{Service: ServiceNAT, Cause: err}
	}

	h.svc = nil
	return nil
}

func (h *natServiceHandler) IsActive() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.svc != nil && h.svc.Active()
}

func (h *natServiceHandler) Health() error {
	h.mu.Lock()
	svc := h.svc
	h.mu.Unlock()

	if svc == nil || !svc.Health().Active {
		return &ErrServiceNotActive{Service: ServiceNAT}
	}
	return nil
}

// NATHealth returns the NAT service health snapshot, or false when the NAT
// service is not registered or not started.
func (g *Gateway) NATHealth() (firewall.NATHealth, bool) {
	handler, ok := g.serviceHandlers[ServiceNAT]
	if !ok {
		return firewall.NATHealth{}, false
	}
	nat, ok := handler.(*natServiceHandler)
	if !ok {
		return firewall.NATHealth{}, false
	}

	nat.mu.Lock()
	svc := nat.svc
	nat.mu.Unlock()

	if svc == nil {
		return firewall.NATHealth{}, false
	}
	return svc.Health(), true
}

// NATService returns the running NAT service for SNAT/DNAT rule
// management, or false when the NAT service is not registered or started.
func (g *Gateway) NATService() (*firewall.NAT, bool) {
	handler, ok := g.serviceHandlers[ServiceNAT]
	if !ok {
		return nil, false
	}
	nat, ok := handler.(*natServiceHandler)
	if !ok {
		return nil, false
	}

	nat.mu.Lock()
	defer nat.mu.Unlock()
	if nat.svc == nil {
		return nil, false
	}
	return nat.svc, true
}

// tunnelServiceHandler implements ServiceHandler for tunnel management.
type tunnelServiceHandler struct {
	gateway *Gateway
	active  atomic.Bool
}

func newTunnelServiceHandler(g *Gateway) *tunnelServiceHandler {
	return &tunnelServiceHandler{gateway: g}
}

func (h *tunnelServiceHandler) Name() string { return ServiceTunnels }

func (h *tunnelServiceHandler) Start(ctx context.Context) error {
	if h.active.Load() {
		return &ErrServiceAlreadyActive{Service: ServiceTunnels}
	}
	h.active.Store(true)
	return nil
}

func (h *tunnelServiceHandler) Stop(ctx context.Context) error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceTunnels}
	}
	h.active.Store(false)
	return nil
}

func (h *tunnelServiceHandler) IsActive() bool {
	return h.active.Load()
}

func (h *tunnelServiceHandler) Health() error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceTunnels}
	}
	return nil
}

// pxeServiceHandler implements ServiceHandler for the PXE boot service.
type pxeServiceHandler struct {
	gateway *Gateway
	active  atomic.Bool
}

func newPXEServiceHandler(g *Gateway) *pxeServiceHandler {
	return &pxeServiceHandler{gateway: g}
}

func (h *pxeServiceHandler) Name() string { return ServicePXE }

func (h *pxeServiceHandler) Start(ctx context.Context) error {
	if h.active.Load() {
		return &ErrServiceAlreadyActive{Service: ServicePXE}
	}
	h.active.Store(true)
	return nil
}

func (h *pxeServiceHandler) Stop(ctx context.Context) error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServicePXE}
	}
	h.active.Store(false)
	return nil
}

func (h *pxeServiceHandler) IsActive() bool {
	return h.active.Load()
}

func (h *pxeServiceHandler) Health() error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServicePXE}
	}
	return nil
}
