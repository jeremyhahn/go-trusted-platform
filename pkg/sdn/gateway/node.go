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
	"sync"
	"sync/atomic"
	"time"
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
type firewallServiceHandler struct {
	gateway *Gateway
	active  atomic.Bool
}

func newFirewallServiceHandler(g *Gateway) *firewallServiceHandler {
	return &firewallServiceHandler{gateway: g}
}

func (h *firewallServiceHandler) Name() string { return ServiceFirewall }

func (h *firewallServiceHandler) Start(ctx context.Context) error {
	if h.active.Load() {
		return &ErrServiceAlreadyActive{Service: ServiceFirewall}
	}
	h.active.Store(true)
	return nil
}

func (h *firewallServiceHandler) Stop(ctx context.Context) error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceFirewall}
	}
	h.active.Store(false)
	return nil
}

func (h *firewallServiceHandler) IsActive() bool {
	return h.active.Load()
}

func (h *firewallServiceHandler) Health() error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceFirewall}
	}
	return nil
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

// loadBalancerServiceHandler implements ServiceHandler for the load balancer service.
type loadBalancerServiceHandler struct {
	gateway *Gateway
	active  atomic.Bool
}

func newLoadBalancerServiceHandler(g *Gateway) *loadBalancerServiceHandler {
	return &loadBalancerServiceHandler{gateway: g}
}

func (h *loadBalancerServiceHandler) Name() string { return ServiceLoadBalancer }

func (h *loadBalancerServiceHandler) Start(ctx context.Context) error {
	if h.active.Load() {
		return &ErrServiceAlreadyActive{Service: ServiceLoadBalancer}
	}
	h.active.Store(true)
	return nil
}

func (h *loadBalancerServiceHandler) Stop(ctx context.Context) error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceLoadBalancer}
	}
	h.active.Store(false)
	return nil
}

func (h *loadBalancerServiceHandler) IsActive() bool {
	return h.active.Load()
}

func (h *loadBalancerServiceHandler) Health() error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceLoadBalancer}
	}
	return nil
}

// natServiceHandler implements ServiceHandler for the NAT service.
type natServiceHandler struct {
	gateway *Gateway
	active  atomic.Bool
}

func newNATServiceHandler(g *Gateway) *natServiceHandler {
	return &natServiceHandler{gateway: g}
}

func (h *natServiceHandler) Name() string { return ServiceNAT }

func (h *natServiceHandler) Start(ctx context.Context) error {
	if h.active.Load() {
		return &ErrServiceAlreadyActive{Service: ServiceNAT}
	}
	h.active.Store(true)
	return nil
}

func (h *natServiceHandler) Stop(ctx context.Context) error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceNAT}
	}
	h.active.Store(false)
	return nil
}

func (h *natServiceHandler) IsActive() bool {
	return h.active.Load()
}

func (h *natServiceHandler) Health() error {
	if !h.active.Load() {
		return &ErrServiceNotActive{Service: ServiceNAT}
	}
	return nil
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
