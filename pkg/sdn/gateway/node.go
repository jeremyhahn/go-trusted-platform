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

// Gateway manages the lifecycle and operations of a gateway node.
type Gateway struct {
	config *GatewayConfig
	node   *GatewayNode

	// Mode handlers
	overlayMode  ModeHandler
	edgeMode     ModeHandler
	transitMode  ModeHandler
	modeHandlers map[GatewayMode]ModeHandler

	// State
	state     atomic.Uint32
	startedAt time.Time
	mu        sync.RWMutex

	// Channels for coordination
	stopCh chan struct{}
}

// ModeHandler defines the interface for gateway mode handlers.
type ModeHandler interface {
	// Activate activates the mode.
	Activate(ctx context.Context) error

	// Deactivate deactivates the mode.
	Deactivate(ctx context.Context) error

	// IsActive returns true if the mode is active.
	IsActive() bool

	// GetState returns the mode-specific state.
	GetState() interface{}
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
		ID:        config.ID,
		NodeID:    config.NodeID,
		Modes:     0,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	g := &Gateway{
		config:       config,
		node:         node,
		modeHandlers: make(map[GatewayMode]ModeHandler),
		stopCh:       make(chan struct{}),
	}

	// Initialize mode handlers
	g.overlayMode = newOverlayModeHandler(g)
	g.edgeMode = newEdgeModeHandler(g)
	g.transitMode = newTransitModeHandler(g)

	g.modeHandlers[GatewayModeOverlay] = g.overlayMode
	g.modeHandlers[GatewayModeEdge] = g.edgeMode
	g.modeHandlers[GatewayModeTransit] = g.transitMode

	g.state.Store(uint32(GatewayStateStopped))

	return g, nil
}

// Start starts the gateway and activates configured modes.
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

	// Activate configured modes
	for _, mode := range g.config.Modes {
		if err := g.activateModeInternal(ctx, mode); err != nil {
			g.state.Store(uint32(GatewayStateError))
			return &ErrStartupFailed{GatewayID: g.config.ID, Phase: "mode-activation", Cause: err}
		}
	}

	g.mu.Lock()
	g.startedAt = time.Now()
	g.stopCh = make(chan struct{})
	g.mu.Unlock()

	g.state.Store(uint32(GatewayStateRunning))
	return nil
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
	g.mu.Unlock()

	// Deactivate all active modes
	activeModes := g.node.Modes.Modes()
	for _, mode := range activeModes {
		if err := g.deactivateModeInternal(ctx, mode); err != nil {
			g.state.Store(uint32(GatewayStateError))
			return &ErrShutdownFailed{GatewayID: g.config.ID, Phase: "mode-deactivation", Cause: err}
		}
	}

	g.state.Store(uint32(GatewayStateStopped))
	return nil
}

// ActivateMode activates a gateway mode.
func (g *Gateway) ActivateMode(ctx context.Context, mode GatewayMode) error {
	if !g.IsRunning() {
		return ErrGatewayNotRunning
	}
	if !mode.Valid() {
		return &ErrModeNotSupported{Mode: mode}
	}
	return g.activateModeInternal(ctx, mode)
}

// activateModeInternal activates a mode without state checks.
func (g *Gateway) activateModeInternal(ctx context.Context, mode GatewayMode) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.node.Modes.HasMode(mode) {
		return &ErrModeAlreadyActive{Mode: mode}
	}

	handler, ok := g.modeHandlers[mode]
	if !ok {
		return &ErrModeNotSupported{Mode: mode}
	}

	if err := handler.Activate(ctx); err != nil {
		return &ErrModeActivationFailed{Mode: mode, Cause: err}
	}

	g.node.Modes |= mode
	g.node.UpdatedAt = time.Now()
	return nil
}

// DeactivateMode deactivates a gateway mode.
func (g *Gateway) DeactivateMode(ctx context.Context, mode GatewayMode) error {
	if !g.IsRunning() {
		return ErrGatewayNotRunning
	}
	if !mode.Valid() {
		return &ErrModeNotSupported{Mode: mode}
	}
	return g.deactivateModeInternal(ctx, mode)
}

// deactivateModeInternal deactivates a mode without state checks.
func (g *Gateway) deactivateModeInternal(ctx context.Context, mode GatewayMode) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.node.Modes.HasMode(mode) {
		return &ErrModeNotActive{Mode: mode}
	}

	handler, ok := g.modeHandlers[mode]
	if !ok {
		return &ErrModeNotSupported{Mode: mode}
	}

	if err := handler.Deactivate(ctx); err != nil {
		return &ErrModeDeactivationFailed{Mode: mode, Cause: err}
	}

	g.node.Modes &^= mode
	g.node.UpdatedAt = time.Now()
	return nil
}

// GetStatus returns the current gateway status.
func (g *Gateway) GetStatus() *GatewayStatus {
	g.mu.RLock()
	defer g.mu.RUnlock()

	state := GatewayState(g.state.Load())
	status := &GatewayStatus{
		ID:          g.config.ID,
		State:       state,
		ActiveModes: g.node.Modes,
	}

	if state.IsOperational() && !g.startedAt.IsZero() {
		status.Uptime = time.Since(g.startedAt)
		status.StartedAt = g.startedAt
	}

	// Copy mode states if active
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
	return *g.node
}

// GetConfig returns the gateway configuration.
func (g *Gateway) GetConfig() *GatewayConfig {
	return g.config
}

// HasMode returns true if the specified mode is active.
func (g *Gateway) HasMode(mode GatewayMode) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.node.Modes.HasMode(mode)
}

// GetActiveModes returns the currently active modes.
func (g *Gateway) GetActiveModes() GatewayMode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.node.Modes
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

// overlayModeHandler implements ModeHandler for overlay mode.
type overlayModeHandler struct {
	gateway *Gateway
	active  atomic.Bool
}

func newOverlayModeHandler(g *Gateway) *overlayModeHandler {
	return &overlayModeHandler{gateway: g}
}

func (h *overlayModeHandler) Activate(ctx context.Context) error {
	if h.active.Load() {
		return &ErrModeAlreadyActive{Mode: GatewayModeOverlay}
	}

	// Initialize overlay state
	h.gateway.node.OverlayState = &OverlayGatewayState{
		LastBGPUpdate: time.Now(),
	}

	h.active.Store(true)
	return nil
}

func (h *overlayModeHandler) Deactivate(ctx context.Context) error {
	if !h.active.Load() {
		return &ErrModeNotActive{Mode: GatewayModeOverlay}
	}

	// Clean up overlay state
	h.gateway.node.OverlayState = nil
	h.active.Store(false)
	return nil
}

func (h *overlayModeHandler) IsActive() bool {
	return h.active.Load()
}

func (h *overlayModeHandler) GetState() interface{} {
	if !h.active.Load() {
		return nil
	}
	return h.gateway.node.OverlayState
}

// edgeModeHandler implements ModeHandler for edge mode.
type edgeModeHandler struct {
	gateway *Gateway
	active  atomic.Bool
}

func newEdgeModeHandler(g *Gateway) *edgeModeHandler {
	return &edgeModeHandler{gateway: g}
}

func (h *edgeModeHandler) Activate(ctx context.Context) error {
	if h.active.Load() {
		return &ErrModeAlreadyActive{Mode: GatewayModeEdge}
	}

	// Initialize edge state
	h.gateway.node.EdgeState = &EdgeGatewayState{
		LastHealthCheck: time.Now(),
	}

	h.active.Store(true)
	return nil
}

func (h *edgeModeHandler) Deactivate(ctx context.Context) error {
	if !h.active.Load() {
		return &ErrModeNotActive{Mode: GatewayModeEdge}
	}

	// Clean up edge state
	h.gateway.node.EdgeState = nil
	h.active.Store(false)
	return nil
}

func (h *edgeModeHandler) IsActive() bool {
	return h.active.Load()
}

func (h *edgeModeHandler) GetState() interface{} {
	if !h.active.Load() {
		return nil
	}
	return h.gateway.node.EdgeState
}

// transitModeHandler implements ModeHandler for transit mode.
type transitModeHandler struct {
	gateway *Gateway
	active  atomic.Bool
}

func newTransitModeHandler(g *Gateway) *transitModeHandler {
	return &transitModeHandler{gateway: g}
}

func (h *transitModeHandler) Activate(ctx context.Context) error {
	if h.active.Load() {
		return &ErrModeAlreadyActive{Mode: GatewayModeTransit}
	}

	// Initialize transit state
	h.gateway.node.TransitState = &TransitGatewayState{
		LastRouteUpdate: time.Now(),
	}

	h.active.Store(true)
	return nil
}

func (h *transitModeHandler) Deactivate(ctx context.Context) error {
	if !h.active.Load() {
		return &ErrModeNotActive{Mode: GatewayModeTransit}
	}

	// Clean up transit state
	h.gateway.node.TransitState = nil
	h.active.Store(false)
	return nil
}

func (h *transitModeHandler) IsActive() bool {
	return h.active.Load()
}

func (h *transitModeHandler) GetState() interface{} {
	if !h.active.Load() {
		return nil
	}
	return h.gateway.node.TransitState
}
