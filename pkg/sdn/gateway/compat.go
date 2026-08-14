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
	"time"
)

// GatewayMode represents the operational mode of a gateway node.
//
// Deprecated: Gateway services are now config-driven. Use GatewayConfig service
// sections (Overlay, Edge, BGP, Firewall, etc.) instead of mode flags.
// This type is retained for API compatibility during the migration period.
type GatewayMode uint8

const (
	// GatewayModeOverlay enables SDN overlay functionality (VXLAN/EVPN).
	GatewayModeOverlay GatewayMode = 1 << iota

	// GatewayModeEdge enables IoT/P2P edge gateway functionality.
	GatewayModeEdge

	// GatewayModeTransit enables BGP transit functionality for IP blocks.
	GatewayModeTransit
)

// serviceToMode maps service names to legacy GatewayMode values.
var serviceToMode = map[string]GatewayMode{
	ServiceOverlay: GatewayModeOverlay,
	ServiceEdge:    GatewayModeEdge,
	ServiceTransit: GatewayModeTransit,
}

// modeToService maps legacy GatewayMode values to service names.
var modeToService = map[GatewayMode]string{
	GatewayModeOverlay: ServiceOverlay,
	GatewayModeEdge:    ServiceEdge,
	GatewayModeTransit: ServiceTransit,
}

// String returns a human-readable representation of the gateway mode.
func (m GatewayMode) String() string {
	switch m {
	case GatewayModeOverlay:
		return "overlay"
	case GatewayModeEdge:
		return "edge"
	case GatewayModeTransit:
		return "transit"
	default:
		if m == 0 {
			return "none"
		}
		return "mixed"
	}
}

// Valid returns true if the gateway mode is a valid non-zero value.
func (m GatewayMode) Valid() bool {
	validMask := GatewayModeOverlay | GatewayModeEdge | GatewayModeTransit
	return m != 0 && (m&^validMask) == 0
}

// HasMode returns true if the specified mode is active.
func (m GatewayMode) HasMode(mode GatewayMode) bool {
	return (m & mode) == mode
}

// Modes returns a slice of individual modes that are active.
func (m GatewayMode) Modes() []GatewayMode {
	var modes []GatewayMode
	if m.HasMode(GatewayModeOverlay) {
		modes = append(modes, GatewayModeOverlay)
	}
	if m.HasMode(GatewayModeEdge) {
		modes = append(modes, GatewayModeEdge)
	}
	if m.HasMode(GatewayModeTransit) {
		modes = append(modes, GatewayModeTransit)
	}
	return modes
}

// GetActiveModes returns the active gateway modes as a bitmask.
//
// Deprecated: Use ActiveServices() instead. This method derives mode values
// from the active service handlers for backward compatibility with API layers.
func (g *Gateway) GetActiveModes() GatewayMode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var modes GatewayMode
	for name := range g.node.ActiveServices {
		if mode, ok := serviceToMode[name]; ok {
			modes |= mode
		}
	}
	return modes
}

// HasMode returns true if the specified mode is active.
//
// Deprecated: Use HasService() instead. This bridges legacy mode checks
// to the service-based architecture.
func (g *Gateway) HasMode(mode GatewayMode) bool {
	service, ok := modeToService[mode]
	if !ok {
		return false
	}
	return g.HasService(service)
}

// ActivateMode activates a gateway mode by starting the corresponding service.
//
// Deprecated: Services are config-driven. This method provides backward
// compatibility for API layers that still use mode-based activation.
func (g *Gateway) ActivateMode(ctx context.Context, mode GatewayMode) error {
	if !g.IsRunning() {
		return ErrGatewayNotRunning
	}
	if !mode.Valid() {
		return &ErrModeNotSupported{Mode: mode}
	}

	service, ok := modeToService[mode]
	if !ok {
		return &ErrModeNotSupported{Mode: mode}
	}

	handler, ok := g.serviceHandlers[service]
	if !ok {
		return &ErrModeNotSupported{Mode: mode}
	}

	if handler.IsActive() {
		return &ErrModeAlreadyActive{Mode: mode}
	}

	if err := handler.Start(ctx); err != nil {
		return &ErrModeActivationFailed{Mode: mode, Cause: err}
	}

	g.mu.Lock()
	g.node.ActiveServices[service] = true
	g.activeOrder = append(g.activeOrder, service)
	g.node.UpdatedAt = time.Now()
	g.mu.Unlock()

	return nil
}

// DeactivateMode deactivates a gateway mode by stopping the corresponding service.
//
// Deprecated: Services are config-driven. This method provides backward
// compatibility for API layers that still use mode-based deactivation.
func (g *Gateway) DeactivateMode(ctx context.Context, mode GatewayMode) error {
	if !g.IsRunning() {
		return ErrGatewayNotRunning
	}
	if !mode.Valid() {
		return &ErrModeNotSupported{Mode: mode}
	}

	service, ok := modeToService[mode]
	if !ok {
		return &ErrModeNotSupported{Mode: mode}
	}

	handler, ok := g.serviceHandlers[service]
	if !ok {
		return &ErrModeNotSupported{Mode: mode}
	}

	if !handler.IsActive() {
		return &ErrModeNotActive{Mode: mode}
	}

	if err := handler.Stop(ctx); err != nil {
		return &ErrModeDeactivationFailed{Mode: mode, Cause: err}
	}

	g.mu.Lock()
	delete(g.node.ActiveServices, service)
	// Remove from active order
	for i, name := range g.activeOrder {
		if name == service {
			g.activeOrder = append(g.activeOrder[:i], g.activeOrder[i+1:]...)
			break
		}
	}
	g.mu.Unlock()

	return nil
}

// ErrModeNotSupported is returned when a gateway mode is not supported.
//
// Deprecated: Use service-based error types instead.
type ErrModeNotSupported struct {
	Mode GatewayMode
}

func (e *ErrModeNotSupported) Error() string {
	return "gateway mode not supported: " + e.Mode.String()
}

// ErrModeActivationFailed is returned when mode activation fails.
//
// Deprecated: Use ErrServiceStartFailed instead.
type ErrModeActivationFailed struct {
	Mode  GatewayMode
	Cause error
}

func (e *ErrModeActivationFailed) Error() string {
	if e.Cause != nil {
		return "failed to activate gateway mode " + e.Mode.String() + ": " + e.Cause.Error()
	}
	return "failed to activate gateway mode " + e.Mode.String()
}

func (e *ErrModeActivationFailed) Unwrap() error {
	return e.Cause
}

// ErrModeDeactivationFailed is returned when mode deactivation fails.
//
// Deprecated: Use ErrServiceStopFailed instead.
type ErrModeDeactivationFailed struct {
	Mode  GatewayMode
	Cause error
}

func (e *ErrModeDeactivationFailed) Error() string {
	if e.Cause != nil {
		return "failed to deactivate gateway mode " + e.Mode.String() + ": " + e.Cause.Error()
	}
	return "failed to deactivate gateway mode " + e.Mode.String()
}

func (e *ErrModeDeactivationFailed) Unwrap() error {
	return e.Cause
}

// ErrModeNotActive is returned when an operation requires a mode that is not active.
//
// Deprecated: Use ErrServiceNotActive instead.
type ErrModeNotActive struct {
	Mode GatewayMode
}

func (e *ErrModeNotActive) Error() string {
	return "gateway mode not active: " + e.Mode.String()
}

// ErrModeAlreadyActive is returned when trying to activate an already active mode.
//
// Deprecated: Use ErrServiceAlreadyActive instead.
type ErrModeAlreadyActive struct {
	Mode GatewayMode
}

func (e *ErrModeAlreadyActive) Error() string {
	return "gateway mode already active: " + e.Mode.String()
}

// LegacyModeBitmask returns the active services encoded as the legacy
// GatewayMode bitmask.
//
// It exists because the platform.v1 GatewayStatus wire message carries a
// `modes` bitmask field and nothing else that names the active services.
// Until that message gains a service-name list, an API layer filling the
// field has no alternative — so the read of the deprecated ActiveModes
// happens here, in the package that owns it, rather than being scattered
// across every transport. Delete this together with the proto field.
func (s *GatewayStatus) LegacyModeBitmask() uint32 {
	if s == nil {
		return 0
	}
	return uint32(s.ActiveModes)
}

// SetLegacyModeBitmask records the active services as the legacy
// GatewayMode bitmask. It is the write half of LegacyModeBitmask, and
// exists for the same reason: the bitmask is a wire-level encoding this
// package owns, so a transport or a test double reconstructing a status
// sets it through here instead of touching the field.
func (s *GatewayStatus) SetLegacyModeBitmask(modes uint32) {
	if s == nil {
		return
	}
	s.ActiveModes = GatewayMode(modes)
}

// ActiveModeBitmask returns the active services encoded as the legacy
// GatewayMode bitmask, in the uint32 form the platform.v1 wire messages
// carry. Transports use this rather than GetActiveModes so the mode type
// itself stays inside this package.
func (g *Gateway) ActiveModeBitmask() uint32 {
	return uint32(g.GetActiveModes())
}

// SetModeBitmask reconciles the running services against a legacy mode
// bitmask: every mode named in modes is activated, and every currently
// active mode absent from it is deactivated.
//
// The translation lives here, beside the mode/service maps it depends on,
// so an API layer implementing the platform.v1 SetGatewayMode RPC never
// has to name GatewayMode. It returns the first activation or deactivation
// error, wrapped so the caller can report which mode failed.
func (g *Gateway) SetModeBitmask(ctx context.Context, modes uint32) error {
	requested := GatewayMode(modes)
	current := g.GetActiveModes()

	for _, mode := range current.Modes() {
		if !requested.HasMode(mode) {
			if err := g.DeactivateMode(ctx, mode); err != nil {
				return &ErrModeDeactivationFailed{Mode: mode, Cause: err}
			}
		}
	}

	for _, mode := range requested.Modes() {
		if !current.HasMode(mode) {
			if err := g.ActivateMode(ctx, mode); err != nil {
				return &ErrModeActivationFailed{Mode: mode, Cause: err}
			}
		}
	}

	return nil
}
