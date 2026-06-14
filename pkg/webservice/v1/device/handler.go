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

package device

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// RestHandler defines the device REST endpoint interface
type RestHandler interface {
	GetProfile(w http.ResponseWriter, r *http.Request)
	Activate(w http.ResponseWriter, r *http.Request)
}

// ProfileResponse is the response for GET /device/profile
type ProfileResponse struct {
	SerialNumber   string           `json:"serialNumber"`
	TrustedNetwork NetworkConfig    `json:"trustedNetwork"`
	ACLs           []ACLConfig      `json:"acls,omitempty"`
	RateLimit      *RateLimitConfig `json:"rateLimit,omitempty"`
}

type NetworkConfig struct {
	VLAN     uint16   `json:"vlan"`
	UseDHCP  bool     `json:"useDHCP"`
	StaticIP string   `json:"staticIP,omitempty"`
	Gateway  string   `json:"gateway,omitempty"`
	DNS      []string `json:"dns,omitempty"`
}

type ACLConfig struct {
	Name     string            `json:"name"`
	Priority int               `json:"priority"`
	Match    map[string]string `json:"match"`
	Action   string            `json:"action"`
}

type RateLimitConfig struct {
	IngressMbps int `json:"ingressMbps"`
	EgressMbps  int `json:"egressMbps"`
}

// ActivateResponse is the response for POST /device/activate
type ActivateResponse struct {
	Status         string    `json:"status"`
	VLAN           uint16    `json:"vlan"`
	TransitionedAt time.Time `json:"transitionedAt"`
}

// ARPTable provides ARP lookup functionality
type ARPTable interface {
	LookupMAC(ipAddr string) (net.HardwareAddr, error)
}

// SwitchServiceProvider abstracts the switch management service for
// dependency injection. It allows the handler to resolve a Manager
// by switch name without depending on the concrete Service type.
type SwitchServiceProvider interface {
	// Manager returns the Manager for the named switch.
	Manager(name string) (switchmgmt.Manager, error)
}

// Handler implements RestHandler
type Handler struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	policyEngine   policy.PolicyEngine
	profileService ProfileService
	arpTable       ARPTable
	switchService  SwitchServiceProvider
}

// ProfileService provides device profile lookup
type ProfileService interface {
	GetBySerial(ctx context.Context, serial string) (*ProfileResponse, error)
}

func NewHandler(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	policyEngine policy.PolicyEngine,
	profileService ProfileService,
	arpTable ARPTable,
	opts ...HandlerOption,
) RestHandler {
	h := &Handler{
		logger:         logger,
		responseWriter: responseWriter,
		policyEngine:   policyEngine,
		profileService: profileService,
		arpTable:       arpTable,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// HandlerOption configures optional Handler dependencies.
type HandlerOption func(*Handler)

// WithSwitchService injects a physical switch service into the handler.
// When set, Activate will move the device's physical port from the
// provisioning VLAN to the trusted VLAN on the configured switch.
func WithSwitchService(svc SwitchServiceProvider) HandlerOption {
	return func(h *Handler) {
		h.switchService = svc
	}
}

// GetProfile returns the device profile for the authenticated device
func (h *Handler) GetProfile(w http.ResponseWriter, r *http.Request) {
	// Extract serial from client certificate (set by mTLS middleware)
	serial, ok := r.Context().Value(ContextKeyDeviceSerial).(string)
	if !ok || serial == "" {
		h.responseWriter.Error400(w, r, ErrMissingSerial)
		return
	}

	profile, err := h.profileService.GetBySerial(r.Context(), serial)
	if err != nil {
		h.responseWriter.Error404(w, r, ErrProfileNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

// Activate transitions the device to the trusted network zone
func (h *Handler) Activate(w http.ResponseWriter, r *http.Request) {
	// Extract serial from client certificate
	serial, ok := r.Context().Value(ContextKeyDeviceSerial).(string)
	if !ok || serial == "" {
		h.responseWriter.Error400(w, r, ErrMissingSerial)
		return
	}

	// Get client IP and lookup MAC from ARP table
	clientIP := extractClientIP(r)
	mac, err := h.arpTable.LookupMAC(clientIP)
	if err != nil {
		h.logger.Errorf("Failed to lookup MAC for %s: %v", clientIP, err)
		h.responseWriter.Error500(w, r, ErrARPLookupFailed)
		return
	}

	// Get port by MAC
	portID := mac.String() // Use MAC as port identifier

	// Get profile for VLAN
	profile, err := h.profileService.GetBySerial(r.Context(), serial)
	if err != nil {
		h.responseWriter.Error404(w, r, ErrProfileNotFound)
		return
	}

	// Move the physical switch port to the trusted VLAN if switch info
	// is available in the profile. This is a no-op when no switch service
	// is configured or when the profile lacks switch fields.
	if switchErr := h.transitionSwitchPort(r.Context(), serial, profile.TrustedNetwork.VLAN); switchErr != nil {
		h.logger.Errorf("Switch VLAN transition failed for device %s: %v", serial, switchErr)
		h.responseWriter.Error500(w, r, switchErr)
		return
	}

	// Transition port to authorized state
	if err := h.policyEngine.SetPortState(portID, policy.PortStateAuthorized); err != nil {
		h.logger.Errorf("Failed to transition port %s to authorized: %v", portID, err)
		h.responseWriter.Error500(w, r, ErrPortTransitionFailed)
		return
	}

	// Apply trusted zone policy with VLAN
	portPolicy := &policy.PortPolicy{
		VLAN:     profile.TrustedNetwork.VLAN,
		IssuedAt: time.Now().UTC(),
	}

	if err := h.policyEngine.ApplyPolicy(portID, portPolicy); err != nil {
		h.logger.Errorf("Failed to apply policy for port %s: %v", portID, err)
		// Continue - policy application is best-effort
	}

	h.logger.Infof("Device %s activated on trusted VLAN %d", serial, profile.TrustedNetwork.VLAN)

	resp := ActivateResponse{
		Status:         "activated",
		VLAN:           profile.TrustedNetwork.VLAN,
		TransitionedAt: time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// transitionSwitchPort moves the device's physical switch port to the
// trusted VLAN. Returns nil when no switch service is configured or
// the device has no switch/port mapping (making VLAN move a no-op).
func (h *Handler) transitionSwitchPort(ctx context.Context, serial string, trustedVLAN uint16) error {
	if h.switchService == nil {
		return nil
	}

	// Look up device switch info from the profile service context.
	// The switch name and port are stored per-device; the profile service
	// provides them via the serial lookup. For now, we extract them from
	// the context set by the mTLS middleware or registration data.
	switchName, _ := ctx.Value(contextKeySwitchName).(string)
	switchPort, _ := ctx.Value(contextKeySwitchPort).(string)

	if switchName == "" || switchPort == "" {
		// No physical switch mapping for this device - skip VLAN move.
		return nil
	}

	mgr, err := h.switchService.Manager(switchName)
	if err != nil {
		return ErrSwitchNotConfigured{SwitchName: switchName}
	}

	if err := mgr.SetPortVLAN(ctx, switchPort, trustedVLAN); err != nil {
		return ErrSwitchVLANTransitionFailed{
			SwitchName: switchName,
			Port:       switchPort,
			VLAN:       trustedVLAN,
			Cause:      err,
		}
	}

	h.logger.Infof("Switch port %s/%s moved to trusted VLAN %d for device %s",
		switchName, switchPort, trustedVLAN, serial)

	return nil
}

// Context keys for switch information passed through request context.
const (
	contextKeySwitchName ContextKey = "switch_name"
	contextKeySwitchPort ContextKey = "switch_port"
)

func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var (
	ErrMissingSerial        = fmt.Errorf("missing device serial number")
	ErrProfileNotFound      = fmt.Errorf("device profile not found")
	ErrARPLookupFailed      = fmt.Errorf("failed to lookup device MAC address")
	ErrPortTransitionFailed = fmt.Errorf("failed to transition port state")
)
