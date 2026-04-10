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
	SerialNumber      string           `json:"serialNumber"`
	ProductionNetwork NetworkConfig    `json:"productionNetwork"`
	ACLs              []ACLConfig      `json:"acls,omitempty"`
	RateLimit         *RateLimitConfig `json:"rateLimit,omitempty"`
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

// Handler implements RestHandler
type Handler struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	policyEngine   policy.PolicyEngine
	profileService ProfileService
	arpTable       ARPTable
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
) RestHandler {
	return &Handler{
		logger:         logger,
		responseWriter: responseWriter,
		policyEngine:   policyEngine,
		profileService: profileService,
		arpTable:       arpTable,
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

// Activate transitions the device to production network
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

	// Transition port to authorized state
	if err := h.policyEngine.SetPortState(portID, policy.PortStateAuthorized); err != nil {
		h.logger.Errorf("Failed to transition port %s to authorized: %v", portID, err)
		h.responseWriter.Error500(w, r, ErrPortTransitionFailed)
		return
	}

	// Apply production policy with VLAN
	portPolicy := &policy.PortPolicy{
		VLAN:     profile.ProductionNetwork.VLAN,
		IssuedAt: time.Now().UTC(),
	}

	if err := h.policyEngine.ApplyPolicy(portID, portPolicy); err != nil {
		h.logger.Errorf("Failed to apply policy for port %s: %v", portID, err)
		// Continue - policy application is best-effort
	}

	h.logger.Infof("Device %s activated on VLAN %d", serial, profile.ProductionNetwork.VLAN)

	resp := ActivateResponse{
		Status:         "activated",
		VLAN:           profile.ProductionNetwork.VLAN,
		TransitionedAt: time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

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
