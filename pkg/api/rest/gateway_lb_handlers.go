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

package rest

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// =============================================================================
// Load Balancer Error Types
// =============================================================================

// ErrLBNotConfigured is returned when load balancer operations are attempted
// but no load balancer service is running.
type ErrLBNotConfigured struct{}

// Error implements the error interface.
func (e ErrLBNotConfigured) Error() string {
	return "load balancer service is not configured"
}

// ErrLBVIPNotFound is returned when a requested VIP does not exist.
type ErrLBVIPNotFound struct{}

// Error implements the error interface.
func (e ErrLBVIPNotFound) Error() string {
	return "VIP not found"
}

// ErrLBVIPAlreadyExists is returned when adding a VIP that already exists.
type ErrLBVIPAlreadyExists struct{}

// Error implements the error interface.
func (e ErrLBVIPAlreadyExists) Error() string {
	return "VIP already exists"
}

// ErrLBInvalidVIP is returned for invalid VIP definitions (bad address,
// port, protocol, algorithm, or backend set).
type ErrLBInvalidVIP struct{ Reason string }

// Error implements the error interface.
func (e ErrLBInvalidVIP) Error() string {
	return "invalid VIP: " + e.Reason
}

// =============================================================================
// Load Balancer Request/Response Types
// =============================================================================

// LBBackend is one load-balanced endpoint behind a VIP.
type LBBackend struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	Weight  uint16 `json:"weight,omitempty"`
}

// LBVIPRequest is the REST body for creating a VIP.
type LBVIPRequest struct {
	Address   string      `json:"address"`
	Port      uint16      `json:"port"`
	Protocol  string      `json:"protocol"`
	Algorithm string      `json:"algorithm,omitempty"`
	Backends  []LBBackend `json:"backends"`
}

// LBBackendStatus reports one backend and its probed health.
type LBBackendStatus struct {
	Backend LBBackend `json:"backend"`
	Healthy bool      `json:"healthy"`
}

// LBVIPResponse represents one VIP and its datapath state.
type LBVIPResponse struct {
	Address   string            `json:"address"`
	Port      uint16            `json:"port"`
	Protocol  string            `json:"protocol"`
	Algorithm string            `json:"algorithm"`
	CTZone    uint16            `json:"ct_zone"`
	GroupID   uint32            `json:"group_id"`
	Backends  []LBBackendStatus `json:"backends"`
}

// LBVIPListResponse represents a list of VIPs.
type LBVIPListResponse struct {
	VIPs      []LBVIPResponse `json:"vips"`
	Count     int             `json:"count"`
	Timestamp time.Time       `json:"timestamp"`
}

// LBSetBackendsRequest is the REST body for replacing a VIP's backends.
type LBSetBackendsRequest struct {
	Backends []LBBackend `json:"backends"`
}

// LBStatusResponse represents the load balancer service health.
type LBStatusResponse struct {
	Active          bool      `json:"active"`
	VIPCount        int       `json:"vip_count"`
	HealthyBackends int       `json:"healthy_backends"`
	TotalBackends   int       `json:"total_backends"`
	LastReconcile   time.Time `json:"last_reconcile,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// =============================================================================
// Load Balancer Handlers
// =============================================================================

// registerLBRoutes registers the load balancer VIP routes on the router.
func (h *GatewayHandlers) registerLBRoutes(router *mux.Router) {
	router.HandleFunc("/api/v1/sdn/gateway/lb/vips", h.handleAddVIP).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/gateway/lb/vips", h.handleListVIPs).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}", h.handleGetVIP).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}", h.handleRemoveVIP).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}/backends", h.handleSetVIPBackends).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/sdn/gateway/lb/status", h.handleGetLBStatus).Methods(http.MethodGet)
}

// vipVars extracts and validates the {protocol}/{address}/{port} path vars.
func vipVars(r *http.Request) (protocol, address string, port uint16, err error) {
	vars := mux.Vars(r)
	protocol = vars["protocol"]
	address = vars["address"]
	portValue, parseErr := strconv.ParseUint(vars["port"], 10, 16)
	if parseErr != nil || portValue == 0 {
		return "", "", 0, ErrLBInvalidVIP{Reason: "port must be 1-65535"}
	}
	return protocol, address, uint16(portValue), nil
}

// handleAddVIP handles POST /api/v1/sdn/gateway/lb/vips
func (h *GatewayHandlers) handleAddVIP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	var req LBVIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	vip, err := h.gatewayService.AddVIP(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to add VIP", "error", err)
		h.writeGatewayError(w, "add_vip", err)
		return
	}

	h.logger.Info("VIP added", "address", req.Address, "port", req.Port, "protocol", req.Protocol)
	h.writeJSON(w, http.StatusCreated, vip)
}

// handleListVIPs handles GET /api/v1/sdn/gateway/lb/vips
func (h *GatewayHandlers) handleListVIPs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	vips, err := h.gatewayService.ListVIPs(ctx)
	if err != nil {
		h.logger.Error("Failed to list VIPs", "error", err)
		h.writeGatewayError(w, "list_vips", err)
		return
	}

	h.writeJSON(w, http.StatusOK, LBVIPListResponse{
		VIPs:      vips,
		Count:     len(vips),
		Timestamp: time.Now().UTC(),
	})
}

// handleGetVIP handles GET /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}
func (h *GatewayHandlers) handleGetVIP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	protocol, address, port, err := vipVars(r)
	if err != nil {
		h.writeGatewayError(w, "get_vip", err)
		return
	}

	vip, err := h.gatewayService.GetVIP(ctx, protocol, address, port)
	if err != nil {
		h.logger.Error("Failed to get VIP", "error", err)
		h.writeGatewayError(w, "get_vip", err)
		return
	}

	h.writeJSON(w, http.StatusOK, vip)
}

// handleRemoveVIP handles DELETE /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}
func (h *GatewayHandlers) handleRemoveVIP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	protocol, address, port, err := vipVars(r)
	if err != nil {
		h.writeGatewayError(w, "remove_vip", err)
		return
	}

	if err := h.gatewayService.RemoveVIP(ctx, protocol, address, port); err != nil {
		h.logger.Error("Failed to remove VIP", "error", err)
		h.writeGatewayError(w, "remove_vip", err)
		return
	}

	h.logger.Info("VIP removed", "address", address, "port", port, "protocol", protocol)
	h.writeJSON(w, http.StatusOK, GatewayActionResponse{
		ResourceID:   protocol + "/" + address + ":" + strconv.Itoa(int(port)),
		ResourceType: "vip",
		Action:       "remove",
		Success:      true,
	})
}

// handleSetVIPBackends handles PUT /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}/backends
func (h *GatewayHandlers) handleSetVIPBackends(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	protocol, address, port, err := vipVars(r)
	if err != nil {
		h.writeGatewayError(w, "set_vip_backends", err)
		return
	}

	var req LBSetBackendsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	vip, err := h.gatewayService.SetVIPBackends(ctx, protocol, address, port, req.Backends)
	if err != nil {
		h.logger.Error("Failed to set VIP backends", "error", err)
		h.writeGatewayError(w, "set_vip_backends", err)
		return
	}

	h.logger.Info("VIP backends updated", "address", address, "port", port, "protocol", protocol)
	h.writeJSON(w, http.StatusOK, vip)
}

// handleGetLBStatus handles GET /api/v1/sdn/gateway/lb/status
func (h *GatewayHandlers) handleGetLBStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	lbStatus, err := h.gatewayService.GetLBStatus(ctx)
	if err != nil {
		h.logger.Error("Failed to get LB status", "error", err)
		h.writeGatewayError(w, "get_lb_status", err)
		return
	}

	lbStatus.Timestamp = time.Now().UTC()
	h.writeJSON(w, http.StatusOK, lbStatus)
}
