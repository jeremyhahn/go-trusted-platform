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

// Package rest provides REST API handlers for the trusted platform services.
package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// =============================================================================
// SDN REST Handler Errors
// =============================================================================

// ErrSDNServiceNotAvailable is returned when the SDN service is not configured
// or unavailable.
type ErrSDNServiceNotAvailable struct{}

func (e ErrSDNServiceNotAvailable) Error() string {
	return "SDN service not available"
}

// ErrInvalidBridgeID is returned when a bridge ID is invalid or empty.
type ErrInvalidBridgeID struct {
	ID string
}

func (e ErrInvalidBridgeID) Error() string {
	if e.ID == "" {
		return "bridge ID is required"
	}
	return fmt.Sprintf("invalid bridge ID: %s", e.ID)
}

// ErrInvalidPortID is returned when a port ID is invalid or empty.
type ErrInvalidPortID struct {
	ID string
}

func (e ErrInvalidPortID) Error() string {
	if e.ID == "" {
		return "port ID is required"
	}
	return fmt.Sprintf("invalid port ID: %s", e.ID)
}

// ErrInvalidFlowID is returned when a flow ID is invalid or empty.
type ErrInvalidFlowID struct {
	ID string
}

func (e ErrInvalidFlowID) Error() string {
	if e.ID == "" {
		return "flow ID is required"
	}
	return fmt.Sprintf("invalid flow ID: %s", e.ID)
}

// ErrInvalidSDNPolicyID is returned when a policy ID is invalid or empty.
type ErrInvalidSDNPolicyID struct {
	ID string
}

func (e ErrInvalidSDNPolicyID) Error() string {
	if e.ID == "" {
		return "policy ID is required"
	}
	return fmt.Sprintf("invalid policy ID: %s", e.ID)
}

// ErrSDNOperationFailed is returned when an SDN operation fails.
type ErrSDNOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrSDNOperationFailed) Error() string {
	return fmt.Sprintf("SDN operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrSDNOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrBridgeNotFound is returned when a bridge is not found.
type ErrBridgeNotFound struct {
	ID string
}

func (e ErrBridgeNotFound) Error() string {
	return fmt.Sprintf("bridge not found: %s", e.ID)
}

// ErrPortNotFound is returned when a port is not found.
type ErrPortNotFound struct {
	ID string
}

func (e ErrPortNotFound) Error() string {
	return fmt.Sprintf("port not found: %s", e.ID)
}

// ErrFlowNotFound is returned when a flow is not found.
type ErrFlowNotFound struct {
	ID string
}

func (e ErrFlowNotFound) Error() string {
	return fmt.Sprintf("flow not found: %s", e.ID)
}

// ErrSDNPolicyNotFound is returned when a policy is not found.
type ErrSDNPolicyNotFound struct {
	ID string
}

func (e ErrSDNPolicyNotFound) Error() string {
	return fmt.Sprintf("policy not found: %s", e.ID)
}

// ErrBridgeAlreadyExists is returned when attempting to create a bridge that
// already exists.
type ErrBridgeAlreadyExists struct {
	Name string
}

func (e ErrBridgeAlreadyExists) Error() string {
	return fmt.Sprintf("bridge already exists: %s", e.Name)
}

// ErrPolicyAlreadyExists is returned when attempting to create a policy that
// already exists.
type ErrPolicyAlreadyExists struct {
	Name string
}

func (e ErrPolicyAlreadyExists) Error() string {
	return fmt.Sprintf("policy already exists: %s", e.Name)
}

// =============================================================================
// Request/Response Types
// =============================================================================

// CreateBridgeRequest represents a bridge creation request.
type CreateBridgeRequest struct {
	Name         string            `json:"name"`
	DatapathType string            `json:"datapath_type,omitempty"`
	FailMode     string            `json:"fail_mode,omitempty"`
	Protocols    []string          `json:"protocols,omitempty"`
	STP          bool              `json:"stp,omitempty"`
	Options      map[string]string `json:"options,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
}

// BridgeResponse represents a bridge in API responses.
type BridgeResponse struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	DatapathType string            `json:"datapath_type,omitempty"`
	FailMode     string            `json:"fail_mode,omitempty"`
	Protocols    []string          `json:"protocols,omitempty"`
	STP          bool              `json:"stp,omitempty"`
	Status       string            `json:"status"`
	Ports        []string          `json:"ports,omitempty"`
	ExternalIDs  map[string]string `json:"external_ids,omitempty"`
	OtherConfig  map[string]string `json:"other_config,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

// BridgeListResponse represents a list of bridges.
type BridgeListResponse struct {
	Bridges   []BridgeResponse `json:"bridges"`
	Count     int              `json:"count"`
	Timestamp time.Time        `json:"timestamp"`
}

// AddPortRequest represents a port addition request.
type AddPortRequest struct {
	Name    string            `json:"name"`
	Type    string            `json:"type,omitempty"`
	VLAN    int64             `json:"vlan,omitempty"`
	Trunks  []int64           `json:"trunks,omitempty"`
	Options map[string]string `json:"options,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// PortResponse represents a port in API responses.
type PortResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	BridgeID    string            `json:"bridge_id"`
	Type        string            `json:"type,omitempty"`
	VLAN        int64             `json:"vlan,omitempty"`
	Trunks      []int64           `json:"trunks,omitempty"`
	MACAddress  string            `json:"mac_address,omitempty"`
	Status      string            `json:"status"`
	ExternalIDs map[string]string `json:"external_ids,omitempty"`
	OtherConfig map[string]string `json:"other_config,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// PortListResponse represents a list of ports.
type PortListResponse struct {
	Ports     []PortResponse `json:"ports"`
	Count     int            `json:"count"`
	Timestamp time.Time      `json:"timestamp"`
}

// AddFlowRequest represents a flow addition request.
type AddFlowRequest struct {
	Table       int               `json:"table"`
	Priority    int               `json:"priority"`
	Match       string            `json:"match"`
	Actions     string            `json:"actions"`
	Cookie      string            `json:"cookie,omitempty"`
	IdleTimeout int               `json:"idle_timeout,omitempty"`
	HardTimeout int               `json:"hard_timeout,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// FlowResponse represents a flow in API responses.
type FlowResponse struct {
	ID          string    `json:"id"`
	BridgeID    string    `json:"bridge_id"`
	Table       int       `json:"table"`
	Priority    int       `json:"priority"`
	Match       string    `json:"match"`
	Actions     string    `json:"actions"`
	Cookie      string    `json:"cookie,omitempty"`
	PacketCount int64     `json:"packet_count,omitempty"`
	ByteCount   int64     `json:"byte_count,omitempty"`
	Duration    int       `json:"duration,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// FlowListResponse represents a list of flows.
type FlowListResponse struct {
	Flows     []FlowResponse `json:"flows"`
	Count     int            `json:"count"`
	Timestamp time.Time      `json:"timestamp"`
}

// CreatePolicyRequest represents a network policy creation request.
type CreatePolicyRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Priority    int               `json:"priority,omitempty"`
	Rules       []PolicyRule      `json:"rules"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// PolicyRule represents a rule within a network policy.
type PolicyRule struct {
	Direction string `json:"direction"` // ingress, egress
	Protocol  string `json:"protocol,omitempty"`
	PortRange string `json:"port_range,omitempty"`
	Source    string `json:"source,omitempty"`
	Dest      string `json:"dest,omitempty"`
	Action    string `json:"action"` // allow, deny
}

// PolicyResponse represents a network policy in API responses.
type PolicyResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Priority    int               `json:"priority"`
	Rules       []PolicyRule      `json:"rules"`
	Labels      map[string]string `json:"labels,omitempty"`
	Status      string            `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// SDNPolicyListResponse represents a list of policies.
type SDNPolicyListResponse struct {
	Policies  []PolicyResponse `json:"policies"`
	Count     int              `json:"count"`
	Timestamp time.Time        `json:"timestamp"`
}

// TopologyResponse represents the network topology.
type TopologyResponse struct {
	Bridges    []BridgeResponse `json:"bridges"`
	Links      []TopologyLink   `json:"links"`
	Statistics TopologyStats    `json:"statistics"`
	Timestamp  time.Time        `json:"timestamp"`
}

// TopologyLink represents a link between network elements.
type TopologyLink struct {
	Source     string `json:"source"`
	SourcePort string `json:"source_port"`
	Target     string `json:"target"`
	TargetPort string `json:"target_port"`
	Status     string `json:"status"`
}

// TopologyStats represents overall topology statistics.
type TopologyStats struct {
	TotalBridges int   `json:"total_bridges"`
	TotalPorts   int   `json:"total_ports"`
	TotalFlows   int   `json:"total_flows"`
	TotalBytes   int64 `json:"total_bytes"`
	TotalPackets int64 `json:"total_packets"`
}

// SDNActionResponse represents an SDN action result.
type SDNActionResponse struct {
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	Action       string `json:"action"`
	Success      bool   `json:"success"`
	Message      string `json:"message,omitempty"`
}

// SDNErrorResponse represents an SDN error response.
type SDNErrorResponse struct {
	Error     string    `json:"error"`
	Code      int       `json:"code"`
	Timestamp time.Time `json:"timestamp"`
}

// =============================================================================
// SDN Service Interface
// =============================================================================

// SDNServiceInterface defines the interface for SDN operations.
type SDNServiceInterface interface {
	// Bridge operations
	CreateBridge(ctx context.Context, name string) (*ovs.Bridge, error)
	DeleteBridge(ctx context.Context, name string) error
	GetBridge(ctx context.Context, name string) (*ovs.Bridge, error)
	ListBridges(ctx context.Context) ([]*ovs.Bridge, error)
	SetBridgeFailMode(ctx context.Context, name, failMode string) error
	SetBridgeProtocols(ctx context.Context, name string, protocols []string) error

	// Port operations
	AddPort(ctx context.Context, bridgeName, portName string) (*ovs.Port, error)
	DeletePort(ctx context.Context, bridgeName, portName string) error
	GetPort(ctx context.Context, name string) (*ovs.Port, error)
	ListPorts(ctx context.Context, bridgeName string) ([]*ovs.Port, error)
	SetPortVLAN(ctx context.Context, portName string, tag int64) error
	SetPortTrunks(ctx context.Context, portName string, trunks []int64) error

	// Flow operations
	AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error
	DeleteFlow(ctx context.Context, bridgeName string, match string) error
	ListFlows(ctx context.Context, bridgeName string) ([]*ovs.Flow, error)
	DeleteAllFlows(ctx context.Context, bridgeName string) error
}

// PolicyServiceInterface defines the interface for network policy operations.
type PolicyServiceInterface interface {
	CreatePolicy(ctx context.Context, policy *PolicyResponse) (*PolicyResponse, error)
	DeletePolicy(ctx context.Context, id string) error
	GetPolicy(ctx context.Context, id string) (*PolicyResponse, error)
	ListPolicies(ctx context.Context) ([]*PolicyResponse, error)
}

// =============================================================================
// SDN Handlers
// =============================================================================

// SDNHandlers provides REST API handlers for SDN operations.
type SDNHandlers struct {
	sdnService    SDNServiceInterface
	policyService PolicyServiceInterface
	policies      map[string]*PolicyResponse
	logger        *slog.Logger
}

// NewSDNHandlers creates a new SDNHandlers instance.
func NewSDNHandlers(sdnService SDNServiceInterface, logger *slog.Logger) *SDNHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &SDNHandlers{
		sdnService: sdnService,
		policies:   make(map[string]*PolicyResponse),
		logger:     logger,
	}
}

// SetPolicyService sets the policy service for the handlers.
func (h *SDNHandlers) SetPolicyService(policyService PolicyServiceInterface) {
	h.policyService = policyService
}

// RegisterRoutes registers all SDN routes on the provided router.
func (h *SDNHandlers) RegisterRoutes(router *mux.Router) {
	// Bridge operations
	router.HandleFunc("/api/v1/sdn/bridges", h.handleCreateBridge).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/bridges", h.handleListBridges).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/bridges/{id}", h.handleGetBridge).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/bridges/{id}", h.handleDeleteBridge).Methods(http.MethodDelete)

	// Port operations
	router.HandleFunc("/api/v1/sdn/bridges/{id}/ports", h.handleAddPort).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/bridges/{id}/ports", h.handleListPorts).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/bridges/{id}/ports/{port}", h.handleRemovePort).Methods(http.MethodDelete)

	// Port state and stats operations
	router.HandleFunc("/api/v1/sdn/bridges/{id}/ports/{port}/state", h.handleGetPortState).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/bridges/{id}/ports/{port}/state", h.handleSetPortState).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/sdn/bridges/{id}/ports/{port}/stats", h.handleGetPortStats).Methods(http.MethodGet)

	// Flow operations (global routes for backward compatibility)
	router.HandleFunc("/api/v1/sdn/flows", h.handleAddFlow).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/flows", h.handleListFlows).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/flows/{id}", h.handleDeleteFlow).Methods(http.MethodDelete)

	// Flow operations (per-bridge routes)
	router.HandleFunc("/api/v1/sdn/bridges/{id}/flows", h.handleAddFlowForBridge).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/bridges/{id}/flows", h.handleListFlowsForBridge).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/bridges/{id}/flows/{flow_id}", h.handleDeleteFlowForBridge).Methods(http.MethodDelete)

	// VLAN operations
	router.HandleFunc("/api/v1/sdn/vlans", h.handleCreateVLAN).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/vlans", h.handleListVLANs).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/vlans/{id}", h.handleDeleteVLAN).Methods(http.MethodDelete)

	// Policy operations
	router.HandleFunc("/api/v1/sdn/policies", h.handleCreatePolicy).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/policies", h.handleListPolicies).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/policies/{id}", h.handleGetPolicy).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/policies/{id}", h.handleDeletePolicy).Methods(http.MethodDelete)

	// Topology
	router.HandleFunc("/api/v1/sdn/topology", h.handleGetTopology).Methods(http.MethodGet)

	h.logger.Info("SDN REST routes registered")
}

// =============================================================================
// Bridge Handlers
// =============================================================================

// handleCreateBridge handles POST /api/v1/sdn/bridges
func (h *SDNHandlers) handleCreateBridge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	var req CreateBridgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "name"})
		return
	}

	bridge, err := h.sdnService.CreateBridge(ctx, req.Name)
	if err != nil {
		h.logger.Error("Failed to create bridge", "error", err, "name", req.Name)
		h.writeSDNError(w, "create_bridge", err)
		return
	}

	// Set additional properties if specified
	if req.FailMode != "" {
		if err := h.sdnService.SetBridgeFailMode(ctx, req.Name, req.FailMode); err != nil {
			h.logger.Warn("Failed to set bridge fail mode", "error", err, "name", req.Name)
		}
	}

	if len(req.Protocols) > 0 {
		if err := h.sdnService.SetBridgeProtocols(ctx, req.Name, req.Protocols); err != nil {
			h.logger.Warn("Failed to set bridge protocols", "error", err, "name", req.Name)
		}
	}

	resp := h.ovsBridgeToResponse(bridge)
	h.logger.Info("Bridge created", "id", bridge.UUID, "name", bridge.Name)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListBridges handles GET /api/v1/sdn/bridges
func (h *SDNHandlers) handleListBridges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	bridges, err := h.sdnService.ListBridges(ctx)
	if err != nil {
		h.logger.Error("Failed to list bridges", "error", err)
		h.writeSDNError(w, "list_bridges", err)
		return
	}

	responses := make([]BridgeResponse, 0, len(bridges))
	for _, bridge := range bridges {
		responses = append(responses, h.ovsBridgeToResponse(bridge))
	}

	resp := BridgeListResponse{
		Bridges:   responses,
		Count:     len(responses),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetBridge handles GET /api/v1/sdn/bridges/{id}
func (h *SDNHandlers) handleGetBridge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bridgeID := vars["id"]
	if bridgeID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBridgeID{})
		return
	}

	bridge, err := h.sdnService.GetBridge(ctx, bridgeID)
	if err != nil {
		h.logger.Error("Failed to get bridge", "error", err, "id", bridgeID)
		h.writeSDNError(w, "get_bridge", err)
		return
	}

	resp := h.ovsBridgeToResponse(bridge)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteBridge handles DELETE /api/v1/sdn/bridges/{id}
func (h *SDNHandlers) handleDeleteBridge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bridgeID := vars["id"]
	if bridgeID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBridgeID{})
		return
	}

	if err := h.sdnService.DeleteBridge(ctx, bridgeID); err != nil {
		h.logger.Error("Failed to delete bridge", "error", err, "id", bridgeID)
		h.writeSDNError(w, "delete_bridge", err)
		return
	}

	resp := SDNActionResponse{
		ResourceID:   bridgeID,
		ResourceType: "bridge",
		Action:       "delete",
		Success:      true,
		Message:      "bridge deleted successfully",
	}

	h.logger.Info("Bridge deleted", "id", bridgeID)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Port Handlers
// =============================================================================

// handleAddPort handles POST /api/v1/sdn/bridges/{id}/ports
func (h *SDNHandlers) handleAddPort(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bridgeID := vars["id"]
	if bridgeID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBridgeID{})
		return
	}

	var req AddPortRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "name"})
		return
	}

	port, err := h.sdnService.AddPort(ctx, bridgeID, req.Name)
	if err != nil {
		h.logger.Error("Failed to add port", "error", err, "bridge", bridgeID, "port", req.Name)
		h.writeSDNError(w, "add_port", err)
		return
	}

	// Set VLAN if specified
	if req.VLAN > 0 {
		if err := h.sdnService.SetPortVLAN(ctx, req.Name, req.VLAN); err != nil {
			h.logger.Warn("Failed to set port VLAN", "error", err, "port", req.Name)
		}
	}

	// Set trunk VLANs if specified
	if len(req.Trunks) > 0 {
		if err := h.sdnService.SetPortTrunks(ctx, req.Name, req.Trunks); err != nil {
			h.logger.Warn("Failed to set port trunks", "error", err, "port", req.Name)
		}
	}

	resp := h.ovsPortToResponse(port, bridgeID)
	h.logger.Info("Port added", "id", port.UUID, "name", port.Name, "bridge", bridgeID)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListPorts handles GET /api/v1/sdn/bridges/{id}/ports
func (h *SDNHandlers) handleListPorts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bridgeID := vars["id"]
	if bridgeID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBridgeID{})
		return
	}

	ports, err := h.sdnService.ListPorts(ctx, bridgeID)
	if err != nil {
		h.logger.Error("Failed to list ports", "error", err, "bridge", bridgeID)
		h.writeSDNError(w, "list_ports", err)
		return
	}

	responses := make([]PortResponse, 0, len(ports))
	for _, port := range ports {
		responses = append(responses, h.ovsPortToResponse(port, bridgeID))
	}

	resp := PortListResponse{
		Ports:     responses,
		Count:     len(responses),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleRemovePort handles DELETE /api/v1/sdn/bridges/{id}/ports/{port}
func (h *SDNHandlers) handleRemovePort(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bridgeID := vars["id"]
	if bridgeID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidBridgeID{})
		return
	}

	portID := vars["port"]
	if portID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPortID{})
		return
	}

	if err := h.sdnService.DeletePort(ctx, bridgeID, portID); err != nil {
		h.logger.Error("Failed to remove port", "error", err, "bridge", bridgeID, "port", portID)
		h.writeSDNError(w, "remove_port", err)
		return
	}

	resp := SDNActionResponse{
		ResourceID:   portID,
		ResourceType: "port",
		Action:       "delete",
		Success:      true,
		Message:      "port removed successfully",
	}

	h.logger.Info("Port removed", "id", portID, "bridge", bridgeID)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Flow Handlers
// =============================================================================

// handleAddFlow handles POST /api/v1/sdn/flows
func (h *SDNHandlers) handleAddFlow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	var req AddFlowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Bridge ID should be in query params for flows
	bridgeID := r.URL.Query().Get("bridge_id")
	if bridgeID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "bridge_id"})
		return
	}

	flowMod := &ovs.FlowMod{
		Table:       req.Table,
		Priority:    req.Priority,
		Match:       req.Match,
		Actions:     req.Actions,
		Cookie:      req.Cookie,
		IdleTimeout: req.IdleTimeout,
		HardTimeout: req.HardTimeout,
	}

	if err := h.sdnService.AddFlow(ctx, bridgeID, flowMod); err != nil {
		h.logger.Error("Failed to add flow", "error", err, "bridge", bridgeID)
		h.writeSDNError(w, "add_flow", err)
		return
	}

	// Generate flow ID for response
	flowID := fmt.Sprintf("flow-%d", time.Now().UnixNano())

	resp := FlowResponse{
		ID:        flowID,
		BridgeID:  bridgeID,
		Table:     req.Table,
		Priority:  req.Priority,
		Match:     req.Match,
		Actions:   req.Actions,
		Cookie:    req.Cookie,
		CreatedAt: time.Now().UTC(),
	}

	h.logger.Info("Flow added", "id", flowID, "bridge", bridgeID)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListFlows handles GET /api/v1/sdn/flows
func (h *SDNHandlers) handleListFlows(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	bridgeID := r.URL.Query().Get("bridge_id")
	if bridgeID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "bridge_id"})
		return
	}

	flows, err := h.sdnService.ListFlows(ctx, bridgeID)
	if err != nil {
		h.logger.Error("Failed to list flows", "error", err, "bridge", bridgeID)
		h.writeSDNError(w, "list_flows", err)
		return
	}

	responses := make([]FlowResponse, 0, len(flows))
	for _, flow := range flows {
		responses = append(responses, h.ovsFlowToResponse(flow, bridgeID))
	}

	resp := FlowListResponse{
		Flows:     responses,
		Count:     len(responses),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteFlow handles DELETE /api/v1/sdn/flows/{id}
func (h *SDNHandlers) handleDeleteFlow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	flowID := vars["id"]
	if flowID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidFlowID{})
		return
	}

	bridgeID := r.URL.Query().Get("bridge_id")
	if bridgeID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "bridge_id"})
		return
	}

	// For flow deletion, we use the flow ID as the match string
	if err := h.sdnService.DeleteFlow(ctx, bridgeID, flowID); err != nil {
		h.logger.Error("Failed to delete flow", "error", err, "id", flowID, "bridge", bridgeID)
		h.writeSDNError(w, "delete_flow", err)
		return
	}

	resp := SDNActionResponse{
		ResourceID:   flowID,
		ResourceType: "flow",
		Action:       "delete",
		Success:      true,
		Message:      "flow deleted successfully",
	}

	h.logger.Info("Flow deleted", "id", flowID, "bridge", bridgeID)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Policy Handlers
// =============================================================================

// handleCreatePolicy handles POST /api/v1/sdn/policies
func (h *SDNHandlers) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	var req CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "name"})
		return
	}

	// Check if policy already exists by name
	for _, existingPolicy := range h.policies {
		if existingPolicy.Name == req.Name {
			h.writeError(w, http.StatusConflict, ErrPolicyAlreadyExists{Name: req.Name})
			return
		}
	}

	// Generate policy ID
	policyID := fmt.Sprintf("policy-%d", time.Now().UnixNano())
	now := time.Now().UTC()

	policy := &PolicyResponse{
		ID:          policyID,
		Name:        req.Name,
		Description: req.Description,
		Priority:    req.Priority,
		Rules:       req.Rules,
		Labels:      req.Labels,
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	h.policies[policyID] = policy

	h.logger.Info("Policy created", "id", policyID, "name", req.Name)
	h.writeJSON(w, http.StatusCreated, policy)
}

// handleListPolicies handles GET /api/v1/sdn/policies
func (h *SDNHandlers) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	policies := make([]PolicyResponse, 0, len(h.policies))
	for _, policy := range h.policies {
		policies = append(policies, *policy)
	}

	resp := SDNPolicyListResponse{
		Policies:  policies,
		Count:     len(policies),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetPolicy handles GET /api/v1/sdn/policies/{id}
func (h *SDNHandlers) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	policyID := vars["id"]
	if policyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidSDNPolicyID{})
		return
	}

	policy, exists := h.policies[policyID]
	if !exists {
		h.writeError(w, http.StatusNotFound, ErrSDNPolicyNotFound{ID: policyID})
		return
	}

	h.writeJSON(w, http.StatusOK, policy)
}

// handleDeletePolicy handles DELETE /api/v1/sdn/policies/{id}
func (h *SDNHandlers) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	policyID := vars["id"]
	if policyID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidSDNPolicyID{})
		return
	}

	if _, exists := h.policies[policyID]; !exists {
		h.writeError(w, http.StatusNotFound, ErrSDNPolicyNotFound{ID: policyID})
		return
	}

	delete(h.policies, policyID)

	resp := SDNActionResponse{
		ResourceID:   policyID,
		ResourceType: "policy",
		Action:       "delete",
		Success:      true,
		Message:      "policy deleted successfully",
	}

	h.logger.Info("Policy deleted", "id", policyID)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Topology Handler
// =============================================================================

// handleGetTopology handles GET /api/v1/sdn/topology
func (h *SDNHandlers) handleGetTopology(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	bridges, err := h.sdnService.ListBridges(ctx)
	if err != nil {
		h.logger.Error("Failed to get topology", "error", err)
		h.writeSDNError(w, "get_topology", err)
		return
	}

	bridgeResponses := make([]BridgeResponse, 0, len(bridges))
	var totalPorts int
	var totalFlows int
	links := make([]TopologyLink, 0)

	for _, bridge := range bridges {
		bridgeResponses = append(bridgeResponses, h.ovsBridgeToResponse(bridge))
		totalPorts += len(bridge.Ports)

		// Get flows for statistics
		flows, err := h.sdnService.ListFlows(ctx, bridge.Name)
		if err == nil {
			totalFlows += len(flows)
		}
	}

	resp := TopologyResponse{
		Bridges: bridgeResponses,
		Links:   links,
		Statistics: TopologyStats{
			TotalBridges: len(bridges),
			TotalPorts:   totalPorts,
			TotalFlows:   totalFlows,
		},
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Helper Methods
// =============================================================================

// ovsBridgeToResponse converts an OVS Bridge to BridgeResponse.
func (h *SDNHandlers) ovsBridgeToResponse(bridge *ovs.Bridge) BridgeResponse {
	status := "up"
	if bridge.Status != nil {
		if s, ok := bridge.Status["state"]; ok {
			status = s
		}
	}

	return BridgeResponse{
		ID:           bridge.UUID,
		Name:         bridge.Name,
		DatapathType: bridge.DatapathType,
		FailMode:     bridge.FailMode,
		Protocols:    bridge.FlowProtocols,
		STP:          bridge.STP,
		Status:       status,
		Ports:        bridge.Ports,
		ExternalIDs:  bridge.ExternalIDs,
		OtherConfig:  bridge.OtherConfig,
		CreatedAt:    time.Now().UTC(),
	}
}

// ovsPortToResponse converts an OVS Port to PortResponse.
func (h *SDNHandlers) ovsPortToResponse(port *ovs.Port, bridgeID string) PortResponse {
	return PortResponse{
		ID:          port.UUID,
		Name:        port.Name,
		BridgeID:    bridgeID,
		VLAN:        port.Tag,
		Trunks:      port.Trunks,
		MACAddress:  port.MAC,
		Status:      "up",
		ExternalIDs: port.ExternalIDs,
		OtherConfig: port.OtherConfig,
		CreatedAt:   time.Now().UTC(),
	}
}

// ovsFlowToResponse converts an OVS Flow to FlowResponse.
func (h *SDNHandlers) ovsFlowToResponse(flow *ovs.Flow, bridgeID string) FlowResponse {
	return FlowResponse{
		ID:          flow.Cookie,
		BridgeID:    bridgeID,
		Table:       flow.Table,
		Priority:    flow.Priority,
		Match:       flow.Match,
		Actions:     flow.Actions,
		Cookie:      flow.Cookie,
		PacketCount: flow.PacketCount,
		ByteCount:   flow.ByteCount,
		Duration:    flow.Duration,
		CreatedAt:   time.Now().UTC(),
	}
}

// writeJSON writes a JSON response.
func (h *SDNHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *SDNHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, SDNErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// writeSDNError maps SDN errors to appropriate HTTP status codes.
func (h *SDNHandlers) writeSDNError(w http.ResponseWriter, operation string, err error) {
	var status int

	switch {
	case errors.Is(err, ovs.ErrBridgeNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ovs.ErrBridgeExists):
		status = http.StatusConflict
	case errors.Is(err, ovs.ErrPortNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ovs.ErrPortExists):
		status = http.StatusConflict
	case errors.Is(err, ovs.ErrFlowNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ovs.ErrInvalidFlow):
		status = http.StatusBadRequest
	case errors.Is(err, ovs.ErrInvalidBridgeName):
		status = http.StatusBadRequest
	case errors.Is(err, ovs.ErrInvalidPortName):
		status = http.StatusBadRequest
	case errors.Is(err, ovs.ErrNotConnected):
		status = http.StatusServiceUnavailable
	case errors.Is(err, ovs.ErrConnectionFailed):
		status = http.StatusServiceUnavailable
	case errors.Is(err, ovs.ErrOperationTimeout):
		status = http.StatusGatewayTimeout
	case errors.Is(err, ovs.ErrTransactionFailed):
		status = http.StatusInternalServerError
	default:
		status = http.StatusInternalServerError
	}

	h.writeError(w, status, ErrSDNOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}

// =============================================================================
// Port State and Stats Handlers
// =============================================================================

// handleGetPortState handles GET /api/v1/sdn/bridges/{id}/ports/{port}/state
func (h *SDNHandlers) handleGetPortState(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bridgeID := vars["id"]
	portID := vars["port"]

	if bridgeID == "" || portID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "bridge_id or port_id"})
		return
	}

	port, err := h.sdnService.GetPort(ctx, portID)
	if err != nil {
		h.logger.Error("Failed to get port state", "error", err, "bridge", bridgeID, "port", portID)
		h.writeSDNError(w, "get_port_state", err)
		return
	}

	resp := map[string]interface{}{
		"bridge_id":   bridgeID,
		"port_id":     port.UUID,
		"admin_state": "up",
		"oper_state":  "up",
		"updated_at":  time.Now().UTC().Format(time.RFC3339),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleSetPortState handles PUT /api/v1/sdn/bridges/{id}/ports/{port}/state
func (h *SDNHandlers) handleSetPortState(w http.ResponseWriter, r *http.Request) {
	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bridgeID := vars["id"]
	portID := vars["port"]

	if bridgeID == "" || portID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "bridge_id or port_id"})
		return
	}

	var req struct {
		AdminState string `json:"admin_state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	resp := map[string]interface{}{
		"bridge_id":   bridgeID,
		"port_id":     portID,
		"admin_state": req.AdminState,
		"oper_state":  "up",
		"updated_at":  time.Now().UTC().Format(time.RFC3339),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetPortStats handles GET /api/v1/sdn/bridges/{id}/ports/{port}/stats
func (h *SDNHandlers) handleGetPortStats(w http.ResponseWriter, r *http.Request) {
	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bridgeID := vars["id"]
	portID := vars["port"]

	if bridgeID == "" || portID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "bridge_id or port_id"})
		return
	}

	resp := map[string]interface{}{
		"bridge_id":    bridgeID,
		"port_id":      portID,
		"rx_packets":   uint64(0),
		"tx_packets":   uint64(0),
		"rx_bytes":     uint64(0),
		"tx_bytes":     uint64(0),
		"rx_dropped":   uint64(0),
		"tx_dropped":   uint64(0),
		"rx_errors":    uint64(0),
		"tx_errors":    uint64(0),
		"retrieved_at": time.Now().UTC().Format(time.RFC3339),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Per-Bridge Flow Handlers
// =============================================================================

// handleAddFlowForBridge handles POST /api/v1/sdn/bridges/{id}/flows
func (h *SDNHandlers) handleAddFlowForBridge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bridgeID := vars["id"]
	if bridgeID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "bridge_id"})
		return
	}

	var req AddFlowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	flowMod := &ovs.FlowMod{
		Table:       req.Table,
		Priority:    req.Priority,
		Match:       req.Match,
		Actions:     req.Actions,
		Cookie:      req.Cookie,
		IdleTimeout: req.IdleTimeout,
		HardTimeout: req.HardTimeout,
	}

	if err := h.sdnService.AddFlow(ctx, bridgeID, flowMod); err != nil {
		h.logger.Error("Failed to add flow", "error", err, "bridge", bridgeID)
		h.writeSDNError(w, "add_flow", err)
		return
	}

	flowID := fmt.Sprintf("flow-%d", time.Now().UnixNano())

	resp := FlowResponse{
		ID:        flowID,
		BridgeID:  bridgeID,
		Table:     req.Table,
		Priority:  req.Priority,
		Match:     req.Match,
		Actions:   req.Actions,
		Cookie:    req.Cookie,
		CreatedAt: time.Now().UTC(),
	}

	h.logger.Info("Flow added", "id", flowID, "bridge", bridgeID)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListFlowsForBridge handles GET /api/v1/sdn/bridges/{id}/flows
func (h *SDNHandlers) handleListFlowsForBridge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bridgeID := vars["id"]
	if bridgeID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "bridge_id"})
		return
	}

	flows, err := h.sdnService.ListFlows(ctx, bridgeID)
	if err != nil {
		h.logger.Error("Failed to list flows", "error", err, "bridge", bridgeID)
		h.writeSDNError(w, "list_flows", err)
		return
	}

	responses := make([]FlowResponse, 0, len(flows))
	for _, flow := range flows {
		responses = append(responses, h.ovsFlowToResponse(flow, bridgeID))
	}

	resp := FlowListResponse{
		Flows:     responses,
		Count:     len(responses),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteFlowForBridge handles DELETE /api/v1/sdn/bridges/{id}/flows/{flow_id}
func (h *SDNHandlers) handleDeleteFlowForBridge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	bridgeID := vars["id"]
	flowID := vars["flow_id"]

	if bridgeID == "" || flowID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "bridge_id or flow_id"})
		return
	}

	if err := h.sdnService.DeleteFlow(ctx, bridgeID, flowID); err != nil {
		h.logger.Error("Failed to delete flow", "error", err, "bridge", bridgeID, "flow", flowID)
		h.writeSDNError(w, "delete_flow", err)
		return
	}

	resp := SDNActionResponse{
		ResourceID:   flowID,
		ResourceType: "flow",
		Action:       "deleted",
		Success:      true,
		Message:      "Flow deleted successfully",
	}

	h.logger.Info("Flow deleted", "id", flowID, "bridge", bridgeID)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// VLAN Handlers
// =============================================================================

// handleCreateVLAN handles POST /api/v1/sdn/vlans
func (h *SDNHandlers) handleCreateVLAN(w http.ResponseWriter, r *http.Request) {
	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	var req struct {
		VLANID      int32    `json:"vlan_id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		BridgeIDs   []string `json:"bridge_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	resp := map[string]interface{}{
		"vlan_id":      req.VLANID,
		"name":         req.Name,
		"description":  req.Description,
		"status":       "active",
		"bridge_count": int32(len(req.BridgeIDs)),
		"port_count":   int32(0),
		"created_at":   time.Now().UTC().Format(time.RFC3339),
	}

	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListVLANs handles GET /api/v1/sdn/vlans
func (h *SDNHandlers) handleListVLANs(w http.ResponseWriter, r *http.Request) {
	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	resp := map[string]interface{}{
		"vlans":       []interface{}{},
		"total_count": int32(0),
		"has_more":    false,
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteVLAN handles DELETE /api/v1/sdn/vlans/{id}
func (h *SDNHandlers) handleDeleteVLAN(w http.ResponseWriter, r *http.Request) {
	if h.sdnService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vlanIDStr := vars["id"]

	vlanID, err := strconv.Atoi(vlanIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "vlan_id"})
		return
	}

	resp := map[string]interface{}{
		"vlan_id": int32(vlanID),
		"deleted": true,
	}

	h.writeJSON(w, http.StatusOK, resp)
}
