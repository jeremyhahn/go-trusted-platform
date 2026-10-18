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
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/status"
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

// ErrInvalidVLANID is returned when a VLAN ID in a path is not a number.
type ErrInvalidVLANID struct {
	Value string
}

func (e ErrInvalidVLANID) Error() string {
	return fmt.Sprintf("invalid VLAN ID: %q", e.Value)
}

// ErrInvalidPortState is returned when a port's admin_state is not "up" or "down".
type ErrInvalidPortState struct {
	Value string
}

func (e ErrInvalidPortState) Error() string {
	return fmt.Sprintf("invalid admin_state %q: must be 'up' or 'down'", e.Value)
}

// ErrInvalidPolicyField is returned when a policy request names a type,
// rule action or target type the SDN service does not define.
type ErrInvalidPolicyField struct {
	Field string
	Value string
}

func (e ErrInvalidPolicyField) Error() string {
	return fmt.Sprintf("invalid policy %s %q", e.Field, e.Value)
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

// ErrBridgeAlreadyExists is returned when attempting to create a bridge that
// already exists.
type ErrBridgeAlreadyExists struct {
	Name string
}

func (e ErrBridgeAlreadyExists) Error() string {
	return fmt.Sprintf("bridge already exists: %s", e.Name)
}

// ErrZoneNotFound is returned when a zone is not found.
type ErrZoneNotFound struct {
	Name string
}

func (e ErrZoneNotFound) Error() string {
	return fmt.Sprintf("zone not found: %s", e.Name)
}

// ErrZoneAlreadyExists is returned when attempting to create a zone that already exists.
type ErrZoneAlreadyExists struct {
	Name string
}

func (e ErrZoneAlreadyExists) Error() string {
	return fmt.Sprintf("zone already exists: %s", e.Name)
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

// CreatePolicyRequest is the REST form of the gRPC ApplyPolicyRequest. With an
// ID it re-applies (replaces) that policy; without one the service assigns it.
type CreatePolicyRequest struct {
	ID          string          `json:"id,omitempty"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Type        string          `json:"type,omitempty"` // acl, qos, nat, firewall, routing
	Priority    int32           `json:"priority,omitempty"`
	Enabled     bool            `json:"enabled"`
	Rules       []PolicyRule    `json:"rules,omitempty"`
	Targets     []PolicyTarget  `json:"targets,omitempty"`
	Schedule    *PolicySchedule `json:"schedule,omitempty"`
}

// PolicyRule is the gRPC PolicyRule with its match fields inlined.
type PolicyRule struct {
	RuleID          string `json:"rule_id,omitempty"`
	Priority        int32  `json:"priority,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	SourcePort      uint32 `json:"source_port,omitempty"`
	DestinationPort uint32 `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	Direction       string `json:"direction,omitempty"` // ingress, egress, both
	Interface       string `json:"interface,omitempty"`
	VLANID          uint32 `json:"vlan_id,omitempty"`
	DSCP            uint32 `json:"dscp,omitempty"`
	Application     string `json:"application,omitempty"`
	Action          string `json:"action,omitempty"` // allow, deny, rate-limit, redirect, mirror, log
	ActionValue     string `json:"action_value,omitempty"`
	Log             bool   `json:"log,omitempty"`
	Counter         bool   `json:"counter,omitempty"`
}

// PolicyTarget names what a policy applies to.
type PolicyTarget struct {
	Type      string `json:"type"` // bridge, port, vlan, interface
	ID        string `json:"id"`
	Direction string `json:"direction,omitempty"`
	Zone      string `json:"zone,omitempty"`
}

// PolicySchedule limits when a policy is in force.
type PolicySchedule struct {
	StartTime string   `json:"start_time,omitempty"`
	EndTime   string   `json:"end_time,omitempty"`
	Days      []string `json:"days,omitempty"`
	Timezone  string   `json:"timezone,omitempty"`
	Enabled   bool     `json:"enabled"`
}

// PolicyResponse is a network policy as the SDN service holds it.
type PolicyResponse struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Type        string          `json:"type,omitempty"`
	Priority    int32           `json:"priority"`
	Enabled     bool            `json:"enabled"`
	Status      string          `json:"status"`
	Rules       []PolicyRule    `json:"rules"`
	Targets     []PolicyTarget  `json:"targets"`
	Schedule    *PolicySchedule `json:"schedule,omitempty"`
	HitCount    uint64          `json:"hit_count"`
	ByteCount   uint64          `json:"byte_count"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
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

// CreateVLANRequest is the request body for POST /api/v1/sdn/vlans.
type CreateVLANRequest struct {
	VLANID   uint32            `json:"vlan_id"`
	Name     string            `json:"name,omitempty"`
	BridgeID string            `json:"bridge_id"`
	Ports    []string          `json:"ports,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// VLANResponse represents a VLAN in API responses.
type VLANResponse struct {
	ID        string            `json:"id"`
	VLANID    uint32            `json:"vlan_id"`
	Name      string            `json:"name,omitempty"`
	BridgeID  string            `json:"bridge_id"`
	Ports     []string          `json:"ports,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	PortCount uint32            `json:"port_count"`
	CreatedAt time.Time         `json:"created_at"`
}

// VLANListResponse represents a list of VLANs on one bridge.
type VLANListResponse struct {
	VLANs     []VLANResponse `json:"vlans"`
	Count     int            `json:"count"`
	Timestamp time.Time      `json:"timestamp"`
}

// SetPortStateRequest represents a request to set a port's admin state and,
// when IngressRate is non-zero, its ingress policing (rate in bps, burst in
// bits; see ovs.ValidateIngressPolicing) and, when EgressRate is non-zero, its
// egress shaping (see ovs.ValidateEgressShaping).
type SetPortStateRequest struct {
	AdminState   string `json:"admin_state"`
	IngressRate  uint64 `json:"ingress_rate,omitempty"`
	IngressBurst uint64 `json:"ingress_burst,omitempty"`
	EgressRate   uint64 `json:"egress_rate,omitempty"`
	EgressBurst  uint64 `json:"egress_burst,omitempty"`
}

// PortStateResponse represents a port's state as Open vSwitch reports it.
type PortStateResponse struct {
	BridgeID   string    `json:"bridge_id"`
	PortID     string    `json:"port_id"`
	PortNumber int32     `json:"port_number"`
	AdminState string    `json:"admin_state"`
	OperState  string    `json:"oper_state"`
	LinkState  string    `json:"link_state"`
	Speed      int64     `json:"speed"`
	Duplex     string    `json:"duplex"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// PortStatsResponse represents a port's interface counters as Open vSwitch
// reports them.
type PortStatsResponse struct {
	BridgeID    string    `json:"bridge_id"`
	PortID      string    `json:"port_id"`
	PortNumber  int32     `json:"port_number"`
	RxPackets   int64     `json:"rx_packets"`
	TxPackets   int64     `json:"tx_packets"`
	RxBytes     int64     `json:"rx_bytes"`
	TxBytes     int64     `json:"tx_bytes"`
	RxDropped   int64     `json:"rx_dropped"`
	TxDropped   int64     `json:"tx_dropped"`
	RxErrors    int64     `json:"rx_errors"`
	TxErrors    int64     `json:"tx_errors"`
	RxFrameErr  int64     `json:"rx_frame_err"`
	RxOverErr   int64     `json:"rx_over_err"`
	RxCRCErr    int64     `json:"rx_crc_err"`
	Collisions  int64     `json:"collisions"`
	RetrievedAt time.Time `json:"retrieved_at"`
}

// SDNErrorResponse represents an SDN error response.
type SDNErrorResponse struct {
	Error     string    `json:"error"`
	Code      int       `json:"code"`
	Timestamp time.Time `json:"timestamp"`
}

// NetworkZoneCreateRequest is the body of POST /api/v1/sdn/zones: an
// owner-defined zone.
type NetworkZoneCreateRequest = gateway.ZoneSpec

// NetworkZoneUpdateRequest is the body of PUT /api/v1/sdn/zones/{name}: the
// zone's new policy (the name comes from the path).
type NetworkZoneUpdateRequest = gateway.ZoneSpec

// NetworkZoneResponse represents a network zone in API responses.
type NetworkZoneResponse = gateway.ZoneView

// NetworkZoneListResponse represents a list of network zones.
type NetworkZoneListResponse struct {
	Zones     []NetworkZoneResponse `json:"zones"`
	Count     int                   `json:"count"`
	Timestamp time.Time             `json:"timestamp"`
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
	AddPortOfType(ctx context.Context, bridgeName, portName, ifType string) (*ovs.Port, error)
	DeletePort(ctx context.Context, bridgeName, portName string) error
	GetPort(ctx context.Context, name string) (*ovs.Port, error)
	ListPorts(ctx context.Context, bridgeName string) ([]*ovs.Port, error)
	SetPortVLAN(ctx context.Context, portName string, tag int64) error
	SetPortTrunks(ctx context.Context, portName string, trunks []int64) error
	SetPortState(ctx context.Context, portName string, state ovs.PortState) error
	SetIngressPolicing(ctx context.Context, name string, rateBps, burstBits uint64) error
	SetEgressShaping(ctx context.Context, name string, rateBps, burstBits uint64) error
	GetInterface(ctx context.Context, name string) (*ovs.Interface, error)

	// Flow operations
	AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error
	DeleteFlow(ctx context.Context, bridgeName string, match string) error
	DeleteFlowsByCookie(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error
	ListFlows(ctx context.Context, bridgeName string) ([]*ovs.Flow, error)
	DeleteAllFlows(ctx context.Context, bridgeName string) error
}

// SDNControlServiceInterface is the daemon's shared SDN service, the one the
// gRPC, QUIC, MCP and Unix transports serve. REST routes whose state that
// service owns (VLANs and policies) call it, so every transport sees the same state and
// applies the same validation.
type SDNControlServiceInterface interface {
	CreateVLAN(ctx context.Context, req *platformv1.CreateVLANRequest) (*platformv1.CreateVLANResponse, error)
	ListVLANs(ctx context.Context, req *platformv1.ListVLANsRequest) (*platformv1.ListVLANsResponse, error)
	DeleteVLAN(ctx context.Context, req *platformv1.DeleteVLANRequest) (*platformv1.DeleteVLANResponse, error)
	ApplyPolicy(ctx context.Context, req *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error)
	GetPolicy(ctx context.Context, req *platformv1.GetPolicyRequest) (*platformv1.GetPolicyResponse, error)
	ListPolicies(ctx context.Context, req *platformv1.ListPoliciesRequest) (*platformv1.ListPoliciesResponse, error)
	DeletePolicy(ctx context.Context, req *platformv1.DeletePolicyRequest) (*platformv1.DeletePolicyResponse, error)
}

// =============================================================================
// SDN Handlers
// =============================================================================

// SDNHandlers provides REST API handlers for SDN operations.
type SDNHandlers struct {
	sdnService     SDNServiceInterface
	controlService SDNControlServiceInterface
	zoneService    gateway.ZoneService
	logger         *slog.Logger
}

// NewSDNHandlers creates a new SDNHandlers instance.
func NewSDNHandlers(sdnService SDNServiceInterface, logger *slog.Logger) *SDNHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &SDNHandlers{
		sdnService: sdnService,
		logger:     logger,
	}
}

// SetZoneService sets the zone service for the handlers.
func (h *SDNHandlers) SetZoneService(svc gateway.ZoneService) {
	h.zoneService = svc
}

// SetControlService wires the daemon's shared SDN service into the routes
// whose state it owns. Until it is set, those routes answer 503.
func (h *SDNHandlers) SetControlService(svc SDNControlServiceInterface) {
	h.controlService = svc
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

	// Network Zone operations
	router.HandleFunc("/api/v1/sdn/zones", h.handleCreateNetworkZone).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/zones", h.handleListNetworkZones).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/zones/{name}", h.handleUpdateNetworkZone).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/sdn/zones/{name}", h.handleDeleteNetworkZone).Methods(http.MethodDelete)

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

	// The interface is created with the requested type: a system interface
	// ("") for a device that does not exist never gets an ofport or an
	// admin_state, so the state route would answer them empty.
	port, err := h.sdnService.AddPortOfType(ctx, bridgeID, req.Name, req.Type)
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

	cookie, err := flowCookie(req.Cookie)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}
	flowMod := &ovs.FlowMod{
		Table:       req.Table,
		Priority:    req.Priority,
		Match:       req.Match,
		Actions:     req.Actions,
		Cookie:      fmt.Sprintf("0x%x", cookie),
		IdleTimeout: req.IdleTimeout,
		HardTimeout: req.HardTimeout,
	}

	if err := h.sdnService.AddFlow(ctx, bridgeID, flowMod); err != nil {
		h.logger.Error("Failed to add flow", "error", err, "bridge", bridgeID)
		h.writeSDNError(w, "add_flow", err)
		return
	}

	// The flow's ID is its cookie, so a delete names exactly this flow.
	flowID := ovs.FlowID(cookie)

	resp := FlowResponse{
		ID:        flowID,
		BridgeID:  bridgeID,
		Table:     req.Table,
		Priority:  req.Priority,
		Match:     req.Match,
		Actions:   req.Actions,
		Cookie:    flowMod.Cookie,
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

	// The ID is the flow's cookie. It used to be handed to OVS as a match
	// string, which the encoder emptied, and an empty-match delete removed
	// every flow on the bridge (#614).
	cookie, err := ovs.ParseFlowID(flowID)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.sdnService.DeleteFlowsByCookie(ctx, bridgeID, cookie, ^uint64(0)); err != nil {
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
	if h.controlService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	var req CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	applyReq, err := PolicyRequestToProto(req)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	resp, err := h.controlService.ApplyPolicy(r.Context(), applyReq)
	if err != nil {
		h.writeControlError(w, "apply_policy", err)
		return
	}

	h.logger.Info("Policy applied", "id", resp.GetPolicy().GetId(), "name", req.Name)
	h.writeJSON(w, http.StatusCreated, PolicyToResponse(resp.GetPolicy()))
}

// handleListPolicies handles GET /api/v1/sdn/policies
func (h *SDNHandlers) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if h.controlService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	query := r.URL.Query()
	resp, err := h.controlService.ListPolicies(r.Context(), &platformv1.ListPoliciesRequest{
		Type:     query.Get("type"),
		TargetId: query.Get("target_id"),
	})
	if err != nil {
		h.writeControlError(w, "list_policies", err)
		return
	}

	policies := make([]PolicyResponse, 0, len(resp.GetPolicies()))
	for _, policy := range resp.GetPolicies() {
		policies = append(policies, PolicyToResponse(policy))
	}

	h.writeJSON(w, http.StatusOK, SDNPolicyListResponse{
		Policies:  policies,
		Count:     len(policies),
		Timestamp: time.Now().UTC(),
	})
}

// handleGetPolicy handles GET /api/v1/sdn/policies/{id}
func (h *SDNHandlers) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	if h.controlService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	resp, err := h.controlService.GetPolicy(r.Context(), &platformv1.GetPolicyRequest{
		PolicyId: mux.Vars(r)["id"],
	})
	if err != nil {
		h.writeControlError(w, "get_policy", err)
		return
	}

	h.writeJSON(w, http.StatusOK, PolicyToResponse(resp.GetPolicy()))
}

// handleDeletePolicy handles DELETE /api/v1/sdn/policies/{id}
func (h *SDNHandlers) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	if h.controlService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	policyID := mux.Vars(r)["id"]
	resp, err := h.controlService.DeletePolicy(r.Context(), &platformv1.DeletePolicyRequest{
		PolicyId: policyID,
	})
	if err != nil {
		h.writeControlError(w, "delete_policy", err)
		return
	}

	h.logger.Info("Policy deleted", "id", policyID)
	h.writeJSON(w, http.StatusOK, SDNActionResponse{
		ResourceID:   policyID,
		ResourceType: "policy",
		Action:       "delete",
		Success:      resp.GetStatus().GetSuccess(),
		Message:      resp.GetStatus().GetMessage(),
	})
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
// flowCookie is the cookie a flow added through the API carries: the one
// the caller asked for, or a fresh one under the API owner prefix. Either
// way it is the flow's identity, and its ID is ovs.FlowID of it.
func flowCookie(requested string) (uint64, error) {
	if requested == "" {
		return ovs.NewAPIFlowCookie()
	}
	return ovs.ParseFlowID(ovs.FlowIDPrefix + requested)
}

func (h *SDNHandlers) ovsFlowToResponse(flow *ovs.Flow, bridgeID string) FlowResponse {
	return FlowResponse{
		ID:          ovs.FlowIDPrefix + flow.Cookie,
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
	var invalidPolicing *ovs.ErrInvalidPolicing
	var invalidShaping *ovs.ErrInvalidShaping

	switch {
	case errors.As(err, &invalidPolicing):
		status = http.StatusBadRequest
	case errors.As(err, &invalidShaping):
		status = http.StatusBadRequest
	case errors.Is(err, ovs.ErrInterfaceNotFound):
		status = http.StatusNotFound
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

// writeControlError translates a gRPC status error from the shared SDN
// service into an HTTP error response, with the same code mapping as the
// other REST adapters over a gRPC service.
func (h *SDNHandlers) writeControlError(w http.ResponseWriter, operation string, err error) {
	httpStatus := http.StatusInternalServerError
	if mapped, ok := grpcCodeToHTTPStatus[status.Code(err)]; ok {
		httpStatus = mapped
	}
	h.logger.Error("SDN operation failed", "operation", operation, "error", err)
	h.writeError(w, httpStatus, ErrSDNOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}

// vlanToResponse converts a VLAN from the shared SDN service to its REST form.
func vlanToResponse(vlan *platformv1.VLAN) VLANResponse {
	config := vlan.GetConfig()
	resp := VLANResponse{
		ID:        vlan.GetId(),
		VLANID:    config.GetVlanId(),
		Name:      config.GetName(),
		BridgeID:  config.GetBridgeId(),
		Ports:     config.GetPorts(),
		Labels:    config.GetLabels(),
		PortCount: vlan.GetStats().GetPortCount(),
	}
	if vlan.GetCreatedAt() != nil {
		resp.CreatedAt = vlan.GetCreatedAt().AsTime().UTC()
	}
	return resp
}

// Proto enum value-name prefixes; REST spells the rest of the name in lower
// case with dashes, e.g. POLICY_RULE_ACTION_RATE_LIMIT is "rate-limit".
const (
	policyTypePrefix       = "POLICY_TYPE_"
	policyStatusPrefix     = "POLICY_STATUS_"
	policyRuleActionPrefix = "POLICY_RULE_ACTION_"
	policyTargetTypePrefix = "POLICY_TARGET_TYPE_"
)

// protoEnumValue resolves a REST enum name to its proto value. An empty name
// is the unspecified value, as an omitted gRPC field is.
func protoEnumValue(values map[string]int32, prefix, field, name string) (int32, error) {
	if name == "" {
		return 0, nil
	}
	value, ok := values[prefix+strings.ToUpper(strings.ReplaceAll(name, "-", "_"))]
	if !ok {
		return 0, ErrInvalidPolicyField{Field: field, Value: name}
	}
	return value, nil
}

// protoEnumName is the inverse of protoEnumValue; the unspecified value is "".
func protoEnumName(name, prefix string) string {
	name = strings.TrimPrefix(name, prefix)
	if name == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

// PolicyRequestToProto converts a REST policy body into the gRPC
// ApplyPolicyRequest, rejecting enum names the proto does not define.
func PolicyRequestToProto(req CreatePolicyRequest) (*platformv1.ApplyPolicyRequest, error) {
	policyType, err := protoEnumValue(platformv1.PolicyType_value, policyTypePrefix, "type", req.Type)
	if err != nil {
		return nil, err
	}

	rules := make([]*platformv1.PolicyRule, 0, len(req.Rules))
	for _, rule := range req.Rules {
		protoRule, err := policyRuleToProto(rule)
		if err != nil {
			return nil, err
		}
		rules = append(rules, protoRule)
	}

	targets := make([]*platformv1.PolicyTarget, 0, len(req.Targets))
	for _, target := range req.Targets {
		targetType, err := protoEnumValue(platformv1.PolicyTargetType_value, policyTargetTypePrefix, "target type", target.Type)
		if err != nil {
			return nil, err
		}
		targets = append(targets, &platformv1.PolicyTarget{
			Type:      platformv1.PolicyTargetType(targetType),
			Id:        target.ID,
			Direction: target.Direction,
			Zone:      target.Zone,
		})
	}

	return &platformv1.ApplyPolicyRequest{
		PolicyId: req.ID,
		Config: &platformv1.PolicyConfig{
			Name:        req.Name,
			Description: req.Description,
			Type:        platformv1.PolicyType(policyType),
			Priority:    req.Priority,
			Enabled:     req.Enabled,
			Rules:       rules,
			Targets:     targets,
			Schedule:    policyScheduleToProto(req.Schedule),
		},
	}, nil
}

func policyRuleToProto(rule PolicyRule) (*platformv1.PolicyRule, error) {
	action, err := protoEnumValue(platformv1.PolicyRuleAction_value, policyRuleActionPrefix, "rule action", rule.Action)
	if err != nil {
		return nil, err
	}
	return &platformv1.PolicyRule{
		RuleId:   rule.RuleID,
		Priority: rule.Priority,
		Match: &platformv1.PolicyRuleMatch{
			SourceIp:        rule.SourceIP,
			DestinationIp:   rule.DestinationIP,
			SourcePort:      rule.SourcePort,
			DestinationPort: rule.DestinationPort,
			Protocol:        rule.Protocol,
			Direction:       rule.Direction,
			Interface:       rule.Interface,
			VlanId:          rule.VLANID,
			Dscp:            rule.DSCP,
			Application:     rule.Application,
		},
		Action:      platformv1.PolicyRuleAction(action),
		ActionValue: rule.ActionValue,
		Log:         rule.Log,
		Counter:     rule.Counter,
	}, nil
}

func policyScheduleToProto(schedule *PolicySchedule) *platformv1.PolicySchedule {
	if schedule == nil {
		return nil
	}
	return &platformv1.PolicySchedule{
		StartTime: schedule.StartTime,
		EndTime:   schedule.EndTime,
		Days:      schedule.Days,
		Timezone:  schedule.Timezone,
		Enabled:   schedule.Enabled,
	}
}

// PolicyToResponse converts a policy held by the SDN service into its REST form.
func PolicyToResponse(policy *platformv1.Policy) PolicyResponse {
	config := policy.GetConfig()

	rules := make([]PolicyRule, 0, len(config.GetRules()))
	for _, rule := range config.GetRules() {
		match := rule.GetMatch()
		rules = append(rules, PolicyRule{
			RuleID:          rule.GetRuleId(),
			Priority:        rule.GetPriority(),
			SourceIP:        match.GetSourceIp(),
			DestinationIP:   match.GetDestinationIp(),
			SourcePort:      match.GetSourcePort(),
			DestinationPort: match.GetDestinationPort(),
			Protocol:        match.GetProtocol(),
			Direction:       match.GetDirection(),
			Interface:       match.GetInterface(),
			VLANID:          match.GetVlanId(),
			DSCP:            match.GetDscp(),
			Application:     match.GetApplication(),
			Action:          protoEnumName(rule.GetAction().String(), policyRuleActionPrefix),
			ActionValue:     rule.GetActionValue(),
			Log:             rule.GetLog(),
			Counter:         rule.GetCounter(),
		})
	}

	targets := make([]PolicyTarget, 0, len(config.GetTargets()))
	for _, target := range config.GetTargets() {
		targets = append(targets, PolicyTarget{
			Type:      protoEnumName(target.GetType().String(), policyTargetTypePrefix),
			ID:        target.GetId(),
			Direction: target.GetDirection(),
			Zone:      target.GetZone(),
		})
	}

	resp := PolicyResponse{
		ID:          policy.GetId(),
		Name:        config.GetName(),
		Description: config.GetDescription(),
		Type:        protoEnumName(config.GetType().String(), policyTypePrefix),
		Priority:    config.GetPriority(),
		Enabled:     config.GetEnabled(),
		Status:      protoEnumName(policy.GetStatus().String(), policyStatusPrefix),
		Rules:       rules,
		Targets:     targets,
		HitCount:    policy.GetHitCount(),
		ByteCount:   policy.GetByteCount(),
	}
	if schedule := config.GetSchedule(); schedule != nil {
		resp.Schedule = &PolicySchedule{
			StartTime: schedule.GetStartTime(),
			EndTime:   schedule.GetEndTime(),
			Days:      schedule.GetDays(),
			Timezone:  schedule.GetTimezone(),
			Enabled:   schedule.GetEnabled(),
		}
	}
	if policy.GetCreatedAt() != nil {
		resp.CreatedAt = policy.GetCreatedAt().AsTime().UTC()
	}
	if policy.GetUpdatedAt() != nil {
		resp.UpdatedAt = policy.GetUpdatedAt().AsTime().UTC()
	}
	return resp
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

	iface, err := h.sdnService.GetInterface(ctx, portID)
	if err != nil {
		h.logger.Error("Failed to get port state", "error", err, "bridge", bridgeID, "port", portID)
		h.writeSDNError(w, "get_port_state", err)
		return
	}

	h.writeJSON(w, http.StatusOK, interfaceToPortState(bridgeID, portID, iface))
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

	var req SetPortStateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	state, ok := portStates[strings.ToLower(req.AdminState)]
	if !ok {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPortState{Value: req.AdminState})
		return
	}
	if err := ovs.ValidateIngressPolicing(req.IngressRate, req.IngressBurst); err != nil {
		h.writeSDNError(w, "set_port_state", err)
		return
	}
	if err := ovs.ValidateEgressShaping(req.EgressRate, req.EgressBurst); err != nil {
		h.writeSDNError(w, "set_port_state", err)
		return
	}

	ctx := r.Context()
	if err := h.sdnService.SetPortState(ctx, portID, state); err != nil {
		h.logger.Error("Failed to set port state", "error", err, "bridge", bridgeID, "port", portID)
		h.writeSDNError(w, "set_port_state", err)
		return
	}
	// A zero ingress rate leaves the port's policing as it is.
	if req.IngressRate > 0 {
		if err := h.sdnService.SetIngressPolicing(ctx, portID, req.IngressRate, req.IngressBurst); err != nil {
			h.logger.Error("Failed to set ingress policing", "error", err, "bridge", bridgeID, "port", portID)
			h.writeSDNError(w, "set_ingress_policing", err)
			return
		}
	}
	// A zero egress rate leaves the port's shaping as it is.
	if req.EgressRate > 0 {
		if err := h.sdnService.SetEgressShaping(ctx, portID, req.EgressRate, req.EgressBurst); err != nil {
			h.logger.Error("Failed to set egress shaping", "error", err, "bridge", bridgeID, "port", portID)
			h.writeSDNError(w, "set_egress_shaping", err)
			return
		}
	}

	iface, err := h.sdnService.GetInterface(ctx, portID)
	if err != nil {
		h.logger.Error("Failed to get port state", "error", err, "bridge", bridgeID, "port", portID)
		h.writeSDNError(w, "get_port_state", err)
		return
	}

	h.writeJSON(w, http.StatusOK, interfaceToPortState(bridgeID, portID, iface))
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

	iface, err := h.sdnService.GetInterface(r.Context(), portID)
	if err != nil {
		h.logger.Error("Failed to get port stats", "error", err, "bridge", bridgeID, "port", portID)
		h.writeSDNError(w, "get_port_stats", err)
		return
	}

	stats := iface.Statistics
	h.writeJSON(w, http.StatusOK, PortStatsResponse{
		BridgeID:    bridgeID,
		PortID:      portID,
		PortNumber:  iface.OFPort,
		RxPackets:   stats["rx_packets"],
		TxPackets:   stats["tx_packets"],
		RxBytes:     stats["rx_bytes"],
		TxBytes:     stats["tx_bytes"],
		RxDropped:   stats["rx_dropped"],
		TxDropped:   stats["tx_dropped"],
		RxErrors:    stats["rx_errors"],
		TxErrors:    stats["tx_errors"],
		RxFrameErr:  stats["rx_frame_err"],
		RxOverErr:   stats["rx_over_err"],
		RxCRCErr:    stats["rx_crc_err"],
		Collisions:  stats["collisions"],
		RetrievedAt: time.Now().UTC(),
	})
}

// portStates maps the admin_state values the port-state route accepts to
// their Open vSwitch states.
var portStates = map[string]ovs.PortState{
	string(ovs.PortStateUp):   ovs.PortStateUp,
	string(ovs.PortStateDown): ovs.PortStateDown,
}

// interfaceToPortState reports an Open vSwitch interface's state.
func interfaceToPortState(bridgeID, portID string, iface *ovs.Interface) PortStateResponse {
	return PortStateResponse{
		BridgeID:   bridgeID,
		PortID:     portID,
		PortNumber: iface.OFPort,
		AdminState: iface.AdminState,
		OperState:  iface.LinkState,
		LinkState:  iface.LinkState,
		Speed:      iface.Speed,
		Duplex:     iface.Duplex,
		UpdatedAt:  time.Now().UTC(),
	}
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

	cookie, err := flowCookie(req.Cookie)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}
	flowMod := &ovs.FlowMod{
		Table:       req.Table,
		Priority:    req.Priority,
		Match:       req.Match,
		Actions:     req.Actions,
		Cookie:      fmt.Sprintf("0x%x", cookie),
		IdleTimeout: req.IdleTimeout,
		HardTimeout: req.HardTimeout,
	}

	if err := h.sdnService.AddFlow(ctx, bridgeID, flowMod); err != nil {
		h.logger.Error("Failed to add flow", "error", err, "bridge", bridgeID)
		h.writeSDNError(w, "add_flow", err)
		return
	}

	flowID := ovs.FlowID(cookie)

	resp := FlowResponse{
		ID:        flowID,
		BridgeID:  bridgeID,
		Table:     req.Table,
		Priority:  req.Priority,
		Match:     req.Match,
		Actions:   req.Actions,
		Cookie:    flowMod.Cookie,
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

	cookie, err := ovs.ParseFlowID(flowID)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.sdnService.DeleteFlowsByCookie(ctx, bridgeID, cookie, ^uint64(0)); err != nil {
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
	if h.controlService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	var req CreateVLANRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	resp, err := h.controlService.CreateVLAN(r.Context(), &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			VlanId:   req.VLANID,
			Name:     req.Name,
			BridgeId: req.BridgeID,
			Ports:    req.Ports,
			Labels:   req.Labels,
		},
	})
	if err != nil {
		h.writeControlError(w, "create_vlan", err)
		return
	}

	h.logger.Info("VLAN created", "vlan_id", req.VLANID, "bridge", req.BridgeID)
	h.writeJSON(w, http.StatusCreated, vlanToResponse(resp.GetVlan()))
}

// handleListVLANs handles GET /api/v1/sdn/vlans?bridge_id={bridge}
func (h *SDNHandlers) handleListVLANs(w http.ResponseWriter, r *http.Request) {
	if h.controlService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	resp, err := h.controlService.ListVLANs(r.Context(), &platformv1.ListVLANsRequest{
		BridgeId: r.URL.Query().Get("bridge_id"),
	})
	if err != nil {
		h.writeControlError(w, "list_vlans", err)
		return
	}

	vlans := make([]VLANResponse, 0, len(resp.GetVlans()))
	for _, vlan := range resp.GetVlans() {
		vlans = append(vlans, vlanToResponse(vlan))
	}

	h.writeJSON(w, http.StatusOK, VLANListResponse{
		VLANs:     vlans,
		Count:     len(vlans),
		Timestamp: time.Now().UTC(),
	})
}

// handleDeleteVLAN handles DELETE /api/v1/sdn/vlans/{id}?bridge_id={bridge}
func (h *SDNHandlers) handleDeleteVLAN(w http.ResponseWriter, r *http.Request) {
	if h.controlService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	vlanIDStr := mux.Vars(r)["id"]
	vlanID, err := strconv.ParseUint(vlanIDStr, 10, 32)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidVLANID{Value: vlanIDStr})
		return
	}
	bridgeID := r.URL.Query().Get("bridge_id")

	_, err = h.controlService.DeleteVLAN(r.Context(), &platformv1.DeleteVLANRequest{
		BridgeId: bridgeID,
		VlanId:   uint32(vlanID),
	})
	if err != nil {
		h.writeControlError(w, "delete_vlan", err)
		return
	}

	h.logger.Info("VLAN deleted", "vlan_id", vlanID, "bridge", bridgeID)
	h.writeJSON(w, http.StatusOK, SDNActionResponse{
		ResourceID:   vlanIDStr,
		ResourceType: "vlan",
		Action:       "deleted",
		Success:      true,
		Message:      "VLAN deleted successfully",
	})
}

// =============================================================================
// Network Zone Handlers
// =============================================================================

// handleCreateNetworkZone handles POST /api/v1/sdn/zones
func (h *SDNHandlers) handleCreateNetworkZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.zoneService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	var req NetworkZoneCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, &WrappedError{Msg: "invalid request body", Err: err})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, &MessageError{Msg: "zone name is required"})
		return
	}

	rec, restartRequired, err := h.zoneService.Create(ctx, req.Config(""))
	if err != nil {
		switch err.(type) {
		case gateway.ErrZoneAlreadyExists:
			h.writeError(w, http.StatusConflict, err)
		case gateway.ErrZoneValidation:
			h.writeError(w, http.StatusBadRequest, err)
		default:
			h.writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	h.writeJSON(w, http.StatusCreated, rec.View(restartRequired))
}

// handleListNetworkZones handles GET /api/v1/sdn/zones
func (h *SDNHandlers) handleListNetworkZones(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.zoneService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	lifecycleRole := r.URL.Query().Get("lifecycle_role")

	recs, err := h.zoneService.List(ctx, zone.LifecycleRole(lifecycleRole))
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err)
		return
	}

	zones := make([]NetworkZoneResponse, 0, len(recs))
	for _, rec := range recs {
		zones = append(zones, rec.View(false))
	}

	h.writeJSON(w, http.StatusOK, NetworkZoneListResponse{
		Zones:     zones,
		Count:     len(zones),
		Timestamp: time.Now(),
	})
}

// handleUpdateNetworkZone handles PUT /api/v1/sdn/zones/{name}
func (h *SDNHandlers) handleUpdateNetworkZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.zoneService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	name := mux.Vars(r)["name"]
	if name == "" {
		h.writeError(w, http.StatusBadRequest, &MessageError{Msg: "zone name is required"})
		return
	}

	var req NetworkZoneUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, &WrappedError{Msg: "invalid request body", Err: err})
		return
	}

	rec, restartRequired, err := h.zoneService.Update(ctx, zone.Zone(name), req.Config(name))
	if err != nil {
		switch err.(type) {
		case gateway.ErrZoneNotFound:
			h.writeError(w, http.StatusNotFound, err)
		case gateway.ErrZoneValidation:
			h.writeError(w, http.StatusBadRequest, err)
		default:
			h.writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	h.writeJSON(w, http.StatusOK, rec.View(restartRequired))
}

// handleDeleteNetworkZone handles DELETE /api/v1/sdn/zones/{name}
func (h *SDNHandlers) handleDeleteNetworkZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.zoneService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	name := mux.Vars(r)["name"]
	if name == "" {
		h.writeError(w, http.StatusBadRequest, &MessageError{Msg: "zone name is required"})
		return
	}

	restartRequired, err := h.zoneService.Delete(ctx, zone.Zone(name))
	if err != nil {
		switch err.(type) {
		case gateway.ErrZoneNotFound:
			h.writeError(w, http.StatusNotFound, err)
		case gateway.ErrZoneValidation:
			h.writeError(w, http.StatusBadRequest, err)
		default:
			h.writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"deleted":          true,
		"restart_required": restartRequired,
	})
}
