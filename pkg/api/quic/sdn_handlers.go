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

package quic

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// SDN pagination defaults
const (
	sdnDefaultLimit int32 = 100
	sdnMaxLimit     int32 = 1000
)

// SDN-specific sentinel errors
var (
	// ErrSDNServiceNotAvailable is returned when the SDN service is not
	// configured or unavailable.
	ErrSDNServiceNotAvailable = errors.New("SDN service not available")

	// ErrSDNMissingBridgeName is returned when a bridge name is required but
	// not provided.
	ErrSDNMissingBridgeName = errors.New("bridge name is required")

	// ErrSDNMissingBridgeID is returned when a bridge ID is required but
	// not provided.
	ErrSDNMissingBridgeID = errors.New("bridge ID is required")

	// ErrSDNMissingPortName is returned when a port name is required but
	// not provided.
	ErrSDNMissingPortName = errors.New("port name is required")

	// ErrSDNMissingPolicyID is returned when a policy ID is required but
	// not provided.
	ErrSDNMissingPolicyID = errors.New("policy ID is required")

	// ErrSDNMissingPolicyName is returned when a policy name is required but
	// not provided.
	ErrSDNMissingPolicyName = errors.New("policy name is required")

	// ErrSDNPolicyNotFound is returned when a requested policy does not exist.
	ErrSDNPolicyNotFound = errors.New("policy not found")

	// ErrSDNPolicyAlreadyExists is returned when attempting to create a policy
	// that already exists.
	ErrSDNPolicyAlreadyExists = errors.New("policy already exists")
)

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

// SDNHandler handles SDN operations over QUIC
type SDNHandler struct {
	sdnService SDNServiceInterface
	logger     *logging.Logger
	policies   map[string]*SDNPolicyInfo
	policyMu   sync.RWMutex
}

// NewSDNHandler creates a new SDN handler
func NewSDNHandler(logger *logging.Logger, sdnService SDNServiceInterface) *SDNHandler {
	return &SDNHandler{
		sdnService: sdnService,
		logger:     logger,
		policies:   make(map[string]*SDNPolicyInfo),
	}
}

// HandleRequest processes an SDN request and returns a response
func (h *SDNHandler) HandleRequest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if req == nil {
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte(quicwire.ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	// Bridge operations
	case quicwire.OpSDNCreateBridge:
		return h.handleCreateBridge(ctx, req)
	case quicwire.OpSDNDeleteBridge:
		return h.handleDeleteBridge(ctx, req)
	case quicwire.OpSDNGetBridge:
		return h.handleGetBridge(ctx, req)
	case quicwire.OpSDNListBridges:
		return h.handleListBridges(ctx, req)

	// Port operations
	case quicwire.OpSDNCreatePort:
		return h.handleCreatePort(ctx, req)
	case quicwire.OpSDNDeletePort:
		return h.handleDeletePort(ctx, req)
	case quicwire.OpSDNGetPort:
		return h.handleGetPort(ctx, req)
	case quicwire.OpSDNListPorts:
		return h.handleListPorts(ctx, req)
	case quicwire.OpSDNSetVLAN:
		return h.handleSetVLAN(ctx, req)
	case quicwire.OpSDNGetVLAN:
		return h.handleGetVLAN(ctx, req)

	// Flow operations
	case quicwire.OpSDNAddFlow:
		return h.handleAddFlow(ctx, req)
	case quicwire.OpSDNDeleteFlow:
		return h.handleDeleteFlow(ctx, req)
	case quicwire.OpSDNListFlows:
		return h.handleListFlows(ctx, req)

	// Policy operations
	case quicwire.OpSDNApplyPolicy:
		return h.handleApplyPolicy(ctx, req)
	case quicwire.OpSDNGetPolicy:
		return h.handleGetPolicy(ctx, req)
	case quicwire.OpSDNListPolicies:
		return h.handleListPolicies(ctx, req)
	case quicwire.OpSDNDeletePolicy:
		return h.handleDeletePolicy(ctx, req)

	// Metrics
	case quicwire.OpSDNGetMetrics:
		return h.handleGetMetrics(ctx, req)

	default:
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte("unknown SDN operation"),
		}
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// SDNCreateBridgeRequest represents a bridge creation request
type SDNCreateBridgeRequest struct {
	Name         string            `codec:"name"`
	DatapathType string            `codec:"datapath_type,omitempty"`
	FailMode     string            `codec:"fail_mode,omitempty"`
	Protocols    []string          `codec:"protocols,omitempty"`
	STP          bool              `codec:"stp,omitempty"`
	Options      map[string]string `codec:"options,omitempty"`
	Labels       map[string]string `codec:"labels,omitempty"`
}

// SDNCreateBridgeResponse represents a bridge creation response
type SDNCreateBridgeResponse struct {
	Bridge    *SDNBridgeInfo `codec:"bridge"`
	Timestamp int64          `codec:"timestamp"`
}

// SDNBridgeInfo contains bridge information
type SDNBridgeInfo struct {
	ID           string            `codec:"id"`
	Name         string            `codec:"name"`
	DatapathType string            `codec:"datapath_type,omitempty"`
	FailMode     string            `codec:"fail_mode,omitempty"`
	Protocols    []string          `codec:"protocols,omitempty"`
	STP          bool              `codec:"stp,omitempty"`
	Status       string            `codec:"status"`
	Ports        []string          `codec:"ports,omitempty"`
	ExternalIDs  map[string]string `codec:"external_ids,omitempty"`
	OtherConfig  map[string]string `codec:"other_config,omitempty"`
	CreatedAt    int64             `codec:"created_at"`
}

// SDNDeleteBridgeRequest represents a bridge deletion request
type SDNDeleteBridgeRequest struct {
	Name string `codec:"name"`
}

// SDNDeleteBridgeResponse represents a bridge deletion response
type SDNDeleteBridgeResponse struct {
	Name      string `codec:"name"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// SDNGetBridgeRequest represents a bridge get request
type SDNGetBridgeRequest struct {
	Name string `codec:"name"`
}

// SDNGetBridgeResponse represents a bridge get response
type SDNGetBridgeResponse struct {
	Bridge    *SDNBridgeInfo `codec:"bridge"`
	Timestamp int64          `codec:"timestamp"`
}

// SDNListBridgesRequest represents a bridges list request
type SDNListBridgesRequest struct {
	Limit int32 `codec:"limit,omitempty"`
}

// SDNListBridgesResponse represents a bridges list response
type SDNListBridgesResponse struct {
	Bridges   []*SDNBridgeInfo `codec:"bridges"`
	Count     int32            `codec:"count"`
	Timestamp int64            `codec:"timestamp"`
}

// SDNCreatePortRequest represents a port creation request
type SDNCreatePortRequest struct {
	BridgeName string            `codec:"bridge_name"`
	PortName   string            `codec:"port_name"`
	Type       string            `codec:"type,omitempty"`
	VLAN       int64             `codec:"vlan,omitempty"`
	Trunks     []int64           `codec:"trunks,omitempty"`
	Options    map[string]string `codec:"options,omitempty"`
	Labels     map[string]string `codec:"labels,omitempty"`
}

// SDNCreatePortResponse represents a port creation response
type SDNCreatePortResponse struct {
	Port      *SDNPortInfo `codec:"port"`
	Timestamp int64        `codec:"timestamp"`
}

// SDNPortInfo contains port information
type SDNPortInfo struct {
	ID          string            `codec:"id"`
	Name        string            `codec:"name"`
	BridgeName  string            `codec:"bridge_name"`
	Type        string            `codec:"type,omitempty"`
	VLAN        int64             `codec:"vlan,omitempty"`
	Trunks      []int64           `codec:"trunks,omitempty"`
	MACAddress  string            `codec:"mac_address,omitempty"`
	Status      string            `codec:"status"`
	ExternalIDs map[string]string `codec:"external_ids,omitempty"`
	OtherConfig map[string]string `codec:"other_config,omitempty"`
	CreatedAt   int64             `codec:"created_at"`
}

// SDNDeletePortRequest represents a port deletion request
type SDNDeletePortRequest struct {
	BridgeName string `codec:"bridge_name"`
	PortName   string `codec:"port_name"`
}

// SDNDeletePortResponse represents a port deletion response
type SDNDeletePortResponse struct {
	PortName  string `codec:"port_name"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// SDNGetPortRequest represents a port get request
type SDNGetPortRequest struct {
	PortName string `codec:"port_name"`
}

// SDNGetPortResponse represents a port get response
type SDNGetPortResponse struct {
	Port      *SDNPortInfo `codec:"port"`
	Timestamp int64        `codec:"timestamp"`
}

// SDNListPortsRequest represents a ports list request
type SDNListPortsRequest struct {
	BridgeName string `codec:"bridge_name"`
	Limit      int32  `codec:"limit,omitempty"`
}

// SDNListPortsResponse represents a ports list response
type SDNListPortsResponse struct {
	Ports     []*SDNPortInfo `codec:"ports"`
	Count     int32          `codec:"count"`
	Timestamp int64          `codec:"timestamp"`
}

// SDNSetVLANRequest represents a VLAN set request
type SDNSetVLANRequest struct {
	PortName string `codec:"port_name"`
	VLAN     int64  `codec:"vlan"`
}

// SDNSetVLANResponse represents a VLAN set response
type SDNSetVLANResponse struct {
	PortName  string `codec:"port_name"`
	VLAN      int64  `codec:"vlan"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// SDNGetVLANRequest represents a VLAN get request
type SDNGetVLANRequest struct {
	PortName string `codec:"port_name"`
}

// SDNGetVLANResponse represents a VLAN get response
type SDNGetVLANResponse struct {
	PortName  string  `codec:"port_name"`
	VLAN      int64   `codec:"vlan"`
	Trunks    []int64 `codec:"trunks,omitempty"`
	Timestamp int64   `codec:"timestamp"`
}

// SDNAddFlowRequest represents a flow addition request
type SDNAddFlowRequest struct {
	BridgeName  string            `codec:"bridge_name"`
	Table       int               `codec:"table"`
	Priority    int               `codec:"priority"`
	Match       string            `codec:"match"`
	Actions     string            `codec:"actions"`
	Cookie      string            `codec:"cookie,omitempty"`
	IdleTimeout int               `codec:"idle_timeout,omitempty"`
	HardTimeout int               `codec:"hard_timeout,omitempty"`
	Metadata    map[string]string `codec:"metadata,omitempty"`
}

// SDNAddFlowResponse represents a flow addition response
type SDNAddFlowResponse struct {
	FlowID    string `codec:"flow_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// SDNDeleteFlowRequest represents a flow deletion request
type SDNDeleteFlowRequest struct {
	BridgeName string `codec:"bridge_name"`
	Match      string `codec:"match"`
}

// SDNDeleteFlowResponse represents a flow deletion response
type SDNDeleteFlowResponse struct {
	Success   bool  `codec:"success"`
	Timestamp int64 `codec:"timestamp"`
}

// SDNListFlowsRequest represents a flows list request
type SDNListFlowsRequest struct {
	BridgeName string `codec:"bridge_name"`
	Limit      int32  `codec:"limit,omitempty"`
}

// SDNFlowInfo contains flow information
type SDNFlowInfo struct {
	ID          string `codec:"id"`
	BridgeName  string `codec:"bridge_name"`
	Table       int    `codec:"table"`
	Priority    int    `codec:"priority"`
	Match       string `codec:"match"`
	Actions     string `codec:"actions"`
	Cookie      string `codec:"cookie,omitempty"`
	PacketCount int64  `codec:"packet_count,omitempty"`
	ByteCount   int64  `codec:"byte_count,omitempty"`
	Duration    int    `codec:"duration,omitempty"`
	CreatedAt   int64  `codec:"created_at"`
}

// SDNListFlowsResponse represents a flows list response
type SDNListFlowsResponse struct {
	Flows     []*SDNFlowInfo `codec:"flows"`
	Count     int32          `codec:"count"`
	Timestamp int64          `codec:"timestamp"`
}

// SDNApplyPolicyRequest represents a policy application request
type SDNApplyPolicyRequest struct {
	Name        string            `codec:"name"`
	Description string            `codec:"description,omitempty"`
	Priority    int               `codec:"priority,omitempty"`
	Rules       []SDNPolicyRule   `codec:"rules"`
	Labels      map[string]string `codec:"labels,omitempty"`
}

// SDNPolicyRule represents a rule within a network policy
type SDNPolicyRule struct {
	Direction string `codec:"direction"` // ingress, egress
	Protocol  string `codec:"protocol,omitempty"`
	PortRange string `codec:"port_range,omitempty"`
	Source    string `codec:"source,omitempty"`
	Dest      string `codec:"dest,omitempty"`
	Action    string `codec:"action"` // allow, deny
}

// SDNApplyPolicyResponse represents a policy application response
type SDNApplyPolicyResponse struct {
	Policy    *SDNPolicyInfo `codec:"policy"`
	Timestamp int64          `codec:"timestamp"`
}

// SDNPolicyInfo contains policy information
type SDNPolicyInfo struct {
	ID          string            `codec:"id"`
	Name        string            `codec:"name"`
	Description string            `codec:"description,omitempty"`
	Priority    int               `codec:"priority"`
	Rules       []SDNPolicyRule   `codec:"rules"`
	Labels      map[string]string `codec:"labels,omitempty"`
	Status      string            `codec:"status"`
	CreatedAt   int64             `codec:"created_at"`
	UpdatedAt   int64             `codec:"updated_at"`
}

// SDNGetPolicyRequest represents a policy get request
type SDNGetPolicyRequest struct {
	ID string `codec:"id"`
}

// SDNGetPolicyResponse represents a policy get response
type SDNGetPolicyResponse struct {
	Policy    *SDNPolicyInfo `codec:"policy"`
	Timestamp int64          `codec:"timestamp"`
}

// SDNListPoliciesRequest represents a policies list request
type SDNListPoliciesRequest struct {
	Limit int32 `codec:"limit,omitempty"`
}

// SDNListPoliciesResponse represents a policies list response
type SDNListPoliciesResponse struct {
	Policies  []*SDNPolicyInfo `codec:"policies"`
	Count     int32            `codec:"count"`
	Timestamp int64            `codec:"timestamp"`
}

// SDNDeletePolicyRequest represents a policy deletion request
type SDNDeletePolicyRequest struct {
	ID string `codec:"id"`
}

// SDNDeletePolicyResponse represents a policy deletion response
type SDNDeletePolicyResponse struct {
	ID        string `codec:"id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// SDNGetMetricsRequest represents a metrics get request
type SDNGetMetricsRequest struct{}

// SDNMetrics contains SDN metrics
type SDNMetrics struct {
	TotalBridges int   `codec:"total_bridges"`
	TotalPorts   int   `codec:"total_ports"`
	TotalFlows   int   `codec:"total_flows"`
	TotalBytes   int64 `codec:"total_bytes"`
	TotalPackets int64 `codec:"total_packets"`
}

// SDNGetMetricsResponse represents a metrics get response
type SDNGetMetricsResponse struct {
	Metrics   *SDNMetrics `codec:"metrics"`
	Timestamp int64       `codec:"timestamp"`
}

// =============================================================================
// Bridge Handlers
// =============================================================================

// handleCreateBridge creates a new bridge
func (h *SDNHandler) handleCreateBridge(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var createReq SDNCreateBridgeRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if createReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingBridgeName)
	}

	bridge, err := h.sdnService.CreateBridge(ctx, createReq.Name)
	if err != nil {
		h.logger.Error(err, "failed to create bridge")
		return h.sdnErrorResponse(err)
	}

	// Set additional properties if specified
	if createReq.FailMode != "" {
		if err := h.sdnService.SetBridgeFailMode(ctx, createReq.Name, createReq.FailMode); err != nil {
			h.logger.Warnf("failed to set bridge fail mode: %v", err)
		}
	}

	if len(createReq.Protocols) > 0 {
		if err := h.sdnService.SetBridgeProtocols(ctx, createReq.Name, createReq.Protocols); err != nil {
			h.logger.Warnf("failed to set bridge protocols: %v", err)
		}
	}

	resp := &SDNCreateBridgeResponse{
		Bridge:    h.ovsBridgeToInfo(bridge),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDeleteBridge deletes a bridge
func (h *SDNHandler) handleDeleteBridge(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var deleteReq SDNDeleteBridgeRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if deleteReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingBridgeName)
	}

	if err := h.sdnService.DeleteBridge(ctx, deleteReq.Name); err != nil {
		h.logger.Error(err, "failed to delete bridge")
		return h.sdnErrorResponse(err)
	}

	resp := &SDNDeleteBridgeResponse{
		Name:      deleteReq.Name,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetBridge gets a bridge by name
func (h *SDNHandler) handleGetBridge(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var getReq SDNGetBridgeRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if getReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingBridgeName)
	}

	bridge, err := h.sdnService.GetBridge(ctx, getReq.Name)
	if err != nil {
		h.logger.Error(err, "failed to get bridge")
		return h.sdnErrorResponse(err)
	}

	resp := &SDNGetBridgeResponse{
		Bridge:    h.ovsBridgeToInfo(bridge),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListBridges lists all bridges
func (h *SDNHandler) handleListBridges(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var listReq SDNListBridgesRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	bridges, err := h.sdnService.ListBridges(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list bridges")
		return h.sdnErrorResponse(err)
	}

	// Apply limit
	limit := listReq.Limit
	if limit <= 0 {
		limit = sdnDefaultLimit
	} else if limit > sdnMaxLimit {
		limit = sdnMaxLimit
	}

	bridgeInfos := make([]*SDNBridgeInfo, 0, len(bridges))
	for i, b := range bridges {
		if int32(i) >= limit {
			break
		}
		bridgeInfos = append(bridgeInfos, h.ovsBridgeToInfo(b))
	}

	resp := &SDNListBridgesResponse{
		Bridges:   bridgeInfos,
		Count:     int32(len(bridgeInfos)),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Port Handlers
// =============================================================================

// handleCreatePort creates a new port
func (h *SDNHandler) handleCreatePort(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var createReq SDNCreatePortRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if createReq.BridgeName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingBridgeName)
	}

	if createReq.PortName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingPortName)
	}

	port, err := h.sdnService.AddPort(ctx, createReq.BridgeName, createReq.PortName)
	if err != nil {
		h.logger.Error(err, "failed to create port")
		return h.sdnErrorResponse(err)
	}

	// Set VLAN if specified
	if createReq.VLAN > 0 {
		if err := h.sdnService.SetPortVLAN(ctx, createReq.PortName, createReq.VLAN); err != nil {
			h.logger.Warnf("failed to set port VLAN: %v", err)
		}
	}

	// Set trunk VLANs if specified
	if len(createReq.Trunks) > 0 {
		if err := h.sdnService.SetPortTrunks(ctx, createReq.PortName, createReq.Trunks); err != nil {
			h.logger.Warnf("failed to set port trunks: %v", err)
		}
	}

	resp := &SDNCreatePortResponse{
		Port:      h.ovsPortToInfo(port, createReq.BridgeName),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDeletePort deletes a port
func (h *SDNHandler) handleDeletePort(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var deleteReq SDNDeletePortRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if deleteReq.BridgeName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingBridgeName)
	}

	if deleteReq.PortName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingPortName)
	}

	if err := h.sdnService.DeletePort(ctx, deleteReq.BridgeName, deleteReq.PortName); err != nil {
		h.logger.Error(err, "failed to delete port")
		return h.sdnErrorResponse(err)
	}

	resp := &SDNDeletePortResponse{
		PortName:  deleteReq.PortName,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetPort gets a port by name
func (h *SDNHandler) handleGetPort(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var getReq SDNGetPortRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if getReq.PortName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingPortName)
	}

	port, err := h.sdnService.GetPort(ctx, getReq.PortName)
	if err != nil {
		h.logger.Error(err, "failed to get port")
		return h.sdnErrorResponse(err)
	}

	resp := &SDNGetPortResponse{
		Port:      h.ovsPortToInfo(port, ""),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListPorts lists ports on a bridge
func (h *SDNHandler) handleListPorts(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var listReq SDNListPortsRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if listReq.BridgeName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingBridgeName)
	}

	ports, err := h.sdnService.ListPorts(ctx, listReq.BridgeName)
	if err != nil {
		h.logger.Error(err, "failed to list ports")
		return h.sdnErrorResponse(err)
	}

	// Apply limit
	limit := listReq.Limit
	if limit <= 0 {
		limit = sdnDefaultLimit
	} else if limit > sdnMaxLimit {
		limit = sdnMaxLimit
	}

	portInfos := make([]*SDNPortInfo, 0, len(ports))
	for i, p := range ports {
		if int32(i) >= limit {
			break
		}
		portInfos = append(portInfos, h.ovsPortToInfo(p, listReq.BridgeName))
	}

	resp := &SDNListPortsResponse{
		Ports:     portInfos,
		Count:     int32(len(portInfos)),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleSetVLAN sets the VLAN on a port
func (h *SDNHandler) handleSetVLAN(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var setReq SDNSetVLANRequest
	if err := quicwire.DecodePayload(req.Payload, &setReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if setReq.PortName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingPortName)
	}

	if err := h.sdnService.SetPortVLAN(ctx, setReq.PortName, setReq.VLAN); err != nil {
		h.logger.Error(err, "failed to set VLAN")
		return h.sdnErrorResponse(err)
	}

	resp := &SDNSetVLANResponse{
		PortName:  setReq.PortName,
		VLAN:      setReq.VLAN,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetVLAN gets the VLAN configuration on a port
func (h *SDNHandler) handleGetVLAN(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var getReq SDNGetVLANRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if getReq.PortName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingPortName)
	}

	port, err := h.sdnService.GetPort(ctx, getReq.PortName)
	if err != nil {
		h.logger.Error(err, "failed to get port for VLAN")
		return h.sdnErrorResponse(err)
	}

	resp := &SDNGetVLANResponse{
		PortName:  getReq.PortName,
		VLAN:      port.Tag,
		Trunks:    port.Trunks,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Flow Handlers
// =============================================================================

// handleAddFlow adds a flow to a bridge
func (h *SDNHandler) handleAddFlow(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var addReq SDNAddFlowRequest
	if err := quicwire.DecodePayload(req.Payload, &addReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if addReq.BridgeName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingBridgeName)
	}

	flowMod := &ovs.FlowMod{
		Table:       addReq.Table,
		Priority:    addReq.Priority,
		Match:       addReq.Match,
		Actions:     addReq.Actions,
		Cookie:      addReq.Cookie,
		IdleTimeout: addReq.IdleTimeout,
		HardTimeout: addReq.HardTimeout,
	}

	if err := h.sdnService.AddFlow(ctx, addReq.BridgeName, flowMod); err != nil {
		h.logger.Error(err, "failed to add flow")
		return h.sdnErrorResponse(err)
	}

	// Generate a flow ID
	flowID := addReq.Cookie
	if flowID == "" {
		flowID = time.Now().Format("flow-20060102150405.000000000")
	}

	resp := &SDNAddFlowResponse{
		FlowID:    flowID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDeleteFlow deletes a flow from a bridge
func (h *SDNHandler) handleDeleteFlow(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var deleteReq SDNDeleteFlowRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if deleteReq.BridgeName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingBridgeName)
	}

	if err := h.sdnService.DeleteFlow(ctx, deleteReq.BridgeName, deleteReq.Match); err != nil {
		h.logger.Error(err, "failed to delete flow")
		return h.sdnErrorResponse(err)
	}

	resp := &SDNDeleteFlowResponse{
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListFlows lists flows on a bridge
func (h *SDNHandler) handleListFlows(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var listReq SDNListFlowsRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if listReq.BridgeName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingBridgeName)
	}

	flows, err := h.sdnService.ListFlows(ctx, listReq.BridgeName)
	if err != nil {
		h.logger.Error(err, "failed to list flows")
		return h.sdnErrorResponse(err)
	}

	// Apply limit
	limit := listReq.Limit
	if limit <= 0 {
		limit = sdnDefaultLimit
	} else if limit > sdnMaxLimit {
		limit = sdnMaxLimit
	}

	flowInfos := make([]*SDNFlowInfo, 0, len(flows))
	for i, f := range flows {
		if int32(i) >= limit {
			break
		}
		flowInfos = append(flowInfos, h.ovsFlowToInfo(f, listReq.BridgeName))
	}

	resp := &SDNListFlowsResponse{
		Flows:     flowInfos,
		Count:     int32(len(flowInfos)),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Policy Handlers
// =============================================================================

// handleApplyPolicy creates or updates a network policy
func (h *SDNHandler) handleApplyPolicy(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var applyReq SDNApplyPolicyRequest
	if err := quicwire.DecodePayload(req.Payload, &applyReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if applyReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingPolicyName)
	}

	now := time.Now().Unix()

	h.policyMu.Lock()
	// Check if policy already exists
	existingPolicy, exists := h.policies[applyReq.Name]
	if exists {
		// Update existing policy
		existingPolicy.Description = applyReq.Description
		existingPolicy.Priority = applyReq.Priority
		existingPolicy.Rules = applyReq.Rules
		existingPolicy.Labels = applyReq.Labels
		existingPolicy.UpdatedAt = now
	} else {
		// Create new policy
		policyID := time.Now().Format("policy-20060102150405.000000000")
		existingPolicy = &SDNPolicyInfo{
			ID:          policyID,
			Name:        applyReq.Name,
			Description: applyReq.Description,
			Priority:    applyReq.Priority,
			Rules:       applyReq.Rules,
			Labels:      applyReq.Labels,
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		h.policies[policyID] = existingPolicy
	}
	h.policyMu.Unlock()

	resp := &SDNApplyPolicyResponse{
		Policy:    existingPolicy,
		Timestamp: now,
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetPolicy gets a policy by ID
func (h *SDNHandler) handleGetPolicy(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var getReq SDNGetPolicyRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if getReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingPolicyID)
	}

	h.policyMu.RLock()
	policy, exists := h.policies[getReq.ID]
	h.policyMu.RUnlock()

	if !exists {
		return h.errorResponse(quicwire.StatusNotFound, ErrSDNPolicyNotFound)
	}

	resp := &SDNGetPolicyResponse{
		Policy:    policy,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListPolicies lists all policies
func (h *SDNHandler) handleListPolicies(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var listReq SDNListPoliciesRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	// Apply limit
	limit := listReq.Limit
	if limit <= 0 {
		limit = sdnDefaultLimit
	} else if limit > sdnMaxLimit {
		limit = sdnMaxLimit
	}

	h.policyMu.RLock()
	policies := make([]*SDNPolicyInfo, 0, len(h.policies))
	count := int32(0)
	for _, p := range h.policies {
		if count >= limit {
			break
		}
		policies = append(policies, p)
		count++
	}
	h.policyMu.RUnlock()

	resp := &SDNListPoliciesResponse{
		Policies:  policies,
		Count:     int32(len(policies)),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDeletePolicy deletes a policy
func (h *SDNHandler) handleDeletePolicy(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	var deleteReq SDNDeletePolicyRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrSDNDecodingFailed{Cause: err})
	}

	if deleteReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNMissingPolicyID)
	}

	h.policyMu.Lock()
	if _, exists := h.policies[deleteReq.ID]; !exists {
		h.policyMu.Unlock()
		return h.errorResponse(quicwire.StatusNotFound, ErrSDNPolicyNotFound)
	}
	delete(h.policies, deleteReq.ID)
	h.policyMu.Unlock()

	resp := &SDNDeletePolicyResponse{
		ID:        deleteReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Metrics Handler
// =============================================================================

// handleGetMetrics gets SDN metrics
func (h *SDNHandler) handleGetMetrics(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrSDNServiceNotAvailable)
	}

	bridges, err := h.sdnService.ListBridges(ctx)
	if err != nil {
		h.logger.Error(err, "failed to get bridges for metrics")
		return h.sdnErrorResponse(err)
	}

	metrics := &SDNMetrics{
		TotalBridges: len(bridges),
	}

	var totalBytes int64
	var totalPackets int64

	for _, bridge := range bridges {
		metrics.TotalPorts += len(bridge.Ports)

		// Get flows for statistics
		flows, err := h.sdnService.ListFlows(ctx, bridge.Name)
		if err == nil {
			metrics.TotalFlows += len(flows)
			for _, flow := range flows {
				totalBytes += flow.ByteCount
				totalPackets += flow.PacketCount
			}
		}
	}

	metrics.TotalBytes = totalBytes
	metrics.TotalPackets = totalPackets

	resp := &SDNGetMetricsResponse{
		Metrics:   metrics,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrSDNEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Helper Methods
// =============================================================================

// ovsBridgeToInfo converts an OVS Bridge to SDNBridgeInfo
func (h *SDNHandler) ovsBridgeToInfo(bridge *ovs.Bridge) *SDNBridgeInfo {
	if bridge == nil {
		return nil
	}

	status := "up"
	if bridge.Status != nil {
		if s, ok := bridge.Status["state"]; ok {
			status = s
		}
	}

	return &SDNBridgeInfo{
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
		CreatedAt:    time.Now().Unix(),
	}
}

// ovsPortToInfo converts an OVS Port to SDNPortInfo
func (h *SDNHandler) ovsPortToInfo(port *ovs.Port, bridgeName string) *SDNPortInfo {
	if port == nil {
		return nil
	}

	return &SDNPortInfo{
		ID:          port.UUID,
		Name:        port.Name,
		BridgeName:  bridgeName,
		VLAN:        port.Tag,
		Trunks:      port.Trunks,
		MACAddress:  port.MAC,
		Status:      "up",
		ExternalIDs: port.ExternalIDs,
		OtherConfig: port.OtherConfig,
		CreatedAt:   time.Now().Unix(),
	}
}

// ovsFlowToInfo converts an OVS Flow to SDNFlowInfo
func (h *SDNHandler) ovsFlowToInfo(flow *ovs.Flow, bridgeName string) *SDNFlowInfo {
	if flow == nil {
		return nil
	}

	return &SDNFlowInfo{
		ID:          flow.Cookie,
		BridgeName:  bridgeName,
		Table:       flow.Table,
		Priority:    flow.Priority,
		Match:       flow.Match,
		Actions:     flow.Actions,
		Cookie:      flow.Cookie,
		PacketCount: flow.PacketCount,
		ByteCount:   flow.ByteCount,
		Duration:    flow.Duration,
		CreatedAt:   time.Now().Unix(),
	}
}

// errorResponse creates an error response with the given status and error
func (h *SDNHandler) errorResponse(status byte, err error) *quicwire.Response {
	return &quicwire.Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// sdnErrorResponse maps SDN errors to appropriate status codes
func (h *SDNHandler) sdnErrorResponse(err error) *quicwire.Response {
	var status byte

	switch {
	case errors.Is(err, ovs.ErrBridgeNotFound):
		status = quicwire.StatusNotFound
	case errors.Is(err, ovs.ErrBridgeExists):
		status = quicwire.StatusAlreadyExists
	case errors.Is(err, ovs.ErrPortNotFound):
		status = quicwire.StatusNotFound
	case errors.Is(err, ovs.ErrPortExists):
		status = quicwire.StatusAlreadyExists
	case errors.Is(err, ovs.ErrFlowNotFound):
		status = quicwire.StatusNotFound
	case errors.Is(err, ovs.ErrInvalidFlow):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ovs.ErrInvalidBridgeName):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ovs.ErrInvalidPortName):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ovs.ErrNotConnected):
		status = quicwire.StatusUnavailable
	case errors.Is(err, ovs.ErrConnectionFailed):
		status = quicwire.StatusUnavailable
	case errors.Is(err, ovs.ErrOperationTimeout):
		status = quicwire.StatusTimeout
	case errors.Is(err, ovs.ErrTransactionFailed):
		status = quicwire.StatusInternalError
	default:
		status = quicwire.StatusInternalError
	}

	return h.errorResponse(status, err)
}

// =============================================================================
// SDN Error Types
// =============================================================================

// ErrSDNEncodingFailed represents an encoding failure error
type ErrSDNEncodingFailed struct {
	Cause error
}

func (e ErrSDNEncodingFailed) Error() string {
	return "failed to encode SDN payload: " + e.Cause.Error()
}

func (e ErrSDNEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrSDNDecodingFailed represents a decoding failure error
type ErrSDNDecodingFailed struct {
	Cause error
}

func (e ErrSDNDecodingFailed) Error() string {
	return "failed to decode SDN payload: " + e.Cause.Error()
}

func (e ErrSDNDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrSDNOperationFailed represents an SDN operation failure
type ErrSDNOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrSDNOperationFailed) Error() string {
	return "SDN operation " + e.Operation + " failed: " + e.Cause.Error()
}

func (e ErrSDNOperationFailed) Unwrap() error {
	return e.Cause
}
