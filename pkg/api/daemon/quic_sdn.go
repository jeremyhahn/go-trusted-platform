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

package daemon

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SDN request/response types for QUIC protocol

// =============================================================================
// Bridge Operations
// =============================================================================

// SDNCreateBridgeRequest represents a request to create an OVS bridge
type SDNCreateBridgeRequest struct {
	Name string `codec:"name"`
}

// SDNCreateBridgeResponse represents the response after creating a bridge
type SDNCreateBridgeResponse struct {
	Name      string `codec:"name"`
	UUID      string `codec:"uuid"`
	Timestamp int64  `codec:"timestamp"`
}

// SDNDeleteBridgeRequest represents a request to delete an OVS bridge
type SDNDeleteBridgeRequest struct {
	Name string `codec:"name"`
}

// SDNDeleteBridgeResponse represents the response after deleting a bridge
type SDNDeleteBridgeResponse struct {
	Name      string `codec:"name"`
	Deleted   bool   `codec:"deleted"`
	Timestamp int64  `codec:"timestamp"`
}

// SDNGetBridgeRequest represents a request to get a bridge
type SDNGetBridgeRequest struct {
	Name string `codec:"name"`
}

// SDNBridge represents an OVS bridge in QUIC responses
type SDNBridge struct {
	UUID          string            `codec:"uuid"`
	Name          string            `codec:"name"`
	DatapathType  string            `codec:"datapath_type"`
	FailMode      string            `codec:"fail_mode"`
	Ports         []string          `codec:"ports"`
	FlowProtocols []string          `codec:"flow_protocols"`
	STP           bool              `codec:"stp"`
	RSTP          bool              `codec:"rstp"`
	McastSnooping bool              `codec:"mcast_snooping"`
	ExternalIDs   map[string]string `codec:"external_ids"`
	OtherConfig   map[string]string `codec:"other_config"`
	Status        map[string]string `codec:"status"`
}

// SDNGetBridgeResponse represents the response containing a bridge
type SDNGetBridgeResponse struct {
	Bridge    *SDNBridge `codec:"bridge"`
	Timestamp int64      `codec:"timestamp"`
}

// SDNListBridgesRequest represents a request to list all bridges
type SDNListBridgesRequest struct{}

// SDNListBridgesResponse represents the response containing bridges
type SDNListBridgesResponse struct {
	Bridges   []*SDNBridge `codec:"bridges"`
	Total     int          `codec:"total"`
	Timestamp int64        `codec:"timestamp"`
}

// =============================================================================
// Port Operations
// =============================================================================

// SDNCreatePortRequest represents a request to create a port on a bridge
type SDNCreatePortRequest struct {
	BridgeName string `codec:"bridge_name"`
	PortName   string `codec:"port_name"`
}

// SDNCreatePortResponse represents the response after creating a port
type SDNCreatePortResponse struct {
	BridgeName string `codec:"bridge_name"`
	PortName   string `codec:"port_name"`
	UUID       string `codec:"uuid"`
	Timestamp  int64  `codec:"timestamp"`
}

// SDNDeletePortRequest represents a request to delete a port
type SDNDeletePortRequest struct {
	BridgeName string `codec:"bridge_name"`
	PortName   string `codec:"port_name"`
}

// SDNDeletePortResponse represents the response after deleting a port
type SDNDeletePortResponse struct {
	BridgeName string `codec:"bridge_name"`
	PortName   string `codec:"port_name"`
	Deleted    bool   `codec:"deleted"`
	Timestamp  int64  `codec:"timestamp"`
}

// SDNGetPortRequest represents a request to get a port
type SDNGetPortRequest struct {
	PortName string `codec:"port_name"`
}

// SDNPort represents an OVS port in QUIC responses
type SDNPort struct {
	UUID        string            `codec:"uuid"`
	Name        string            `codec:"name"`
	Interfaces  []string          `codec:"interfaces"`
	Tag         int64             `codec:"tag"`
	Trunks      []int64           `codec:"trunks"`
	VLANMode    string            `codec:"vlan_mode"`
	MAC         string            `codec:"mac"`
	ExternalIDs map[string]string `codec:"external_ids"`
	OtherConfig map[string]string `codec:"other_config"`
}

// SDNGetPortResponse represents the response containing a port
type SDNGetPortResponse struct {
	Port      *SDNPort `codec:"port"`
	Timestamp int64    `codec:"timestamp"`
}

// SDNListPortsRequest represents a request to list ports on a bridge
type SDNListPortsRequest struct {
	BridgeName string `codec:"bridge_name"`
}

// SDNListPortsResponse represents the response containing ports
type SDNListPortsResponse struct {
	Ports     []*SDNPort `codec:"ports"`
	Total     int        `codec:"total"`
	Timestamp int64      `codec:"timestamp"`
}

// SDNGetPortStateRequest represents a request to get port state
type SDNGetPortStateRequest struct {
	PortName string `codec:"port_name"`
}

// SDNGetPortStateResponse represents the response containing port state
type SDNGetPortStateResponse struct {
	PortName  string `codec:"port_name"`
	State     string `codec:"state"`
	Timestamp int64  `codec:"timestamp"`
}

// SDNSetPortStateRequest represents a request to set port state
type SDNSetPortStateRequest struct {
	PortName string `codec:"port_name"`
	State    string `codec:"state"`
}

// SDNSetPortStateResponse represents the response after setting port state
type SDNSetPortStateResponse struct {
	PortName  string `codec:"port_name"`
	State     string `codec:"state"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// VLAN Operations
// =============================================================================

// SDNSetVLANRequest represents a request to set VLAN on a port
type SDNSetVLANRequest struct {
	PortName string `codec:"port_name"`
	VLAN     uint16 `codec:"vlan"`
}

// SDNSetVLANResponse represents the response after setting VLAN
type SDNSetVLANResponse struct {
	PortName  string `codec:"port_name"`
	VLAN      uint16 `codec:"vlan"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// SDNGetVLANRequest represents a request to get VLAN for a port
type SDNGetVLANRequest struct {
	PortName string `codec:"port_name"`
}

// SDNGetVLANResponse represents the response containing VLAN info
type SDNGetVLANResponse struct {
	PortName  string `codec:"port_name"`
	VLAN      uint16 `codec:"vlan"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// Flow Operations
// =============================================================================

// SDNAddFlowRequest represents a request to add a flow
type SDNAddFlowRequest struct {
	BridgeName  string `codec:"bridge_name"`
	Table       int    `codec:"table"`
	Priority    int    `codec:"priority"`
	Match       string `codec:"match"`
	Actions     string `codec:"actions"`
	Cookie      string `codec:"cookie"`
	IdleTimeout int    `codec:"idle_timeout"`
	HardTimeout int    `codec:"hard_timeout"`
}

// SDNAddFlowResponse represents the response after adding a flow
type SDNAddFlowResponse struct {
	BridgeName string `codec:"bridge_name"`
	Success    bool   `codec:"success"`
	Timestamp  int64  `codec:"timestamp"`
}

// SDNDeleteFlowRequest represents a request to delete a flow
type SDNDeleteFlowRequest struct {
	BridgeName string `codec:"bridge_name"`
	Match      string `codec:"match"`
}

// SDNDeleteFlowResponse represents the response after deleting a flow
type SDNDeleteFlowResponse struct {
	BridgeName string `codec:"bridge_name"`
	Success    bool   `codec:"success"`
	Timestamp  int64  `codec:"timestamp"`
}

// SDNGetFlowRequest represents a request to get flow stats
type SDNGetFlowRequest struct {
	BridgeName string `codec:"bridge_name"`
	Match      string `codec:"match"`
}

// SDNFlow represents an OpenFlow rule in QUIC responses
type SDNFlow struct {
	Table       int    `codec:"table"`
	Priority    int    `codec:"priority"`
	Match       string `codec:"match"`
	Actions     string `codec:"actions"`
	Cookie      string `codec:"cookie"`
	Duration    int    `codec:"duration"`
	IdleAge     int    `codec:"idle_age"`
	HardAge     int    `codec:"hard_age"`
	PacketCount int64  `codec:"packet_count"`
	ByteCount   int64  `codec:"byte_count"`
}

// SDNGetFlowResponse represents the response containing flows
type SDNGetFlowResponse struct {
	Flows     []*SDNFlow `codec:"flows"`
	Total     int        `codec:"total"`
	Timestamp int64      `codec:"timestamp"`
}

// SDNListFlowsRequest represents a request to list all flows
type SDNListFlowsRequest struct {
	BridgeName string `codec:"bridge_name"`
}

// SDNListFlowsResponse represents the response containing all flows
type SDNListFlowsResponse struct {
	Flows     []*SDNFlow `codec:"flows"`
	Total     int        `codec:"total"`
	Timestamp int64      `codec:"timestamp"`
}

// =============================================================================
// Policy Operations
// =============================================================================

// SDNApplyPolicyRequest represents a request to apply a policy
type SDNApplyPolicyRequest struct {
	PortID   string            `codec:"port_id"`
	TenantID string            `codec:"tenant_id"`
	VLAN     uint16            `codec:"vlan"`
	ACLs     []*SDNACLRule     `codec:"acls"`
	Metadata map[string]string `codec:"metadata"`
}

// SDNACLRule represents an ACL rule for QUIC protocol
type SDNACLRule struct {
	Priority    int           `codec:"priority"`
	Match       *SDNFlowMatch `codec:"match"`
	Action      string        `codec:"action"`
	Description string        `codec:"description"`
}

// SDNFlowMatch represents flow match criteria
type SDNFlowMatch struct {
	InPort  string `codec:"in_port"`
	EthSrc  string `codec:"eth_src"`
	EthDst  string `codec:"eth_dst"`
	EthType uint16 `codec:"eth_type"`
	VLANVid uint16 `codec:"vlan_vid"`
	IPProto uint8  `codec:"ip_proto"`
	IPv4Src string `codec:"ipv4_src"`
	IPv4Dst string `codec:"ipv4_dst"`
	TCPSrc  uint16 `codec:"tcp_src"`
	TCPDst  uint16 `codec:"tcp_dst"`
	UDPSrc  uint16 `codec:"udp_src"`
	UDPDst  uint16 `codec:"udp_dst"`
}

// SDNApplyPolicyResponse represents the response after applying a policy
type SDNApplyPolicyResponse struct {
	PortID    string `codec:"port_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// SDNDeletePolicyRequest represents a request to delete/remove a policy
type SDNDeletePolicyRequest struct {
	PortID string `codec:"port_id"`
}

// SDNDeletePolicyResponse represents the response after removing a policy
type SDNDeletePolicyResponse struct {
	PortID    string `codec:"port_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// SDNGetPolicyRequest represents a request to get a policy
type SDNGetPolicyRequest struct {
	PortID string `codec:"port_id"`
}

// SDNPolicy represents a policy in QUIC responses
type SDNPolicy struct {
	PortID    string            `codec:"port_id"`
	TenantID  string            `codec:"tenant_id"`
	VLAN      uint16            `codec:"vlan"`
	ACLs      []*SDNACLRule     `codec:"acls"`
	ExpiresAt int64             `codec:"expires_at"`
	IssuedAt  int64             `codec:"issued_at"`
	Metadata  map[string]string `codec:"metadata"`
}

// SDNGetPolicyResponse represents the response containing a policy
type SDNGetPolicyResponse struct {
	Policy    *SDNPolicy `codec:"policy"`
	Timestamp int64      `codec:"timestamp"`
}

// SDNListPoliciesRequest represents a request to list policies
type SDNListPoliciesRequest struct{}

// SDNListPoliciesResponse represents the response containing policies
type SDNListPoliciesResponse struct {
	Policies  []*SDNPolicy `codec:"policies"`
	Total     int          `codec:"total"`
	Timestamp int64        `codec:"timestamp"`
}

// =============================================================================
// Metrics
// =============================================================================

// SDNGetMetricsRequest represents a request to get SDN metrics
type SDNGetMetricsRequest struct {
	BridgeName string `codec:"bridge_name"`
}

// SDNMetrics represents SDN metrics
type SDNMetrics struct {
	BridgeCount     int   `codec:"bridge_count"`
	PortCount       int   `codec:"port_count"`
	FlowCount       int   `codec:"flow_count"`
	PolicyCount     int   `codec:"policy_count"`
	TotalPackets    int64 `codec:"total_packets"`
	TotalBytes      int64 `codec:"total_bytes"`
	ActivePorts     int   `codec:"active_ports"`
	BlockedPorts    int   `codec:"blocked_ports"`
	AuthorizedPorts int   `codec:"authorized_ports"`
	Timestamp       int64 `codec:"timestamp"`
}

// SDNGetMetricsResponse represents the response containing SDN metrics
type SDNGetMetricsResponse struct {
	Metrics   *SDNMetrics `codec:"metrics"`
	Timestamp int64       `codec:"timestamp"`
}

// =============================================================================
// Handler Implementation
// =============================================================================

// handleSDNOperation routes SDN operations to their handlers
func (h *QUICServiceHandler) handleSDNOperation(ctx context.Context, req *quic.Request) *quic.Response {
	if h.sdnService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "sdn"})
	}

	switch req.Opcode {
	// Bridge operations
	case quic.OpSDNCreateBridge:
		return h.handleSDNCreateBridge(ctx, req)
	case quic.OpSDNDeleteBridge:
		return h.handleSDNDeleteBridge(ctx, req)
	case quic.OpSDNGetBridge:
		return h.handleSDNGetBridge(ctx, req)
	case quic.OpSDNListBridges:
		return h.handleSDNListBridges(ctx, req)

	// Port operations
	case quic.OpSDNCreatePort:
		return h.handleSDNCreatePort(ctx, req)
	case quic.OpSDNDeletePort:
		return h.handleSDNDeletePort(ctx, req)
	case quic.OpSDNGetPort:
		return h.handleSDNGetPort(ctx, req)
	case quic.OpSDNListPorts:
		return h.handleSDNListPorts(ctx, req)
	case quic.OpSDNGetPortState:
		return h.handleSDNGetPortState(ctx, req)
	case quic.OpSDNSetPortState:
		return h.handleSDNSetPortState(ctx, req)

	// VLAN operations
	case quic.OpSDNSetVLAN:
		return h.handleSDNSetVLAN(ctx, req)
	case quic.OpSDNGetVLAN:
		return h.handleSDNGetVLAN(ctx, req)

	// Flow operations
	case quic.OpSDNAddFlow:
		return h.handleSDNAddFlow(ctx, req)
	case quic.OpSDNDeleteFlow:
		return h.handleSDNDeleteFlow(ctx, req)
	case quic.OpSDNGetFlow:
		return h.handleSDNGetFlow(ctx, req)
	case quic.OpSDNListFlows:
		return h.handleSDNListFlows(ctx, req)

	// Policy operations
	case quic.OpSDNApplyPolicy:
		return h.handleSDNApplyPolicy(ctx, req)
	case quic.OpSDNDeletePolicy:
		return h.handleSDNDeletePolicy(ctx, req)
	case quic.OpSDNGetPolicy:
		return h.handleSDNGetPolicy(ctx, req)
	case quic.OpSDNListPolicies:
		return h.handleSDNListPolicies(ctx, req)

	// Metrics
	case quic.OpSDNGetMetrics:
		return h.handleSDNGetMetrics(ctx, req)

	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// =============================================================================
// Bridge Handlers
// =============================================================================

func (h *QUICServiceHandler) handleSDNCreateBridge(ctx context.Context, req *quic.Request) *quic.Response {
	var createReq SDNCreateBridgeRequest
	if err := quic.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if createReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	pbResp, err := h.sdnService.CreateBridge(ctx, &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{
			Name: createReq.Name,
		},
	})
	if err != nil {
		h.logger.Error(err, "failed to create SDN bridge", "name", createReq.Name)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNCreateBridge", Cause: err})
	}

	bridgeID := ""
	bridgeName := createReq.Name
	if pbResp.GetBridge() != nil {
		bridgeID = pbResp.GetBridge().GetId()
		if pbResp.GetBridge().GetConfig() != nil {
			bridgeName = pbResp.GetBridge().GetConfig().GetName()
		}
	}

	resp := &SDNCreateBridgeResponse{
		Name:      bridgeName,
		UUID:      bridgeID,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("created SDN bridge", "name", bridgeName, "uuid", bridgeID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNDeleteBridge(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq SDNDeleteBridgeRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	_, err := h.sdnService.DeleteBridge(ctx, &platformv1.DeleteBridgeRequest{
		Id: deleteReq.Name,
	})
	if err != nil {
		h.logger.Error(err, "failed to delete SDN bridge", "name", deleteReq.Name)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNDeleteBridge", Cause: err})
	}

	resp := &SDNDeleteBridgeResponse{
		Name:      deleteReq.Name,
		Deleted:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("deleted SDN bridge", "name", deleteReq.Name)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNGetBridge(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq SDNGetBridgeRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	pbResp, err := h.sdnService.GetBridge(ctx, &platformv1.GetBridgeRequest{
		Id: getReq.Name,
	})
	if err != nil {
		h.logger.Error(err, "failed to get SDN bridge", "name", getReq.Name)
		return h.errorResponse(quic.StatusNotFound, ErrSDNBridgeNotFound{BridgeName: getReq.Name})
	}

	resp := &SDNGetBridgeResponse{
		Bridge:    convertPbBridgeToSDNBridge(pbResp.GetBridge()),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNListBridges(ctx context.Context, req *quic.Request) *quic.Response {
	pbResp, err := h.sdnService.ListBridges(ctx, &platformv1.ListBridgesRequest{})
	if err != nil {
		h.logger.Error(err, "failed to list SDN bridges")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNListBridges", Cause: err})
	}

	sdnBridges := make([]*SDNBridge, 0, len(pbResp.GetBridges()))
	for _, bridge := range pbResp.GetBridges() {
		sdnBridges = append(sdnBridges, convertPbBridgeToSDNBridge(bridge))
	}

	resp := &SDNListBridgesResponse{
		Bridges:   sdnBridges,
		Total:     len(sdnBridges),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Port Handlers
// =============================================================================

func (h *QUICServiceHandler) handleSDNCreatePort(ctx context.Context, req *quic.Request) *quic.Response {
	var createReq SDNCreatePortRequest
	if err := quic.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if createReq.BridgeName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_name"})
	}
	if createReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	pbResp, err := h.sdnService.AddPort(ctx, &platformv1.AddPortRequest{
		BridgeId: createReq.BridgeName,
		Config: &platformv1.PortConfig{
			Name: createReq.PortName,
		},
	})
	if err != nil {
		h.logger.Error(err, "failed to create SDN port",
			"bridge", createReq.BridgeName,
			"port", createReq.PortName)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNCreatePort", Cause: err})
	}

	portUUID := ""
	portName := createReq.PortName
	if pbResp.GetPort() != nil {
		portUUID = pbResp.GetPort().GetId()
		if pbResp.GetPort().GetConfig() != nil {
			portName = pbResp.GetPort().GetConfig().GetName()
		}
	}

	resp := &SDNCreatePortResponse{
		BridgeName: createReq.BridgeName,
		PortName:   portName,
		UUID:       portUUID,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("created SDN port",
		"bridge", createReq.BridgeName,
		"port", portName,
		"uuid", portUUID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNDeletePort(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq SDNDeletePortRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.BridgeName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_name"})
	}
	if deleteReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	_, err := h.sdnService.DeletePort(ctx, &platformv1.DeletePortRequest{
		BridgeId: deleteReq.BridgeName,
		PortId:   deleteReq.PortName,
	})
	if err != nil {
		h.logger.Error(err, "failed to delete SDN port",
			"bridge", deleteReq.BridgeName,
			"port", deleteReq.PortName)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNDeletePort", Cause: err})
	}

	resp := &SDNDeletePortResponse{
		BridgeName: deleteReq.BridgeName,
		PortName:   deleteReq.PortName,
		Deleted:    true,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("deleted SDN port",
		"bridge", deleteReq.BridgeName,
		"port", deleteReq.PortName)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNGetPort(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq SDNGetPortRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	// Look up the bridge associated with this port
	bridgeID, found := h.sdnService.FindPortBridge(getReq.PortName)
	if !found {
		return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.PortName})
	}

	pbResp, err := h.sdnService.GetPort(ctx, &platformv1.GetPortRequest{
		BridgeId: bridgeID,
		PortId:   getReq.PortName,
	})
	if err != nil {
		h.logger.Error(err, "failed to get SDN port", "port", getReq.PortName)
		return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.PortName})
	}

	resp := &SDNGetPortResponse{
		Port:      convertPbPortToSDNPort(pbResp.GetPort()),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNListPorts(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq SDNListPortsRequest
	if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if listReq.BridgeName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_name"})
	}

	pbResp, err := h.sdnService.ListPorts(ctx, &platformv1.ListPortsRequest{
		BridgeId: listReq.BridgeName,
	})
	if err != nil {
		h.logger.Error(err, "failed to list SDN ports", "bridge", listReq.BridgeName)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNListPorts", Cause: err})
	}

	sdnPorts := make([]*SDNPort, 0, len(pbResp.GetPorts()))
	for _, port := range pbResp.GetPorts() {
		sdnPorts = append(sdnPorts, convertPbPortToSDNPort(port))
	}

	resp := &SDNListPortsResponse{
		Ports:     sdnPorts,
		Total:     len(sdnPorts),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNGetPortState(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq SDNGetPortStateRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	// Look up the bridge associated with this port
	bridgeID, found := h.sdnService.FindPortBridge(getReq.PortName)
	if !found {
		return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.PortName})
	}

	// Use GetPort via the service layer to determine port state
	pbResp, err := h.sdnService.GetPort(ctx, &platformv1.GetPortRequest{
		BridgeId: bridgeID,
		PortId:   getReq.PortName,
	})
	if err != nil {
		h.logger.Error(err, "failed to get SDN port state", "port", getReq.PortName)
		return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.PortName})
	}

	state := "unknown"
	if pbResp.GetPort() != nil {
		switch pbResp.GetPort().GetStatus() {
		case platformv1.PortStatus_PORT_STATUS_UP:
			state = "up"
		case platformv1.PortStatus_PORT_STATUS_DOWN:
			state = "down"
		case platformv1.PortStatus_PORT_STATUS_BLOCKED:
			state = "blocked"
		}
	}

	resp := &SDNGetPortStateResponse{
		PortName:  getReq.PortName,
		State:     state,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNSetPortState(ctx context.Context, req *quic.Request) *quic.Response {
	var setReq SDNSetPortStateRequest
	if err := quic.DecodePayload(req.Payload, &setReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if setReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}
	if setReq.State == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "state"})
	}

	// Look up the bridge associated with this port
	bridgeID, found := h.sdnService.FindPortBridge(setReq.PortName)
	if !found {
		return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: setReq.PortName})
	}

	_, err := h.sdnService.SetPortState(ctx, &platformv1.SetPortStateRequest{
		BridgeId:   bridgeID,
		PortId:     setReq.PortName,
		AdminState: setReq.State,
	})
	if err != nil {
		h.logger.Error(err, "failed to set SDN port state",
			"port", setReq.PortName,
			"state", setReq.State)
		return h.errorResponse(quic.StatusInternalError, ErrSDNSetPortStateFailed{PortID: setReq.PortName, Cause: err})
	}

	resp := &SDNSetPortStateResponse{
		PortName:  setReq.PortName,
		State:     setReq.State,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("set SDN port state",
		"port", setReq.PortName,
		"state", setReq.State)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// VLAN Handlers
// =============================================================================

func (h *QUICServiceHandler) handleSDNSetVLAN(ctx context.Context, req *quic.Request) *quic.Response {
	var setReq SDNSetVLANRequest
	if err := quic.DecodePayload(req.Payload, &setReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if setReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	// Look up the bridge associated with this port
	bridgeID, found := h.sdnService.FindPortBridge(setReq.PortName)
	if !found {
		return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: setReq.PortName})
	}

	// Use CreateVLAN service method to set VLAN on the port
	_, err := h.sdnService.CreateVLAN(ctx, &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			VlanId:   uint32(setReq.VLAN),
			BridgeId: bridgeID,
			Ports:    []string{setReq.PortName},
		},
	})
	if err != nil {
		h.logger.Error(err, "failed to set VLAN",
			"port", setReq.PortName,
			"vlan", setReq.VLAN)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNSetVLAN", Cause: err})
	}

	resp := &SDNSetVLANResponse{
		PortName:  setReq.PortName,
		VLAN:      setReq.VLAN,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("set VLAN",
		"port", setReq.PortName,
		"vlan", setReq.VLAN)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNGetVLAN(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq SDNGetVLANRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	// Look up the bridge associated with this port
	bridgeID, found := h.sdnService.FindPortBridge(getReq.PortName)
	if !found {
		return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.PortName})
	}

	// Use GetPort via the service layer to retrieve VLAN tag
	pbResp, err := h.sdnService.GetPort(ctx, &platformv1.GetPortRequest{
		BridgeId: bridgeID,
		PortId:   getReq.PortName,
	})
	if err != nil {
		h.logger.Error(err, "failed to get VLAN", "port", getReq.PortName)
		return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.PortName})
	}

	var vlan uint16
	if pbResp.GetPort() != nil && pbResp.GetPort().GetConfig() != nil {
		vlan = uint16(pbResp.GetPort().GetConfig().GetVlan())
	}

	resp := &SDNGetVLANResponse{
		PortName:  getReq.PortName,
		VLAN:      vlan,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Flow Handlers
// =============================================================================

func (h *QUICServiceHandler) handleSDNAddFlow(ctx context.Context, req *quic.Request) *quic.Response {
	var addReq SDNAddFlowRequest
	if err := quic.DecodePayload(req.Payload, &addReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if addReq.BridgeName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_name"})
	}

	_, err := h.sdnService.AddFlow(ctx, &platformv1.AddFlowRequest{
		Config: &platformv1.FlowConfig{
			BridgeId: addReq.BridgeName,
			Priority: uint32(addReq.Priority),
			Table:    platformv1.FlowTable(addReq.Table),
			Match: &platformv1.FlowMatch{
				InPort: addReq.Match,
			},
			Actions: []*platformv1.FlowAction{
				{
					Type: platformv1.FlowActionType_FLOW_ACTION_UNSPECIFIED,
					Port: addReq.Actions,
				},
			},
			IdleTimeout: uint32(addReq.IdleTimeout),
			HardTimeout: uint32(addReq.HardTimeout),
		},
	})
	if err != nil {
		h.logger.Error(err, "failed to add flow",
			"bridge", addReq.BridgeName,
			"match", addReq.Match)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNAddFlow", Cause: err})
	}

	resp := &SDNAddFlowResponse{
		BridgeName: addReq.BridgeName,
		Success:    true,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("added flow",
		"bridge", addReq.BridgeName,
		"priority", addReq.Priority)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNDeleteFlow(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq SDNDeleteFlowRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.BridgeName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_name"})
	}

	_, err := h.sdnService.DeleteFlow(ctx, &platformv1.DeleteFlowRequest{
		BridgeId: deleteReq.BridgeName,
		FlowId:   deleteReq.Match,
	})
	if err != nil {
		h.logger.Error(err, "failed to delete flow",
			"bridge", deleteReq.BridgeName,
			"match", deleteReq.Match)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNDeleteFlow", Cause: err})
	}

	resp := &SDNDeleteFlowResponse{
		BridgeName: deleteReq.BridgeName,
		Success:    true,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("deleted flow",
		"bridge", deleteReq.BridgeName,
		"match", deleteReq.Match)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNGetFlow(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq SDNGetFlowRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.BridgeName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_name"})
	}

	pbResp, err := h.sdnService.GetFlowStats(ctx, &platformv1.GetFlowStatsRequest{
		BridgeId: getReq.BridgeName,
		FlowId:   getReq.Match,
	})
	if err != nil {
		h.logger.Error(err, "failed to get flow stats",
			"bridge", getReq.BridgeName,
			"match", getReq.Match)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNGetFlow", Cause: err})
	}

	// Convert flow stats to SDN flow format
	sdnFlows := make([]*SDNFlow, 0, 1)
	if pbResp.GetStats() != nil {
		sdnFlows = append(sdnFlows, &SDNFlow{
			Match:       getReq.Match,
			PacketCount: int64(pbResp.GetStats().GetPacketCount()),
			ByteCount:   int64(pbResp.GetStats().GetByteCount()),
			Duration:    int(pbResp.GetStats().GetDurationSeconds()),
		})
	}

	resp := &SDNGetFlowResponse{
		Flows:     sdnFlows,
		Total:     len(sdnFlows),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNListFlows(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq SDNListFlowsRequest
	if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if listReq.BridgeName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_name"})
	}

	pbResp, err := h.sdnService.ListFlows(ctx, &platformv1.ListFlowsRequest{
		BridgeId: listReq.BridgeName,
	})
	if err != nil {
		h.logger.Error(err, "failed to list flows", "bridge", listReq.BridgeName)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNListFlows", Cause: err})
	}

	sdnFlows := make([]*SDNFlow, 0, len(pbResp.GetFlows()))
	for _, flow := range pbResp.GetFlows() {
		sdnFlows = append(sdnFlows, convertPbFlowToSDNFlow(flow))
	}

	resp := &SDNListFlowsResponse{
		Flows:     sdnFlows,
		Total:     len(sdnFlows),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Policy Handlers
// =============================================================================

func (h *QUICServiceHandler) handleSDNApplyPolicy(ctx context.Context, req *quic.Request) *quic.Response {
	var applyReq SDNApplyPolicyRequest
	if err := quic.DecodePayload(req.Payload, &applyReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if applyReq.PortID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_id"})
	}
	if applyReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	// Convert QUIC ACL rules to protobuf policy rules
	rules := convertSDNACLsToPbRules(applyReq.ACLs)

	pbResp, err := h.sdnService.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		Config: &platformv1.PolicyConfig{
			Name:    applyReq.PortID,
			Type:    platformv1.PolicyType_POLICY_TYPE_ACL,
			Enabled: true,
			Rules:   rules,
		},
	})
	if err != nil {
		h.logger.Error(err, "failed to apply policy",
			"port_id", applyReq.PortID,
			"tenant_id", applyReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrSDNApplyPolicyFailed{PolicyID: applyReq.PortID, Cause: err})
	}

	success := pbResp.GetStatus() != nil && pbResp.GetStatus().GetSuccess()

	resp := &SDNApplyPolicyResponse{
		PortID:    applyReq.PortID,
		Success:   success,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("applied policy",
		"port_id", applyReq.PortID,
		"tenant_id", applyReq.TenantID,
		"vlan", applyReq.VLAN)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNDeletePolicy(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq SDNDeletePolicyRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.PortID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_id"})
	}

	_, err := h.sdnService.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{
		PolicyId: deleteReq.PortID,
	})
	if err != nil {
		h.logger.Error(err, "failed to remove policy", "port_id", deleteReq.PortID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNDeletePolicy", Cause: err})
	}

	resp := &SDNDeletePolicyResponse{
		PortID:    deleteReq.PortID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("removed policy", "port_id", deleteReq.PortID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNGetPolicy(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq SDNGetPolicyRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.PortID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_id"})
	}

	pbResp, err := h.sdnService.GetPolicy(ctx, &platformv1.GetPolicyRequest{
		PolicyId: getReq.PortID,
	})
	if err != nil {
		h.logger.Error(err, "failed to get policy", "port_id", getReq.PortID)
		return h.errorResponse(quic.StatusNotFound, ErrSDNPolicyNotFound{PolicyID: getReq.PortID})
	}

	resp := &SDNGetPolicyResponse{
		Policy:    convertPbPolicyToSDNPolicy(getReq.PortID, pbResp.GetPolicy()),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleSDNListPolicies(ctx context.Context, req *quic.Request) *quic.Response {
	pbResp, err := h.sdnService.ListPolicies(ctx, &platformv1.ListPoliciesRequest{})
	if err != nil {
		h.logger.Error(err, "failed to list policies")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNListPolicies", Cause: err})
	}

	policies := make([]*SDNPolicy, 0, len(pbResp.GetPolicies()))
	for _, p := range pbResp.GetPolicies() {
		policies = append(policies, convertPbPolicyToSDNPolicy(p.GetId(), p))
	}

	resp := &SDNListPoliciesResponse{
		Policies:  policies,
		Total:     len(policies),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Metrics Handler
// =============================================================================

func (h *QUICServiceHandler) handleSDNGetMetrics(ctx context.Context, req *quic.Request) *quic.Response {
	var metricsReq SDNGetMetricsRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &metricsReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	metrics := &SDNMetrics{
		Timestamp: time.Now().Unix(),
	}

	// Get bridge count via the service layer
	bridgesResp, err := h.sdnService.ListBridges(ctx, &platformv1.ListBridgesRequest{})
	if err == nil {
		metrics.BridgeCount = len(bridgesResp.GetBridges())
	}

	// Get flow count and stats for specific bridge or all bridges
	if metricsReq.BridgeName != "" {
		flowsResp, flowErr := h.sdnService.ListFlows(ctx, &platformv1.ListFlowsRequest{
			BridgeId: metricsReq.BridgeName,
		})
		if flowErr == nil {
			metrics.FlowCount = len(flowsResp.GetFlows())
		}

		portsResp, portErr := h.sdnService.ListPorts(ctx, &platformv1.ListPortsRequest{
			BridgeId: metricsReq.BridgeName,
		})
		if portErr == nil {
			metrics.PortCount = len(portsResp.GetPorts())
		}
	} else if bridgesResp != nil {
		// Aggregate across all bridges
		for _, bridge := range bridgesResp.GetBridges() {
			bridgeID := bridge.GetId()
			if bridgeID == "" && bridge.GetConfig() != nil {
				bridgeID = bridge.GetConfig().GetName()
			}

			flowsResp, flowErr := h.sdnService.ListFlows(ctx, &platformv1.ListFlowsRequest{
				BridgeId: bridgeID,
			})
			if flowErr == nil {
				metrics.FlowCount += len(flowsResp.GetFlows())
			}

			portsResp, portErr := h.sdnService.ListPorts(ctx, &platformv1.ListPortsRequest{
				BridgeId: bridgeID,
			})
			if portErr == nil {
				metrics.PortCount += len(portsResp.GetPorts())
			}
		}
	}

	// Get policy count via the service layer
	policiesResp, policyErr := h.sdnService.ListPolicies(ctx, &platformv1.ListPoliciesRequest{})
	if policyErr == nil {
		metrics.PolicyCount = len(policiesResp.GetPolicies())
	}

	resp := &SDNGetMetricsResponse{
		Metrics:   metrics,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Conversion Helpers (protobuf to QUIC types)
// =============================================================================

// convertPbBridgeToSDNBridge converts a protobuf Bridge to the QUIC SDNBridge type.
func convertPbBridgeToSDNBridge(b *platformv1.Bridge) *SDNBridge {
	if b == nil {
		return nil
	}

	sdnBridge := &SDNBridge{
		UUID: b.GetId(),
	}

	if config := b.GetConfig(); config != nil {
		sdnBridge.Name = config.GetName()
		sdnBridge.STP = config.GetStpEnabled()
		sdnBridge.ExternalIDs = config.GetLabels()
		sdnBridge.OtherConfig = config.GetOptions()
	}

	return sdnBridge
}

// convertPbPortToSDNPort converts a protobuf Port to the QUIC SDNPort type.
func convertPbPortToSDNPort(p *platformv1.Port) *SDNPort {
	if p == nil {
		return nil
	}

	sdnPort := &SDNPort{
		UUID: p.GetId(),
	}

	if config := p.GetConfig(); config != nil {
		sdnPort.Name = config.GetName()
		sdnPort.Tag = int64(config.GetVlan())
		sdnPort.ExternalIDs = config.GetLabels()
	}

	return sdnPort
}

// convertPbFlowToSDNFlow converts a protobuf Flow to the QUIC SDNFlow type.
func convertPbFlowToSDNFlow(f *platformv1.Flow) *SDNFlow {
	if f == nil {
		return nil
	}

	sdnFlow := &SDNFlow{
		Cookie: f.GetId(),
	}

	if config := f.GetConfig(); config != nil {
		sdnFlow.Table = int(config.GetTable())
		sdnFlow.Priority = int(config.GetPriority())
	}

	return sdnFlow
}

// convertPbPolicyToSDNPolicy converts a protobuf Policy to the QUIC SDNPolicy type.
func convertPbPolicyToSDNPolicy(portID string, p *platformv1.Policy) *SDNPolicy {
	if p == nil {
		return nil
	}

	sdnPolicy := &SDNPolicy{
		PortID: portID,
	}

	if p.GetCreatedAt() != nil {
		sdnPolicy.IssuedAt = p.GetCreatedAt().GetSeconds()
	}

	if config := p.GetConfig(); config != nil {
		sdnPolicy.ACLs = convertPbRulesToSDNACLs(config.GetRules())
	}

	return sdnPolicy
}

// convertSDNACLsToPbRules converts QUIC SDNACLRule slice to protobuf PolicyRule slice.
func convertSDNACLsToPbRules(acls []*SDNACLRule) []*platformv1.PolicyRule {
	if len(acls) == 0 {
		return nil
	}

	rules := make([]*platformv1.PolicyRule, 0, len(acls))
	for _, acl := range acls {
		rule := &platformv1.PolicyRule{
			Priority: int32(acl.Priority),
		}

		// Map action string to protobuf enum
		switch acl.Action {
		case "allow":
			rule.Action = platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW
		case "deny":
			rule.Action = platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY
		default:
			rule.Action = platformv1.PolicyRuleAction_POLICY_RULE_ACTION_UNSPECIFIED
		}

		// Convert match criteria
		if acl.Match != nil {
			rule.Match = &platformv1.PolicyRuleMatch{
				SourceIp:      acl.Match.IPv4Src,
				DestinationIp: acl.Match.IPv4Dst,
			}
			if acl.Match.TCPDst > 0 {
				rule.Match.DestinationPort = uint32(acl.Match.TCPDst)
			}
			if acl.Match.TCPSrc > 0 {
				rule.Match.SourcePort = uint32(acl.Match.TCPSrc)
			}
			if acl.Match.VLANVid > 0 {
				rule.Match.VlanId = uint32(acl.Match.VLANVid)
			}
		}

		rules = append(rules, rule)
	}

	return rules
}

// convertPbRulesToSDNACLs converts protobuf PolicyRule slice to QUIC SDNACLRule slice.
func convertPbRulesToSDNACLs(rules []*platformv1.PolicyRule) []*SDNACLRule {
	if len(rules) == 0 {
		return nil
	}

	acls := make([]*SDNACLRule, 0, len(rules))
	for _, rule := range rules {
		acl := &SDNACLRule{
			Priority: int(rule.GetPriority()),
		}

		// Map protobuf action to string
		switch rule.GetAction() {
		case platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW:
			acl.Action = "allow"
		case platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY:
			acl.Action = "deny"
		default:
			acl.Action = "unspecified"
		}

		// Convert match criteria
		if match := rule.GetMatch(); match != nil {
			acl.Match = &SDNFlowMatch{
				IPv4Src: match.GetSourceIp(),
				IPv4Dst: match.GetDestinationIp(),
				TCPSrc:  uint16(match.GetSourcePort()),
				TCPDst:  uint16(match.GetDestinationPort()),
				VLANVid: uint16(match.GetVlanId()),
			}
		}

		acls = append(acls, acl)
	}

	return acls
}
