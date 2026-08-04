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

// =============================================================================
// SDN QUIC wire contract
// =============================================================================
//
// The canonical QUIC wire contract for the SDN surface is the platform.v1
// protobuf request/response messages themselves. The SDK QUIC transport
// adapter (sdk/go/transport/quic) hands the generated platform.v1 request
// struct straight to the wire (the msgpack payload codec keys on exact Go
// field names), so the daemon MUST decode the payload into the SAME
// platform.v1 message the SDK sent and encode the platform.v1 response the
// SDK expects. Decoding into a flat local struct whose Go field names differ
// from the pb Go field names silently drops every field (e.g. the SDK sends
// CreateBridgeRequest{Config:{Name}} but a flat {Name} decode leaves Name
// empty). Each of the twelve SDK-mapped operations below therefore decodes /
// encodes the pb message and delegates to the shared *SDNService (the same
// business path the gRPC transport uses).
//
// The operations that the SDK QUIC adapter does NOT map — port-state read
// (OpSDNGetPortState), VLAN set/get, flow-get, the ACL policy surface, and
// the aggregate metrics view — have no SDK QUIC client and remain
// daemon-native flat-struct operations, exercised by the local CLI and the
// integration harness only.

// =============================================================================
// Daemon-native SDN wire types (no SDK QUIC pb counterpart)
// =============================================================================

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

// =============================================================================
// Policy Operations (daemon-native)
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
// Metrics (daemon-native)
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

// encodeSDNResponse encodes v (a platform.v1 pb response or a daemon-native
// wire struct) as a StatusOK QUIC response.
func (h *QUICServiceHandler) encodeSDNResponse(v interface{}) *quic.Response {
	payload, err := quic.EncodePayload(v)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}
	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

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
// Bridge Handlers (pb wire contract, delegated to *SDNService)
// =============================================================================

func (h *QUICServiceHandler) handleSDNCreateBridge(ctx context.Context, req *quic.Request) *quic.Response {
	var createReq platformv1.CreateBridgeRequest
	if err := quic.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if createReq.GetConfig().GetName() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	resp, err := h.sdnService.CreateBridge(ctx, &createReq)
	if err != nil {
		h.logger.Error(err, "failed to create SDN bridge", "name", createReq.GetConfig().GetName())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNCreateBridge", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNDeleteBridge(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq platformv1.DeleteBridgeRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.GetId() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	resp, err := h.sdnService.DeleteBridge(ctx, &deleteReq)
	if err != nil {
		h.logger.Error(err, "failed to delete SDN bridge", "id", deleteReq.GetId())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNDeleteBridge", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNGetBridge(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq platformv1.GetBridgeRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.GetId() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	resp, err := h.sdnService.GetBridge(ctx, &getReq)
	if err != nil {
		h.logger.Error(err, "failed to get SDN bridge", "id", getReq.GetId())
		return h.errorResponse(quic.StatusNotFound, ErrSDNBridgeNotFound{BridgeName: getReq.GetId()})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNListBridges(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq platformv1.ListBridgesRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	resp, err := h.sdnService.ListBridges(ctx, &listReq)
	if err != nil {
		h.logger.Error(err, "failed to list SDN bridges")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNListBridges", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

// =============================================================================
// Port Handlers (pb wire contract, delegated to *SDNService)
// =============================================================================

func (h *QUICServiceHandler) handleSDNCreatePort(ctx context.Context, req *quic.Request) *quic.Response {
	var addReq platformv1.AddPortRequest
	if err := quic.DecodePayload(req.Payload, &addReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if addReq.GetBridgeId() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_id"})
	}
	if addReq.GetConfig().GetName() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	resp, err := h.sdnService.AddPort(ctx, &addReq)
	if err != nil {
		h.logger.Error(err, "failed to create SDN port",
			"bridge", addReq.GetBridgeId(), "port", addReq.GetConfig().GetName())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNCreatePort", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNDeletePort(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq platformv1.DeletePortRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.GetBridgeId() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_id"})
	}
	if deleteReq.GetPortId() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_id"})
	}

	resp, err := h.sdnService.DeletePort(ctx, &deleteReq)
	if err != nil {
		h.logger.Error(err, "failed to delete SDN port",
			"bridge", deleteReq.GetBridgeId(), "port", deleteReq.GetPortId())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNDeletePort", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNGetPort(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq platformv1.GetPortRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.GetPortId() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_id"})
	}

	// The SDK carries bridge_id in the request; the local CLI may omit it, in
	// which case the port name alone identifies the bridge.
	if getReq.GetBridgeId() == "" {
		bridgeID, found := h.sdnService.FindPortBridge(getReq.GetPortId())
		if !found {
			return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.GetPortId()})
		}
		getReq.BridgeId = bridgeID
	}

	resp, err := h.sdnService.GetPort(ctx, &getReq)
	if err != nil {
		h.logger.Error(err, "failed to get SDN port", "port", getReq.GetPortId())
		return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.GetPortId()})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNListPorts(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq platformv1.ListPortsRequest
	if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if listReq.GetBridgeId() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_id"})
	}

	resp, err := h.sdnService.ListPorts(ctx, &listReq)
	if err != nil {
		h.logger.Error(err, "failed to list SDN ports", "bridge", listReq.GetBridgeId())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNListPorts", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNSetPortState(ctx context.Context, req *quic.Request) *quic.Response {
	var setReq platformv1.SetPortStateRequest
	if err := quic.DecodePayload(req.Payload, &setReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if setReq.GetPortId() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_id"})
	}
	if setReq.GetAdminState() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "admin_state"})
	}

	// The SDK carries bridge_id; the local CLI may omit it, in which case the
	// port name alone identifies the bridge.
	if setReq.GetBridgeId() == "" {
		bridgeID, found := h.sdnService.FindPortBridge(setReq.GetPortId())
		if !found {
			return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: setReq.GetPortId()})
		}
		setReq.BridgeId = bridgeID
	}

	resp, err := h.sdnService.SetPortState(ctx, &setReq)
	if err != nil {
		h.logger.Error(err, "failed to set SDN port state",
			"port", setReq.GetPortId(), "state", setReq.GetAdminState())
		return h.errorResponse(quic.StatusInternalError, ErrSDNSetPortStateFailed{PortID: setReq.GetPortId(), Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

// =============================================================================
// Flow Handlers (pb wire contract, delegated to *SDNService)
// =============================================================================

func (h *QUICServiceHandler) handleSDNAddFlow(ctx context.Context, req *quic.Request) *quic.Response {
	var addReq platformv1.AddFlowRequest
	if err := quic.DecodePayload(req.Payload, &addReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if addReq.GetConfig().GetBridgeId() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_id"})
	}

	resp, err := h.sdnService.AddFlow(ctx, &addReq)
	if err != nil {
		h.logger.Error(err, "failed to add flow", "bridge", addReq.GetConfig().GetBridgeId())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNAddFlow", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNDeleteFlow(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq platformv1.DeleteFlowRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.GetBridgeId() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_id"})
	}

	resp, err := h.sdnService.DeleteFlow(ctx, &deleteReq)
	if err != nil {
		h.logger.Error(err, "failed to delete flow",
			"bridge", deleteReq.GetBridgeId(), "flow", deleteReq.GetFlowId())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNDeleteFlow", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNListFlows(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq platformv1.ListFlowsRequest
	if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if listReq.GetBridgeId() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_id"})
	}

	resp, err := h.sdnService.ListFlows(ctx, &listReq)
	if err != nil {
		h.logger.Error(err, "failed to list flows", "bridge", listReq.GetBridgeId())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNListFlows", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

// =============================================================================
// Port State Handler (daemon-native)
// =============================================================================

func (h *QUICServiceHandler) handleSDNGetPortState(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq SDNGetPortStateRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	bridgeID, found := h.sdnService.FindPortBridge(getReq.PortName)
	if !found {
		return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.PortName})
	}

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

	return h.encodeSDNResponse(&SDNGetPortStateResponse{
		PortName:  getReq.PortName,
		State:     state,
		Timestamp: time.Now().Unix(),
	})
}

// =============================================================================
// VLAN Handlers (daemon-native)
// =============================================================================

func (h *QUICServiceHandler) handleSDNSetVLAN(ctx context.Context, req *quic.Request) *quic.Response {
	var setReq SDNSetVLANRequest
	if err := quic.DecodePayload(req.Payload, &setReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if setReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	bridgeID, found := h.sdnService.FindPortBridge(setReq.PortName)
	if !found {
		return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: setReq.PortName})
	}

	_, err := h.sdnService.CreateVLAN(ctx, &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			VlanId:   uint32(setReq.VLAN),
			BridgeId: bridgeID,
			Ports:    []string{setReq.PortName},
		},
	})
	if err != nil {
		h.logger.Error(err, "failed to set VLAN", "port", setReq.PortName, "vlan", setReq.VLAN)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNSetVLAN", Cause: err})
	}

	return h.encodeSDNResponse(&SDNSetVLANResponse{
		PortName:  setReq.PortName,
		VLAN:      setReq.VLAN,
		Success:   true,
		Timestamp: time.Now().Unix(),
	})
}

func (h *QUICServiceHandler) handleSDNGetVLAN(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq SDNGetVLANRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	bridgeID, found := h.sdnService.FindPortBridge(getReq.PortName)
	if !found {
		return h.errorResponse(quic.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.PortName})
	}

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

	return h.encodeSDNResponse(&SDNGetVLANResponse{
		PortName:  getReq.PortName,
		VLAN:      vlan,
		Timestamp: time.Now().Unix(),
	})
}

// =============================================================================
// Flow-stats Handler (daemon-native)
// =============================================================================

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
		h.logger.Error(err, "failed to get flow stats", "bridge", getReq.BridgeName, "match", getReq.Match)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SDNGetFlow", Cause: err})
	}

	sdnFlows := make([]*SDNFlow, 0, 1)
	if pbResp.GetStats() != nil {
		sdnFlows = append(sdnFlows, &SDNFlow{
			Match:       getReq.Match,
			PacketCount: int64(pbResp.GetStats().GetPacketCount()),
			ByteCount:   int64(pbResp.GetStats().GetByteCount()),
			Duration:    int(pbResp.GetStats().GetDurationSeconds()),
		})
	}

	return h.encodeSDNResponse(&SDNGetFlowResponse{
		Flows:     sdnFlows,
		Total:     len(sdnFlows),
		Timestamp: time.Now().Unix(),
	})
}

// =============================================================================
// Policy Handlers (daemon-native)
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
		h.logger.Error(err, "failed to apply policy", "port_id", applyReq.PortID, "tenant_id", applyReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrSDNApplyPolicyFailed{PolicyID: applyReq.PortID, Cause: err})
	}

	success := pbResp.GetStatus() != nil && pbResp.GetStatus().GetSuccess()

	return h.encodeSDNResponse(&SDNApplyPolicyResponse{
		PortID:    applyReq.PortID,
		Success:   success,
		Timestamp: time.Now().Unix(),
	})
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

	return h.encodeSDNResponse(&SDNDeletePolicyResponse{
		PortID:    deleteReq.PortID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	})
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

	return h.encodeSDNResponse(&SDNGetPolicyResponse{
		Policy:    convertPbPolicyToSDNPolicy(getReq.PortID, pbResp.GetPolicy()),
		Timestamp: time.Now().Unix(),
	})
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

	return h.encodeSDNResponse(&SDNListPoliciesResponse{
		Policies:  policies,
		Total:     len(policies),
		Timestamp: time.Now().Unix(),
	})
}

// =============================================================================
// Metrics Handler (daemon-native)
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

	bridgesResp, err := h.sdnService.ListBridges(ctx, &platformv1.ListBridgesRequest{})
	if err == nil {
		metrics.BridgeCount = len(bridgesResp.GetBridges())
	}

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

	policiesResp, policyErr := h.sdnService.ListPolicies(ctx, &platformv1.ListPoliciesRequest{})
	if policyErr == nil {
		metrics.PolicyCount = len(policiesResp.GetPolicies())
	}

	return h.encodeSDNResponse(&SDNGetMetricsResponse{
		Metrics:   metrics,
		Timestamp: time.Now().Unix(),
	})
}

// =============================================================================
// Conversion Helpers (protobuf to QUIC types, policy surface only)
// =============================================================================

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

		switch acl.Action {
		case "allow":
			rule.Action = platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW
		case "deny":
			rule.Action = platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY
		default:
			rule.Action = platformv1.PolicyRuleAction_POLICY_RULE_ACTION_UNSPECIFIED
		}

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

		switch rule.GetAction() {
		case platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW:
			acl.Action = "allow"
		case platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY:
			acl.Action = "deny"
		default:
			acl.Action = "unspecified"
		}

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
