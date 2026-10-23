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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// SDNGetFlowRequest represents a request to get flow stats. Match carries
// the flow ID the API hands out ("flow-<cookie>", as AddFlow and ListFlows
// report it); the wire name predates that and is kept for compatibility.
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

// The policy operations carry the policy shape REST, gRPC and MCP use: apply
// takes a rest.CreatePolicyRequest and returns a rest.PolicyResponse, get
// returns a rest.PolicyResponse, list returns a rest.SDNPolicyListResponse and
// delete returns a rest.SDNActionResponse. The wire codec keys fields by their
// Go names, so those types are the QUIC contract as they stand.

// SDNDeletePolicyRequest represents a request to delete a policy by ID or name.
type SDNDeletePolicyRequest struct {
	PolicyID string `codec:"policy_id"`
}

// SDNGetPolicyRequest represents a request to get a policy by ID or name.
type SDNGetPolicyRequest struct {
	PolicyID string `codec:"policy_id"`
}

// SDNListPoliciesRequest filters a policy listing the way REST's type and
// target_id query parameters do; empty fields do not filter.
type SDNListPoliciesRequest struct {
	Type     string `codec:"type"`
	TargetID string `codec:"target_id"`
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
func (h *QUICServiceHandler) encodeSDNResponse(v interface{}) *quicwire.Response {
	payload, err := quicwire.EncodePayload(v)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}
	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleSDNOperation routes SDN operations to their handlers
func (h *QUICServiceHandler) handleSDNOperation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.sdnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "sdn"})
	}

	switch req.Opcode {
	// Bridge operations
	case quicwire.OpSDNCreateBridge:
		return h.handleSDNCreateBridge(ctx, req)
	case quicwire.OpSDNDeleteBridge:
		return h.handleSDNDeleteBridge(ctx, req)
	case quicwire.OpSDNGetBridge:
		return h.handleSDNGetBridge(ctx, req)
	case quicwire.OpSDNListBridges:
		return h.handleSDNListBridges(ctx, req)

	// Port operations
	case quicwire.OpSDNCreatePort:
		return h.handleSDNCreatePort(ctx, req)
	case quicwire.OpSDNDeletePort:
		return h.handleSDNDeletePort(ctx, req)
	case quicwire.OpSDNGetPort:
		return h.handleSDNGetPort(ctx, req)
	case quicwire.OpSDNListPorts:
		return h.handleSDNListPorts(ctx, req)
	case quicwire.OpSDNGetPortState:
		return h.handleSDNGetPortState(ctx, req)
	case quicwire.OpSDNSetPortState:
		return h.handleSDNSetPortState(ctx, req)

	// VLAN operations
	case quicwire.OpSDNSetVLAN:
		return h.handleSDNSetVLAN(ctx, req)
	case quicwire.OpSDNGetVLAN:
		return h.handleSDNGetVLAN(ctx, req)

	// Flow operations
	case quicwire.OpSDNAddFlow:
		return h.handleSDNAddFlow(ctx, req)
	case quicwire.OpSDNDeleteFlow:
		return h.handleSDNDeleteFlow(ctx, req)
	case quicwire.OpSDNGetFlow:
		return h.handleSDNGetFlow(ctx, req)
	case quicwire.OpSDNListFlows:
		return h.handleSDNListFlows(ctx, req)

	// Policy operations
	case quicwire.OpSDNApplyPolicy:
		return h.handleSDNApplyPolicy(ctx, req)
	case quicwire.OpSDNDeletePolicy:
		return h.handleSDNDeletePolicy(ctx, req)
	case quicwire.OpSDNGetPolicy:
		return h.handleSDNGetPolicy(ctx, req)
	case quicwire.OpSDNListPolicies:
		return h.handleSDNListPolicies(ctx, req)

	// Metrics
	case quicwire.OpSDNGetMetrics:
		return h.handleSDNGetMetrics(ctx, req)

	default:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// =============================================================================
// Bridge Handlers (pb wire contract, delegated to *SDNService)
// =============================================================================

func (h *QUICServiceHandler) handleSDNCreateBridge(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var createReq platformv1.CreateBridgeRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if createReq.GetConfig().GetName() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	resp, err := h.sdnService.CreateBridge(ctx, &createReq)
	if err != nil {
		h.logger.Error(err, "failed to create SDN bridge", "name", createReq.GetConfig().GetName())
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "SDNCreateBridge", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNDeleteBridge(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var deleteReq platformv1.DeleteBridgeRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.GetId() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	resp, err := h.sdnService.DeleteBridge(ctx, &deleteReq)
	if err != nil {
		h.logger.Error(err, "failed to delete SDN bridge", "id", deleteReq.GetId())
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "SDNDeleteBridge", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNGetBridge(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq platformv1.GetBridgeRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.GetId() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	resp, err := h.sdnService.GetBridge(ctx, &getReq)
	if err != nil {
		h.logger.Error(err, "failed to get SDN bridge", "id", getReq.GetId())
		return h.errorResponse(quicwire.StatusNotFound, ErrSDNBridgeNotFound{BridgeName: getReq.GetId()})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNListBridges(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var listReq platformv1.ListBridgesRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	resp, err := h.sdnService.ListBridges(ctx, &listReq)
	if err != nil {
		h.logger.Error(err, "failed to list SDN bridges")
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "SDNListBridges", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

// =============================================================================
// Port Handlers (pb wire contract, delegated to *SDNService)
// =============================================================================

func (h *QUICServiceHandler) handleSDNCreatePort(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var addReq platformv1.AddPortRequest
	if err := quicwire.DecodePayload(req.Payload, &addReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if addReq.GetBridgeId() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_id"})
	}
	if addReq.GetConfig().GetName() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	resp, err := h.sdnService.AddPort(ctx, &addReq)
	if err != nil {
		h.logger.Error(err, "failed to create SDN port",
			"bridge", addReq.GetBridgeId(), "port", addReq.GetConfig().GetName())
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "SDNCreatePort", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNDeletePort(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var deleteReq platformv1.DeletePortRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.GetBridgeId() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_id"})
	}
	if deleteReq.GetPortId() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "port_id"})
	}

	resp, err := h.sdnService.DeletePort(ctx, &deleteReq)
	if err != nil {
		h.logger.Error(err, "failed to delete SDN port",
			"bridge", deleteReq.GetBridgeId(), "port", deleteReq.GetPortId())
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "SDNDeletePort", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNGetPort(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq platformv1.GetPortRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.GetPortId() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "port_id"})
	}

	// The SDK carries bridge_id in the request; the local CLI may omit it, in
	// which case the port name alone identifies the bridge.
	if getReq.GetBridgeId() == "" {
		bridgeID, found := h.sdnService.FindPortBridge(getReq.GetPortId())
		if !found {
			return h.errorResponse(quicwire.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.GetPortId()})
		}
		getReq.BridgeId = bridgeID
	}

	resp, err := h.sdnService.GetPort(ctx, &getReq)
	if err != nil {
		h.logger.Error(err, "failed to get SDN port", "port", getReq.GetPortId())
		return h.errorResponse(quicwire.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.GetPortId()})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNListPorts(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var listReq platformv1.ListPortsRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if listReq.GetBridgeId() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_id"})
	}

	resp, err := h.sdnService.ListPorts(ctx, &listReq)
	if err != nil {
		h.logger.Error(err, "failed to list SDN ports", "bridge", listReq.GetBridgeId())
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "SDNListPorts", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

// sdnQUICStatus maps a gRPC status error from the shared SDNService to the
// QUIC status the other transports would answer with (an invalid argument is
// not an internal error).
func sdnQUICStatus(err error) byte {
	if mapped, ok := deviceGRPCCodeToQUICStatus[status.Code(err)]; ok {
		return mapped
	}
	return quicwire.StatusInternalError
}

// sdnPolicyError names the requested policy when the shared SDNService has no
// such policy, and otherwise reports op as failed with its cause.
func sdnPolicyError(op, policyID string, err error) error {
	if status.Code(err) == codes.NotFound {
		return ErrSDNPolicyNotFound{PolicyID: policyID}
	}
	return ErrQUICOperationFailed{Op: op, Cause: err}
}

func (h *QUICServiceHandler) handleSDNSetPortState(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var setReq platformv1.SetPortStateRequest
	if err := quicwire.DecodePayload(req.Payload, &setReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if setReq.GetPortId() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "port_id"})
	}
	if setReq.GetAdminState() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "admin_state"})
	}

	// The SDK carries bridge_id; the local CLI may omit it, in which case the
	// port name alone identifies the bridge.
	if setReq.GetBridgeId() == "" {
		bridgeID, found := h.sdnService.FindPortBridge(setReq.GetPortId())
		if !found {
			return h.errorResponse(quicwire.StatusNotFound, ErrSDNPortNotFound{PortName: setReq.GetPortId()})
		}
		setReq.BridgeId = bridgeID
	}

	resp, err := h.sdnService.SetPortState(ctx, &setReq)
	if err != nil {
		h.logger.Error(err, "failed to set SDN port state",
			"port", setReq.GetPortId(), "state", setReq.GetAdminState())
		return h.errorResponse(sdnQUICStatus(err), ErrSDNSetPortStateFailed{PortID: setReq.GetPortId(), Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

// =============================================================================
// Flow Handlers (pb wire contract, delegated to *SDNService)
// =============================================================================

func (h *QUICServiceHandler) handleSDNAddFlow(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var addReq platformv1.AddFlowRequest
	if err := quicwire.DecodePayload(req.Payload, &addReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if addReq.GetConfig().GetBridgeId() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_id"})
	}

	resp, err := h.sdnService.AddFlow(ctx, &addReq)
	if err != nil {
		h.logger.Error(err, "failed to add flow", "bridge", addReq.GetConfig().GetBridgeId())
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "SDNAddFlow", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNDeleteFlow(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var deleteReq platformv1.DeleteFlowRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.GetBridgeId() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_id"})
	}

	resp, err := h.sdnService.DeleteFlow(ctx, &deleteReq)
	if err != nil {
		h.logger.Error(err, "failed to delete flow",
			"bridge", deleteReq.GetBridgeId(), "flow", deleteReq.GetFlowId())
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "SDNDeleteFlow", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

func (h *QUICServiceHandler) handleSDNListFlows(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var listReq platformv1.ListFlowsRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if listReq.GetBridgeId() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_id"})
	}

	resp, err := h.sdnService.ListFlows(ctx, &listReq)
	if err != nil {
		h.logger.Error(err, "failed to list flows", "bridge", listReq.GetBridgeId())
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "SDNListFlows", Cause: err})
	}

	return h.encodeSDNResponse(resp)
}

// =============================================================================
// Port State Handler (daemon-native)
// =============================================================================

func (h *QUICServiceHandler) handleSDNGetPortState(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq SDNGetPortStateRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.PortName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	bridgeID, found := h.sdnService.FindPortBridge(getReq.PortName)
	if !found {
		return h.errorResponse(quicwire.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.PortName})
	}

	pbResp, err := h.sdnService.GetPort(ctx, &platformv1.GetPortRequest{
		BridgeId: bridgeID,
		PortId:   getReq.PortName,
	})
	if err != nil {
		h.logger.Error(err, "failed to get SDN port state", "port", getReq.PortName)
		return h.errorResponse(quicwire.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.PortName})
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

func (h *QUICServiceHandler) handleSDNSetVLAN(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var setReq SDNSetVLANRequest
	if err := quicwire.DecodePayload(req.Payload, &setReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if setReq.PortName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	bridgeID, found := h.sdnService.FindPortBridge(setReq.PortName)
	if !found {
		return h.errorResponse(quicwire.StatusNotFound, ErrSDNPortNotFound{PortName: setReq.PortName})
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
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "SDNSetVLAN", Cause: err})
	}

	return h.encodeSDNResponse(&SDNSetVLANResponse{
		PortName:  setReq.PortName,
		VLAN:      setReq.VLAN,
		Success:   true,
		Timestamp: time.Now().Unix(),
	})
}

func (h *QUICServiceHandler) handleSDNGetVLAN(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq SDNGetVLANRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.PortName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	bridgeID, found := h.sdnService.FindPortBridge(getReq.PortName)
	if !found {
		return h.errorResponse(quicwire.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.PortName})
	}

	pbResp, err := h.sdnService.GetPort(ctx, &platformv1.GetPortRequest{
		BridgeId: bridgeID,
		PortId:   getReq.PortName,
	})
	if err != nil {
		h.logger.Error(err, "failed to get VLAN", "port", getReq.PortName)
		return h.errorResponse(quicwire.StatusNotFound, ErrSDNPortNotFound{PortName: getReq.PortName})
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

func (h *QUICServiceHandler) handleSDNGetFlow(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq SDNGetFlowRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.BridgeName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "bridge_name"})
	}

	pbResp, err := h.sdnService.GetFlowStats(ctx, &platformv1.GetFlowStatsRequest{
		BridgeId: getReq.BridgeName,
		FlowId:   getReq.Match,
	})
	if err != nil {
		h.logger.Error(err, "failed to get flow stats", "bridge", getReq.BridgeName, "match", getReq.Match)
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "SDNGetFlow", Cause: err})
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

func (h *QUICServiceHandler) handleSDNApplyPolicy(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var policyReq rest.CreatePolicyRequest
	if err := quicwire.DecodePayload(req.Payload, &policyReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	applyReq, err := rest.PolicyRequestToProto(policyReq)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrSDNInvalidPolicy{Reason: err.Error()})
	}

	resp, err := h.sdnService.ApplyPolicy(ctx, applyReq)
	if err != nil {
		h.logger.Error(err, "failed to apply policy", "name", policyReq.Name)
		return h.errorResponse(sdnQUICStatus(err), ErrSDNApplyPolicyFailed{PolicyID: policyReq.Name, Cause: err})
	}

	return h.encodeSDNResponse(rest.PolicyToResponse(resp.GetPolicy()))
}

func (h *QUICServiceHandler) handleSDNDeletePolicy(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var deleteReq SDNDeletePolicyRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.PolicyID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "policy_id"})
	}

	resp, err := h.sdnService.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{
		PolicyId: deleteReq.PolicyID,
	})
	if err != nil {
		h.logger.Error(err, "failed to remove policy", "policy_id", deleteReq.PolicyID)
		return h.errorResponse(sdnQUICStatus(err), sdnPolicyError("SDNDeletePolicy", deleteReq.PolicyID, err))
	}

	return h.encodeSDNResponse(rest.SDNActionResponse{
		ResourceID:   deleteReq.PolicyID,
		ResourceType: "policy",
		Action:       "delete",
		Success:      resp.GetStatus().GetSuccess(),
		Message:      resp.GetStatus().GetMessage(),
	})
}

func (h *QUICServiceHandler) handleSDNGetPolicy(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq SDNGetPolicyRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.PolicyID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "policy_id"})
	}

	resp, err := h.sdnService.GetPolicy(ctx, &platformv1.GetPolicyRequest{
		PolicyId: getReq.PolicyID,
	})
	if err != nil {
		h.logger.Error(err, "failed to get policy", "policy_id", getReq.PolicyID)
		return h.errorResponse(sdnQUICStatus(err), sdnPolicyError("SDNGetPolicy", getReq.PolicyID, err))
	}

	return h.encodeSDNResponse(rest.PolicyToResponse(resp.GetPolicy()))
}

func (h *QUICServiceHandler) handleSDNListPolicies(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var listReq SDNListPoliciesRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.sdnService.ListPolicies(ctx, &platformv1.ListPoliciesRequest{
		Type:     listReq.Type,
		TargetId: listReq.TargetID,
	})
	if err != nil {
		h.logger.Error(err, "failed to list policies")
		return h.errorResponse(sdnQUICStatus(err), ErrQUICOperationFailed{Op: "SDNListPolicies", Cause: err})
	}

	policies := make([]rest.PolicyResponse, 0, len(resp.GetPolicies()))
	for _, policy := range resp.GetPolicies() {
		policies = append(policies, rest.PolicyToResponse(policy))
	}

	return h.encodeSDNResponse(rest.SDNPolicyListResponse{
		Policies:  policies,
		Count:     len(policies),
		Timestamp: time.Now().UTC(),
	})
}

// =============================================================================
// Metrics Handler (daemon-native)
// =============================================================================

func (h *QUICServiceHandler) handleSDNGetMetrics(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var metricsReq SDNGetMetricsRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &metricsReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
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
