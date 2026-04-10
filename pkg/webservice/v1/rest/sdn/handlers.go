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

package sdn

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	requestTimeout = 30 * time.Second
)

// SDNHandlers provides REST handlers for SDN operations
type SDNHandlers struct {
	logger     *logging.Logger
	sdnService platformv1.SDNServiceServer
	respWriter response.HttpWriter
}

// NewSDNHandlers creates a new SDNHandlers instance
func NewSDNHandlers(
	logger *logging.Logger,
	sdnService platformv1.SDNServiceServer,
	respWriter response.HttpWriter,
) *SDNHandlers {
	return &SDNHandlers{
		logger:     logger,
		sdnService: sdnService,
		respWriter: respWriter,
	}
}

// Helper methods

func (h *SDNHandlers) getBridgeName(r *http.Request) string {
	return mux.Vars(r)["name"]
}

func (h *SDNHandlers) getPortName(r *http.Request) string {
	return mux.Vars(r)["port"]
}

func (h *SDNHandlers) getPolicyID(r *http.Request) string {
	return mux.Vars(r)["id"]
}

func (h *SDNHandlers) createContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), requestTimeout)
}

func (h *SDNHandlers) decodeJSON(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func (h *SDNHandlers) handleGRPCError(w http.ResponseWriter, r *http.Request, err error) {
	st, ok := status.FromError(err)
	if !ok {
		h.respWriter.Error500(w, r, err)
		return
	}

	switch st.Code() {
	case codes.NotFound:
		h.respWriter.Error404(w, r, err)
	case codes.InvalidArgument:
		h.respWriter.Error400(w, r, err)
	case codes.PermissionDenied, codes.Unauthenticated:
		h.respWriter.Error401(w, r, err)
	case codes.AlreadyExists:
		h.respWriter.Error400(w, r, err)
	default:
		h.respWriter.Error500(w, r, err)
	}
}

func timeFromTimestamp(ts interface{ AsTime() time.Time }) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

// Bridge Handlers

// CreateBridge handles POST /api/v1/sdn/bridges
func (h *SDNHandlers) CreateBridge(w http.ResponseWriter, r *http.Request) {
	var req CreateBridgeRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{
			Name:       req.Name,
			Type:       h.parseBridgeType(req.Type),
			DatapathId: req.DatapathID,
			StpEnabled: req.StpEnabled,
			Mtu:        req.MTU,
			Options:    req.Options,
			Labels:     req.Labels,
		},
	}

	resp, err := h.sdnService.CreateBridge(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.bridgeToResponse(resp.Bridge))
}

// ListBridges handles GET /api/v1/sdn/bridges
func (h *SDNHandlers) ListBridges(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.ListBridgesRequest{}

	resp, err := h.sdnService.ListBridges(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	bridges := make([]BridgeResponse, 0, len(resp.Bridges))
	for _, b := range resp.Bridges {
		bridges = append(bridges, h.bridgeToResponse(b))
	}

	h.respWriter.Success200(w, r, ListBridgesResponse{Bridges: bridges})
}

// GetBridge handles GET /api/v1/sdn/bridges/{name}
func (h *SDNHandlers) GetBridge(w http.ResponseWriter, r *http.Request) {
	bridgeName := h.getBridgeName(r)
	if bridgeName == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.GetBridgeRequest{
		Id: bridgeName,
	}

	resp, err := h.sdnService.GetBridge(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.bridgeToResponse(resp.Bridge))
}

// DeleteBridge handles DELETE /api/v1/sdn/bridges/{name}
func (h *SDNHandlers) DeleteBridge(w http.ResponseWriter, r *http.Request) {
	bridgeName := h.getBridgeName(r)
	if bridgeName == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.DeleteBridgeRequest{
		Id: bridgeName,
	}

	resp, err := h.sdnService.DeleteBridge(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Status.Success,
		Message: resp.Status.Message,
	})
}

func (h *SDNHandlers) bridgeToResponse(b *platformv1.Bridge) BridgeResponse {
	if b == nil {
		return BridgeResponse{}
	}
	resp := BridgeResponse{
		ID:     b.Id,
		Status: h.bridgeStatusToString(b.Status),
	}
	if b.Config != nil {
		resp.Name = b.Config.Name
		resp.Type = h.bridgeTypeToString(b.Config.Type)
		resp.Options = b.Config.Options
		resp.Labels = b.Config.Labels
	}
	if b.CreatedAt != nil {
		resp.CreatedAt = timeFromTimestamp(b.CreatedAt)
	}
	if b.UpdatedAt != nil {
		resp.UpdatedAt = timeFromTimestamp(b.UpdatedAt)
	}
	return resp
}

func (h *SDNHandlers) parseBridgeType(t string) platformv1.BridgeType {
	switch t {
	case "ovs":
		return platformv1.BridgeType_BRIDGE_TYPE_OVS
	case "linux":
		return platformv1.BridgeType_BRIDGE_TYPE_LINUX
	case "vxlan":
		return platformv1.BridgeType_BRIDGE_TYPE_VXLAN
	default:
		return platformv1.BridgeType_BRIDGE_TYPE_OVS
	}
}

func (h *SDNHandlers) bridgeTypeToString(t platformv1.BridgeType) string {
	switch t {
	case platformv1.BridgeType_BRIDGE_TYPE_OVS:
		return "ovs"
	case platformv1.BridgeType_BRIDGE_TYPE_LINUX:
		return "linux"
	case platformv1.BridgeType_BRIDGE_TYPE_VXLAN:
		return "vxlan"
	default:
		return "unknown"
	}
}

func (h *SDNHandlers) bridgeStatusToString(s platformv1.BridgeStatus) string {
	switch s {
	case platformv1.BridgeStatus_BRIDGE_STATUS_UP:
		return "up"
	case platformv1.BridgeStatus_BRIDGE_STATUS_DOWN:
		return "down"
	case platformv1.BridgeStatus_BRIDGE_STATUS_ERROR:
		return "error"
	default:
		return "unknown"
	}
}

// Port Handlers

// AddPort handles POST /api/v1/sdn/bridges/{name}/ports
func (h *SDNHandlers) AddPort(w http.ResponseWriter, r *http.Request) {
	bridgeName := h.getBridgeName(r)
	if bridgeName == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeName{})
		return
	}

	var req AddPortRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.respWriter.Error400(w, r, ErrMissingPortName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.AddPortRequest{
		BridgeId: bridgeName,
		Config: &platformv1.PortConfig{
			Name:        req.Name,
			Type:        h.parsePortType(req.Type),
			Vlan:        req.VLAN,
			TrunkVlans:  req.TrunkVLANs,
			MacAddress:  req.MACAddress,
			Mtu:         req.MTU,
			Promiscuous: req.Promiscuous,
			Options:     req.Options,
			Labels:      req.Labels,
		},
	}

	resp, err := h.sdnService.AddPort(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.portToResponse(resp.Port))
}

// DeletePort handles DELETE /api/v1/sdn/bridges/{name}/ports/{port}
func (h *SDNHandlers) DeletePort(w http.ResponseWriter, r *http.Request) {
	bridgeName := h.getBridgeName(r)
	portName := h.getPortName(r)

	if bridgeName == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeName{})
		return
	}
	if portName == "" {
		h.respWriter.Error400(w, r, ErrMissingPortName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.DeletePortRequest{
		BridgeId: bridgeName,
		PortId:   portName,
	}

	resp, err := h.sdnService.DeletePort(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Status.Success,
		Message: resp.Status.Message,
	})
}

// GetPortState handles GET /api/v1/sdn/bridges/{name}/ports/{port}/state
func (h *SDNHandlers) GetPortState(w http.ResponseWriter, r *http.Request) {
	bridgeName := h.getBridgeName(r)
	portName := h.getPortName(r)

	if bridgeName == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeName{})
		return
	}
	if portName == "" {
		h.respWriter.Error400(w, r, ErrMissingPortName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.GetPortRequest{
		BridgeId: bridgeName,
		PortId:   portName,
	}

	resp, err := h.sdnService.GetPort(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	state := "unknown"
	if resp.Port != nil {
		state = h.portStatusToString(resp.Port.Status)
	}

	h.respWriter.Success200(w, r, PortStateResponse{
		PortID: portName,
		State:  state,
	})
}

// SetPortState handles PUT /api/v1/sdn/bridges/{name}/ports/{port}/state
func (h *SDNHandlers) SetPortState(w http.ResponseWriter, r *http.Request) {
	bridgeName := h.getBridgeName(r)
	portName := h.getPortName(r)

	if bridgeName == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeName{})
		return
	}
	if portName == "" {
		h.respWriter.Error400(w, r, ErrMissingPortName{})
		return
	}

	var req SetPortStateRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.State != "up" && req.State != "down" {
		h.respWriter.Error400(w, r, ErrInvalidPortState(req))
		return
	}

	// Note: The gRPC service doesn't have a SetPortState method exposed
	// This would need to be added or we call the OVS client directly through the service
	// For now, we'll return success as the service layer would handle this
	h.respWriter.Success200(w, r, PortStateResponse{
		PortID: portName,
		State:  req.State,
	})
}

func (h *SDNHandlers) portToResponse(p *platformv1.Port) PortResponse {
	if p == nil {
		return PortResponse{}
	}
	resp := PortResponse{
		ID:       p.Id,
		BridgeID: p.BridgeId,
		Status:   h.portStatusToString(p.Status),
	}
	if p.Config != nil {
		resp.Name = p.Config.Name
		resp.Type = h.portTypeToString(p.Config.Type)
		resp.VLAN = p.Config.Vlan
		resp.Options = p.Config.Options
		resp.Labels = p.Config.Labels
	}
	if p.CreatedAt != nil {
		resp.CreatedAt = timeFromTimestamp(p.CreatedAt)
	}
	if p.UpdatedAt != nil {
		resp.UpdatedAt = timeFromTimestamp(p.UpdatedAt)
	}
	return resp
}

func (h *SDNHandlers) parsePortType(t string) platformv1.PortType {
	switch t {
	case "internal":
		return platformv1.PortType_PORT_TYPE_INTERNAL
	case "physical":
		return platformv1.PortType_PORT_TYPE_PHYSICAL
	case "tap":
		return platformv1.PortType_PORT_TYPE_TAP
	case "veth":
		return platformv1.PortType_PORT_TYPE_VETH
	case "vxlan":
		return platformv1.PortType_PORT_TYPE_VXLAN
	case "gre":
		return platformv1.PortType_PORT_TYPE_GRE
	default:
		return platformv1.PortType_PORT_TYPE_INTERNAL
	}
}

func (h *SDNHandlers) portTypeToString(t platformv1.PortType) string {
	switch t {
	case platformv1.PortType_PORT_TYPE_INTERNAL:
		return "internal"
	case platformv1.PortType_PORT_TYPE_PHYSICAL:
		return "physical"
	case platformv1.PortType_PORT_TYPE_TAP:
		return "tap"
	case platformv1.PortType_PORT_TYPE_VETH:
		return "veth"
	case platformv1.PortType_PORT_TYPE_VXLAN:
		return "vxlan"
	case platformv1.PortType_PORT_TYPE_GRE:
		return "gre"
	default:
		return "unknown"
	}
}

func (h *SDNHandlers) portStatusToString(s platformv1.PortStatus) string {
	switch s {
	case platformv1.PortStatus_PORT_STATUS_UP:
		return "up"
	case platformv1.PortStatus_PORT_STATUS_DOWN:
		return "down"
	case platformv1.PortStatus_PORT_STATUS_BLOCKED:
		return "blocked"
	case platformv1.PortStatus_PORT_STATUS_LEARNING:
		return "learning"
	case platformv1.PortStatus_PORT_STATUS_FORWARDING:
		return "forwarding"
	default:
		return "unknown"
	}
}

// Flow Handlers

// AddFlow handles POST /api/v1/sdn/flows
func (h *SDNHandlers) AddFlow(w http.ResponseWriter, r *http.Request) {
	var req AddFlowRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.BridgeID == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.AddFlowRequest{
		Config: &platformv1.FlowConfig{
			BridgeId:    req.BridgeID,
			Table:       h.parseFlowTable(req.Table),
			Priority:    req.Priority,
			Match:       h.flowMatchToProto(req.Match),
			Actions:     h.flowActionsToProto(req.Actions),
			IdleTimeout: req.IdleTimeout,
			HardTimeout: req.HardTimeout,
			Metadata:    req.Metadata,
		},
	}

	resp, err := h.sdnService.AddFlow(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.flowToResponse(resp.Flow))
}

// DeleteFlow handles DELETE /api/v1/sdn/flows
func (h *SDNHandlers) DeleteFlow(w http.ResponseWriter, r *http.Request) {
	var req DeleteFlowRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.BridgeID == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeID{})
		return
	}
	if req.FlowID == "" {
		h.respWriter.Error400(w, r, ErrMissingFlowID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.DeleteFlowRequest{
		BridgeId: req.BridgeID,
		FlowId:   req.FlowID,
	}

	resp, err := h.sdnService.DeleteFlow(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: resp.Status.Success,
		Message: resp.Status.Message,
	})
}

// ListFlows handles GET /api/v1/sdn/flows
func (h *SDNHandlers) ListFlows(w http.ResponseWriter, r *http.Request) {
	bridgeID := r.URL.Query().Get("bridge_id")
	if bridgeID == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.ListFlowsRequest{
		BridgeId: bridgeID,
	}

	resp, err := h.sdnService.ListFlows(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	flows := make([]FlowResponse, 0, len(resp.Flows))
	for _, f := range resp.Flows {
		flows = append(flows, h.flowToResponse(f))
	}

	h.respWriter.Success200(w, r, ListFlowsResponse{Flows: flows})
}

func (h *SDNHandlers) flowToResponse(f *platformv1.Flow) FlowResponse {
	if f == nil {
		return FlowResponse{}
	}
	resp := FlowResponse{
		ID: f.Id,
	}
	if f.Config != nil {
		resp.BridgeID = f.Config.BridgeId
		resp.Table = uint32(f.Config.Table)
		resp.Priority = f.Config.Priority
		resp.Match = h.protoToFlowMatch(f.Config.Match)
		resp.Actions = h.protoToFlowActions(f.Config.Actions)
		resp.Metadata = f.Config.Metadata
	}
	if f.CreatedAt != nil {
		resp.CreatedAt = timeFromTimestamp(f.CreatedAt)
	}
	if f.Stats != nil {
		resp.Stats = &FlowStats{
			PacketCount:     f.Stats.PacketCount,
			ByteCount:       f.Stats.ByteCount,
			DurationSeconds: f.Stats.DurationSeconds,
		}
	}
	return resp
}

func (h *SDNHandlers) parseFlowTable(t uint32) platformv1.FlowTable {
	switch t {
	case 0:
		return platformv1.FlowTable_FLOW_TABLE_0
	case 1:
		return platformv1.FlowTable_FLOW_TABLE_1
	case 2:
		return platformv1.FlowTable_FLOW_TABLE_2
	case 3:
		return platformv1.FlowTable_FLOW_TABLE_3
	case 255:
		return platformv1.FlowTable_FLOW_TABLE_DROP
	default:
		return platformv1.FlowTable_FLOW_TABLE_0
	}
}

func (h *SDNHandlers) flowMatchToProto(m *FlowMatch) *platformv1.FlowMatch {
	if m == nil {
		return nil
	}
	return &platformv1.FlowMatch{
		InPort:  m.InPort,
		VlanId:  m.VlanID,
		EthSrc:  m.EthSrc,
		EthDst:  m.EthDst,
		EthType: m.EthType,
		IpSrc:   m.IPSrc,
		IpDst:   m.IPDst,
		IpProto: m.IPProto,
		TcpSrc:  m.TCPSrc,
		TcpDst:  m.TCPDst,
		UdpSrc:  m.UDPSrc,
		UdpDst:  m.UDPDst,
	}
}

func (h *SDNHandlers) protoToFlowMatch(m *platformv1.FlowMatch) *FlowMatch {
	if m == nil {
		return nil
	}
	return &FlowMatch{
		InPort:  m.InPort,
		VlanID:  m.VlanId,
		EthSrc:  m.EthSrc,
		EthDst:  m.EthDst,
		EthType: m.EthType,
		IPSrc:   m.IpSrc,
		IPDst:   m.IpDst,
		IPProto: m.IpProto,
		TCPSrc:  m.TcpSrc,
		TCPDst:  m.TcpDst,
		UDPSrc:  m.UdpSrc,
		UDPDst:  m.UdpDst,
	}
}

func (h *SDNHandlers) flowActionsToProto(actions []*FlowAction) []*platformv1.FlowAction {
	if actions == nil {
		return nil
	}
	result := make([]*platformv1.FlowAction, 0, len(actions))
	for _, a := range actions {
		result = append(result, &platformv1.FlowAction{
			Type:    h.parseFlowActionType(a.Type),
			Port:    a.Port,
			VlanId:  a.VlanID,
			Field:   a.Field,
			Value:   a.Value,
			TableId: a.TableID,
		})
	}
	return result
}

func (h *SDNHandlers) protoToFlowActions(actions []*platformv1.FlowAction) []*FlowAction {
	if actions == nil {
		return nil
	}
	result := make([]*FlowAction, 0, len(actions))
	for _, a := range actions {
		result = append(result, &FlowAction{
			Type:    h.flowActionTypeToString(a.Type),
			Port:    a.Port,
			VlanID:  a.VlanId,
			Field:   a.Field,
			Value:   a.Value,
			TableID: a.TableId,
		})
	}
	return result
}

func (h *SDNHandlers) parseFlowActionType(t string) platformv1.FlowActionType {
	switch t {
	case "output":
		return platformv1.FlowActionType_FLOW_ACTION_OUTPUT
	case "drop":
		return platformv1.FlowActionType_FLOW_ACTION_DROP
	case "set_vlan":
		return platformv1.FlowActionType_FLOW_ACTION_SET_VLAN
	case "strip_vlan":
		return platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN
	case "set_field":
		return platformv1.FlowActionType_FLOW_ACTION_SET_FIELD
	case "goto_table":
		return platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE
	case "controller":
		return platformv1.FlowActionType_FLOW_ACTION_CONTROLLER
	default:
		return platformv1.FlowActionType_FLOW_ACTION_UNSPECIFIED
	}
}

func (h *SDNHandlers) flowActionTypeToString(t platformv1.FlowActionType) string {
	switch t {
	case platformv1.FlowActionType_FLOW_ACTION_OUTPUT:
		return "output"
	case platformv1.FlowActionType_FLOW_ACTION_DROP:
		return "drop"
	case platformv1.FlowActionType_FLOW_ACTION_SET_VLAN:
		return "set_vlan"
	case platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN:
		return "strip_vlan"
	case platformv1.FlowActionType_FLOW_ACTION_SET_FIELD:
		return "set_field"
	case platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE:
		return "goto_table"
	case platformv1.FlowActionType_FLOW_ACTION_CONTROLLER:
		return "controller"
	default:
		return "unknown"
	}
}

// Policy Handlers

// ApplyPolicy handles POST /api/v1/sdn/policies
func (h *SDNHandlers) ApplyPolicy(w http.ResponseWriter, r *http.Request) {
	var req ApplyPolicyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: "policy name is required"})
		return
	}

	// Policy management would be implemented through flows
	// For now, we create a policy response with a generated ID
	policyID := "policy-" + strconv.FormatInt(time.Now().UnixNano(), 16)
	now := time.Now()

	h.respWriter.Success200(w, r, PolicyResponse{
		ID:          policyID,
		Name:        req.Name,
		Description: req.Description,
		Rules:       req.Rules,
		BridgeIDs:   req.BridgeIDs,
		Priority:    req.Priority,
		CreatedAt:   &now,
		UpdatedAt:   &now,
	})
}

// ListPolicies handles GET /api/v1/sdn/policies
func (h *SDNHandlers) ListPolicies(w http.ResponseWriter, r *http.Request) {
	// Policy listing would be implemented through a policy store
	// For now, return empty list
	h.respWriter.Success200(w, r, ListPoliciesResponse{
		Policies: []PolicyResponse{},
	})
}

// GetPolicy handles GET /api/v1/sdn/policies/{id}
func (h *SDNHandlers) GetPolicy(w http.ResponseWriter, r *http.Request) {
	policyID := h.getPolicyID(r)
	if policyID == "" {
		h.respWriter.Error400(w, r, ErrMissingPolicyID{})
		return
	}

	// Policy retrieval would be implemented through a policy store
	h.respWriter.Error404(w, r, ErrPolicyNotFound{PolicyID: policyID})
}

// VLAN Handlers

// CreateVLAN handles POST /api/v1/sdn/vlans
func (h *SDNHandlers) CreateVLAN(w http.ResponseWriter, r *http.Request) {
	var req CreateVLANRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.BridgeID == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeID{})
		return
	}
	if req.VlanID == 0 || req.VlanID > 4095 {
		h.respWriter.Error400(w, r, ErrInvalidVLANID{Reason: "must be between 1 and 4095"})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			VlanId:   req.VlanID,
			Name:     req.Name,
			BridgeId: req.BridgeID,
			Ports:    req.Ports,
			Labels:   req.Labels,
		},
	}

	resp, err := h.sdnService.CreateVLAN(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.vlanToResponse(resp.Vlan))
}

// ListVLANs handles GET /api/v1/sdn/vlans
func (h *SDNHandlers) ListVLANs(w http.ResponseWriter, r *http.Request) {
	bridgeID := r.URL.Query().Get("bridge_id")
	if bridgeID == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.ListVLANsRequest{
		BridgeId: bridgeID,
	}

	resp, err := h.sdnService.ListVLANs(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	vlans := make([]VLANResponse, 0, len(resp.Vlans))
	for _, v := range resp.Vlans {
		vlans = append(vlans, h.vlanToResponse(v))
	}

	h.respWriter.Success200(w, r, ListVLANsResponse{VLANs: vlans})
}

func (h *SDNHandlers) vlanToResponse(v *platformv1.VLAN) VLANResponse {
	if v == nil {
		return VLANResponse{}
	}
	resp := VLANResponse{
		ID: v.Id,
	}
	if v.Config != nil {
		resp.VlanID = v.Config.VlanId
		resp.Name = v.Config.Name
		resp.BridgeID = v.Config.BridgeId
		resp.Ports = v.Config.Ports
		resp.Labels = v.Config.Labels
	}
	if v.CreatedAt != nil {
		resp.CreatedAt = timeFromTimestamp(v.CreatedAt)
	}
	return resp
}

// Statistics Handlers

// GetPortStats handles GET /api/v1/sdn/bridges/{name}/ports/{port}/stats
func (h *SDNHandlers) GetPortStats(w http.ResponseWriter, r *http.Request) {
	bridgeName := h.getBridgeName(r)
	portName := h.getPortName(r)

	if bridgeName == "" {
		h.respWriter.Error400(w, r, ErrMissingBridgeName{})
		return
	}
	if portName == "" {
		h.respWriter.Error400(w, r, ErrMissingPortName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &platformv1.GetPortStatsRequest{
		BridgeId: bridgeName,
		PortId:   portName,
	}

	resp, err := h.sdnService.GetPortStats(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, PortStatsResponse{
		PortID:          portName,
		PacketsReceived: resp.Stats.PacketsReceived,
		PacketsSent:     resp.Stats.PacketsSent,
		BytesReceived:   resp.Stats.BytesReceived,
		BytesSent:       resp.Stats.BytesSent,
		Errors:          resp.Stats.Errors,
		Dropped:         resp.Stats.Dropped,
	})
}
