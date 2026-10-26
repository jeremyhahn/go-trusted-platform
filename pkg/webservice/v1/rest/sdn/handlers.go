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
	"net/http"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SDNHandlers serves the SDN REST routes on the SDN gRPC service. Bridge,
// port, flow, policy and VLAN routes read the proto request as protojson and
// answer the proto response as protojson, so REST carries the gRPC and SDK
// wire shape (ruling 189). The service validates every request; a handler
// only fills in the identifiers the path and query carry.
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

// ensureAvailable answers 503 when no SDN service is wired.
func (h *SDNHandlers) ensureAvailable(w http.ResponseWriter, r *http.Request) bool {
	if h.sdnService == nil {
		protorest.WriteError(w, r, h.respWriter, &protorest.ErrServiceUnavailable{Service: "sdn"})
		return false
	}
	return true
}

// decode reads the protojson body into req, answering 400 when it cannot.
func (h *SDNHandlers) decode(w http.ResponseWriter, r *http.Request, req proto.Message) bool {
	if !h.ensureAvailable(w, r) {
		return false
	}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return false
	}
	return true
}

// reply writes the service's answer: its error as the mapped HTTP status, or
// its response as the protojson payload.
func (h *SDNHandlers) reply(w http.ResponseWriter, r *http.Request, resp proto.Message, err error) {
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// bridgeScope is the bridge a route addresses: the path's, else the
// bridge_id query parameter, else the one the body carried.
func bridgeScope(r *http.Request, fromBody string) string {
	vars := mux.Vars(r)
	if name := vars["name"]; name != "" {
		return name
	}
	if id := vars["bridge_id"]; id != "" {
		return id
	}
	if id := r.URL.Query().Get("bridge_id"); id != "" {
		return id
	}
	return fromBody
}

// portPath is the bridge and port a /bridges/{name}/ports/{port} route names.
func portPath(r *http.Request) (bridgeID, portID string) {
	vars := mux.Vars(r)
	return vars["name"], vars["port"]
}

// Bridge Handlers

// CreateBridge handles POST /api/v1/sdn/bridges with a CreateBridgeRequest.
func (h *SDNHandlers) CreateBridge(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.CreateBridgeRequest{}
	if !h.decode(w, r, req) {
		return
	}
	resp, err := h.sdnService.CreateBridge(r.Context(), req)
	h.reply(w, r, resp, err)
}

// ListBridges handles GET /api/v1/sdn/bridges; an optional body carries the
// ListBridgesRequest selector and pagination.
func (h *SDNHandlers) ListBridges(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.ListBridgesRequest{}
	if !h.decode(w, r, req) {
		return
	}
	resp, err := h.sdnService.ListBridges(r.Context(), req)
	h.reply(w, r, resp, err)
}

// GetBridge handles GET /api/v1/sdn/bridges/{name}.
func (h *SDNHandlers) GetBridge(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.GetBridgeRequest{Id: mux.Vars(r)["name"]}
	resp, err := h.sdnService.GetBridge(r.Context(), req)
	h.reply(w, r, resp, err)
}

// DeleteBridge handles DELETE /api/v1/sdn/bridges/{name}.
func (h *SDNHandlers) DeleteBridge(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.DeleteBridgeRequest{Id: mux.Vars(r)["name"]}
	resp, err := h.sdnService.DeleteBridge(r.Context(), req)
	h.reply(w, r, resp, err)
}

// Port Handlers

// AddPort handles POST /api/v1/sdn/bridges/{name}/ports with an
// AddPortRequest; the path names the bridge.
func (h *SDNHandlers) AddPort(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.AddPortRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.BridgeId = mux.Vars(r)["name"]
	resp, err := h.sdnService.AddPort(r.Context(), req)
	h.reply(w, r, resp, err)
}

// ListPorts handles GET /api/v1/sdn/bridges/{name}/ports.
func (h *SDNHandlers) ListPorts(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.ListPortsRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.BridgeId = mux.Vars(r)["name"]
	resp, err := h.sdnService.ListPorts(r.Context(), req)
	h.reply(w, r, resp, err)
}

// DeletePort handles DELETE /api/v1/sdn/bridges/{name}/ports/{port}.
func (h *SDNHandlers) DeletePort(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	bridgeID, portID := portPath(r)
	req := &platformv1.DeletePortRequest{BridgeId: bridgeID, PortId: portID}
	resp, err := h.sdnService.DeletePort(r.Context(), req)
	h.reply(w, r, resp, err)
}

// GetPortState handles GET /api/v1/sdn/bridges/{name}/ports/{port}/state;
// it answers the GetPortResponse, whose port carries the state.
func (h *SDNHandlers) GetPortState(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	bridgeID, portID := portPath(r)
	req := &platformv1.GetPortRequest{BridgeId: bridgeID, PortId: portID}
	resp, err := h.sdnService.GetPort(r.Context(), req)
	h.reply(w, r, resp, err)
}

// SetPortState handles PUT /api/v1/sdn/bridges/{name}/ports/{port}/state
// with a SetPortStateRequest; the path names the bridge and port.
func (h *SDNHandlers) SetPortState(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.SetPortStateRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.BridgeId, req.PortId = portPath(r)
	resp, err := h.sdnService.SetPortState(r.Context(), req)
	h.reply(w, r, resp, err)
}

// GetPortStats handles GET /api/v1/sdn/bridges/{name}/ports/{port}/stats.
func (h *SDNHandlers) GetPortStats(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	bridgeID, portID := portPath(r)
	req := &platformv1.GetPortStatsRequest{BridgeId: bridgeID, PortId: portID}
	resp, err := h.sdnService.GetPortStats(r.Context(), req)
	h.reply(w, r, resp, err)
}

// AuthenticatePort handles POST /api/v1/sdn/bridges/{name}/ports/{port}/auth
// with an AuthenticatePortRequest; the path names the bridge and port.
func (h *SDNHandlers) AuthenticatePort(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.AuthenticatePortRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.BridgeId, req.PortId = portPath(r)
	resp, err := h.sdnService.AuthenticatePort(r.Context(), req)
	h.reply(w, r, resp, err)
}

// RevokePortAuth handles DELETE /api/v1/sdn/bridges/{name}/ports/{port}/auth.
func (h *SDNHandlers) RevokePortAuth(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	bridgeID, portID := portPath(r)
	req := &platformv1.RevokePortAuthRequest{BridgeId: bridgeID, PortId: portID}
	resp, err := h.sdnService.RevokePortAuth(r.Context(), req)
	h.reply(w, r, resp, err)
}

// Flow Handlers

// AddFlow handles POST /api/v1/sdn/flows and /api/v1/sdn/bridges/{name}/flows
// with an AddFlowRequest; a bridge in the path is the flow's bridge.
func (h *SDNHandlers) AddFlow(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.AddFlowRequest{}
	if !h.decode(w, r, req) {
		return
	}
	if config := req.GetConfig(); config != nil {
		config.BridgeId = bridgeScope(r, config.GetBridgeId())
	}
	resp, err := h.sdnService.AddFlow(r.Context(), req)
	h.reply(w, r, resp, err)
}

// DeleteFlow handles DELETE /api/v1/sdn/flows with a DeleteFlowRequest body.
func (h *SDNHandlers) DeleteFlow(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.DeleteFlowRequest{}
	if !h.decode(w, r, req) {
		return
	}
	resp, err := h.sdnService.DeleteFlow(r.Context(), req)
	h.reply(w, r, resp, err)
}

// ListFlows handles GET /api/v1/sdn/flows?bridge_id= and
// /api/v1/sdn/bridges/{name}/flows.
func (h *SDNHandlers) ListFlows(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.ListFlowsRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.BridgeId = bridgeScope(r, req.GetBridgeId())
	resp, err := h.sdnService.ListFlows(r.Context(), req)
	h.reply(w, r, resp, err)
}

// Policy Handlers

// ApplyPolicy handles POST /api/v1/sdn/policies with an ApplyPolicyRequest
// and answers 201 with the ApplyPolicyResponse.
func (h *SDNHandlers) ApplyPolicy(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.ApplyPolicyRequest{}
	if !h.decode(w, r, req) {
		return
	}
	resp, err := h.sdnService.ApplyPolicy(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// ListPolicies handles GET /api/v1/sdn/policies; an optional body carries the
// ListPoliciesRequest filters.
func (h *SDNHandlers) ListPolicies(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.ListPoliciesRequest{}
	if !h.decode(w, r, req) {
		return
	}
	resp, err := h.sdnService.ListPolicies(r.Context(), req)
	h.reply(w, r, resp, err)
}

// GetPolicy handles GET /api/v1/sdn/policies/{id}.
func (h *SDNHandlers) GetPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.GetPolicyRequest{PolicyId: mux.Vars(r)["id"]}
	resp, err := h.sdnService.GetPolicy(r.Context(), req)
	h.reply(w, r, resp, err)
}

// VLAN Handlers

// CreateVLAN handles POST /api/v1/sdn/vlans and
// /api/v1/sdn/bridges/{bridge_id}/vlans with a CreateVLANRequest; a bridge in
// the path is the VLAN's bridge.
func (h *SDNHandlers) CreateVLAN(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.CreateVLANRequest{}
	if !h.decode(w, r, req) {
		return
	}
	if config := req.GetConfig(); config != nil {
		config.BridgeId = bridgeScope(r, config.GetBridgeId())
	}
	resp, err := h.sdnService.CreateVLAN(r.Context(), req)
	h.reply(w, r, resp, err)
}

// ListVLANs handles GET /api/v1/sdn/vlans?bridge_id= and
// /api/v1/sdn/bridges/{bridge_id}/vlans.
func (h *SDNHandlers) ListVLANs(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.ListVLANsRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.BridgeId = bridgeScope(r, req.GetBridgeId())
	resp, err := h.sdnService.ListVLANs(r.Context(), req)
	h.reply(w, r, resp, err)
}
