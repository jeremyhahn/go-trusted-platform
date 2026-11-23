package sdn

import (
	"net/http"

	"github.com/gorilla/mux"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// FlushFlows serves POST /api/v1/sdn/bridges/{name}/flows/flush: it deletes
// the flows of the path bridge, in the body's table when one is given.
func (h *SDNHandlers) FlushFlows(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.FlushFlowsRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.BridgeId = bridgeScope(r, req.GetBridgeId())
	resp, err := h.sdnService.FlushFlows(r.Context(), req)
	h.reply(w, r, resp, err)
}

// GetFlowStats serves GET /api/v1/sdn/bridges/{name}/flows/{flow}/stats: it
// reads the packet and byte counters of one flow on the path bridge.
func (h *SDNHandlers) GetFlowStats(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.GetFlowStatsRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.BridgeId = bridgeScope(r, req.GetBridgeId())
	req.FlowId = mux.Vars(r)["flow"]
	resp, err := h.sdnService.GetFlowStats(r.Context(), req)
	h.reply(w, r, resp, err)
}
