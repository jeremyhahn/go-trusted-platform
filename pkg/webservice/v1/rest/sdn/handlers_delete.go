package sdn

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// maxVLANID is the highest usable 802.1Q VLAN id.
const maxVLANID = 4095

// DeleteVLAN handles DELETE /api/v1/sdn/vlans/{vlan_id}?bridge_id=. The
// bridge comes from bridgeScope; a vlan_id that is not a number in 1-4095 is
// a 400 and never reaches the service.
func (h *SDNHandlers) DeleteVLAN(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	raw := mux.Vars(r)["vlan_id"]
	id, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || id < 1 || id > maxVLANID {
		protorest.WriteError(w, r, h.respWriter,
			status.Errorf(codes.InvalidArgument, "vlan_id %q is not a VLAN id in 1-%d", raw, maxVLANID))
		return
	}
	req := &platformv1.DeleteVLANRequest{BridgeId: bridgeScope(r, ""), VlanId: uint32(id)}
	resp, err := h.sdnService.DeleteVLAN(r.Context(), req)
	h.reply(w, r, resp, err)
}

// DeletePolicy handles DELETE /api/v1/sdn/policies/{id}.
func (h *SDNHandlers) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.DeletePolicyRequest{PolicyId: mux.Vars(r)["id"]}
	resp, err := h.sdnService.DeletePolicy(r.Context(), req)
	h.reply(w, r, resp, err)
}
