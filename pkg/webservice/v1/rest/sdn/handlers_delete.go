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
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// maxVLANID is the highest 802.1Q VLAN ID a route may name.
const maxVLANID = 4095

// DeleteVLAN handles DELETE /api/v1/sdn/vlans/{vlan_id}?bridge_id=, the
// shape the daemon serves. A vlan_id outside 1-4095 is a 400.
func (h *SDNHandlers) DeleteVLAN(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	raw := mux.Vars(r)["vlan_id"]
	vlanID, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || vlanID < 1 || vlanID > maxVLANID {
		h.respWriter.Error400(w, r, fmt.Errorf("vlan_id %q is not a VLAN ID in 1-%d", raw, maxVLANID))
		return
	}
	req := &platformv1.DeleteVLANRequest{BridgeId: bridgeScope(r, ""), VlanId: uint32(vlanID)}
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
