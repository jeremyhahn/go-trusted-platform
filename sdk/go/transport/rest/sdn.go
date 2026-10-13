// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"encoding/json"
	"net/http"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SDN port state (#730). The daemon REST stack (pkg/api/rest/sdn_handlers.go)
// serves set-state as PUT /api/v1/sdn/bridges/{id}/ports/{port}/state; the
// flat row this replaces posted to /api/v1/sdn/ports/state, which no server
// serves. The bridge and port travel in the path, admin_state and the rates
// in the body. The server answers the port's state as Open vSwitch reports
// it, not the gRPC reply, so decodeSDNSetPortState builds the reply from it.
func init() {
	templatedRouteTable[platformv1.SDNService_SetPortState_FullMethodName] = templatedRoute{
		path:   "/api/v1/sdn/bridges/{id}/ports/{port}/state",
		method: http.MethodPut,
		pathParams: []pathParam{
			{placeholder: "{id}", field: "bridge_id"},
			{placeholder: "{port}", field: "port_id"},
		},
	}
	restResponseDecoders[platformv1.SDNService_SetPortState_FullMethodName] = decodeSDNSetPortState
}

// sdnPortState is the subset of the server's port-state answer the gRPC
// reply carries.
type sdnPortState struct {
	BridgeID   string `json:"bridge_id"`
	PortID     string `json:"port_id"`
	AdminState string `json:"admin_state"`
}

// sdnPortStatuses maps the admin state Open vSwitch reports to the gRPC port
// status; any other value is PORT_STATUS_UNSPECIFIED.
var sdnPortStatuses = map[string]platformv1.PortStatus{
	"up":   platformv1.PortStatus_PORT_STATUS_UP,
	"down": platformv1.PortStatus_PORT_STATUS_DOWN,
}

// decodeSDNSetPortState places the port state the server read back from Open
// vSwitch on the SetPortState reply. The REST answer names the port as the
// caller did and carries no OVSDB UUID, so the port's name is set and its ID
// is left empty.
func decodeSDNSetPortState(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.SetPortStateResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_SetPortState_FullMethodName}
	}
	var state sdnPortState
	if err := json.Unmarshal(raw, &state); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Status = &platformv1.Status{Success: true}
	out.Port = &platformv1.Port{
		BridgeId: state.BridgeID,
		Config:   &platformv1.PortConfig{Name: state.PortID},
		Status:   sdnPortStatuses[strings.ToLower(state.AdminState)],
	}
	return nil
}
