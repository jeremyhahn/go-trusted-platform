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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
)

// Physical switch ports (#452). The daemon REST stack
// (pkg/webservice/v1/rest/switch/router.go) serves every port operation under
// /api/v1/switches/{switch}/ports; the flat rows these replace sent the
// switch and port in the body to /api/v1/switches/ports/..., which no server
// serves. The switch and port travel in the path, escaped so a port name
// such as Eth1/3 arrives as one segment; only the VLAN travels in the body.
//
// The server answers port reads as switchwire.PortStatus and the mutators
// with a {"status":"ok"} acknowledgement, not the gRPC replies, so the
// decoders below build the replies from them.
func init() {
	templatedRouteTable[platformv1.SwitchService_ListPorts_FullMethodName] =
		itemRoute("/api/v1/switches/{switch}/ports", http.MethodGet, "{switch}", "switch_name")
	templatedRouteTable[platformv1.SwitchService_GetPortStatus_FullMethodName] = switchPortRoute("", http.MethodGet)
	templatedRouteTable[platformv1.SwitchService_SetPortVLAN_FullMethodName] = switchPortRoute("/vlan", http.MethodPost)
	templatedRouteTable[platformv1.SwitchService_EnablePort_FullMethodName] = switchPortRoute("/enable", http.MethodPost)
	templatedRouteTable[platformv1.SwitchService_DisablePort_FullMethodName] = switchPortRoute("/disable", http.MethodPost)

	restResponseDecoders[platformv1.SwitchService_ListPorts_FullMethodName] = decodeSwitchListPorts
	restResponseDecoders[platformv1.SwitchService_GetPortStatus_FullMethodName] = decodeSwitchGetPortStatus
	restResponseDecoders[platformv1.SwitchService_SetPortVLAN_FullMethodName] = decodeSwitchSetPortVLAN
	restResponseDecoders[platformv1.SwitchService_EnablePort_FullMethodName] = decodeSwitchEnablePort
	restResponseDecoders[platformv1.SwitchService_DisablePort_FullMethodName] = decodeSwitchDisablePort
}

// The status messages the gRPC service answers the mutators with
// (pkg/api/daemon/switch_grpc_service.go), so a caller sees the same reply on
// either transport.
const (
	switchVLANUpdatedMessage  = "port VLAN updated successfully"
	switchPortEnabledMessage  = "port enabled successfully"
	switchPortDisabledMessage = "port disabled successfully"
)

// switchAckOK is the status the REST port mutators answer on success.
const switchAckOK = "ok"

// switchPortRoute is the route of one port on one switch, plus suffix.
func switchPortRoute(suffix, method string) templatedRoute {
	return templatedRoute{
		path:   "/api/v1/switches/{switch}/ports/{port}" + suffix,
		method: method,
		pathParams: []pathParam{
			{placeholder: "{switch}", field: "switch_name"},
			{placeholder: "{port}", field: "port_name"},
		},
	}
}

// switchAck is the part of a port mutator's REST answer the gRPC reply
// carries.
type switchAck struct {
	Status string `json:"status"`
}

// decodeSwitchListPorts places the server's port list on the ListPorts reply.
func decodeSwitchListPorts(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ListSwitchPortsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SwitchService_ListPorts_FullMethodName}
	}
	var ports []*switchwire.PortStatus
	if err := json.Unmarshal(raw, &ports); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Ports = make([]*platformv1.SwitchPortStatus, 0, len(ports))
	for _, port := range ports {
		out.Ports = append(out.Ports, switchPortStatusToProto(port))
	}
	return nil
}

// decodeSwitchGetPortStatus places the server's port on the GetPortStatus
// reply.
func decodeSwitchGetPortStatus(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetSwitchPortStatusResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SwitchService_GetPortStatus_FullMethodName}
	}
	var port switchwire.PortStatus
	if err := json.Unmarshal(raw, &port); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Port = switchPortStatusToProto(&port)
	return nil
}

// decodeSwitchSetPortVLAN turns the server's acknowledgement into the
// SetPortVLAN reply.
func decodeSwitchSetPortVLAN(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.SetSwitchPortVLANResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SwitchService_SetPortVLAN_FullMethodName}
	}
	status, err := switchAckStatus(platformv1.SwitchService_SetPortVLAN_FullMethodName, raw, switchVLANUpdatedMessage)
	if err != nil {
		return err
	}
	out.Status = status
	return nil
}

// decodeSwitchEnablePort turns the server's acknowledgement into the
// EnablePort reply.
func decodeSwitchEnablePort(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.EnableSwitchPortResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SwitchService_EnablePort_FullMethodName}
	}
	status, err := switchAckStatus(platformv1.SwitchService_EnablePort_FullMethodName, raw, switchPortEnabledMessage)
	if err != nil {
		return err
	}
	out.Status = status
	return nil
}

// decodeSwitchDisablePort turns the server's acknowledgement into the
// DisablePort reply.
func decodeSwitchDisablePort(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.DisableSwitchPortResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SwitchService_DisablePort_FullMethodName}
	}
	status, err := switchAckStatus(platformv1.SwitchService_DisablePort_FullMethodName, raw, switchPortDisabledMessage)
	if err != nil {
		return err
	}
	out.Status = status
	return nil
}

// switchAckStatus reads a port mutator's acknowledgement and returns the
// gRPC status for it. An answer whose status is not "ok" did not acknowledge
// the change, so it is an error rather than a failed status.
func switchAckStatus(method string, raw []byte, message string) (*platformv1.Status, error) {
	var ack switchAck
	if err := json.Unmarshal(raw, &ack); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	if ack.Status != switchAckOK {
		return nil, ErrSwitchActionNotAcknowledged{Method: method, Status: ack.Status}
	}
	return &platformv1.Status{Success: true, Message: message}, nil
}

// switchPortStatusToProto converts the server's port to the gRPC port,
// widening the VLANs the way the gRPC service does.
func switchPortStatusToProto(port *switchwire.PortStatus) *platformv1.SwitchPortStatus {
	if port == nil {
		return nil
	}
	trunkVLANs := make([]uint32, 0, len(port.TrunkVLANs))
	for _, vlan := range port.TrunkVLANs {
		trunkVLANs = append(trunkVLANs, uint32(vlan))
	}
	return &platformv1.SwitchPortStatus{
		Port:        port.Port,
		Mode:        string(port.Mode),
		AccessVlan:  uint32(port.AccessVLAN),
		TrunkVlans:  trunkVLANs,
		Enabled:     port.Enabled,
		LinkUp:      port.LinkUp,
		Description: port.Description,
		NativeVlan:  uint32(port.NativeVLAN),
	}
}
