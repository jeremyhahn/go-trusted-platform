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
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdnsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
)

// SDN port state (#730). The daemon REST stack (pkg/api/rest/sdn_handlers.go)
// serves set-state as PUT /api/v1/sdn/bridges/{id}/ports/{port}/state; the
// flat row this replaces posted to /api/v1/sdn/ports/state, which no server
// serves. The bridge and port travel in the path, admin_state and the rates
// in the body. The server answers the port's state as Open vSwitch reports
// it, not the gRPC reply, so decodeSDNSetPortState builds the reply from it.
//
// Bridges, ports and port authentication (#452). The webservice router
// (pkg/webservice/v1/rest/sdn/router.go) serves them on bridge- and
// port-scoped paths; the flat rows these replace sent the IDs in the body to
// /api/v1/sdn/bridges, /api/v1/sdn/ports and /api/v1/sdn/ports/auth, none of
// which serves the operation. The server answers REST documents rather than
// the gRPC replies, so each method has a decoder, and AddPort's body is the
// flat REST port document.
func init() {
	sdnRoutes := map[string]templatedRoute{
		platformv1.SDNService_SetPortState_FullMethodName: {
			path:       "/api/v1/sdn/bridges/{id}/ports/{port}/state",
			method:     http.MethodPut,
			pathParams: sdnPortPathParams,
		},
		platformv1.SDNService_DeleteBridge_FullMethodName: itemRoute("/api/v1/sdn/bridges/{id}", http.MethodDelete, "{id}", "id"),
		platformv1.SDNService_AddPort_FullMethodName:      itemRoute("/api/v1/sdn/bridges/{id}/ports", http.MethodPost, "{id}", "bridge_id"),
		platformv1.SDNService_DeletePort_FullMethodName: {
			path:       "/api/v1/sdn/bridges/{id}/ports/{port}",
			method:     http.MethodDelete,
			pathParams: sdnPortPathParams,
		},
		platformv1.SDNService_AuthenticatePort_FullMethodName: {
			path:       "/api/v1/sdn/bridges/{id}/ports/{port}/auth",
			method:     http.MethodPost,
			pathParams: sdnPortPathParams,
		},
		platformv1.SDNService_RevokePortAuth_FullMethodName: {
			path:       "/api/v1/sdn/bridges/{id}/ports/{port}/auth",
			method:     http.MethodDelete,
			pathParams: sdnPortPathParams,
		},
	}
	for method, route := range sdnRoutes {
		templatedRouteTable[method] = route
	}

	restRequestEncoders[platformv1.SDNService_AddPort_FullMethodName] = requestEncoder(
		platformv1.SDNService_AddPort_FullMethodName, encodeSDNAddPort)

	restResponseDecoders[platformv1.SDNService_SetPortState_FullMethodName] = decodeSDNSetPortState
	restResponseDecoders[platformv1.SDNService_AddPort_FullMethodName] = wireDecoder(
		platformv1.SDNService_AddPort_FullMethodName, decodeSDNAddPort)
	restResponseDecoders[platformv1.SDNService_AuthenticatePort_FullMethodName] = wireDecoder(
		platformv1.SDNService_AuthenticatePort_FullMethodName, decodeSDNAuthenticatePort)
	restResponseDecoders[platformv1.SDNService_DeleteBridge_FullMethodName] = sdnStatusDecoder(
		platformv1.SDNService_DeleteBridge_FullMethodName,
		func(s *platformv1.Status) *platformv1.DeleteBridgeResponse {
			return &platformv1.DeleteBridgeResponse{Status: s}
		})
	restResponseDecoders[platformv1.SDNService_DeletePort_FullMethodName] = sdnStatusDecoder(
		platformv1.SDNService_DeletePort_FullMethodName,
		func(s *platformv1.Status) *platformv1.DeletePortResponse {
			return &platformv1.DeletePortResponse{Status: s}
		})
	restResponseDecoders[platformv1.SDNService_RevokePortAuth_FullMethodName] = sdnStatusDecoder(
		platformv1.SDNService_RevokePortAuth_FullMethodName,
		func(s *platformv1.Status) *platformv1.RevokePortAuthResponse {
			return &platformv1.RevokePortAuthResponse{Status: s}
		})

	// ApplyPolicy posts to /api/v1/sdn/policies (pkg/api/rest CreatePolicyRequest):
	// the config is flattened, policy_id travels as id and the enums as
	// lowercase names. The server answers the applied policy, not the gRPC
	// reply. The MCP transport speaks the same JSON through the same codec.
	const applyPolicy = platformv1.SDNService_ApplyPolicy_FullMethodName
	restRequestEncoders[applyPolicy] = requestEncoder(applyPolicy, sdnsdk.EncodeApplyPolicyRequest)
	restResponseDecoders[applyPolicy] = wireDecoder(applyPolicy, sdnsdk.DecodeApplyPolicyJSON)
}

// sdnPortPathParams places a port-scoped call's bridge and port in the path.
var sdnPortPathParams = []pathParam{
	{placeholder: "{id}", field: "bridge_id"},
	{placeholder: "{port}", field: "port_id"},
}

// sdnPortTypePrefix is the prefix the pb port type names carry and the REST
// port document drops: PORT_TYPE_TAP travels as "tap".
const sdnPortTypePrefix = "PORT_TYPE_"

// encodeSDNAddPort sends the port's configuration as the flat REST port
// document. The bridge travels in the path.
func encodeSDNAddPort(in *platformv1.AddPortRequest) (map[string]interface{}, error) {
	config := in.GetConfig()
	portType, err := sdnPortTypeName(config.GetType())
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"name":        config.GetName(),
		"type":        portType,
		"vlan":        config.GetVlan(),
		"trunk_vlans": config.GetTrunkVlans(),
		"mac_address": config.GetMacAddress(),
		"mtu":         config.GetMtu(),
		"promiscuous": config.GetPromiscuous(),
		"options":     config.GetOptions(),
		"labels":      config.GetLabels(),
	}, nil
}

// sdnPortTypeName is the REST name of a pb port type. An unspecified type is
// sent empty, which the server takes as internal; a value outside the enum is
// refused rather than sent as a type the server would not recognise.
func sdnPortTypeName(t platformv1.PortType) (string, error) {
	if t == platformv1.PortType_PORT_TYPE_UNSPECIFIED {
		return "", nil
	}
	if _, ok := platformv1.PortType_name[int32(t)]; !ok {
		return "", ErrUnknownPortType{Type: int32(t)}
	}
	return strings.ToLower(strings.TrimPrefix(t.String(), sdnPortTypePrefix)), nil
}

// sdnPort is the REST port document the server answers AddPort with.
type sdnPort struct {
	ID        string            `json:"id"`
	BridgeID  string            `json:"bridge_id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	VLAN      uint32            `json:"vlan"`
	Status    string            `json:"status"`
	CreatedAt *time.Time        `json:"created_at"`
	UpdatedAt *time.Time        `json:"updated_at"`
	Options   map[string]string `json:"options"`
	Labels    map[string]string `json:"labels"`
}

// decodeSDNAddPort builds the AddPort reply from the port the server added.
// A type or status name outside the pb enums decodes as unspecified.
func decodeSDNAddPort(raw []byte) (*platformv1.AddPortResponse, error) {
	var port sdnPort
	if err := json.Unmarshal(raw, &port); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return &platformv1.AddPortResponse{
		Status: &platformv1.Status{Success: true},
		Port: &platformv1.Port{
			Id:       port.ID,
			BridgeId: port.BridgeID,
			Config: &platformv1.PortConfig{
				Name:    port.Name,
				Type:    platformv1.PortType(platformv1.PortType_value[sdnPortTypePrefix+strings.ToUpper(port.Type)]),
				Vlan:    port.VLAN,
				Options: port.Options,
				Labels:  port.Labels,
			},
			Status:    platformv1.PortStatus(platformv1.PortStatus_value["PORT_STATUS_"+strings.ToUpper(port.Status)]),
			CreatedAt: sdnTimestamp(port.CreatedAt),
			UpdatedAt: sdnTimestamp(port.UpdatedAt),
		},
	}, nil
}

// sdnPortAuth is the REST port authentication state the server answers
// AuthenticatePort with. It does not echo the certificate the caller sent.
type sdnPortAuth struct {
	Authenticated   bool       `json:"authenticated"`
	CertificateCN   string     `json:"certificate_cn"`
	AuthenticatedAt *time.Time `json:"authenticated_at"`
	ExpiresAt       *time.Time `json:"expires_at"`
	AuthorizedVLANs []uint32   `json:"authorized_vlans"`
}

// decodeSDNAuthenticatePort builds the AuthenticatePort reply from the
// port's authentication state.
func decodeSDNAuthenticatePort(raw []byte) (*platformv1.AuthenticatePortResponse, error) {
	var auth sdnPortAuth
	if err := json.Unmarshal(raw, &auth); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return &platformv1.AuthenticatePortResponse{
		Status: &platformv1.Status{Success: true},
		Auth: &platformv1.PortAuth{
			Authenticated:   auth.Authenticated,
			CertificateCn:   auth.CertificateCN,
			AuthenticatedAt: sdnTimestamp(auth.AuthenticatedAt),
			ExpiresAt:       sdnTimestamp(auth.ExpiresAt),
			AuthorizedVlans: auth.AuthorizedVLANs,
		},
	}, nil
}

// sdnTimestamp converts an optional REST time to a pb timestamp.
func sdnTimestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

// sdnStatus is the {success, message} answer of the SDN delete and revoke
// routes.
type sdnStatus struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// sdnStatusDecoder builds a restResponseDecoder for a method whose reply is
// only a Status: it decodes the server's {success, message} answer and wraps
// it in the reply with wrap.
func sdnStatusDecoder[R any, P interface {
	*R
	proto.Message
}](method string, wrap func(*platformv1.Status) P) restResponseDecoder {
	return wireDecoder(method, func(raw []byte) (P, error) {
		var answer sdnStatus
		if err := json.Unmarshal(raw, &answer); err != nil {
			return nil, ErrUnmarshalFailed{Err: err}
		}
		return wrap(&platformv1.Status{Success: answer.Success, Message: answer.Message}), nil
	})
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
