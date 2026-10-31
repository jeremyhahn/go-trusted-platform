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

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SDN bridges, ports, flows, policies and VLANs (#452, #445). The webservice
// SDN router (pkg/webservice/v1/rest/sdn/router.go) keys a bridge by the ID
// in the path and a port by its bridge and port in the path, as
// docs/sdn/api-reference-rest.md specifies.
//
// The server decodes the proto requests and answers the proto replies with
// protojson. Every SDN request body is sent as protojson too: the default
// encoding/json rendering spells enums as numbers and fields in snake_case,
// and carries bytes and 64-bit integers in shapes protojson cannot read.
// Replies need no translation. The network-zone methods are left out: the
// zone routes keep the REST zone document the web console reads.
func init() {
	methods := platformv1.File_sdn_proto.Services().ByName("SDNService").Methods()
	for i := range methods.Len() {
		method := methods.Get(i)
		if sdnRESTShapeMethods[method.Name()] {
			continue
		}
		fullName := "/" + platformv1.SDNService_ServiceDesc.ServiceName + "/" + string(method.Name())
		restRequestEncoders[fullName] = sdnBodyEncoder(fullName, method.Input().FullName())
	}

	sdnRoutes := map[string]templatedRoute{
		platformv1.SDNService_GetBridge_FullMethodName:        itemRoute("/api/v1/sdn/bridges/{id}", http.MethodGet, "{id}", "id"),
		platformv1.SDNService_DeleteBridge_FullMethodName:     itemRoute("/api/v1/sdn/bridges/{id}", http.MethodDelete, "{id}", "id"),
		platformv1.SDNService_AddPort_FullMethodName:          itemRoute("/api/v1/sdn/bridges/{id}/ports", http.MethodPost, "{id}", "bridge_id"),
		platformv1.SDNService_ListPorts_FullMethodName:        itemRoute("/api/v1/sdn/bridges/{id}/ports", http.MethodGet, "{id}", "bridge_id"),
		platformv1.SDNService_DeletePort_FullMethodName:       sdnPortRoute("", http.MethodDelete),
		platformv1.SDNService_GetPort_FullMethodName:          sdnPortRoute("/state", http.MethodGet),
		platformv1.SDNService_SetPortState_FullMethodName:     sdnPortRoute("/state", http.MethodPut),
		platformv1.SDNService_GetPortStats_FullMethodName:     sdnPortRoute("/stats", http.MethodGet),
		platformv1.SDNService_AuthenticatePort_FullMethodName: sdnPortRoute("/auth", http.MethodPost),
		platformv1.SDNService_RevokePortAuth_FullMethodName:   sdnPortRoute("/auth", http.MethodDelete),
		platformv1.SDNService_ListVLANs_FullMethodName: {
			path:        "/api/v1/sdn/vlans",
			method:      http.MethodGet,
			queryParams: []queryParam{{name: "bridge_id", field: "bridge_id"}},
		},
	}
	for method, route := range sdnRoutes {
		templatedRouteTable[method] = route
	}
}

// sdnRESTShapeMethods are the SDNService methods whose routes keep a REST
// document rather than the proto request.
var sdnRESTShapeMethods = map[protoreflect.Name]bool{
	"CreateNetworkZone": true,
	"UpdateNetworkZone": true,
	"DeleteNetworkZone": true,
	"ListNetworkZones":  true,
}

// sdnPortRoute is the port-scoped route /api/v1/sdn/bridges/{id}/ports/{port}
// followed by suffix; the bridge and port travel in the path.
func sdnPortRoute(suffix, method string) templatedRoute {
	return templatedRoute{
		path:   "/api/v1/sdn/bridges/{id}/ports/{port}" + suffix,
		method: method,
		pathParams: []pathParam{
			{placeholder: "{id}", field: "bridge_id"},
			{placeholder: "{port}", field: "port_id"},
		},
	}
}

// sdnBodyJSON writes SDN request bodies in the proto JSON mapping the
// server's protorest decoder reads.
var sdnBodyJSON = protojson.MarshalOptions{}

// sdnBodyEncoder sends an SDN request (the clone with its path and query
// fields cleared, for a templated route) as its protojson body.
func sdnBodyEncoder(method string, input protoreflect.FullName) restRequestEncoder {
	return func(body interface{}) (interface{}, error) {
		msg, ok := body.(proto.Message)
		if !ok || msg == nil || msg.ProtoReflect().Descriptor().FullName() != input {
			return nil, ErrUnexpectedRequestType{Method: method}
		}
		raw, err := sdnBodyJSON.Marshal(msg)
		if err != nil {
			return nil, ErrMarshalFailed{Err: err}
		}
		return json.RawMessage(raw), nil
	}
}
