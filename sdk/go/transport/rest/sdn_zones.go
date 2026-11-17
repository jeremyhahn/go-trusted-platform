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
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// sdnZonesPath is the collection route the webservice and the daemon
// both serve for network zones.
const sdnZonesPath = "/api/v1/sdn/zones"

// The zone routes take and return the flat REST zone document: the
// zone config fields at the top level (snake_case), with numbering,
// restart_required and timestamps beside them on replies. The proto
// nests the config under "config", so Create and Update flatten the
// request and every reply folds the flat document back into
// NetworkZone. The zone name travels in the path for Update and Delete,
// lifecycle_role in the query for List.
func init() {
	zoneItem := func(method string) templatedRoute {
		return templatedRoute{
			path:       sdnZonesPath + "/{name}",
			method:     method,
			pathParams: []pathParam{{placeholder: "{name}", field: "name"}},
		}
	}
	update := zoneItem(http.MethodPut)
	update.encodeBody = encodeUpdateNetworkZone

	templatedRouteTable[platformv1.SDNService_CreateNetworkZone_FullMethodName] = templatedRoute{
		path: sdnZonesPath, method: http.MethodPost, encodeBody: encodeCreateNetworkZone,
	}
	templatedRouteTable[platformv1.SDNService_ListNetworkZones_FullMethodName] = templatedRoute{
		path: sdnZonesPath, method: http.MethodGet,
		queryParams: []queryParam{{name: "lifecycle_role", field: "lifecycle_role"}},
	}
	templatedRouteTable[platformv1.SDNService_UpdateNetworkZone_FullMethodName] = update
	templatedRouteTable[platformv1.SDNService_DeleteNetworkZone_FullMethodName] = zoneItem(http.MethodDelete)

	restResponseDecoders[platformv1.SDNService_CreateNetworkZone_FullMethodName] = decodeCreateNetworkZone
	restResponseDecoders[platformv1.SDNService_ListNetworkZones_FullMethodName] = decodeListNetworkZones
	restResponseDecoders[platformv1.SDNService_UpdateNetworkZone_FullMethodName] = decodeUpdateNetworkZone
	restResponseDecoders[platformv1.SDNService_DeleteNetworkZone_FullMethodName] = decodeDeleteNetworkZone
}

// zoneConfigJSON writes the zone config with the proto field names the
// REST zone document uses; zoneConfigRead reads the config fields out of
// a flat reply and skips the reply-only ones beside them.
var (
	zoneConfigJSON = protojson.MarshalOptions{UseProtoNames: true}
	zoneConfigRead = protojson.UnmarshalOptions{DiscardUnknown: true}
)

// flatZoneDocument renders a zone config as the flat REST zone document.
func flatZoneDocument(cfg *platformv1.NetworkZoneConfig) (interface{}, error) {
	if cfg == nil {
		cfg = &platformv1.NetworkZoneConfig{}
	}
	raw, err := zoneConfigJSON.Marshal(cfg)
	if err != nil {
		return nil, ErrMarshalFailed{Err: err}
	}
	return json.RawMessage(raw), nil
}

// zoneDocumentOrRefuse refuses omit=true with InvalidArgument before any
// body is built: neither the webservice's NetworkZoneRequest nor the daemon's
// zone spec carries omit, so sending it would create or replace the zone
// while the gRPC path refuses the same request.
func zoneDocumentOrRefuse(cfg *platformv1.NetworkZoneConfig) (interface{}, error) {
	if cfg.GetOmit() {
		return nil, status.Error(codes.InvalidArgument, "network zone omit is not supported over REST")
	}
	return flatZoneDocument(cfg)
}

func encodeCreateNetworkZone(body interface{}) (interface{}, error) {
	req, ok := body.(*platformv1.CreateNetworkZoneRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.SDNService_CreateNetworkZone_FullMethodName}
	}
	return zoneDocumentOrRefuse(req.GetConfig())
}

// encodeUpdateNetworkZone sends the config flat; the name is already in
// the path, and the server refuses a body name that differs from it.
func encodeUpdateNetworkZone(body interface{}) (interface{}, error) {
	req, ok := body.(*platformv1.UpdateNetworkZoneRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.SDNService_UpdateNetworkZone_FullMethodName}
	}
	return zoneDocumentOrRefuse(req.GetConfig())
}

// flatZoneExtras are the reply-only fields of the flat zone document.
type flatZoneExtras struct {
	Numbering *struct {
		VLAN    uint32 `json:"vlan"`
		Subnet4 string `json:"subnet4"`
		Subnet6 string `json:"subnet6"`
		Gateway string `json:"gateway"`
	} `json:"numbering"`
	RestartRequired bool      `json:"restart_required"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// unmarshalFlatZone folds a flat REST zone document into NetworkZone.
func unmarshalFlatZone(raw []byte) (*platformv1.NetworkZone, error) {
	cfg := &platformv1.NetworkZoneConfig{}
	if err := zoneConfigRead.Unmarshal(raw, cfg); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	var extras flatZoneExtras
	if err := json.Unmarshal(raw, &extras); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	zone := &platformv1.NetworkZone{Config: cfg, RestartRequired: extras.RestartRequired}
	if n := extras.Numbering; n != nil {
		zone.Numbering = &platformv1.NetworkZoneNumbering{
			Vlan: n.VLAN, Subnet4: n.Subnet4, Subnet6: n.Subnet6, Gateway: n.Gateway,
		}
	}
	if !extras.CreatedAt.IsZero() {
		zone.CreatedAt = timestamppb.New(extras.CreatedAt)
	}
	if !extras.UpdatedAt.IsZero() {
		zone.UpdatedAt = timestamppb.New(extras.UpdatedAt)
	}
	return zone, nil
}

func decodeCreateNetworkZone(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.CreateNetworkZoneResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_CreateNetworkZone_FullMethodName}
	}
	zone, err := unmarshalFlatZone(raw)
	if err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: true}
	out.Zone = zone
	return nil
}

func decodeUpdateNetworkZone(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.UpdateNetworkZoneResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_UpdateNetworkZone_FullMethodName}
	}
	zone, err := unmarshalFlatZone(raw)
	if err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: true}
	out.Zone = zone
	return nil
}

// decodeListNetworkZones reads {zones, count, timestamp}; count and
// timestamp have no place in ListNetworkZonesResponse.
func decodeListNetworkZones(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ListNetworkZonesResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_ListNetworkZones_FullMethodName}
	}
	var list struct {
		Zones []json.RawMessage `json:"zones"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	zones := make([]*platformv1.NetworkZone, 0, len(list.Zones))
	for _, item := range list.Zones {
		zone, err := unmarshalFlatZone(item)
		if err != nil {
			return err
		}
		zones = append(zones, zone)
	}
	out.Zones = zones
	return nil
}

// decodeDeleteNetworkZone reads {deleted, restart_required}.
func decodeDeleteNetworkZone(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.DeleteNetworkZoneResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_DeleteNetworkZone_FullMethodName}
	}
	var deleted struct {
		Deleted         bool `json:"deleted"`
		RestartRequired bool `json:"restart_required"`
	}
	if err := json.Unmarshal(raw, &deleted); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Status = &platformv1.Status{Success: deleted.Deleted}
	out.RestartRequired = deleted.RestartRequired
	return nil
}
