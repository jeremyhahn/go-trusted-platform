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

package mcp

import (
	"encoding/json"
	"math"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SDN network zone MCP mapping. The daemon's gateway_zone_* tools take the
// zone fields under the pb NetworkZoneConfig JSON names and answer with the
// gateway ZoneView (pkg/sdn/gateway/zone_view.go): the flattened zone, its
// numbering, whether the change needs a restart, and RFC 3339 timestamps.

// zoneViewWire is the part of a ZoneView that is not the zone itself.
type zoneViewWire struct {
	Numbering       *platformv1.NetworkZoneNumbering `json:"numbering"`
	RestartRequired bool                             `json:"restart_required"`
	CreatedAt       time.Time                        `json:"created_at"`
	UpdatedAt       time.Time                        `json:"updated_at"`
}

func init() {
	for method, tool := range map[string]string{
		platformv1.SDNService_ListNetworkZones_FullMethodName:  "gateway_zone_list",
		platformv1.SDNService_CreateNetworkZone_FullMethodName: "gateway_zone_create",
		platformv1.SDNService_UpdateNetworkZone_FullMethodName: "gateway_zone_update",
		platformv1.SDNService_DeleteNetworkZone_FullMethodName: "gateway_zone_delete",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}

	mcpArgBuilders[platformv1.SDNService_CreateNetworkZone_FullMethodName] = buildSDNCreateNetworkZoneArgs
	mcpArgBuilders[platformv1.SDNService_UpdateNetworkZone_FullMethodName] = buildSDNUpdateNetworkZoneArgs

	for method, decode := range map[string]mcpReplyDecoder{
		platformv1.SDNService_ListNetworkZones_FullMethodName:  decodeSDNListNetworkZonesResult,
		platformv1.SDNService_CreateNetworkZone_FullMethodName: decodeSDNCreateNetworkZoneResult,
		platformv1.SDNService_UpdateNetworkZone_FullMethodName: decodeSDNUpdateNetworkZoneResult,
	} {
		mcpReplyDecoders[method] = decode
	}
}

// zoneArgs sends a zone config under its pb JSON names. The tools have no
// omit argument (deleting a built-in zone omits it) and hold the offset in
// a byte, so a config needing either is refused.
func zoneArgs(method string, config *platformv1.NetworkZoneConfig) (map[string]interface{}, error) {
	if config.GetOmit() {
		return nil, ErrFieldNotSupported{Method: method, Field: "config.omit"}
	}
	if config.GetOffset() > math.MaxUint8 {
		return nil, ErrValueOutOfRange{Field: "config.offset", Value: uint64(config.GetOffset()), Max: math.MaxUint8}
	}
	return structToMap(config)
}

func buildSDNCreateNetworkZoneArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.SDNService_CreateNetworkZone_FullMethodName
	in, ok := args.(*platformv1.CreateNetworkZoneRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	return zoneArgs(method, in.GetConfig())
}

// buildSDNUpdateNetworkZoneArgs names the zone by the request's name; the
// tool has no way to rename, so a config naming another zone is refused.
func buildSDNUpdateNetworkZoneArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.SDNService_UpdateNetworkZone_FullMethodName
	in, ok := args.(*platformv1.UpdateNetworkZoneRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	if name := in.GetConfig().GetName(); name != "" && name != in.GetName() {
		return nil, ErrFieldNotSupported{Method: method, Field: "config.name"}
	}
	out, err := zoneArgs(method, in.GetConfig())
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]interface{}{}
	}
	out["name"] = in.GetName()
	return out, nil
}

// decodeZoneView converts one ZoneView to the pb NetworkZone.
func decodeZoneView(raw []byte) (*platformv1.NetworkZone, error) {
	config := &platformv1.NetworkZoneConfig{}
	if err := json.Unmarshal(raw, config); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	var view zoneViewWire
	if err := json.Unmarshal(raw, &view); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return &platformv1.NetworkZone{
		Config:          config,
		CreatedAt:       timestampOrNil(view.CreatedAt),
		UpdatedAt:       timestampOrNil(view.UpdatedAt),
		RestartRequired: view.RestartRequired,
		Numbering:       view.Numbering,
	}, nil
}

// decodeZoneResult decodes the single ZoneView a tool answers with.
func decodeZoneResult(result interface{}) (*platformv1.NetworkZone, error) {
	raw, err := resultJSON(result)
	if err != nil {
		return nil, err
	}
	return decodeZoneView(raw)
}

func decodeSDNListNetworkZonesResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListNetworkZonesResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_ListNetworkZones_FullMethodName}
	}
	var wire struct {
		Zones []json.RawMessage `json:"zones"`
	}
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	zones := make([]*platformv1.NetworkZone, 0, len(wire.Zones))
	for _, raw := range wire.Zones {
		zone, err := decodeZoneView(raw)
		if err != nil {
			return err
		}
		zones = append(zones, zone)
	}
	out.Zones = zones
	return nil
}

func decodeSDNCreateNetworkZoneResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.CreateNetworkZoneResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_CreateNetworkZone_FullMethodName}
	}
	zone, err := decodeZoneResult(result)
	if err != nil {
		return err
	}
	out.Zone = zone
	return nil
}

func decodeSDNUpdateNetworkZoneResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.UpdateNetworkZoneResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_UpdateNetworkZone_FullMethodName}
	}
	zone, err := decodeZoneResult(result)
	if err != nil {
		return err
	}
	out.Zone = zone
	return nil
}
