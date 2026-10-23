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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// zoneViewResult is a zone as the gateway_zone_* tools answer with it.
func zoneViewResult() map[string]interface{} {
	return map[string]interface{}{
		"name":              "lab",
		"offset":            7,
		"port_classes":      []interface{}{"access"},
		"allow_to":          []interface{}{map[string]interface{}{"zone": "mgmt", "services": []interface{}{"ssh"}}},
		"privileged_access": map[string]interface{}{"reason": "bmc", "approved_by": "ops"},
		"numbering":         map[string]interface{}{"vlan": 107, "subnet4": "10.7.0.0/24", "gateway": "10.7.0.1"},
		"restart_required":  true,
		"created_at":        "2026-01-02T03:04:05Z",
		"updated_at":        "0001-01-01T00:00:00Z",
	}
}

func requireZone(t *testing.T, zone *platformv1.NetworkZone) {
	t.Helper()
	config := zone.GetConfig()
	if config.GetName() != "lab" || config.GetOffset() != 7 || config.GetPortClasses()[0] != "access" ||
		config.GetAllowTo()[0].GetZone() != "mgmt" || config.GetAllowTo()[0].GetServices()[0] != "ssh" ||
		config.GetPrivilegedAccess().GetApprovedBy() != "ops" {
		t.Errorf("config = %+v", config)
	}
	if numbering := zone.GetNumbering(); numbering.GetVlan() != 107 || numbering.GetSubnet4() != "10.7.0.0/24" ||
		numbering.GetGateway() != "10.7.0.1" {
		t.Errorf("numbering = %+v", numbering)
	}
	if !zone.GetRestartRequired() || zone.GetCreatedAt().AsTime().Year() != 2026 || zone.GetUpdatedAt() != nil {
		t.Errorf("zone = %+v", zone)
	}
}

func TestSDNMCP_CreateNetworkZone_RoundTrip(t *testing.T) {
	reply := &platformv1.CreateNetworkZoneResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{"gateway_zone_create": zoneViewResult()},
		platformv1.SDNService_CreateNetworkZone_FullMethodName, &platformv1.CreateNetworkZoneRequest{
			Config: &platformv1.NetworkZoneConfig{
				Name: "lab", Offset: 7, PortClasses: []string{"access"},
				AllowTo:          []*platformv1.NetworkZonePath{{Zone: "mgmt", Services: []string{"ssh"}}},
				PrivilegedAccess: &platformv1.NetworkZonePrivilegedAccess{Reason: "bmc", ApprovedBy: "ops"},
			},
		}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	args := calls[0].Arguments
	if args["name"] != "lab" || args["offset"] != float64(7) || args["port_classes"].([]interface{})[0] != "access" {
		t.Errorf("zone args = %+v", args)
	}
	if path := args["allow_to"].([]interface{})[0].(map[string]interface{}); path["zone"] != "mgmt" {
		t.Errorf("allow_to = %+v", path)
	}
	if access := args["privileged_access"].(map[string]interface{}); access["approved_by"] != "ops" {
		t.Errorf("privileged_access = %+v", access)
	}
	requireZone(t, reply.GetZone())
}

func TestSDNMCP_UpdateNetworkZone_RoundTrip(t *testing.T) {
	reply := &platformv1.UpdateNetworkZoneResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{"gateway_zone_update": zoneViewResult()},
		platformv1.SDNService_UpdateNetworkZone_FullMethodName, &platformv1.UpdateNetworkZoneRequest{
			Name: "lab", Config: &platformv1.NetworkZoneConfig{Isolate: true},
		}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if args := calls[0].Arguments; args["name"] != "lab" || args["isolate"] != true {
		t.Errorf("zone args = %+v", args)
	}
	requireZone(t, reply.GetZone())
}

// TestSDNMCP_UpdateNetworkZone_NoConfig checks an update without a config
// still names the zone.
func TestSDNMCP_UpdateNetworkZone_NoConfig(t *testing.T) {
	calls, err := invokePhase35(t, map[string]interface{}{"gateway_zone_update": zoneViewResult()},
		platformv1.SDNService_UpdateNetworkZone_FullMethodName,
		&platformv1.UpdateNetworkZoneRequest{Name: "lab"}, &platformv1.UpdateNetworkZoneResponse{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if args := calls[0].Arguments; len(args) != 1 || args["name"] != "lab" {
		t.Errorf("zone args = %+v", args)
	}
}

func TestSDNMCP_ListNetworkZones_RoundTrip(t *testing.T) {
	reply := &platformv1.ListNetworkZonesResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{
		"gateway_zone_list": map[string]interface{}{"zones": []interface{}{zoneViewResult()}},
	}, platformv1.SDNService_ListNetworkZones_FullMethodName,
		&platformv1.ListNetworkZonesRequest{LifecycleRole: "build"}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["lifecycle_role"] != "build" {
		t.Errorf("call = %+v", calls[0])
	}
	if len(reply.GetZones()) != 1 {
		t.Fatalf("zones = %+v", reply.GetZones())
	}
	requireZone(t, reply.GetZones()[0])
}

func TestSDNMCP_DeleteNetworkZone_RoundTrip(t *testing.T) {
	reply := &platformv1.DeleteNetworkZoneResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{
		"gateway_zone_delete": map[string]interface{}{"success": true, "restart_required": true},
	}, platformv1.SDNService_DeleteNetworkZone_FullMethodName,
		&platformv1.DeleteNetworkZoneRequest{Name: "lab"}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["name"] != "lab" || !reply.GetRestartRequired() {
		t.Errorf("call = %+v, reply = %+v", calls[0], reply)
	}
}

// TestSDNMCP_NetworkZone_OffsetOutOfRange checks an offset the tool's byte
// cannot hold is refused instead of wrapping to another zone's offset.
func TestSDNMCP_NetworkZone_OffsetOutOfRange(t *testing.T) {
	calls, err := invokePhase35(t, map[string]interface{}{},
		platformv1.SDNService_CreateNetworkZone_FullMethodName,
		&platformv1.CreateNetworkZoneRequest{Config: &platformv1.NetworkZoneConfig{Name: "lab", Offset: 256}}, nil)
	requireCode(t, err, codes.InvalidArgument)
	want := ErrValueOutOfRange{Field: "config.offset", Value: 256, Max: 255}.Error()
	if status.Convert(err).Message() != want {
		t.Errorf("message = %q, want %q", status.Convert(err).Message(), want)
	}
	if len(calls) != 0 {
		t.Errorf("a refused request reached the tool: %+v", calls)
	}
}

func TestSDNMCP_NetworkZoneDecoders_RejectMalformedResult(t *testing.T) {
	malformed := zoneViewResult()
	malformed["offset"] = "seven"
	for method, reply := range map[string]interface{}{
		platformv1.SDNService_CreateNetworkZone_FullMethodName: &platformv1.CreateNetworkZoneResponse{},
		platformv1.SDNService_UpdateNetworkZone_FullMethodName: &platformv1.UpdateNetworkZoneResponse{},
	} {
		if err := mcpReplyDecoders[method](malformed, reply); err == nil {
			t.Errorf("%s decoded a malformed zone", method)
		}
	}

	badView := zoneViewResult()
	badView["created_at"] = "yesterday"
	if _, err := decodeZoneResult(badView); err == nil {
		t.Error("decoded a zone with a malformed timestamp")
	}

	for _, result := range []interface{}{
		"not an object",
		map[string]interface{}{"zones": []interface{}{malformed}},
	} {
		if err := decodeSDNListNetworkZonesResult(result, &platformv1.ListNetworkZonesResponse{}); err == nil {
			t.Errorf("ListNetworkZones decoded %v", result)
		}
	}

	_, err := invokePhase35(t, map[string]interface{}{"gateway_zone_create": malformed},
		platformv1.SDNService_CreateNetworkZone_FullMethodName,
		&platformv1.CreateNetworkZoneRequest{Config: &platformv1.NetworkZoneConfig{Name: "lab"}},
		&platformv1.CreateNetworkZoneResponse{})
	requireCode(t, err, codes.Internal)
}
