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
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SDN MCP mapping for every SDNService method the platformctl sdn commands
// call. The daemon's sdn_* tools (pkg/api/mcp/tools_exec.go) name a bridge
// bridge_name and a port port_name; both carry the gRPC bridge_id and
// port_id unchanged. Their results are the pb messages encoded with
// encoding/json, so the generic JSON round-trip decodes most replies; the
// tools that answer with a bare message get a decoder that places it.
//
// A request field the tool has no argument for is refused with
// ErrFieldNotSupported instead of being dropped. Policies are in
// sdn_policy.go and network zones in sdn_zone.go.

func init() {
	for method, tool := range map[string]string{
		platformv1.SDNService_CreateBridge_FullMethodName: "sdn_create_bridge",
		platformv1.SDNService_DeleteBridge_FullMethodName: "sdn_delete_bridge",
		platformv1.SDNService_GetBridge_FullMethodName:    "sdn_list_bridges",
		platformv1.SDNService_ListBridges_FullMethodName:  "sdn_list_bridges",
		platformv1.SDNService_AddPort_FullMethodName:      "sdn_add_port",
		platformv1.SDNService_DeletePort_FullMethodName:   "sdn_delete_port",
		platformv1.SDNService_GetPort_FullMethodName:      "sdn_get_port_state",
		platformv1.SDNService_SetPortState_FullMethodName: "sdn_set_port_state",
		platformv1.SDNService_GetPortStats_FullMethodName: "sdn_get_port_stats",
		platformv1.SDNService_AddFlow_FullMethodName:      "sdn_add_flow",
		platformv1.SDNService_DeleteFlow_FullMethodName:   "sdn_delete_flow",
		platformv1.SDNService_ListFlows_FullMethodName:    "sdn_list_flows",
		platformv1.SDNService_FlushFlows_FullMethodName:   "sdn_flush_flows",
		platformv1.SDNService_CreateVLAN_FullMethodName:   "sdn_create_vlan",
		platformv1.SDNService_DeleteVLAN_FullMethodName:   "sdn_delete_vlan",
		platformv1.SDNService_ListVLANs_FullMethodName:    "sdn_list_vlans",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}

	for method, build := range map[string]mcpArgBuilder{
		platformv1.SDNService_CreateBridge_FullMethodName: buildSDNCreateBridgeArgs,
		platformv1.SDNService_DeleteBridge_FullMethodName: buildSDNDeleteBridgeArgs,
		platformv1.SDNService_GetBridge_FullMethodName:    buildSDNGetBridgeArgs,
		platformv1.SDNService_ListBridges_FullMethodName:  buildSDNListBridgesArgs,
		platformv1.SDNService_AddPort_FullMethodName:      buildSDNAddPortArgs,
		platformv1.SDNService_DeletePort_FullMethodName:   buildSDNDeletePortArgs,
		platformv1.SDNService_GetPort_FullMethodName:      buildSDNGetPortArgs,
		platformv1.SDNService_SetPortState_FullMethodName: buildSDNSetPortStateArgs,
		platformv1.SDNService_GetPortStats_FullMethodName: buildSDNGetPortStatsArgs,
		platformv1.SDNService_AddFlow_FullMethodName:      buildSDNAddFlowArgs,
		platformv1.SDNService_DeleteFlow_FullMethodName:   buildSDNDeleteFlowArgs,
		platformv1.SDNService_ListFlows_FullMethodName:    buildSDNListFlowsArgs,
		platformv1.SDNService_FlushFlows_FullMethodName:   buildSDNFlushFlowsArgs,
		platformv1.SDNService_CreateVLAN_FullMethodName:   buildSDNCreateVLANArgs,
		platformv1.SDNService_DeleteVLAN_FullMethodName:   buildSDNDeleteVLANArgs,
		platformv1.SDNService_ListVLANs_FullMethodName:    buildSDNListVLANsArgs,
	} {
		mcpArgBuilders[method] = build
	}

	mcpReplyDecoders[platformv1.SDNService_GetPort_FullMethodName] = decodeSDNGetPortResult
	mcpReplyDecoders[platformv1.SDNService_GetPortStats_FullMethodName] = decodeSDNGetPortStatsResult
	mcpRequestReplyDecoders[platformv1.SDNService_GetBridge_FullMethodName] = decodeSDNGetBridgeResult
}

// refuseUncarried returns ErrFieldNotSupported for a populated field of msg
// that is not carried. A field is carried when the MCP tool takes an
// argument for it, or when the daemon ignores it on every transport (labels):
// refusing those would fail a call that gRPC accepts and drops alike. When
// several fields are uncarried, the first by name is reported.
func refuseUncarried(method, prefix string, msg proto.Message, carried ...string) error {
	var uncarried []string
	msg.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		if name := string(fd.Name()); !slices.Contains(carried, name) {
			uncarried = append(uncarried, name)
		}
		return true
	})
	if len(uncarried) == 0 {
		return nil
	}
	slices.Sort(uncarried)
	return ErrFieldNotSupported{Method: method, Field: prefix + uncarried[0]}
}

// bridgePortArgs names a port on a bridge the way the sdn_* tools do.
func bridgePortArgs(bridgeID, portID string) map[string]interface{} {
	return map[string]interface{}{"bridge_name": bridgeID, "port_name": portID}
}

func buildSDNCreateBridgeArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.SDNService_CreateBridge_FullMethodName
	in, ok := args.(*platformv1.CreateBridgeRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	config := in.GetConfig()
	if err := refuseUncarried(method, "config.", config, "name", "type", "labels"); err != nil {
		return nil, err
	}
	// sdn_create_bridge always creates an Open vSwitch bridge.
	if t := config.GetType(); t != platformv1.BridgeType_BRIDGE_TYPE_UNSPECIFIED && t != platformv1.BridgeType_BRIDGE_TYPE_OVS {
		return nil, ErrFieldNotSupported{Method: method, Field: "config.type"}
	}
	return map[string]interface{}{"bridge_name": config.GetName()}, nil
}

func buildSDNDeleteBridgeArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.SDNService_DeleteBridge_FullMethodName
	in, ok := args.(*platformv1.DeleteBridgeRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	if err := refuseUncarried(method, "", in, "id"); err != nil {
		return nil, err
	}
	return map[string]interface{}{"bridge_name": in.GetId()}, nil
}

// buildSDNGetBridgeArgs lists every bridge: there is no single-bridge tool,
// so decodeSDNGetBridgeResult picks the requested one out of the list.
func buildSDNGetBridgeArgs(args interface{}) (map[string]interface{}, error) {
	if _, ok := args.(*platformv1.GetBridgeRequest); !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.SDNService_GetBridge_FullMethodName}
	}
	return map[string]interface{}{}, nil
}

func buildSDNListBridgesArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.SDNService_ListBridges_FullMethodName
	in, ok := args.(*platformv1.ListBridgesRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	if err := refuseUncarried(method, "", in); err != nil {
		return nil, err
	}
	return map[string]interface{}{}, nil
}

func buildSDNAddPortArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.SDNService_AddPort_FullMethodName
	in, ok := args.(*platformv1.AddPortRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	config := in.GetConfig()
	if err := refuseUncarried(method, "config.", config, "name", "type", "labels"); err != nil {
		return nil, err
	}
	out := bridgePortArgs(in.GetBridgeId(), config.GetName())
	if t := config.GetType(); t != platformv1.PortType_PORT_TYPE_UNSPECIFIED {
		out["port_type"] = strings.ToLower(strings.TrimPrefix(t.String(), "PORT_TYPE_"))
	}
	return out, nil
}

func buildSDNDeletePortArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.DeletePortRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.SDNService_DeletePort_FullMethodName}
	}
	return bridgePortArgs(in.GetBridgeId(), in.GetPortId()), nil
}

func buildSDNGetPortArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.GetPortRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.SDNService_GetPort_FullMethodName}
	}
	return bridgePortArgs(in.GetBridgeId(), in.GetPortId()), nil
}

// buildSDNSetPortStateArgs sends the rates as decimal strings so a uint64
// survives JSON number precision in every client along the path.
func buildSDNSetPortStateArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.SetPortStateRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.SDNService_SetPortState_FullMethodName}
	}
	out := bridgePortArgs(in.GetBridgeId(), in.GetPortId())
	out["state"] = in.GetAdminState()
	out["ingress_rate"] = strconv.FormatUint(in.GetIngressRate(), 10)
	out["ingress_burst"] = strconv.FormatUint(in.GetIngressBurst(), 10)
	out["egress_rate"] = strconv.FormatUint(in.GetEgressRate(), 10)
	out["egress_burst"] = strconv.FormatUint(in.GetEgressBurst(), 10)
	return out, nil
}

func buildSDNGetPortStatsArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.GetPortStatsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.SDNService_GetPortStats_FullMethodName}
	}
	return bridgePortArgs(in.GetBridgeId(), in.GetPortId()), nil
}

// buildSDNAddFlowArgs carries the whole flow: sdn_add_flow takes the
// FlowConfig fields under their proto names, with the bridge as bridge_name,
// and decodes them as strictly as the gRPC request is decoded.
func buildSDNAddFlowArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.SDNService_AddFlow_FullMethodName
	in, ok := args.(*platformv1.AddFlowRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	config := in.GetConfig()
	if config == nil {
		config = &platformv1.FlowConfig{}
	}
	out, err := protoJSONArgs(method)(config)
	if err != nil {
		return nil, err
	}
	delete(out, "bridge_id")
	out["bridge_name"] = config.GetBridgeId()
	return out, nil
}

func buildSDNDeleteFlowArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.DeleteFlowRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.SDNService_DeleteFlow_FullMethodName}
	}
	return map[string]interface{}{"bridge_name": in.GetBridgeId(), "flow_id": in.GetFlowId()}, nil
}

func buildSDNListFlowsArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.SDNService_ListFlows_FullMethodName
	in, ok := args.(*platformv1.ListFlowsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	if err := refuseUncarried(method, "", in, "bridge_id"); err != nil {
		return nil, err
	}
	return map[string]interface{}{"bridge_name": in.GetBridgeId()}, nil
}

func buildSDNFlushFlowsArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.SDNService_FlushFlows_FullMethodName
	in, ok := args.(*platformv1.FlushFlowsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	if err := refuseUncarried(method, "", in, "bridge_id"); err != nil {
		return nil, err
	}
	return map[string]interface{}{"bridge_name": in.GetBridgeId()}, nil
}

func buildSDNCreateVLANArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.SDNService_CreateVLAN_FullMethodName
	in, ok := args.(*platformv1.CreateVLANRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	config := in.GetConfig()
	if err := refuseUncarried(method, "config.", config, "vlan_id", "name", "bridge_id", "labels"); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"bridge_name": config.GetBridgeId(),
		"vlan_id":     config.GetVlanId(),
		"name":        config.GetName(),
	}, nil
}

func buildSDNDeleteVLANArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.DeleteVLANRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.SDNService_DeleteVLAN_FullMethodName}
	}
	return map[string]interface{}{"bridge_name": in.GetBridgeId(), "vlan_id": in.GetVlanId()}, nil
}

func buildSDNListVLANsArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.SDNService_ListVLANs_FullMethodName
	in, ok := args.(*platformv1.ListVLANsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	if err := refuseUncarried(method, "", in, "bridge_id"); err != nil {
		return nil, err
	}
	return map[string]interface{}{"bridge_name": in.GetBridgeId()}, nil
}

// decodeSDNGetPortResult places the bare port sdn_get_port_state answers.
func decodeSDNGetPortResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetPortResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_GetPort_FullMethodName}
	}
	port := &platformv1.Port{}
	if err := decodeToolResult(result, port); err != nil {
		return err
	}
	out.Port = port
	return nil
}

// decodeSDNGetPortStatsResult places the bare statistics sdn_get_port_stats
// answers.
func decodeSDNGetPortStatsResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetPortStatsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_GetPortStats_FullMethodName}
	}
	stats := &platformv1.PortStats{}
	if err := decodeToolResult(result, stats); err != nil {
		return err
	}
	out.Stats = stats
	return nil
}

// decodeSDNGetBridgeResult picks the requested bridge out of the
// sdn_list_bridges result by UUID or by name, as SDNService does; a bridge
// that is not listed is NotFound.
func decodeSDNGetBridgeResult(args interface{}, result interface{}, reply interface{}) error {
	const method = platformv1.SDNService_GetBridge_FullMethodName
	in, ok := args.(*platformv1.GetBridgeRequest)
	if !ok {
		return ErrUnexpectedArgsType{Method: method}
	}
	out, ok := reply.(*platformv1.GetBridgeResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: method}
	}
	list := &platformv1.ListBridgesResponse{}
	if err := decodeToolResult(result, list); err != nil {
		return err
	}
	for _, bridge := range list.GetBridges() {
		if bridge.GetId() == in.GetId() || bridge.GetConfig().GetName() == in.GetId() {
			out.Bridge = bridge
			return nil
		}
	}
	return ErrBridgeNotFound{ID: in.GetId()}
}
