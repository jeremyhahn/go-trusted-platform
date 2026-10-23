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
	"strconv"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Overlay MCP mapping. The daemon's overlay_* tools
// (pkg/api/mcp/overlay_tools.go) answer with the JSON views in
// pkg/api/daemon/overlay_mcp_bindings.go: the status, VTEP and VNI objects
// themselves, {"vteps": [...]}, {"vnis": [...]}, {"tunnels": [...]},
// {"tunnel": {...}}, {"macs": [...]} and {"success": true}. Times are
// RFC 3339, or "" when unset.

func init() {
	for method, tool := range map[string]string{
		platformv1.OverlayService_GetOverlayStatus_FullMethodName: "overlay_status",
		platformv1.OverlayService_ListVTEPs_FullMethodName:        "overlay_vtep_list",
		platformv1.OverlayService_GetVTEP_FullMethodName:          "overlay_vtep_get",
		platformv1.OverlayService_ListVNIs_FullMethodName:         "overlay_vni_list",
		platformv1.OverlayService_CreateVNI_FullMethodName:        "overlay_vni_create",
		platformv1.OverlayService_DeleteVNI_FullMethodName:        "overlay_vni_delete",
		platformv1.OverlayService_ListTunnels_FullMethodName:      "overlay_tunnel_list",
		platformv1.OverlayService_GetTunnelStats_FullMethodName:   "overlay_tunnel_stats",
		platformv1.OverlayService_ListRemoteMACs_FullMethodName:   "overlay_mac_list",
		platformv1.OverlayService_ForgetMAC_FullMethodName:        "overlay_mac_forget",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}

	for method, build := range map[string]mcpArgBuilder{
		platformv1.OverlayService_GetOverlayStatus_FullMethodName: buildOverlayStatusArgs,
		platformv1.OverlayService_ListVTEPs_FullMethodName:        buildListVTEPsArgs,
		platformv1.OverlayService_GetVTEP_FullMethodName:          buildGetVTEPArgs,
		platformv1.OverlayService_ListVNIs_FullMethodName:         buildListVNIsArgs,
		platformv1.OverlayService_CreateVNI_FullMethodName:        buildCreateVNIArgs,
		platformv1.OverlayService_DeleteVNI_FullMethodName:        buildDeleteVNIArgs,
		platformv1.OverlayService_ListTunnels_FullMethodName:      buildListTunnelsArgs,
		platformv1.OverlayService_GetTunnelStats_FullMethodName:   buildGetTunnelStatsArgs,
		platformv1.OverlayService_ListRemoteMACs_FullMethodName:   buildListRemoteMACsArgs,
		platformv1.OverlayService_ForgetMAC_FullMethodName:        buildForgetMACArgs,
	} {
		mcpArgBuilders[method] = build
	}

	for method, decode := range map[string]mcpReplyDecoder{
		platformv1.OverlayService_GetOverlayStatus_FullMethodName: decodeOverlayStatusResult,
		platformv1.OverlayService_ListVTEPs_FullMethodName:        decodeListVTEPsResult,
		platformv1.OverlayService_GetVTEP_FullMethodName:          decodeGetVTEPResult,
		platformv1.OverlayService_ListVNIs_FullMethodName:         decodeListVNIsResult,
		platformv1.OverlayService_CreateVNI_FullMethodName:        decodeCreateVNIResult,
		platformv1.OverlayService_DeleteVNI_FullMethodName:        decodeDeleteVNIResult,
		platformv1.OverlayService_ListTunnels_FullMethodName:      decodeListTunnelsResult,
		platformv1.OverlayService_GetTunnelStats_FullMethodName:   decodeGetTunnelStatsResult,
		platformv1.OverlayService_ListRemoteMACs_FullMethodName:   decodeListRemoteMACsResult,
		platformv1.OverlayService_ForgetMAC_FullMethodName:        decodeForgetMACResult,
	} {
		mcpReplyDecoders[method] = decode
	}
}

func buildOverlayStatusArgs(args interface{}) (map[string]interface{}, error) {
	if _, ok := args.(*platformv1.GetOverlayStatusRequest); !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.OverlayService_GetOverlayStatus_FullMethodName}
	}
	return map[string]interface{}{}, nil
}

func buildListVTEPsArgs(args interface{}) (map[string]interface{}, error) {
	if _, ok := args.(*platformv1.ListVTEPsRequest); !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.OverlayService_ListVTEPs_FullMethodName}
	}
	return map[string]interface{}{}, nil
}

func buildGetVTEPArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.GetVTEPRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.OverlayService_GetVTEP_FullMethodName}
	}
	return map[string]interface{}{"node_id": in.GetNodeId()}, nil
}

func buildListVNIsArgs(args interface{}) (map[string]interface{}, error) {
	if _, ok := args.(*platformv1.ListVNIsRequest); !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.OverlayService_ListVNIs_FullMethodName}
	}
	return map[string]interface{}{}, nil
}

// buildCreateVNIArgs sends the config's VNI, VLAN and name, the arguments
// overlay_vni_create takes.
func buildCreateVNIArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.CreateVNIRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.OverlayService_CreateVNI_FullMethodName}
	}
	cfg := in.GetConfig()
	return map[string]interface{}{"vni": cfg.GetVni(), "vlan": cfg.GetVlan(), "name": cfg.GetName()}, nil
}

func buildDeleteVNIArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.DeleteVNIRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.OverlayService_DeleteVNI_FullMethodName}
	}
	return map[string]interface{}{"vni": in.GetVni()}, nil
}

func buildListTunnelsArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.ListTunnelsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.OverlayService_ListTunnels_FullMethodName}
	}
	return map[string]interface{}{"vni": in.GetVni()}, nil
}

func buildGetTunnelStatsArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.GetTunnelStatsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.OverlayService_GetTunnelStats_FullMethodName}
	}
	return map[string]interface{}{"remote_vtep": in.GetRemoteVtep(), "vni": in.GetVni()}, nil
}

func buildListRemoteMACsArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.ListRemoteMACsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.OverlayService_ListRemoteMACs_FullMethodName}
	}
	return map[string]interface{}{"vni": in.GetVni()}, nil
}

func buildForgetMACArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.ForgetMACRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.OverlayService_ForgetMAC_FullMethodName}
	}
	return map[string]interface{}{"mac": in.GetMac(), "vni": in.GetVni()}, nil
}

// optionalTime is a tool result moment: RFC 3339, or "" when unset.
type optionalTime struct {
	time.Time
}

// UnmarshalJSON reads "" as the zero time and anything else as RFC 3339.
func (t *optionalTime) UnmarshalJSON(data []byte) error {
	if string(data) == `""` {
		t.Time = time.Time{}
		return nil
	}
	return t.Time.UnmarshalJSON(data)
}

// overlayStatusWire is the overlay_status result.
type overlayStatusWire struct {
	NodeID         string `json:"node_id"`
	VTEPIP         string `json:"vtep_ip"`
	Healthy        bool   `json:"healthy"`
	UnderlayMTU    uint32 `json:"underlay_mtu"`
	VXLANPort      uint32 `json:"vxlan_port"`
	VNICount       uint32 `json:"vni_count"`
	VTEPCount      uint32 `json:"vtep_count"`
	RemoteMACCount uint32 `json:"remote_mac_count"`
	TunnelCount    uint32 `json:"tunnel_count"`
}

// overlayVTEPWire is one overlay_vtep_list entry, or the overlay_vtep_get
// result, which adds the VNIs, MAC count and byte counts.
type overlayVTEPWire struct {
	NodeID    string       `json:"node_id"`
	IP        string       `json:"ip"`
	Healthy   bool         `json:"healthy"`
	LastSeen  optionalTime `json:"last_seen"`
	VNIs      []uint32     `json:"vnis"`
	MACCount  uint32       `json:"mac_count"`
	BytesSent uint64       `json:"bytes_sent"`
	BytesRecv uint64       `json:"bytes_recv"`
}

func (v overlayVTEPWire) toPb() *platformv1.VTEPInfo {
	return &platformv1.VTEPInfo{
		NodeId:    v.NodeID,
		Ip:        v.IP,
		Healthy:   v.Healthy,
		LastSeen:  timestampOrNil(v.LastSeen.Time),
		Vnis:      v.VNIs,
		MacCount:  v.MACCount,
		BytesSent: v.BytesSent,
		BytesRecv: v.BytesRecv,
	}
}

// overlayVNIWire is one overlay_vni_list entry, or the overlay_vni_create
// result. The overlay stores no VNI name.
type overlayVNIWire struct {
	VNI       uint32       `json:"vni"`
	VLAN      uint32       `json:"vlan"`
	MACCount  uint32       `json:"mac_count"`
	CreatedAt optionalTime `json:"created_at"`
}

// toPb names the VNI as gRPC names it.
func (v overlayVNIWire) toPb() *platformv1.VNI {
	return &platformv1.VNI{
		Id:        "vni-" + strconv.FormatUint(uint64(v.VNI), 10),
		Config:    &platformv1.VNIConfig{Vni: v.VNI, Vlan: v.VLAN},
		CreatedAt: timestampOrNil(v.CreatedAt.Time),
		MacCount:  v.MACCount,
	}
}

// overlayTunnelWire is one overlay_tunnel_list entry, or the
// overlay_tunnel_stats tunnel.
type overlayTunnelWire struct {
	LocalVTEP  string `json:"local_vtep"`
	RemoteVTEP string `json:"remote_vtep"`
	VNI        uint32 `json:"vni"`
	State      string `json:"state"`
	BytesSent  uint64 `json:"bytes_sent"`
	BytesRecv  uint64 `json:"bytes_recv"`
}

func (t overlayTunnelWire) toPb() *platformv1.TunnelInfo {
	return &platformv1.TunnelInfo{
		LocalVtep:  t.LocalVTEP,
		RemoteVtep: t.RemoteVTEP,
		Vni:        t.VNI,
		State:      t.State,
		BytesTx:    t.BytesSent,
		BytesRx:    t.BytesRecv,
	}
}

// overlayMACWire is one overlay_mac_list entry.
type overlayMACWire struct {
	MAC        string       `json:"mac"`
	VNI        uint32       `json:"vni"`
	RemoteVTEP string       `json:"remote_vtep"`
	LearnedAt  optionalTime `json:"learned_at"`
}

func (m overlayMACWire) toPb() *platformv1.RemoteMACEntry {
	return &platformv1.RemoteMACEntry{
		Mac:        m.MAC,
		Vni:        m.VNI,
		RemoteVtep: m.RemoteVTEP,
		LearnedAt:  timestampOrNil(m.LearnedAt.Time),
	}
}

func decodeOverlayStatusResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetOverlayStatusResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.OverlayService_GetOverlayStatus_FullMethodName}
	}
	var wire overlayStatusWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.OverlayStatus{
		NodeId:         wire.NodeID,
		VtepIp:         wire.VTEPIP,
		VtepCount:      wire.VTEPCount,
		VniCount:       wire.VNICount,
		TunnelCount:    wire.TunnelCount,
		RemoteMacCount: wire.RemoteMACCount,
		Healthy:        wire.Healthy,
		VxlanPort:      wire.VXLANPort,
		UnderlayMtu:    wire.UnderlayMTU,
	}
	return nil
}

func decodeListVTEPsResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListVTEPsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.OverlayService_ListVTEPs_FullMethodName}
	}
	var wire struct {
		VTEPs []overlayVTEPWire `json:"vteps"`
	}
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Vteps = make([]*platformv1.VTEPInfo, 0, len(wire.VTEPs))
	for i := range wire.VTEPs {
		out.Vteps = append(out.Vteps, wire.VTEPs[i].toPb())
	}
	return nil
}

func decodeGetVTEPResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetVTEPResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.OverlayService_GetVTEP_FullMethodName}
	}
	var wire overlayVTEPWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Vtep = wire.toPb()
	return nil
}

func decodeListVNIsResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListVNIsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.OverlayService_ListVNIs_FullMethodName}
	}
	var wire struct {
		VNIs []overlayVNIWire `json:"vnis"`
	}
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Vnis = make([]*platformv1.VNI, 0, len(wire.VNIs))
	for i := range wire.VNIs {
		out.Vnis = append(out.Vnis, wire.VNIs[i].toPb())
	}
	return nil
}

func decodeCreateVNIResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.CreateVNIResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.OverlayService_CreateVNI_FullMethodName}
	}
	var wire overlayVNIWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: true}
	out.Vni = wire.toPb()
	return nil
}

func decodeDeleteVNIResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DeleteVNIResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.OverlayService_DeleteVNI_FullMethodName}
	}
	var wire gatewaySuccessWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: wire.Success}
	return nil
}

func decodeListTunnelsResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListTunnelsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.OverlayService_ListTunnels_FullMethodName}
	}
	var wire struct {
		Tunnels []overlayTunnelWire `json:"tunnels"`
	}
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Tunnels = make([]*platformv1.TunnelInfo, 0, len(wire.Tunnels))
	for i := range wire.Tunnels {
		out.Tunnels = append(out.Tunnels, wire.Tunnels[i].toPb())
	}
	return nil
}

func decodeGetTunnelStatsResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetTunnelStatsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.OverlayService_GetTunnelStats_FullMethodName}
	}
	var wire struct {
		Tunnel overlayTunnelWire `json:"tunnel"`
	}
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Tunnel = wire.Tunnel.toPb()
	return nil
}

func decodeListRemoteMACsResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListRemoteMACsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.OverlayService_ListRemoteMACs_FullMethodName}
	}
	var wire struct {
		MACs []overlayMACWire `json:"macs"`
	}
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Macs = make([]*platformv1.RemoteMACEntry, 0, len(wire.MACs))
	for i := range wire.MACs {
		out.Macs = append(out.Macs, wire.MACs[i].toPb())
	}
	return nil
}

func decodeForgetMACResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ForgetMACResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.OverlayService_ForgetMAC_FullMethodName}
	}
	var wire gatewaySuccessWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: wire.Success}
	return nil
}
