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

package quic

import (
	"strconv"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Overlay QUIC wire mapping.
//
// Every OverlayService method multiplexes under OpOverlayCategory (0x2E) with
// the sub-opcode in payload[0]. The daemon handler
// (pkg/api/quic/overlay_handlers.go) speaks the quicwire overlay shapes, so
// requests and replies are converted here, the replies as the daemon's gRPC
// OverlayService builds them. GetOverlayStatus carries no body. The daemon
// serves the four lists a page at a time, so they are paged (categoryPagers)
// and the caller still receives every entry.

// overlaySubOpcodes routes OverlayService methods to their sub-opcode byte.
var overlaySubOpcodes = map[string]byte{
	platformv1.OverlayService_GetOverlayStatus_FullMethodName: quicwire.OpOverlayStatus,
	platformv1.OverlayService_ListVTEPs_FullMethodName:        quicwire.OpOverlayListVTEPs,
	platformv1.OverlayService_GetVTEP_FullMethodName:          quicwire.OpOverlayGetVTEP,
	platformv1.OverlayService_ListVNIs_FullMethodName:         quicwire.OpOverlayListVNIs,
	platformv1.OverlayService_CreateVNI_FullMethodName:        quicwire.OpOverlayCreateVNI,
	platformv1.OverlayService_DeleteVNI_FullMethodName:        quicwire.OpOverlayDeleteVNI,
	platformv1.OverlayService_ListTunnels_FullMethodName:      quicwire.OpOverlayListTunns,
	platformv1.OverlayService_GetTunnelStats_FullMethodName:   quicwire.OpOverlayTunnelStats,
	platformv1.OverlayService_ListRemoteMACs_FullMethodName:   quicwire.OpOverlayListMACs,
	platformv1.OverlayService_ForgetMAC_FullMethodName:        quicwire.OpOverlayForgetMAC,
}

var overlayRequestEncoders = map[string]categoryRequestEncoder{
	platformv1.OverlayService_GetVTEP_FullMethodName: requestEncoder(
		platformv1.OverlayService_GetVTEP_FullMethodName, encodeGetVTEPRequest),
	platformv1.OverlayService_CreateVNI_FullMethodName: requestEncoder(
		platformv1.OverlayService_CreateVNI_FullMethodName, encodeCreateVNIRequest),
	platformv1.OverlayService_DeleteVNI_FullMethodName: requestEncoder(
		platformv1.OverlayService_DeleteVNI_FullMethodName, encodeDeleteVNIRequest),
	platformv1.OverlayService_GetTunnelStats_FullMethodName: requestEncoder(
		platformv1.OverlayService_GetTunnelStats_FullMethodName, encodeGetTunnelStatsRequest),
	platformv1.OverlayService_ForgetMAC_FullMethodName: requestEncoder(
		platformv1.OverlayService_ForgetMAC_FullMethodName, encodeForgetMACRequest),
}

var overlayResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.OverlayService_GetOverlayStatus_FullMethodName: responseDecoder(
		platformv1.OverlayService_GetOverlayStatus_FullMethodName, applyOverlayStatusReply),
	platformv1.OverlayService_GetVTEP_FullMethodName: responseDecoder(
		platformv1.OverlayService_GetVTEP_FullMethodName, applyGetVTEPReply),
	platformv1.OverlayService_CreateVNI_FullMethodName: responseDecoder(
		platformv1.OverlayService_CreateVNI_FullMethodName, applyCreateVNIReply),
	platformv1.OverlayService_DeleteVNI_FullMethodName: responseDecoder(
		platformv1.OverlayService_DeleteVNI_FullMethodName, applyDeleteVNIReply),
	platformv1.OverlayService_GetTunnelStats_FullMethodName: responseDecoder(
		platformv1.OverlayService_GetTunnelStats_FullMethodName, applyGetTunnelStatsReply),
	platformv1.OverlayService_ForgetMAC_FullMethodName: responseDecoder(
		platformv1.OverlayService_ForgetMAC_FullMethodName, applyForgetMACReply),
}

var overlayPagers = map[string]categoryPager{
	platformv1.OverlayService_ListVTEPs_FullMethodName: {
		request: pagedRequest(platformv1.OverlayService_ListVTEPs_FullMethodName, encodeListVTEPsRequest),
		decode:  overlayPageDecoder(platformv1.OverlayService_ListVTEPs_FullMethodName, applyListVTEPsPage),
	},
	platformv1.OverlayService_ListVNIs_FullMethodName: {
		request: pagedRequest(platformv1.OverlayService_ListVNIs_FullMethodName, encodeListVNIsRequest),
		decode:  overlayPageDecoder(platformv1.OverlayService_ListVNIs_FullMethodName, applyListVNIsPage),
	},
	platformv1.OverlayService_ListTunnels_FullMethodName: {
		request: pagedRequest(platformv1.OverlayService_ListTunnels_FullMethodName, encodeListTunnelsRequest),
		decode:  overlayPageDecoder(platformv1.OverlayService_ListTunnels_FullMethodName, applyListTunnelsPage),
	},
	platformv1.OverlayService_ListRemoteMACs_FullMethodName: {
		request: pagedRequest(platformv1.OverlayService_ListRemoteMACs_FullMethodName, encodeListRemoteMACsRequest),
		decode:  overlayPageDecoder(platformv1.OverlayService_ListRemoteMACs_FullMethodName, applyListRemoteMACsPage),
	},
}

// init merges the overlay wire mapping into the shared adapter tables. The
// file name sorts before adapter.go so this init runs before the adapter's
// category-invariant assertion.
func init() {
	categoryOpcodes[quicwire.OpOverlayCategory] = struct{}{}
	for method, sub := range overlaySubOpcodes {
		grpcMethodToOpcodeMap[method] = quicwire.OpOverlayCategory
		categorySubOpcodeMap[method] = sub
	}
	categoryEmptyBodyMethods[platformv1.OverlayService_GetOverlayStatus_FullMethodName] = struct{}{}
	registerCategoryCodecs(overlayRequestEncoders, overlayResponseDecoders)
	for method, pager := range overlayPagers {
		categoryPagers[method] = pager
	}
}

// overlayListPageSize is the page the SDK asks for: the most the daemon
// serves in one reply (gatewayMaxLimit in pkg/api/quic, which the overlay
// lists share).
const overlayListPageSize int32 = 1000

func encodeListVTEPsRequest(_ *platformv1.ListVTEPsRequest, offset int32) interface{} {
	return &quicwire.OverlayListVTEPsRequest{Limit: overlayListPageSize, Offset: offset}
}

func encodeListVNIsRequest(_ *platformv1.ListVNIsRequest, offset int32) interface{} {
	return &quicwire.OverlayListVNIsRequest{Limit: overlayListPageSize, Offset: offset}
}

func encodeListTunnelsRequest(in *platformv1.ListTunnelsRequest, offset int32) interface{} {
	return &quicwire.OverlayListTunnelsRequest{VNI: in.GetVni(), Limit: overlayListPageSize, Offset: offset}
}

func encodeListRemoteMACsRequest(in *platformv1.ListRemoteMACsRequest, offset int32) interface{} {
	return &quicwire.OverlayListMACsRequest{VNI: in.GetVni(), Limit: overlayListPageSize, Offset: offset}
}

func encodeGetVTEPRequest(in *platformv1.GetVTEPRequest) (interface{}, error) {
	return &quicwire.OverlayGetVTEPRequest{ID: in.GetNodeId()}, nil
}

func encodeCreateVNIRequest(in *platformv1.CreateVNIRequest) (interface{}, error) {
	config := in.GetConfig()
	return &quicwire.OverlayCreateVNIRequest{
		VNI:    config.GetVni(),
		VLAN:   config.GetVlan(),
		Name:   config.GetName(),
		Labels: config.GetLabels(),
	}, nil
}

func encodeDeleteVNIRequest(in *platformv1.DeleteVNIRequest) (interface{}, error) {
	return &quicwire.OverlayDeleteVNIRequest{VNI: in.GetVni()}, nil
}

func encodeGetTunnelStatsRequest(in *platformv1.GetTunnelStatsRequest) (interface{}, error) {
	return &quicwire.OverlayTunnelStatsRequest{RemoteVTEP: in.GetRemoteVtep(), VNI: in.GetVni()}, nil
}

func encodeForgetMACRequest(in *platformv1.ForgetMACRequest) (interface{}, error) {
	return &quicwire.OverlayForgetMACRequest{MAC: in.GetMac(), VNI: in.GetVni()}, nil
}

func applyOverlayStatusReply(wire *quicwire.OverlayStatusResponse, out *platformv1.GetOverlayStatusResponse) error {
	out.Status = overlayStatusFromWire(wire.Status)
	return nil
}

func applyGetVTEPReply(wire *quicwire.OverlayGetVTEPResponse, out *platformv1.GetVTEPResponse) error {
	out.Vtep = vtepFromWire(wire.VTEP)
	return nil
}

// applyCreateVNIReply reports success with the VNI the daemon created, as
// gRPC CreateVNI does.
func applyCreateVNIReply(wire *quicwire.OverlayCreateVNIResponse, out *platformv1.CreateVNIResponse) error {
	out.Status = &platformv1.Status{Success: true}
	out.Vni = vniFromWire(wire.VNI)
	return nil
}

func applyDeleteVNIReply(wire *quicwire.OverlayDeleteVNIResponse, out *platformv1.DeleteVNIResponse) error {
	out.Status = &platformv1.Status{Success: wire.Success}
	return nil
}

func applyGetTunnelStatsReply(wire *quicwire.OverlayTunnelStatsResponse, out *platformv1.GetTunnelStatsResponse) error {
	out.Tunnel = tunnelFromWire(wire.Tunnel)
	return nil
}

func applyForgetMACReply(wire *quicwire.OverlayForgetMACResponse, out *platformv1.ForgetMACResponse) error {
	out.Status = &platformv1.Status{Success: wire.Success}
	return nil
}

// overlayPageDecoder decodes one page of a W reply, appends its entries to
// the R reply with apply, and reports the page. The page counts every wire
// entry, a nil one too, since the offset counts the daemon's entries.
func overlayPageDecoder[W any, R any](method string, apply func(*W, *R) categoryPage) func([]byte, interface{}) (categoryPage, error) {
	return func(payload []byte, reply interface{}) (categoryPage, error) {
		out, ok := reply.(*R)
		if !ok || out == nil {
			return categoryPage{}, ErrInvalidReplyType{Method: method}
		}
		var wire W
		if err := decodeReplyPayload(payload, &wire); err != nil {
			return categoryPage{}, err
		}
		return apply(&wire, out), nil
	}
}

func applyListVTEPsPage(wire *quicwire.OverlayListVTEPsResponse, out *platformv1.ListVTEPsResponse) categoryPage {
	for _, vtep := range wire.VTEPs {
		if vtep != nil {
			out.Vteps = append(out.Vteps, vtepFromWire(vtep))
		}
	}
	return categoryPage{received: pageCount(len(wire.VTEPs)), total: wire.Total}
}

func applyListVNIsPage(wire *quicwire.OverlayListVNIsResponse, out *platformv1.ListVNIsResponse) categoryPage {
	for _, vni := range wire.VNIs {
		if vni != nil {
			out.Vnis = append(out.Vnis, vniFromWire(vni))
		}
	}
	return categoryPage{received: pageCount(len(wire.VNIs)), total: wire.Total}
}

func applyListTunnelsPage(wire *quicwire.OverlayListTunnelsResponse, out *platformv1.ListTunnelsResponse) categoryPage {
	for _, tunnel := range wire.Tunnels {
		if tunnel != nil {
			out.Tunnels = append(out.Tunnels, tunnelFromWire(tunnel))
		}
	}
	return categoryPage{received: pageCount(len(wire.Tunnels)), total: wire.Total}
}

func applyListRemoteMACsPage(wire *quicwire.OverlayListMACsResponse, out *platformv1.ListRemoteMACsResponse) categoryPage {
	for _, mac := range wire.MACs {
		if mac != nil {
			out.Macs = append(out.Macs, &platformv1.RemoteMACEntry{
				Mac:        mac.MAC,
				Vni:        mac.VNI,
				RemoteVtep: mac.VTEP,
				LearnedAt:  unixNanoTimestamp(mac.LastSeen),
			})
		}
	}
	return categoryPage{received: pageCount(len(wire.MACs)), total: wire.Total}
}

// overlayStatusFromWire converts the wire status; a reply without one is a
// nil status. The daemon answers only while the overlay runs, and then calls
// it healthy.
func overlayStatusFromWire(s *quicwire.OverlayStatusInfo) *platformv1.OverlayStatus {
	if s == nil {
		return nil
	}
	return &platformv1.OverlayStatus{
		NodeId:         s.NodeID,
		VtepIp:         s.LocalVTEP,
		VtepCount:      wireCount32(s.VTEPCount),
		VniCount:       wireCount32(s.VNICount),
		TunnelCount:    wireCount32(s.TunnelCount),
		RemoteMacCount: wireCount32(s.MACCount),
		Healthy:        s.HealthStatus == "healthy",
		VxlanPort:      uint32(s.VXLANPort),
		UnderlayMtu:    wireCount32(s.MTU),
	}
}

// vtepFromWire converts a wire VTEP; the wire carries its health as a status
// word and its last-seen moment in Unix nanoseconds.
func vtepFromWire(v *quicwire.VTEPInfo) *platformv1.VTEPInfo {
	if v == nil {
		return nil
	}
	return &platformv1.VTEPInfo{
		NodeId:   v.ID,
		Ip:       v.IPAddress,
		Healthy:  v.Status == "healthy",
		LastSeen: unixNanoTimestamp(v.LastSeen),
		Vnis:     v.VNIs,
	}
}

// vniFromWire converts a wire VNI, naming it as gRPC does ("vni-<n>").
func vniFromWire(v *quicwire.VNIInfo) *platformv1.VNI {
	if v == nil {
		return nil
	}
	return &platformv1.VNI{
		Id: "vni-" + strconv.FormatUint(uint64(v.VNI), 10),
		Config: &platformv1.VNIConfig{
			Vni:    v.VNI,
			Vlan:   uint32(v.VLAN),
			Name:   v.Name,
			Labels: v.Labels,
		},
		CreatedAt: unixTimestamp(v.CreatedAt),
		MacCount:  wireCount32(v.MACCount),
	}
}

// tunnelFromWire converts a wire tunnel; its status word is the tunnel state.
func tunnelFromWire(t *quicwire.TunnelInfo) *platformv1.TunnelInfo {
	if t == nil {
		return nil
	}
	return &platformv1.TunnelInfo{
		LocalVtep:  t.LocalVTEP,
		RemoteVtep: t.RemoteVTEP,
		Vni:        t.VNI,
		State:      t.Status,
		BytesTx:    wireBytes(t.TxBytes),
		BytesRx:    wireBytes(t.RxBytes),
	}
}

// unixNanoTimestamp converts Unix nanoseconds to a timestamp; zero is no
// timestamp.
func unixNanoTimestamp(nanos int64) *timestamppb.Timestamp {
	if nanos == 0 {
		return nil
	}
	return timestamppb.New(time.Unix(0, nanos))
}

// wireBytes converts a wire byte counter to the proto's uint64, reporting a
// negative counter as zero.
func wireBytes(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}
