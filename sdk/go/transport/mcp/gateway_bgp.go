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
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Gateway BGP MCP mapping. The daemon's gateway_bgp_* tools
// (pkg/api/mcp/gateway_tools.go) answer with the JSON views in
// pkg/api/daemon/gateway_bgp_bindings.go: the status object itself,
// {"peers": [...]}, {"prefixes": [...]} and {"success": true}.

func init() {
	for method, tool := range map[string]string{
		platformv1.GatewayService_GetBGPStatus_FullMethodName:          "gateway_bgp_status",
		platformv1.GatewayService_ListBGPPeers_FullMethodName:          "gateway_bgp_peers",
		platformv1.GatewayService_AnnouncePrefix_FullMethodName:        "gateway_bgp_announce",
		platformv1.GatewayService_WithdrawPrefix_FullMethodName:        "gateway_bgp_withdraw",
		platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName: "gateway_bgp_prefixes",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}

	for method, build := range map[string]mcpArgBuilder{
		platformv1.GatewayService_GetBGPStatus_FullMethodName:          buildBGPStatusArgs,
		platformv1.GatewayService_ListBGPPeers_FullMethodName:          buildListBGPPeersArgs,
		platformv1.GatewayService_AnnouncePrefix_FullMethodName:        buildAnnouncePrefixArgs,
		platformv1.GatewayService_WithdrawPrefix_FullMethodName:        buildWithdrawPrefixArgs,
		platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName: buildListAnnouncedPrefixesArgs,
	} {
		mcpArgBuilders[method] = build
	}

	for method, decode := range map[string]mcpReplyDecoder{
		platformv1.GatewayService_GetBGPStatus_FullMethodName:          decodeBGPStatusResult,
		platformv1.GatewayService_ListBGPPeers_FullMethodName:          decodeListBGPPeersResult,
		platformv1.GatewayService_AnnouncePrefix_FullMethodName:        decodeAnnouncePrefixResult,
		platformv1.GatewayService_WithdrawPrefix_FullMethodName:        decodeWithdrawPrefixResult,
		platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName: decodeListAnnouncedPrefixesResult,
	} {
		mcpReplyDecoders[method] = decode
	}
}

func buildBGPStatusArgs(args interface{}) (map[string]interface{}, error) {
	if _, ok := args.(*platformv1.GetBGPStatusRequest); !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_GetBGPStatus_FullMethodName}
	}
	return map[string]interface{}{}, nil
}

func buildListBGPPeersArgs(args interface{}) (map[string]interface{}, error) {
	if _, ok := args.(*platformv1.ListBGPPeersRequest); !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_ListBGPPeers_FullMethodName}
	}
	return map[string]interface{}{}, nil
}

func buildAnnouncePrefixArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.AnnouncePrefixRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_AnnouncePrefix_FullMethodName}
	}
	return map[string]interface{}{"prefix": in.GetPrefix(), "next_hop": in.GetNextHop()}, nil
}

func buildWithdrawPrefixArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.WithdrawPrefixRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_WithdrawPrefix_FullMethodName}
	}
	return map[string]interface{}{"prefix": in.GetPrefix()}, nil
}

func buildListAnnouncedPrefixesArgs(args interface{}) (map[string]interface{}, error) {
	if _, ok := args.(*platformv1.ListAnnouncedPrefixesRequest); !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName}
	}
	return map[string]interface{}{}, nil
}

// bgpStatusWire is the gateway_bgp_status result.
type bgpStatusWire struct {
	LocalASN          uint32 `json:"local_asn"`
	RouterID          string `json:"router_id"`
	PeerCount         uint32 `json:"peer_count"`
	EstablishedPeers  uint32 `json:"established_peers"`
	PrefixesAnnounced uint32 `json:"prefixes_announced"`
	Running           bool   `json:"running"`
}

// bgpPeerWire is one gateway_bgp_peers entry; EstablishedAt is absent for a
// peer that is not established.
type bgpPeerWire struct {
	Address          string    `json:"address"`
	ASN              uint32    `json:"asn"`
	State            string    `json:"state"`
	Description      string    `json:"description"`
	PrefixesReceived uint32    `json:"prefixes_received"`
	PrefixesSent     uint32    `json:"prefixes_sent"`
	EstablishedAt    time.Time `json:"established_at"`
}

func (p bgpPeerWire) toPb() *platformv1.BGPPeer {
	return &platformv1.BGPPeer{
		Address:          p.Address,
		Asn:              p.ASN,
		State:            p.State,
		Description:      p.Description,
		PrefixesReceived: p.PrefixesReceived,
		PrefixesSent:     p.PrefixesSent,
		Uptime:           timestampOrNil(p.EstablishedAt),
	}
}

// announcedPrefixWire is one gateway_bgp_prefixes entry.
type announcedPrefixWire struct {
	Prefix      string    `json:"prefix"`
	NextHop     string    `json:"next_hop"`
	AnnouncedAt time.Time `json:"announced_at"`
}

func (p announcedPrefixWire) toPb() *platformv1.AnnouncedPrefix {
	return &platformv1.AnnouncedPrefix{
		Prefix:      p.Prefix,
		NextHop:     p.NextHop,
		AnnouncedAt: timestampOrNil(p.AnnouncedAt),
	}
}

func decodeBGPStatusResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetBGPStatusResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_GetBGPStatus_FullMethodName}
	}
	var wire bgpStatusWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.BGPStatus{
		LocalAsn:          wire.LocalASN,
		RouterId:          wire.RouterID,
		PeerCount:         wire.PeerCount,
		EstablishedPeers:  wire.EstablishedPeers,
		PrefixesAnnounced: wire.PrefixesAnnounced,
		Running:           wire.Running,
	}
	return nil
}

func decodeListBGPPeersResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListBGPPeersResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_ListBGPPeers_FullMethodName}
	}
	var wire struct {
		Peers []bgpPeerWire `json:"peers"`
	}
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Peers = make([]*platformv1.BGPPeer, 0, len(wire.Peers))
	for i := range wire.Peers {
		out.Peers = append(out.Peers, wire.Peers[i].toPb())
	}
	return nil
}

func decodeAnnouncePrefixResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.AnnouncePrefixResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_AnnouncePrefix_FullMethodName}
	}
	var wire gatewaySuccessWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: wire.Success}
	return nil
}

func decodeWithdrawPrefixResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.WithdrawPrefixResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_WithdrawPrefix_FullMethodName}
	}
	var wire gatewaySuccessWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: wire.Success}
	return nil
}

func decodeListAnnouncedPrefixesResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListAnnouncedPrefixesResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName}
	}
	var wire struct {
		Prefixes []announcedPrefixWire `json:"prefixes"`
	}
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Prefixes = make([]*platformv1.AnnouncedPrefix, 0, len(wire.Prefixes))
	for i := range wire.Prefixes {
		out.Prefixes = append(out.Prefixes, wire.Prefixes[i].toPb())
	}
	return nil
}
