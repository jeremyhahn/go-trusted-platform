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
	"math"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Gateway BGP QUIC wire mapping.
//
// The five BGP methods ride OpGatewayCategory with sub-opcodes
// OpGatewayBGPStatus through OpGatewayListPrefixes (adapter.go). The server
// handler (pkg/api/quic/gateway_handlers.go) speaks the quicwire BGP shapes,
// so requests and replies are converted here rather than sent verbatim.
// GetBGPStatus carries no body (provisioning.go categoryEmptyBodyMethods).
// The daemon serves the two lists a page at a time, so they are paged
// (categoryPagers) and the caller still receives every peer and prefix.

func init() {
	registerCategoryCodecs(gatewayBGPRequestEncoders, gatewayBGPResponseDecoders)
	for method, pager := range gatewayBGPPagers {
		categoryPagers[method] = pager
	}
}

var gatewayBGPRequestEncoders = map[string]categoryRequestEncoder{
	platformv1.GatewayService_AnnouncePrefix_FullMethodName: requestEncoder(
		platformv1.GatewayService_AnnouncePrefix_FullMethodName, encodeAnnouncePrefixRequest),
	platformv1.GatewayService_WithdrawPrefix_FullMethodName: requestEncoder(
		platformv1.GatewayService_WithdrawPrefix_FullMethodName, encodeWithdrawPrefixRequest),
}

var gatewayBGPResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.GatewayService_GetBGPStatus_FullMethodName:   decodeBGPStatusReply,
	platformv1.GatewayService_AnnouncePrefix_FullMethodName: decodeAnnouncePrefixReply,
	platformv1.GatewayService_WithdrawPrefix_FullMethodName: decodeWithdrawPrefixReply,
}

var gatewayBGPPagers = map[string]categoryPager{
	platformv1.GatewayService_ListBGPPeers_FullMethodName: {
		request: pagedRequest(platformv1.GatewayService_ListBGPPeers_FullMethodName, encodeListBGPPeersRequest),
		decode:  decodeListBGPPeersPage,
	},
	platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName: {
		request: pagedRequest(platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName, encodeListAnnouncedPrefixesRequest),
		decode:  decodeListAnnouncedPrefixesPage,
	},
}

// gatewayListPageSize is the page the SDK asks for: the most the daemon
// serves in one reply (gatewayMaxLimit in pkg/api/quic). A daemon that
// serves fewer costs more round trips, not entries.
const gatewayListPageSize int32 = 1000

// encodeListBGPPeersRequest asks for the page of peers starting at offset.
func encodeListBGPPeersRequest(_ *platformv1.ListBGPPeersRequest, offset int32) interface{} {
	return &quicwire.GatewayBGPPeersRequest{Limit: gatewayListPageSize, Offset: offset}
}

func encodeAnnouncePrefixRequest(in *platformv1.AnnouncePrefixRequest) (interface{}, error) {
	return &quicwire.GatewayAnnouncePrefixRequest{Prefix: in.GetPrefix(), NextHop: in.GetNextHop()}, nil
}

func encodeWithdrawPrefixRequest(in *platformv1.WithdrawPrefixRequest) (interface{}, error) {
	return &quicwire.GatewayWithdrawPrefixRequest{Prefix: in.GetPrefix()}, nil
}

// encodeListAnnouncedPrefixesRequest asks for the page of announced
// prefixes starting at offset.
func encodeListAnnouncedPrefixesRequest(_ *platformv1.ListAnnouncedPrefixesRequest, offset int32) interface{} {
	return &quicwire.GatewayListPrefixesRequest{Limit: gatewayListPageSize, Offset: offset}
}

func decodeBGPStatusReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetBGPStatusResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_GetBGPStatus_FullMethodName}
	}
	var wire quicwire.GatewayBGPStatusResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Status = bgpStatusFromWire(wire.Status)
	return nil
}

// decodeListBGPPeersPage appends one page of peers to the reply. The page
// counts every wire entry, a nil one too, since the offset counts the
// daemon's entries.
func decodeListBGPPeersPage(payload []byte, reply interface{}) (categoryPage, error) {
	out, ok := reply.(*platformv1.ListBGPPeersResponse)
	if !ok {
		return categoryPage{}, ErrInvalidReplyType{Method: platformv1.GatewayService_ListBGPPeers_FullMethodName}
	}
	var wire quicwire.GatewayBGPPeersResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return categoryPage{}, err
	}
	now := time.Now()
	for _, peer := range wire.Peers {
		if peer != nil {
			out.Peers = append(out.Peers, bgpPeerFromWire(peer, now))
		}
	}
	return categoryPage{received: pageCount(len(wire.Peers)), total: wire.Total}, nil
}

func decodeAnnouncePrefixReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.AnnouncePrefixResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_AnnouncePrefix_FullMethodName}
	}
	var wire quicwire.GatewayAnnouncePrefixResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: wire.Success}
	return nil
}

func decodeWithdrawPrefixReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.WithdrawPrefixResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_WithdrawPrefix_FullMethodName}
	}
	var wire quicwire.GatewayWithdrawPrefixResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: wire.Success}
	return nil
}

// decodeListAnnouncedPrefixesPage appends one page of announced prefixes
// to the reply, counting the page as decodeListBGPPeersPage does.
func decodeListAnnouncedPrefixesPage(payload []byte, reply interface{}) (categoryPage, error) {
	out, ok := reply.(*platformv1.ListAnnouncedPrefixesResponse)
	if !ok {
		return categoryPage{}, ErrInvalidReplyType{Method: platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName}
	}
	var wire quicwire.GatewayListPrefixesResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return categoryPage{}, err
	}
	for _, prefix := range wire.Prefixes {
		if prefix != nil {
			out.Prefixes = append(out.Prefixes, &platformv1.AnnouncedPrefix{
				Prefix:      prefix.Prefix,
				NextHop:     prefix.NextHop,
				AnnouncedAt: unixTimestamp(prefix.AnnouncedAt),
			})
		}
	}
	return categoryPage{received: pageCount(len(wire.Prefixes)), total: wire.Total}, nil
}

// bgpStatusFromWire converts the wire status; a reply without one is a nil
// status, as the gRPC transport would carry it.
func bgpStatusFromWire(s *quicwire.BGPStatusInfo) *platformv1.BGPStatus {
	if s == nil {
		return nil
	}
	return &platformv1.BGPStatus{
		LocalAsn:          s.LocalAS,
		RouterId:          s.RouterID,
		PeerCount:         wireCount32(s.PeerCount),
		EstablishedPeers:  wireCount32(s.EstablishedCount),
		PrefixesAnnounced: wireCount32(s.PrefixesSent),
		Running:           s.Enabled,
	}
}

// bgpPeerFromWire converts a wire peer. The wire carries seconds in the
// Established state; the proto carries the moment it was entered, so a peer
// that is not established has no Uptime.
func bgpPeerFromWire(p *quicwire.BGPPeerInfo, now time.Time) *platformv1.BGPPeer {
	peer := &platformv1.BGPPeer{
		Address:          p.Address,
		Asn:              p.RemoteAS,
		State:            p.State,
		Description:      p.Description,
		PrefixesReceived: wireCount32(p.PrefixesReceived),
		PrefixesSent:     wireCount32(p.PrefixesSent),
	}
	if p.Uptime > 0 {
		peer.Uptime = timestamppb.New(now.Add(-time.Duration(p.Uptime) * time.Second))
	}
	return peer
}

// wireCount32 converts a wire count to the proto's uint32, reporting a
// negative count as zero and saturating one beyond the uint32 range.
func wireCount32(n int) uint32 {
	count := nonNegative(n)
	if count > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(count)
}
