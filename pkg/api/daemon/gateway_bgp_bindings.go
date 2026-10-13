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

package daemon

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// GatewayBGPController is the BGP half of the gateway gRPC service. The
// QUIC, MCP and REST surfaces bind to it so every transport answers from
// the one implementation (#65): on a node with no BGP speaker they all
// report BGP as not configured.
type GatewayBGPController interface {
	GetBGPStatus(ctx context.Context, req *platformv1.GetBGPStatusRequest) (*platformv1.GetBGPStatusResponse, error)
	ListBGPPeers(ctx context.Context, req *platformv1.ListBGPPeersRequest) (*platformv1.ListBGPPeersResponse, error)
	AnnouncePrefix(ctx context.Context, req *platformv1.AnnouncePrefixRequest) (*platformv1.AnnouncePrefixResponse, error)
	WithdrawPrefix(ctx context.Context, req *platformv1.WithdrawPrefixRequest) (*platformv1.WithdrawPrefixResponse, error)
	ListAnnouncedPrefixes(ctx context.Context, req *platformv1.ListAnnouncedPrefixesRequest) (*platformv1.ListAnnouncedPrefixesResponse, error)
}

// Compile-time check: the gateway gRPC service is a BGP controller.
var _ GatewayBGPController = (*GatewayService)(nil)

// gatewayBGPQUICAdapter serves the QUIC BGP sub-opcodes from the gateway
// gRPC service. gRPC status errors pass through; the QUIC handler maps
// their codes.
type gatewayBGPQUICAdapter struct {
	controller GatewayBGPController
}

// BGPStatus returns the BGP speaker status.
func (a gatewayBGPQUICAdapter) BGPStatus(ctx context.Context) (*quic.BGPStatusInfo, error) {
	if a.controller == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	resp, err := a.controller.GetBGPStatus(ctx, &platformv1.GetBGPStatusRequest{})
	if err != nil {
		return nil, err
	}
	return protoBGPStatusToQUIC(resp.GetStatus()), nil
}

// ListBGPPeers returns the BGP speaker's peers.
func (a gatewayBGPQUICAdapter) ListBGPPeers(ctx context.Context) ([]*quic.BGPPeerInfo, error) {
	if a.controller == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	resp, err := a.controller.ListBGPPeers(ctx, &platformv1.ListBGPPeersRequest{})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	peers := make([]*quic.BGPPeerInfo, 0, len(resp.GetPeers()))
	for _, p := range resp.GetPeers() {
		peers = append(peers, protoBGPPeerToQUIC(p, now))
	}
	return peers, nil
}

// AnnouncePrefix announces prefix with the options' next hop. The gateway
// service announces with its own path attributes, so a request carrying
// LOCAL_PREF, MED, communities or labels is refused rather than announced
// without them.
func (a gatewayBGPQUICAdapter) AnnouncePrefix(ctx context.Context, prefix string, opts *quic.AnnouncePrefixOptions) error {
	if a.controller == nil {
		return errGatewayFeatureNotConfigured
	}
	var nextHop string
	if opts != nil {
		if err := unsupportedBGPAttribute(opts); err != nil {
			return err
		}
		nextHop = opts.NextHop
	}
	_, err := a.controller.AnnouncePrefix(ctx, &platformv1.AnnouncePrefixRequest{Prefix: prefix, NextHop: nextHop})
	return err
}

// WithdrawPrefix withdraws an announced prefix.
func (a gatewayBGPQUICAdapter) WithdrawPrefix(ctx context.Context, prefix string) error {
	if a.controller == nil {
		return errGatewayFeatureNotConfigured
	}
	_, err := a.controller.WithdrawPrefix(ctx, &platformv1.WithdrawPrefixRequest{Prefix: prefix})
	return err
}

// ListPrefixes returns the prefixes the BGP speaker announces.
func (a gatewayBGPQUICAdapter) ListPrefixes(ctx context.Context) ([]*quic.PrefixInfo, error) {
	if a.controller == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	resp, err := a.controller.ListAnnouncedPrefixes(ctx, &platformv1.ListAnnouncedPrefixesRequest{})
	if err != nil {
		return nil, err
	}
	prefixes := make([]*quic.PrefixInfo, 0, len(resp.GetPrefixes()))
	for _, p := range resp.GetPrefixes() {
		prefixes = append(prefixes, protoAnnouncedPrefixToQUIC(p))
	}
	return prefixes, nil
}

// unsupportedBGPAttribute returns ErrBGPAttributeUnsupported naming the
// first path attribute in opts the gateway service cannot announce with,
// or nil when there is none.
func unsupportedBGPAttribute(opts *quic.AnnouncePrefixOptions) error {
	switch {
	case opts.LocalPref != 0:
		return ErrBGPAttributeUnsupported{Attribute: "local_pref"}
	case opts.MED != 0:
		return ErrBGPAttributeUnsupported{Attribute: "med"}
	case len(opts.Communities) > 0:
		return ErrBGPAttributeUnsupported{Attribute: "communities"}
	case len(opts.Labels) > 0:
		return ErrBGPAttributeUnsupported{Attribute: "labels"}
	default:
		return nil
	}
}

// protoBGPStatusToQUIC converts the gRPC BGP status to its QUIC wire
// shape; nil stays nil.
func protoBGPStatusToQUIC(s *platformv1.BGPStatus) *quic.BGPStatusInfo {
	if s == nil {
		return nil
	}
	return &quic.BGPStatusInfo{
		Enabled:          s.GetRunning(),
		RouterID:         s.GetRouterId(),
		LocalAS:          s.GetLocalAsn(),
		PeerCount:        int(s.GetPeerCount()),
		EstablishedCount: int(s.GetEstablishedPeers()),
		PrefixesSent:     int(s.GetPrefixesAnnounced()),
	}
}

// protoBGPPeerToQUIC converts a gRPC BGP peer to its QUIC wire shape. The
// gRPC uptime is the time the session came up; the QUIC uptime is its age
// in seconds at now. nil stays nil.
func protoBGPPeerToQUIC(p *platformv1.BGPPeer, now time.Time) *quic.BGPPeerInfo {
	if p == nil {
		return nil
	}
	info := &quic.BGPPeerInfo{
		Address:          p.GetAddress(),
		RemoteAS:         p.GetAsn(),
		State:            p.GetState(),
		Description:      p.GetDescription(),
		PrefixesReceived: int(p.GetPrefixesReceived()),
		PrefixesSent:     int(p.GetPrefixesSent()),
	}
	if p.GetUptime() != nil {
		info.Uptime = int64(now.Sub(p.GetUptime().AsTime()).Seconds())
	}
	return info
}

// protoAnnouncedPrefixToQUIC converts a gRPC announced prefix to its QUIC
// wire shape; nil stays nil.
func protoAnnouncedPrefixToQUIC(p *platformv1.AnnouncedPrefix) *quic.PrefixInfo {
	if p == nil {
		return nil
	}
	info := &quic.PrefixInfo{
		Prefix:  p.GetPrefix(),
		NextHop: p.GetNextHop(),
		Status:  "announced",
	}
	if p.GetAnnouncedAt() != nil {
		info.AnnouncedAt = p.GetAnnouncedAt().AsTime().Unix()
	}
	return info
}

// bgpStatusView is the MCP result of gateway_bgp_status.
type bgpStatusView struct {
	LocalASN          uint32 `json:"local_asn"`
	RouterID          string `json:"router_id"`
	PeerCount         uint32 `json:"peer_count"`
	EstablishedPeers  uint32 `json:"established_peers"`
	PrefixesAnnounced uint32 `json:"prefixes_announced"`
	Running           bool   `json:"running"`
}

// bgpPeerView is one entry of the MCP gateway_bgp_peers result.
// EstablishedAt is when the session came up; it is absent while it is down.
type bgpPeerView struct {
	Address          string     `json:"address"`
	ASN              uint32     `json:"asn"`
	State            string     `json:"state"`
	Description      string     `json:"description,omitempty"`
	PrefixesReceived uint32     `json:"prefixes_received"`
	PrefixesSent     uint32     `json:"prefixes_sent"`
	EstablishedAt    *time.Time `json:"established_at,omitempty"`
}

// announcedPrefixView is one entry of the MCP gateway_bgp_prefixes result.
type announcedPrefixView struct {
	Prefix      string     `json:"prefix"`
	NextHop     string     `json:"next_hop,omitempty"`
	AnnouncedAt *time.Time `json:"announced_at,omitempty"`
}

// newBGPStatusView converts the gRPC BGP status to its MCP view; nil stays
// nil.
func newBGPStatusView(s *platformv1.BGPStatus) *bgpStatusView {
	if s == nil {
		return nil
	}
	return &bgpStatusView{
		LocalASN:          s.GetLocalAsn(),
		RouterID:          s.GetRouterId(),
		PeerCount:         s.GetPeerCount(),
		EstablishedPeers:  s.GetEstablishedPeers(),
		PrefixesAnnounced: s.GetPrefixesAnnounced(),
		Running:           s.GetRunning(),
	}
}

// newBGPPeerView converts a gRPC BGP peer to its MCP view; nil stays nil.
func newBGPPeerView(p *platformv1.BGPPeer) *bgpPeerView {
	if p == nil {
		return nil
	}
	view := &bgpPeerView{
		Address:          p.GetAddress(),
		ASN:              p.GetAsn(),
		State:            p.GetState(),
		Description:      p.GetDescription(),
		PrefixesReceived: p.GetPrefixesReceived(),
		PrefixesSent:     p.GetPrefixesSent(),
	}
	if p.GetUptime() != nil {
		established := p.GetUptime().AsTime()
		view.EstablishedAt = &established
	}
	return view
}

// newAnnouncedPrefixView converts a gRPC announced prefix to its MCP view;
// nil stays nil.
func newAnnouncedPrefixView(p *platformv1.AnnouncedPrefix) *announcedPrefixView {
	if p == nil {
		return nil
	}
	view := &announcedPrefixView{
		Prefix:  p.GetPrefix(),
		NextHop: p.GetNextHop(),
	}
	if p.GetAnnouncedAt() != nil {
		announced := p.GetAnnouncedAt().AsTime()
		view.AnnouncedAt = &announced
	}
	return view
}

// gatewayBGPTools serves the MCP gateway_bgp_* tools from the gateway gRPC
// service. It is embedded by both MCP service providers.
type gatewayBGPTools struct {
	controller GatewayBGPController
}

// SetGatewayBGPController wires the gateway gRPC service the BGP tools
// answer from.
func (t *gatewayBGPTools) SetGatewayBGPController(controller GatewayBGPController) {
	t.controller = controller
}

// GatewayBGPStatus returns the BGP speaker status.
func (t gatewayBGPTools) GatewayBGPStatus(ctx context.Context) (interface{}, error) {
	if t.controller == nil {
		return nil, ErrServiceNotAvailable{Service: "gateway"}
	}
	resp, err := t.controller.GetBGPStatus(ctx, &platformv1.GetBGPStatusRequest{})
	if err != nil {
		return nil, err
	}
	return newBGPStatusView(resp.GetStatus()), nil
}

// GatewayBGPPeers returns the BGP speaker's peers.
func (t gatewayBGPTools) GatewayBGPPeers(ctx context.Context) ([]interface{}, error) {
	if t.controller == nil {
		return nil, ErrServiceNotAvailable{Service: "gateway"}
	}
	resp, err := t.controller.ListBGPPeers(ctx, &platformv1.ListBGPPeersRequest{})
	if err != nil {
		return nil, err
	}
	peers := make([]interface{}, 0, len(resp.GetPeers()))
	for _, p := range resp.GetPeers() {
		peers = append(peers, newBGPPeerView(p))
	}
	return peers, nil
}

// GatewayBGPAnnounce announces prefix via nextHop; an empty nextHop lets
// the speaker choose.
func (t gatewayBGPTools) GatewayBGPAnnounce(ctx context.Context, prefix, nextHop string) error {
	if t.controller == nil {
		return ErrServiceNotAvailable{Service: "gateway"}
	}
	_, err := t.controller.AnnouncePrefix(ctx, &platformv1.AnnouncePrefixRequest{Prefix: prefix, NextHop: nextHop})
	return err
}

// GatewayBGPWithdraw withdraws an announced prefix.
func (t gatewayBGPTools) GatewayBGPWithdraw(ctx context.Context, prefix string) error {
	if t.controller == nil {
		return ErrServiceNotAvailable{Service: "gateway"}
	}
	_, err := t.controller.WithdrawPrefix(ctx, &platformv1.WithdrawPrefixRequest{Prefix: prefix})
	return err
}

// GatewayBGPPrefixes returns the prefixes the BGP speaker announces.
func (t gatewayBGPTools) GatewayBGPPrefixes(ctx context.Context) ([]interface{}, error) {
	if t.controller == nil {
		return nil, ErrServiceNotAvailable{Service: "gateway"}
	}
	resp, err := t.controller.ListAnnouncedPrefixes(ctx, &platformv1.ListAnnouncedPrefixesRequest{})
	if err != nil {
		return nil, err
	}
	prefixes := make([]interface{}, 0, len(resp.GetPrefixes()))
	for _, p := range resp.GetPrefixes() {
		prefixes = append(prefixes, newAnnouncedPrefixView(p))
	}
	return prefixes, nil
}
