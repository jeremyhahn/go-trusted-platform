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

package quicwire

// Wire shapes of the gateway BGP sub-opcodes (OpGatewayBGPStatus through
// OpGatewayListPrefixes). The server handler and the SDK adapter share them
// so the two ends cannot drift.

// BGPStatusInfo contains BGP status information
type BGPStatusInfo struct {
	Enabled           bool   `codec:"enabled"`
	RouterID          string `codec:"router_id"`
	LocalAS           uint32 `codec:"local_as"`
	HoldTime          int    `codec:"hold_time"`
	KeepaliveInterval int    `codec:"keepalive_interval"`
	PeerCount         int    `codec:"peer_count"`
	EstablishedCount  int    `codec:"established_count"`
	PrefixesReceived  int    `codec:"prefixes_received"`
	PrefixesSent      int    `codec:"prefixes_sent"`
	Uptime            int64  `codec:"uptime"`
	LastError         string `codec:"last_error,omitempty"`
}

// BGPPeerInfo contains BGP peer information. Uptime is seconds in the
// Established state; zero means not established.
type BGPPeerInfo struct {
	Address          string   `codec:"address"`
	RemoteAS         uint32   `codec:"remote_as"`
	LocalAS          uint32   `codec:"local_as"`
	State            string   `codec:"state"`
	Description      string   `codec:"description,omitempty"`
	HoldTime         int      `codec:"hold_time"`
	KeepaliveTime    int      `codec:"keepalive_time"`
	PrefixesReceived int      `codec:"prefixes_received"`
	PrefixesSent     int      `codec:"prefixes_sent"`
	Uptime           int64    `codec:"uptime"`
	LastError        string   `codec:"last_error,omitempty"`
	Capabilities     []string `codec:"capabilities,omitempty"`
	RouteReflector   bool     `codec:"route_reflector"`
}

// PrefixInfo contains announced prefix information. AnnouncedAt is Unix
// seconds; zero means unknown.
type PrefixInfo struct {
	Prefix      string            `codec:"prefix"`
	NextHop     string            `codec:"next_hop,omitempty"`
	Origin      string            `codec:"origin"`
	ASPath      []uint32          `codec:"as_path,omitempty"`
	LocalPref   uint32            `codec:"local_pref,omitempty"`
	MED         uint32            `codec:"med,omitempty"`
	Communities []string          `codec:"communities,omitempty"`
	Status      string            `codec:"status"`
	AnnouncedAt int64             `codec:"announced_at"`
	Labels      map[string]string `codec:"labels,omitempty"`
}

// GatewayBGPStatusResponse represents a BGP status response
type GatewayBGPStatusResponse struct {
	Status    *BGPStatusInfo `codec:"status"`
	Timestamp int64          `codec:"timestamp"`
}

// GatewayBGPPeersRequest represents a BGP peers list request: the page of
// at most Limit peers starting at Offset.
type GatewayBGPPeersRequest struct {
	Limit  int32 `codec:"limit,omitempty"`
	Offset int32 `codec:"offset,omitempty"`
}

// GatewayBGPPeersResponse represents a BGP peers list response. Count is
// the page's length and Total the number of peers the gateway holds.
type GatewayBGPPeersResponse struct {
	Peers     []*BGPPeerInfo `codec:"peers"`
	Count     int32          `codec:"count"`
	Total     int32          `codec:"total"`
	Timestamp int64          `codec:"timestamp"`
}

// GatewayAnnouncePrefixRequest represents a prefix announce request
type GatewayAnnouncePrefixRequest struct {
	Prefix      string            `codec:"prefix"`
	NextHop     string            `codec:"next_hop,omitempty"`
	LocalPref   uint32            `codec:"local_pref,omitempty"`
	MED         uint32            `codec:"med,omitempty"`
	Communities []string          `codec:"communities,omitempty"`
	Labels      map[string]string `codec:"labels,omitempty"`
}

// GatewayAnnouncePrefixResponse represents a prefix announce response
type GatewayAnnouncePrefixResponse struct {
	Prefix    string `codec:"prefix"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// GatewayWithdrawPrefixRequest represents a prefix withdraw request
type GatewayWithdrawPrefixRequest struct {
	Prefix string `codec:"prefix"`
}

// GatewayWithdrawPrefixResponse represents a prefix withdraw response
type GatewayWithdrawPrefixResponse struct {
	Prefix    string `codec:"prefix"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// GatewayListPrefixesRequest represents a prefixes list request: the page
// of at most Limit announced prefixes starting at Offset.
type GatewayListPrefixesRequest struct {
	Limit  int32 `codec:"limit,omitempty"`
	Offset int32 `codec:"offset,omitempty"`
}

// GatewayListPrefixesResponse represents a prefixes list response. Count is
// the page's length and Total the number of prefixes the gateway announces.
type GatewayListPrefixesResponse struct {
	Prefixes  []*PrefixInfo `codec:"prefixes"`
	Count     int32         `codec:"count"`
	Total     int32         `codec:"total"`
	Timestamp int64         `codec:"timestamp"`
}
