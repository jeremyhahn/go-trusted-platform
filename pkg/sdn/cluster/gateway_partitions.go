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

package cluster

import (
	"encoding/json"
	"time"
)

// Gateway data-plane partitions use the HighPerfStateMachine for
// in-memory concurrent state that is replicated asynchronously via Raft.
// These hold high-frequency, latency-sensitive data that must never
// block the packet forwarding path.
const (
	// PartitionGatewayConnTrack stores connection tracking entries.
	// Replicated asynchronously in batches for HA failover.
	PartitionGatewayConnTrack = "gw/conntrack"

	// PartitionGatewayNATSessions stores NAT session mappings
	// (source IP:port to translated IP:port).
	PartitionGatewayNATSessions = "gw/nat/sessions"
)

// Gateway control-plane partitions use the standard durable state
// machine for configuration state that must survive node restarts.
const (
	// PartitionGatewayVIPs stores VIP ownership assignments across
	// the gateway cluster. Changes trigger gratuitous ARP (LAN) or
	// BGP route withdrawal (WAN).
	PartitionGatewayVIPs = "gw/vips"

	// PartitionGatewayFirewallRules stores the active firewall rule
	// set. Replicated synchronously via Raft for consistency.
	PartitionGatewayFirewallRules = "gw/firewall/rules"

	// PartitionGatewayBGPRoutes stores BGP route state including
	// advertised prefixes, AS path, and next-hop information.
	PartitionGatewayBGPRoutes = "gw/bgp/routes"
)

// VIPEntry represents a Virtual IP address assignment in the gateway
// cluster. VIPs are distributed across gateway nodes in an active-active
// configuration. On node failure, surviving nodes take over orphaned VIPs
// via Raft registry update + gratuitous ARP (LAN) or BGP withdrawal (WAN).
type VIPEntry struct {
	// Address is the VIP address in CIDR notation (e.g., "203.0.113.1/24").
	Address string `json:"address"`

	// OwnerNode is the cluster node ID that currently owns this VIP.
	OwnerNode string `json:"owner_node"`

	// Priority determines VIP assignment preference during rebalancing.
	// Higher values indicate higher priority for ownership.
	Priority int `json:"priority"`

	// LastSeen is the timestamp of the last heartbeat from the owner node.
	LastSeen time.Time `json:"last_seen"`

	// Active indicates whether this VIP is currently being served.
	Active bool `json:"active"`
}

// EntityID returns a deterministic entity ID for QuicBaaS storage
// derived from the VIP address.
func (v *VIPEntry) EntityID() uint64 {
	return hashString(v.Address)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as the entity ID is derived from the VIP address.
func (v *VIPEntry) SetEntityID(_ uint64) {
	// No-op: entity ID is derived from address.
}

// MarshalJSON implements json.Marshaler for VIPEntry.
func (v *VIPEntry) MarshalJSON() ([]byte, error) {
	type vipAlias VIPEntry
	return json.Marshal((*vipAlias)(v))
}

// UnmarshalJSON implements json.Unmarshaler for VIPEntry.
func (v *VIPEntry) UnmarshalJSON(data []byte) error {
	type vipAlias VIPEntry
	return json.Unmarshal(data, (*vipAlias)(v))
}

// ConnTrackEntry represents a tracked connection in the gateway
// stateful firewall. These entries are stored in the high-performance
// in-memory partition and replicated asynchronously for HA failover.
type ConnTrackEntry struct {
	// ID is a unique identifier for this connection (typically a
	// hash of the 5-tuple).
	ID string `json:"id"`

	// Protocol is the IP protocol number (6=TCP, 17=UDP, 1=ICMP).
	Protocol uint8 `json:"protocol"`

	// SrcAddr is the source IP address.
	SrcAddr string `json:"src_addr"`

	// DstAddr is the destination IP address.
	DstAddr string `json:"dst_addr"`

	// SrcPort is the source transport port.
	SrcPort uint16 `json:"src_port"`

	// DstPort is the destination transport port.
	DstPort uint16 `json:"dst_port"`

	// State is the connection state (e.g., "NEW", "ESTABLISHED",
	// "RELATED", "TIME_WAIT").
	State string `json:"state"`

	// CreatedAt is the timestamp when this connection was first seen.
	CreatedAt time.Time `json:"created_at"`

	// LastSeen is the timestamp of the last packet for this connection.
	LastSeen time.Time `json:"last_seen"`

	// BytesSent is the total bytes sent in the forward direction.
	BytesSent uint64 `json:"bytes_sent"`

	// BytesRecv is the total bytes received in the reverse direction.
	BytesRecv uint64 `json:"bytes_recv"`

	// PacketsSent is the total packets sent in the forward direction.
	PacketsSent uint64 `json:"packets_sent"`

	// PacketsRecv is the total packets received in the reverse direction.
	PacketsRecv uint64 `json:"packets_recv"`
}

// EntityID returns a deterministic entity ID for QuicBaaS storage
// derived from the connection ID.
func (c *ConnTrackEntry) EntityID() uint64 {
	return hashString(c.ID)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as the entity ID is derived from the connection ID.
func (c *ConnTrackEntry) SetEntityID(_ uint64) {
	// No-op: entity ID is derived from ID.
}

// NATSessionEntry represents a NAT session mapping in the gateway.
// These entries are stored in the high-performance in-memory partition
// alongside connection tracking entries.
type NATSessionEntry struct {
	// ID is a unique identifier for this NAT session.
	ID string `json:"id"`

	// ConnTrackID links this NAT session to its connection tracking
	// entry.
	ConnTrackID string `json:"conntrack_id"`

	// OrigSrcAddr is the original source IP address before NAT.
	OrigSrcAddr string `json:"orig_src_addr"`

	// OrigSrcPort is the original source port before NAT.
	OrigSrcPort uint16 `json:"orig_src_port"`

	// TransAddr is the translated source IP address after NAT.
	TransAddr string `json:"trans_addr"`

	// TransPort is the translated source port after NAT.
	TransPort uint16 `json:"trans_port"`

	// DstAddr is the destination IP address.
	DstAddr string `json:"dst_addr"`

	// DstPort is the destination transport port.
	DstPort uint16 `json:"dst_port"`

	// Protocol is the IP protocol number.
	Protocol uint8 `json:"protocol"`

	// CreatedAt is the timestamp when this NAT session was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is the timestamp when this NAT session expires.
	ExpiresAt time.Time `json:"expires_at"`
}

// EntityID returns a deterministic entity ID for QuicBaaS storage
// derived from the NAT session ID.
func (n *NATSessionEntry) EntityID() uint64 {
	return hashString(n.ID)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as the entity ID is derived from the NAT session ID.
func (n *NATSessionEntry) SetEntityID(_ uint64) {
	// No-op: entity ID is derived from ID.
}

// FirewallRuleEntry represents an active firewall rule in the gateway
// cluster. Rules are stored in the durable control-plane partition and
// replicated synchronously via Raft.
type FirewallRuleEntry struct {
	// ID is the unique identifier for this firewall rule.
	ID string `json:"id"`

	// Priority determines rule evaluation order (lower = evaluated first).
	Priority int `json:"priority"`

	// Direction specifies whether the rule applies to inbound or outbound
	// traffic ("inbound" or "outbound").
	Direction string `json:"direction"`

	// Action specifies the rule action ("allow", "deny", "reject").
	Action string `json:"action"`

	// Protocol is the IP protocol to match ("tcp", "udp", "icmp", "any").
	Protocol string `json:"protocol"`

	// SrcCIDR is the source address range in CIDR notation.
	SrcCIDR string `json:"src_cidr,omitempty"`

	// DstCIDR is the destination address range in CIDR notation.
	DstCIDR string `json:"dst_cidr,omitempty"`

	// SrcPortRange is the source port range ("80", "1024-65535", "any").
	SrcPortRange string `json:"src_port_range,omitempty"`

	// DstPortRange is the destination port range.
	DstPortRange string `json:"dst_port_range,omitempty"`

	// Stateful indicates whether to create connection tracking entries
	// for traffic matching this rule.
	Stateful bool `json:"stateful"`

	// Enabled indicates whether this rule is currently active.
	Enabled bool `json:"enabled"`

	// Description provides a human-readable description of the rule.
	Description string `json:"description,omitempty"`

	// Version is used for optimistic locking.
	Version uint64 `json:"version"`

	// CreatedAt is the timestamp when this rule was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp of the last update.
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID returns a deterministic entity ID for QuicBaaS storage
// derived from the firewall rule ID.
func (f *FirewallRuleEntry) EntityID() uint64 {
	return hashString(f.ID)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as the entity ID is derived from the firewall rule ID.
func (f *FirewallRuleEntry) SetEntityID(_ uint64) {
	// No-op: entity ID is derived from ID.
}

// BGPRouteEntry represents a BGP route in the gateway cluster state.
// Routes are stored in the durable control-plane partition.
type BGPRouteEntry struct {
	// Prefix is the IP prefix being advertised (e.g., "203.0.113.0/24").
	Prefix string `json:"prefix"`

	// NextHop is the BGP next-hop address.
	NextHop string `json:"next_hop"`

	// ASPath is the AS path for this route.
	ASPath []uint32 `json:"as_path"`

	// LocalPref is the BGP local preference value.
	LocalPref uint32 `json:"local_pref"`

	// MED is the Multi-Exit Discriminator value.
	MED uint32 `json:"med"`

	// Origin specifies the route origin ("igp", "egp", "incomplete").
	Origin string `json:"origin"`

	// Communities contains BGP community values.
	Communities []string `json:"communities,omitempty"`

	// Active indicates whether this route is currently in the RIB.
	Active bool `json:"active"`

	// Source identifies where this route was learned from
	// ("local", "ebgp", "ibgp").
	Source string `json:"source"`

	// PeerAddr is the address of the BGP peer that advertised this route.
	PeerAddr string `json:"peer_addr,omitempty"`

	// LastUpdated is the timestamp of the last route update.
	LastUpdated time.Time `json:"last_updated"`
}

// EntityID returns a deterministic entity ID for QuicBaaS storage
// derived from the route prefix.
func (b *BGPRouteEntry) EntityID() uint64 {
	return hashString(b.Prefix)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as the entity ID is derived from the route prefix.
func (b *BGPRouteEntry) SetEntityID(_ uint64) {
	// No-op: entity ID is derived from prefix.
}
