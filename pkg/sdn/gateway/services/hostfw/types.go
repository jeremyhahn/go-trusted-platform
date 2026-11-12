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

// Package hostfw is the platform-owned host packet filter (#569).
//
// Open vSwitch filters what crosses the bridge; it structurally cannot
// filter traffic addressed to the host itself — the daemon's listeners,
// ssh, the tunnel endpoints. Only the platform knows which listeners a
// node is supposed to answer on, so it renders the host filter from that
// knowledge: one nftables table, `inet tp_host`, with an input chain whose
// policy is drop and whose accept rules come from a declarative Ruleset —
// the listener inventory the daemons declare, the peer allowances the WAN
// needs (ESP and GRE from named addresses, BGP and BFD on tunnel
// interfaces), and rate-limited ICMP with neighbour discovery always
// admitted. Two layers carry it: an install-time `.nft` file closes the
// boot window before any daemon runs, and the Service reconciles the live
// table atomically whenever the inventory changes.
package hostfw

import (
	"net/netip"
	"sort"
	"strings"
)

// Protocol is a transport protocol a listener accepts.
type Protocol string

const (
	// ProtocolTCP is TCP.
	ProtocolTCP Protocol = "tcp"
	// ProtocolUDP is UDP.
	ProtocolUDP Protocol = "udp"
)

// PeerProtocol is an IP protocol a WAN peer is allowed to send.
type PeerProtocol string

const (
	// PeerProtocolESP is IPsec ESP (IP protocol 50).
	PeerProtocolESP PeerProtocol = "esp"
	// PeerProtocolGRE is GRE (IP protocol 47).
	PeerProtocolGRE PeerProtocol = "gre"
)

const (
	// TableName is the nftables table the filter owns. Nothing else in the
	// table is ever touched; nothing outside it is ever touched.
	TableName = "tp_host"
	// ChainInput is the input chain inside TableName.
	ChainInput = "input"

	// PortBGP is the TCP port allowed on tunnel interfaces for BGP.
	PortBGP uint16 = 179
	// PortBFD is the UDP port allowed on tunnel interfaces for single-hop BFD.
	PortBFD uint16 = 3784

	ipProtoGRE      uint8 = 47
	ipProtoESP      uint8 = 50
	ipProtoVRRP     uint8 = 112
	ipProtoTCP      uint8 = 6
	ipProtoUDP      uint8 = 17
	ipProtoICMP     uint8 = 1
	ipProtoIPv6ICMP uint8 = 58

	// Neighbour-discovery ICMPv6 types (RFC 4861): router solicitation
	// through redirect. Without them an IPv6 host cannot resolve anything.
	icmpv6NDFirst uint8 = 133
	icmpv6NDLast  uint8 = 137
)

// Listener is one socket the host answers on: a protocol and port on an
// interface, optionally restricted to source prefixes. An empty Interface
// means every interface; empty Sources means any source.
type Listener struct {
	Interface string         `yaml:"interface" json:"interface" mapstructure:"interface"`
	Protocol  Protocol       `yaml:"protocol" json:"protocol" mapstructure:"protocol"`
	Port      uint16         `yaml:"port" json:"port" mapstructure:"port"`
	Sources   []netip.Prefix `yaml:"sources,omitempty" json:"sources,omitempty" mapstructure:"sources"`
	// Comment names the listener in the rendered ruleset so an operator
	// reading `nft list table inet tp_host` can tell what each rule is for.
	Comment string `yaml:"comment,omitempty" json:"comment,omitempty" mapstructure:"comment"`
}

// PeerAllowance admits one IP protocol from named peer addresses on an
// interface: the WAN side of an ESP or GRE tunnel.
type PeerAllowance struct {
	Interface string       `yaml:"interface" json:"interface" mapstructure:"interface"`
	Protocol  PeerProtocol `yaml:"protocol" json:"protocol" mapstructure:"protocol"`
	Addresses []netip.Addr `yaml:"addresses" json:"addresses" mapstructure:"addresses"`
}

// RateLimit bounds a packet class to Rate packets per second with Burst
// headroom.
type RateLimit struct {
	Rate  uint64 `yaml:"rate" json:"rate" mapstructure:"rate"`
	Burst uint32 `yaml:"burst" json:"burst" mapstructure:"burst"`
}

// DefaultICMPRateLimit is the ICMP/ICMPv6 limit used when none is set.
var DefaultICMPRateLimit = RateLimit{Rate: 50, Burst: 100}

// Ruleset is the complete declarative input policy for one host.
type Ruleset struct {
	// Listeners are the sockets the host may answer on.
	Listeners []Listener
	// Peers are the WAN peer allowances (ESP, GRE).
	Peers []PeerAllowance
	// Tunnels are the interfaces on which BGP (TCP 179) and BFD (UDP 3784)
	// are accepted from anyone reaching the tunnel — the tunnel itself
	// bounds who that can be.
	Tunnels []string
	// VRRP are the interfaces on which VRRP advertisements (IP protocol 112) from FHRP peers are accepted.
	VRRP []string
	// Unfiltered are interfaces the filter deliberately leaves open. It is
	// for a rollout that must not lock the operator out of the management
	// leg before its listeners are in the inventory; the rendered ruleset
	// names every one so the exception is visible.
	Unfiltered []string
	// ICMP bounds ICMP and ICMPv6 (other than neighbour discovery).
	ICMP RateLimit
}

// ListenerInventory is what gatewayd and platformd implement: the sockets
// they are configured to bind, from their resolved configuration. A
// listener nobody declares is unreachable by construction.
type ListenerInventory interface {
	Listeners() []Listener
}

// StaticInventory is a ListenerInventory over a fixed slice.
type StaticInventory []Listener

// Listeners implements ListenerInventory.
func (s StaticInventory) Listeners() []Listener { return []Listener(s) }

// Config is the hostfw service section: what the operator declares beyond
// the daemons' own inventory.
type Config struct {
	// Enabled turns the service on.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	// Extra are operator-declared listeners the daemons do not own — sshd
	// on the management interface is the canonical one.
	Extra []Listener `yaml:"extra,omitempty" json:"extra,omitempty" mapstructure:"extra"`
	// Peers are the WAN peer allowances.
	Peers []PeerAllowance `yaml:"peers,omitempty" json:"peers,omitempty" mapstructure:"peers"`
	// Tunnels are the tunnel interfaces carrying BGP and BFD.
	Tunnels []string `yaml:"tunnels,omitempty" json:"tunnels,omitempty" mapstructure:"tunnels"`
	// VRRP are the FHRP interfaces that admit VRRP advertisements.
	VRRP []string `yaml:"vrrp,omitempty" json:"vrrp,omitempty" mapstructure:"vrrp"`
	// Unfiltered are interfaces left open on purpose; see Ruleset.
	Unfiltered []string `yaml:"unfiltered,omitempty" json:"unfiltered,omitempty" mapstructure:"unfiltered"`
	// ICMP bounds ICMP; zero fields take DefaultICMPRateLimit.
	ICMP RateLimit `yaml:"icmp" json:"icmp" mapstructure:"icmp"`
	// BaseRulesetPath, when set, is where Start writes the install-time
	// `.nft` file so the next boot's `nft -f` closes the window before the
	// daemons run. Empty writes no file.
	BaseRulesetPath string `yaml:"base-ruleset-path,omitempty" json:"base_ruleset_path,omitempty" mapstructure:"base-ruleset-path"`
}

// Validate checks the operator-declared part of the ruleset.
func (c Config) Validate() error {
	rs := Ruleset{Listeners: c.Extra, Peers: c.Peers, Tunnels: c.Tunnels, Unfiltered: c.Unfiltered, VRRP: c.VRRP, ICMP: c.ICMP}
	return rs.Validate()
}

// Validate checks every entry: interface names must be valid Linux
// interface names, ports non-zero, protocols known, peer addresses
// present, and no two listeners may claim the same interface, protocol and
// port (a duplicate is a sign two inventories disagree, not something to
// merge silently).
func (rs Ruleset) Validate() error {
	seen := map[string]bool{}
	for i, l := range rs.Listeners {
		if err := validateInterface(l.Interface, true); err != nil {
			return &ValidationError{Field: "listeners", Index: i, Err: err}
		}
		if l.Protocol != ProtocolTCP && l.Protocol != ProtocolUDP {
			return &ValidationError{Field: "listeners", Index: i, Err: ErrUnknownProtocol}
		}
		if l.Port == 0 {
			return &ValidationError{Field: "listeners", Index: i, Err: ErrZeroPort}
		}
		for _, p := range l.Sources {
			if !p.IsValid() {
				return &ValidationError{Field: "listeners", Index: i, Err: ErrInvalidPrefix}
			}
		}
		k := listenerKey(l)
		if seen[k] {
			return &ValidationError{Field: "listeners", Index: i, Err: ErrDuplicateListener}
		}
		seen[k] = true
	}
	for i, p := range rs.Peers {
		if err := validateInterface(p.Interface, false); err != nil {
			return &ValidationError{Field: "peers", Index: i, Err: err}
		}
		if p.Protocol != PeerProtocolESP && p.Protocol != PeerProtocolGRE {
			return &ValidationError{Field: "peers", Index: i, Err: ErrUnknownProtocol}
		}
		if len(p.Addresses) == 0 {
			return &ValidationError{Field: "peers", Index: i, Err: ErrNoPeerAddresses}
		}
		for _, a := range p.Addresses {
			if !a.IsValid() || a.IsUnspecified() {
				return &ValidationError{Field: "peers", Index: i, Err: ErrInvalidAddress}
			}
		}
	}
	for i, t := range rs.Tunnels {
		if err := validateInterface(t, false); err != nil {
			return &ValidationError{Field: "tunnels", Index: i, Err: err}
		}
	}
	for i, v := range rs.VRRP {
		if err := validateInterface(v, false); err != nil {
			return &ValidationError{Field: "vrrp", Index: i, Err: err}
		}
	}
	for i, u := range rs.Unfiltered {
		if err := validateInterface(u, false); err != nil {
			return &ValidationError{Field: "unfiltered", Index: i, Err: err}
		}
	}
	return nil
}

// normalized returns a copy with defaults applied and entries sorted so the
// rendering — and its fingerprint — is stable regardless of the order the
// inventories reported them in.
func (rs Ruleset) normalized() Ruleset {
	out := Ruleset{
		Listeners:  append([]Listener(nil), rs.Listeners...),
		Peers:      append([]PeerAllowance(nil), rs.Peers...),
		Tunnels:    append([]string(nil), rs.Tunnels...),
		Unfiltered: append([]string(nil), rs.Unfiltered...),
		VRRP:       append([]string(nil), rs.VRRP...),
		ICMP:       rs.ICMP,
	}
	if out.ICMP.Rate == 0 {
		out.ICMP.Rate = DefaultICMPRateLimit.Rate
	}
	if out.ICMP.Burst == 0 {
		out.ICMP.Burst = DefaultICMPRateLimit.Burst
	}
	sort.SliceStable(out.Listeners, func(i, j int) bool { return listenerKey(out.Listeners[i]) < listenerKey(out.Listeners[j]) })
	for i := range out.Peers {
		addrs := append([]netip.Addr(nil), out.Peers[i].Addresses...)
		sort.Slice(addrs, func(a, b int) bool { return addrs[a].Less(addrs[b]) })
		out.Peers[i].Addresses = addrs
	}
	sort.SliceStable(out.Peers, func(i, j int) bool {
		return out.Peers[i].Interface+"/"+string(out.Peers[i].Protocol) < out.Peers[j].Interface+"/"+string(out.Peers[j].Protocol)
	})
	sort.Strings(out.Tunnels)
	sort.Strings(out.Unfiltered)
	sort.Strings(out.VRRP)
	return out
}

func listenerKey(l Listener) string {
	return l.Interface + "/" + string(l.Protocol) + "/" + itoa(int(l.Port))
}

// validateInterface accepts a Linux interface name: 1–15 characters, no
// whitespace, slash or NUL. allowEmpty admits "" (every interface).
func validateInterface(name string, allowEmpty bool) error {
	if name == "" {
		if allowEmpty {
			return nil
		}
		return ErrEmptyInterface
	}
	if len(name) > 15 || strings.ContainsAny(name, " \t\n/\x00\"") {
		return ErrInvalidInterface
	}
	return nil
}
