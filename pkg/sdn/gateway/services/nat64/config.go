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

// Package nat64 implements the gateway's stateful NAT64 service (RFC 6146)
// on top of the Jool kernel translator. The package owns the translator the
// way services/hostfw owns the nftables table: it renders an instance
// configuration, applies it, verifies it, reports its health, and refuses to
// start when the kernel cannot carry it.
//
// The datapath split matters. OVS ct(nat) cannot rewrite between address
// families, so translation is never an OpenFlow action; the pipeline's only
// job is to deliver frames addressed to the translation prefix to the
// translator's port (the table-27 gate) and to leave every other IPv6 frame
// alone. See docs/gateway/engineering.md §"IPv6-only clients" for the packet
// path and docs/gateway/architecture.md for the R6 decision this implements.
package nat64

import (
	"net/netip"
	"strings"
	"time"
)

// DefaultPrefix is the well-known prefix RFC 6052 §2.1 reserves for
// translation. A site that routes its own /96 configures it instead.
const DefaultPrefix = "64:ff9b::/96"

// MaxPool4Addresses bounds the addresses pool4 may name across all its
// ranges: a /16. The driver converges pool4 one address at a time, and a
// typo such as 10.0.0.0-10.255.255.255 would otherwise have it hold and
// compare tens of millions of entries.
const MaxPool4Addresses = 1 << 16

// DefaultInstance is the Jool instance name the service programs when the
// configuration names none.
const DefaultInstance = "tp-nat64"

// RFC 6146 session lifetime defaults (§3.5) and the minimums the same
// section makes mandatory. Zero in the configuration takes the default; a
// value below the minimum is refused rather than quietly raised, because an
// operator who wrote a number meant it and should learn it is not allowed.
const (
	// DefaultUDPTimeout is the RFC 6146 §3.5.1 default UDP session lifetime.
	DefaultUDPTimeout = 5 * time.Minute

	// MinUDPTimeout is the RFC 6146 REQ-5 floor for UDP sessions.
	MinUDPTimeout = 2 * time.Minute

	// DefaultTCPEstablishedTimeout is the RFC 6146 §3.5.2 default lifetime
	// of an established TCP session.
	DefaultTCPEstablishedTimeout = 2*time.Hour + 4*time.Minute

	// MinTCPEstablishedTimeout is the RFC 6146 REQ-7 floor for established
	// TCP sessions.
	MinTCPEstablishedTimeout = 2*time.Hour + 4*time.Minute

	// DefaultTCPTransitoryTimeout is the RFC 6146 §3.5.2 default lifetime
	// of a transitory TCP session.
	DefaultTCPTransitoryTimeout = 4 * time.Minute

	// MinTCPTransitoryTimeout is the RFC 6146 REQ-7 floor for transitory
	// TCP sessions.
	MinTCPTransitoryTimeout = 4 * time.Minute

	// DefaultICMPTimeout is the RFC 6146 §3.5.3 default ICMP query session
	// lifetime.
	DefaultICMPTimeout = 60 * time.Second

	// MinICMPTimeout is the RFC 6146 floor for ICMP query sessions.
	MinICMPTimeout = 60 * time.Second
)

// Pool4Range is one IPv4 address range with the L4 ports the translator may
// allocate on it. It mirrors the NAT44 pool syntax deliberately: an operator
// who can read `nat.uplinks[].addresses` can read this without learning a
// second spelling.
type Pool4Range struct {
	// Addresses is a single address ("203.0.113.64") or an inclusive range
	// ("203.0.113.64-203.0.113.71").
	Addresses string

	// PortStart and PortEnd bound the ports the translator allocates on
	// every address in the range.
	PortStart uint16
	PortEnd   uint16
}

// SessionTimeouts are the RFC 6146 §3.5 session lifetimes. A zero field
// takes its RFC default.
type SessionTimeouts struct {
	// UDP is the UDP session lifetime.
	UDP time.Duration

	// TCPEstablished is the established TCP session lifetime.
	TCPEstablished time.Duration

	// TCPTransitory is the transitory TCP session lifetime.
	TCPTransitory time.Duration

	// ICMP is the ICMP query session lifetime.
	ICMP time.Duration
}

// WithDefaults returns the timeouts with every zero field filled from RFC
// 6146 §3.5. It is exported because a caller rendering an instance without
// a Config — the integration suite, and any tool that wants the standard's
// numbers — needs the same defaults the service applies.
func (t SessionTimeouts) WithDefaults() SessionTimeouts {
	if t.UDP == 0 {
		t.UDP = DefaultUDPTimeout
	}
	if t.TCPEstablished == 0 {
		t.TCPEstablished = DefaultTCPEstablishedTimeout
	}
	if t.TCPTransitory == 0 {
		t.TCPTransitory = DefaultTCPTransitoryTimeout
	}
	if t.ICMP == 0 {
		t.ICMP = DefaultICMPTimeout
	}
	return t
}

// timeoutRule is one validated lifetime: the field's name for the error and
// the RFC floor it may not go below.
type timeoutRule struct {
	name  string
	value time.Duration
	min   time.Duration
}

// validate checks every lifetime against its RFC 6146 floor.
func (t SessionTimeouts) validate() error {
	for _, rule := range []timeoutRule{
		{"udp", t.UDP, MinUDPTimeout},
		{"tcp-established", t.TCPEstablished, MinTCPEstablishedTimeout},
		{"tcp-transitory", t.TCPTransitory, MinTCPTransitoryTimeout},
		{"icmp", t.ICMP, MinICMPTimeout},
	} {
		if rule.value < rule.min {
			return &ErrSessionTimeoutTooLow{Field: rule.name, Value: rule.value, Min: rule.min}
		}
	}
	return nil
}

// ClientZone is a client zone whose traffic to the translation prefix is
// diverted. Naming zones explicitly is what keeps the divert an operator
// decision: a zone that is not listed reaches no IPv4 destination through
// the translator, because the divert outranks the firewall's zone gate and
// so the zone matrix does not adjudicate the translated flow.
type ClientZone struct {
	// Name is the zone name, used in flow comments and health only.
	Name string

	// VLAN is the zone's VLAN ID; the divert matches it so only this zone's
	// frames are translated.
	VLAN uint16
}

// Config is the NAT64 service configuration. The gateway maps its
// serialized NAT64Config section onto this struct; the nat64 package owns
// its own type so it never imports the gateway package that composes it.
type Config struct {
	// Prefix is the RFC 6052 translation prefix (pool6). Empty takes
	// DefaultPrefix.
	Prefix string

	// Instance is the Jool instance name. Empty takes DefaultInstance.
	Instance string

	// TranslatorPort is the OVS port name the table-27 gate outputs to —
	// the internal port whose host side the translator's netfilter hooks
	// see. There is no default: a wrong guess here is a black hole.
	TranslatorPort string

	// Bridge is the OVS bridge carrying the gate and the divert.
	Bridge string

	// Pool4 are the IPv4 ranges the translator allocates from. At least one
	// is required.
	Pool4 []Pool4Range

	// Timeouts are the RFC 6146 session lifetimes.
	Timeouts SessionTimeouts

	// ClientZones restricts the divert to the named zones. Empty diverts
	// every frame addressed to the prefix, whatever zone it came from.
	ClientZones []ClientZone
}

// pool is a validated IPv4 pool range.
type pool struct {
	first, last netip.Addr
	portStart   uint16
	portEnd     uint16
}

// overlaps reports whether two pools share an address and a port at once.
// Ranges that share addresses but no port, or ports but no address, can
// coexist: the allocation key is the pair.
func (p pool) overlaps(other pool) bool {
	if p.last.Less(other.first) || other.last.Less(p.first) {
		return false
	}
	return p.portStart <= other.portEnd && other.portStart <= p.portEnd
}

// String renders the pool the way the configuration spells it.
func (p pool) String() string {
	addr := p.first.String()
	if p.last != p.first {
		addr += "-" + p.last.String()
	}
	return addr
}

// resolved is a validated Config: every field parsed once, at Start, so no
// flow builder or driver call has to re-parse or re-check.
type resolved struct {
	prefix   netip.Prefix
	instance string
	port     string
	bridge   string
	pools    []pool
	timeouts SessionTimeouts
	zones    []ClientZone
}

// parsePool4 parses "addr" or "first-last" into an inclusive IPv4 range.
func parsePool4(spec string, portStart, portEnd uint16) (pool, error) {
	first, last, found := strings.Cut(spec, "-")
	if !found {
		last = first
	}
	a, err := netip.ParseAddr(strings.TrimSpace(first))
	if err != nil || !a.Is4() {
		return pool{}, ErrInvalidPool4Range
	}
	b, err := netip.ParseAddr(strings.TrimSpace(last))
	if err != nil || !b.Is4() {
		return pool{}, ErrInvalidPool4Range
	}
	if b.Less(a) {
		return pool{}, ErrInvalidPool4Range
	}
	if portStart == 0 || portStart >= portEnd {
		return pool{}, ErrInvalidPortRange
	}
	return pool{first: a, last: b, portStart: portStart, portEnd: portEnd}, nil
}

// ParsePrefix validates a pool6 translation prefix: it must parse as IPv6,
// be exactly on a prefix boundary, and carry one of the RFC 6052 lengths.
// It is exported because the gateway validates the section before the
// service is ever built.
func ParsePrefix(spec string) (netip.Prefix, error) {
	if spec == "" {
		spec = DefaultPrefix
	}
	pfx, err := netip.ParsePrefix(spec)
	if err != nil {
		return netip.Prefix{}, &ErrInvalidNAT64Prefix{Prefix: spec, Reason: "not an IP prefix"}
	}
	if !pfx.Addr().Is6() || pfx.Addr().Is4In6() {
		return netip.Prefix{}, &ErrInvalidNAT64Prefix{Prefix: spec, Reason: "not an IPv6 prefix"}
	}
	if pfx.Masked() != pfx {
		return netip.Prefix{}, &ErrInvalidNAT64Prefix{Prefix: spec, Reason: "has bits set below the prefix length"}
	}
	for _, l := range rfc6052Lengths {
		if pfx.Bits() == l {
			return pfx, nil
		}
	}
	return netip.Prefix{}, InvalidPrefixLength(spec, pfx.Bits())
}

// resolve validates the whole configuration and returns the parsed form.
func (c *Config) resolve() (*resolved, error) {
	pfx, err := ParsePrefix(c.Prefix)
	if err != nil {
		return nil, err
	}
	if c.Bridge == "" {
		return nil, ErrEmptyBridge
	}
	if c.TranslatorPort == "" {
		return nil, ErrEmptyTranslatorPort
	}
	instance := c.Instance
	if instance == "" {
		instance = DefaultInstance
	}
	if strings.TrimSpace(instance) == "" {
		return nil, ErrEmptyInstance
	}
	if len(c.Pool4) == 0 {
		return nil, ErrNoPool4
	}
	pools := make([]pool, 0, len(c.Pool4))
	for _, spec := range c.Pool4 {
		p, err := parsePool4(spec.Addresses, spec.PortStart, spec.PortEnd)
		if err != nil {
			return nil, err
		}
		pools = append(pools, p)
	}
	var total uint64
	for _, p := range pools {
		total += ipv4Uint(p.last) - ipv4Uint(p.first) + 1
	}
	if total > MaxPool4Addresses {
		return nil, &ErrPool4TooLarge{Addresses: total, Max: MaxPool4Addresses}
	}
	for i := range pools {
		for j := i + 1; j < len(pools); j++ {
			if pools[i].overlaps(pools[j]) {
				return nil, &ErrNAT64PoolOverlap{Pool: pools[i].String(), Conflict: pools[j].String()}
			}
		}
	}
	timeouts := c.Timeouts.WithDefaults()
	if err := timeouts.validate(); err != nil {
		return nil, err
	}
	for i, z := range c.ClientZones {
		if z.VLAN == 0 || z.VLAN > 4094 {
			return nil, &ErrInvalidClientZone{Index: i, Reason: "vlan must be between 1 and 4094"}
		}
	}
	return &resolved{
		prefix:   pfx,
		instance: instance,
		port:     c.TranslatorPort,
		bridge:   c.Bridge,
		pools:    pools,
		timeouts: timeouts,
		zones:    c.ClientZones,
	}, nil
}

// Validate checks the configuration without building a service, so the
// gateway can refuse a bad section at config load rather than at Start.
func (c *Config) Validate() error {
	_, err := c.resolve()
	return err
}

// CheckPoolOverlap refuses a pool4 range that collides with a NAT44 SNAT
// range. Jool and the OVS conntrack NAT each keep their own allocation
// table; handing both the same address and port produces a collision that
// looks like packet loss and explains itself nowhere. The gateway calls it
// with the NAT service's configured pools because only the gateway sees
// both sections.
func (c *Config) CheckPoolOverlap(ranges []NAT44Range) error {
	res, err := c.resolve()
	if err != nil {
		return err
	}
	for _, other := range ranges {
		p, err := parsePool4(other.Addresses, other.PortStart, other.PortEnd)
		if err != nil {
			// A NAT44 range the NAT service itself will refuse is not this
			// service's error to report.
			continue
		}
		for _, mine := range res.pools {
			if mine.overlaps(p) {
				return &ErrNAT64PoolOverlap{Pool: mine.String(), Conflict: p.String(), Uplink: other.Uplink}
			}
		}
	}
	return nil
}

// NAT44Range is one NAT44 SNAT range the overlap check compares against.
// It is a plain value so the gateway can build it from firewall.NATConfig
// without this package importing the firewall service.
type NAT44Range struct {
	// Uplink names the NAT44 uplink the range belongs to, for the error.
	Uplink string
	// Addresses is the range in the same syntax as Pool4Range.Addresses.
	Addresses string
	// PortStart and PortEnd bound the NAT44 port range.
	PortStart uint16
	PortEnd   uint16
}
