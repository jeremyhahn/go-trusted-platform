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

package hostfw

import (
	"errors"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fixtureRuleset is the reference inventory: a control-plane's TLS
// listeners on the management leg, ssh restricted to the office prefix
// (v4 and v6), the WAN peers for the two VPS relays over ESP and GRE, one
// tunnel interface, and a deliberately unfiltered interface.
func fixtureRuleset() Ruleset {
	return Ruleset{
		Listeners: []Listener{
			{Interface: "eth0", Protocol: ProtocolTCP, Port: 8443, Comment: "webservice public tls"},
			{Interface: "eth0", Protocol: ProtocolTCP, Port: 22, Sources: []netip.Prefix{
				netip.MustParsePrefix("10.4.6.0/24"), netip.MustParsePrefix("fd00:101::/64")}, Comment: "sshd office"},
			{Interface: "", Protocol: ProtocolUDP, Port: 3784, Comment: "bfd any"},
			{Interface: "br-fabric", Protocol: ProtocolTCP, Port: 10443},
		},
		Peers: []PeerAllowance{
			{Interface: "wan0", Protocol: PeerProtocolGRE, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.100"), netip.MustParseAddr("198.51.100.100")}},
			{Interface: "wan0", Protocol: PeerProtocolESP, Addresses: []netip.Addr{netip.MustParseAddr("198.51.100.100"), netip.MustParseAddr("2001:db8::1")}},
		},
		Tunnels:    []string{"gre1"},
		Unfiltered: []string{"eth1"},
	}
}

func TestRender_GoldenText(t *testing.T) {
	rendered, err := Render(fixtureRuleset())
	require.NoError(t, err)
	golden := filepath.Join("testdata", "fixture.nft")
	if *update {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(golden, []byte(rendered.Text), 0o644))
	}
	want, err := os.ReadFile(golden)
	require.NoError(t, err, "run with -update to create the golden file")
	assert.Equal(t, string(want), rendered.Text)
	assert.True(t, strings.HasPrefix(rendered.Fingerprint, "sha256:"))
	assert.Len(t, rendered.Rules, 3+1+3+5+4+2, "loopback+ct, unfiltered, icmp, listeners (1+2+1+1), peers (2+2), tunnel ports")
}

// TestRender_IsStable pins the property the reconciler depends on: the
// same policy in a different order renders the same bytes.
func TestRender_IsStable(t *testing.T) {
	a := fixtureRuleset()
	b := fixtureRuleset()
	b.Listeners[0], b.Listeners[3] = b.Listeners[3], b.Listeners[0]
	b.Peers[0], b.Peers[1] = b.Peers[1], b.Peers[0]
	b.Peers[1].Addresses[0], b.Peers[1].Addresses[1] = b.Peers[1].Addresses[1], b.Peers[1].Addresses[0]
	ra, err := Render(a)
	require.NoError(t, err)
	rb, err := Render(b)
	require.NoError(t, err)
	assert.Equal(t, ra.Fingerprint, rb.Fingerprint)
	assert.Equal(t, ra.Text, rb.Text)
}

// TestRender_UndeclaredListenerChangesTheRuleset is the build-gate
// property: a listener nobody declared cannot be in the table, and a
// listener added to the inventory is visibly in the table.
func TestRender_UndeclaredListenerChangesTheRuleset(t *testing.T) {
	base, err := Render(fixtureRuleset())
	require.NoError(t, err)
	assert.NotContains(t, base.Text, "dport 9445", "an undeclared port must not appear")

	rs := fixtureRuleset()
	rs.Listeners = append(rs.Listeners, Listener{Interface: "eth0", Protocol: ProtocolTCP, Port: 9445, Comment: "mcp"})
	with, err := Render(rs)
	require.NoError(t, err)
	assert.Contains(t, with.Text, `iifname "eth0" tcp dport 9445 accept comment "mcp"`)
	assert.NotEqual(t, base.Fingerprint, with.Fingerprint)
}

func TestRender_PolicyShape(t *testing.T) {
	rendered, err := Render(Ruleset{})
	require.NoError(t, err)
	text := rendered.Text
	assert.Contains(t, text, "table inet tp_host\n")
	assert.Contains(t, text, "delete table inet tp_host\n")
	assert.Contains(t, text, "type filter hook input priority filter; policy drop;")
	assert.Contains(t, text, `iifname "lo" accept`)
	assert.Contains(t, text, "meta l4proto != { gre, esp } ct state established,related accept",
		"GRE and ESP are admitted only by a peer allowance, never by conntrack")
	assert.Contains(t, text, "ct state invalid drop")
	assert.Contains(t, text, "meta l4proto icmp limit rate 50/second burst 100 packets accept")
	assert.Contains(t, text, "nd-neighbor-solicit")
	assert.Equal(t, DefaultICMPRateLimit, rendered.ICMP)
	// Nothing else: the empty ruleset admits only loopback, conntrack and ICMP.
	assert.Len(t, rendered.Rules, 6)
}

func TestRender_ICMPRateLimitIsConfigurable(t *testing.T) {
	rendered, err := Render(Ruleset{ICMP: RateLimit{Rate: 5, Burst: 7}})
	require.NoError(t, err)
	assert.Contains(t, rendered.Text, "limit rate 5/second burst 7 packets")
	assert.Equal(t, RateLimit{Rate: 5, Burst: 7}, rendered.ICMP)
}

func TestRender_ValidationErrors(t *testing.T) {
	cases := map[string]struct {
		rs    Ruleset
		want  error
		field string
	}{
		"port zero":          {Ruleset{Listeners: []Listener{{Protocol: ProtocolTCP}}}, ErrZeroPort, "listeners"},
		"unknown protocol":   {Ruleset{Listeners: []Listener{{Protocol: "sctp", Port: 1}}}, ErrUnknownProtocol, "listeners"},
		"bad interface":      {Ruleset{Listeners: []Listener{{Interface: "eth 0", Protocol: ProtocolTCP, Port: 1}}}, ErrInvalidInterface, "listeners"},
		"long interface":     {Ruleset{Listeners: []Listener{{Interface: "abcdefghijklmnop", Protocol: ProtocolTCP, Port: 1}}}, ErrInvalidInterface, "listeners"},
		"invalid prefix":     {Ruleset{Listeners: []Listener{{Protocol: ProtocolTCP, Port: 1, Sources: []netip.Prefix{{}}}}}, ErrInvalidPrefix, "listeners"},
		"duplicate listener": {Ruleset{Listeners: []Listener{{Protocol: ProtocolTCP, Port: 1}, {Protocol: ProtocolTCP, Port: 1}}}, ErrDuplicateListener, "listeners"},
		"peer no interface":  {Ruleset{Peers: []PeerAllowance{{Protocol: PeerProtocolESP, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}}}, ErrEmptyInterface, "peers"},
		"peer bad protocol":  {Ruleset{Peers: []PeerAllowance{{Interface: "wan0", Protocol: "ah", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}}}, ErrUnknownProtocol, "peers"},
		"peer no addresses":  {Ruleset{Peers: []PeerAllowance{{Interface: "wan0", Protocol: PeerProtocolESP}}}, ErrNoPeerAddresses, "peers"},
		"peer unspecified":   {Ruleset{Peers: []PeerAllowance{{Interface: "wan0", Protocol: PeerProtocolGRE, Addresses: []netip.Addr{netip.IPv4Unspecified()}}}}, ErrInvalidAddress, "peers"},
		"tunnel empty":       {Ruleset{Tunnels: []string{""}}, ErrEmptyInterface, "tunnels"},
		"unfiltered bad":     {Ruleset{Unfiltered: []string{"a/b"}}, ErrInvalidInterface, "unfiltered"},
		"vrrp bad":           {Ruleset{VRRP: []string{"a/b"}}, ErrInvalidInterface, "vrrp"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Render(c.rs)
			var verr *ValidationError
			require.True(t, errors.As(err, &verr), "got %v", err)
			assert.Equal(t, c.field, verr.Field)
			assert.ErrorIs(t, err, c.want)
			assert.Contains(t, err.Error(), c.field+"[")
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	assert.NoError(t, Config{}.Validate())
	assert.NoError(t, Config{Extra: []Listener{{Interface: "eth0", Protocol: ProtocolTCP, Port: 22}}, Tunnels: []string{"gre1"}}.Validate())
	assert.ErrorIs(t, Config{Extra: []Listener{{Protocol: ProtocolTCP}}}.Validate(), ErrZeroPort)
	assert.ErrorIs(t, Config{VRRP: []string{""}}.Validate(), ErrEmptyInterface)
}

func TestRender_VRRPOnInterfaces(t *testing.T) {
	rendered, err := Render(Ruleset{VRRP: []string{"eth2", "eth1"}})
	require.NoError(t, err)
	eth1 := `iifname "eth1" meta l4proto 112 accept comment "vrrp on eth1"`
	eth2 := `iifname "eth2" meta l4proto 112 accept comment "vrrp on eth2"`
	assert.Contains(t, rendered.Text, eth1)
	assert.Contains(t, rendered.Text, eth2)
	assert.Less(t, strings.Index(rendered.Text, eth1), strings.Index(rendered.Text, eth2), "sorted")
	assert.Len(t, rendered.Rules, 8, "6 base rules plus 2 VRRP")
}

// accept-mode off (RFC 5798 §6.4.3): traffic to a VIP is dropped whatever
// interface it arrives on (Linux delivers an installed VIP locally from any
// ingress), and before the conntrack allowance, so an established flow or
// a reply to VIP-sourced traffic is dropped too (Codex #1716 round 4). For
// IPv6 neighbour discovery to the VIP stays answered, so an IPv6 VIP takes
// two rules: one for every non-ICMPv6 packet, one for ICMPv6 other than
// NS/NA (an `icmpv6 type` match implies ICMPv6, so one rule alone would
// let TCP through).
func TestRender_VIPDeny(t *testing.T) {
	rendered, err := Render(Ruleset{VIPDeny: []VIPDeny{
		{Interface: "br-int", Address: netip.MustParseAddr("2001:db8::1")},
		{Interface: "br-int", Address: netip.MustParseAddr("10.4.200.1")},
	}})
	require.NoError(t, err)
	v4 := `ip daddr 10.4.200.1 drop comment "vip 10.4.200.1 accept-mode off"`
	v6 := `ip6 daddr 2001:db8::1 meta l4proto != ipv6-icmp drop comment "vip 2001:db8::1 accept-mode off"`
	v6icmp := `ip6 daddr 2001:db8::1 icmpv6 type != { nd-neighbor-solicit, nd-neighbor-advert } drop comment "vip 2001:db8::1 accept-mode off"`
	for _, line := range []string{v4, v6, v6icmp} {
		require.Contains(t, rendered.Text, line)
		assert.NotContains(t, rendered.Text, `iifname "br-int" `+line, "matches every ingress interface")
		assert.Less(t, strings.Index(rendered.Text, "loopback"), strings.Index(rendered.Text, line), "after loopback")
		assert.Less(t, strings.Index(rendered.Text, line), strings.Index(rendered.Text, "ct state established,related accept"), "before the established allowance")
	}
	for _, r := range rendered.Rules {
		if r.Kind == RuleVIPDeny || r.Kind == RuleVIPDenyICMPv6 {
			assert.Empty(t, r.Interface, "no ingress restriction")
		}
	}
	assert.Less(t, strings.Index(rendered.Text, v4), strings.Index(rendered.Text, v6), "sorted")
	assert.Len(t, rendered.Rules, 9, "6 base rules plus 3 VIP denies")
}

// The same VIP on two interfaces compiles to one set of deny rules, now
// that the rules match every ingress.
func TestRender_VIPDenyDeduplicatesAddresses(t *testing.T) {
	rendered, err := Render(Ruleset{VIPDeny: []VIPDeny{
		{Interface: "br-int", Address: netip.MustParseAddr("10.4.200.1")},
		{Interface: "eth1", Address: netip.MustParseAddr("10.4.200.1")},
	}})
	require.NoError(t, err)
	assert.Len(t, rendered.Rules, 7, "6 base rules plus 1 VIP deny")
}

func TestRuleset_ValidateVIPDeny(t *testing.T) {
	bad := []VIPDeny{
		{Interface: "", Address: netip.MustParseAddr("10.4.200.1")},
		{Interface: "br-int"},
	}
	for _, v := range bad {
		var ve *ValidationError
		require.ErrorAs(t, Ruleset{VIPDeny: []VIPDeny{v}}.Validate(), &ve)
		assert.Equal(t, "vip-deny", ve.Field)
	}
}

func TestErrors_Messages(t *testing.T) {
	op := &OpError{Op: "apply", Err: errors.New("boom")}
	assert.Equal(t, "hostfw: apply: boom", op.Error())
	assert.ErrorIs(t, op, op.Err)
	rb := &RollbackError{Apply: errors.New("a"), Rollback: errors.New("b")}
	assert.Contains(t, rb.Error(), "rollback failed (b)")
	assert.ErrorIs(t, rb, rb.Apply)
	assert.NotEmpty(t, ErrTableMissing.Error())
}
