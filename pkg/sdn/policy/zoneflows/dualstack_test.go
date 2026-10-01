// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-control-plane-platform.
//
// go-control-plane-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package zoneflows

import (
	"net"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// dualStackConfig is the #554 fixture: control-plane and backup are dual-stack,
// storage is IPv4-only, and every allowed pair carries a service scope so
// the per-service permits are exercised in both families.
func dualStackConfig(defaultPolicy string) (MatrixRuleConfig, map[zone.Zone]uint16) {
	zones := []zone.ZoneConfig{
		{Name: zone.ZoneControlPlane, AllowTo: []zone.ZonePath{{Zone: zone.ZoneBackup, Services: []string{"dns", "acme"}}, {Zone: zone.ZoneStorage}}},
		{Name: zone.ZoneBackup, IsolateFrom: []zone.Zone{zone.ZoneControlPlane, zone.ZoneStorage}},
		{Name: zone.ZoneStorage, IsolateFrom: []zone.Zone{zone.ZoneBackup}},
	}
	cfg := MatrixRuleConfig{
		Matrix: zone.CompileMatrix(zones),
		Zones:  zones,
		NetworksByZone: map[zone.Zone]NetworkSummary{
			zone.ZoneControlPlane: {VLAN: 100, Subnet: "10.0.100.0/24", Subnet6: "2001:db8:100::/64"},
			zone.ZoneBackup:       {VLAN: 200, Subnet: "10.0.200.0/24", Subnet6: "2001:db8:200::/64"},
			zone.ZoneStorage:      {VLAN: 203, Subnet: "10.0.203.0/24"},
		},
		DefaultPolicy: defaultPolicy,
	}
	ctZones := map[zone.Zone]uint16{zone.ZoneControlPlane: 11, zone.ZoneBackup: 22, zone.ZoneStorage: 33}
	return cfg, ctZones
}

// ipv6TwinOf derives the IPv6 twin an address-family-neutral IPv4 match must
// have: the EtherType swaps and every nw_dst on a dual-stack subnet becomes
// ipv6_dst on that network's IPv6 prefix. Ports and protocols are the same
// in both families except DHCP, whose IPv6 form is DHCPv6 on its own ports.
func ipv6TwinOf(match string, subnets map[string]string) (string, bool) {
	if !strings.Contains(match, "dl_type=0x0800") {
		return "", false
	}
	twin := strings.Replace(match, "dl_type=0x0800", "dl_type=0x86dd", 1)
	if strings.Contains(twin, "nw_dst=") {
		re := regexp.MustCompile(`nw_dst=([^,]+)`)
		m := re.FindStringSubmatch(twin)
		v6, ok := subnets[m[1]]
		if !ok {
			// A single IPv4 host or an IPv4-only subnet has no IPv6 twin.
			return "", false
		}
		twin = re.ReplaceAllString(twin, "ipv6_dst="+v6)
	}
	twin = strings.Replace(twin, "tp_src=68,tp_dst=67", "tp_src=546,tp_dst=547", 1)
	if !strings.Contains(twin, "nw_proto=17") {
		twin = strings.Replace(twin, "nw_proto=1", "nw_proto=58", 1)
	}
	return twin, true
}

// assertFamilyParity is the static invariant: every IPv4 rule whose policy
// is address-family-neutral has an IPv6 sibling with the same table,
// priority and action.
func assertFamilyParity(t *testing.T, flows []FlowRule, subnets map[string]string) {
	t.Helper()
	type key struct {
		table, priority int
		match, actions  string
	}
	index := map[key]bool{}
	for _, f := range flows {
		index[key{f.Table, f.Priority, f.Match, f.Actions}] = true
	}
	checked := 0
	for _, f := range flows {
		twin, neutral := ipv6TwinOf(f.Match, subnets)
		if !neutral {
			continue
		}
		checked++
		require.True(t, index[key{f.Table, f.Priority, twin, f.Actions}],
			"IPv4 rule %+v has no IPv6 twin with match %q at the same table, priority and action", f, twin)
	}
	require.Positive(t, checked, "the parity check matched no IPv4 rule; the fixture is wrong")
}

func TestCompileMatrixRules_DualStackParity(t *testing.T) {
	cfg, _ := dualStackConfig("deny")
	flows := CompileMatrixRules(cfg)
	assertFamilyParity(t, flows, map[string]string{
		"10.0.100.0/24": "2001:db8:100::/64",
		"10.0.200.0/24": "2001:db8:200::/64",
	})

	// The IPv4-only storage network gets an IPv4 deny from backup and no
	// IPv6 rule at all: nothing to name.
	var storageRules []FlowRule
	for _, f := range flows {
		if strings.Contains(f.Match, "10.0.203.0/24") || strings.Contains(f.Match, "203::") {
			storageRules = append(storageRules, f)
		}
	}
	require.NotEmpty(t, storageRules)
	for _, f := range storageRules {
		assert.Contains(t, f.Match, "dl_type=0x0800")
	}
}

func TestCompileMatrixRules_DualStackGolden(t *testing.T) {
	cfg, _ := dualStackConfig("deny")
	got := CompileMatrixRules(cfg)

	// backup → control-plane is denied in both families; the IPv6 twin follows
	// its IPv4 rule immediately.
	want := []FlowRule{
		{Table: 0, Priority: 200, Match: "dl_vlan=200,dl_type=0x0800,nw_dst=10.0.100.0/24", Actions: "drop"},
		{Table: 0, Priority: 200, Match: "dl_vlan=200,dl_type=0x86dd,ipv6_dst=2001:db8:100::/64", Actions: "drop"},
	}
	for _, w := range want {
		assert.Contains(t, got, w)
	}
	// control-plane → backup dns permits exist per family and per port.
	assert.Contains(t, got, FlowRule{Table: 0, Priority: 100, Match: "dl_vlan=100,dl_type=0x0800,nw_proto=17,nw_dst=10.0.200.0/24,tp_dst=53", Actions: "normal"})
	assert.Contains(t, got, FlowRule{Table: 0, Priority: 100, Match: "dl_vlan=100,dl_type=0x86dd,nw_proto=17,ipv6_dst=2001:db8:200::/64,tp_dst=53", Actions: "normal"})
	assert.Contains(t, got, FlowRule{Table: 0, Priority: 100, Match: "dl_vlan=100,dl_type=0x86dd,nw_proto=6,ipv6_dst=2001:db8:200::/64,tp_dst=443", Actions: "normal"})
}

func TestCompileStatefulMatrixRules_DualStack(t *testing.T) {
	cfg, ctZones := dualStackConfig("deny")
	flows := CompileStatefulMatrixRules(cfg, ctZones)
	assertFamilyParity(t, flows, map[string]string{
		"10.0.100.0/24": "2001:db8:100::/64",
		"10.0.200.0/24": "2001:db8:200::/64",
	})

	// Both families are gated into conntrack per zone.
	assert.Contains(t, flows, FlowRule{Table: 20, Priority: 100, Match: "dl_vlan=100,dl_type=0x86dd", Actions: "ct(table=21,zone=11)"})
	// Neighbor discovery bypasses conntrack ahead of the gate.
	assert.Contains(t, flows, FlowRule{Table: 20, Priority: 200, Match: "dl_vlan=100,dl_type=0x86dd,nw_proto=58,icmp_type=135", Actions: "goto_table:30"})
	// A new IPv6 connection backup → control-plane is denied; control-plane → backup is committed.
	assert.Contains(t, flows, FlowRule{Table: 21, Priority: 200, Match: "ct_state=+new+trk,dl_vlan=200,dl_type=0x86dd,ipv6_dst=2001:db8:100::/64", Actions: "drop"})
	assert.Contains(t, flows, FlowRule{Table: 21, Priority: 100, Match: "ct_state=+new+trk,dl_vlan=100,dl_type=0x86dd,ipv6_dst=2001:db8:200::/64", Actions: "ct(commit,zone=11),goto_table:30"})
	// Nothing addresses the IPv4-only storage network by an IPv6 prefix,
	// while its own IPv6 traffic toward dual-stack zones still gets verdicts.
	toStorage6, fromStorage6 := 0, 0
	for _, f := range flows {
		if strings.Contains(f.Match, "ipv6_dst=2001:db8:203") {
			toStorage6++
		}
		if strings.Contains(f.Match, "dl_vlan=203,dl_type=0x86dd,ipv6_dst=") {
			fromStorage6++
		}
	}
	assert.Zero(t, toStorage6)
	assert.Equal(t, 2, fromStorage6, "storage → control-plane and storage → backup IPv6 verdicts")
}

func TestTemplates_DualStackParity(t *testing.T) {
	gs := NewGeneratorSet(ZoneFlowConfig{
		Provisioning: ProvisioningConfig{AllowICMP: true},
	})
	subnets := map[string]string{"10.0.100.0/24": "2001:db8:100::/64"}
	for _, z := range []zone.Zone{zone.ZoneQuarantine, zone.ZoneProvisioning} {
		t.Run(string(z), func(t *testing.T) {
			flows := gs.Generate("p1", z, Tagged(201))
			assertFamilyParity(t, flows, subnets)
		})
	}
}

func TestTemplates_NeighborDiscoveryPairsWithARP(t *testing.T) {
	gs := NewGeneratorSet(ZoneFlowConfig{})
	for _, z := range []zone.Zone{zone.ZoneQuarantine, zone.ZoneProvisioning} {
		flows := gs.Generate("p1", z, Tagged(201))
		var arpPrio int
		nd := 0
		for _, f := range flows {
			if strings.Contains(f.Match, "dl_type=0x0806") {
				arpPrio = f.Priority
			}
			if strings.Contains(f.Match, "nw_proto=58,icmp_type=13") {
				nd++
				assert.Equal(t, "normal", f.Actions)
				assert.Contains(t, f.Match, "in_port=p1,dl_vlan=201,dl_type=0x86dd")
			}
		}
		assert.Equal(t, 5, nd, "%s: RS, RA, NS, NA and redirect must all be permitted", z)
		for _, f := range flows {
			if strings.Contains(f.Match, "icmp_type=13") {
				assert.Equal(t, arpPrio, f.Priority, "%s: ND takes ARP's priority", z)
			}
		}
	}
}

func TestTemplates_ServerAddressesFollowTheirFamily(t *testing.T) {
	gs := NewGeneratorSet(ZoneFlowConfig{
		Quarantine: QuarantineConfig{
			DNSServerIP:          net.ParseIP("2001:db8::53"),
			RemediationServerIPs: []net.IP{net.ParseIP("10.0.9.9"), net.ParseIP("2001:db8::9")},
		},
		Provisioning: ProvisioningConfig{
			ACMEServerIPs: []net.IP{net.ParseIP("2001:db8::ac")},
		},
	})
	q := gs.Generate("p1", zone.ZoneQuarantine, Tagged(202))
	assert.Contains(t, q, FlowRule{Table: 0, Priority: prioDNS, Match: "in_port=p1,dl_vlan=202,dl_type=0x86dd,nw_proto=17,ipv6_dst=2001:db8::53,tp_dst=53", Actions: "normal"})
	assert.Contains(t, q, FlowRule{Table: 0, Priority: prioRemediation, Match: "in_port=p1,dl_vlan=202,dl_type=0x0800,nw_proto=6,nw_dst=10.0.9.9,tp_dst=443", Actions: "normal"})
	assert.Contains(t, q, FlowRule{Table: 0, Priority: prioRemediation, Match: "in_port=p1,dl_vlan=202,dl_type=0x86dd,nw_proto=6,ipv6_dst=2001:db8::9,tp_dst=443", Actions: "normal"})
	for _, f := range q {
		assert.False(t, strings.Contains(f.Match, "nw_dst=2001"), "an IPv6 address must never be rendered as nw_dst: %q", f.Match)
	}
	p := gs.Generate("p1", zone.ZoneProvisioning, Tagged(201))
	assert.Contains(t, p, FlowRule{Table: 0, Priority: prioACME, Match: "in_port=p1,dl_vlan=201,dl_type=0x86dd,nw_proto=6,ipv6_dst=2001:db8::ac,tp_dst=443", Actions: "normal"})
}

func TestNewNetworkSummary(t *testing.T) {
	v4 := netip.MustParsePrefix("10.4.6.0/24")
	v6 := netip.MustParsePrefix("2602:f5bb:1::/64")

	s := NewNetworkSummary(200, v4, v6)
	assert.Equal(t, NetworkSummary{VLAN: 200, Subnet: "10.4.6.0/24", Subnet6: "2602:f5bb:1::/64"}, s)

	// An IPv6 prefix in the legacy single field is filed as IPv6.
	s = NewNetworkSummary(200, v6)
	assert.Equal(t, NetworkSummary{VLAN: 200, Subnet6: "2602:f5bb:1::/64"}, s)

	// Invalid prefixes are ignored.
	s = NewNetworkSummary(200, netip.Prefix{}, v4)
	assert.Equal(t, NetworkSummary{VLAN: 200, Subnet: "10.4.6.0/24"}, s)

	// IPv4-mapped IPv6 is IPv4.
	s = NewNetworkSummary(200, netip.MustParsePrefix("::ffff:10.0.0.0/120"))
	assert.Equal(t, "::ffff:10.0.0.0/120", s.Subnet)
	assert.Empty(t, s.Subnet6)
}

func TestFamilyHelpers(t *testing.T) {
	assert.Equal(t, ipv4, familyOf(net.ParseIP("10.1.2.3")))
	assert.Equal(t, ipv6, familyOf(net.ParseIP("2001:db8::1")))
	assert.Equal(t, ipv4, familyOfPrefix("10.0.0.0/8"))
	assert.Equal(t, ipv6, familyOfPrefix("2001:db8::/32"))
	assert.Equal(t, ipv4, familyOfPrefix("garbage"))
	assert.Equal(t, "dl_type=0x86dd,nw_proto=17,tp_src=546,tp_dst=547", ipv6.dhcpMatch())
	assert.Equal(t, "dl_type=0x0800,nw_proto=17,tp_src=68,tp_dst=67", ipv4.dhcpMatch())
	assert.Equal(t, "ipv6_dst=::/0", ipv6.toDst("::/0"))

	n := NetworkSummary{Subnet: "10.0.0.0/24"}
	_, ok := n.subnetFor(ipv6)
	assert.False(t, ok)
	got, ok := n.subnetFor(ipv4)
	assert.True(t, ok)
	assert.Equal(t, "10.0.0.0/24", got)
}
