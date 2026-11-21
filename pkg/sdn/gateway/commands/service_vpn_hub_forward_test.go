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

//go:build !fips

package commands

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hubForwardNetworks is the zones' network summaries for the forwarding
// rule tests: management dual-stack, control-plane and storage IPv4 only.
func hubForwardNetworks() map[zone.Zone]zoneflows.NetworkSummary {
	return map[zone.Zone]zoneflows.NetworkSummary{
		zone.ZoneManagement:   zoneflows.NewNetworkSummary(10, netip.MustParsePrefix("10.4.10.0/24"), netip.MustParsePrefix("fd00:10::/64")),
		zone.ZoneControlPlane: zoneflows.NewNetworkSummary(20, netip.MustParsePrefix("10.4.20.0/24")),
		zone.ZoneStorage:      zoneflows.NewNetworkSummary(30, netip.MustParsePrefix("10.4.30.0/24")),
	}
}

func hubForwardTexts(rules []vpnHubForwardRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.text())
	}
	return out
}

func TestVPNHubForward_AcceptsOnlyTheLeasesOpenedZones(t *testing.T) {
	e := newVPNHubZoneEnforcement(hubZoneMatrix())
	lease := &vpn.Lease{
		Address: netip.MustParsePrefix("10.99.0.7/32"),
		Zones:   []string{string(zone.ZoneManagement), string(zone.ZoneStorage)},
	}
	rules, err := compileVPNHubForwardRules(e, hubForwardNetworks(), []*vpn.Lease{lease})
	require.NoError(t, err)
	texts := hubForwardTexts(rules)

	require.NotEmpty(t, texts)
	assert.Equal(t, `iifname "vpn-hub0" ct state established,related accept`, texts[0], "replies to admitted flows pass first")
	assert.Contains(t, texts, `iifname "vpn-hub0" ip saddr 10.99.0.7/32 ip daddr 10.4.10.0/24 accept comment "vpn lease to management"`)
	for _, s := range texts {
		assert.NotContains(t, s, "10.4.30.0/24", "the matrix does not open storage, so no rule reaches it")
		assert.NotContains(t, s, "10.4.20.0/24", "control-plane is not in the lease")
		assert.NotContains(t, s, "fd00:10::/64", "an IPv4 lease gets only IPv4 destinations")
	}

	six := &vpn.Lease{Address: netip.MustParsePrefix("fd00:99::7/128"), Zones: []string{string(zone.ZoneManagement)}}
	rules, err = compileVPNHubForwardRules(e, hubForwardNetworks(), []*vpn.Lease{six})
	require.NoError(t, err)
	assert.Contains(t, hubForwardTexts(rules), `iifname "vpn-hub0" ip6 saddr fd00:99::7/128 ip6 daddr fd00:10::/64 accept comment "vpn lease to management"`)
}

func TestVPNHubForward_ServiceScopedCellOpensOnlyItsPorts(t *testing.T) {
	e := newVPNHubZoneEnforcement(zone.CompileMatrix([]zone.ZoneConfig{
		{Name: vpnHubZone, AllowTo: []zone.ZonePath{
			{Zone: zone.ZoneControlPlane, Services: []string{"dns", "https"}},
		}},
		{Name: zone.ZoneControlPlane},
	}))
	lease := &vpn.Lease{Address: netip.MustParsePrefix("10.99.0.8/32"), Zones: []string{string(zone.ZoneControlPlane)}}
	rules, err := compileVPNHubForwardRules(e, hubForwardNetworks(), []*vpn.Lease{lease})
	require.NoError(t, err)

	var ports []string
	for _, r := range rules {
		if r.Drop || !r.Source.IsValid() {
			continue
		}
		assert.Equal(t, netip.MustParsePrefix("10.4.20.0/24"), r.Destination)
		require.NotZero(t, r.Port, "a service-scoped cell never gets a whole-zone accept")
		ports = append(ports, r.Protocol+"/"+strconv.Itoa(int(r.Port)))
	}
	assert.ElementsMatch(t, []string{"tcp/53", "udp/53", "tcp/8053", "udp/8053", "tcp/9053", "udp/9053"}, ports,
		"dns opens its ports; https has no port table entry, so it opens nothing")
	assert.Contains(t, hubForwardTexts(rules), `iifname "vpn-hub0" ip saddr 10.99.0.8/32 ip daddr 10.4.20.0/24 udp dport 53 accept comment "vpn lease to control-plane dns"`)
}

func TestVPNHubForward_EndsInADropForTheHubInterface(t *testing.T) {
	e := newVPNHubZoneEnforcement(hubZoneMatrix())
	for _, leases := range [][]*vpn.Lease{
		nil,
		{{Address: netip.MustParsePrefix("10.99.0.7/32"), Zones: []string{string(zone.ZoneManagement)}}},
	} {
		rules, err := compileVPNHubForwardRules(e, hubForwardNetworks(), leases)
		require.NoError(t, err)
		require.NotEmpty(t, rules)
		last := rules[len(rules)-1]
		assert.True(t, last.Drop)
		assert.Equal(t, `iifname "vpn-hub0" drop`, last.text())
	}
}

func TestVPNHubForward_RefusesALeaseZoneWithNoSubnet(t *testing.T) {
	e := newVPNHubZoneEnforcement(hubZoneMatrix())
	nets := hubForwardNetworks()
	delete(nets, zone.ZoneManagement)
	lease := &vpn.Lease{Address: netip.MustParsePrefix("10.99.0.7/32"), Zones: []string{string(zone.ZoneManagement)}}
	_, err := compileVPNHubForwardRules(e, nets, []*vpn.Lease{lease})
	require.Error(t, err, "a lease zone with no network summary cannot be enforced")

	nets[zone.ZoneManagement] = zoneflows.NetworkSummary{VLAN: 10}
	_, err = compileVPNHubForwardRules(e, nets, []*vpn.Lease{lease})
	require.Error(t, err, "a lease zone whose summary has no subnet cannot be enforced")

	_, err = compileVPNHubForwardRules(nil, hubForwardNetworks(), nil)
	require.Error(t, err, "no enforcement, no rules")
}
