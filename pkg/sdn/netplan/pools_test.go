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

package netplan_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestRanges pins the split of the IPAM /17 and checks the ranges tile
// inside it without overlapping.
func TestRanges(t *testing.T) {
	p := referencePlan(t)
	want := map[netplan.RangeKind]string{
		netplan.RangeTunnelP2P:     "10.4.128.0/22",
		netplan.RangeLoopbacks:     "10.4.132.0/22",
		netplan.RangeServiceVIPs:   "10.4.136.0/21",
		netplan.RangePlatformHosts: "10.4.144.0/20",
		netplan.RangeTenantDefault: "10.4.192.0/18",
	}
	ipam := p.IPAMPool()
	kinds := netplan.RangeKinds()
	require.Len(t, kinds, len(want))
	for i, k := range kinds {
		r, ok := p.Range(k)
		require.True(t, ok)
		assert.Equal(t, want[k], r.String(), "range %s", k)
		assert.True(t, ipam.Contains(r.Addr()) && ipam.Contains(r.Addr().Next()), "range %s inside %s", k, ipam)
		for _, other := range kinds[i+1:] {
			o, _ := p.Range(other)
			assert.False(t, r.Overlaps(o), "%s overlaps %s", k, other)
		}
	}
	_, ok := p.Range("nowhere")
	assert.False(t, ok)
}

// TestZonePool derives a zone's pool: gateway .1 reserved, DHCP .50-.254.
func TestZonePool(t *testing.T) {
	p := referencePlan(t)
	pool, ok := p.ZonePool(zone.ZoneProvisioning)
	require.True(t, ok)
	assert.Equal(t, "provisioning", pool.Name)
	assert.Equal(t, zone.ZoneProvisioning, pool.Zone)
	assert.Empty(t, pool.Range)
	assert.Equal(t, "192.0.2.0/24", pool.Prefix.String())
	assert.Equal(t, "192.0.2.1", pool.Gateway.String())
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, pool.Reserved)
	require.True(t, pool.HasDynamicRange())
	assert.Equal(t, "192.0.2.50", pool.RangeStart.String())
	assert.Equal(t, "192.0.2.254", pool.RangeEnd.String())

	_, ok = p.ZonePool("lab")
	assert.False(t, ok)
}

// TestZonePool_WiderAndNarrowerSubnets covers a /22 fabric (DHCP to the
// end of the /22) and the smallest accepted zone, a /26 (DHCP .50-.62), and
// refuses a /27: it could not hold the static host bands and a DHCP range,
// so dynamic allocation would hand out static addresses.
func TestZonePool_WiderAndNarrowerSubnets(t *testing.T) {
	env := netplan.Environment{ID: 4, Overrides: []netplan.Override{
		{Zone: zone.ZoneFabric, Subnet: netip.MustParsePrefix("10.4.100.0/22")},
		{Zone: zone.ZoneBackup, Subnet: netip.MustParsePrefix("10.4.8.0/26")},
	}}
	p, err := netplan.New(env, zone.Defaults())
	require.NoError(t, err)

	fabric, _ := p.ZonePool(zone.ZoneFabric)
	assert.Equal(t, "10.4.100.50", fabric.RangeStart.String())
	assert.Equal(t, "10.4.103.254", fabric.RangeEnd.String())

	backup, _ := p.ZonePool(zone.ZoneBackup)
	require.True(t, backup.HasDynamicRange())
	assert.Equal(t, "10.4.8.50", backup.RangeStart.String())
	assert.Equal(t, "10.4.8.62", backup.RangeEnd.String())

	_, err = netplan.New(netplan.Environment{ID: 4, Overrides: []netplan.Override{
		{Zone: zone.ZoneBackup, Subnet: netip.MustParsePrefix("10.4.8.0/27")},
	}}, zone.Defaults())
	var overrideErr netplan.ErrOverride
	require.True(t, errors.As(err, &overrideErr), "got %v", err)
}

// TestRangePool covers the tunnel range's reserved HA sync /31 and a plain
// range.
func TestRangePool(t *testing.T) {
	p := referencePlan(t)
	tun, ok := p.RangePool(netplan.RangeTunnelP2P)
	require.True(t, ok)
	assert.Equal(t, "10.4.128.0/31", p.GatewayHASync().String())
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.4.128.0/31")}, tun.Reserved)
	assert.Equal(t, "10.4.128.2", tun.RangeStart.String())
	assert.Equal(t, "10.4.131.255", tun.RangeEnd.String())

	hosts, ok := p.RangePool(netplan.RangePlatformHosts)
	require.True(t, ok)
	assert.Empty(t, hosts.Reserved)
	assert.Equal(t, "10.4.144.0", hosts.RangeStart.String())
	assert.Equal(t, "10.4.159.255", hosts.RangeEnd.String())

	_, ok = p.RangePool("nowhere")
	assert.False(t, ok)
}

// TestPools lists one pool per zone, then one per range, leaving out the
// tenant default range (tenant subnets are carved from it).
func TestPools(t *testing.T) {
	pools := referencePlan(t).Pools()
	require.Len(t, pools, 9+4)
	assert.Equal(t, "transit", pools[0].Name)
	assert.Equal(t, "backup", pools[8].Name)
	assert.Equal(t, "tunnel-p2p", pools[9].Name)
	assert.Equal(t, "platform-hosts", pools[12].Name)
	for _, p := range pools {
		assert.NotEqual(t, netplan.RangeTenantDefault, p.Range)
	}
	tenant, ok := referencePlan(t).RangePool(netplan.RangeTenantDefault)
	require.True(t, ok)
	assert.Equal(t, "10.4.192.0/18", tenant.Prefix.String())
}

// TestReserved lists the never-allocatable ranges.
func TestReserved(t *testing.T) {
	p := referencePlan(t)
	reserved := p.Reserved()
	assert.Contains(t, reserved, netip.MustParsePrefix("10.4.128.0/31"))
	assert.Contains(t, reserved, netip.MustParsePrefix("169.254.169.253/32"))
	assert.Contains(t, reserved, netip.MustParsePrefix("fd12:3456:789a:ffff::/64"))
	assert.Contains(t, reserved, netip.MustParsePrefix("10.4.6.1/32"))

	for _, a := range []string{"10.4.128.1", "169.254.169.253", "fd12:3456:789a:ffff::53", "10.4.1.1"} {
		assert.True(t, p.IsReserved(netip.MustParseAddr(a)), a)
	}
	for _, a := range []string{"10.4.128.2", "10.4.1.10", "169.254.169.254"} {
		assert.False(t, p.IsReserved(netip.MustParseAddr(a)), a)
	}

	hs6, ok := p.HostServices6()
	require.True(t, ok)
	assert.Equal(t, "fd12:3456:789a:ffff::/64", hs6.String())
}
