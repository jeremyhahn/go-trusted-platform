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

// referencePlan is environment 4 of the reference with the built-in zones.
func referencePlan(t *testing.T) *netplan.Plan {
	t.Helper()
	p, err := netplan.New(netplan.Environment{ID: 4, ULA: ula}, zone.Defaults())
	require.NoError(t, err)
	return p
}

// TestNew_WorkedExample reproduces the "Worked example: environment 4"
// table of docs/architecture/reference-network.md.
func TestNew_WorkedExample(t *testing.T) {
	want := []struct {
		zone          zone.Zone
		vlan          uint16
		ipv4, ipv6, g string
	}{
		{zone.ZoneTransit, 400, "10.4.0.0/24", "fd12:3456:789a:400::/64", "10.4.0.1"},
		{zone.ZoneFabric, 401, "10.4.1.0/24", "fd12:3456:789a:401::/64", "10.4.1.1"},
		{zone.ZoneManagement, 402, "198.51.100.0/24", "fd12:3456:789a:402::/64", "198.51.100.1"},
		{zone.ZoneHypervisor, 403, "10.4.3.0/24", "fd12:3456:789a:403::/64", "10.4.3.1"},
		{zone.ZoneQuarantine, 404, "10.4.4.0/24", "fd12:3456:789a:404::/64", "10.4.4.1"},
		{zone.ZoneProvisioning, 405, "192.0.2.0/24", "fd12:3456:789a:405::/64", "192.0.2.1"},
		{zone.ZoneControlPlane, 406, "10.4.6.0/24", "fd12:3456:789a:406::/64", "10.4.6.1"},
		{zone.ZoneStorage, 407, "10.4.7.0/24", "fd12:3456:789a:407::/64", "10.4.7.1"},
		{zone.ZoneBackup, 408, "10.4.8.0/24", "fd12:3456:789a:408::/64", "10.4.8.1"},
	}
	p, err := netplan.New(netplan.Environment{ID: 4, ULA: ula, Overrides: []netplan.Override{
		{Zone: zone.ZoneManagement, Subnet: netip.MustParsePrefix("198.51.100.0/24")},
		{Zone: zone.ZoneProvisioning, Subnet: netip.MustParsePrefix("192.0.2.0/24")},
	}}, zone.Defaults())
	require.NoError(t, err)
	zones := p.Zones()
	require.Len(t, zones, len(want))
	for i, w := range want {
		z := zones[i]
		assert.Equal(t, w.zone, z.Zone)
		assert.Equal(t, w.vlan, z.VLAN, "zone %s", w.zone)
		assert.Equal(t, w.ipv4, z.Subnet4.String(), "zone %s", w.zone)
		assert.Equal(t, w.ipv6, z.Subnet6.String(), "zone %s", w.zone)
		assert.Equal(t, w.g, z.Gateway.String(), "zone %s", w.zone)
	}
	assert.Equal(t, "10.4.128.0/17", p.IPAMPool().String())
	assert.Equal(t, netplan.DefaultBase, p.Environment().Base, "the effective base is filled in")
}

// TestNew_Lookups covers zone, VLAN, address and VNI lookups.
func TestNew_Lookups(t *testing.T) {
	p := referencePlan(t)

	z, ok := p.ZoneForVLAN(405)
	require.True(t, ok)
	assert.Equal(t, zone.ZoneProvisioning, z)
	_, ok = p.ZoneForVLAN(409)
	assert.False(t, ok)

	z, ok = p.ZoneForAddr(netip.MustParseAddr("10.4.7.20"))
	require.True(t, ok)
	assert.Equal(t, zone.ZoneStorage, z)
	z, ok = p.ZoneForAddr(netip.MustParseAddr("fd12:3456:789a:401::5"))
	require.True(t, ok)
	assert.Equal(t, zone.ZoneFabric, z)
	_, ok = p.ZoneForAddr(netip.MustParseAddr("10.4.144.7"))
	assert.False(t, ok, "the IPAM pool is not a zone")

	_, err := p.MustZone("lab")
	var unknown netplan.ErrUnknownZone
	require.True(t, errors.As(err, &unknown))
	n, err := p.MustZone(zone.ZoneFabric)
	require.NoError(t, err)
	assert.Equal(t, uint16(401), n.VLAN)

	vni, err := p.VNI(7)
	require.NoError(t, err)
	assert.Equal(t, uint32(400007), vni)
	net, ok := p.OwnsVNI(400007)
	require.True(t, ok)
	assert.Equal(t, uint32(7), net)
	_, ok = p.OwnsVNI(300007)
	assert.False(t, ok, "a VNI of environment 3 is not ours")
}

// TestNew_OwnerZone derives an owner-defined zone from its offset.
func TestNew_OwnerZone(t *testing.T) {
	zones, err := zone.Resolve([]zone.ZoneConfig{{
		Name: "lab", Offset: 9, PortClasses: []zone.PortClass{zone.PortClassHypervisor}, Isolate: true,
	}})
	require.NoError(t, err)
	p, err := netplan.New(netplan.Environment{ID: 4, ULA: ula}, zones)
	require.NoError(t, err)

	lab, ok := p.Zone("lab")
	require.True(t, ok)
	assert.Equal(t, uint16(409), lab.VLAN)
	assert.Equal(t, "10.4.9.0/24", lab.Subnet4.String())
	assert.Equal(t, "fd12:3456:789a:409::/64", lab.Subnet6.String())
}

// TestNew_NoULA derives no IPv6 subnets and no host-services /64.
func TestNew_NoULA(t *testing.T) {
	p, err := netplan.New(netplan.Environment{ID: 3}, zone.Defaults())
	require.NoError(t, err)
	fabric, _ := p.Zone(zone.ZoneFabric)
	assert.False(t, fabric.Subnet6.IsValid())
	_, ok := p.HostServices6()
	assert.False(t, ok)
	assert.Equal(t, "10.3.1.0/24", fabric.Subnet4.String())
}

// TestNew_Overrides applies a dev-fleet style override (VLAN and subnet
// outside the base) and a wider fabric in the unused lower /17 range.
func TestNew_Overrides(t *testing.T) {
	env := netplan.Environment{
		ID:  4,
		ULA: ula,
		Overrides: []netplan.Override{
			{Zone: zone.ZoneControlPlane, VLAN: 50, Subnet: netip.MustParsePrefix("172.30.50.0/24")},
			{Zone: zone.ZoneFabric, Subnet: netip.MustParsePrefix("10.4.100.0/22")},
			{Zone: zone.ZoneStorage, Subnet6: netip.MustParsePrefix("fd00:1:2:3::/64")},
		},
	}
	p, err := netplan.New(env, zone.Defaults())
	require.NoError(t, err)

	cp, _ := p.Zone(zone.ZoneControlPlane)
	assert.Equal(t, uint16(50), cp.VLAN)
	assert.Equal(t, "172.30.50.0/24", cp.Subnet4.String())
	assert.Equal(t, "fd12:3456:789a:406::/64", cp.Subnet6.String(), "IPv6 follows the reference VLAN digits")
	assert.Equal(t, "172.30.50.1", cp.Gateway.String())

	fabric, _ := p.Zone(zone.ZoneFabric)
	assert.Equal(t, uint16(401), fabric.VLAN)
	assert.Equal(t, "10.4.100.0/22", fabric.Subnet4.String())

	storage, _ := p.Zone(zone.ZoneStorage)
	assert.Equal(t, "fd00:1:2:3::/64", storage.Subnet6.String())

	z, ok := p.ZoneForVLAN(50)
	require.True(t, ok)
	assert.Equal(t, zone.ZoneControlPlane, z)
	assert.Len(t, p.Environment().Overrides, 3)
}

// TestNew_Errors covers every way a plan refuses to derive.
func TestNew_Errors(t *testing.T) {
	defaults := zone.Defaults()
	tests := []struct {
		name  string
		env   netplan.Environment
		zones []zone.ZoneConfig
		check func(t *testing.T, err error)
	}{
		{"environment", netplan.Environment{ID: 41}, defaults, func(t *testing.T, err error) {
			var target netplan.ErrEnvironmentID
			require.True(t, errors.As(err, &target))
		}},
		{"override of an undeclared zone", netplan.Environment{ID: 4, Overrides: []netplan.Override{{Zone: "lab", VLAN: 900}}}, defaults, func(t *testing.T, err error) {
			var target netplan.ErrOverride
			require.True(t, errors.As(err, &target))
			assert.Contains(t, err.Error(), "not declared")
		}},
		{"duplicate VLAN", netplan.Environment{ID: 4, Overrides: []netplan.Override{{Zone: zone.ZoneBackup, VLAN: 401}}}, defaults, func(t *testing.T, err error) {
			var target netplan.ErrDuplicateVLAN
			require.True(t, errors.As(err, &target))
			assert.Equal(t, uint16(401), target.VLAN)
		}},
		{"fabric overlapping management", netplan.Environment{ID: 4, Overrides: []netplan.Override{{Zone: zone.ZoneFabric, Subnet: netip.MustParsePrefix("10.4.0.0/22")}}}, defaults, func(t *testing.T, err error) {
			var target netplan.ErrOverlap
			require.True(t, errors.As(err, &target))
		}},
		{"zone in the IPAM pool", netplan.Environment{ID: 4, Overrides: []netplan.Override{{Zone: zone.ZoneStorage, Subnet: netip.MustParsePrefix("10.4.200.0/24")}}}, defaults, func(t *testing.T, err error) {
			var target netplan.ErrOverlap
			require.True(t, errors.As(err, &target))
			assert.Contains(t, err.Error(), "IPAM pool")
		}},
		{"zone in link-local", netplan.Environment{ID: 4, Overrides: []netplan.Override{{Zone: zone.ZoneStorage, Subnet: netip.MustParsePrefix("169.254.1.0/24")}}}, defaults, func(t *testing.T, err error) {
			var target netplan.ErrOverlap
			require.True(t, errors.As(err, &target))
			assert.Contains(t, err.Error(), "link-local")
		}},
		{"zone on the host-services /64", netplan.Environment{ID: 4, ULA: ula, Overrides: []netplan.Override{{Zone: zone.ZoneStorage, Subnet6: netip.MustParsePrefix("fd12:3456:789a:ffff::/64")}}}, defaults, func(t *testing.T, err error) {
			var target netplan.ErrOverlap
			require.True(t, errors.As(err, &target))
			assert.Contains(t, err.Error(), "host-services")
		}},
		{"duplicate IPv6 subnet", netplan.Environment{ID: 4, ULA: ula, Overrides: []netplan.Override{{Zone: zone.ZoneStorage, Subnet6: netip.MustParsePrefix("fd12:3456:789a:401::/64")}}}, defaults, func(t *testing.T, err error) {
			var target netplan.ErrOverlap
			require.True(t, errors.As(err, &target))
		}},
		{"owner zone past VLAN 4094", netplan.Environment{ID: 40}, ownerAt(t, 95), func(t *testing.T, err error) {
			var target netplan.ErrVLANOutOfRange
			require.True(t, errors.As(err, &target))
			assert.Equal(t, zone.Zone("lab"), target.Zone)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := netplan.New(tc.env, tc.zones)
			require.Error(t, err)
			tc.check(t, err)
		})
	}
}

// TestNew_OverrideRescuesBlock40 shows an owner zone past 4094 is usable
// with an explicit VLAN override (its IPv6 has no reference digits then).
func TestNew_OverrideRescuesBlock40(t *testing.T) {
	env := netplan.Environment{ID: 40, ULA: ula, Overrides: []netplan.Override{{Zone: "lab", VLAN: 3999}}}
	p, err := netplan.New(env, ownerAt(t, 95))
	require.NoError(t, err)
	lab, _ := p.Zone("lab")
	assert.Equal(t, uint16(3999), lab.VLAN)
	assert.Equal(t, "10.40.95.0/24", lab.Subnet4.String())
	assert.False(t, lab.Subnet6.IsValid())
}

func ownerAt(t *testing.T, off zone.Offset) []zone.ZoneConfig {
	t.Helper()
	zones, err := zone.Resolve([]zone.ZoneConfig{{
		Name: "lab", Offset: off, PortClasses: []zone.PortClass{zone.PortClassGateway},
	}})
	require.NoError(t, err)
	return zones
}
