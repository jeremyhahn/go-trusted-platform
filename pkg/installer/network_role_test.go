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

package installer

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// testPlan is environment 4 of the reference with the built-in zones.
func testPlan(t *testing.T) *netplan.Plan {
	t.Helper()
	p, err := netplan.New(netplan.Environment{ID: 4, ULA: netip.MustParsePrefix("fd12:3456:789a::/48")}, zone.Defaults())
	require.NoError(t, err)
	return p
}

// ovsBond returns an OVS bond carrying the given zone addresses.
func ovsBond(vlans ...BondVLANConfig) BondConfig {
	return BondConfig{Name: "bond0", Type: BondTypeOVS, Mode: "balance-tcp", Interfaces: []string{"eth6", "eth7"}, VLANs: vlans}
}

// referenceHost is a valid host config for role: a fabric VTEP address plus
// the role's own zone address.
func referenceHost(role HostRole) *NetworkConfig {
	vlans := []BondVLANConfig{{Zone: "fabric", IPv4Address: "10.4.1.10/24"}}
	if role == HostRoleControlPlane {
		vlans = append(vlans, BondVLANConfig{Zone: "control-plane", IPv4Address: "10.4.6.10/24"})
	} else {
		vlans = append(vlans, BondVLANConfig{Zone: "hypervisor", IPv4Address: "10.4.3.20/24"})
	}
	return &NetworkConfig{
		Role:        role,
		Bonds:       []BondConfig{ovsBond(vlans...)},
		PlatformVRF: &PlatformVRFConfig{Address: "10.4.144.10/32"},
	}
}

// TestNetworkConfig_Validate_ReferenceHosts accepts a reference control-plane
// node, compute node and gateway.
func TestNetworkConfig_Validate_ReferenceHosts(t *testing.T) {
	plan := testPlan(t)
	require.NoError(t, referenceHost(HostRoleControlPlane).Validate(plan))
	require.NoError(t, referenceHost(HostRoleCompute).Validate(plan))

	storage := referenceHost(HostRoleCompute)
	storage.Bonds[0].VLANs = append(storage.Bonds[0].VLANs, BondVLANConfig{Zone: "storage", IPv4Address: "10.4.7.20/24"})
	storage.Interfaces = []InterfaceConfig{{Name: "eth0", Type: InterfaceTypeStatic, IPv6Address: "fd12:3456:789a:401::14/64"}}
	require.NoError(t, storage.Validate(plan), "storage and a fabric IPv6 address are permitted")

	gw := &NetworkConfig{
		Role:       HostRoleGateway,
		IPForward:  true,
		Interfaces: []InterfaceConfig{{Name: "wan0", Type: InterfaceTypeDHCP}, {Name: "eth0", Type: InterfaceTypeStatic, IPv4Address: "203.0.113.2/29"}},
	}
	require.NoError(t, gw.Validate(plan), "gateways are exempt from host addressing")
}

// TestNetworkConfig_Validate_NoRole keeps the lab/image shape valid with
// and without a plan.
func TestNetworkConfig_Validate_NoRole(t *testing.T) {
	nc := &NetworkConfig{Interfaces: []InterfaceConfig{{Name: "eth0", Type: InterfaceTypeDHCP}}}
	require.NoError(t, nc.Validate(nil))
	require.NoError(t, nc.Validate(testPlan(t)))
}

// TestNetworkConfig_Validate_RoleErrors covers every reference-network
// refusal.
func TestNetworkConfig_Validate_RoleErrors(t *testing.T) {
	plan := testPlan(t)

	t.Run("unknown role", func(t *testing.T) {
		var target *ErrInvalidHostRole
		require.True(t, errors.As((&NetworkConfig{Role: "router"}).Validate(plan), &target))
		assert.Contains(t, target.Error(), `"router"`)
	})

	t.Run("forwarding off a gateway", func(t *testing.T) {
		nc := referenceHost(HostRoleCompute)
		nc.IPForward = true
		var target *ErrForwardingNotAllowed
		require.True(t, errors.As(nc.Validate(plan), &target))
		assert.Contains(t, target.Error(), "only allowed on a gateway")
	})

	t.Run("plan required", func(t *testing.T) {
		var target *ErrNetworkPlanRequired
		require.True(t, errors.As((&NetworkConfig{Role: HostRoleCompute}).Validate(nil), &target))
		assert.Contains(t, target.Error(), "network.role")
		require.True(t, errors.As((&NetworkConfig{PlatformVRF: &PlatformVRFConfig{Address: "10.4.144.1/32"}}).Validate(nil), &target))
		assert.Contains(t, target.Error(), "platform-vrf")
		require.True(t, errors.As((&NetworkConfig{Bonds: []BondConfig{ovsBond(BondVLANConfig{Zone: "fabric"})}}).Validate(nil), &target))
		assert.Contains(t, target.Error(), "bonds[bond0]")
	})

	t.Run("address in a zone the role may not use", func(t *testing.T) {
		nc := referenceHost(HostRoleCompute)
		nc.Bonds[0].VLANs = append(nc.Bonds[0].VLANs, BondVLANConfig{Zone: "control-plane", IPv4Address: "10.4.6.20/24"})
		var target *ErrAddressNotPermitted
		require.True(t, errors.As(nc.Validate(plan), &target))
		assert.Equal(t, zone.ZoneControlPlane, target.Zone)
		assert.Contains(t, target.Error(), "fabric, hypervisor and storage")
	})

	t.Run("provisioning address on a control-plane node", func(t *testing.T) {
		nc := referenceHost(HostRoleControlPlane)
		nc.Bonds[0].VLANs = append(nc.Bonds[0].VLANs, BondVLANConfig{Zone: "provisioning", IPv4Address: "192.0.2.10/24"})
		var target *ErrAddressNotPermitted
		require.True(t, errors.As(nc.Validate(plan), &target))
		assert.Equal(t, zone.ZoneProvisioning, target.Zone)
	})

	t.Run("address outside every zone", func(t *testing.T) {
		nc := referenceHost(HostRoleCompute)
		nc.Interfaces = []InterfaceConfig{{Name: "eth0", Type: InterfaceTypeStatic, IPv4Address: "198.18.1.10/24"}}
		var target *ErrAddressNotPermitted
		require.True(t, errors.As(nc.Validate(plan), &target))
		assert.Empty(t, target.Zone)
		assert.Contains(t, target.Error(), "in no platform zone")
	})

	t.Run("unparseable address", func(t *testing.T) {
		nc := referenceHost(HostRoleCompute)
		nc.Bridges = []BridgeConfig{{Name: "br-fabric", IPv4Address: "not-an-ip"}}
		err := nc.Validate(plan)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not parse")
	})

	t.Run("dhcp", func(t *testing.T) {
		var target *ErrDHCPNotPermitted
		for _, mutate := range []func(*NetworkConfig){
			func(nc *NetworkConfig) {
				nc.Interfaces = []InterfaceConfig{{Name: "eth0", Type: InterfaceTypeDHCP}}
			},
			func(nc *NetworkConfig) { nc.Bridges = []BridgeConfig{{Name: "br0", DHCP: true}} },
			func(nc *NetworkConfig) { nc.Bonds[0].DHCP = true },
			func(nc *NetworkConfig) {
				nc.VLANs = []VLANConfig{{Name: "v", Parent: "eth0", Zone: "fabric", DHCP: true}}
			},
		} {
			nc := referenceHost(HostRoleControlPlane)
			mutate(nc)
			require.True(t, errors.As(nc.Validate(plan), &target))
			assert.Contains(t, target.Error(), "uses DHCP")
		}
	})

	t.Run("no fabric address", func(t *testing.T) {
		nc := referenceHost(HostRoleCompute)
		nc.Bonds[0].VLANs = nc.Bonds[0].VLANs[1:]
		var target *ErrFabricAddressRequired
		require.True(t, errors.As(nc.Validate(plan), &target))
		assert.Contains(t, target.Error(), "VTEP")
	})

	t.Run("bond zone not in plan", func(t *testing.T) {
		nc := &NetworkConfig{Bonds: []BondConfig{ovsBond(BondVLANConfig{Zone: "trusted", IPv4Address: "10.4.1.10/24"})}}
		var target *ErrBondZoneVLAN
		require.True(t, errors.As(nc.Validate(plan), &target))
		assert.Contains(t, target.Error(), "not in the network plan")
	})

	t.Run("bond address outside its zone", func(t *testing.T) {
		nc := &NetworkConfig{Bonds: []BondConfig{ovsBond(BondVLANConfig{Zone: "fabric", IPv4Address: "10.4.6.10/24"})}}
		var target *ErrBondZoneVLAN
		require.True(t, errors.As(nc.Validate(plan), &target))
		assert.Contains(t, target.Error(), "outside the zone subnet 10.4.1.0/24")
	})

	t.Run("bond address unparseable", func(t *testing.T) {
		nc := &NetworkConfig{Bonds: []BondConfig{ovsBond(BondVLANConfig{Zone: "fabric", IPv4Address: "x"})}}
		var target *ErrBondZoneVLAN
		require.True(t, errors.As(nc.Validate(plan), &target))
		assert.Contains(t, target.Error(), "does not parse")
	})

	t.Run("platform vrf", func(t *testing.T) {
		var target *ErrInvalidPlatformVRF
		for addr, want := range map[string]string{
			"10.4.144.10/24": "/32",
			"bad":            "/32",
			"10.4.6.10/32":   "outside the platform-hosts range 10.4.144.0/20",
		} {
			nc := &NetworkConfig{PlatformVRF: &PlatformVRFConfig{Address: addr}}
			require.True(t, errors.As(nc.Validate(plan), &target), addr)
			assert.Contains(t, target.Error(), want)
		}
		nc := &NetworkConfig{PlatformVRF: &PlatformVRFConfig{Address: "10.4.144.10/32", Table: -1}}
		require.True(t, errors.As(nc.Validate(plan), &target))
		assert.Contains(t, target.Error(), "table")
	})
}

// TestPlatformVRFConfig_Effective covers the name and table defaults.
func TestPlatformVRFConfig_Effective(t *testing.T) {
	v := &PlatformVRFConfig{}
	assert.Equal(t, DefaultPlatformVRFName, v.EffectiveName())
	assert.Equal(t, DefaultPlatformVRFTable, v.EffectiveTable())
	v = &PlatformVRFConfig{Name: "vrf-p", Table: 7}
	assert.Equal(t, "vrf-p", v.EffectiveName())
	assert.Equal(t, 7, v.EffectiveTable())
}

// TestZoneList renders zone lists for error messages.
func TestZoneList(t *testing.T) {
	assert.Equal(t, "no zone", zoneList(nil))
	assert.Equal(t, "fabric", zoneList([]zone.Zone{zone.ZoneFabric}))
	assert.Equal(t, "fabric and storage", zoneList([]zone.Zone{zone.ZoneFabric, zone.ZoneStorage}))
}

// TestConfig_Validate_PassesPlan checks Config.Validate applies the plan to
// the network section.
func TestConfig_Validate_PassesPlan(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Disk.Device = "/dev/sda"
	cfg.Network = referenceHost(HostRoleCompute)
	err := cfg.Validate()
	var target *ErrNetworkPlanRequired
	require.True(t, errors.As(err, &target), "got %v", err)

	cfg.Plan = testPlan(t)
	require.NoError(t, cfg.Validate())
}

// TestNetworkConfig_Validate_VLANZones covers zone-named VLAN interfaces.
func TestNetworkConfig_Validate_VLANZones(t *testing.T) {
	plan := testPlan(t)

	nc := referenceHost(HostRoleCompute)
	nc.VLANs = []VLANConfig{{Name: "stor", Parent: "eth2", Zone: "storage", IPv4Address: "10.4.7.20/24"}}
	require.NoError(t, nc.Validate(plan))

	lab := &NetworkConfig{VLANs: []VLANConfig{{Name: "eth1.100", Parent: "eth1", ID: 100}}}
	require.NoError(t, lab.Validate(nil), "a literal id stays allowed off a platform network")
	require.NoError(t, lab.Validate(plan))

	var zoneErr *ErrVLANZone
	both := &NetworkConfig{VLANs: []VLANConfig{{Name: "v", Parent: "eth1", ID: 401, Zone: "fabric"}}}
	require.True(t, errors.As(both.Validate(plan), &zoneErr))
	assert.Contains(t, zoneErr.Error(), "not both")

	for addr, want := range map[string]string{"10.4.6.20/24": "outside the zone subnet 10.4.7.0/24", "x": "does not parse"} {
		bad := &NetworkConfig{VLANs: []VLANConfig{{Name: "v", Parent: "eth1", Zone: "storage", IPv4Address: addr}}}
		require.True(t, errors.As(bad.Validate(plan), &zoneErr), addr)
		assert.Contains(t, zoneErr.Error(), want)
	}
	unknown := &NetworkConfig{VLANs: []VLANConfig{{Name: "v", Parent: "eth1", Zone: "trusted"}}}
	require.True(t, errors.As(unknown.Validate(plan), &zoneErr))

	var planErr *ErrNetworkPlanRequired
	noPlan := &NetworkConfig{VLANs: []VLANConfig{{Name: "v", Parent: "eth1", Zone: "fabric"}}}
	require.True(t, errors.As(noPlan.Validate(nil), &planErr))
	assert.Contains(t, planErr.Error(), "vlans[v].zone")

	var literalErr *ErrLiteralVLANWithRole
	literal := referenceHost(HostRoleCompute)
	literal.VLANs = []VLANConfig{{Name: "eth1.100", Parent: "eth1", ID: 100}}
	require.True(t, errors.As(literal.Validate(plan), &literalErr))
	assert.Contains(t, literalErr.Error(), "name its zone")

	var addrErr *ErrAddressNotPermitted
	cpZone := referenceHost(HostRoleCompute)
	cpZone.VLANs = []VLANConfig{{Name: "cp", Parent: "eth2", Zone: "control-plane", IPv4Address: "10.4.6.20/24"}}
	require.True(t, errors.As(cpZone.Validate(plan), &addrErr), "role rules apply to zone VLANs")
}
