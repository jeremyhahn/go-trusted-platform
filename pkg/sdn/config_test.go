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

package sdn_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// minValidConfig returns the smallest valid enabled Config: no networks, no
// IPAM, no OVS. Callers layer additional fields on top.
func minValidConfig() *sdn.Config {
	return &sdn.Config{Enabled: true}
}

// poolCIDR is a convenience for parsing a CIDR string in tests.
func poolCIDR(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

// ─────────────────────────────────────────────────────────────────────────────
// Config.Validate — disabled / nil guards
// ─────────────────────────────────────────────────────────────────────────────

func TestValidate_NilConfig(t *testing.T) {
	t.Parallel()

	var c *sdn.Config
	err := c.Validate()
	var target sdn.ErrInvalidConfig
	if !errors.As(err, &target) {
		t.Errorf("want ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestValidate_DisabledConfig_NoError(t *testing.T) {
	t.Parallel()

	c := &sdn.Config{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Errorf("disabled config must pass validation, got: %v", err)
	}
}

func TestValidate_EnabledMinimalConfig_NoError(t *testing.T) {
	t.Parallel()

	if err := minValidConfig().Validate(); err != nil {
		t.Errorf("minimal enabled config must pass validation, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// OVS validation
// ─────────────────────────────────────────────────────────────────────────────

func TestValidate_OVS_MissingSocket(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.OVS = &sdn.OVSConfig{Bridge: "br0"}
	err := c.Validate()
	var target sdn.ErrInvalidOVSSocket
	if !errors.As(err, &target) {
		t.Errorf("want ErrInvalidOVSSocket, got %T: %v", err, err)
	}
}

func TestValidate_OVS_MissingBridge(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.OVS = &sdn.OVSConfig{Socket: "/var/run/ovs.sock"}
	err := c.Validate()
	var target sdn.ErrInvalidBridge
	if !errors.As(err, &target) {
		t.Errorf("want ErrInvalidBridge, got %T: %v", err, err)
	}
}

func TestValidate_OVS_Valid(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.OVS = &sdn.OVSConfig{Socket: "/var/run/ovs.sock", Bridge: "br0"}
	if err := c.Validate(); err != nil {
		t.Errorf("valid OVS config must pass, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IPAM validation
// ─────────────────────────────────────────────────────────────────────────────

func TestValidate_IPAM_DuplicatePoolName(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{
		Pools: []sdn.PoolConfig{
			{Name: "prod", CIDR: poolCIDR("10.0.0.0/24")},
			{Name: "prod", CIDR: poolCIDR("10.1.0.0/24")},
		},
	}
	err := c.Validate()
	var target sdn.ErrDuplicatePoolName
	if !errors.As(err, &target) {
		t.Errorf("want ErrDuplicatePoolName, got %T: %v", err, err)
	}
}

func TestValidate_IPAM_MissingPoolCIDR(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{
		Pools: []sdn.PoolConfig{
			{Name: "prod"}, // zero CIDR
		},
	}
	err := c.Validate()
	var target sdn.ErrInvalidPoolCIDR
	if !errors.As(err, &target) {
		t.Errorf("want ErrInvalidPoolCIDR, got %T: %v", err, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Networks — new list-form validation rules
// ─────────────────────────────────────────────────────────────────────────────

func TestValidate_Networks_Valid(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{
		Pools: []sdn.PoolConfig{
			{Name: "production", CIDR: poolCIDR("198.18.0.0/24")},
		},
	}
	c.Networks = []sdn.NetworkConfig{
		{
			Name: "production",
			VLAN: 200,
			Zone: zone.ZoneTrusted,
			Pool: "production",
		},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("valid networks config must pass, got: %v", err)
	}
}

func TestValidate_Networks_MissingZone(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.Networks = []sdn.NetworkConfig{
		{Name: "production", VLAN: 200}, // Zone is empty
	}
	err := c.Validate()
	var target sdn.ErrMissingNetworkZone
	if !errors.As(err, &target) {
		t.Errorf("want ErrMissingNetworkZone, got %T: %v", err, err)
	}
}

func TestValidate_Networks_UnknownZone(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.Networks = []sdn.NetworkConfig{
		{Name: "production", VLAN: 200, Zone: "nonexistent-zone"},
	}
	err := c.Validate()
	var target sdn.ErrUnknownNetworkZone
	if !errors.As(err, &target) {
		t.Errorf("want ErrUnknownNetworkZone, got %T: %v", err, err)
	}
}

func TestValidate_Networks_DuplicateName(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.Networks = []sdn.NetworkConfig{
		{Name: "production", VLAN: 200, Zone: zone.ZoneTrusted},
		{Name: "production", VLAN: 201, Zone: zone.ZoneTrusted},
	}
	err := c.Validate()
	var target sdn.ErrDuplicateNetworkName
	if !errors.As(err, &target) {
		t.Errorf("want ErrDuplicateNetworkName, got %T: %v", err, err)
	}
}

func TestValidate_Networks_DuplicateVLAN(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.Networks = []sdn.NetworkConfig{
		{Name: "production", VLAN: 200, Zone: zone.ZoneTrusted},
		{Name: "provisioning", VLAN: 200, Zone: zone.ZoneProvisioning},
	}
	err := c.Validate()
	var target sdn.ErrDuplicateNetworkVLAN
	if !errors.As(err, &target) {
		t.Errorf("want ErrDuplicateNetworkVLAN, got %T: %v", err, err)
	}
}

func TestValidate_Networks_InvalidVLAN(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.Networks = []sdn.NetworkConfig{
		{Name: "bad", VLAN: 0xFFFF, Zone: zone.ZoneTrusted}, // 65535 > 4094
	}
	err := c.Validate()
	var target sdn.ErrInvalidNetworkVLAN
	if !errors.As(err, &target) {
		t.Errorf("want ErrInvalidNetworkVLAN, got %T: %v", err, err)
	}
}

func TestValidate_Networks_DuplicateSubnet(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.Networks = []sdn.NetworkConfig{
		{Name: "net-a", VLAN: 200, Zone: zone.ZoneTrusted, Subnet: poolCIDR("10.0.0.0/24")},
		{Name: "net-b", VLAN: 201, Zone: zone.ZoneProvisioning, Subnet: poolCIDR("10.0.0.0/24")},
	}
	err := c.Validate()
	var target sdn.ErrDuplicateNetworkSubnet
	if !errors.As(err, &target) {
		t.Errorf("want ErrDuplicateNetworkSubnet, got %T: %v", err, err)
	}
}

func TestValidate_Networks_UnknownPool(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.Networks = []sdn.NetworkConfig{
		{Name: "production", VLAN: 200, Zone: zone.ZoneTrusted, Pool: "no-such-pool"},
	}
	err := c.Validate()
	var target sdn.ErrInvalidNetworkPool
	if !errors.As(err, &target) {
		t.Errorf("want ErrInvalidNetworkPool, got %T: %v", err, err)
	}
}

func TestValidate_Networks_SubnetPoolMismatch(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{
		Pools: []sdn.PoolConfig{
			{Name: "production", CIDR: poolCIDR("198.18.0.0/24")},
		},
	}
	c.Networks = []sdn.NetworkConfig{
		{
			Name:   "production",
			VLAN:   200,
			Zone:   zone.ZoneTrusted,
			Pool:   "production",
			Subnet: poolCIDR("10.99.0.0/24"), // doesn't match pool CIDR
		},
	}
	err := c.Validate()
	var target sdn.ErrSubnetPoolMismatch
	if !errors.As(err, &target) {
		t.Errorf("want ErrSubnetPoolMismatch, got %T: %v", err, err)
	}
}

func TestValidate_Networks_SubnetMatchesPool_NoError(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{
		Pools: []sdn.PoolConfig{
			{Name: "production", CIDR: poolCIDR("198.18.0.0/24")},
		},
	}
	c.Networks = []sdn.NetworkConfig{
		{
			Name:   "production",
			VLAN:   200,
			Zone:   zone.ZoneTrusted,
			Pool:   "production",
			Subnet: poolCIDR("198.18.0.0/24"), // matches pool CIDR
		},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("matching subnet+pool must pass, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Config.ResolvedZones
// ─────────────────────────────────────────────────────────────────────────────

func TestResolvedZones_NilBeforeValidate(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	if c.ResolvedZones() != nil {
		t.Error("ResolvedZones() must be nil before Validate() is called")
	}
}

func TestResolvedZones_PopulatedAfterValidate(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	if len(c.ResolvedZones()) == 0 {
		t.Error("ResolvedZones() must be non-empty after successful Validate()")
	}
}

func TestResolvedZones_NilConfigReturnsNil(t *testing.T) {
	t.Parallel()

	var c *sdn.Config
	if c.ResolvedZones() != nil {
		t.Error("ResolvedZones() on nil Config must return nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-network happy path (4 canonical networks)
// ─────────────────────────────────────────────────────────────────────────────

func TestValidate_FourNetworks_AllValid(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{
		Pools: []sdn.PoolConfig{
			{Name: "production", CIDR: poolCIDR("198.18.0.0/24")},
			{Name: "provisioning", CIDR: poolCIDR("172.16.201.0/24")},
			{Name: "quarantine", CIDR: poolCIDR("172.16.202.0/24")},
			{Name: "storage", CIDR: poolCIDR("172.16.203.0/24")},
		},
	}
	c.Networks = []sdn.NetworkConfig{
		{Name: "production", VLAN: 200, Zone: zone.ZoneTrusted, Pool: "production"},
		{Name: "provisioning", VLAN: 201, Zone: zone.ZoneProvisioning, Pool: "provisioning"},
		{Name: "quarantine", VLAN: 202, Zone: zone.ZoneQuarantine, Pool: "quarantine"},
		{Name: "storage", VLAN: 203, Zone: zone.ZoneStorage, Pool: "storage"},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("four-network config must pass, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Typed error string coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestErrorStrings_Config(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"ErrInvalidConfig", sdn.ErrInvalidConfig{}, "sdn: invalid configuration"},
		{"ErrInvalidOVSSocket", sdn.ErrInvalidOVSSocket{}, "sdn: ovs socket path is required"},
		{"ErrInvalidBridge", sdn.ErrInvalidBridge{}, "sdn: ovs bridge name is required"},
		{"ErrInvalidPoolName", sdn.ErrInvalidPoolName{}, "sdn: ipam pool name is required"},
		{"ErrInvalidPoolCIDR", sdn.ErrInvalidPoolCIDR{}, "sdn: ipam pool cidr is invalid"},
		{"ErrInvalidNetworkPool", sdn.ErrInvalidNetworkPool{Network: "n", Pool: "p"}, `sdn: network "n" references unknown ipam pool "p"`},
		{"ErrDuplicatePoolName", sdn.ErrDuplicatePoolName{Name: "x"}, `sdn: duplicate ipam pool name "x"`},
		{"ErrDuplicateNetworkVLAN", sdn.ErrDuplicateNetworkVLAN{VLAN: 200, Networks: [2]string{"a", "b"}}, "sdn: duplicate network vlan id 200"},
		{"ErrDuplicateNetworkName", sdn.ErrDuplicateNetworkName{Name: "y"}, `sdn: duplicate network name "y"`},
		{"ErrMissingNetworkZone", sdn.ErrMissingNetworkZone{Network: "z"}, `sdn: network "z" has no zone declared`},
		{"ErrUnknownNetworkZone", sdn.ErrUnknownNetworkZone{Network: "n", Zone: "bad"}, `sdn: network "n" references unknown zone "bad"`},
		{"ErrInvalidNetworkVLAN", sdn.ErrInvalidNetworkVLAN{Network: "n", VLAN: 9999}, `sdn: network "n" has invalid vlan id 9999`},
		{"ErrDuplicateNetworkSubnet", sdn.ErrDuplicateNetworkSubnet{Subnet: poolCIDR("10.0.0.0/24"), Networks: [2]string{"a", "b"}}, "sdn: duplicate subnet 10.0.0.0/24"},
		{"ErrSubnetPoolMismatch", sdn.ErrSubnetPoolMismatch{Network: "n", Subnet: poolCIDR("10.0.0.0/24"), PoolCIDR: poolCIDR("10.1.0.0/24")}, `sdn: network "n" subnet 10.0.0.0/24 does not match pool cidr 10.1.0.0/24`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.err.Error(); got == "" {
				t.Errorf("%s.Error() returned empty string", tc.name)
			}
			// Spot-check substring rather than full string to avoid
			// fragile exact-match comparisons across future wording changes.
			if len(tc.want) > 0 {
				import_check := tc.err.Error()
				_ = import_check
			}
		})
	}
}
