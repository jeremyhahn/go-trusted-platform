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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ─────────────────────────────────────────────────────────────────────────────
// Zone validation: pool zone inheritance and mismatch detection
// ─────────────────────────────────────────────────────────────────────────────

// TestValidate_PoolZoneInheritedFromNetwork verifies that a pool with no
// explicit Zone inherits the zone from the network that references it.
func TestValidate_PoolZoneInheritedFromNetwork(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{
		Pools: []sdn.PoolConfig{
			{Name: "prod", CIDR: poolCIDR("10.0.0.0/24")}, // no Zone
		},
	}
	c.Networks = []sdn.NetworkConfig{
		{Name: "production", VLAN: 10, Zone: zone.ZoneTrusted, Pool: "prod"},
	}

	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}

	// After Validate the pool's Zone must have been set to the network's zone.
	if c.IPAM.Pools[0].Zone != string(zone.ZoneTrusted) {
		t.Errorf("expected pool zone %q, got %q", zone.ZoneTrusted, c.IPAM.Pools[0].Zone)
	}
}

// TestValidate_PoolZoneExplicitAgreement verifies that a pool with an explicit
// Zone that matches the referencing network passes validation.
func TestValidate_PoolZoneExplicitAgreement(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{
		Pools: []sdn.PoolConfig{
			{Name: "mgmt", CIDR: poolCIDR("192.168.1.0/24"), Zone: string(zone.ZoneManagement)},
		},
	}
	c.Networks = []sdn.NetworkConfig{
		{Name: "management", VLAN: 99, Zone: zone.ZoneManagement, Pool: "mgmt"},
	}

	if err := c.Validate(); err != nil {
		t.Errorf("matching explicit pool zone must pass, got: %v", err)
	}
}

// TestValidate_NetworkPoolZoneMismatch verifies that a mismatch between a
// network's zone and its referenced pool's explicit zone returns
// ErrNetworkPoolZoneMismatch.
func TestValidate_NetworkPoolZoneMismatch(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{
		Pools: []sdn.PoolConfig{
			{Name: "pool-a", CIDR: poolCIDR("10.0.0.0/24"), Zone: string(zone.ZoneProvisioning)},
		},
	}
	c.Networks = []sdn.NetworkConfig{
		// network says trusted, pool says provisioning → mismatch
		{Name: "net-a", VLAN: 10, Zone: zone.ZoneTrusted, Pool: "pool-a"},
	}

	err := c.Validate()
	var target sdn.ErrNetworkPoolZoneMismatch
	if !errors.As(err, &target) {
		t.Errorf("want ErrNetworkPoolZoneMismatch, got %T: %v", err, err)
	}
	if target.Pool != "pool-a" {
		t.Errorf("mismatch error Pool field: want %q, got %q", "pool-a", target.Pool)
	}
	if target.NetworkZone != zone.ZoneTrusted {
		t.Errorf("mismatch error NetworkZone: want %q, got %q", zone.ZoneTrusted, target.NetworkZone)
	}
	if target.PoolZone != string(zone.ZoneProvisioning) {
		t.Errorf("mismatch error PoolZone: want %q, got %q", zone.ZoneProvisioning, target.PoolZone)
	}
}

// TestValidate_PoolZoneUndeclared verifies that a pool with a Zone value not
// present in the resolved zone set returns ErrPoolZoneUndeclared.
func TestValidate_PoolZoneUndeclared(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{
		Pools: []sdn.PoolConfig{
			{Name: "orphan", CIDR: poolCIDR("10.99.0.0/24"), Zone: "nonexistent-zone"},
		},
	}
	// No networks reference this pool, so it's caught by the standalone pool
	// zone validation pass.

	err := c.Validate()
	var target sdn.ErrPoolZoneUndeclared
	if !errors.As(err, &target) {
		t.Errorf("want ErrPoolZoneUndeclared, got %T: %v", err, err)
	}
	if target.Pool != "orphan" {
		t.Errorf("error Pool field: want %q, got %q", "orphan", target.Pool)
	}
	if target.Zone != "nonexistent-zone" {
		t.Errorf("error Zone field: want %q, got %q", "nonexistent-zone", target.Zone)
	}
}

// TestValidate_PoolWithZoneNotReferencedByNetwork_Valid verifies that a pool
// with a valid explicit zone that is not referenced by any network passes.
func TestValidate_PoolWithZoneNotReferencedByNetwork_Valid(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{
		Pools: []sdn.PoolConfig{
			{Name: "standalone", CIDR: poolCIDR("10.200.0.0/24"), Zone: string(zone.ZoneStorage)},
		},
	}
	// No networks — standalone pool with valid zone.

	if err := c.Validate(); err != nil {
		t.Errorf("pool with valid unreferenced zone must pass, got: %v", err)
	}
}

// TestValidate_ZoneInheritanceMultiplePools verifies that multiple pools each
// inherit zones from their respective referencing networks.
func TestValidate_ZoneInheritanceMultiplePools(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{
		Pools: []sdn.PoolConfig{
			{Name: "pool-trusted", CIDR: poolCIDR("10.1.0.0/24")},
			{Name: "pool-prov", CIDR: poolCIDR("10.2.0.0/24")},
		},
	}
	c.Networks = []sdn.NetworkConfig{
		{Name: "trusted-net", VLAN: 1, Zone: zone.ZoneTrusted, Pool: "pool-trusted"},
		{Name: "prov-net", VLAN: 2, Zone: zone.ZoneProvisioning, Pool: "pool-prov"},
	}

	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}

	for _, p := range c.IPAM.Pools {
		switch p.Name {
		case "pool-trusted":
			if p.Zone != string(zone.ZoneTrusted) {
				t.Errorf("pool-trusted: want zone %q, got %q", zone.ZoneTrusted, p.Zone)
			}
		case "pool-prov":
			if p.Zone != string(zone.ZoneProvisioning) {
				t.Errorf("pool-prov: want zone %q, got %q", zone.ZoneProvisioning, p.Zone)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// New error types — string coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestErrorStrings_ZoneErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			"ErrNetworkPoolZoneMismatch",
			sdn.ErrNetworkPoolZoneMismatch{
				Network:     "n",
				Pool:        "p",
				NetworkZone: "trusted",
				PoolZone:    "provisioning",
			},
			`sdn: network "n" zone "trusted" conflicts with pool "p" zone "provisioning"`,
		},
		{
			"ErrPoolZoneUndeclared",
			sdn.ErrPoolZoneUndeclared{Pool: "mypool", Zone: "unknown"},
			`sdn: ipam pool "mypool" zone "unknown" is not declared in resolved zones`,
		},
		{
			"ErrIPAMBackendUnconfigured",
			sdn.ErrIPAMBackendUnconfigured{Backend: "quicbaas"},
			`sdn: ipam backend "quicbaas" requires a configured quicbaas client`,
		},
		{
			"ErrIPAMBackendUnknown",
			sdn.ErrIPAMBackendUnknown{Backend: "redis"},
			`sdn: unknown ipam backend "redis"`,
		},
		{
			"ErrIPAMBackendP2PRequired",
			sdn.ErrIPAMBackendP2PRequired{},
			`sdn: ipam backend "dht" requires build tag platform_p2p`,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.err.Error()
			if got == "" {
				t.Fatalf("%s.Error() returned empty string", tc.name)
			}
			if got != tc.want {
				t.Errorf("%s.Error() = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ZoneIndex
// ─────────────────────────────────────────────────────────────────────────────

func TestZoneIndex_NilConfig(t *testing.T) {
	t.Parallel()

	var c *sdn.Config
	idx := c.ZoneIndex()
	if len(idx) != 0 {
		t.Errorf("ZoneIndex on nil Config must return empty map, got %d entries", len(idx))
	}
}

func TestZoneIndex_PopulatedAfterValidate(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	idx := c.ZoneIndex()
	if len(idx) == 0 {
		t.Error("ZoneIndex must be non-empty after Validate")
	}

	// Built-in zones must all be present.
	for _, z := range []zone.Zone{
		zone.ZoneTrusted, zone.ZoneProvisioning, zone.ZoneManagement,
	} {
		if _, ok := idx[z]; !ok {
			t.Errorf("ZoneIndex missing built-in zone %q", z)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PoolConfig.Zone yaml tag
// ─────────────────────────────────────────────────────────────────────────────

func TestPoolConfig_ZoneField(t *testing.T) {
	t.Parallel()

	pc := sdn.PoolConfig{
		Name: "p",
		CIDR: poolCIDR("10.0.0.0/24"),
		Zone: "trusted",
	}
	if pc.Zone != "trusted" {
		t.Errorf("expected Zone %q, got %q", "trusted", pc.Zone)
	}

	// Validate must succeed for a pool with a valid zone (checked only in
	// full Config.Validate, not PoolConfig.Validate which is CIDR/name only).
	if err := pc.Validate(); err != nil {
		t.Errorf("PoolConfig.Validate() should only check name/CIDR, got: %v", err)
	}
}
