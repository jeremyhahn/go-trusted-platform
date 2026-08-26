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

// testZones returns the canonical built-in zone set for use in index tests.
func testZones() []zone.ZoneConfig {
	z, err := zone.Resolve(nil) // built-ins only
	if err != nil {
		panic(err)
	}
	return z
}

// testNetworks is a representative set of four networks covering the four
// well-known zones used in most templates.
func testNetworks() []sdn.NetworkConfig {
	return []sdn.NetworkConfig{
		{
			Name:   "production",
			VLAN:   200,
			Zone:   zone.ZoneTrusted,
			Subnet: netip.MustParsePrefix("198.18.0.0/24"),
			Pool:   "production",
		},
		{
			Name:   "provisioning",
			VLAN:   201,
			Zone:   zone.ZoneProvisioning,
			Subnet: netip.MustParsePrefix("172.16.201.0/24"),
			Pool:   "provisioning",
		},
		{
			Name:   "quarantine",
			VLAN:   202,
			Zone:   zone.ZoneQuarantine,
			Subnet: netip.MustParsePrefix("172.16.202.0/24"),
			Pool:   "quarantine",
		},
		{
			Name:   "storage",
			VLAN:   203,
			Zone:   zone.ZoneStorage,
			Subnet: netip.MustParsePrefix("172.16.203.0/24"),
			Pool:   "storage",
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildZoneIndex
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildZoneIndex_HappyPath(t *testing.T) {
	t.Parallel()

	idx, err := sdn.BuildZoneIndex(testZones(), testNetworks())
	if err != nil {
		t.Fatalf("BuildZoneIndex: unexpected error: %v", err)
	}
	if idx == nil {
		t.Fatal("BuildZoneIndex returned nil index")
	}
}

func TestBuildZoneIndex_UndeclaredZone_Error(t *testing.T) {
	t.Parallel()

	networks := []sdn.NetworkConfig{
		{Name: "rogue", VLAN: 999, Zone: "no-such-zone"},
	}
	_, err := sdn.BuildZoneIndex(testZones(), networks)
	var target sdn.ErrBuildZoneIndex
	if !errors.As(err, &target) {
		t.Errorf("want ErrBuildZoneIndex for undeclared zone, got %T: %v", err, err)
	}
}

func TestBuildZoneIndex_EmptyNetworks_NoError(t *testing.T) {
	t.Parallel()

	idx, err := sdn.BuildZoneIndex(testZones(), nil)
	if err != nil {
		t.Fatalf("BuildZoneIndex with no networks: unexpected error: %v", err)
	}
	if idx == nil {
		t.Fatal("BuildZoneIndex returned nil index")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ByZone
// ─────────────────────────────────────────────────────────────────────────────

func TestZoneIndex_ByZone_KnownZone(t *testing.T) {
	t.Parallel()

	idx, err := sdn.BuildZoneIndex(testZones(), testNetworks())
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}

	nets := idx.ByZone(zone.ZoneTrusted)
	if len(nets) != 1 {
		t.Errorf("ByZone(trusted): want 1 network, got %d", len(nets))
	}
	if len(nets) > 0 && nets[0].Name != "production" {
		t.Errorf("ByZone(trusted): want name 'production', got %q", nets[0].Name)
	}
}

func TestZoneIndex_ByZone_UnknownZone_ReturnsNil(t *testing.T) {
	t.Parallel()

	idx, err := sdn.BuildZoneIndex(testZones(), testNetworks())
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}

	if nets := idx.ByZone("ghost-zone"); nets != nil {
		t.Errorf("ByZone for unknown zone: want nil, got %v", nets)
	}
}

func TestZoneIndex_ByZone_ZoneWithNoNetworks_ReturnsNil(t *testing.T) {
	t.Parallel()

	// ZonePublic is in the resolved set but has no network entries.
	idx, err := sdn.BuildZoneIndex(testZones(), testNetworks())
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}

	if nets := idx.ByZone(zone.ZonePublic); nets != nil {
		t.Errorf("ByZone(public) with no matching network: want nil, got %v", nets)
	}
}

func TestZoneIndex_ByZone_NilIndex_ReturnsNil(t *testing.T) {
	t.Parallel()

	var idx *sdn.ZoneIndex
	if nets := idx.ByZone(zone.ZoneTrusted); nets != nil {
		t.Errorf("nil ZoneIndex.ByZone: want nil, got %v", nets)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ZoneForVLAN
// ─────────────────────────────────────────────────────────────────────────────

func TestZoneIndex_ZoneForVLAN_Known(t *testing.T) {
	t.Parallel()

	idx, err := sdn.BuildZoneIndex(testZones(), testNetworks())
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}

	z, ok := idx.ZoneForVLAN(200)
	if !ok {
		t.Fatal("ZoneForVLAN(200): want ok=true, got false")
	}
	if z != zone.ZoneTrusted {
		t.Errorf("ZoneForVLAN(200): want %q, got %q", zone.ZoneTrusted, z)
	}
}

func TestZoneIndex_ZoneForVLAN_Unknown(t *testing.T) {
	t.Parallel()

	idx, err := sdn.BuildZoneIndex(testZones(), testNetworks())
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}

	_, ok := idx.ZoneForVLAN(9999)
	if ok {
		t.Error("ZoneForVLAN(9999): want ok=false, got true")
	}
}

func TestZoneIndex_ZoneForVLAN_NilIndex_ReturnsFalse(t *testing.T) {
	t.Parallel()

	var idx *sdn.ZoneIndex
	_, ok := idx.ZoneForVLAN(200)
	if ok {
		t.Error("nil ZoneIndex.ZoneForVLAN: want false, got true")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ZoneForSubnet
// ─────────────────────────────────────────────────────────────────────────────

func TestZoneIndex_ZoneForSubnet_AddressInRange(t *testing.T) {
	t.Parallel()

	idx, err := sdn.BuildZoneIndex(testZones(), testNetworks())
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}

	// 198.18.0.42 is inside the production (trusted) subnet 198.18.0.0/24.
	addr := netip.MustParseAddr("198.18.0.42")
	z, ok := idx.ZoneForSubnet(addr)
	if !ok {
		t.Fatal("ZoneForSubnet(198.18.0.42): want ok=true, got false")
	}
	if z != zone.ZoneTrusted {
		t.Errorf("ZoneForSubnet: want %q, got %q", zone.ZoneTrusted, z)
	}
}

func TestZoneIndex_ZoneForSubnet_AddressNotInAnyRange(t *testing.T) {
	t.Parallel()

	idx, err := sdn.BuildZoneIndex(testZones(), testNetworks())
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}

	addr := netip.MustParseAddr("192.168.99.1")
	_, ok := idx.ZoneForSubnet(addr)
	if ok {
		t.Error("ZoneForSubnet(192.168.99.1): want ok=false for address in no registered prefix, got true")
	}
}

func TestZoneIndex_ZoneForSubnet_NilIndex_ReturnsFalse(t *testing.T) {
	t.Parallel()

	var idx *sdn.ZoneIndex
	_, ok := idx.ZoneForSubnet(netip.MustParseAddr("10.0.0.1"))
	if ok {
		t.Error("nil ZoneIndex.ZoneForSubnet: want false, got true")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkByName
// ─────────────────────────────────────────────────────────────────────────────

func TestZoneIndex_NetworkByName_Known(t *testing.T) {
	t.Parallel()

	idx, err := sdn.BuildZoneIndex(testZones(), testNetworks())
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}

	n, ok := idx.NetworkByName("storage")
	if !ok {
		t.Fatal("NetworkByName('storage'): want ok=true, got false")
	}
	if n.VLAN != 203 {
		t.Errorf("NetworkByName('storage'): want VLAN 203, got %d", n.VLAN)
	}
}

func TestZoneIndex_NetworkByName_Unknown(t *testing.T) {
	t.Parallel()

	idx, err := sdn.BuildZoneIndex(testZones(), testNetworks())
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}

	_, ok := idx.NetworkByName("no-such-network")
	if ok {
		t.Error("NetworkByName('no-such-network'): want ok=false, got true")
	}
}

func TestZoneIndex_NetworkByName_NilIndex_ReturnsFalse(t *testing.T) {
	t.Parallel()

	var idx *sdn.ZoneIndex
	_, ok := idx.NetworkByName("production")
	if ok {
		t.Error("nil ZoneIndex.NetworkByName: want false, got true")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ByZone returns independent copy (mutation safety)
// ─────────────────────────────────────────────────────────────────────────────

func TestZoneIndex_ByZone_ReturnsCopy(t *testing.T) {
	t.Parallel()

	idx, err := sdn.BuildZoneIndex(testZones(), testNetworks())
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}

	first := idx.ByZone(zone.ZoneTrusted)
	if len(first) == 0 {
		t.Fatal("ByZone returned empty slice for trusted zone")
	}
	// Mutate the returned slice.
	first[0].Name = "mutated"

	// A second call must return the original name, not the mutated value.
	second := idx.ByZone(zone.ZoneTrusted)
	if len(second) == 0 {
		t.Fatal("ByZone returned empty slice on second call")
	}
	if second[0].Name == "mutated" {
		t.Error("ByZone returned a reference to internal state; expected a copy")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Multiple networks in the same zone
// ─────────────────────────────────────────────────────────────────────────────

func TestZoneIndex_ByZone_MultipleNetworks(t *testing.T) {
	t.Parallel()

	networks := []sdn.NetworkConfig{
		{Name: "trusted-a", VLAN: 200, Zone: zone.ZoneTrusted},
		{Name: "trusted-b", VLAN: 201, Zone: zone.ZoneTrusted},
	}
	idx, err := sdn.BuildZoneIndex(testZones(), networks)
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}

	nets := idx.ByZone(zone.ZoneTrusted)
	if len(nets) != 2 {
		t.Errorf("ByZone(trusted): want 2 networks, got %d", len(nets))
	}
}

func TestNetworkSummariesByZone(t *testing.T) {
	zones := testZones()
	networks := []sdn.NetworkConfig{
		{
			Name:   "trusted-net",
			VLAN:   200,
			Zone:   zone.ZoneTrusted,
			Subnet: netip.MustParsePrefix("10.20.0.0/24"),
		},
		{
			Name: "storage-net-no-vlan",
			Zone: zone.ZoneStorage,
		},
	}
	idx, err := sdn.BuildZoneIndex(zones, networks)
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}

	nets := sdn.NetworkSummariesByZone(zones, idx)
	summary, ok := nets[zone.ZoneTrusted]
	if !ok {
		t.Fatalf("summaries = %v, want trusted entry", nets)
	}
	if summary.VLAN != 200 || summary.Subnet != "10.20.0.0/24" {
		t.Fatalf("trusted summary = %+v", summary)
	}
	if _, ok := nets[zone.ZoneStorage]; ok {
		t.Fatal("a network without a VLAN must not produce a summary")
	}
	if _, ok := nets[zone.ZoneQuarantine]; ok {
		t.Fatal("a zone without a network must not produce a summary")
	}
}

func TestNetworkSummariesByZoneNilIndex(t *testing.T) {
	nets := sdn.NetworkSummariesByZone(testZones(), nil)
	if len(nets) != 0 {
		t.Fatalf("summaries = %v, want empty for nil index", nets)
	}
}

func TestNetworkSummariesByZoneSkipsVLANLessDeclaredFirst(t *testing.T) {
	zones := testZones()
	networks := []sdn.NetworkConfig{
		{Name: "trusted-mgmt", Zone: zone.ZoneTrusted}, // no VLAN, declared first
		{
			Name:   "trusted-data",
			VLAN:   200,
			Zone:   zone.ZoneTrusted,
			Subnet: netip.MustParsePrefix("10.20.0.0/24"),
		},
	}
	idx, err := sdn.BuildZoneIndex(zones, networks)
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}
	summary, ok := sdn.NetworkSummariesByZone(zones, idx)[zone.ZoneTrusted]
	if !ok || summary.VLAN != 200 {
		t.Fatalf("summary = %+v ok=%v — declaration order must not disable enforcement", summary, ok)
	}
}
