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

package compute

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// buildZoneIndex builds a minimal ZoneIndex for the given zones and networks.
func buildZoneIndex(t *testing.T, zones []zone.ZoneConfig, networks []sdn.NetworkConfig) *sdn.ZoneIndex {
	t.Helper()
	idx, err := sdn.BuildZoneIndex(zones, networks)
	if err != nil {
		t.Fatalf("BuildZoneIndex: %v", err)
	}
	return idx
}

func trustedZones() []zone.ZoneConfig {
	return []zone.ZoneConfig{
		{Name: zone.ZoneTrusted},
		{Name: zone.ZoneQuarantine, LifecycleRole: zone.LifecycleRoleQuarantine},
	}
}

func trustedNetworks() []sdn.NetworkConfig {
	return []sdn.NetworkConfig{
		{Name: "corp", Zone: zone.ZoneTrusted, VLAN: 100, Subnet: netip.MustParsePrefix("10.0.0.0/24")},
		{Name: "mgmt", Zone: zone.ZoneTrusted, VLAN: 101, Subnet: netip.MustParsePrefix("10.0.1.0/24")},
	}
}

// TestPlaceVNIC_HappyPath verifies that the alphabetically-first network in the
// profile's zone is selected and the placement is returned correctly.
func TestPlaceVNIC_HappyPath(t *testing.T) {
	idx := buildZoneIndex(t, trustedZones(), trustedNetworks())

	cfg := &PlaceVNICConfig{
		Profile:   &entities.DeviceProfile{Zone: string(zone.ZoneTrusted)},
		ZoneIndex: idx,
		PortID:    "tap0",
	}

	placement, err := PlaceVNIC(context.Background(), cfg)
	if err != nil {
		t.Fatalf("PlaceVNIC: %v", err)
	}

	// "corp" < "mgmt" alphabetically → corp is selected.
	if placement.NetworkName != "corp" {
		t.Errorf("expected 'corp' (first alphabetically), got %q", placement.NetworkName)
	}
	if placement.Zone != zone.ZoneTrusted {
		t.Errorf("expected zone trusted, got %q", placement.Zone)
	}
	if placement.VLAN != 100 {
		t.Errorf("expected VLAN 100, got %d", placement.VLAN)
	}
}

// TestPlaceVNIC_DefaultZone verifies that a profile with no zone set falls back
// to ZoneTrusted.
func TestPlaceVNIC_DefaultZone(t *testing.T) {
	idx := buildZoneIndex(t, trustedZones(), trustedNetworks())

	cfg := &PlaceVNICConfig{
		Profile:   &entities.DeviceProfile{}, // empty zone
		ZoneIndex: idx,
		PortID:    "tap1",
	}

	placement, err := PlaceVNIC(context.Background(), cfg)
	if err != nil {
		t.Fatalf("PlaceVNIC: %v", err)
	}
	if placement.Zone != zone.ZoneTrusted {
		t.Errorf("expected fallback to ZoneTrusted, got %q", placement.Zone)
	}
}

// TestPlaceVNIC_NoNetworkInZone verifies ErrNoNetworkInZone when the profile's
// zone has no networks registered in the ZoneIndex.
func TestPlaceVNIC_NoNetworkInZone(t *testing.T) {
	zones := []zone.ZoneConfig{
		{Name: zone.ZoneTrusted},
		{Name: zone.ZoneQuarantine, LifecycleRole: zone.LifecycleRoleQuarantine},
	}
	// Only populate trusted — quarantine has no networks.
	networks := []sdn.NetworkConfig{
		{Name: "corp", Zone: zone.ZoneTrusted, VLAN: 100, Subnet: netip.MustParsePrefix("10.0.0.0/24")},
	}
	idx := buildZoneIndex(t, zones, networks)

	cfg := &PlaceVNICConfig{
		Profile:   &entities.DeviceProfile{Zone: string(zone.ZoneQuarantine)},
		ZoneIndex: idx,
		PortID:    "tap2",
	}

	_, err := PlaceVNIC(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected ErrNoNetworkInZone, got nil")
	}
	var noNet ErrNoNetworkInZone
	if !errors.As(err, &noNet) {
		t.Errorf("expected ErrNoNetworkInZone, got %T: %v", err, err)
	}
	if noNet.Zone != zone.ZoneQuarantine {
		t.Errorf("expected Zone quarantine in error, got %q", noNet.Zone)
	}
}

// TestPlaceVNIC_NilConfig verifies that a nil config returns an error.
func TestPlaceVNIC_NilConfig(t *testing.T) {
	_, err := PlaceVNIC(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

// TestPlaceVNIC_NilProfile verifies that a nil profile returns ErrInvalidProfile.
func TestPlaceVNIC_NilProfile(t *testing.T) {
	idx := buildZoneIndex(t, trustedZones(), trustedNetworks())
	_, err := PlaceVNIC(context.Background(), &PlaceVNICConfig{
		ZoneIndex: idx,
		PortID:    "tap3",
	})
	if !errors.Is(err, ErrInvalidProfile) {
		t.Errorf("expected ErrInvalidProfile, got %v", err)
	}
}

// TestPlaceVNIC_NilZoneIndex verifies that a nil ZoneIndex returns an error.
func TestPlaceVNIC_NilZoneIndex(t *testing.T) {
	_, err := PlaceVNIC(context.Background(), &PlaceVNICConfig{
		Profile: &entities.DeviceProfile{Zone: string(zone.ZoneTrusted)},
		PortID:  "tap4",
	})
	if err == nil {
		t.Error("expected error for nil ZoneIndex")
	}
}

// TestPlaceVNIC_EmptyPortID verifies that an empty PortID returns an error.
func TestPlaceVNIC_EmptyPortID(t *testing.T) {
	idx := buildZoneIndex(t, trustedZones(), trustedNetworks())
	_, err := PlaceVNIC(context.Background(), &PlaceVNICConfig{
		Profile:   &entities.DeviceProfile{Zone: string(zone.ZoneTrusted)},
		ZoneIndex: idx,
		// PortID intentionally empty
	})
	if err == nil {
		t.Error("expected error for empty PortID")
	}
}

// TestPlaceVNIC_DeterministicSelection verifies that the same network is always
// selected regardless of the order networks appear in the ZoneIndex.
func TestPlaceVNIC_DeterministicSelection(t *testing.T) {
	// Intentionally reversed order in the config slice.
	networks := []sdn.NetworkConfig{
		{Name: "zzz", Zone: zone.ZoneTrusted, VLAN: 999, Subnet: netip.MustParsePrefix("10.9.0.0/24")},
		{Name: "aaa", Zone: zone.ZoneTrusted, VLAN: 10, Subnet: netip.MustParsePrefix("10.1.0.0/24")},
		{Name: "mmm", Zone: zone.ZoneTrusted, VLAN: 500, Subnet: netip.MustParsePrefix("10.5.0.0/24")},
	}
	idx := buildZoneIndex(t, trustedZones(), networks)

	for i := range 3 {
		portID := "tap" + itoa(i)
		placement, err := PlaceVNIC(context.Background(), &PlaceVNICConfig{
			Profile:   &entities.DeviceProfile{Zone: string(zone.ZoneTrusted)},
			ZoneIndex: idx,
			PortID:    portID,
		})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if placement.NetworkName != "aaa" {
			t.Errorf("run %d: expected 'aaa', got %q", i, placement.NetworkName)
		}
	}
}

// TestErrNoNetworkInZone_Error verifies the error message is non-empty.
func TestErrNoNetworkInZone_Error(t *testing.T) {
	e := ErrNoNetworkInZone{Zone: zone.ZoneQuarantine}
	if e.Error() == "" {
		t.Error("Error() should return non-empty string")
	}
}

// itoa is a minimal helper so the test file has no additional imports.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 4)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
