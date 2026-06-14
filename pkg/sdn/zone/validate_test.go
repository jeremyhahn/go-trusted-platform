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

package zone_test

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

func TestValidate_DefaultsPass(t *testing.T) {
	t.Parallel()

	if err := zone.Validate(zone.Defaults()); err != nil {
		t.Errorf("Validate(Defaults()): unexpected error: %v", err)
	}
}

func TestValidate_EmptyName(t *testing.T) {
	t.Parallel()

	zones := zone.Defaults()
	zones = append(zones, zone.ZoneConfig{Name: ""})
	err := zone.Validate(zones)
	var target zone.ErrEmptyZoneName
	if !errors.As(err, &target) {
		t.Errorf("want ErrEmptyZoneName, got %T: %v", err, err)
	}
}

func TestValidate_InvalidName(t *testing.T) {
	t.Parallel()

	zones := zone.Defaults()
	zones = append(zones, zone.ZoneConfig{Name: "Invalid_Zone"})
	err := zone.Validate(zones)
	var target zone.ErrInvalidZoneName
	if !errors.As(err, &target) {
		t.Errorf("want ErrInvalidZoneName, got %T: %v", err, err)
	}
}

func TestValidate_NameStartsWithHyphen(t *testing.T) {
	t.Parallel()

	zones := zone.Defaults()
	zones = append(zones, zone.ZoneConfig{Name: "-bad"})
	err := zone.Validate(zones)
	var target zone.ErrInvalidZoneName
	if !errors.As(err, &target) {
		t.Errorf("want ErrInvalidZoneName, got %T: %v", err, err)
	}
}

func TestValidate_DuplicateZone(t *testing.T) {
	t.Parallel()

	zones := zone.Defaults()
	// append a second trusted entry
	zones = append(zones, zone.ZoneConfig{Name: zone.ZoneTrusted})
	err := zone.Validate(zones)
	var target zone.ErrDuplicateZone
	if !errors.As(err, &target) {
		t.Errorf("want ErrDuplicateZone, got %T: %v", err, err)
	}
	if target.Name != zone.ZoneTrusted {
		t.Errorf("ErrDuplicateZone.Name = %q, want %q", target.Name, zone.ZoneTrusted)
	}
}

func TestValidate_NoProvisioningRole(t *testing.T) {
	t.Parallel()

	// Replace the provisioning zone with one that has no lifecycle role.
	var zones []zone.ZoneConfig
	for _, z := range zone.Defaults() {
		if z.Name == zone.ZoneProvisioning {
			z.LifecycleRole = ""
		}
		zones = append(zones, z)
	}
	err := zone.Validate(zones)
	var target zone.ErrLifecycleRoleCount
	if !errors.As(err, &target) {
		t.Errorf("want ErrLifecycleRoleCount, got %T: %v", err, err)
	}
	if target.Role != zone.LifecycleRoleProvisioning {
		t.Errorf("ErrLifecycleRoleCount.Role = %q, want provisioning", target.Role)
	}
}

func TestValidate_TwoProvisioningRoles(t *testing.T) {
	t.Parallel()

	zones := zone.Defaults()
	zones = append(zones, zone.ZoneConfig{
		Name:          "extra-provisioning",
		LifecycleRole: zone.LifecycleRoleProvisioning,
	})
	err := zone.Validate(zones)
	var target zone.ErrLifecycleRoleCount
	if !errors.As(err, &target) {
		t.Errorf("want ErrLifecycleRoleCount, got %T: %v", err, err)
	}
	if target.Count != 2 {
		t.Errorf("ErrLifecycleRoleCount.Count = %d, want 2", target.Count)
	}
}

func TestValidate_UnknownRoleValue(t *testing.T) {
	t.Parallel()

	zones := zone.Defaults()
	zones = append(zones, zone.ZoneConfig{
		Name:          "weird",
		LifecycleRole: "unknown-role",
	})
	err := zone.Validate(zones)
	var target zone.ErrInvalidLifecycleRole
	if !errors.As(err, &target) {
		t.Errorf("want ErrInvalidLifecycleRole, got %T: %v", err, err)
	}
}

func TestValidate_UnknownIsolateFromRef(t *testing.T) {
	t.Parallel()

	var zones []zone.ZoneConfig
	for _, z := range zone.Defaults() {
		if z.Name == zone.ZoneTrusted {
			z.IsolateFrom = append(z.IsolateFrom, "ghost")
		}
		zones = append(zones, z)
	}
	err := zone.Validate(zones)
	var target zone.ErrUnknownZoneRef
	if !errors.As(err, &target) {
		t.Errorf("want ErrUnknownZoneRef, got %T: %v", err, err)
	}
	if target.Field != "isolate_from" {
		t.Errorf("ErrUnknownZoneRef.Field = %q, want isolate_from", target.Field)
	}
	if target.Target != "ghost" {
		t.Errorf("ErrUnknownZoneRef.Target = %q, want ghost", target.Target)
	}
}

func TestValidate_UnknownAllowToRef(t *testing.T) {
	t.Parallel()

	var zones []zone.ZoneConfig
	for _, z := range zone.Defaults() {
		if z.Name == zone.ZoneStorage {
			z.AllowTo = append(z.AllowTo, zone.ZonePath{Zone: "phantom"})
		}
		zones = append(zones, z)
	}
	err := zone.Validate(zones)
	var target zone.ErrUnknownZoneRef
	if !errors.As(err, &target) {
		t.Errorf("want ErrUnknownZoneRef, got %T: %v", err, err)
	}
	if target.Field != "allow_to" {
		t.Errorf("ErrUnknownZoneRef.Field = %q, want allow_to", target.Field)
	}
}

func TestValidate_OOBWithInternetIngress(t *testing.T) {
	t.Parallel()

	var zones []zone.ZoneConfig
	for _, z := range zone.Defaults() {
		if z.Name == zone.ZoneManagement {
			z.InternetIngress = true
		}
		zones = append(zones, z)
	}
	err := zone.Validate(zones)
	var target zone.ErrOOBWithInternetIngress
	if !errors.As(err, &target) {
		t.Errorf("want ErrOOBWithInternetIngress, got %T: %v", err, err)
	}
}

func TestValidate_UserAddedZone(t *testing.T) {
	t.Parallel()

	// A user-added zone with valid name and no lifecycle role must pass.
	resolved, err := zone.Resolve([]zone.ZoneConfig{
		{Name: "dmz"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := zone.Validate(resolved); err != nil {
		t.Errorf("Validate with user-added zone: unexpected error: %v", err)
	}
}
