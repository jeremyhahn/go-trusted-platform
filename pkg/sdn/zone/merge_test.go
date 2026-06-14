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

// TestResolve_EmptyUser verifies that resolving an empty user list returns all
// seven built-ins unchanged.
func TestResolve_EmptyUser(t *testing.T) {
	t.Parallel()

	resolved, err := zone.Resolve(nil)
	if err != nil {
		t.Fatalf("Resolve(nil): %v", err)
	}
	defaults := zone.Defaults()
	if len(resolved) != len(defaults) {
		t.Fatalf("Resolve(nil): len = %d, want %d", len(resolved), len(defaults))
	}
	for i, d := range defaults {
		if resolved[i].Name != d.Name {
			t.Errorf("[%d] name = %q, want %q", i, resolved[i].Name, d.Name)
		}
	}
}

// TestResolve_OverrideBuiltin verifies that a user entry with a built-in name
// fully replaces the built-in.
func TestResolve_OverrideBuiltin(t *testing.T) {
	t.Parallel()

	override := zone.ZoneConfig{
		Name:            zone.ZoneTrusted,
		InternetIngress: true, // deliberate change to verify replacement
	}
	resolved, err := zone.Resolve([]zone.ZoneConfig{override})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var found zone.ZoneConfig
	for _, z := range resolved {
		if z.Name == zone.ZoneTrusted {
			found = z
			break
		}
	}
	if !found.InternetIngress {
		t.Errorf("overridden trusted zone should have InternetIngress=true")
	}
}

// TestResolve_AddNewZone verifies that a user entry with a novel name is
// appended after the built-ins.
func TestResolve_AddNewZone(t *testing.T) {
	t.Parallel()

	user := zone.ZoneConfig{Name: "labs"}
	resolved, err := zone.Resolve([]zone.ZoneConfig{user})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resolved) != len(zone.Defaults())+1 {
		t.Fatalf("len = %d, want %d", len(resolved), len(zone.Defaults())+1)
	}
	last := resolved[len(resolved)-1]
	if last.Name != "labs" {
		t.Errorf("last zone = %q, want labs", last.Name)
	}
}

// TestResolve_OmitNoLifecycleRole verifies that omitting a built-in with no
// lifecycle role succeeds.
func TestResolve_OmitNoLifecycleRole(t *testing.T) {
	t.Parallel()

	omit := zone.ZoneConfig{Name: zone.ZoneStorage, Omit: true}
	resolved, err := zone.Resolve([]zone.ZoneConfig{omit})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, z := range resolved {
		if z.Name == zone.ZoneStorage {
			t.Errorf("storage should have been omitted from resolved set")
		}
	}
}

// TestResolve_OmitLifecycleHolderWithReplacement verifies that omitting a
// lifecycle-role holder succeeds when another user zone takes that role.
func TestResolve_OmitLifecycleHolderWithReplacement(t *testing.T) {
	t.Parallel()

	user := []zone.ZoneConfig{
		{Name: zone.ZoneProvisioning, Omit: true},
		{Name: "onboarding", LifecycleRole: zone.LifecycleRoleProvisioning, Isolate: true,
			Services: []string{"dhcp", "tftp", "dns", "acme"},
		},
	}
	_, err := zone.Resolve(user)
	if err != nil {
		t.Errorf("Resolve: unexpected error: %v", err)
	}
}

// TestResolve_OmitLifecycleHolderWithoutReplacement verifies that omitting a
// lifecycle-role holder without providing a replacement returns
// ErrOmitLifecycleHolder.
func TestResolve_OmitLifecycleHolderWithoutReplacement(t *testing.T) {
	t.Parallel()

	user := []zone.ZoneConfig{
		{Name: zone.ZoneProvisioning, Omit: true},
	}
	_, err := zone.Resolve(user)
	var target zone.ErrOmitLifecycleHolder
	if !errors.As(err, &target) {
		t.Errorf("want ErrOmitLifecycleHolder, got %T: %v", err, err)
	}
	if target.Zone != zone.ZoneProvisioning {
		t.Errorf("ErrOmitLifecycleHolder.Zone = %q, want provisioning", target.Zone)
	}
	if target.Role != zone.LifecycleRoleProvisioning {
		t.Errorf("ErrOmitLifecycleHolder.Role = %q, want provisioning", target.Role)
	}
}

// TestResolve_OmitNonBuiltin verifies that an Omit entry for a non-built-in
// name is silently ignored (no entry added, no error).
func TestResolve_OmitNonBuiltin(t *testing.T) {
	t.Parallel()

	user := []zone.ZoneConfig{
		{Name: "imaginary", Omit: true},
	}
	resolved, err := zone.Resolve(user)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resolved) != len(zone.Defaults()) {
		t.Errorf("len = %d, want %d (omit of non-builtin should be no-op)",
			len(resolved), len(zone.Defaults()))
	}
}

// TestResolve_MutationDoesNotAffectBuiltins verifies that mutating returned
// configs does not alter subsequent calls to Defaults().
func TestResolve_MutationDoesNotAffectBuiltins(t *testing.T) {
	t.Parallel()

	resolved, _ := zone.Resolve(nil)
	for i := range resolved {
		resolved[i].InternetIngress = true
		resolved[i].Services = append(resolved[i].Services, "injected")
	}
	defaults := zone.Defaults()
	for _, d := range defaults {
		if d.Name == zone.ZoneTrusted && d.InternetIngress {
			t.Errorf("mutation of resolved slice polluted Defaults()")
		}
	}
}
