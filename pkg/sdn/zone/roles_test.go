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

// TestZoneForRole_Defaults verifies that both required lifecycle roles resolve
// to the expected built-in zone names.
func TestZoneForRole_Defaults(t *testing.T) {
	t.Parallel()

	defaults := zone.Defaults()

	tests := []struct {
		role zone.LifecycleRole
		want zone.Zone
	}{
		{zone.LifecycleRoleProvisioning, zone.ZoneProvisioning},
		{zone.LifecycleRoleQuarantine, zone.ZoneQuarantine},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(string(tc.role), func(t *testing.T) {
			t.Parallel()
			got, err := zone.ZoneForRole(defaults, tc.role)
			if err != nil {
				t.Fatalf("ZoneForRole(%q): %v", tc.role, err)
			}
			if got != tc.want {
				t.Errorf("ZoneForRole(%q) = %q, want %q", tc.role, got, tc.want)
			}
		})
	}
}

// TestZoneForRole_CustomName verifies that ZoneForRole returns the custom
// zone name when the operator has renamed a lifecycle-role holder.
func TestZoneForRole_CustomName(t *testing.T) {
	t.Parallel()

	user := []zone.ZoneConfig{
		{Name: zone.ZoneProvisioning, Omit: true},
		{
			Name:          "onboarding",
			LifecycleRole: zone.LifecycleRoleProvisioning,
			Isolate:       true,
			Services:      []string{"dhcp", "tftp", "dns", "acme"},
		},
	}
	resolved, err := zone.Resolve(user)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got, err := zone.ZoneForRole(resolved, zone.LifecycleRoleProvisioning)
	if err != nil {
		t.Fatalf("ZoneForRole: %v", err)
	}
	if got != "onboarding" {
		t.Errorf("ZoneForRole = %q, want onboarding", got)
	}
}

// TestZoneForRole_NotFound verifies that ZoneForRole returns ErrNoZoneForRole
// when no zone carries the requested role.
func TestZoneForRole_NotFound(t *testing.T) {
	t.Parallel()

	empty := []zone.ZoneConfig{
		{Name: "generic"},
	}
	_, err := zone.ZoneForRole(empty, zone.LifecycleRoleQuarantine)
	var target zone.ErrNoZoneForRole
	if !errors.As(err, &target) {
		t.Errorf("want ErrNoZoneForRole, got %T: %v", err, err)
	}
	if target.Role != zone.LifecycleRoleQuarantine {
		t.Errorf("ErrNoZoneForRole.Role = %q, want quarantine", target.Role)
	}
}
