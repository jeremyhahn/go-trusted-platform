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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

func indexOf(t *testing.T, zones []zone.ZoneConfig, name zone.Zone) zone.ZoneConfig {
	t.Helper()
	for _, z := range zones {
		if z.Name == name {
			return z
		}
	}
	t.Fatalf("zone %q not in resolved set", name)
	return zone.ZoneConfig{}
}

// TestResolve_NoUserEntries returns exactly the built-ins.
func TestResolve_NoUserEntries(t *testing.T) {
	got, err := zone.Resolve(nil)
	require.NoError(t, err)
	assert.Equal(t, zone.Defaults(), got)
}

// TestResolve_TunesBuiltinPolicyKeepsIdentity verifies that an operator entry
// replaces a built-in's policy but keeps its offset, port classes and role.
func TestResolve_TunesBuiltinPolicyKeepsIdentity(t *testing.T) {
	got, err := zone.Resolve([]zone.ZoneConfig{{
		Name:     zone.ZoneProvisioning,
		Isolate:  true,
		Services: []string{"dhcp"},
		AllowTo:  []zone.ZonePath{{Zone: zone.ZoneControlPlane, Services: []string{"dns"}}},
	}})
	require.NoError(t, err)

	p := indexOf(t, got, zone.ZoneProvisioning)
	assert.Equal(t, zone.OffsetProvisioning, p.Offset)
	assert.Equal(t, zone.LifecycleRoleProvisioning, p.LifecycleRole)
	assert.ElementsMatch(t, []zone.PortClass{zone.PortClassGateway, zone.PortClassHypervisor}, p.PortClasses)
	assert.Equal(t, []string{"dhcp"}, p.Services)
	assert.Equal(t, []string{"dns"}, p.AllowTo[0].Services)
	require.NoError(t, zone.Validate(got))
}

// TestResolve_BuiltinIdentityIsFixed verifies that an operator entry cannot
// renumber, re-class, re-role or re-flag a built-in zone.
func TestResolve_BuiltinIdentityIsFixed(t *testing.T) {
	tests := []struct {
		name  string
		entry zone.ZoneConfig
		field string
	}{
		{"offset", zone.ZoneConfig{Name: zone.ZoneStorage, Offset: 20}, "offset"},
		{"port classes", zone.ZoneConfig{Name: zone.ZoneTransit, PortClasses: []zone.PortClass{zone.PortClassHypervisor}}, "port_classes"},
		{"lifecycle role", zone.ZoneConfig{Name: zone.ZoneStorage, LifecycleRole: zone.LifecycleRoleQuarantine}, "lifecycle_role"},
		{"oob", zone.ZoneConfig{Name: zone.ZoneBackup, OOB: true}, "oob"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := zone.Resolve([]zone.ZoneConfig{tc.entry})
			var target zone.ErrBuiltinIdentity
			require.True(t, errors.As(err, &target), "got %v", err)
			assert.Equal(t, tc.field, target.Field)
			assert.Equal(t, tc.entry.Name, target.Zone)
		})
	}
}

// TestResolve_RepeatingIdentityIsAllowed verifies that an entry may restate
// a built-in's own offset and port classes (in any order).
func TestResolve_RepeatingIdentityIsAllowed(t *testing.T) {
	_, err := zone.Resolve([]zone.ZoneConfig{{
		Name:        zone.ZoneFabric,
		Offset:      zone.OffsetFabric,
		PortClasses: []zone.PortClass{zone.PortClassHypervisor, zone.PortClassGateway},
	}})
	require.NoError(t, err)
}

// TestResolve_Omit covers omitting an optional built-in, refusing to omit a
// required one, and refusing omit on a name that is not built in.
func TestResolve_Omit(t *testing.T) {
	got, err := zone.Resolve([]zone.ZoneConfig{{Name: zone.ZoneBackup, Omit: true}})
	require.NoError(t, err)
	for _, z := range got {
		assert.NotEqual(t, zone.ZoneBackup, z.Name)
	}

	for _, required := range []zone.Zone{zone.ZoneFabric, zone.ZoneProvisioning, zone.ZoneQuarantine, zone.ZoneControlPlane} {
		_, err := zone.Resolve([]zone.ZoneConfig{{Name: required, Omit: true}})
		var target zone.ErrOmitRequired
		require.True(t, errors.As(err, &target), "omit %s: got %v", required, err)
		assert.Equal(t, required, target.Zone)
	}

	_, err = zone.Resolve([]zone.ZoneConfig{{Name: "lab", Omit: true}})
	var unknown zone.ErrOmitUnknown
	require.True(t, errors.As(err, &unknown), "got %v", err)
}

// TestResolve_OwnerZonesAppendedInOffsetOrder verifies owner-defined zones
// follow the built-ins, sorted by offset.
func TestResolve_OwnerZonesAppendedInOffsetOrder(t *testing.T) {
	got, err := zone.Resolve([]zone.ZoneConfig{
		{Name: "lab-b", Offset: 12, PortClasses: []zone.PortClass{zone.PortClassHypervisor}},
		{Name: "lab-a", Offset: 9, PortClasses: []zone.PortClass{zone.PortClassGateway}},
	})
	require.NoError(t, err)
	require.Len(t, got, 11)
	assert.Equal(t, zone.Zone("lab-a"), got[9].Name)
	assert.Equal(t, zone.Zone("lab-b"), got[10].Name)
	require.NoError(t, zone.Validate(got))
}

// TestResolve_DuplicateEntry refuses two operator entries with one name.
func TestResolve_DuplicateEntry(t *testing.T) {
	_, err := zone.Resolve([]zone.ZoneConfig{{Name: zone.ZoneStorage}, {Name: zone.ZoneStorage}})
	var target zone.ErrDuplicateZone
	require.True(t, errors.As(err, &target), "got %v", err)
	assert.Equal(t, zone.ZoneStorage, target.Name)
}
