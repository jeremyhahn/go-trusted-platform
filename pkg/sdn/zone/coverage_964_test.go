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

package zone

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defaultsWith returns the reference set with the named built-in changed by
// mutate.
func defaultsWith(t *testing.T, name Zone, mutate func(*ZoneConfig)) []ZoneConfig {
	t.Helper()
	set := Defaults()
	for i := range set {
		if set[i].Name == name {
			mutate(&set[i])
			return set
		}
	}
	require.FailNow(t, "built-in not in the reference set", "zone %s", name)
	return nil
}

// TestValidate_BuiltinIdentityFields covers each identity field the guard
// keeps for a hand-built set, and accepts port classes in another order.
func TestValidate_BuiltinIdentityFields(t *testing.T) {
	tests := []struct {
		name   string
		zone   Zone
		mutate func(*ZoneConfig)
		field  string
	}{
		{
			name: "port classes changed, same count",
			zone: ZoneFabric,
			mutate: func(z *ZoneConfig) {
				z.PortClasses = []PortClass{PortClassHypervisor, PortClassHypervisor}
			},
			field: "port_classes",
		},
		{
			name:   "port classes dropped",
			zone:   ZoneFabric,
			mutate: func(z *ZoneConfig) { z.PortClasses = []PortClass{PortClassGateway} },
			field:  "port_classes",
		},
		{
			name:   "lifecycle role cleared",
			zone:   ZoneQuarantine,
			mutate: func(z *ZoneConfig) { z.LifecycleRole = "" },
			field:  "lifecycle_role",
		},
		{
			name:   "oob cleared",
			zone:   ZoneManagement,
			mutate: func(z *ZoneConfig) { z.OOB = false },
			field:  "oob",
		},
		{
			name: "port classes reordered",
			zone: ZoneFabric,
			mutate: func(z *ZoneConfig) {
				z.PortClasses = []PortClass{PortClassHypervisor, PortClassGateway}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(defaultsWith(t, tt.zone, tt.mutate))
			if tt.field == "" {
				require.NoError(t, err)
				return
			}
			var target ErrBuiltinIdentity
			require.True(t, errors.As(err, &target), "got %v", err)
			assert.Equal(t, tt.zone, target.Zone)
			assert.Equal(t, tt.field, target.Field)
		})
	}
}

// TestValidate_DuplicateZone refuses a set that declares a zone twice.
func TestValidate_DuplicateZone(t *testing.T) {
	set := Defaults()
	set = append(set, set[0])
	var target ErrDuplicateZone
	require.True(t, errors.As(Validate(set), &target))
	assert.Equal(t, set[0].Name, target.Name)
}

// TestCoveredBy decides whether a path stays within a built-in's reference
// paths.
func TestCoveredBy(t *testing.T) {
	defaults := []ZonePath{
		{Zone: ZoneControlPlane, Services: []string{"dns", "auth"}},
		{Zone: ZoneControlPlane, Services: []string{"remediation"}},
		{Zone: ZoneStorage},
	}
	tests := []struct {
		name string
		path ZonePath
		want bool
	}{
		{"no default for the zone", ZonePath{Zone: ZoneManagement}, false},
		{"unrestricted default", ZonePath{Zone: ZoneStorage, Services: []string{"any"}}, true},
		{"all services under a restricted default", ZonePath{Zone: ZoneControlPlane}, false},
		{"subset of the first default", ZonePath{Zone: ZoneControlPlane, Services: []string{"dns"}}, true},
		{"subset of a later default", ZonePath{Zone: ZoneControlPlane, Services: []string{"remediation"}}, true},
		{"spans two defaults", ZonePath{Zone: ZoneControlPlane, Services: []string{"dns", "remediation"}}, false},
		{"service outside every default", ZonePath{Zone: ZoneControlPlane, Services: []string{"ssh"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, coveredBy(tt.path, defaults))
		})
	}
	assert.False(t, coveredBy(ZonePath{Zone: ZoneStorage}, nil), "no defaults cover nothing")
}

// TestIsDNSLabelSafe accepts lowercase RFC 1123 labels only.
func TestIsDNSLabelSafe(t *testing.T) {
	tests := []struct {
		label string
		want  bool
	}{
		{"", false},
		{"lab", true},
		{"lab-2", true},
		{"-lab", false},
		{"lab-", false},
		{"la_b", false},
		{"Lab", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, isDNSLabelSafe(tt.label), "label %q", tt.label)
	}
}

// TestSamePortClasses compares port classes as multisets.
func TestSamePortClasses(t *testing.T) {
	tests := []struct {
		name string
		a, b []PortClass
		want bool
	}{
		{"both empty", nil, nil, true},
		{"reordered", []PortClass{PortClassGateway, PortClassHypervisor}, []PortClass{PortClassHypervisor, PortClassGateway}, true},
		{"different length", []PortClass{PortClassGateway}, []PortClass{PortClassGateway, PortClassHypervisor}, false},
		{"same length, different classes", []PortClass{PortClassGateway, PortClassGateway}, []PortClass{PortClassGateway, PortClassHypervisor}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, samePortClasses(tt.a, tt.b))
		})
	}
}
