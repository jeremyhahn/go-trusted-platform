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

package policy

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestValidateAdmissionZone_Allowed admits onto ordinary zones and an
// owner-defined zone.
func TestValidateAdmissionZone_Allowed(t *testing.T) {
	zones, err := zone.Resolve([]zone.ZoneConfig{{
		Name: "lab", Offset: 9, PortClasses: []zone.PortClass{zone.PortClassHypervisor}, Isolate: true,
	}})
	require.NoError(t, err)
	for _, z := range []zone.Zone{zone.ZoneStorage, zone.ZoneBackup, zone.ZoneHypervisor, "lab"} {
		assert.NoError(t, ValidateAdmissionZone(zones, z), "zone %s", z)
	}
}

// TestValidateAdmissionZone_Refused covers one refusal per rule.
func TestValidateAdmissionZone_Refused(t *testing.T) {
	tests := []struct {
		zone   zone.Zone
		reason string
	}{
		{"nowhere", admissionUndeclared},
		{zone.ZoneManagement, admissionOOB},
		{zone.ZoneTransit, admissionTransit},
		{zone.ZoneFabric, admissionFabric},
		{zone.ZoneProvisioning, admissionLifecycle},
		{zone.ZoneQuarantine, admissionLifecycle},
		{zone.ZoneControlPlane, admissionControl},
	}
	for _, tc := range tests {
		err := ValidateAdmissionZone(zone.Defaults(), tc.zone)
		var target ErrAdmissionZone
		require.True(t, errors.As(err, &target), "zone %s: got %v", tc.zone, err)
		assert.Equal(t, tc.zone, target.Zone)
		assert.Equal(t, tc.reason, target.Reason, "zone %s", tc.zone)
		assert.Contains(t, err.Error(), string(tc.zone))
	}
}

// TestValidateAdmissionZone_ControlPlaneBehindPrivilegedPath admits onto
// control-plane only when the zone set opens an audited path into it.
func TestValidateAdmissionZone_ControlPlaneBehindPrivilegedPath(t *testing.T) {
	zones, err := zone.Resolve([]zone.ZoneConfig{{
		Name: "lab", Offset: 9, PortClasses: []zone.PortClass{zone.PortClassHypervisor}, Isolate: true,
		AllowTo:          []zone.ZonePath{{Zone: zone.ZoneControlPlane, Services: []string{"api"}}},
		PrivilegedAccess: &zone.PrivilegedAccess{Reason: "ci", ApprovedBy: "owner"},
	}})
	require.NoError(t, err)
	require.NoError(t, zone.Validate(zones))
	assert.NoError(t, ValidateAdmissionZone(zones, zone.ZoneControlPlane))
}

// TestZoneFlowManager_ValidateAdmissionZone uses the configured zone set,
// and the built-ins when none is configured.
func TestZoneFlowManager_ValidateAdmissionZone(t *testing.T) {
	m := &ZoneFlowManager{}
	assert.NoError(t, m.ValidateAdmissionZone(zone.ZoneStorage))
	var target ErrAdmissionZone
	require.True(t, errors.As(m.ValidateAdmissionZone(zone.ZoneManagement), &target))

	m = &ZoneFlowManager{zones: []zone.ZoneConfig{{Name: "only"}}}
	assert.NoError(t, m.ValidateAdmissionZone("only"))
	require.True(t, errors.As(m.ValidateAdmissionZone(zone.ZoneStorage), &target), "storage is not in this zone set")
}
