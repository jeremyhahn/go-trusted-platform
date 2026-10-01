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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestErrorMessages checks that every typed error names its origin and the
// values an operator needs to fix the configuration.
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		err  error
		want []string
	}{
		{zone.ErrDuplicateZone{Name: "lab"}, []string{"zone:", `"lab"`}},
		{zone.ErrEmptyZoneName{}, []string{"zone:", "empty"}},
		{zone.ErrInvalidZoneName{Name: "Lab"}, []string{"zone:", `"Lab"`}},
		{zone.ErrLifecycleRoleCount{Role: zone.LifecycleRoleQuarantine, Count: 2}, []string{"quarantine", "2"}},
		{zone.ErrInvalidLifecycleRole{Zone: "lab", Role: "x"}, []string{`"lab"`, `"x"`}},
		{zone.ErrUnknownZoneRef{Source: "lab", Field: "allow_to", Target: "nowhere"}, []string{"allow_to", `"nowhere"`}},
		{zone.ErrOOBWithInternetIngress{Zone: "management"}, []string{"oob", "internet_ingress"}},
		{zone.ErrOOBAllowTo{Zone: zone.ZoneManagement, To: zone.ZoneStorage}, []string{`"management"`, `"storage"`}},
		{zone.ErrOmitRequired{Zone: zone.ZoneFabric}, []string{`"fabric"`, "required"}},
		{zone.ErrOmitUnknown{Zone: "lab"}, []string{`"lab"`, "built-in"}},
		{zone.ErrBuiltinIdentity{Zone: zone.ZoneStorage, Field: "offset"}, []string{`"storage"`, "offset"}},
		{zone.ErrReservedZoneName{Name: "public"}, []string{`"public"`, "overlays are not zones"}},
		{zone.ErrDuplicateOffset{Offset: 9, Zones: [2]zone.Zone{"a", "b"}}, []string{`"a"`, `"b"`, "09"}},
		{zone.ErrOwnerZoneOffset{Zone: "lab", Offset: 3}, []string{`"lab"`, "09-99", "03"}},
		{zone.ErrOwnerZonePortClass{Zone: "lab"}, []string{`"lab"`, "must join"}},
		{zone.ErrOwnerZonePortClass{Zone: "lab", Class: zone.PortClassBMC}, []string{`"lab"`, `"bmc"`}},
		{zone.ErrOwnerZoneField{Zone: "lab", Field: "oob"}, []string{`"lab"`, "oob"}},
		{zone.ErrPrivilegedAccessRequired{Zone: "lab", To: zone.ZoneControlPlane}, []string{`"lab"`, `"control-plane"`, "privileged_access"}},
		{zone.ErrNoZoneForRole{Role: zone.LifecycleRoleProvisioning}, []string{"provisioning"}},
	}
	for _, tc := range tests {
		msg := tc.err.Error()
		for _, w := range tc.want {
			assert.Contains(t, msg, w, "%T", tc.err)
		}
	}
}
