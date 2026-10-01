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

// resolveAndValidate resolves user entries onto the built-ins and validates
// the result.
func resolveAndValidate(user ...zone.ZoneConfig) error {
	resolved, err := zone.Resolve(user)
	if err != nil {
		return err
	}
	return zone.Validate(resolved)
}

func lab(offset zone.Offset, classes ...zone.PortClass) zone.ZoneConfig {
	return zone.ZoneConfig{Name: "lab", Offset: offset, PortClasses: classes, Isolate: true}
}

// TestValidate_OwnerZone covers a valid owner-defined zone at both ends of
// the owner range.
func TestValidate_OwnerZone(t *testing.T) {
	require.NoError(t, resolveAndValidate(lab(zone.MinOwnerOffset, zone.PortClassHypervisor)))
	require.NoError(t, resolveAndValidate(lab(zone.MaxOffset, zone.PortClassGateway, zone.PortClassHypervisor)))
}

// TestValidate_OwnerZoneOffset refuses an owner zone outside 9-99, including
// one that leaves the offset unset.
func TestValidate_OwnerZoneOffset(t *testing.T) {
	for _, off := range []zone.Offset{0, 8, 100} {
		err := resolveAndValidate(lab(off, zone.PortClassHypervisor))
		var target zone.ErrOwnerZoneOffset
		require.True(t, errors.As(err, &target), "offset %d: got %v", off, err)
		assert.Equal(t, off, target.Offset)
	}
}

// TestValidate_DuplicateOffset refuses two owner zones on one offset.
func TestValidate_DuplicateOffset(t *testing.T) {
	a := lab(20, zone.PortClassHypervisor)
	b := lab(20, zone.PortClassHypervisor)
	b.Name = "lab2"
	err := resolveAndValidate(a, b)
	var target zone.ErrDuplicateOffset
	require.True(t, errors.As(err, &target), "got %v", err)
	assert.Equal(t, zone.Offset(20), target.Offset)
}

// TestValidate_OwnerZonePortClass refuses an owner zone with no port class
// or with a management-only class.
func TestValidate_OwnerZonePortClass(t *testing.T) {
	var target zone.ErrOwnerZonePortClass

	err := resolveAndValidate(lab(10))
	require.True(t, errors.As(err, &target), "got %v", err)
	assert.Empty(t, target.Class)
	assert.Contains(t, err.Error(), "must join")

	err = resolveAndValidate(lab(10, zone.PortClassBMC))
	require.True(t, errors.As(err, &target), "got %v", err)
	assert.Equal(t, zone.PortClassBMC, target.Class)
	assert.Contains(t, err.Error(), "cannot join")
}

// TestValidate_OwnerZoneBuiltinOnlyFields refuses a lifecycle role or OOB on
// an owner zone.
func TestValidate_OwnerZoneBuiltinOnlyFields(t *testing.T) {
	withRole := lab(10, zone.PortClassHypervisor)
	withRole.LifecycleRole = zone.LifecycleRoleQuarantine
	var target zone.ErrOwnerZoneField
	require.True(t, errors.As(resolveAndValidate(withRole), &target))
	assert.Equal(t, "lifecycle_role", target.Field)

	withOOB := lab(10, zone.PortClassHypervisor)
	withOOB.OOB = true
	require.True(t, errors.As(resolveAndValidate(withOOB), &target))
	assert.Equal(t, "oob", target.Field)
}

// TestValidate_ReservedNames refuses overlay kinds and the retired trusted
// zone as zone names.
func TestValidate_ReservedNames(t *testing.T) {
	for _, name := range []zone.Zone{"platform", "tenant", "public", "trusted"} {
		z := lab(10, zone.PortClassHypervisor)
		z.Name = name
		var target zone.ErrReservedZoneName
		require.True(t, errors.As(resolveAndValidate(z), &target), "name %s", name)
		assert.Equal(t, name, target.Name)
	}
}

// TestValidate_Names refuses empty and non-DNS-label names.
func TestValidate_Names(t *testing.T) {
	var empty zone.ErrEmptyZoneName
	require.True(t, errors.As(zone.Validate([]zone.ZoneConfig{{}}), &empty))

	for _, name := range []zone.Zone{"Lab", "-lab", "lab-", "la_b"} {
		var target zone.ErrInvalidZoneName
		require.True(t, errors.As(zone.Validate([]zone.ZoneConfig{{Name: name}}), &target), "name %q", name)
	}
}

// TestValidate_BuiltinIdentityGuard catches a resolved set whose built-in
// was changed after Resolve (the guard Validate keeps for hand-built sets).
func TestValidate_BuiltinIdentityGuard(t *testing.T) {
	set := zone.Defaults()
	set[7].Offset = 30 // storage
	var target zone.ErrBuiltinIdentity
	require.True(t, errors.As(zone.Validate(set), &target))
	assert.Equal(t, "offset", target.Field)
}

// TestValidate_LifecycleRoles requires exactly one holder per role.
func TestValidate_LifecycleRoles(t *testing.T) {
	set := zone.Defaults()
	set[4].LifecycleRole = "" // quarantine
	set[4].Name = "q2"
	set[4].Offset = 40
	set[4].PortClasses = []zone.PortClass{zone.PortClassHypervisor}
	var count zone.ErrLifecycleRoleCount
	require.True(t, errors.As(zone.Validate(set), &count))
	assert.Equal(t, zone.LifecycleRoleQuarantine, count.Role)
	assert.Equal(t, 0, count.Count)
}

// TestValidate_References refuses allow_to and isolate_from entries that
// name undeclared zones.
func TestValidate_References(t *testing.T) {
	z := lab(10, zone.PortClassHypervisor)
	z.AllowTo = []zone.ZonePath{{Zone: "nowhere"}}
	var target zone.ErrUnknownZoneRef
	require.True(t, errors.As(resolveAndValidate(z), &target))
	assert.Equal(t, "allow_to", target.Field)

	z = lab(10, zone.PortClassHypervisor)
	z.IsolateFrom = []zone.Zone{"nowhere"}
	require.True(t, errors.As(resolveAndValidate(z), &target))
	assert.Equal(t, "isolate_from", target.Field)
}

// TestValidate_OOBWithInternetIngress refuses management with ingress.
func TestValidate_OOBWithInternetIngress(t *testing.T) {
	err := resolveAndValidate(zone.ZoneConfig{Name: zone.ZoneManagement, InternetIngress: true, Isolate: true})
	var target zone.ErrOOBWithInternetIngress
	require.True(t, errors.As(err, &target), "got %v", err)
}

// TestValidate_PrivilegedAccess covers the audited override for paths into
// control-plane and management.
func TestValidate_PrivilegedAccess(t *testing.T) {
	toCP := lab(10, zone.PortClassHypervisor)
	toCP.AllowTo = []zone.ZonePath{{Zone: zone.ZoneControlPlane, Services: []string{"api"}}}

	var target zone.ErrPrivilegedAccessRequired
	require.True(t, errors.As(resolveAndValidate(toCP), &target))
	assert.Equal(t, zone.ZoneControlPlane, target.To)

	toCP.PrivilegedAccess = &zone.PrivilegedAccess{Reason: "lab CI runner reaches the API"}
	require.True(t, errors.As(resolveAndValidate(toCP), &target), "approved_by is required too")

	toCP.PrivilegedAccess.ApprovedBy = "owner"
	require.NoError(t, resolveAndValidate(toCP))

	toMgmt := lab(10, zone.PortClassHypervisor)
	toMgmt.AllowTo = []zone.ZonePath{{Zone: zone.ZoneManagement}}
	require.True(t, errors.As(resolveAndValidate(toMgmt), &target))
	assert.Equal(t, zone.ZoneManagement, target.To)
}

// TestValidate_PrivilegedAccessOnBuiltins verifies that the reference paths
// of provisioning and quarantine need no override, a narrower restatement
// needs none, and widening them does.
func TestValidate_PrivilegedAccessOnBuiltins(t *testing.T) {
	narrower := zone.ZoneConfig{
		Name:    zone.ZoneProvisioning,
		Isolate: true,
		AllowTo: []zone.ZonePath{{Zone: zone.ZoneControlPlane, Services: []string{"dns"}}},
	}
	require.NoError(t, resolveAndValidate(narrower))

	wider := narrower
	wider.AllowTo = []zone.ZonePath{{Zone: zone.ZoneControlPlane}}
	var target zone.ErrPrivilegedAccessRequired
	require.True(t, errors.As(resolveAndValidate(wider), &target))
	assert.Equal(t, zone.ZoneProvisioning, target.Zone)

	extraService := narrower
	extraService.AllowTo = []zone.ZonePath{{Zone: zone.ZoneControlPlane, Services: []string{"dns", "ssh"}}}
	require.True(t, errors.As(resolveAndValidate(extraService), &target))
}

// TestPrivilegedPaths lists the audited paths of a validated set and none
// for the reference defaults.
func TestPrivilegedPaths(t *testing.T) {
	assert.Empty(t, zone.PrivilegedPaths(zone.Defaults()))

	z := lab(10, zone.PortClassHypervisor)
	z.AllowTo = []zone.ZonePath{
		{Zone: zone.ZoneControlPlane, Services: []string{"api"}},
		{Zone: zone.ZoneStorage},
	}
	z.PrivilegedAccess = &zone.PrivilegedAccess{Reason: "ci", ApprovedBy: "owner"}
	resolved, err := zone.Resolve([]zone.ZoneConfig{z})
	require.NoError(t, err)
	require.NoError(t, zone.Validate(resolved))

	paths := zone.PrivilegedPaths(resolved)
	require.Len(t, paths, 1)
	assert.Equal(t, zone.Zone("lab"), paths[0].From)
	assert.Equal(t, zone.ZoneControlPlane, paths[0].To)
	assert.Equal(t, []string{"api"}, paths[0].Services)
	assert.Equal(t, "owner", paths[0].Access.ApprovedBy)
}

// TestValidate_OOBReachesNothing refuses a tuned management zone that opens
// a path to another zone, and accepts one that only allows itself.
func TestValidate_OOBReachesNothing(t *testing.T) {
	err := resolveAndValidate(zone.ZoneConfig{
		Name: zone.ZoneManagement, Isolate: true,
		AllowTo: []zone.ZonePath{{Zone: zone.ZoneStorage}},
	})
	var target zone.ErrOOBAllowTo
	require.True(t, errors.As(err, &target), "got %v", err)
	assert.Equal(t, zone.ZoneStorage, target.To)

	require.NoError(t, resolveAndValidate(zone.ZoneConfig{
		Name: zone.ZoneManagement, Isolate: true,
		AllowTo: []zone.ZonePath{{Zone: zone.ZoneManagement}},
	}))
}
