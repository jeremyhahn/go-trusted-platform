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
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestDefaults_ReferenceOffsets pins the built-in zones to the offsets of
// the reference network: x00 transit through x08 backup, in that order.
func TestDefaults_ReferenceOffsets(t *testing.T) {
	want := []struct {
		name   zone.Zone
		offset zone.Offset
	}{
		{zone.ZoneTransit, 0},
		{zone.ZoneFabric, 1},
		{zone.ZoneManagement, 2},
		{zone.ZoneHypervisor, 3},
		{zone.ZoneQuarantine, 4},
		{zone.ZoneProvisioning, 5},
		{zone.ZoneControlPlane, 6},
		{zone.ZoneStorage, 7},
		{zone.ZoneBackup, 8},
	}
	got := zone.Defaults()
	require.Len(t, got, len(want))
	for i, w := range want {
		assert.Equal(t, w.name, got[i].Name, "position %d", i)
		assert.Equal(t, w.offset, got[i].Offset, "zone %s", w.name)
	}
	require.NoError(t, zone.Validate(got), "the built-in set must validate on its own")
}

// TestDefaults_PortClassMembership pins the port-class model of the
// reference: transit on gateway ports only, management on BMC ports and the
// firewall uplink only, the hypervisor trunk carrying x01 and x03-x08.
func TestDefaults_PortClassMembership(t *testing.T) {
	members := func(class zone.PortClass) []zone.Zone {
		var out []zone.Zone
		for _, z := range zone.Defaults() {
			for _, c := range z.PortClasses {
				if c == class {
					out = append(out, z.Name)
				}
			}
		}
		return out
	}

	assert.Equal(t, []zone.Zone{
		zone.ZoneTransit, zone.ZoneFabric, zone.ZoneQuarantine,
		zone.ZoneProvisioning, zone.ZoneControlPlane, zone.ZoneBackup,
	}, members(zone.PortClassGateway))
	assert.Equal(t, []zone.Zone{
		zone.ZoneFabric, zone.ZoneHypervisor, zone.ZoneQuarantine,
		zone.ZoneProvisioning, zone.ZoneControlPlane, zone.ZoneStorage, zone.ZoneBackup,
	}, members(zone.PortClassHypervisor))
	assert.Equal(t, []zone.Zone{zone.ZoneManagement}, members(zone.PortClassBMC))
	assert.Equal(t, []zone.Zone{zone.ZoneManagement}, members(zone.PortClassMgmtUplink))
	assert.Empty(t, members(zone.PortClassPeerLink), "the peer-link carries every zone implicitly")
}

// TestDefaults_DeepCopy verifies that mutating the returned slice does not
// change the package defaults.
func TestDefaults_DeepCopy(t *testing.T) {
	first := zone.Defaults()
	first[1].AllowTo[0].Services[0] = "mutated"
	first[1].PortClasses[0] = "mutated"

	second := zone.Defaults()
	assert.Equal(t, "vxlan", second[1].AllowTo[0].Services[0])
	assert.Equal(t, zone.PortClassGateway, second[1].PortClasses[0])
}

// TestBuiltin covers the lookup of a built-in zone by name, for a known and
// an unknown name.
func TestBuiltin(t *testing.T) {
	b, ok := zone.Builtin(zone.ZoneStorage)
	require.True(t, ok)
	assert.Equal(t, zone.OffsetStorage, b.Offset)
	assert.True(t, zone.IsBuiltin(zone.ZoneStorage))

	_, ok = zone.Builtin("lab")
	assert.False(t, ok)
	assert.False(t, zone.IsBuiltin("trusted"), "the trusted zone is gone")
}
