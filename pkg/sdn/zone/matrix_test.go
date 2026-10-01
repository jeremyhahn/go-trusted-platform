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

// referenceAllowed is every path the built-in zones open, from the "Routing
// and inter-zone policy" table of docs/architecture/reference-network.md.
// Every other (from, to) pair of the 9×9 matrix must be denied.
var referenceAllowed = map[[2]zone.Zone][]string{
	{zone.ZoneFabric, zone.ZoneFabric}:             {"vxlan", "bgp", "ipsec"},
	{zone.ZoneHypervisor, zone.ZoneHypervisor}:     {"migration"},
	{zone.ZoneQuarantine, zone.ZoneControlPlane}:   {"dns", "auth", "remediation"},
	{zone.ZoneProvisioning, zone.ZoneControlPlane}: {"tftp", "http", "dns", "acme"},
	{zone.ZoneControlPlane, zone.ZoneControlPlane}: nil,
	{zone.ZoneStorage, zone.ZoneStorage}:           {"storage"},
	{zone.ZoneBackup, zone.ZoneBackup}:             {"backup"},
}

// TestCompileMatrix_Reference checks every cell of the built-in matrix: the
// default between zones is deny, and management and transit reach nothing.
func TestCompileMatrix_Reference(t *testing.T) {
	m := zone.CompileMatrix(zone.Defaults())
	for _, from := range zone.Defaults() {
		for _, to := range zone.Defaults() {
			v := m.Allowed(from.Name, to.Name)
			want, open := referenceAllowed[[2]zone.Zone{from.Name, to.Name}]
			assert.Equal(t, open, v.Allowed, "%s → %s", from.Name, to.Name)
			if open {
				assert.Equal(t, want, v.Services, "%s → %s services", from.Name, to.Name)
			}
		}
	}
}

// TestCompileMatrix_IsolateFromWins verifies an IsolateFrom entry overrides
// an AllowTo path toward the same zone.
func TestCompileMatrix_IsolateFromWins(t *testing.T) {
	zones := []zone.ZoneConfig{
		{Name: "a", AllowTo: []zone.ZonePath{{Zone: "b"}}, IsolateFrom: []zone.Zone{"b"}},
		{Name: "b"},
	}
	m := zone.CompileMatrix(zones)
	assert.False(t, m.Allowed("a", "b").Allowed)
	assert.True(t, m.Allowed("a", "a").Allowed, "a non-isolated zone allows itself")
	assert.True(t, m.Allowed("b", "b").Allowed)
}

// TestMatrix_UnknownZoneDenied verifies a lookup of unknown zones is a deny.
func TestMatrix_UnknownZoneDenied(t *testing.T) {
	m := zone.CompileMatrix(zone.Defaults())
	assert.False(t, m.Allowed("nowhere", zone.ZoneFabric).Allowed)
	assert.False(t, m.Allowed(zone.ZoneFabric, "nowhere").Allowed)
}
