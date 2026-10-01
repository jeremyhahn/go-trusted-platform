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

package netplan_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestEnvironment_Validate accepts the reference shapes at both edges.
func TestEnvironment_Validate(t *testing.T) {
	for _, env := range []netplan.Environment{
		{ID: netplan.MinEnvironment},
		{ID: netplan.MaxEnvironment},
		{ID: 4, Base: base, ULA: ula},
		{ID: 4, Overrides: []netplan.Override{{Zone: zone.ZoneFabric, VLAN: 3001}}},
	} {
		require.NoError(t, env.Validate(), "%+v", env)
	}
	assert.Equal(t, netplan.DefaultBase, netplan.Environment{ID: 4}.EffectiveBase())
}

// TestEnvironment_Validate_Errors refuses every malformed field.
func TestEnvironment_Validate_Errors(t *testing.T) {
	var envErr netplan.ErrEnvironmentID
	require.True(t, errors.As(netplan.Environment{ID: 1}.Validate(), &envErr))
	require.True(t, errors.As(netplan.Environment{}.Validate(), &envErr), "the environment number is required")

	var baseErr netplan.ErrBase
	require.True(t, errors.As(netplan.Environment{ID: 4, Base: netip.MustParsePrefix("10.0.0.0/12")}.Validate(), &baseErr))

	var ulaErr netplan.ErrULA
	require.True(t, errors.As(netplan.Environment{ID: 4, ULA: netip.MustParsePrefix("fc00:1:2::/48")}.Validate(), &ulaErr),
		"fc00::/8 is not locally assigned")

	overrides := []struct {
		o      netplan.Override
		reason string
	}{
		{netplan.Override{VLAN: 10}, "zone is required"},
		{netplan.Override{Zone: zone.ZoneFabric}, "overrides nothing"},
		{netplan.Override{Zone: zone.ZoneFabric, VLAN: 4095}, "1-4094"},
		{netplan.Override{Zone: zone.ZoneFabric, Subnet: netip.MustParsePrefix("10.4.1.0/30")}, "/16 to /26"},
		{netplan.Override{Zone: zone.ZoneFabric, Subnet: netip.MustParsePrefix("10.4.1.7/24")}, "masked"},
		{netplan.Override{Zone: zone.ZoneFabric, Subnet: netip.MustParsePrefix("fd00::/24")}, "IPv4"},
		{netplan.Override{Zone: zone.ZoneFabric, Subnet6: netip.MustParsePrefix("fd00::/56")}, "/64"},
	}
	for _, tc := range overrides {
		err := netplan.Environment{ID: 4, Overrides: []netplan.Override{tc.o}}.Validate()
		var target netplan.ErrOverride
		require.True(t, errors.As(err, &target), "%+v: got %v", tc.o, err)
		assert.Contains(t, err.Error(), tc.reason)
	}

	dup := netplan.Environment{ID: 4, Overrides: []netplan.Override{
		{Zone: zone.ZoneFabric, VLAN: 3001}, {Zone: zone.ZoneFabric, VLAN: 3002},
	}}
	var target netplan.ErrOverride
	require.True(t, errors.As(dup.Validate(), &target))
	assert.Contains(t, target.Error(), "twice")
}

// TestEnvironment_YAML decodes the sdn.environment form.
func TestEnvironment_YAML(t *testing.T) {
	const doc = `
id: 4
base: 10.0.0.0/8
ula: fd12:3456:789a::/48
overrides:
  - {zone: fabric, subnet: 10.4.100.0/22}
  - {zone: control-plane, vlan: 50}
`
	var env netplan.Environment
	require.NoError(t, yaml.Unmarshal([]byte(doc), &env))
	require.NoError(t, env.Validate())
	assert.Equal(t, uint16(4), env.ID)
	assert.Equal(t, ula, env.ULA)
	require.Len(t, env.Overrides, 2)
	assert.Equal(t, "10.4.100.0/22", env.Overrides[0].Subnet.String())
	assert.Equal(t, uint16(50), env.Overrides[1].VLAN)
}

// TestErrorMessages checks each error names its origin and values.
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		err  error
		want []string
	}{
		{netplan.ErrEnvironmentID{ID: 1}, []string{"netplan:", "environment 1", "2-40"}},
		{netplan.ErrBase{Base: netip.MustParsePrefix("10.0.0.0/12")}, []string{"10.0.0.0/12", "/8"}},
		{netplan.ErrULA{ULA: ula}, []string{"/48", "fd00::/8"}},
		{netplan.ErrVLANOutOfRange{VLAN: 4095}, []string{"4095", "1-4094"}},
		{netplan.ErrVLANOutOfRange{Zone: "lab", VLAN: 4095}, []string{`"lab"`, "4095"}},
		{netplan.ErrOffset{Offset: 100}, []string{"offset 100"}},
		{netplan.ErrVNIOutOfRange{Network: 0}, []string{"network 0", "99999"}},
		{netplan.ErrOverride{Zone: "fabric", Reason: "x"}, []string{`"fabric"`, "x"}},
		{netplan.ErrDuplicateVLAN{VLAN: 401, Zones: [2]zone.Zone{"a", "b"}}, []string{"401", `"a"`, `"b"`}},
		{netplan.ErrOverlap{Zone: "a", Subnet: netip.MustParsePrefix("10.4.1.0/24"), Other: "zone b"}, []string{`"a"`, "10.4.1.0/24", "zone b"}},
		{netplan.ErrUnknownZone{Zone: "lab"}, []string{`"lab"`}},
		{netplan.ErrHostNumber{Prefix: netip.MustParsePrefix("10.4.1.0/28"), Host: 20}, []string{".20", "10.4.1.0/28"}},
		{netplan.ErrUnknownPortClass{Class: "x"}, []string{`"x"`}},
		{netplan.ErrEmptyPortClass{Class: zone.PortClassBMC}, []string{`"bmc"`}},
	}
	for _, tc := range tests {
		for _, w := range tc.want {
			assert.Contains(t, tc.err.Error(), w, "%T", tc.err)
		}
	}
}
