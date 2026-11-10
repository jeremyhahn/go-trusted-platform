package netplan_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestNew_ZoneOffsetPastBlock pins that a zone whose offset lies outside the
// environment block is refused with ErrOffset, and that a VLAN override does
// not rescue it: the IPv4 subnet still derives from the offset.
func TestNew_ZoneOffsetPastBlock(t *testing.T) {
	past := zone.MaxOffset + 1
	zones := []zone.ZoneConfig{{Name: "lab", Offset: past, PortClasses: []zone.PortClass{zone.PortClassGateway}}}
	tests := []struct {
		name string
		env  netplan.Environment
	}{
		{"derived VLAN", netplan.Environment{ID: 4, ULA: ula}},
		{"overridden VLAN", netplan.Environment{ID: 4, ULA: ula, Overrides: []netplan.Override{{Zone: "lab", VLAN: 900}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := netplan.New(tc.env, zones)
			require.Error(t, err)
			assert.Nil(t, p)
			var target netplan.ErrOffset
			require.True(t, errors.As(err, &target), "got %T: %v", err, err)
			assert.Equal(t, past, target.Offset)
		})
	}
}

// TestPortClass_HypervisorNative pins that the hypervisor trunk's native VLAN
// is the provisioning zone's VLAN, and that a plan without a provisioning
// zone refuses the hypervisor class with ErrUnknownZone rather than
// returning a trunk with no native VLAN.
func TestPortClass_HypervisorNative(t *testing.T) {
	t.Run("provisioning present", func(t *testing.T) {
		p := referencePlan(t)
		prov, ok := p.Zone(zone.ZoneProvisioning)
		require.True(t, ok)

		got, err := p.PortClass(zone.PortClassHypervisor)
		require.NoError(t, err)
		assert.Equal(t, prov.VLAN, got.Native)
		assert.Contains(t, got.Allowed, prov.VLAN)
	})

	t.Run("provisioning absent", func(t *testing.T) {
		zones := []zone.ZoneConfig{{Name: "lab", Offset: zone.MinOwnerOffset, PortClasses: []zone.PortClass{zone.PortClassHypervisor}}}
		p, err := netplan.New(netplan.Environment{ID: 4, ULA: ula}, zones)
		require.NoError(t, err)

		got, err := p.PortClass(zone.PortClassHypervisor)
		require.Error(t, err)
		assert.Equal(t, netplan.PortClassPlan{}, got)
		var target netplan.ErrUnknownZone
		require.True(t, errors.As(err, &target), "got %T: %v", err, err)
		assert.Equal(t, zone.ZoneProvisioning, target.Zone)
	})
}
