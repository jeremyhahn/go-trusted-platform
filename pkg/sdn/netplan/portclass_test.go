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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestPortClass_Reference reproduces the switch port model of the
// reference for environment 4.
func TestPortClass_Reference(t *testing.T) {
	p := referencePlan(t)
	tests := []struct {
		class   zone.PortClass
		mode    netplan.PortMode
		allowed []uint16
		native  uint16
	}{
		{zone.PortClassGateway, netplan.PortModeTrunk, []uint16{400, 401, 404, 405, 406, 408}, 0},
		{zone.PortClassHypervisor, netplan.PortModeTrunk, []uint16{401, 403, 404, 405, 406, 407, 408}, 405},
		{zone.PortClassBMC, netplan.PortModeAccess, []uint16{402}, 402},
		{zone.PortClassMgmtUplink, netplan.PortModeTrunk, []uint16{402}, 0},
		{zone.PortClassPeerLink, netplan.PortModeTrunk, []uint16{400, 401, 402, 403, 404, 405, 406, 407, 408}, 0},
	}
	require.Len(t, netplan.PortClasses(), len(tests))
	for _, tc := range tests {
		got, err := p.PortClass(tc.class)
		require.NoError(t, err, "class %s", tc.class)
		assert.Equal(t, tc.mode, got.Mode, "class %s", tc.class)
		assert.Equal(t, tc.allowed, got.Allowed, "class %s", tc.class)
		assert.Equal(t, tc.native, got.Native, "class %s", tc.class)
		assert.Equal(t, 9216, got.MTU)
	}
}

// TestPortClass_OwnerZoneJoinsItsClasses adds an owner zone to the gateway
// trunk and the peer-link but not the hypervisor trunk.
func TestPortClass_OwnerZoneJoinsItsClasses(t *testing.T) {
	p, err := netplan.New(netplan.Environment{ID: 4}, ownerAt(t, 9))
	require.NoError(t, err)

	gw, err := p.PortClass(zone.PortClassGateway)
	require.NoError(t, err)
	assert.Contains(t, gw.Allowed, uint16(409))

	hv, err := p.PortClass(zone.PortClassHypervisor)
	require.NoError(t, err)
	assert.NotContains(t, hv.Allowed, uint16(409))

	peer, err := p.PortClass(zone.PortClassPeerLink)
	require.NoError(t, err)
	assert.Contains(t, peer.Allowed, uint16(409))
}

// TestPortClass_Errors refuses an unknown class and a class with no zone.
func TestPortClass_Errors(t *testing.T) {
	_, err := referencePlan(t).PortClass("uplink")
	var unknown netplan.ErrUnknownPortClass
	require.True(t, errors.As(err, &unknown))

	zones, err := zone.Resolve([]zone.ZoneConfig{{Name: zone.ZoneManagement, Omit: true}})
	require.NoError(t, err)
	p, err := netplan.New(netplan.Environment{ID: 4}, zones)
	require.NoError(t, err)
	_, err = p.PortClass(zone.PortClassBMC)
	var empty netplan.ErrEmptyPortClass
	require.True(t, errors.As(err, &empty))
}
