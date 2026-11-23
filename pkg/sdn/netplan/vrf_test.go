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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
)

// TestTenantVRF_Derives gives a tenant's VRF its L3VNI and, per network in
// input order, the L2VNI and the anycast gateway of the tenant's subnet.
func TestTenantVRF_Derives(t *testing.T) {
	p := referencePlan(t)
	v4 := netip.MustParsePrefix("172.16.0.0/24")
	v6 := netip.MustParsePrefix("fd00:1::/64")
	vrf, err := p.TenantVRF("t1", 1, []netplan.TenantSubnet{
		{Network: 2, Subnet: v4},
		{Network: 3, Subnet: v6},
	})
	require.NoError(t, err)
	assert.Equal(t, "t1", vrf.Tenant)
	assert.Equal(t, uint32(400001), vrf.L3VNI)
	assert.Equal(t, []netplan.TenantNetwork{
		{Network: 2, VNI: 400002, Subnet: v4, Gateway: netip.MustParseAddr("172.16.0.1")},
		{Network: 3, VNI: 400003, Subnet: v6, Gateway: netip.MustParseAddr("fd00:1::1")},
	}, vrf.Networks)
}

// TestTenantVRF_NoNetworks derives a VRF with its L3VNI and no networks.
func TestTenantVRF_NoNetworks(t *testing.T) {
	p := referencePlan(t)
	vrf, err := p.TenantVRF("t1", 1, nil)
	require.NoError(t, err)
	assert.Equal(t, uint32(400001), vrf.L3VNI)
	assert.Empty(t, vrf.Networks)
}

// TestTenantVRF_TenantsMayOverlap lets two tenants use the same subnet:
// each lives in its own VRF.
func TestTenantVRF_TenantsMayOverlap(t *testing.T) {
	p := referencePlan(t)
	s := netip.MustParsePrefix("172.16.0.0/24")
	_, err := p.TenantVRF("t1", 1, []netplan.TenantSubnet{{Network: 2, Subnet: s}})
	require.NoError(t, err)
	_, err = p.TenantVRF("t2", 4, []netplan.TenantSubnet{{Network: 5, Subnet: s}})
	require.NoError(t, err)
}

// TestTenantVRF_Refuses names the reason for each VRF the plan cannot
// derive, and passes the VNI and subnet errors through.
func TestTenantVRF_Refuses(t *testing.T) {
	p := referencePlan(t)
	s16 := netip.MustParsePrefix("172.16.0.0/16")
	s24 := netip.MustParsePrefix("172.16.0.0/24")
	vips := netip.MustParsePrefix("10.4.136.0/24")

	vrfCases := []struct {
		name    string
		tenant  string
		l3      uint32
		subnets []netplan.TenantSubnet
		reason  string
	}{
		{"no tenant", "", 1, nil, "has no tenant ID"},
		{"network is the L3VNI", "t1", 1, []netplan.TenantSubnet{{Network: 1, Subnet: s24}}, "network 1 is the L3VNI"},
		{"network twice", "t1", 1, []netplan.TenantSubnet{
			{Network: 2, Subnet: s24},
			{Network: 2, Subnet: netip.MustParsePrefix("172.17.0.0/24")},
		}, "network 2 appears twice"},
		{"subnets overlap", "t1", 1, []netplan.TenantSubnet{
			{Network: 2, Subnet: s16},
			{Network: 3, Subnet: s24},
		}, "172.16.0.0/24 overlaps 172.16.0.0/16"},
	}
	for _, tc := range vrfCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.TenantVRF(tc.tenant, tc.l3, tc.subnets)
			var e netplan.ErrTenantVRF
			require.ErrorAs(t, err, &e)
			assert.Equal(t, tc.tenant, e.Tenant)
			assert.Contains(t, e.Error(), tc.reason)
		})
	}

	for _, l3 := range []uint32{0, 100000} {
		_, err := p.TenantVRF("t1", l3, nil)
		var e netplan.ErrVNIOutOfRange
		require.ErrorAs(t, err, &e, "l3 %d", l3)
		assert.Equal(t, l3, e.Network)
	}

	_, err := p.TenantVRF("t1", 1, []netplan.TenantSubnet{{Network: 0, Subnet: s24}})
	var ev netplan.ErrVNIOutOfRange
	require.ErrorAs(t, err, &ev)
	assert.Equal(t, netplan.ErrVNIOutOfRange{Network: 0}, ev)

	_, err = p.TenantVRF("t1", 1, []netplan.TenantSubnet{{Network: 2, Subnet: vips}})
	var es netplan.ErrTenantSubnet
	require.ErrorAs(t, err, &es)
	assert.Equal(t, vips, es.Subnet)
}
