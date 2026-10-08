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

package bgp

import (
	"net/netip"
	"testing"

	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAutoRouteTarget(t *testing.T) {
	t.Run("RFC 8365 layout", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			asn      uint16
			domainID uint8
			vni      uint32
			want     uint32
		}{
			{"VNI 100", 65000, 0, 100, 1<<28 | 100},
			{"domain ID in bits 24-27", 65000, 5, 100, 1<<28 | 5<<24 | 100},
			{"largest VNI and domain", 64512, MaxDomainID, MaxVNI, 1<<28 | 15<<24 | 0xffffff},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rt, err := AutoRouteTarget(tc.asn, tc.domainID, tc.vni)
				require.NoError(t, err)
				assert.Equal(t, RouteTarget{AS: tc.asn, Value: tc.want}, rt)
			})
		}
		rt, err := AutoRouteTarget(65000, 0, 100)
		require.NoError(t, err)
		assert.Equal(t, "65000:268435556", rt.String(), "the form policy allowlists name")
	})

	t.Run("invalid input", func(t *testing.T) {
		for name, tc := range map[string]struct {
			asn      uint16
			domainID uint8
			vni      uint32
		}{
			"public ASN":     {64001, 0, 100},
			"reserved ASN":   {65535, 0, 100},
			"domain ID > 15": {65000, 16, 100},
			"zero VNI":       {65000, 0, 0},
			"VNI > 24 bits":  {65000, 0, MaxVNI + 1},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := AutoRouteTarget(tc.asn, tc.domainID, tc.vni)
				require.Error(t, err)
			})
		}
	})
}

func TestRouteTarget_Native(t *testing.T) {
	native, ok := RouteTarget{AS: 65000, Value: 268435556}.native().(*gobgp.TwoOctetAsSpecificExtended)
	require.True(t, ok)
	assert.Equal(t, uint16(65000), native.AS)
	assert.Equal(t, uint32(268435556), native.LocalAdmin)
	assert.Equal(t, gobgp.EC_SUBTYPE_ROUTE_TARGET, native.SubType)
	assert.True(t, native.IsTransitive)
}

func TestRouteDistinguisher(t *testing.T) {
	rd := RouteDistinguisher{Admin: netip.MustParseAddr("192.0.2.11"), Index: 7}
	assert.Equal(t, "192.0.2.11:7", rd.String())

	t.Run("round trip through GoBGP", func(t *testing.T) {
		native, err := rd.native()
		require.NoError(t, err)
		back, err := routeDistinguisherFromNative(native)
		require.NoError(t, err)
		assert.Equal(t, rd, back)
	})

	t.Run("an IPv6 administrator is not Type-1", func(t *testing.T) {
		_, err := RouteDistinguisher{Admin: netip.MustParseAddr("2001:db8::1")}.native()
		var invalid ErrInvalidRouteDistinguisher
		require.ErrorAs(t, err, &invalid)
	})

	t.Run("received RDs other than Type-1 are refused", func(t *testing.T) {
		for name, native := range map[string]gobgp.RouteDistinguisherInterface{
			"Type-0": gobgp.NewRouteDistinguisherTwoOctetAS(65000, 100),
			"Type-2": gobgp.NewRouteDistinguisherFourOctetAS(4200000000, 1),
			"nil":    nil,
		} {
			t.Run(name, func(t *testing.T) {
				_, err := routeDistinguisherFromNative(native)
				var invalid ErrInvalidRouteDistinguisher
				require.ErrorAs(t, err, &invalid)
			})
		}
	})
}

func TestRDAllocator(t *testing.T) {
	admin := netip.MustParseAddr("192.0.2.11")

	t.Run("one RD per instance, stable on reuse", func(t *testing.T) {
		a := newRDAllocator(admin)
		evi, err := a.allocate(rdInstance{vni: 100})
		require.NoError(t, err)
		vrf, err := a.allocate(rdInstance{ipVRF: true, vni: 100})
		require.NoError(t, err)
		again, err := a.allocate(rdInstance{vni: 100})
		require.NoError(t, err)

		assert.Equal(t, RouteDistinguisher{Admin: admin, Index: 1}, evi)
		assert.Equal(t, RouteDistinguisher{Admin: admin, Index: 2}, vrf, "an IP-VRF and an EVI of the same number are distinct")
		assert.Equal(t, evi, again)
		got, ok := a.lookup(rdInstance{vni: 100})
		assert.True(t, ok)
		assert.Equal(t, evi, got)
	})

	t.Run("released numbers are reused", func(t *testing.T) {
		a := newRDAllocator(admin)
		first, err := a.allocate(rdInstance{vni: 1})
		require.NoError(t, err)
		a.release(rdInstance{vni: 1})
		a.release(rdInstance{vni: 1})
		_, ok := a.lookup(rdInstance{vni: 1})
		assert.False(t, ok)

		next, err := a.allocate(rdInstance{vni: 2})
		require.NoError(t, err)
		assert.Equal(t, first, next)
	})

	t.Run("exhaustion", func(t *testing.T) {
		a := newRDAllocator(admin)
		a.next = 0xffff
		_, err := a.allocate(rdInstance{vni: 1})
		require.NoError(t, err)
		_, err = a.allocate(rdInstance{vni: 2})
		var exhausted ErrRouteDistinguishersExhausted
		require.ErrorAs(t, err, &exhausted)
		assert.Equal(t, admin, exhausted.Admin)
		assert.NotEmpty(t, exhausted.Error())
	})
}

func TestValidateVNI(t *testing.T) {
	for _, vni := range []uint32{MinVNI, 100, MaxVNI} {
		assert.NoError(t, validateVNI(vni), "VNI %d", vni)
	}
	for _, vni := range []uint32{0, MaxVNI + 1, 1 << 28} {
		var invalid ErrInvalidVNI
		assert.ErrorAs(t, validateVNI(vni), &invalid, "VNI %d", vni)
	}
}
