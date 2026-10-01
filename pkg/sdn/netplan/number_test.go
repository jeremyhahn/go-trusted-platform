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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

var (
	base = netip.MustParsePrefix("10.0.0.0/8")
	ula  = netip.MustParsePrefix("fd12:3456:789a::/48")
)

// TestVLAN covers VLAN = E·100+n at both edges of the platform range.
func TestVLAN(t *testing.T) {
	tests := []struct {
		e    uint16
		off  zone.Offset
		want uint16
	}{
		{2, 0, 200},
		{4, 6, 406},
		{4, 99, 499},
		{40, 94, 4094},
	}
	for _, tc := range tests {
		got, err := netplan.VLAN(tc.e, tc.off)
		require.NoError(t, err, "E=%d n=%d", tc.e, tc.off)
		assert.Equal(t, tc.want, got)
	}
}

// TestVLAN_OutOfRange refuses VLANs past 4094 and offsets past 99.
func TestVLAN_OutOfRange(t *testing.T) {
	_, err := netplan.VLAN(40, 95)
	var vlanErr netplan.ErrVLANOutOfRange
	require.True(t, errors.As(err, &vlanErr), "got %v", err)
	assert.Equal(t, uint32(4095), vlanErr.VLAN)

	_, err = netplan.VLAN(4, 100)
	var offErr netplan.ErrOffset
	require.True(t, errors.As(err, &offErr), "got %v", err)

	_, err = netplan.VLAN(0, 0)
	require.True(t, errors.As(err, &vlanErr), "VLAN 0 is not a VLAN")
}

// TestSubnet4 covers 10.E.n.0/24 on the default and a non-default base.
func TestSubnet4(t *testing.T) {
	got, err := netplan.Subnet4(base, 4, 6)
	require.NoError(t, err)
	assert.Equal(t, "10.4.6.0/24", got.String())

	got, err = netplan.Subnet4(base, 2, 0)
	require.NoError(t, err)
	assert.Equal(t, "10.2.0.0/24", got.String())

	got, err = netplan.Subnet4(netip.MustParsePrefix("100.0.0.0/8"), 40, 99)
	require.NoError(t, err)
	assert.Equal(t, "100.40.99.0/24", got.String())
}

// TestSubnet4_Errors refuses a bad base, environment or offset.
func TestSubnet4_Errors(t *testing.T) {
	var baseErr netplan.ErrBase
	for _, b := range []string{"10.0.0.0/16", "10.1.0.0/8", "fd00::/8"} {
		_, err := netplan.Subnet4(netip.MustParsePrefix(b), 4, 1)
		require.True(t, errors.As(err, &baseErr), "base %s: got %v", b, err)
	}
	_, err := netplan.Subnet4(netip.Prefix{}, 4, 1)
	require.True(t, errors.As(err, &baseErr))

	var envErr netplan.ErrEnvironmentID
	_, err = netplan.Subnet4(base, 1, 0)
	require.True(t, errors.As(err, &envErr))
	_, err = netplan.Subnet4(base, 41, 0)
	require.True(t, errors.As(err, &envErr))

	var offErr netplan.ErrOffset
	_, err = netplan.Subnet4(base, 4, 100)
	require.True(t, errors.As(err, &offErr))
}

// TestSubnet6 reads the VLAN digits as the hex subnet ID.
func TestSubnet6(t *testing.T) {
	tests := map[uint16]string{
		406:  "fd12:3456:789a:406::/64",
		200:  "fd12:3456:789a:200::/64",
		4094: "fd12:3456:789a:4094::/64",
		9:    "fd12:3456:789a:9::/64",
	}
	for vlan, want := range tests {
		got, err := netplan.Subnet6(ula, vlan)
		require.NoError(t, err, "VLAN %d", vlan)
		assert.Equal(t, want, got.String())
	}
}

// TestSubnet6_Errors refuses a non-ULA, a wrong length and a bad VLAN.
func TestSubnet6_Errors(t *testing.T) {
	var ulaErr netplan.ErrULA
	for _, p := range []string{"2001:db8::/48", "fd12:3456::/32", "fd12:3456:789a:1::/64", "10.0.0.0/8"} {
		_, err := netplan.Subnet6(netip.MustParsePrefix(p), 406)
		require.True(t, errors.As(err, &ulaErr), "ula %s: got %v", p, err)
	}
	var vlanErr netplan.ErrVLANOutOfRange
	_, err := netplan.Subnet6(ula, 0)
	require.True(t, errors.As(err, &vlanErr))
	_, err = netplan.Subnet6(ula, 4095)
	require.True(t, errors.As(err, &vlanErr))
}

// TestVNI covers E·100000+n at the block edges and its inverse.
func TestVNI(t *testing.T) {
	got, err := netplan.VNI(4, 1)
	require.NoError(t, err)
	assert.Equal(t, uint32(400001), got)

	got, err = netplan.VNI(4, netplan.MaxNetworksPerEnvironment)
	require.NoError(t, err)
	assert.Equal(t, uint32(499999), got)

	got, err = netplan.VNI(40, 99999)
	require.NoError(t, err)
	assert.Equal(t, uint32(4099999), got)
	assert.Less(t, got, uint32(1<<24), "VNIs are 24-bit")

	e, n, ok := netplan.SplitVNI(400001)
	require.True(t, ok)
	assert.Equal(t, uint16(4), e)
	assert.Equal(t, uint32(1), n)
}

// TestVNI_Errors refuses network 0, network 100000 and bad environments;
// SplitVNI refuses VNIs that encode none.
func TestVNI_Errors(t *testing.T) {
	var vniErr netplan.ErrVNIOutOfRange
	_, err := netplan.VNI(4, 0)
	require.True(t, errors.As(err, &vniErr))
	_, err = netplan.VNI(4, 100000)
	require.True(t, errors.As(err, &vniErr))

	var envErr netplan.ErrEnvironmentID
	_, err = netplan.VNI(1, 1)
	require.True(t, errors.As(err, &envErr))

	for _, vni := range []uint32{0, 400000, 100001, 4100001} {
		_, _, ok := netplan.SplitVNI(vni)
		assert.False(t, ok, "VNI %d", vni)
	}
}

// TestHostNumbering covers the reference host bands of a zone subnet.
func TestHostNumbering(t *testing.T) {
	s := netip.MustParsePrefix("10.4.6.0/24")

	gw, err := netplan.Gateway(s)
	require.NoError(t, err)
	assert.Equal(t, "10.4.6.1", gw.String())

	n, err := netplan.GatewayNode(s, 1)
	require.NoError(t, err)
	assert.Equal(t, "10.4.6.3", n.String())

	cp, err := netplan.ControlPlaneNode(s, 0)
	require.NoError(t, err)
	assert.Equal(t, "10.4.6.10", cp.String())
	cp, err = netplan.ControlPlaneNode(s, 9)
	require.NoError(t, err)
	assert.Equal(t, "10.4.6.19", cp.String())

	h, err := netplan.StaticHost(s, 29)
	require.NoError(t, err)
	assert.Equal(t, "10.4.6.49", h.String())

	anycast, err := netplan.AnycastGateway(netip.MustParsePrefix("10.4.192.0/24"))
	require.NoError(t, err)
	assert.Equal(t, "10.4.192.1", anycast.String())
}

// TestHostNumbering_Errors refuses hosts outside their band or subnet.
func TestHostNumbering_Errors(t *testing.T) {
	s := netip.MustParsePrefix("10.4.6.0/24")
	var hostErr netplan.ErrHostNumber

	_, err := netplan.GatewayNode(s, 2)
	require.True(t, errors.As(err, &hostErr))
	_, err = netplan.ControlPlaneNode(s, 10)
	require.True(t, errors.As(err, &hostErr))
	_, err = netplan.StaticHost(s, -1)
	require.True(t, errors.As(err, &hostErr))
	_, err = netplan.Host(s, 0)
	require.True(t, errors.As(err, &hostErr), "the network address is not a host")
	_, err = netplan.Host(s, 255)
	require.True(t, errors.As(err, &hostErr), "the broadcast address is not a host")
	_, err = netplan.Host(netip.MustParsePrefix("10.4.6.0/28"), 20)
	require.True(t, errors.As(err, &hostErr), "host past the end of a /28")
	assert.Contains(t, hostErr.Error(), "10.4.6.0/28")

	p, err := netplan.Host(netip.MustParsePrefix("fd12:3456:789a:406::/64"), 10)
	require.NoError(t, err)
	assert.Equal(t, "fd12:3456:789a:406::a", p.String())
}
