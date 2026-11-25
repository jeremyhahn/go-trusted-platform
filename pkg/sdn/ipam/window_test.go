// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// zonePool is a reference zone pool: gateway .1, DHCP window .50-.254.
func zonePool() *Pool {
	return &Pool{
		ID:         "provisioning",
		Name:       "provisioning",
		CIDR:       netip.MustParsePrefix("192.0.2.0/24"),
		Gateway:    netip.MustParseAddr("192.0.2.1"),
		Reserved:   []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
		RangeStart: netip.MustParseAddr("192.0.2.50"),
		RangeEnd:   netip.MustParseAddr("192.0.2.254"),
	}
}

// freeFrom returns a nextFree function over a set of taken offsets.
func freeFrom(taken map[uint64]bool, last uint64) func(uint64) (uint64, bool) {
	return func(from uint64) (uint64, bool) {
		for off := from; off <= last; off++ {
			if !taken[off] {
				return off, true
			}
		}
		return 0, false
	}
}

func TestPool_IsReserved(t *testing.T) {
	p := zonePool()
	p.Reserved = append(p.Reserved, netip.MustParsePrefix("192.0.2.8/29"))
	assert.True(t, p.IsReserved(netip.MustParseAddr("192.0.2.1")), "the gateway")
	assert.True(t, p.IsReserved(netip.MustParseAddr("192.0.2.12")), "inside a reserved /29")
	assert.False(t, p.IsReserved(netip.MustParseAddr("192.0.2.16")), ".16 is past the /29")
	assert.False(t, p.IsReserved(netip.MustParseAddr("192.0.2.50")))
	assert.False(t, p.IsReserved(netip.Addr{}), "an invalid address is not reserved")

	// The gateway is reserved even when Reserved does not list it.
	gwOnly := &Pool{CIDR: p.CIDR, Gateway: p.Gateway}
	assert.True(t, gwOnly.IsReserved(p.Gateway))
}

func TestPool_InDynamicRange(t *testing.T) {
	p := zonePool()
	assert.True(t, p.InDynamicRange(netip.MustParseAddr("192.0.2.50")))
	assert.True(t, p.InDynamicRange(netip.MustParseAddr("192.0.2.254")))
	assert.False(t, p.InDynamicRange(netip.MustParseAddr("192.0.2.10")))

	whole := &Pool{CIDR: p.CIDR}
	assert.True(t, whole.InDynamicRange(netip.MustParseAddr("192.0.2.10")), "no range means the whole CIDR")
	assert.False(t, whole.InDynamicRange(netip.MustParseAddr("10.4.6.10")))
}

func TestPool_CheckSpecific(t *testing.T) {
	p := zonePool()
	require.NoError(t, p.CheckSpecific(netip.MustParseAddr("192.0.2.10")), "a static address outside the window is allowed")
	require.NoError(t, p.CheckSpecific(netip.MustParseAddr("192.0.2.60")))

	var reserved *ErrIPReserved
	err := p.CheckSpecific(netip.MustParseAddr("192.0.2.1"))
	require.True(t, errors.As(err, &reserved), "got %v", err)
	assert.Equal(t, "192.0.2.1/32", reserved.Reserved.String())
	assert.Equal(t, "provisioning", reserved.PoolID)
	assert.True(t, IsAllocationError(err))

	assert.ErrorIs(t, p.CheckSpecific(netip.Addr{}), ErrInvalidIP)
	assert.ErrorIs(t, p.CheckSpecific(netip.MustParseAddr("10.4.6.5")), ErrIPNotInPool)
	assert.ErrorIs(t, p.CheckSpecific(netip.MustParseAddr("192.0.2.0")), ErrNetworkAddress)
	assert.ErrorIs(t, p.CheckSpecific(netip.MustParseAddr("192.0.2.255")), ErrBroadcastAddress)
}

func TestPool_DynamicOffsets(t *testing.T) {
	first, last, ok := zonePool().DynamicOffsets()
	require.True(t, ok)
	assert.Equal(t, uint64(50), first)
	assert.Equal(t, uint64(254), last)

	// Without a range the usable CIDR is the window.
	first, last, ok = (&Pool{CIDR: netip.MustParsePrefix("192.0.2.0/24")}).DynamicOffsets()
	require.True(t, ok)
	assert.Equal(t, uint64(1), first)
	assert.Equal(t, uint64(254), last)

	// A range reaching the network and broadcast addresses is clipped.
	clipped := &Pool{
		CIDR:       netip.MustParsePrefix("192.0.2.0/24"),
		RangeStart: netip.MustParseAddr("192.0.2.0"),
		RangeEnd:   netip.MustParseAddr("192.0.2.255"),
	}
	first, last, ok = clipped.DynamicOffsets()
	require.True(t, ok)
	assert.Equal(t, uint64(1), first)
	assert.Equal(t, uint64(254), last)

	// A /31 has both addresses usable.
	first, last, ok = (&Pool{CIDR: netip.MustParsePrefix("10.4.128.0/31")}).DynamicOffsets()
	require.True(t, ok)
	assert.Equal(t, uint64(0), first)
	assert.Equal(t, uint64(1), last)
}

func TestPool_DynamicOffsets_Empty(t *testing.T) {
	_, _, ok := (&Pool{}).DynamicOffsets()
	assert.False(t, ok, "an invalid CIDR has no window")

	outside := &Pool{
		CIDR:       netip.MustParsePrefix("192.0.2.0/24"),
		RangeStart: netip.MustParseAddr("10.4.6.1"),
		RangeEnd:   netip.MustParseAddr("10.4.6.9"),
	}
	_, _, ok = outside.DynamicOffsets()
	assert.False(t, ok, "a range outside the CIDR is no window")
}

func TestPool_NextDynamic(t *testing.T) {
	p := zonePool()
	ip, off, err := p.NextDynamic(freeFrom(nil, 255))
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.50", ip.String(), "dynamic allocation starts at .50, never at the gateway")
	assert.Equal(t, uint64(50), off)

	// A reserved /29 inside the window is skipped in one step.
	p.Reserved = append(p.Reserved, netip.MustParsePrefix("192.0.2.48/29"))
	ip, _, err = p.NextDynamic(freeFrom(nil, 255))
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.56", ip.String())

	// Taken addresses are skipped.
	ip, _, err = p.NextDynamic(freeFrom(map[uint64]bool{56: true, 57: true}, 255))
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.58", ip.String())
}

func TestPool_NextDynamic_Exhausted(t *testing.T) {
	p := zonePool()
	taken := map[uint64]bool{}
	for off := uint64(50); off <= 254; off++ {
		taken[off] = true
	}
	_, _, err := p.NextDynamic(freeFrom(taken, 255))
	assert.ErrorIs(t, err, ErrPoolExhausted)

	// A reserved prefix that runs to the end of the window exhausts it.
	tail := zonePool()
	tail.Reserved = []netip.Prefix{netip.MustParsePrefix("192.0.2.128/25")}
	tail.RangeStart = netip.MustParseAddr("192.0.2.128")
	_, _, err = tail.NextDynamic(freeFrom(nil, 255))
	assert.ErrorIs(t, err, ErrPoolExhausted)

	_, _, err = (&Pool{}).NextDynamic(freeFrom(nil, 0))
	assert.ErrorIs(t, err, ErrPoolExhausted)
}

func TestPool_NextDynamic_HASyncSlash31(t *testing.T) {
	// The tunnel range reserves its first /31 for the gateway HA sync link.
	p := &Pool{
		ID:       "tunnel-p2p",
		CIDR:     netip.MustParsePrefix("10.4.128.0/22"),
		Reserved: []netip.Prefix{netip.MustParsePrefix("10.4.128.0/31")},
	}
	ip, _, err := p.NextDynamic(freeFrom(nil, 1023))
	require.NoError(t, err)
	assert.Equal(t, "10.4.128.2", ip.String())
	assert.True(t, p.IsReserved(netip.MustParseAddr("10.4.128.1")))
}

func TestPool_NextDynamic_IPv6(t *testing.T) {
	p := &Pool{
		ID:      "v6",
		CIDR:    netip.MustParsePrefix("fd12:3456:789a:405::/64"),
		Gateway: netip.MustParseAddr("fd12:3456:789a:405::1"),
	}
	ip, _, err := p.NextDynamic(freeFrom(map[uint64]bool{0: true}, 16))
	require.NoError(t, err)
	assert.Equal(t, "fd12:3456:789a:405::2", ip.String(), "::0 taken, ::1 is the gateway")
}

func TestPool_RandomDynamic(t *testing.T) {
	p := zonePool()
	for range 64 {
		ip, err := p.RandomDynamic()
		require.NoError(t, err)
		assert.True(t, p.InDynamicRange(ip), "%s outside the window", ip)
	}

	// A window that is a single reserved address always draws it.
	only := &Pool{
		ID:         "only",
		CIDR:       netip.MustParsePrefix("192.0.2.0/24"),
		Gateway:    netip.MustParseAddr("192.0.2.1"),
		RangeStart: netip.MustParseAddr("192.0.2.1"),
		RangeEnd:   netip.MustParseAddr("192.0.2.1"),
	}
	_, err := only.RandomDynamic()
	var reserved *ErrIPReserved
	require.True(t, errors.As(err, &reserved), "got %v", err)

	_, err = (&Pool{}).RandomDynamic()
	assert.ErrorIs(t, err, ErrPoolExhausted)
}

func TestPool_AllocatableIPs(t *testing.T) {
	assert.Equal(t, uint64(253), zonePool().AllocatableIPs(), "254 usable less the gateway")

	// A reserved prefix that also lists the gateway is not counted twice,
	// and the network/broadcast addresses it covers were never usable.
	p := zonePool()
	p.Reserved = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/28"), netip.MustParsePrefix("192.0.2.1/32")}
	assert.Equal(t, uint64(254-15), p.AllocatableIPs())

	whole := &Pool{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Reserved: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	assert.Equal(t, uint64(0), whole.AllocatableIPs())

	tun := &Pool{CIDR: netip.MustParsePrefix("10.4.128.0/22"), Reserved: []netip.Prefix{netip.MustParsePrefix("10.4.128.0/31")}}
	assert.Equal(t, uint64(1022-1), tun.AllocatableIPs(), "the /31 covers the network address and one usable")

	huge := &Pool{CIDR: netip.MustParsePrefix("fd00::/48"), Gateway: netip.MustParseAddr("fd00::1")}
	assert.Equal(t, ^uint64(0), huge.AllocatableIPs(), "very large pools saturate")
}

func TestPoolManager_ValidatePool_Window(t *testing.T) {
	pm := NewPoolManager()
	require.NoError(t, pm.ValidatePool(zonePool()))

	tests := []struct {
		name   string
		mutate func(*Pool)
		reason string
	}{
		{"reserved outside", func(p *Pool) { p.Reserved = []netip.Prefix{netip.MustParsePrefix("10.4.6.0/30")} }, "not inside"},
		{"reserved wider than cidr", func(p *Pool) { p.Reserved = []netip.Prefix{netip.MustParsePrefix("10.4.0.0/16")} }, "not inside"},
		{"reserved other family", func(p *Pool) { p.Reserved = []netip.Prefix{netip.MustParsePrefix("fd00::/64")} }, "not inside"},
		{"reserved invalid", func(p *Pool) { p.Reserved = []netip.Prefix{{}} }, "not inside"},
		{"start only", func(p *Pool) { p.RangeEnd = netip.Addr{} }, "together"},
		{"end only", func(p *Pool) { p.RangeStart = netip.Addr{} }, "together"},
		{"range outside", func(p *Pool) { p.RangeEnd = netip.MustParseAddr("10.4.6.1") }, "not inside"},
		{"start after end", func(p *Pool) {
			p.RangeStart = netip.MustParseAddr("192.0.2.200")
			p.RangeEnd = netip.MustParseAddr("192.0.2.100")
		}, "after"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := zonePool()
			tc.mutate(p)
			err := pm.ValidatePool(p)
			var window *ErrInvalidWindow
			require.True(t, errors.As(err, &window), "got %v", err)
			assert.Contains(t, err.Error(), tc.reason)
			assert.True(t, IsValidationError(err))
		})
	}
}

func TestPoolManager_InitializePool_CountsAllocatable(t *testing.T) {
	p := zonePool()
	NewPoolManager().InitializePool(p)
	assert.Equal(t, uint64(253), p.TotalIPs)
	assert.Equal(t, uint64(253), p.AvailableIPs)
}

func TestPool_CloneCopiesWindow(t *testing.T) {
	p := zonePool()
	c := p.Clone()
	c.Reserved[0] = netip.MustParsePrefix("192.0.2.2/32")
	assert.Equal(t, "192.0.2.1/32", p.Reserved[0].String())
	assert.Equal(t, p.RangeStart, c.RangeStart)
}

func TestLastAddrOf(t *testing.T) {
	assert.Equal(t, "192.0.2.15", lastAddrOf(netip.MustParsePrefix("192.0.2.0/28")).String())
	assert.Equal(t, "192.0.2.1", lastAddrOf(netip.MustParsePrefix("192.0.2.1/32")).String())
	assert.Equal(t, "10.4.131.255", lastAddrOf(netip.MustParsePrefix("10.4.128.0/22")).String())
	assert.Equal(t, "fd00::ffff:ffff:ffff:ffff", lastAddrOf(netip.MustParsePrefix("fd00::/64")).String())
}

func TestErrIPReserved_Error(t *testing.T) {
	err := &ErrIPReserved{IP: netip.MustParseAddr("192.0.2.1"), PoolID: "p", Reserved: netip.MustParsePrefix("192.0.2.1/32")}
	assert.Contains(t, err.Error(), "192.0.2.1")
	assert.Contains(t, err.Error(), "reserved")
	w := &ErrInvalidWindow{PoolID: "p", Reason: "r"}
	assert.Equal(t, "ipam: pool p: r", w.Error())
}

func TestParseWindow(t *testing.T) {
	r, start, end, err := ParseWindow([]string{"192.0.2.1/32", "192.0.2.9/30"}, "192.0.2.50", "192.0.2.254")
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("192.0.2.8/30")}, r, "prefixes are masked")
	assert.Equal(t, "192.0.2.50", start.String())
	assert.Equal(t, "192.0.2.254", end.String())

	r, start, end, err = ParseWindow(nil, "", "")
	require.NoError(t, err)
	assert.Nil(t, r)
	assert.False(t, start.IsValid() || end.IsValid())
}

func TestParseWindow_Errors(t *testing.T) {
	var window *ErrInvalidWindow
	_, _, _, err := ParseWindow([]string{"192.0.2.1"}, "", "")
	require.True(t, errors.As(err, &window))
	_, _, _, err = ParseWindow(nil, "nope", "")
	require.True(t, errors.As(err, &window))
	_, _, _, err = ParseWindow(nil, "", "nope")
	require.True(t, errors.As(err, &window))
}

func TestPool_WindowStrings(t *testing.T) {
	p := zonePool()
	assert.Equal(t, []string{"192.0.2.1/32"}, p.ReservedStrings())
	assert.Nil(t, (&Pool{}).ReservedStrings())
	assert.Equal(t, "192.0.2.50", AddrString(p.RangeStart))
	assert.Equal(t, "", AddrString(netip.Addr{}))
}

func TestPool_ApplyWindowUpdate(t *testing.T) {
	p := zonePool()
	require.NoError(t, p.ApplyWindowUpdate(nil, nil, nil))
	assert.Equal(t, zonePool().RangeStart, p.RangeStart, "nothing set changes nothing")

	start := "192.0.2.100"
	require.NoError(t, p.ApplyWindowUpdate(nil, &start, nil))
	assert.Equal(t, "192.0.2.100", p.RangeStart.String())
	assert.Equal(t, "192.0.2.254", p.RangeEnd.String(), "the end is kept")
	assert.Equal(t, []string{"192.0.2.1/32"}, p.ReservedStrings(), "reservations are kept")

	empty := ""
	require.NoError(t, p.ApplyWindowUpdate([]string{}, &empty, &empty))
	assert.Empty(t, p.Reserved)
	assert.False(t, p.HasDynamicRange())
}

func TestPool_ApplyWindowUpdate_Error(t *testing.T) {
	p := zonePool()
	bad := "nope"
	var window *ErrInvalidWindow
	require.True(t, errors.As(p.ApplyWindowUpdate(nil, nil, &bad), &window))
	assert.Equal(t, "192.0.2.254", p.RangeEnd.String(), "a refused update leaves the pool alone")
}
