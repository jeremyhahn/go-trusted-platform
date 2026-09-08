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

package fhrp

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Golden vectors were produced by an independent Python encoder of RFC 5798
// §5.2 with the §5.2.8 pseudo-header checksum (see the PR body), so the Go
// encoder is checked against something other than itself.
var goldenVectors = []struct {
	name string
	adv  Advertisement
	src  string
	dst  string
	hex  string
}{
	{
		name: "ipv4 single address",
		adv:  Advertisement{VRID: 1, Priority: 100, MaxAdvertInterval: 100, Addresses: addrs("192.168.10.1")},
		src:  "192.168.10.2", dst: "224.0.0.18",
		hex: "310164010064f4b5c0a80a01",
	},
	{
		name: "ipv6 single address",
		adv:  Advertisement{VRID: 20, Priority: 254, MaxAdvertInterval: 100, Addresses: addrs("2602:f5bb::1")},
		src:  "fe80::1", dst: "ff02::12",
		hex: "3114fe010064b6a72602f5bb000000000000000000000001",
	},
	{
		name: "ipv4 two addresses",
		adv:  Advertisement{VRID: 2, Priority: 200, MaxAdvertInterval: 50, Addresses: addrs("198.18.0.1", "23.143.36.1")},
		src:  "198.18.0.2", dst: "224.0.0.18",
		hex: "3102c80200320280ac10c801178f2401",
	},
}

func addrs(list ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(list))
	for _, a := range list {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func TestAdvertisement_MarshalGolden(t *testing.T) {
	for _, v := range goldenVectors {
		t.Run(v.name, func(t *testing.T) {
			got, err := v.adv.Marshal(netip.MustParseAddr(v.src), netip.MustParseAddr(v.dst))
			require.NoError(t, err)
			assert.Equal(t, v.hex, hex.EncodeToString(got))
		})
	}
}

func TestUnmarshal_GoldenRoundTrip(t *testing.T) {
	for _, v := range goldenVectors {
		t.Run(v.name, func(t *testing.T) {
			raw, err := hex.DecodeString(v.hex)
			require.NoError(t, err)
			adv, err := Unmarshal(raw, netip.MustParseAddr(v.src), netip.MustParseAddr(v.dst))
			require.NoError(t, err)
			assert.Equal(t, v.adv.VRID, adv.VRID)
			assert.Equal(t, v.adv.Priority, adv.Priority)
			assert.Equal(t, v.adv.MaxAdvertInterval, adv.MaxAdvertInterval)
			assert.Equal(t, v.adv.Addresses, adv.Addresses)
		})
	}
}

func TestUnmarshal_Rejects(t *testing.T) {
	src, dst := netip.MustParseAddr("192.168.10.2"), netip.MustParseAddr("224.0.0.18")
	good, err := goldenVectors[0].adv.Marshal(src, dst)
	require.NoError(t, err)

	flip := func(i int, mask byte) []byte {
		b := append([]byte(nil), good...)
		b[i] ^= mask
		return b
	}
	cases := map[string]struct {
		buf    []byte
		reason string
	}{
		"short":            {good[:7], "shorter than the header"},
		"version 2":        {flip(0, 0x10), "not version 3"},
		"type 2":           {flip(0, 0x03), "not an advertisement"},
		"zero addresses":   {flip(3, 0x01), "no addresses"},
		"count mismatch":   {flip(3, 0x02), "length does not match"},
		"corrupt checksum": {flip(6, 0x01), "checksum mismatch"},
		"corrupt address":  {flip(11, 0x01), "checksum mismatch"},
		"wrong pseudo src": {good, "checksum mismatch"},
		"zero interval":    {func() []byte { b := append([]byte(nil), good...); b[4], b[5] = 0, 0; return b }(), ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := src
			if name == "wrong pseudo src" {
				s = netip.MustParseAddr("192.168.10.3")
			}
			_, err := Unmarshal(c.buf, s, dst)
			var invalid *ErrInvalidPacket
			require.True(t, errors.As(err, &invalid), "got %v", err)
			if c.reason != "" {
				assert.Contains(t, err.Error(), c.reason)
			}
		})
	}
}

func TestAdvertisement_MarshalRejects(t *testing.T) {
	src, dst := netip.MustParseAddr("192.168.10.2"), netip.MustParseAddr("224.0.0.18")
	cases := map[string]Advertisement{
		"interval 0":      {VRID: 1, Priority: 1, MaxAdvertInterval: 0, Addresses: addrs("10.0.0.1")},
		"interval 4096":   {VRID: 1, Priority: 1, MaxAdvertInterval: 4096, Addresses: addrs("10.0.0.1")},
		"no addresses":    {VRID: 1, Priority: 1, MaxAdvertInterval: 100},
		"mixed families":  {VRID: 1, Priority: 1, MaxAdvertInterval: 100, Addresses: addrs("10.0.0.1", "fd00::1")},
		"pseudo mismatch": {VRID: 1, Priority: 1, MaxAdvertInterval: 100, Addresses: addrs("fd00::1")},
	}
	for name, adv := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := adv.Marshal(src, dst)
			var invalid *ErrInvalidPacket
			assert.True(t, errors.As(err, &invalid), "got %v", err)
		})
	}
}

func TestVirtualMAC(t *testing.T) {
	assert.Equal(t, "00:00:5e:00:01:14", VirtualMAC(FamilyIPv4, 20).String())
	assert.Equal(t, "00:00:5e:00:02:14", VirtualMAC(FamilyIPv6, 20).String())
	assert.Equal(t, "224.0.0.18", FamilyIPv4.MulticastAddr().String())
	assert.Equal(t, "ff02::12", FamilyIPv6.MulticastAddr().String())
	assert.Equal(t, "ipv4", FamilyIPv4.String())
	assert.Equal(t, "ipv6", FamilyIPv6.String())
	assert.Equal(t, "unknown", Family(9).String())
}
