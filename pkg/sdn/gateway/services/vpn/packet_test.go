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

package vpn

import (
	"net/netip"
	"testing"
)

func TestPacketAddresses(t *testing.T) {
	v4 := make([]byte, 20)
	v4[0] = 0x45
	copy(v4[12:16], []byte{10, 9, 0, 23})
	copy(v4[16:20], []byte{192, 168, 1, 5})
	v6 := make([]byte, 40)
	v6[0] = 0x60
	copy(v6[8:24], netip.MustParseAddr("fd00:9::17").AsSlice())
	copy(v6[24:40], netip.MustParseAddr("fd00:1::5").AsSlice())

	cases := map[string]struct {
		pkt      []byte
		ok       bool
		src, dst string
	}{
		"ipv4":            {v4, true, "10.9.0.23", "192.168.1.5"},
		"ipv6":            {v6, true, "fd00:9::17", "fd00:1::5"},
		"empty":           {nil, false, "", ""},
		"short ipv4":      {v4[:19], false, "", ""},
		"short ipv6":      {v6[:39], false, "", ""},
		"unknown version": {[]byte{0x35, 0, 0, 0}, false, "", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			src, dst, ok := packetAddresses(tc.pkt)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !tc.ok {
				return
			}
			if src.String() != tc.src || dst.String() != tc.dst {
				t.Fatalf("src/dst = %s/%s, want %s/%s", src, dst, tc.src, tc.dst)
			}
		})
	}
}

func TestPrefixRange(t *testing.T) {
	cases := map[string]struct{ prefix, start, end string }{
		"ipv4 host":    {"10.9.0.23/32", "10.9.0.23", "10.9.0.23"},
		"ipv4 /24":     {"10.9.0.0/24", "10.9.0.0", "10.9.0.255"},
		"ipv4 /23":     {"10.9.0.0/23", "10.9.0.0", "10.9.1.255"},
		"ipv4 unmaskd": {"10.9.0.23/24", "10.9.0.0", "10.9.0.255"},
		"ipv4 /0":      {"0.0.0.0/0", "0.0.0.0", "255.255.255.255"},
		"ipv6 host":    {"fd00:9::17/128", "fd00:9::17", "fd00:9::17"},
		"ipv6 /64":     {"fd00:9::/64", "fd00:9::", "fd00:9::ffff:ffff:ffff:ffff"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			start, end := prefixRange(netip.MustParsePrefix(tc.prefix))
			if start.String() != tc.start || end.String() != tc.end {
				t.Fatalf("range = %s..%s, want %s..%s", start, end, tc.start, tc.end)
			}
		})
	}
}

func TestAllowedSource(t *testing.T) {
	leased := netip.MustParseAddr("10.9.0.23")
	v4 := func(src string) []byte {
		pkt := make([]byte, 20)
		pkt[0] = 0x45
		copy(pkt[12:16], netip.MustParseAddr(src).AsSlice())
		return pkt
	}
	cases := map[string]struct {
		pkt  []byte
		want bool
	}{
		"leased address": {v4("10.9.0.23"), true},
		"another lease":  {v4("10.9.0.24"), false},
		"off pool":       {v4("192.168.1.5"), false},
		"unparsable":     {[]byte{0x45, 0x00}, false},
		"empty":          {nil, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := allowedSource(tc.pkt, leased); got != tc.want {
				t.Fatalf("allowedSource = %v, want %v", got, tc.want)
			}
		})
	}
}
