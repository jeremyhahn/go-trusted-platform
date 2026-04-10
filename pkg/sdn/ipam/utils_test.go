// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"net/netip"
	"testing"
)

func TestIsNetworkAddress(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		ip   string
		want bool
	}{
		{"IPv4 network address", "192.168.1.0/24", "192.168.1.0", true},
		{"IPv4 not network address", "192.168.1.0/24", "192.168.1.1", false},
		{"IPv4 /31 first", "192.168.1.0/31", "192.168.1.0", false},
		{"IPv4 /32", "192.168.1.1/32", "192.168.1.1", false},
		{"IPv6 address", "2001:db8::/64", "2001:db8::", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			ip := netip.MustParseAddr(tt.ip)
			got := IsNetworkAddress(cidr, ip)
			if got != tt.want {
				t.Errorf("IsNetworkAddress(%s, %s) = %v, want %v", tt.cidr, tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsBroadcastAddress(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		ip   string
		want bool
	}{
		{"IPv4 broadcast address", "192.168.1.0/24", "192.168.1.255", true},
		{"IPv4 not broadcast", "192.168.1.0/24", "192.168.1.254", false},
		{"IPv4 /30 broadcast", "192.168.1.0/30", "192.168.1.3", true},
		{"IPv4 /31 second", "192.168.1.0/31", "192.168.1.1", false},
		{"IPv4 /32", "192.168.1.1/32", "192.168.1.1", false},
		{"IPv6 address", "2001:db8::/64", "2001:db8::ffff", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			ip := netip.MustParseAddr(tt.ip)
			got := IsBroadcastAddress(cidr, ip)
			if got != tt.want {
				t.Errorf("IsBroadcastAddress(%s, %s) = %v, want %v", tt.cidr, tt.ip, got, tt.want)
			}
		})
	}
}

func TestNextUsableIP(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		want    string
		wantErr error
	}{
		{"IPv4 /24", "192.168.1.0/24", "192.168.1.1", nil},
		{"IPv4 /31", "192.168.1.0/31", "192.168.1.0", nil},
		{"IPv4 /32", "192.168.1.1/32", "192.168.1.1", nil},
		{"IPv6 /64", "2001:db8::/64", "2001:db8::", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			got, err := NextUsableIP(cidr)
			if err != tt.wantErr {
				t.Errorf("NextUsableIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			want := netip.MustParseAddr(tt.want)
			if got != want {
				t.Errorf("NextUsableIP(%s) = %v, want %v", tt.cidr, got, want)
			}
		})
	}
}

func TestLastUsableIP(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		want    string
		wantErr error
	}{
		{"IPv4 /24", "192.168.1.0/24", "192.168.1.254", nil},
		{"IPv4 /31", "192.168.1.0/31", "192.168.1.1", nil},
		{"IPv4 /32", "192.168.1.1/32", "192.168.1.1", nil},
		{"IPv6 /120", "2001:db8::/120", "2001:db8::ff", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			got, err := LastUsableIP(cidr)
			if err != tt.wantErr {
				t.Errorf("LastUsableIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			want := netip.MustParseAddr(tt.want)
			if got != want {
				t.Errorf("LastUsableIP(%s) = %v, want %v", tt.cidr, got, want)
			}
		})
	}
}

func TestCIDROverlaps(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"same CIDR", "192.168.1.0/24", "192.168.1.0/24", true},
		{"contained", "192.168.0.0/16", "192.168.1.0/24", true},
		{"contains", "192.168.1.0/24", "192.168.0.0/16", true},
		{"adjacent", "192.168.1.0/24", "192.168.2.0/24", false},
		{"disjoint", "192.168.1.0/24", "10.0.0.0/8", false},
		{"IPv6 overlapping", "2001:db8::/32", "2001:db8:1::/48", true},
		{"IPv6 disjoint", "2001:db8::/32", "2001:db9::/32", false},
		{"mixed families", "192.168.1.0/24", "2001:db8::/32", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := netip.MustParsePrefix(tt.a)
			b := netip.MustParsePrefix(tt.b)
			got := CIDROverlaps(a, b)
			if got != tt.want {
				t.Errorf("CIDROverlaps(%s, %s) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestIsUsableOffset(t *testing.T) {
	tests := []struct {
		name   string
		cidr   string
		offset uint64
		want   bool
	}{
		// IPv4 /24 - offsets 0 (network) and 255 (broadcast) are not usable
		{"IPv4 /24 network", "192.168.1.0/24", 0, false},
		{"IPv4 /24 first usable", "192.168.1.0/24", 1, true},
		{"IPv4 /24 last usable", "192.168.1.0/24", 254, true},
		{"IPv4 /24 broadcast", "192.168.1.0/24", 255, false},
		{"IPv4 /24 out of range", "192.168.1.0/24", 256, false},

		// IPv4 /31 - both addresses are usable
		{"IPv4 /31 first", "192.168.1.0/31", 0, true},
		{"IPv4 /31 second", "192.168.1.0/31", 1, true},
		{"IPv4 /31 out of range", "192.168.1.0/31", 2, false},

		// IPv4 /32 - single address
		{"IPv4 /32", "192.168.1.1/32", 0, true},
		{"IPv4 /32 out of range", "192.168.1.1/32", 1, false},

		// IPv6 - all addresses usable
		{"IPv6 /120 first", "2001:db8::/120", 0, true},
		{"IPv6 /120 last", "2001:db8::/120", 255, true},
		{"IPv6 /120 out of range", "2001:db8::/120", 256, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			got := IsUsableOffset(cidr, tt.offset)
			if got != tt.want {
				t.Errorf("IsUsableOffset(%s, %d) = %v, want %v", tt.cidr, tt.offset, got, tt.want)
			}
		})
	}
}

func TestAdjustOffsetForUsable(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		usableIndex uint64
		want        uint64
	}{
		// IPv4 /24 - add 1 to skip network address
		{"IPv4 /24 index 0", "192.168.1.0/24", 0, 1},
		{"IPv4 /24 index 1", "192.168.1.0/24", 1, 2},
		{"IPv4 /24 index 253", "192.168.1.0/24", 253, 254},

		// IPv4 /31 - no adjustment needed
		{"IPv4 /31 index 0", "192.168.1.0/31", 0, 0},
		{"IPv4 /31 index 1", "192.168.1.0/31", 1, 1},

		// IPv4 /32 - no adjustment needed
		{"IPv4 /32 index 0", "192.168.1.1/32", 0, 0},

		// IPv6 - no adjustment needed
		{"IPv6 /120 index 0", "2001:db8::/120", 0, 0},
		{"IPv6 /120 index 100", "2001:db8::/120", 100, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			got := AdjustOffsetForUsable(cidr, tt.usableIndex)
			if got != tt.want {
				t.Errorf("AdjustOffsetForUsable(%s, %d) = %v, want %v", tt.cidr, tt.usableIndex, got, tt.want)
			}
		})
	}
}
