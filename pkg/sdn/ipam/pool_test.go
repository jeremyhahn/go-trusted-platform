// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"net/netip"
	"testing"
)

func TestPoolManager_ValidatePool(t *testing.T) {
	pm := NewPoolManager()

	tests := []struct {
		name    string
		pool    *Pool
		wantErr error
	}{
		{
			name: "valid pool",
			pool: &Pool{
				ID:   "pool-1",
				Name: "test-pool",
				CIDR: netip.MustParsePrefix("192.168.1.0/24"),
			},
			wantErr: nil,
		},
		{
			name: "valid pool with gateway",
			pool: &Pool{
				ID:      "pool-1",
				Name:    "test-pool",
				CIDR:    netip.MustParsePrefix("192.168.1.0/24"),
				Gateway: netip.MustParseAddr("192.168.1.1"),
			},
			wantErr: nil,
		},
		{
			name:    "nil pool",
			pool:    nil,
			wantErr: ErrPoolNotFound,
		},
		{
			name: "missing ID",
			pool: &Pool{
				Name: "test-pool",
				CIDR: netip.MustParsePrefix("192.168.1.0/24"),
			},
			wantErr: ErrInvalidPoolID,
		},
		{
			name: "missing name",
			pool: &Pool{
				ID:   "pool-1",
				CIDR: netip.MustParsePrefix("192.168.1.0/24"),
			},
			wantErr: ErrInvalidPoolName,
		},
		{
			name: "invalid CIDR",
			pool: &Pool{
				ID:   "pool-1",
				Name: "test-pool",
			},
			wantErr: ErrInvalidCIDR,
		},
		{
			name: "gateway outside CIDR",
			pool: &Pool{
				ID:      "pool-1",
				Name:    "test-pool",
				CIDR:    netip.MustParsePrefix("192.168.1.0/24"),
				Gateway: netip.MustParseAddr("10.0.0.1"),
			},
			wantErr: ErrInvalidGateway,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pm.ValidatePool(tt.pool)
			if err != tt.wantErr {
				t.Errorf("ValidatePool() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPoolManager_InitializePool(t *testing.T) {
	pm := NewPoolManager()

	pool := &Pool{
		ID:   "pool-1",
		Name: "test-pool",
		CIDR: netip.MustParsePrefix("192.168.1.0/24"),
	}

	pm.InitializePool(pool)

	// Check defaults were set
	if pool.TotalIPs != 254 {
		t.Errorf("TotalIPs = %v, want 254", pool.TotalIPs)
	}
	if pool.AvailableIPs != 254 {
		t.Errorf("AvailableIPs = %v, want 254", pool.AvailableIPs)
	}
	if pool.AllocatedIPs != 0 {
		t.Errorf("AllocatedIPs = %v, want 0", pool.AllocatedIPs)
	}
	if pool.InactivityTimeout != DefaultInactivityTimeout {
		t.Errorf("InactivityTimeout = %v, want %v", pool.InactivityTimeout, DefaultInactivityTimeout)
	}
	if pool.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if pool.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should not be zero")
	}
}

func TestCalculatePoolSize(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		want uint64
	}{
		// IPv4 tests
		{"IPv4 /24", "192.168.1.0/24", 254},
		{"IPv4 /25", "192.168.1.0/25", 126},
		{"IPv4 /30", "192.168.1.0/30", 2},
		{"IPv4 /31 point-to-point", "192.168.1.0/31", 2},
		{"IPv4 /32 single host", "192.168.1.1/32", 1},
		{"IPv4 /16", "192.168.0.0/16", 65534},
		{"IPv4 /8", "10.0.0.0/8", 16777214},

		// IPv6 tests
		{"IPv6 /64", "2001:db8::/64", ^uint64(0)}, // Max uint64
		{"IPv6 /120", "2001:db8::/120", 256},
		{"IPv6 /126", "2001:db8::/126", 4},
		{"IPv6 /127", "2001:db8::/127", 2},
		{"IPv6 /128 single host", "2001:db8::1/128", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			got := CalculatePoolSize(cidr)
			if got != tt.want {
				t.Errorf("CalculatePoolSize(%s) = %v, want %v", tt.cidr, got, tt.want)
			}
		})
	}

	t.Run("invalid CIDR", func(t *testing.T) {
		got := CalculatePoolSize(netip.Prefix{})
		if got != 0 {
			t.Errorf("CalculatePoolSize(invalid) = %v, want 0", got)
		}
	})
}

func TestIPToOffset(t *testing.T) {
	tests := []struct {
		name       string
		cidr       string
		ip         string
		wantOffset uint64
		wantErr    error
	}{
		// IPv4 tests
		{"IPv4 network address", "192.168.1.0/24", "192.168.1.0", 0, nil},
		{"IPv4 first usable", "192.168.1.0/24", "192.168.1.1", 1, nil},
		{"IPv4 middle", "192.168.1.0/24", "192.168.1.100", 100, nil},
		{"IPv4 last usable", "192.168.1.0/24", "192.168.1.254", 254, nil},
		{"IPv4 broadcast", "192.168.1.0/24", "192.168.1.255", 255, nil},

		// IPv6 tests
		{"IPv6 first", "2001:db8::/120", "2001:db8::", 0, nil},
		{"IPv6 offset 10", "2001:db8::/120", "2001:db8::a", 10, nil},
		{"IPv6 last", "2001:db8::/120", "2001:db8::ff", 255, nil},

		// Error cases
		{"IP not in pool", "192.168.1.0/24", "10.0.0.1", 0, ErrIPNotInPool},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			ip := netip.MustParseAddr(tt.ip)
			offset, err := IPToOffset(cidr, ip)
			if err != tt.wantErr {
				t.Errorf("IPToOffset() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && offset != tt.wantOffset {
				t.Errorf("IPToOffset() = %v, want %v", offset, tt.wantOffset)
			}
		})
	}

	t.Run("invalid CIDR", func(t *testing.T) {
		_, err := IPToOffset(netip.Prefix{}, netip.MustParseAddr("192.168.1.1"))
		if err != ErrInvalidCIDR {
			t.Errorf("IPToOffset(invalid CIDR) error = %v, want ErrInvalidCIDR", err)
		}
	})

	t.Run("invalid IP", func(t *testing.T) {
		_, err := IPToOffset(netip.MustParsePrefix("192.168.1.0/24"), netip.Addr{})
		if err != ErrInvalidIP {
			t.Errorf("IPToOffset(invalid IP) error = %v, want ErrInvalidIP", err)
		}
	})

	t.Run("address family mismatch", func(t *testing.T) {
		_, err := IPToOffset(netip.MustParsePrefix("192.168.1.0/24"), netip.MustParseAddr("2001:db8::1"))
		if _, ok := err.(*ErrCIDRMismatch); !ok {
			t.Errorf("IPToOffset(mismatch) error = %v, want ErrCIDRMismatch", err)
		}
	})
}

func TestOffsetToIP(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		offset  uint64
		wantIP  string
		wantErr error
	}{
		// IPv4 tests
		{"IPv4 offset 0", "192.168.1.0/24", 0, "192.168.1.0", nil},
		{"IPv4 offset 1", "192.168.1.0/24", 1, "192.168.1.1", nil},
		{"IPv4 offset 100", "192.168.1.0/24", 100, "192.168.1.100", nil},
		{"IPv4 offset 255", "192.168.1.0/24", 255, "192.168.1.255", nil},
		{"IPv4 offset out of range", "192.168.1.0/24", 256, "", ErrInvalidOffset},

		// IPv6 tests
		{"IPv6 offset 0", "2001:db8::/120", 0, "2001:db8::", nil},
		{"IPv6 offset 10", "2001:db8::/120", 10, "2001:db8::a", nil},
		{"IPv6 offset 255", "2001:db8::/120", 255, "2001:db8::ff", nil},
		{"IPv6 offset out of range", "2001:db8::/120", 256, "", ErrInvalidOffset},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			ip, err := OffsetToIP(cidr, tt.offset)
			if err != tt.wantErr {
				t.Errorf("OffsetToIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				wantIP := netip.MustParseAddr(tt.wantIP)
				if ip != wantIP {
					t.Errorf("OffsetToIP() = %v, want %v", ip, wantIP)
				}
			}
		})
	}

	t.Run("invalid CIDR", func(t *testing.T) {
		_, err := OffsetToIP(netip.Prefix{}, 0)
		if err != ErrInvalidCIDR {
			t.Errorf("OffsetToIP(invalid CIDR) error = %v, want ErrInvalidCIDR", err)
		}
	})
}

func TestContainsIP(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		ip   string
		want bool
	}{
		{"IPv4 contains", "192.168.1.0/24", "192.168.1.100", true},
		{"IPv4 not contains", "192.168.1.0/24", "10.0.0.1", false},
		{"IPv4 boundary low", "192.168.1.0/24", "192.168.1.0", true},
		{"IPv4 boundary high", "192.168.1.0/24", "192.168.1.255", true},
		{"IPv4 just outside", "192.168.1.0/24", "192.168.2.0", false},
		{"IPv6 contains", "2001:db8::/32", "2001:db8::1", true},
		{"IPv6 not contains", "2001:db8::/32", "2001:db9::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			ip := netip.MustParseAddr(tt.ip)
			got := ContainsIP(cidr, ip)
			if got != tt.want {
				t.Errorf("ContainsIP(%s, %s) = %v, want %v", tt.cidr, tt.ip, got, tt.want)
			}
		})
	}

	t.Run("address family mismatch", func(t *testing.T) {
		cidr := netip.MustParsePrefix("192.168.1.0/24")
		ip := netip.MustParseAddr("2001:db8::1")
		if ContainsIP(cidr, ip) {
			t.Error("ContainsIP() should return false for address family mismatch")
		}
	})

	t.Run("invalid inputs", func(t *testing.T) {
		if ContainsIP(netip.Prefix{}, netip.MustParseAddr("192.168.1.1")) {
			t.Error("ContainsIP(invalid CIDR) should return false")
		}
		if ContainsIP(netip.MustParsePrefix("192.168.1.0/24"), netip.Addr{}) {
			t.Error("ContainsIP(invalid IP) should return false")
		}
	})
}

func TestIsNetworkOrBroadcast(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		ip   string
		want bool
	}{
		{"IPv4 network address", "192.168.1.0/24", "192.168.1.0", true},
		{"IPv4 broadcast address", "192.168.1.0/24", "192.168.1.255", true},
		{"IPv4 usable address", "192.168.1.0/24", "192.168.1.100", false},
		{"IPv4 /31 first", "192.168.1.0/31", "192.168.1.0", false},
		{"IPv4 /31 second", "192.168.1.0/31", "192.168.1.1", false},
		{"IPv4 /32 single", "192.168.1.1/32", "192.168.1.1", false},
		{"IPv6 any address", "2001:db8::/64", "2001:db8::", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			ip := netip.MustParseAddr(tt.ip)
			got := IsNetworkOrBroadcast(cidr, ip)
			if got != tt.want {
				t.Errorf("IsNetworkOrBroadcast(%s, %s) = %v, want %v", tt.cidr, tt.ip, got, tt.want)
			}
		})
	}
}

func TestGetNetworkAddress(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		want string
	}{
		{"IPv4 /24", "192.168.1.0/24", "192.168.1.0"},
		{"IPv4 /24 non-zero", "192.168.1.128/24", "192.168.1.0"},
		{"IPv4 /16", "192.168.0.0/16", "192.168.0.0"},
		{"IPv6 /64", "2001:db8:abcd::/64", "2001:db8:abcd::"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			want := netip.MustParseAddr(tt.want)
			got := GetNetworkAddress(cidr)
			if got != want {
				t.Errorf("GetNetworkAddress(%s) = %v, want %v", tt.cidr, got, want)
			}
		})
	}

	t.Run("invalid CIDR", func(t *testing.T) {
		got := GetNetworkAddress(netip.Prefix{})
		if got.IsValid() {
			t.Error("GetNetworkAddress(invalid) should return invalid address")
		}
	})
}

func TestGetBroadcastAddress(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		want string
	}{
		{"IPv4 /24", "192.168.1.0/24", "192.168.1.255"},
		{"IPv4 /25", "192.168.1.0/25", "192.168.1.127"},
		{"IPv4 /30", "192.168.1.0/30", "192.168.1.3"},
		{"IPv4 /16", "192.168.0.0/16", "192.168.255.255"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			want := netip.MustParseAddr(tt.want)
			got := GetBroadcastAddress(cidr)
			if got != want {
				t.Errorf("GetBroadcastAddress(%s) = %v, want %v", tt.cidr, got, want)
			}
		})
	}

	t.Run("IPv6 returns invalid", func(t *testing.T) {
		got := GetBroadcastAddress(netip.MustParsePrefix("2001:db8::/64"))
		if got.IsValid() {
			t.Error("GetBroadcastAddress(IPv6) should return invalid address")
		}
	})

	t.Run("invalid CIDR", func(t *testing.T) {
		got := GetBroadcastAddress(netip.Prefix{})
		if got.IsValid() {
			t.Error("GetBroadcastAddress(invalid) should return invalid address")
		}
	})
}

func TestGetFirstUsableIP(t *testing.T) {
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
			got, err := GetFirstUsableIP(cidr)
			if err != tt.wantErr {
				t.Errorf("GetFirstUsableIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			want := netip.MustParseAddr(tt.want)
			if got != want {
				t.Errorf("GetFirstUsableIP(%s) = %v, want %v", tt.cidr, got, want)
			}
			if alias, err := NextUsableIP(cidr); err != nil || alias != want {
				t.Errorf("NextUsableIP(%s) = %v, %v, want %v", tt.cidr, alias, err, want)
			}
		})
	}

	t.Run("invalid CIDR", func(t *testing.T) {
		_, err := GetFirstUsableIP(netip.Prefix{})
		if err != ErrInvalidCIDR {
			t.Errorf("GetFirstUsableIP(invalid) error = %v, want ErrInvalidCIDR", err)
		}
	})
}

func TestGetLastUsableIP(t *testing.T) {
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
			got, err := GetLastUsableIP(cidr)
			if err != tt.wantErr {
				t.Errorf("GetLastUsableIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			want := netip.MustParseAddr(tt.want)
			if got != want {
				t.Errorf("GetLastUsableIP(%s) = %v, want %v", tt.cidr, got, want)
			}
			if alias, err := LastUsableIP(cidr); err != nil || alias != want {
				t.Errorf("LastUsableIP(%s) = %v, %v, want %v", tt.cidr, alias, err, want)
			}
		})
	}

	t.Run("invalid CIDR", func(t *testing.T) {
		_, err := GetLastUsableIP(netip.Prefix{})
		if err != ErrInvalidCIDR {
			t.Errorf("GetLastUsableIP(invalid) error = %v, want ErrInvalidCIDR", err)
		}
	})
}

func TestSplitCIDR(t *testing.T) {
	tests := []struct {
		name       string
		cidr       string
		wantFirst  string
		wantSecond string
		wantErr    error
	}{
		{"IPv4 /24", "192.168.1.0/24", "192.168.1.0/25", "192.168.1.128/25", nil},
		{"IPv4 /30", "192.168.1.0/30", "192.168.1.0/31", "192.168.1.2/31", nil},
		{"IPv6 /64", "2001:db8::/64", "2001:db8::/65", "2001:db8:0:0:8000::/65", nil},
		{"IPv4 /32 cannot split", "192.168.1.1/32", "", "", ErrInvalidCIDR},
		{"IPv6 /128 cannot split", "2001:db8::1/128", "", "", ErrInvalidCIDR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			first, second, err := SplitCIDR(cidr)
			if err != tt.wantErr {
				t.Errorf("SplitCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				wantFirst := netip.MustParsePrefix(tt.wantFirst)
				wantSecond := netip.MustParsePrefix(tt.wantSecond)
				if first != wantFirst {
					t.Errorf("SplitCIDR() first = %v, want %v", first, wantFirst)
				}
				if second != wantSecond {
					t.Errorf("SplitCIDR() second = %v, want %v", second, wantSecond)
				}
			}
		})
	}

	t.Run("invalid CIDR", func(t *testing.T) {
		_, _, err := SplitCIDR(netip.Prefix{})
		if err != ErrInvalidCIDR {
			t.Errorf("SplitCIDR(invalid) error = %v, want ErrInvalidCIDR", err)
		}
	})
}

func TestRandomIPInCIDR(t *testing.T) {
	tests := []struct {
		name string
		cidr string
	}{
		{"IPv4 /24", "192.168.1.0/24"},
		{"IPv4 /30", "192.168.1.0/30"},
		{"IPv6 /120", "2001:db8::/120"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			ip, err := RandomIPInCIDR(cidr)
			if err != nil {
				t.Fatalf("RandomIPInCIDR() error = %v", err)
			}

			// Verify IP is within CIDR
			if !cidr.Contains(ip) {
				t.Errorf("RandomIPInCIDR() returned IP %v not in CIDR %s", ip, tt.cidr)
			}

			// For IPv4, verify it's not network or broadcast
			if ip.Is4() && cidr.Bits() < 31 {
				if IsNetworkOrBroadcast(cidr, ip) {
					t.Errorf("RandomIPInCIDR() returned network/broadcast address %v", ip)
				}
			}
		})
	}

	t.Run("invalid CIDR", func(t *testing.T) {
		_, err := RandomIPInCIDR(netip.Prefix{})
		if err != ErrInvalidCIDR {
			t.Errorf("RandomIPInCIDR(invalid) error = %v, want ErrInvalidCIDR", err)
		}
	})
}

func TestPoolManager_NextAvailableIP(t *testing.T) {
	pm := NewPoolManager()

	t.Run("returns first usable IP when no allocations", func(t *testing.T) {
		cidr := netip.MustParsePrefix("192.168.1.0/30")
		allocated := make(map[netip.Addr]bool)

		ip, err := pm.NextAvailableIP(cidr, allocated)
		if err != nil {
			t.Fatalf("NextAvailableIP() error = %v", err)
		}

		// First usable in /30 is .1
		want := netip.MustParseAddr("192.168.1.1")
		if ip != want {
			t.Errorf("NextAvailableIP() = %v, want %v", ip, want)
		}
	})

	t.Run("skips allocated IPs", func(t *testing.T) {
		cidr := netip.MustParsePrefix("192.168.1.0/30")
		allocated := map[netip.Addr]bool{
			netip.MustParseAddr("192.168.1.1"): true,
		}

		ip, err := pm.NextAvailableIP(cidr, allocated)
		if err != nil {
			t.Fatalf("NextAvailableIP() error = %v", err)
		}

		// With .1 allocated, next is .2
		want := netip.MustParseAddr("192.168.1.2")
		if ip != want {
			t.Errorf("NextAvailableIP() = %v, want %v", ip, want)
		}
	})

	t.Run("returns error when pool exhausted", func(t *testing.T) {
		cidr := netip.MustParsePrefix("192.168.1.0/30")
		// Allocate both usable IPs in /30
		allocated := map[netip.Addr]bool{
			netip.MustParseAddr("192.168.1.1"): true,
			netip.MustParseAddr("192.168.1.2"): true,
		}

		_, err := pm.NextAvailableIP(cidr, allocated)
		if err != ErrPoolExhausted {
			t.Errorf("NextAvailableIP() error = %v, want ErrPoolExhausted", err)
		}
	})

	t.Run("invalid CIDR", func(t *testing.T) {
		_, err := pm.NextAvailableIP(netip.Prefix{}, make(map[netip.Addr]bool))
		if err != ErrInvalidCIDR {
			t.Errorf("NextAvailableIP(invalid) error = %v, want ErrInvalidCIDR", err)
		}
	})
}
