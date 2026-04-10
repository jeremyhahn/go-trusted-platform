// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// Pool Benchmarks

func BenchmarkPool_Clone(b *testing.B) {
	pool := &Pool{
		ID:                   "pool-1",
		Name:                 "Test Pool",
		CIDR:                 netip.MustParsePrefix("10.0.0.0/16"),
		Gateway:              netip.MustParseAddr("10.0.0.1"),
		Description:          "A test pool for benchmarking",
		Tags:                 []string{"test", "benchmark", "ipam"},
		TotalIPs:             65534,
		AllocatedIPs:         1000,
		AvailableIPs:         64534,
		DefaultLeaseDuration: 24 * time.Hour,
		InactivityTimeout:    30 * 24 * time.Hour,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pool.Clone()
	}
}

// Allocation Benchmarks

func BenchmarkAllocation_Clone(b *testing.B) {
	allocation := &Allocation{
		ID:          "alloc-1",
		PoolID:      "pool-1",
		IP:          netip.MustParseAddr("10.0.0.100"),
		DeviceID:    "device-123",
		Hostname:    "server-01.example.com",
		Description: "Web server allocation",
		Tags:        []string{"web", "production"},
		Metadata: map[string]string{
			"env":     "production",
			"team":    "platform",
			"project": "web-services",
		},
		AllocatedAt: time.Now(),
		LastSeen:    time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Status:      AllocationStatusActive,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = allocation.Clone()
	}
}

func BenchmarkAllocation_IsExpired(b *testing.B) {
	allocations := []*Allocation{
		{ExpiresAt: time.Time{}},                     // Never expires
		{ExpiresAt: time.Now().Add(24 * time.Hour)},  // Not expired
		{ExpiresAt: time.Now().Add(-24 * time.Hour)}, // Expired
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alloc := allocations[i%len(allocations)]
		_ = alloc.IsExpired()
	}
}

func BenchmarkAllocation_IsActive(b *testing.B) {
	allocations := []*Allocation{
		{Status: AllocationStatusActive, ExpiresAt: time.Time{}},
		{Status: AllocationStatusActive, ExpiresAt: time.Now().Add(24 * time.Hour)},
		{Status: AllocationStatusExpired, ExpiresAt: time.Now().Add(-24 * time.Hour)},
		{Status: AllocationStatusReleased},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alloc := allocations[i%len(allocations)]
		_ = alloc.IsActive()
	}
}

// AllocationRequest Benchmarks

func BenchmarkAllocationRequest_Validate(b *testing.B) {
	requests := []*AllocationRequest{
		{PoolID: "pool-1", DeviceID: "device-1"},
		{PoolID: "pool-1", DeviceID: "device-2", Hostname: "server-01"},
		{PoolID: "", DeviceID: "device-1"}, // Invalid
		{PoolID: "pool-1", DeviceID: ""},   // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := requests[i%len(requests)]
		_ = req.Validate()
	}
}

func BenchmarkAllocationRequest_Clone(b *testing.B) {
	request := &AllocationRequest{
		PoolID:        "pool-1",
		DeviceID:      "device-123",
		Hostname:      "server-01.example.com",
		Description:   "Web server allocation",
		Tags:          []string{"web", "production"},
		Metadata:      map[string]string{"env": "production", "team": "platform"},
		RequestedIP:   netip.MustParseAddr("10.0.0.100"),
		LeaseDuration: 24 * time.Hour,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = request.Clone()
	}
}

// AllocationStatus Benchmarks

func BenchmarkAllocationStatus_String(b *testing.B) {
	statuses := []AllocationStatus{
		AllocationStatusActive,
		AllocationStatusExpired,
		AllocationStatusReleased,
		AllocationStatusReserved,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		status := statuses[i%len(statuses)]
		_ = status.String()
	}
}

func BenchmarkAllocationStatus_IsValid(b *testing.B) {
	statuses := []AllocationStatus{
		AllocationStatusActive,
		AllocationStatusExpired,
		AllocationStatusReleased,
		AllocationStatusReserved,
		AllocationStatus("invalid"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		status := statuses[i%len(statuses)]
		_ = status.IsValid()
	}
}

// PoolStats Benchmarks

func BenchmarkPoolStats_CalculateUtilization(b *testing.B) {
	stats := []*PoolStats{
		{TotalIPs: 65534, AllocatedIPs: 32767},
		{TotalIPs: 254, AllocatedIPs: 100},
		{TotalIPs: 1048574, AllocatedIPs: 524287},
		{TotalIPs: 0, AllocatedIPs: 0}, // Edge case
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := stats[i%len(stats)]
		s.CalculateUtilization()
	}
}

// Pool Manager Benchmarks

func BenchmarkCalculatePoolSize(b *testing.B) {
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.0.0/30"),
		netip.MustParsePrefix("10.0.0.0/31"),
		netip.MustParsePrefix("10.0.0.0/32"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8::/64"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cidr := cidrs[i%len(cidrs)]
		_ = CalculatePoolSize(cidr)
	}
}

func BenchmarkIPToOffset(b *testing.B) {
	cidr := netip.MustParsePrefix("10.0.0.0/16")
	ips := []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.100"),
		netip.MustParseAddr("10.0.128.0"),
		netip.MustParseAddr("10.0.255.254"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := ips[i%len(ips)]
		_, _ = IPToOffset(cidr, ip)
	}
}

func BenchmarkOffsetToIP(b *testing.B) {
	cidr := netip.MustParsePrefix("10.0.0.0/16")
	offsets := []uint64{1, 100, 32768, 65533}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		offset := offsets[i%len(offsets)]
		_, _ = OffsetToIP(cidr, offset)
	}
}

func BenchmarkContainsIP(b *testing.B) {
	cidr := netip.MustParsePrefix("10.0.0.0/16")
	ips := []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),     // In range
		netip.MustParseAddr("10.0.255.254"), // In range
		netip.MustParseAddr("10.1.0.1"),     // Out of range
		netip.MustParseAddr("192.168.1.1"),  // Out of range
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := ips[i%len(ips)]
		_ = ContainsIP(cidr, ip)
	}
}

func BenchmarkIsNetworkOrBroadcast(b *testing.B) {
	cidr := netip.MustParsePrefix("10.0.0.0/24")
	ips := []netip.Addr{
		netip.MustParseAddr("10.0.0.0"),   // Network
		netip.MustParseAddr("10.0.0.255"), // Broadcast
		netip.MustParseAddr("10.0.0.1"),   // Usable
		netip.MustParseAddr("10.0.0.100"), // Usable
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := ips[i%len(ips)]
		_ = IsNetworkOrBroadcast(cidr, ip)
	}
}

func BenchmarkGetNetworkAddress(b *testing.B) {
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("2001:db8::/64"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cidr := cidrs[i%len(cidrs)]
		_ = GetNetworkAddress(cidr)
	}
}

func BenchmarkGetBroadcastAddress(b *testing.B) {
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/24"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cidr := cidrs[i%len(cidrs)]
		_ = GetBroadcastAddress(cidr)
	}
}

func BenchmarkGetFirstUsableIP(b *testing.B) {
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.0.0/30"),
		netip.MustParsePrefix("10.0.0.0/31"),
		netip.MustParsePrefix("2001:db8::/64"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cidr := cidrs[i%len(cidrs)]
		_, _ = GetFirstUsableIP(cidr)
	}
}

func BenchmarkGetLastUsableIP(b *testing.B) {
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.0.0/30"),
		netip.MustParsePrefix("10.0.0.0/31"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cidr := cidrs[i%len(cidrs)]
		_, _ = GetLastUsableIP(cidr)
	}
}

func BenchmarkSplitCIDR(b *testing.B) {
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/24"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cidr := cidrs[i%len(cidrs)]
		_, _, _ = SplitCIDR(cidr)
	}
}

func BenchmarkRandomIPInCIDR(b *testing.B) {
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/24"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cidr := cidrs[i%len(cidrs)]
		_, _ = RandomIPInCIDR(cidr)
	}
}

// Pool Manager Integration Benchmarks

func BenchmarkPoolManager_ValidatePool(b *testing.B) {
	pm := NewPoolManager()
	pools := []*Pool{
		{ID: "pool-1", Name: "Test Pool 1", CIDR: netip.MustParsePrefix("10.0.0.0/24")},
		{ID: "pool-2", Name: "Test Pool 2", CIDR: netip.MustParsePrefix("10.0.0.0/24"), Gateway: netip.MustParseAddr("10.0.0.1")},
		{ID: "", Name: "Invalid", CIDR: netip.MustParsePrefix("10.0.0.0/24")}, // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool := pools[i%len(pools)]
		_ = pm.ValidatePool(pool)
	}
}

func BenchmarkPoolManager_InitializePool(b *testing.B) {
	pm := NewPoolManager()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool := &Pool{
			ID:   fmt.Sprintf("pool-%d", i),
			Name: fmt.Sprintf("Test Pool %d", i),
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		pm.InitializePool(pool)
	}
}

func BenchmarkPoolManager_NextAvailableIP(b *testing.B) {
	pm := NewPoolManager()
	cidr := netip.MustParsePrefix("10.0.0.0/24")
	allocated := make(map[netip.Addr]bool)

	// Allocate first 100 IPs
	for i := 1; i <= 100; i++ {
		allocated[netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i))] = true
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pm.NextAvailableIP(cidr, allocated)
	}
}

// Parallel Benchmarks

func BenchmarkIPToOffset_Parallel(b *testing.B) {
	cidr := netip.MustParsePrefix("10.0.0.0/16")
	ips := make([]netip.Addr, 256)
	for i := 0; i < 256; i++ {
		ips[i] = netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/16, (i%16)*16))
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := ips[i%len(ips)]
			_, _ = IPToOffset(cidr, ip)
			i++
		}
	})
}

func BenchmarkContainsIP_Parallel(b *testing.B) {
	cidr := netip.MustParsePrefix("10.0.0.0/16")
	ips := make([]netip.Addr, 256)
	for i := 0; i < 256; i++ {
		ips[i] = netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i, i))
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := ips[i%len(ips)]
			_ = ContainsIP(cidr, ip)
			i++
		}
	})
}
