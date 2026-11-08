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

package dhcp

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// LeaseStore Benchmarks

func BenchmarkLeaseStore_Add(b *testing.B) {
	store := NewLeaseStore()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lease := &Lease{
			IP:        netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/256%256, i%256)),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, byte(i >> 16), byte(i >> 8), byte(i)},
			Hostname:  fmt.Sprintf("host-%d", i),
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			State:     LeaseStateActive,
		}
		_ = store.Add(lease)
	}
}

func BenchmarkLeaseStore_GetByIP(b *testing.B) {
	store := NewLeaseStore()

	// Pre-populate store
	leases := make([]*Lease, 1000)
	for i := 0; i < 1000; i++ {
		lease := &Lease{
			IP:        netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x00, byte(i >> 8), byte(i)},
			Hostname:  fmt.Sprintf("host-%d", i),
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			State:     LeaseStateActive,
		}
		_ = store.Add(lease)
		leases[i] = lease
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := leases[i%len(leases)].IP
		_, _ = store.GetByIP(ip)
	}
}

func BenchmarkLeaseStore_GetByMAC(b *testing.B) {
	store := NewLeaseStore()

	// Pre-populate store
	leases := make([]*Lease, 1000)
	for i := 0; i < 1000; i++ {
		lease := &Lease{
			IP:        netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x00, byte(i >> 8), byte(i)},
			Hostname:  fmt.Sprintf("host-%d", i),
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			State:     LeaseStateActive,
		}
		_ = store.Add(lease)
		leases[i] = lease
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mac := leases[i%len(leases)].MAC
		_, _ = store.GetByMAC(mac)
	}
}

func BenchmarkLeaseStore_Remove(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		store := NewLeaseStore()
		lease := &Lease{
			IP:        netip.MustParseAddr("10.0.0.1"),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc},
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			State:     LeaseStateActive,
		}
		_ = store.Add(lease)
		b.StartTimer()

		_ = store.Remove(lease.IP)
	}
}

func BenchmarkLeaseStore_Renew(b *testing.B) {
	store := NewLeaseStore()

	// Pre-populate store
	leases := make([]*Lease, 100)
	for i := 0; i < 100; i++ {
		lease := &Lease{
			IP:        netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i+1)),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x00, 0x00, byte(i)},
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			State:     LeaseStateActive,
		}
		_ = store.Add(lease)
		leases[i] = lease
	}

	duration := 24 * time.Hour

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := leases[i%len(leases)].IP
		_ = store.Renew(ip, duration)
	}
}

func BenchmarkLeaseStore_Count(b *testing.B) {
	store := NewLeaseStore()

	// Pre-populate store
	for i := 0; i < 1000; i++ {
		lease := &Lease{
			IP:        netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x00, byte(i >> 8), byte(i)},
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			State:     LeaseStateActive,
		}
		_ = store.Add(lease)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.Count()
	}
}

func BenchmarkLeaseStore_CountActive(b *testing.B) {
	store := NewLeaseStore()

	// Pre-populate store with mixed active/expired leases
	for i := 0; i < 1000; i++ {
		lease := &Lease{
			IP:        netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x00, byte(i >> 8), byte(i)},
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			State:     LeaseStateActive,
		}
		// Make 50% expired
		if i%2 == 0 {
			lease.ExpiresAt = time.Now().Add(-24 * time.Hour)
			lease.State = LeaseStateExpired
		} else {
			lease.ExpiresAt = time.Now().Add(24 * time.Hour)
		}
		_ = store.Add(lease)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.CountActive()
	}
}

func BenchmarkLeaseStore_All(b *testing.B) {
	store := NewLeaseStore()

	// Pre-populate store
	for i := 0; i < 1000; i++ {
		lease := &Lease{
			IP:        netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x00, byte(i >> 8), byte(i)},
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			State:     LeaseStateActive,
		}
		_ = store.Add(lease)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.All()
	}
}

func BenchmarkLeaseStore_AllActive(b *testing.B) {
	store := NewLeaseStore()

	// Pre-populate store with mixed active/expired leases
	for i := 0; i < 1000; i++ {
		lease := &Lease{
			IP:        netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x00, byte(i >> 8), byte(i)},
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			State:     LeaseStateActive,
		}
		if i%2 == 0 {
			lease.ExpiresAt = time.Now().Add(-24 * time.Hour)
			lease.State = LeaseStateExpired
		} else {
			lease.ExpiresAt = time.Now().Add(24 * time.Hour)
		}
		_ = store.Add(lease)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.AllActive()
	}
}

// Lease Benchmarks

func BenchmarkLease_Clone(b *testing.B) {
	lease := &Lease{
		IP:          netip.MustParseAddr("10.0.0.100"),
		MAC:         net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc},
		Hostname:    "server-01.example.com",
		PoolID:      "pool-1",
		Interface:   "eth0",
		ClientID:    []byte{0x01, 0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc},
		VendorClass: "PXEClient",
		UserClass:   "Linux",
		LeasedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		RenewedAt:   time.Now(),
		State:       LeaseStateActive,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lease.Clone()
	}
}

func BenchmarkLease_IsExpired(b *testing.B) {
	leases := []*Lease{
		{ExpiresAt: time.Time{}},                     // Never expires
		{ExpiresAt: time.Now().Add(24 * time.Hour)},  // Not expired
		{ExpiresAt: time.Now().Add(-24 * time.Hour)}, // Expired
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lease := leases[i%len(leases)]
		_ = lease.IsExpired()
	}
}

func BenchmarkLease_IsActive(b *testing.B) {
	leases := []*Lease{
		{State: LeaseStateActive, ExpiresAt: time.Time{}},
		{State: LeaseStateActive, ExpiresAt: time.Now().Add(24 * time.Hour)},
		{State: LeaseStateExpired, ExpiresAt: time.Now().Add(-24 * time.Hour)},
		{State: LeaseStateReleased},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lease := leases[i%len(leases)]
		_ = lease.IsActive()
	}
}

func BenchmarkLease_TimeRemaining(b *testing.B) {
	leases := []*Lease{
		{ExpiresAt: time.Time{}},                     // Zero time
		{ExpiresAt: time.Now().Add(24 * time.Hour)},  // Future
		{ExpiresAt: time.Now().Add(-24 * time.Hour)}, // Past
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lease := leases[i%len(leases)]
		_ = lease.TimeRemaining()
	}
}

// LeaseState Benchmarks

func BenchmarkLeaseState_String(b *testing.B) {
	states := []LeaseState{
		LeaseStateActive,
		LeaseStateExpired,
		LeaseStateReleased,
		LeaseStateDeclined,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.String()
	}
}

func BenchmarkLeaseState_IsValid(b *testing.B) {
	states := []LeaseState{
		LeaseStateActive,
		LeaseStateExpired,
		LeaseStateReleased,
		LeaseStateDeclined,
		LeaseState(100), // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.IsValid()
	}
}

// LeaseRequest Benchmarks

func BenchmarkLeaseRequest_Validate(b *testing.B) {
	requests := []*LeaseRequest{
		{MAC: net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc}, PoolID: "pool-1"},
		{MAC: nil, PoolID: "pool-1"}, // Invalid
		{MAC: net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc}, PoolID: ""}, // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := requests[i%len(requests)]
		_ = req.Validate()
	}
}

func BenchmarkLeaseRequest_Clone(b *testing.B) {
	request := &LeaseRequest{
		MAC:           net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc},
		PoolID:        "pool-1",
		Interface:     "eth0",
		Hostname:      "server-01",
		RequestedIP:   netip.MustParseAddr("10.0.0.100"),
		LeaseDuration: 24 * time.Hour,
		ClientID:      []byte{0x01, 0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc},
		VendorClass:   "PXEClient",
		UserClass:     "Linux",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = request.Clone()
	}
}

// DHCPOptions Benchmarks

func BenchmarkDHCPOptions_Clone(b *testing.B) {
	options := &DHCPOptions{
		SubnetMask: net.IPMask{255, 255, 255, 0},
		Router:     netip.MustParseAddr("10.0.0.1"),
		DNS: []netip.Addr{
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("8.8.4.4"),
		},
		DomainName:  "example.com",
		LeaseTime:   24 * time.Hour,
		RenewalTime: 12 * time.Hour,
		RebindTime:  21 * time.Hour,
		NTPServers: []netip.Addr{
			netip.MustParseAddr("129.6.15.28"),
		},
		MTU:          1500,
		Hostname:     "server-01",
		NextServer:   net.ParseIP("10.0.0.10"),
		BootFileName: "pxelinux.0",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = options.Clone()
	}
}

func BenchmarkDHCPOptions_Validate(b *testing.B) {
	options := &DHCPOptions{
		LeaseTime:   0, // Will be set to default
		RenewalTime: 0, // Will be calculated
		RebindTime:  0, // Will be calculated
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = options.Validate()
	}
}

// InterfaceConfig Benchmarks

func BenchmarkInterfaceConfig_Validate(b *testing.B) {
	configs := []*InterfaceConfig{
		{Name: "eth0", Address: netip.MustParseAddr("10.0.0.1"), PoolID: "pool-1", Network: NetworkPrivate},
		{Name: "", Address: netip.MustParseAddr("10.0.0.1"), PoolID: "pool-1"}, // Invalid
		{Name: "eth0", Address: netip.Addr{}, PoolID: "pool-1"},                // Invalid
		{Name: "eth0", Address: netip.MustParseAddr("10.0.0.1"), PoolID: ""},   // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := configs[i%len(configs)]
		_ = config.Validate()
	}
}

func BenchmarkInterfaceConfig_Clone(b *testing.B) {
	config := &InterfaceConfig{
		Name:    "eth0",
		Network: NetworkPrivate,
		Address: netip.MustParseAddr("10.0.0.1"),
		PoolID:  "pool-1",
		Options: DHCPOptions{
			SubnetMask: net.IPMask{255, 255, 255, 0},
			Router:     netip.MustParseAddr("10.0.0.1"),
			DNS:        []netip.Addr{netip.MustParseAddr("8.8.8.8")},
			LeaseTime:  24 * time.Hour,
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.Clone()
	}
}

// ServerConfig Benchmarks

func BenchmarkServerConfig_Validate(b *testing.B) {
	config := &ServerConfig{
		Interfaces: []InterfaceConfig{
			{Name: "eth0", Address: netip.MustParseAddr("10.0.0.1"), PoolID: "pool-1"},
			{Name: "eth1", Address: netip.MustParseAddr("192.168.1.1"), PoolID: "pool-2"},
		},
		DefaultLeaseDuration: 24 * time.Hour,
		IPAMBackend:          IPAMBackendMemory,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.Validate()
	}
}

func BenchmarkServerConfig_Clone(b *testing.B) {
	config := &ServerConfig{
		Interfaces: []InterfaceConfig{
			{Name: "eth0", Address: netip.MustParseAddr("10.0.0.1"), PoolID: "pool-1"},
			{Name: "eth1", Address: netip.MustParseAddr("192.168.1.1"), PoolID: "pool-2"},
		},
		DefaultLeaseDuration: 24 * time.Hour,
		IPAMBackend:          IPAMBackendMemory,
		IPAMConfig:           map[string]string{"key1": "value1", "key2": "value2"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.Clone()
	}
}

// PXEOptions Benchmarks

func BenchmarkPXEOptions_Validate(b *testing.B) {
	options := []*PXEOptions{
		{NextServer: net.ParseIP("10.0.0.10"), BootFileName: "pxelinux.0"},
		{NextServer: nil, BootFileName: "pxelinux.0"},            // Invalid
		{NextServer: net.ParseIP("10.0.0.10"), BootFileName: ""}, // Invalid
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opt := options[i%len(options)]
		_ = opt.Validate()
	}
}

func BenchmarkPXEOptions_Clone(b *testing.B) {
	options := &PXEOptions{
		NextServer:   net.ParseIP("10.0.0.10"),
		BootFileName: "pxelinux.0",
		TFTPRoot:     "/tftpboot",
		ArchitectureFilters: map[uint16]string{
			0: "pxelinux.0",
			7: "bootx64.efi",
			9: "bootaa64.efi",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = options.Clone()
	}
}

func BenchmarkPXEOptions_GetBootFileForArch(b *testing.B) {
	options := &PXEOptions{
		NextServer:   net.ParseIP("10.0.0.10"),
		BootFileName: "pxelinux.0",
		ArchitectureFilters: map[uint16]string{
			0: "pxelinux.0",
			7: "bootx64.efi",
			9: "bootaa64.efi",
		},
	}

	archs := []uint16{0, 7, 9, 15} // 15 is not in filters

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		arch := archs[i%len(archs)]
		_ = options.GetBootFileForArch(arch)
	}
}

// ServerStats Benchmarks

func BenchmarkServerStats_Clone(b *testing.B) {
	stats := &ServerStats{
		StartedAt:       time.Now(),
		PacketsReceived: 100000,
		PacketsSent:     100000,
		DiscoverCount:   25000,
		OfferCount:      25000,
		RequestCount:    25000,
		AckCount:        25000,
		NakCount:        100,
		ReleaseCount:    1000,
		DeclineCount:    50,
		InformCount:     500,
		ErrorCount:      10,
		ActiveLeases:    500,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = stats.Clone()
	}
}

// Parallel Benchmarks

func BenchmarkLeaseStore_GetByIP_Parallel(b *testing.B) {
	store := NewLeaseStore()

	// Pre-populate store
	leases := make([]*Lease, 1000)
	for i := 0; i < 1000; i++ {
		lease := &Lease{
			IP:        netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x00, byte(i >> 8), byte(i)},
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			State:     LeaseStateActive,
		}
		_ = store.Add(lease)
		leases[i] = lease
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := leases[i%len(leases)].IP
			_, _ = store.GetByIP(ip)
			i++
		}
	})
}

func BenchmarkLeaseStore_GetByMAC_Parallel(b *testing.B) {
	store := NewLeaseStore()

	// Pre-populate store
	leases := make([]*Lease, 1000)
	for i := 0; i < 1000; i++ {
		lease := &Lease{
			IP:        netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x00, byte(i >> 8), byte(i)},
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			State:     LeaseStateActive,
		}
		_ = store.Add(lease)
		leases[i] = lease
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			mac := leases[i%len(leases)].MAC
			_, _ = store.GetByMAC(mac)
			i++
		}
	})
}

func BenchmarkLeaseStore_Add_Parallel(b *testing.B) {
	store := NewLeaseStore()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			lease := &Lease{
				IP:        netip.MustParseAddr(fmt.Sprintf("10.%d.%d.%d", (i>>16)%256, (i>>8)%256, i%256)),
				MAC:       net.HardwareAddr{0x52, 0x54, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)},
				PoolID:    "pool-1",
				Interface: "eth0",
				LeasedAt:  time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
				State:     LeaseStateActive,
			}
			_ = store.Add(lease)
			i++
		}
	})
}

func BenchmarkLeaseStore_Renew_Parallel(b *testing.B) {
	store := NewLeaseStore()

	// Pre-populate store
	leases := make([]*Lease, 1000)
	for i := 0; i < 1000; i++ {
		lease := &Lease{
			IP:        netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x00, byte(i >> 8), byte(i)},
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			State:     LeaseStateActive,
		}
		_ = store.Add(lease)
		leases[i] = lease
	}

	duration := 24 * time.Hour

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := leases[i%len(leases)].IP
			_ = store.Renew(ip, duration)
			i++
		}
	})
}

// BenchmarkLeaseStore_Churn_Parallel is the DHCP client lifecycle under load:
// 60% new leases, 30% renewals of live leases and 10% releases (#964).
func BenchmarkLeaseStore_Churn_Parallel(b *testing.B) {
	store := NewLeaseStore()

	// Pre-populate the leases the renewals target.
	live := make([]netip.Addr, 1000)
	for i := range live {
		lease := &Lease{
			IP:        netip.AddrFrom4([4]byte{172, 16, byte(i >> 8), byte(i)}),
			MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x02, byte(i >> 8), byte(i)},
			PoolID:    "pool-1",
			Interface: "eth0",
			LeasedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			State:     LeaseStateActive,
		}
		_ = store.Add(lease)
		live[i] = lease.IP
	}

	var next atomic.Uint64
	duration := 24 * time.Hour

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var lastAdded netip.Addr
		for pb.Next() {
			n := next.Add(1)
			switch n % 10 {
			case 0, 1, 2, 3, 4, 5:
				lease := &Lease{
					IP:        netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)}),
					MAC:       net.HardwareAddr{0x52, 0x54, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)},
					PoolID:    "pool-1",
					Interface: "eth0",
					LeasedAt:  time.Now(),
					ExpiresAt: time.Now().Add(duration),
					State:     LeaseStateActive,
				}
				_ = store.Add(lease)
				lastAdded = lease.IP
			case 6, 7, 8:
				_ = store.Renew(live[n%uint64(len(live))], duration)
			default:
				if lastAdded.IsValid() {
					_ = store.Remove(lastAdded)
					lastAdded = netip.Addr{}
				}
			}
		}
	})
}
