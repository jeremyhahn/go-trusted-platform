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

package vxlan

import (
	"fmt"
	"net/netip"
	"testing"
)

// VNI Mapping Benchmarks

func BenchmarkVNIMapper_VLANToVNI(b *testing.B) {
	config := VNIMappingConfig{
		BaseVNI: DefaultBaseVNI,
		MaxVLAN: 4094,
	}
	mapper := NewVNIMapper(config)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vlan := uint16(i % 4094)
		_, _ = mapper.VLANToVNI(vlan)
	}
}

func BenchmarkVNIMapper_VLANToVNI_WithExplicitMapping(b *testing.B) {
	config := VNIMappingConfig{
		BaseVNI: DefaultBaseVNI,
		MaxVLAN: 4094,
	}
	mapper := NewVNIMapper(config)

	// Pre-populate explicit mappings
	for i := uint16(1); i <= 100; i++ {
		_ = mapper.RegisterMapping(i, VNI(2000000+uint32(i)))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vlan := uint16((i % 100) + 1)
		_, _ = mapper.VLANToVNI(vlan)
	}
}

func BenchmarkVNIMapper_VNIToVLAN(b *testing.B) {
	config := VNIMappingConfig{
		BaseVNI: DefaultBaseVNI,
		MaxVLAN: 4094,
	}
	mapper := NewVNIMapper(config)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vni := VNI(uint32(DefaultBaseVNI) + uint32(i%4094))
		_, _ = mapper.VNIToVLAN(vni)
	}
}

func BenchmarkVNIMapper_RegisterMapping(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		config := VNIMappingConfig{
			BaseVNI: DefaultBaseVNI,
			MaxVLAN: 4094,
		}
		mapper := NewVNIMapper(config)
		b.StartTimer()

		vlan := uint16(i % 4094)
		vni := VNI(3000000 + uint32(i))
		_ = mapper.RegisterMapping(vlan, vni)
	}
}

func BenchmarkVNIMapper_HasMapping(b *testing.B) {
	config := VNIMappingConfig{
		BaseVNI: DefaultBaseVNI,
		MaxVLAN: 4094,
	}
	mapper := NewVNIMapper(config)

	// Pre-populate mappings
	for i := uint16(1); i <= 1000; i++ {
		_ = mapper.RegisterMapping(i, VNI(2000000+uint32(i)))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vlan := uint16((i % 1000) + 1)
		_ = mapper.HasMapping(vlan)
	}
}

func BenchmarkVNIMapper_ListMappings(b *testing.B) {
	config := VNIMappingConfig{
		BaseVNI: DefaultBaseVNI,
		MaxVLAN: 4094,
	}
	mapper := NewVNIMapper(config)

	// Pre-populate mappings
	for i := uint16(1); i <= 100; i++ {
		_ = mapper.RegisterMapping(i, VNI(2000000+uint32(i)))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mapper.ListMappings()
	}
}

// Sub-benchmarks for different mapping counts
func BenchmarkVNIMapper_VLANToVNI_Sizes(b *testing.B) {
	sizes := []int{10, 100, 1000, 4000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("mappings_%d", size), func(b *testing.B) {
			config := VNIMappingConfig{
				BaseVNI: DefaultBaseVNI,
				MaxVLAN: 4094,
			}
			mapper := NewVNIMapper(config)

			// Pre-populate explicit mappings
			for i := uint16(1); i <= uint16(size); i++ {
				_ = mapper.RegisterMapping(i, VNI(2000000+uint32(i)))
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				vlan := uint16((i % size) + 1)
				_, _ = mapper.VLANToVNI(vlan)
			}
		})
	}
}

// VNI Type Benchmarks

func BenchmarkVNI_Valid(b *testing.B) {
	vnis := []VNI{1, 100, 1000, 10000, 16777215, 0, 16777216}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vni := vnis[i%len(vnis)]
		_ = vni.Valid()
	}
}

func BenchmarkVNI_Uint32(b *testing.B) {
	vni := VNI(1000000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = vni.Uint32()
	}
}

// TunnelStatus Benchmarks

func BenchmarkTunnelStatus_String(b *testing.B) {
	statuses := []TunnelStatus{TunnelStatusUnknown, TunnelStatusUp, TunnelStatusDown, TunnelStatusError}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		status := statuses[i%len(statuses)]
		_ = status.String()
	}
}

// VTEPConfig Benchmarks

func BenchmarkVTEPConfig_Validate(b *testing.B) {
	config := &VTEPConfig{
		LocalIP:       netip.MustParseAddr("10.0.0.1"),
		UnderlayIface: "eth0",
		UnderlayMTU:   9000,
		VXLANPort:     4789,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.Validate()
	}
}

func BenchmarkVTEPConfig_EffectiveMTU(b *testing.B) {
	config := &VTEPConfig{
		LocalIP:       netip.MustParseAddr("10.0.0.1"),
		UnderlayIface: "eth0",
		UnderlayMTU:   9000,
		VXLANPort:     4789,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.EffectiveMTU()
	}
}

// RemoteMACEntry Benchmarks

func BenchmarkRemoteMACEntry_IsExpired(b *testing.B) {
	entry := &RemoteMACEntry{
		VNI:        1000100,
		RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entry.IsExpired()
	}
}

// VXLANPortConfig Benchmarks

func BenchmarkVXLANPortConfig_Options(b *testing.B) {
	config := &VXLANPortConfig{
		RemoteIP: netip.MustParseAddr("10.0.0.2"),
		VNI:      1000100,
		DstPort:  4789,
		TOS:      0,
		TTL:      64,
		DF:       true,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.Options()
	}
}

// Parallel Benchmarks

func BenchmarkVNIMapper_VLANToVNI_Parallel(b *testing.B) {
	config := VNIMappingConfig{
		BaseVNI: DefaultBaseVNI,
		MaxVLAN: 4094,
	}
	mapper := NewVNIMapper(config)

	// Pre-populate mappings
	for i := uint16(1); i <= 100; i++ {
		_ = mapper.RegisterMapping(i, VNI(2000000+uint32(i)))
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := uint16(0)
		for pb.Next() {
			vlan := (i % 100) + 1
			_, _ = mapper.VLANToVNI(vlan)
			i++
		}
	})
}

func BenchmarkVNIMapper_RegisterMapping_Parallel(b *testing.B) {
	config := VNIMappingConfig{
		BaseVNI: DefaultBaseVNI,
		MaxVLAN: 4094,
	}
	mapper := NewVNIMapper(config)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := uint16(0)
		for pb.Next() {
			vlan := (i % 4094) + 1
			vni := VNI(3000000 + uint32(i))
			_ = mapper.RegisterMapping(vlan, vni)
			i++
		}
	})
}

func BenchmarkVNIMapper_HasMapping_Parallel(b *testing.B) {
	config := VNIMappingConfig{
		BaseVNI: DefaultBaseVNI,
		MaxVLAN: 4094,
	}
	mapper := NewVNIMapper(config)

	// Pre-populate mappings
	for i := uint16(1); i <= 1000; i++ {
		_ = mapper.RegisterMapping(i, VNI(2000000+uint32(i)))
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := uint16(0)
		for pb.Next() {
			vlan := (i % 1000) + 1
			_ = mapper.HasMapping(vlan)
			i++
		}
	})
}
