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

package vlan

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
)

// Note: This file extends the existing benchmarks in allocator_test.go and bitset_test.go
// with additional parallel benchmarks and sub-benchmarks for different scenarios.

// BenchmarkBitset_Set_Sizes benchmarks setting bits with different bitset sizes.
func BenchmarkBitset_Set_Sizes(b *testing.B) {
	sizes := []int{100, 1000, 4095}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			bs := newBitset(size)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				bs.Set(uint16(i % size))
			}
		})
	}
}

// BenchmarkBitset_Set_Parallel benchmarks concurrent bit setting.
func BenchmarkBitset_Set_Parallel(b *testing.B) {
	bs := newBitset(4095)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			bs.Set(uint16(counter % 4095))
		}
	})
}

// BenchmarkBitset_Clear_Extended benchmarks clearing bits in the bitset.
func BenchmarkBitset_Clear_Extended(b *testing.B) {
	bs := newBitset(4095)
	// Set all bits first
	for i := uint16(0); i < 4095; i++ {
		bs.Set(i)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		bs.Clear(uint16(i % 4095))
		// Re-set to maintain consistent state
		bs.Set(uint16(i % 4095))
	}
}

// BenchmarkBitset_Test_Parallel benchmarks concurrent bit testing.
func BenchmarkBitset_Test_Parallel(b *testing.B) {
	bs := newBitset(4095)
	for i := uint16(0); i < 4095; i += 2 {
		bs.Set(i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			_ = bs.Test(uint16(counter % 4095))
		}
	})
}

// BenchmarkBitset_SetRange_Sizes benchmarks setting a range of bits.
func BenchmarkBitset_SetRange_Sizes(b *testing.B) {
	rangeSizes := []uint16{10, 50, 100, 500}

	for _, size := range rangeSizes {
		b.Run(fmt.Sprintf("RangeSize_%d", size), func(b *testing.B) {
			bs := newBitset(4095)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				start := uint16(i % int(4095-size))
				bs.SetRange(start, start+size-1)
				// Clear for next iteration
				bs.ClearRange(start, start+size-1)
			}
		})
	}
}

// BenchmarkBitset_FindFirstClear_Extended benchmarks finding the first clear bit.
func BenchmarkBitset_FindFirstClear_Extended(b *testing.B) {
	b.Run("SparselyFilled", func(b *testing.B) {
		bs := newBitset(4095)
		// Fill 10%
		for i := uint16(0); i < 409; i++ {
			bs.Set(i)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = bs.FindFirstClear(0, 4094)
		}
	})

	b.Run("DenselyFilled", func(b *testing.B) {
		bs := newBitset(4095)
		// Fill 90%
		for i := uint16(0); i < 3685; i++ {
			bs.Set(i)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = bs.FindFirstClear(0, 4094)
		}
	})

	b.Run("AlmostFull", func(b *testing.B) {
		bs := newBitset(4095)
		// Fill 99%
		for i := uint16(0); i < 4054; i++ {
			bs.Set(i)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = bs.FindFirstClear(0, 4094)
		}
	})
}

// BenchmarkBitset_FindClearRange_Sizes benchmarks finding a clear range with different sizes.
func BenchmarkBitset_FindClearRange_Sizes(b *testing.B) {
	rangeSizes := []uint16{10, 50, 100}

	for _, size := range rangeSizes {
		b.Run(fmt.Sprintf("RangeSize_%d", size), func(b *testing.B) {
			bs := newBitset(4095)
			// Fill 50% leaving some gaps
			for i := uint16(0); i < 4095; i += 2 {
				bs.Set(i)
			}
			// Clear a known range
			bs.ClearRange(1000, 1000+size)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, _ = bs.FindClearRange(0, 4094, size)
			}
		})
	}
}

// BenchmarkBitset_CountSet_FillLevels benchmarks counting set bits at different fill levels.
func BenchmarkBitset_CountSet_FillLevels(b *testing.B) {
	fillLevels := []int{10, 50, 90}

	for _, fill := range fillLevels {
		b.Run(fmt.Sprintf("Fill_%d_percent", fill), func(b *testing.B) {
			bs := newBitset(4095)
			count := 4095 * fill / 100
			for i := 0; i < count; i++ {
				bs.Set(uint16(i))
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = bs.CountSet()
			}
		})
	}
}

// BenchmarkBitset_CountSetInRange_Extended benchmarks counting set bits in a range.
func BenchmarkBitset_CountSetInRange_Extended(b *testing.B) {
	bs := newBitset(4095)
	for i := uint16(0); i < 4095; i += 2 {
		bs.Set(i)
	}

	rangeSizes := []uint16{100, 500, 1000}

	for _, size := range rangeSizes {
		b.Run(fmt.Sprintf("RangeSize_%d", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = bs.CountSetInRange(0, size-1)
			}
		})
	}
}

// BenchmarkBitset_Clone_Extended benchmarks cloning the bitset.
func BenchmarkBitset_Clone_Extended(b *testing.B) {
	bs := newBitset(4095)
	for i := uint16(0); i < 4095; i += 2 {
		bs.Set(i)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = bs.Clone()
	}
}

// BenchmarkAllocator_Allocate_Parallel benchmarks concurrent VLAN allocation.
func BenchmarkAllocator_Allocate_Parallel(b *testing.B) {
	store := newMockStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := &Config{
		GlobalRangeStart: 100,
		GlobalRangeEnd:   4000,
		DefaultRangeSize: 10,
	}

	allocator, _ := NewAllocator(store, cfg, logger)
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			tenantID := fmt.Sprintf("tenant-parallel-%d", counter)
			_, _ = allocator.Allocate(ctx, tenantID, 10)
		}
	})
}

// BenchmarkAllocator_Get_Parallel benchmarks concurrent VLAN allocation retrieval.
func BenchmarkAllocator_Get_Parallel(b *testing.B) {
	store := newMockStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := &Config{
		GlobalRangeStart: 100,
		GlobalRangeEnd:   4000,
		DefaultRangeSize: 10,
	}

	allocator, _ := NewAllocator(store, cfg, logger)
	ctx := context.Background()

	// Pre-allocate tenants
	for i := 0; i < 100; i++ {
		tenantID := fmt.Sprintf("tenant-%03d", i)
		_, _ = allocator.Allocate(ctx, tenantID, 10)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			tenantID := fmt.Sprintf("tenant-%03d", counter%100)
			_, _ = allocator.Get(ctx, tenantID)
		}
	})
}

// BenchmarkAllocator_Release_Extended benchmarks releasing a VLAN allocation.
func BenchmarkAllocator_Release_Extended(b *testing.B) {
	store := newMockStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := &Config{
		GlobalRangeStart: 100,
		GlobalRangeEnd:   4000,
		DefaultRangeSize: 10,
	}

	allocator, _ := NewAllocator(store, cfg, logger)
	ctx := context.Background()

	// Pre-allocate tenants
	for i := 0; i < b.N; i++ {
		tenantID := fmt.Sprintf("tenant-release-%d", i)
		_, _ = allocator.Allocate(ctx, tenantID, 10)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tenantID := fmt.Sprintf("tenant-release-%d", i)
		_ = allocator.Release(ctx, tenantID)
	}
}

// BenchmarkAllocator_IsAvailable benchmarks checking VLAN availability.
func BenchmarkAllocator_IsAvailable(b *testing.B) {
	store := newMockStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := &Config{
		GlobalRangeStart: 100,
		GlobalRangeEnd:   4000,
		DefaultRangeSize: 10,
	}

	allocator, _ := NewAllocator(store, cfg, logger)
	ctx := context.Background()

	// Pre-allocate some tenants
	for i := 0; i < 50; i++ {
		tenantID := fmt.Sprintf("tenant-%03d", i)
		_, _ = allocator.Allocate(ctx, tenantID, 10)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		r := Range{
			Start: uint16(500 + (i % 3000)),
			End:   uint16(509 + (i % 3000)),
		}
		_ = allocator.IsAvailable(ctx, r)
	}
}

// BenchmarkAllocator_ListAllocations benchmarks listing all allocations.
func BenchmarkAllocator_ListAllocations(b *testing.B) {
	allocationCounts := []int{10, 50, 100, 500}

	for _, count := range allocationCounts {
		b.Run(fmt.Sprintf("Allocations_%d", count), func(b *testing.B) {
			store := newMockStore()
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			cfg := &Config{
				GlobalRangeStart: 100,
				GlobalRangeEnd:   4000,
				DefaultRangeSize: 5,
			}

			allocator, _ := NewAllocator(store, cfg, logger)
			ctx := context.Background()

			// Pre-allocate tenants
			for i := 0; i < count; i++ {
				tenantID := fmt.Sprintf("tenant-%03d", i)
				_, _ = allocator.Allocate(ctx, tenantID, 5)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, _ = allocator.ListAllocations(ctx)
			}
		})
	}
}

// BenchmarkAllocator_GetAvailableCapacity benchmarks capacity calculation.
func BenchmarkAllocator_GetAvailableCapacity(b *testing.B) {
	store := newMockStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := &Config{
		GlobalRangeStart: 100,
		GlobalRangeEnd:   4000,
		DefaultRangeSize: 10,
	}

	allocator, _ := NewAllocator(store, cfg, logger)
	ctx := context.Background()

	// Pre-allocate some tenants
	for i := 0; i < 100; i++ {
		tenantID := fmt.Sprintf("tenant-%03d", i)
		_, _ = allocator.Allocate(ctx, tenantID, 10)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = allocator.GetAvailableCapacity()
	}
}

// BenchmarkRange_Contains benchmarks VLAN containment checks.
func BenchmarkRange_Contains(b *testing.B) {
	r := Range{Start: 100, End: 199}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = r.Contains(uint16(100 + (i % 100)))
	}
}

// BenchmarkRange_Overlaps benchmarks overlap detection.
func BenchmarkRange_Overlaps(b *testing.B) {
	r1 := Range{Start: 100, End: 199}
	r2 := Range{Start: 150, End: 249}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = r1.Overlaps(r2)
	}
}

// BenchmarkRange_Validate benchmarks range validation.
func BenchmarkRange_Validate(b *testing.B) {
	r := Range{Start: 100, End: 199}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = r.Validate()
	}
}

// BenchmarkPopcount_Extended benchmarks the popcount function with various values.
func BenchmarkPopcount_Extended(b *testing.B) {
	testCases := []uint64{
		0,
		0xFFFFFFFFFFFFFFFF,
		0x5555555555555555,
		0xAAAAAAAAAAAAAAAA,
	}

	for idx, tc := range testCases {
		b.Run(fmt.Sprintf("Case_%d", idx), func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = popcount(tc)
			}
		})
	}
}
