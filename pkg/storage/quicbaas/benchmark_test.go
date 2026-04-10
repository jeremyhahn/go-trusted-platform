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

package quicbaas

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// BenchmarkMockStorage_Put benchmarks Put operations on MockStorage.
func BenchmarkMockStorage_Put(b *testing.B) {
	storage := NewMockStorage()
	_ = storage.Start(context.Background())
	defer func() { _ = storage.Stop(context.Background()) }()

	ctx := context.Background()
	entityType := "test_entity"

	dataSizes := []int{64, 256, 1024, 4096}

	for _, size := range dataSizes {
		b.Run(fmt.Sprintf("DataSize_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 256)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = storage.Put(ctx, entityType, uint64(i), data, 0)
			}
		})
	}
}

// BenchmarkMockStorage_Put_Parallel benchmarks concurrent Put operations.
func BenchmarkMockStorage_Put_Parallel(b *testing.B) {
	storage := NewMockStorage()
	_ = storage.Start(context.Background())
	defer func() { _ = storage.Stop(context.Background()) }()

	ctx := context.Background()
	entityType := "test_entity"
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := uint64(0)
		for pb.Next() {
			counter++
			_ = storage.Put(ctx, entityType, counter, data, 0)
		}
	})
}

// BenchmarkMockStorage_Get benchmarks Get operations.
func BenchmarkMockStorage_Get(b *testing.B) {
	storage := NewMockStorage()
	_ = storage.Start(context.Background())
	defer func() { _ = storage.Stop(context.Background()) }()

	ctx := context.Background()
	entityType := "test_entity"

	// Pre-populate data
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i % 256)
	}
	for i := uint64(0); i < 1000; i++ {
		_ = storage.Put(ctx, entityType, i, data, 0)
	}

	b.Run("ExistingKey", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _, _ = storage.Get(ctx, entityType, uint64(i%1000), 0)
		}
	})

	b.Run("MissingKey", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _, _ = storage.Get(ctx, entityType, uint64(i+10000), 0)
		}
	})
}

// BenchmarkMockStorage_Get_Parallel benchmarks concurrent Get operations.
func BenchmarkMockStorage_Get_Parallel(b *testing.B) {
	storage := NewMockStorage()
	_ = storage.Start(context.Background())
	defer func() { _ = storage.Stop(context.Background()) }()

	ctx := context.Background()
	entityType := "test_entity"

	// Pre-populate data
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i % 256)
	}
	for i := uint64(0); i < 1000; i++ {
		_ = storage.Put(ctx, entityType, i, data, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := uint64(0)
		for pb.Next() {
			counter++
			_, _, _ = storage.Get(ctx, entityType, counter%1000, 0)
		}
	})
}

// BenchmarkMockStorage_Delete benchmarks Delete operations.
func BenchmarkMockStorage_Delete(b *testing.B) {
	storage := NewMockStorage()
	_ = storage.Start(context.Background())
	defer func() { _ = storage.Stop(context.Background()) }()

	ctx := context.Background()
	entityType := "test_entity"

	// Pre-populate data
	data := make([]byte, 256)
	for i := uint64(0); i < uint64(b.N); i++ {
		_ = storage.Put(ctx, entityType, i, data, 0)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = storage.Delete(ctx, entityType, uint64(i), 0)
	}
}

// BenchmarkMockStorage_List benchmarks List operations.
func BenchmarkMockStorage_List(b *testing.B) {
	entityCounts := []int{10, 100, 1000}

	for _, count := range entityCounts {
		b.Run(fmt.Sprintf("Entities_%d", count), func(b *testing.B) {
			storage := NewMockStorage()
			_ = storage.Start(context.Background())
			defer func() { _ = storage.Stop(context.Background()) }()

			ctx := context.Background()
			entityType := "test_entity"

			// Pre-populate data
			data := make([]byte, 64)
			for i := uint64(0); i < uint64(count); i++ {
				_ = storage.Put(ctx, entityType, i, data, 0)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, _, _ = storage.List(ctx, entityType, 100, "", 0)
			}
		})
	}
}

// BenchmarkMockStorage_List_Parallel benchmarks concurrent List operations.
func BenchmarkMockStorage_List_Parallel(b *testing.B) {
	storage := NewMockStorage()
	_ = storage.Start(context.Background())
	defer func() { _ = storage.Stop(context.Background()) }()

	ctx := context.Background()
	entityType := "test_entity"

	// Pre-populate data
	data := make([]byte, 64)
	for i := uint64(0); i < 100; i++ {
		_ = storage.Put(ctx, entityType, i, data, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = storage.List(ctx, entityType, 100, "", 0)
		}
	})
}

// BenchmarkMockStorage_Query benchmarks Query operations.
func BenchmarkMockStorage_Query(b *testing.B) {
	storage := NewMockStorage()
	_ = storage.Start(context.Background())
	defer func() { _ = storage.Stop(context.Background()) }()

	ctx := context.Background()
	entityType := "test_entity"

	// Pre-populate data and query results
	data := make([]byte, 64)
	entities := make([]*service.Entity, 10)
	for i := uint64(0); i < 100; i++ {
		_ = storage.Put(ctx, entityType, i, data, 0)
		if i < 10 {
			entities[i] = &service.Entity{ID: i, Data: data}
		}
	}
	storage.SetQueryResult(entityType, "test_index", []byte("test_value"), entities)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = storage.Query(ctx, entityType, "test_index", []byte("test_value"), 0)
	}
}

// BenchmarkMockStorage_MixedWorkload benchmarks mixed read/write workload.
func BenchmarkMockStorage_MixedWorkload(b *testing.B) {
	storage := NewMockStorage()
	_ = storage.Start(context.Background())
	defer func() { _ = storage.Stop(context.Background()) }()

	ctx := context.Background()
	entityType := "test_entity"
	data := make([]byte, 256)

	// Pre-populate some data
	for i := uint64(0); i < 100; i++ {
		_ = storage.Put(ctx, entityType, i, data, 0)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		switch i % 10 {
		case 0, 1: // 20% writes
			_ = storage.Put(ctx, entityType, uint64(i), data, 0)
		default: // 80% reads
			_, _, _ = storage.Get(ctx, entityType, uint64(i%100), 0)
		}
	}
}

// BenchmarkMockStorage_MixedWorkload_Parallel benchmarks concurrent mixed workload.
func BenchmarkMockStorage_MixedWorkload_Parallel(b *testing.B) {
	storage := NewMockStorage()
	_ = storage.Start(context.Background())
	defer func() { _ = storage.Stop(context.Background()) }()

	ctx := context.Background()
	entityType := "test_entity"
	data := make([]byte, 256)

	// Pre-populate some data
	for i := uint64(0); i < 100; i++ {
		_ = storage.Put(ctx, entityType, i, data, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			switch counter % 10 {
			case 0, 1: // 20% writes
				_ = storage.Put(ctx, entityType, uint64(counter), data, 0)
			default: // 80% reads
				_, _, _ = storage.Get(ctx, entityType, uint64(counter%100), 0)
			}
		}
	})
}

// BenchmarkConfig_Validate benchmarks configuration validation.
func BenchmarkConfig_Validate(b *testing.B) {
	config := &Config{
		DataDir:          "/tmp/quicbaas",
		NodeID:           1,
		RequestTimeout:   5 * time.Second,
		ConsistencyLevel: ConsistencyLinearizable,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = config.Validate()
	}
}

// BenchmarkConsistencyLevel_Conversion benchmarks consistency level conversion.
func BenchmarkConsistencyLevel_Conversion(b *testing.B) {
	client := &Client{
		config: &Config{
			ConsistencyLevel: ConsistencyLinearizable,
		},
	}

	levels := []ConsistencyLevel{
		ConsistencyLinearizable,
		ConsistencyStrong,
		ConsistencyEventual,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		level := levels[i%len(levels)]
		_ = client.toSDKConsistency(level)
	}
}

// BenchmarkContext_EnsureDeadline benchmarks deadline enforcement.
func BenchmarkContext_EnsureDeadline(b *testing.B) {
	client := &Client{
		config: &Config{
			RequestTimeout: 5 * time.Second,
		},
	}

	b.Run("WithoutDeadline", func(b *testing.B) {
		ctx := context.Background()
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = client.ensureDeadline(ctx)
		}
	})

	b.Run("WithDeadline", func(b *testing.B) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = client.ensureDeadline(ctx)
		}
	})
}

// BenchmarkStorage_StartStop benchmarks start/stop lifecycle operations.
func BenchmarkStorage_StartStop(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		storage := NewMockStorage()
		_ = storage.Start(ctx)
		_ = storage.Stop(ctx)
	}
}

// BenchmarkStorage_Count benchmarks entity counting.
func BenchmarkStorage_Count(b *testing.B) {
	storage := NewMockStorage()
	_ = storage.Start(context.Background())
	defer func() { _ = storage.Stop(context.Background()) }()

	entityType := "test_entity"
	data := make([]byte, 64)

	for i := uint64(0); i < 1000; i++ {
		storage.SetData(entityType, i, data)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = storage.Count(entityType)
	}
}

// BenchmarkPageToken_Operations benchmarks page token encoding/decoding.
func BenchmarkPageToken_Operations(b *testing.B) {
	b.Run("Format", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = formatPageToken(uint64(i))
		}
	})

	b.Run("Parse", func(b *testing.B) {
		token := formatPageToken(12345)
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = parsePageToken(token)
		}
	})
}
