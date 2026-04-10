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

package quota

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"
)

// Note: This file uses the mockQuotaStore and newMockQuotaStore defined in enforcer_test.go

// BenchmarkQuotaEnforcer_Reserve benchmarks quota reservation.
func BenchmarkQuotaEnforcer_Reserve(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	enforcer, _ := NewEnforcer(store, logger)

	tenantID := "tenant-001"
	store.setQuota(tenantID, &TenantQuotas{
		TenantID: tenantID,
		Compute: ComputeQuota{
			MaxVMs:      1000000,
			MaxVCPUs:    10000000,
			MaxMemoryMB: 100000000,
		},
	})
	store.setUsage(tenantID, &TenantUsage{
		TenantID: tenantID,
	})

	ctx := context.Background()
	resources := []ResourceType{ResourceVMs, ResourceVCPUs, ResourceMemory}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resource := resources[i%len(resources)]
		reservation, err := enforcer.Reserve(ctx, tenantID, resource, 1)
		if err == nil && reservation != nil {
			_ = enforcer.Release(ctx, reservation.ID)
		}
	}
}

// BenchmarkQuotaEnforcer_Reserve_Parallel benchmarks concurrent quota reservation.
func BenchmarkQuotaEnforcer_Reserve_Parallel(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	enforcer, _ := NewEnforcer(store, logger)

	for i := 0; i < 100; i++ {
		tenantID := fmt.Sprintf("tenant-%03d", i)
		store.setQuota(tenantID, &TenantQuotas{
			TenantID: tenantID,
			Compute: ComputeQuota{
				MaxVMs:      1000000,
				MaxVCPUs:    10000000,
				MaxMemoryMB: 100000000,
			},
		})
		store.setUsage(tenantID, &TenantUsage{
			TenantID: tenantID,
		})
	}

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			tenantID := fmt.Sprintf("tenant-%03d", counter%100)
			reservation, err := enforcer.Reserve(ctx, tenantID, ResourceVMs, 1)
			if err == nil && reservation != nil {
				_ = enforcer.Release(ctx, reservation.ID)
			}
		}
	})
}

// BenchmarkQuotaEnforcer_Release benchmarks quota release.
func BenchmarkQuotaEnforcer_Release(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	enforcer, _ := NewEnforcer(store, logger)

	tenantID := "tenant-001"
	store.setQuota(tenantID, &TenantQuotas{
		TenantID: tenantID,
		Compute: ComputeQuota{
			MaxVMs: 1000000,
		},
	})
	store.setUsage(tenantID, &TenantUsage{
		TenantID: tenantID,
	})

	ctx := context.Background()

	// Pre-create reservations
	reservations := make([]*Reservation, b.N)
	for i := 0; i < b.N; i++ {
		reservations[i], _ = enforcer.Reserve(ctx, tenantID, ResourceVMs, 1)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if reservations[i] != nil {
			_ = enforcer.Release(ctx, reservations[i].ID)
		}
	}
}

// BenchmarkQuotaEnforcer_CheckQuota benchmarks quota checking.
func BenchmarkQuotaEnforcer_CheckQuota(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	enforcer, _ := NewEnforcer(store, logger)

	tenantID := "tenant-001"
	store.setQuota(tenantID, &TenantQuotas{
		TenantID: tenantID,
		Compute: ComputeQuota{
			MaxVMs:      100,
			MaxVCPUs:    1000,
			MaxMemoryMB: 102400,
		},
	})
	store.setUsage(tenantID, &TenantUsage{
		TenantID: tenantID,
		VMs:      50,
		VCPUs:    500,
		MemoryMB: 51200,
	})

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = enforcer.CheckQuota(ctx, tenantID, ResourceVMs, 1)
	}
}

// BenchmarkQuotaEnforcer_CheckQuota_Parallel benchmarks concurrent quota checking.
func BenchmarkQuotaEnforcer_CheckQuota_Parallel(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	enforcer, _ := NewEnforcer(store, logger)

	for i := 0; i < 100; i++ {
		tenantID := fmt.Sprintf("tenant-%03d", i)
		store.setQuota(tenantID, &TenantQuotas{
			TenantID: tenantID,
			Compute: ComputeQuota{
				MaxVMs: 100,
			},
		})
		store.setUsage(tenantID, &TenantUsage{
			TenantID: tenantID,
			VMs:      50,
		})
	}

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			tenantID := fmt.Sprintf("tenant-%03d", counter%100)
			_ = enforcer.CheckQuota(ctx, tenantID, ResourceVMs, 1)
		}
	})
}

// BenchmarkQuotaEnforcer_GetAvailable benchmarks available quota retrieval.
func BenchmarkQuotaEnforcer_GetAvailable(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	enforcer, _ := NewEnforcer(store, logger)

	tenantID := "tenant-001"
	store.setQuota(tenantID, &TenantQuotas{
		TenantID: tenantID,
		Compute: ComputeQuota{
			MaxVMs: 100,
		},
	})
	store.setUsage(tenantID, &TenantUsage{
		TenantID: tenantID,
		VMs:      50,
	})

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = enforcer.GetAvailable(ctx, tenantID, ResourceVMs)
	}
}

// BenchmarkQuotaEnforcer_GetUtilization benchmarks utilization calculation.
func BenchmarkQuotaEnforcer_GetUtilization(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	enforcer, _ := NewEnforcer(store, logger)

	tenantID := "tenant-001"
	store.setQuota(tenantID, &TenantQuotas{
		TenantID: tenantID,
		Compute: ComputeQuota{
			MaxVMs: 100,
		},
	})
	store.setUsage(tenantID, &TenantUsage{
		TenantID: tenantID,
		VMs:      50,
	})

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = enforcer.GetUtilization(ctx, tenantID, ResourceVMs)
	}
}

// BenchmarkUsageTracker_Increment benchmarks usage increment.
func BenchmarkUsageTracker_Increment(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker, _ := NewTracker(store, logger)

	tenantID := "tenant-001"
	store.setUsage(tenantID, &TenantUsage{TenantID: tenantID})

	ctx := context.Background()
	resources := []ResourceType{ResourceVMs, ResourceContainers, ResourceVCPUs, ResourceMemory}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resource := resources[i%len(resources)]
		_ = tracker.Increment(ctx, tenantID, resource, 1)
	}
}

// BenchmarkUsageTracker_Increment_Parallel benchmarks concurrent usage increment.
func BenchmarkUsageTracker_Increment_Parallel(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker, _ := NewTracker(store, logger)

	for i := 0; i < 100; i++ {
		tenantID := fmt.Sprintf("tenant-%03d", i)
		store.setUsage(tenantID, &TenantUsage{TenantID: tenantID})
	}

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			tenantID := fmt.Sprintf("tenant-%03d", counter%100)
			_ = tracker.Increment(ctx, tenantID, ResourceVMs, 1)
		}
	})
}

// BenchmarkUsageTracker_Decrement benchmarks usage decrement.
func BenchmarkUsageTracker_Decrement(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker, _ := NewTracker(store, logger)

	tenantID := "tenant-001"
	store.setUsage(tenantID, &TenantUsage{
		TenantID: tenantID,
		VMs:      1000000,
	})

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = tracker.Decrement(ctx, tenantID, ResourceVMs, 1)
	}
}

// BenchmarkUsageTracker_GetUsage benchmarks usage retrieval.
func BenchmarkUsageTracker_GetUsage(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker, _ := NewTracker(store, logger)

	tenantID := "tenant-001"
	store.setUsage(tenantID, &TenantUsage{
		TenantID: tenantID,
		VMs:      50,
	})

	ctx := context.Background()
	// Pre-warm the cache
	_, _ = tracker.GetUsage(ctx, tenantID, ResourceVMs)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = tracker.GetUsage(ctx, tenantID, ResourceVMs)
	}
}

// BenchmarkUsageTracker_GetUsage_Parallel benchmarks concurrent usage retrieval.
func BenchmarkUsageTracker_GetUsage_Parallel(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker, _ := NewTracker(store, logger)

	for i := 0; i < 100; i++ {
		tenantID := fmt.Sprintf("tenant-%03d", i)
		store.setUsage(tenantID, &TenantUsage{TenantID: tenantID, VMs: 50})
	}

	ctx := context.Background()
	// Pre-warm caches
	for i := 0; i < 100; i++ {
		tenantID := fmt.Sprintf("tenant-%03d", i)
		_, _ = tracker.GetUsage(ctx, tenantID, ResourceVMs)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			tenantID := fmt.Sprintf("tenant-%03d", counter%100)
			_, _ = tracker.GetUsage(ctx, tenantID, ResourceVMs)
		}
	})
}

// BenchmarkUsageTracker_GetAllUsage benchmarks retrieving all usage.
func BenchmarkUsageTracker_GetAllUsage(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker, _ := NewTracker(store, logger)

	tenantID := "tenant-001"
	store.setUsage(tenantID, &TenantUsage{
		TenantID:   tenantID,
		VMs:        50,
		Containers: 100,
		VCPUs:      200,
		MemoryMB:   51200,
	})

	ctx := context.Background()
	// Pre-warm the cache
	_, _ = tracker.GetAllUsage(ctx, tenantID)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = tracker.GetAllUsage(ctx, tenantID)
	}
}

// BenchmarkUsageTracker_Set benchmarks setting usage directly.
func BenchmarkUsageTracker_Set(b *testing.B) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker, _ := NewTracker(store, logger)

	tenantID := "tenant-001"
	store.setUsage(tenantID, &TenantUsage{TenantID: tenantID})

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = tracker.Set(ctx, tenantID, ResourceVMs, int64(i))
	}
}

// BenchmarkResourceType_IsValid benchmarks resource type validation.
func BenchmarkResourceType_IsValid(b *testing.B) {
	resources := []ResourceType{
		ResourceVMs, ResourceContainers, ResourceVCPUs, ResourceMemory,
		ResourceDisk, ResourceBridges, ResourcePorts, ResourceBandwidth,
		ResourceVolumes, ResourceSnapshots,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resource := resources[i%len(resources)]
		_ = resource.IsValid()
	}
}

// BenchmarkResourceType_Category benchmarks resource type categorization.
func BenchmarkResourceType_Category(b *testing.B) {
	resources := []ResourceType{
		ResourceVMs, ResourceBridges, ResourceVolumes,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resource := resources[i%len(resources)]
		_ = resource.Category()
	}
}

// BenchmarkTenantQuotas_GetLimit benchmarks getting quota limits.
func BenchmarkTenantQuotas_GetLimit(b *testing.B) {
	quotas := &TenantQuotas{
		Compute: ComputeQuota{
			MaxVMs:        100,
			MaxContainers: 500,
			MaxVCPUs:      1000,
			MaxMemoryMB:   102400,
		},
		Network: NetworkQuota{
			MaxBridges:       10,
			MaxPorts:         1000,
			MaxBandwidthMbps: 10000,
		},
		Storage: StorageQuota{
			MaxDiskGB:    10000,
			MaxVolumes:   100,
			MaxSnapshots: 100,
		},
	}

	resources := []ResourceType{
		ResourceVMs, ResourceContainers, ResourceVCPUs, ResourceMemory,
		ResourceBridges, ResourcePorts, ResourceDisk,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resource := resources[i%len(resources)]
		_ = quotas.GetLimit(resource)
	}
}

// BenchmarkTenantUsage_GetUsage benchmarks getting usage values.
func BenchmarkTenantUsage_GetUsage(b *testing.B) {
	usage := &TenantUsage{
		VMs:        50,
		Containers: 250,
		VCPUs:      500,
		MemoryMB:   51200,
		Bridges:    5,
		Ports:      500,
		DiskGB:     5000,
	}

	resources := []ResourceType{
		ResourceVMs, ResourceContainers, ResourceVCPUs, ResourceMemory,
		ResourceBridges, ResourcePorts, ResourceDisk,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resource := resources[i%len(resources)]
		_ = usage.GetUsage(resource)
	}
}

// BenchmarkReservation_IsExpired benchmarks expiration checks.
func BenchmarkReservation_IsExpired(b *testing.B) {
	now := time.Now()

	b.Run("NotExpired", func(b *testing.B) {
		reservation := &Reservation{
			ExpiresAt: now.Add(5 * time.Minute),
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = reservation.IsExpired()
		}
	})

	b.Run("Expired", func(b *testing.B) {
		reservation := &Reservation{
			ExpiresAt: now.Add(-5 * time.Minute),
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = reservation.IsExpired()
		}
	})
}
