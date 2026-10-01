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

package tenant

import (
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// BenchmarkTenantEntity_ToProto benchmarks converting a TenantEntity to proto.
func BenchmarkTenantEntity_ToProto(b *testing.B) {
	entity := createBenchmarkTenantEntity()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = entity.ToIAM()
	}
}

// BenchmarkTenantEntity_ToProto_Parallel benchmarks concurrent proto conversion.
func BenchmarkTenantEntity_ToProto_Parallel(b *testing.B) {
	entity := createBenchmarkTenantEntity()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = entity.ToIAM()
		}
	})
}

// BenchmarkTenantEntity_FromIAM benchmarks converting proto to TenantEntity.
func BenchmarkTenantEntity_FromIAM(b *testing.B) {
	now := time.Now()
	proto := &iam.Tenant{
		ID:        "tenant-001",
		Name:      "test-tenant",
		CreatedAt: now,
		UpdatedAt: now,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = FromIAM(proto)
	}
}

// BenchmarkTenantEntity_FromIAM_Parallel benchmarks concurrent proto conversion.
func BenchmarkTenantEntity_FromIAM_Parallel(b *testing.B) {
	now := time.Now()
	proto := &iam.Tenant{
		ID:        "tenant-001",
		Name:      "test-tenant",
		CreatedAt: now,
		UpdatedAt: now,
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = FromIAM(proto)
		}
	})
}

// BenchmarkTenantEntity_Clone benchmarks cloning a TenantEntity.
func BenchmarkTenantEntity_Clone(b *testing.B) {
	b.Run("MinimalEntity", func(b *testing.B) {
		entity := &TenantEntity{
			ID:    "tenant-001",
			Name:  "test-tenant",
			State: StateActive,
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = entity.Clone()
		}
	})

	b.Run("FullEntity", func(b *testing.B) {
		entity := createBenchmarkTenantEntity()

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = entity.Clone()
		}
	})

	b.Run("WithManyLabels", func(b *testing.B) {
		entity := createBenchmarkTenantEntity()
		for i := 0; i < 50; i++ {
			entity.Labels[fmt.Sprintf("label-%d", i)] = fmt.Sprintf("value-%d", i)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = entity.Clone()
		}
	})
}

// BenchmarkTenantEntity_Validate benchmarks entity validation.
func BenchmarkTenantEntity_Validate(b *testing.B) {
	entity := createBenchmarkTenantEntity()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = entity.Validate()
	}
}

// BenchmarkTenantState_Transition benchmarks state transitions.
func BenchmarkTenantState_Transition(b *testing.B) {
	transitions := []struct {
		from State
		to   State
	}{
		{StateCreated, StateActive},
		{StateActive, StateSuspended},
		{StateSuspended, StateActive},
		{StateActive, StateDeleting},
		{StateDeleting, StateDeleted},
	}

	for _, tt := range transitions {
		b.Run(fmt.Sprintf("%s_to_%s", tt.from, tt.to), func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				entity := &TenantEntity{
					ID:    "tenant-001",
					Name:  "test-tenant",
					State: tt.from,
				}
				_ = entity.SetState(tt.to)
			}
		})
	}
}

// BenchmarkTenantState_CanTransitionTo benchmarks transition validation.
func BenchmarkTenantState_CanTransitionTo(b *testing.B) {
	states := AllStates()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		from := states[i%len(states)]
		to := states[(i+1)%len(states)]
		_ = from.CanTransitionTo(to)
	}
}

// BenchmarkTenantState_IsValid benchmarks state validity checks.
func BenchmarkTenantState_IsValid(b *testing.B) {
	validStates := AllStates()
	invalidState := State("invalid")

	b.Run("ValidState", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			state := validStates[i%len(validStates)]
			_ = state.IsValid()
		}
	})

	b.Run("InvalidState", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = invalidState.IsValid()
		}
	})
}

// BenchmarkTenantState_AllowsResourceCreation benchmarks resource creation checks.
func BenchmarkTenantState_AllowsResourceCreation(b *testing.B) {
	states := AllStates()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.AllowsResourceCreation()
	}
}

// BenchmarkComputeQuota_HasCapacity benchmarks quota capacity checks.
func BenchmarkComputeQuota_HasCapacity(b *testing.B) {
	quota := &ComputeQuota{
		MaxVMs:         100,
		MaxContainers:  500,
		MaxVCPUs:       1000,
		MaxMemoryMB:    102400,
		MaxDiskGB:      10000,
		UsedVMs:        50,
		UsedContainers: 250,
		UsedVCPUs:      500,
		UsedMemoryMB:   51200,
		UsedDiskGB:     5000,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = quota.HasCapacity(1, 2, 4, 1024, 100)
	}
}

// BenchmarkComputeQuota_Reserve benchmarks quota reservation.
func BenchmarkComputeQuota_Reserve(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		quota := &ComputeQuota{
			MaxVMs:        100,
			MaxContainers: 500,
			MaxVCPUs:      1000,
			MaxMemoryMB:   102400,
			MaxDiskGB:     10000,
		}
		_ = quota.Reserve("tenant-001", 1, 2, 4, 1024, 100)
	}
}

// BenchmarkComputeQuota_Release benchmarks quota release.
func BenchmarkComputeQuota_Release(b *testing.B) {
	quota := &ComputeQuota{
		UsedVMs:        50,
		UsedContainers: 250,
		UsedVCPUs:      500,
		UsedMemoryMB:   51200,
		UsedDiskGB:     5000,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		quota.Release(1, 2, 4, 1024, 100)
		// Reset for next iteration
		quota.UsedVMs = 50
		quota.UsedContainers = 250
		quota.UsedVCPUs = 500
		quota.UsedMemoryMB = 51200
		quota.UsedDiskGB = 5000
	}
}

// BenchmarkComputeQuota_GetUtilization benchmarks utilization calculation.
func BenchmarkComputeQuota_GetUtilization(b *testing.B) {
	quota := &ComputeQuota{
		MaxVMs:         100,
		MaxContainers:  500,
		MaxVCPUs:       1000,
		MaxMemoryMB:    102400,
		MaxDiskGB:      10000,
		UsedVMs:        50,
		UsedContainers: 250,
		UsedVCPUs:      500,
		UsedMemoryMB:   51200,
		UsedDiskGB:     5000,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = quota.GetUtilization()
	}
}

// BenchmarkNetworkQuota_HasCapacity benchmarks network quota capacity checks.
func BenchmarkNetworkQuota_HasCapacity(b *testing.B) {
	quota := &NetworkQuota{
		MaxBridges:       10,
		MaxPorts:         1000,
		MaxBandwidthMbps: 10000,
		UsedBridges:      5,
		UsedPorts:        500,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = quota.HasCapacity(1, 10)
	}
}

// BenchmarkStorageQuota_HasCapacity benchmarks storage quota capacity checks.
func BenchmarkStorageQuota_HasCapacity(b *testing.B) {
	quota := &StorageQuota{
		MaxVolumesGB:  10000,
		MaxSnapshots:  100,
		UsedVolumesGB: 5000,
		UsedSnapshots: 50,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = quota.HasCapacity(100, 5)
	}
}

// BenchmarkGetQuotaSummary benchmarks quota summary generation.
func BenchmarkGetQuotaSummary(b *testing.B) {
	compute := &ComputeQuota{
		MaxVMs:         100,
		MaxContainers:  500,
		UsedVMs:        50,
		UsedContainers: 250,
	}
	network := &NetworkQuota{
		MaxBridges:  10,
		MaxPorts:    1000,
		UsedBridges: 5,
		UsedPorts:   500,
	}
	storage := &StorageQuota{
		MaxVolumesGB:  10000,
		MaxSnapshots:  100,
		UsedVolumesGB: 5000,
		UsedSnapshots: 50,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = GetQuotaSummary(compute, network, storage)
	}
}

// BenchmarkTenantEntity_Labels benchmarks label operations.
func BenchmarkTenantEntity_Labels(b *testing.B) {
	b.Run("GetLabel", func(b *testing.B) {
		entity := createBenchmarkTenantEntity()
		entity.Labels["test-key"] = "test-value"

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = entity.GetLabel("test-key")
		}
	})

	b.Run("SetLabel", func(b *testing.B) {
		entity := createBenchmarkTenantEntity()

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			entity.SetLabel("key", "value")
		}
	})
}

// createBenchmarkTenantEntity creates a fully populated TenantEntity for benchmarks.
func createBenchmarkTenantEntity() *TenantEntity {
	now := time.Now()
	return &TenantEntity{
		ID:          "tenant-001",
		Name:        "test-tenant",
		DisplayName: "Test Tenant",
		State:       StateActive,
		DEKPath:     "/tenant/tenant-001/default",
		ComputeQuota: ComputeQuota{
			MaxVMs:        100,
			MaxContainers: 500,
			MaxVCPUs:      1000,
			MaxMemoryMB:   102400,
			MaxDiskGB:     10000,
		},
		NetworkQuota: NetworkQuota{
			MaxBridges:       10,
			MaxPorts:         1000,
			MaxBandwidthMbps: 10000,
		},
		StorageQuota: StorageQuota{
			MaxVolumesGB: 10000,
			MaxSnapshots: 100,
		},
		Labels: map[string]string{
			"environment": "production",
			"team":        "platform",
		},
		Annotations: map[string]string{
			"description": "Test tenant for benchmarks",
		},
		CreatedAt: now.Add(-24 * time.Hour),
		UpdatedAt: now,
	}
}
