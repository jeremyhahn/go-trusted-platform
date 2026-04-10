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

package device

import (
	"context"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/require"
)

func benchmarkDatastore(b *testing.B) *Datastore {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(b, err)
	return NewDatastore(mockStorage, logger)
}

// Device Service Benchmarks

func BenchmarkDeviceService_Save(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		device := &entities.Device{
			ID:         uint64(i + 1),
			Model:      fmt.Sprintf("TPM-Model-%d", i),
			Serial:     fmt.Sprintf("SN%08d", i),
			AttestPub:  fmt.Sprintf("attest-pub-key-%d", i),
			SigningPub: fmt.Sprintf("signing-pub-key-%d", i),
			EKCert:     fmt.Sprintf("ek-certificate-%d", i),
			EventLog:   []byte(fmt.Sprintf("event-log-data-%d", i)),
			HashAlgoId: 11,
		}
		_ = service.Save(ctx, device)
	}
}

func BenchmarkDeviceService_Get(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	// Pre-populate with a device
	device := &entities.Device{
		ID:         1,
		Model:      "BenchTPM",
		Serial:     "SNBENCH001",
		AttestPub:  "attest-key",
		SigningPub: "signing-key",
	}
	err = service.Save(ctx, device)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.Get(ctx, 1)
	}
}

func BenchmarkDeviceService_Update(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     1,
		Model:  "OriginalModel",
		Serial: "ORIG001",
	}
	err = service.Save(ctx, device)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		device.Model = fmt.Sprintf("UpdatedModel-%d", i)
		_ = service.Update(ctx, device)
	}
}

func BenchmarkDeviceService_Delete(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		device := &entities.Device{
			ID:     uint64(i + 1),
			Model:  "DeleteTPM",
			Serial: fmt.Sprintf("SNDEL%08d", i),
		}
		_ = service.Save(ctx, device)
		b.StartTimer()
		_ = service.Delete(ctx, device)
	}
}

func BenchmarkDeviceService_Count(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	// Pre-populate with some devices
	for i := 1; i <= 100; i++ {
		device := &entities.Device{
			ID:     uint64(i),
			Model:  fmt.Sprintf("TPM%d", i),
			Serial: fmt.Sprintf("SN%08d", i),
		}
		_ = service.Save(ctx, device)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.Count(ctx)
	}
}

func BenchmarkDeviceService_Page(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	// Pre-populate with devices
	for i := 1; i <= 100; i++ {
		device := &entities.Device{
			ID:     uint64(i),
			Model:  fmt.Sprintf("TPM%d", i),
			Serial: fmt.Sprintf("SN%08d", i),
		}
		_ = service.Save(ctx, device)
	}

	pageQuery := datastore.PageQuery{
		Page:      1,
		PageSize:  20,
		SortOrder: datastore.SORT_ASCENDING,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.Page(ctx, pageQuery)
	}
}

func BenchmarkDeviceService_FindBySerial(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     1,
		Model:  "FindTPM",
		Serial: "SNFIND001",
	}
	err = service.Save(ctx, device)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.FindBySerial(ctx, "SNFIND001")
	}
}

// Profile Service Benchmarks

func BenchmarkProfileService_Save(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewProfileService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		profile := &entities.DeviceProfile{
			ID:    uint64(i + 1),
			Name:  fmt.Sprintf("Profile-%d", i),
			Model: fmt.Sprintf("Model-%d", i),
			Role:  entities.DeviceRoleServer,
			MatchRules: &entities.ProfileMatchRules{
				MACPrefix:    fmt.Sprintf("52:54:%02x", i%256),
				SerialPrefix: fmt.Sprintf("SN%d", i),
			},
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultEnrollmentNetwork: {
					VLAN:       998,
					AuthMethod: entities.AuthMethodNone,
				},
				entities.DefaultPostEnrollmentNetwork: {
					VLAN:       uint16(100 + i%100),
					AuthMethod: entities.AuthMethod802_1X,
				},
			},
		}
		_ = service.Save(ctx, profile)
	}
}

func BenchmarkProfileService_Get(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewProfileService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "BenchProfile",
		Role: entities.DeviceRoleServer,
	}
	err = service.Save(ctx, profile)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.Get(ctx, 1)
	}
}

func BenchmarkProfileService_Update(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewProfileService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "OriginalProfile",
		Role: entities.DeviceRoleServer,
	}
	err = service.Save(ctx, profile)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		profile.Name = fmt.Sprintf("UpdatedProfile-%d", i)
		_ = service.Update(ctx, profile)
	}
}

func BenchmarkProfileService_Delete(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewProfileService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		profile := &entities.DeviceProfile{
			ID:   uint64(i + 1),
			Name: fmt.Sprintf("DeleteProfile-%d", i),
			Role: entities.DeviceRoleServer,
		}
		_ = service.Save(ctx, profile)
		b.StartTimer()
		_ = service.Delete(ctx, profile)
	}
}

func BenchmarkProfileService_Count(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewProfileService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	// Pre-populate with profiles
	for i := 1; i <= 50; i++ {
		profile := &entities.DeviceProfile{
			ID:   uint64(i),
			Name: fmt.Sprintf("Profile%d", i),
			Role: entities.DeviceRoleServer,
		}
		_ = service.Save(ctx, profile)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.Count(ctx)
	}
}

func BenchmarkProfileService_Page(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewProfileService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	// Pre-populate with profiles
	for i := 1; i <= 50; i++ {
		profile := &entities.DeviceProfile{
			ID:   uint64(i),
			Name: fmt.Sprintf("Profile%d", i),
			Role: entities.DeviceRoleServer,
		}
		_ = service.Save(ctx, profile)
	}

	pageQuery := datastore.PageQuery{
		Page:      1,
		PageSize:  10,
		SortOrder: datastore.SORT_ASCENDING,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.Page(ctx, pageQuery)
	}
}

// Profile Matching Benchmarks

func BenchmarkProfileService_FindByMACAddress(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewProfileService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "MACProfile",
		Role: entities.DeviceRoleServer,
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}
	err = service.Save(ctx, profile)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.FindByMACAddress(ctx, "52:54:00:aa:bb:cc")
	}
}

func BenchmarkProfileService_FindBySerial(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewProfileService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "SerialProfile",
		Role: entities.DeviceRoleServer,
		MatchRules: &entities.ProfileMatchRules{
			SerialPrefix: "SRV-",
		},
	}
	err = service.Save(ctx, profile)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.FindBySerial(ctx, "SRV-12345")
	}
}

func BenchmarkProfileService_FindMatchingProfile(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewProfileService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "MatchProfile",
		Role: entities.DeviceRoleServer,
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix:    "52:54:00",
			SerialPrefix: "SRV-",
			Model:        "Server-TPM-2.0",
		},
	}
	err = service.Save(ctx, profile)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.FindMatchingProfile(ctx, "52:54:00:aa:bb:cc", "SRV-12345", "Server-TPM-2.0")
	}
}

func BenchmarkProfileMatchRules_Matches(b *testing.B) {
	rules := &entities.ProfileMatchRules{
		MACPrefix:    "52:54:00",
		SerialPrefix: "SRV-",
		Model:        "Server-TPM-2.0",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rules.Matches("52:54:00:aa:bb:cc", "SRV-12345", "Server-TPM-2.0")
	}
}

// Large Dataset Benchmarks

func BenchmarkDeviceService_LargeDataset_Save1000(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 1000; j++ {
			device := &entities.Device{
				ID:         uint64(i*1000 + j + 1),
				Model:      fmt.Sprintf("TPM-Model-%d", j),
				Serial:     fmt.Sprintf("SN%08d", i*1000+j),
				AttestPub:  fmt.Sprintf("attest-key-%d", j),
				SigningPub: fmt.Sprintf("signing-key-%d", j),
			}
			_ = service.Save(ctx, device)
		}
	}
}

func BenchmarkDeviceService_LargeDataset_Page(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	// Pre-populate with 1000 devices
	for i := 0; i < 1000; i++ {
		device := &entities.Device{
			ID:     uint64(i + 1),
			Model:  fmt.Sprintf("TPM%d", i),
			Serial: fmt.Sprintf("SN%08d", i),
		}
		_ = service.Save(ctx, device)
	}

	pageQuery := datastore.PageQuery{
		Page:      1,
		PageSize:  50,
		SortOrder: datastore.SORT_ASCENDING,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.Page(ctx, pageQuery)
	}
}

func BenchmarkDeviceService_LargeDataset_Count(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	// Pre-populate with 1000 devices
	for i := 0; i < 1000; i++ {
		device := &entities.Device{
			ID:     uint64(i + 1),
			Model:  fmt.Sprintf("TPM%d", i),
			Serial: fmt.Sprintf("SN%08d", i),
		}
		_ = service.Save(ctx, device)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.Count(ctx)
	}
}

func BenchmarkProfileService_LargeDataset_FindMatchingProfile(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewProfileService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	// Pre-populate with 100 profiles with different match rules
	for i := 0; i < 100; i++ {
		profile := &entities.DeviceProfile{
			ID:   uint64(i + 1),
			Name: fmt.Sprintf("Profile%d", i),
			Role: entities.DeviceRoleServer,
			MatchRules: &entities.ProfileMatchRules{
				MACPrefix:    fmt.Sprintf("52:54:%02x", i),
				SerialPrefix: fmt.Sprintf("SN%02d", i),
			},
		}
		_ = service.Save(ctx, profile)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.FindMatchingProfile(ctx, "52:54:32:aa:bb:cc", "SN32001", "ModelX")
	}
}

// Parallel Benchmarks

func BenchmarkDeviceService_Save_Parallel(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		id := uint64(1)
		for pb.Next() {
			device := &entities.Device{
				ID:     id,
				Model:  fmt.Sprintf("TPM-Model-%d", id),
				Serial: fmt.Sprintf("SN%08d", id),
			}
			_ = service.Save(ctx, device)
			id++
		}
	})
}

func BenchmarkDeviceService_Get_Parallel(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	// Pre-populate
	device := &entities.Device{
		ID:     1,
		Model:  "ParallelTPM",
		Serial: "SNPARALLEL001",
	}
	err = service.Save(ctx, device)
	require.NoError(b, err)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = service.Get(ctx, 1)
		}
	})
}

func BenchmarkProfileService_FindMatchingProfile_Parallel(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewProfileService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "ParallelProfile",
		Role: entities.DeviceRoleServer,
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix:    "52:54:00",
			SerialPrefix: "SRV-",
		},
	}
	err = service.Save(ctx, profile)
	require.NoError(b, err)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = service.FindMatchingProfile(ctx, "52:54:00:aa:bb:cc", "SRV-12345", "ModelX")
		}
	})
}

// Memory Allocation Benchmarks

func BenchmarkDeviceService_Save_Allocs(b *testing.B) {
	ds := benchmarkDatastore(b)
	service, err := NewService(ds)
	require.NoError(b, err)

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		device := &entities.Device{
			ID:     uint64(i + 1),
			Model:  "AllocTPM",
			Serial: fmt.Sprintf("SNALLOC%08d", i),
		}
		_ = service.Save(ctx, device)
	}
}

func BenchmarkProfileMatchRules_Matches_Allocs(b *testing.B) {
	rules := &entities.ProfileMatchRules{
		MACPrefix:    "52:54:00",
		SerialPrefix: "SRV-",
		Model:        "Server-TPM-2.0",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rules.Matches("52:54:00:aa:bb:cc", "SRV-12345", "Server-TPM-2.0")
	}
}
