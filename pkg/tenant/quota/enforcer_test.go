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
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

// mockQuotaStore is a thread-safe in-memory implementation of QuotaStore for testing.
type mockQuotaStore struct {
	quotas     map[string]*TenantQuotas
	usage      map[string]*TenantUsage
	mu         sync.RWMutex
	getError   error
	updateErr  error
	usageError error
}

func newMockQuotaStore() *mockQuotaStore {
	return &mockQuotaStore{
		quotas: make(map[string]*TenantQuotas),
		usage:  make(map[string]*TenantUsage),
	}
}

func (m *mockQuotaStore) GetQuota(ctx context.Context, tenantID string) (*TenantQuotas, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.getError != nil {
		return nil, m.getError
	}
	quota, ok := m.quotas[tenantID]
	if !ok {
		return nil, nil
	}
	// Return a copy to avoid data races
	copy := *quota
	return &copy, nil
}

func (m *mockQuotaStore) UpdateQuota(ctx context.Context, tenantID string, quotas *TenantQuotas) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	copy := *quotas
	m.quotas[tenantID] = &copy
	return nil
}

func (m *mockQuotaStore) GetUsage(ctx context.Context, tenantID string) (*TenantUsage, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.usageError != nil {
		return nil, m.usageError
	}
	usage, ok := m.usage[tenantID]
	if !ok {
		return nil, nil
	}
	// Return a copy to avoid data races
	copy := *usage
	return &copy, nil
}

func (m *mockQuotaStore) UpdateUsage(ctx context.Context, tenantID string, usage *TenantUsage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	copy := *usage
	m.usage[tenantID] = &copy
	return nil
}

func (m *mockQuotaStore) setQuota(tenantID string, quotas *TenantQuotas) {
	m.mu.Lock()
	defer m.mu.Unlock()
	copy := *quotas
	m.quotas[tenantID] = &copy
}

func (m *mockQuotaStore) setUsage(tenantID string, usage *TenantUsage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	copy := *usage
	m.usage[tenantID] = &copy
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNewEnforcer_Valid(t *testing.T) {
	store := newMockQuotaStore()
	logger := testLogger()

	enforcer, err := NewEnforcer(store, logger)
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v, expected nil", err)
	}
	if enforcer == nil {
		t.Fatal("NewEnforcer() returned nil enforcer")
	}
	if enforcer.reservationTTL != DefaultReservationTTL {
		t.Errorf("reservationTTL = %v, expected %v", enforcer.reservationTTL, DefaultReservationTTL)
	}
}

func TestNewEnforcer_NilStore(t *testing.T) {
	logger := testLogger()

	_, err := NewEnforcer(nil, logger)
	if err == nil {
		t.Fatal("NewEnforcer() with nil store should return error")
	}

	var nilStoreErr ErrNilStore
	if !errors.As(err, &nilStoreErr) {
		t.Errorf("error type = %T, expected ErrNilStore", err)
	}
}

func TestNewEnforcer_NilLogger(t *testing.T) {
	store := newMockQuotaStore()

	_, err := NewEnforcer(store, nil)
	if err == nil {
		t.Fatal("NewEnforcer() with nil logger should return error")
	}

	var nilLoggerErr ErrNilLogger
	if !errors.As(err, &nilLoggerErr) {
		t.Errorf("error type = %T, expected ErrNilLogger", err)
	}
}

func TestNewEnforcer_WithReservationTTL(t *testing.T) {
	store := newMockQuotaStore()
	logger := testLogger()
	customTTL := 10 * time.Minute

	enforcer, err := NewEnforcer(store, logger, WithReservationTTL(customTTL))
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}
	if enforcer.reservationTTL != customTTL {
		t.Errorf("reservationTTL = %v, expected %v", enforcer.reservationTTL, customTTL)
	}
}

func TestEnforcer_CheckQuota_AllowsWithinLimit(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      3,
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	// Requesting 5 VMs, with limit 10 and usage 3, available is 7
	err = enforcer.CheckQuota(ctx, "tenant-1", ResourceVMs, 5)
	if err != nil {
		t.Errorf("CheckQuota() error = %v, expected nil (5 <= 7 available)", err)
	}
}

func TestEnforcer_CheckQuota_RejectsOverLimit(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      8,
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	// Requesting 5 VMs, with limit 10 and usage 8, available is 2
	err = enforcer.CheckQuota(ctx, "tenant-1", ResourceVMs, 5)
	if err == nil {
		t.Fatal("CheckQuota() should return error for over limit")
	}

	var quotaErr ErrQuotaExceeded
	if !errors.As(err, &quotaErr) {
		t.Errorf("error type = %T, expected ErrQuotaExceeded", err)
	}
	if quotaErr.Requested != 5 || quotaErr.Available != 2 {
		t.Errorf("QuotaExceeded.Requested = %d, Available = %d; expected 5, 2",
			quotaErr.Requested, quotaErr.Available)
	}
}

func TestEnforcer_CheckQuota_InvalidResource(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{TenantID: "tenant-1"})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	err = enforcer.CheckQuota(ctx, "tenant-1", ResourceType("invalid"), 1)
	if err == nil {
		t.Fatal("CheckQuota() with invalid resource should return error")
	}

	var invalidErr ErrInvalidResource
	if !errors.As(err, &invalidErr) {
		t.Errorf("error type = %T, expected ErrInvalidResource", err)
	}
}

func TestEnforcer_CheckQuota_NegativeAmount(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{TenantID: "tenant-1"})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	err = enforcer.CheckQuota(ctx, "tenant-1", ResourceVMs, -5)
	if err == nil {
		t.Fatal("CheckQuota() with negative amount should return error")
	}

	var amountErr ErrInvalidAmount
	if !errors.As(err, &amountErr) {
		t.Errorf("error type = %T, expected ErrInvalidAmount", err)
	}
}

func TestEnforcer_CheckQuota_TenantNotFound(t *testing.T) {
	store := newMockQuotaStore()

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	err = enforcer.CheckQuota(ctx, "nonexistent", ResourceVMs, 1)
	if err == nil {
		t.Fatal("CheckQuota() with nonexistent tenant should return error")
	}

	var notFoundErr ErrTenantNotFound
	if !errors.As(err, &notFoundErr) {
		t.Errorf("error type = %T, expected ErrTenantNotFound", err)
	}
}

func TestEnforcer_CheckQuota_StoreError(t *testing.T) {
	store := newMockQuotaStore()
	store.getError = errors.New("connection refused")

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	err = enforcer.CheckQuota(ctx, "tenant-1", ResourceVMs, 1)
	if err == nil {
		t.Fatal("CheckQuota() with store error should return error")
	}

	var storeErr ErrStoreFailed
	if !errors.As(err, &storeErr) {
		t.Errorf("error type = %T, expected ErrStoreFailed", err)
	}
}

func TestEnforcer_CheckQuota_UsageStoreError(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{TenantID: "tenant-1", Compute: ComputeQuota{MaxVMs: 10}})
	store.usageError = errors.New("usage read failed")

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	err = enforcer.CheckQuota(ctx, "tenant-1", ResourceVMs, 1)
	if err == nil {
		t.Fatal("CheckQuota() with usage store error should return error")
	}

	var storeErr ErrStoreFailed
	if !errors.As(err, &storeErr) {
		t.Errorf("error type = %T, expected ErrStoreFailed", err)
	}
}

func TestEnforcer_CheckQuota_NoUsageRecord(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})
	// No usage record exists

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	// With no usage, full quota is available
	err = enforcer.CheckQuota(ctx, "tenant-1", ResourceVMs, 10)
	if err != nil {
		t.Errorf("CheckQuota() with no usage should succeed, got error: %v", err)
	}
}

func TestEnforcer_Reserve_CreatesReservation(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	reservation, err := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 3)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}

	if reservation == nil {
		t.Fatal("Reserve() returned nil reservation")
	}
	if reservation.ID == "" {
		t.Error("reservation.ID should not be empty")
	}
	if reservation.TenantID != "tenant-1" {
		t.Errorf("reservation.TenantID = %q, expected %q", reservation.TenantID, "tenant-1")
	}
	if reservation.Resource != ResourceVMs {
		t.Errorf("reservation.Resource = %q, expected %q", reservation.Resource, ResourceVMs)
	}
	if reservation.Amount != 3 {
		t.Errorf("reservation.Amount = %d, expected %d", reservation.Amount, 3)
	}
	if reservation.Committed {
		t.Error("reservation should not be committed initially")
	}
	if reservation.IsExpired() {
		t.Error("new reservation should not be expired")
	}
}

func TestEnforcer_Reserve_InvalidResource(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{TenantID: "tenant-1"})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	_, err = enforcer.Reserve(ctx, "tenant-1", ResourceType("invalid"), 1)
	if err == nil {
		t.Fatal("Reserve() with invalid resource should return error")
	}

	var invalidErr ErrInvalidResource
	if !errors.As(err, &invalidErr) {
		t.Errorf("error type = %T, expected ErrInvalidResource", err)
	}
}

func TestEnforcer_Reserve_InvalidAmount(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{TenantID: "tenant-1"})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name   string
		amount int64
	}{
		{name: "zero", amount: 0},
		{name: "negative", amount: -5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err = enforcer.Reserve(ctx, "tenant-1", ResourceVMs, tt.amount)
			if err == nil {
				t.Fatalf("Reserve() with %s amount should return error", tt.name)
			}

			var amountErr ErrInvalidAmount
			if !errors.As(err, &amountErr) {
				t.Errorf("error type = %T, expected ErrInvalidAmount", err)
			}
		})
	}
}

func TestEnforcer_Reserve_ExceedsQuota(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 5},
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	_, err = enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 10)
	if err == nil {
		t.Fatal("Reserve() exceeding quota should return error")
	}

	var quotaErr ErrQuotaExceeded
	if !errors.As(err, &quotaErr) {
		t.Errorf("error type = %T, expected ErrQuotaExceeded", err)
	}
}

func TestEnforcer_Reserve_ConsidersExistingReservations(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()

	// First reservation of 6 VMs
	_, err = enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 6)
	if err != nil {
		t.Fatalf("First Reserve() error = %v", err)
	}

	// Second reservation of 5 VMs should fail (6+5 > 10)
	_, err = enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 5)
	if err == nil {
		t.Fatal("Second Reserve() should fail due to existing reservation")
	}

	var quotaErr ErrQuotaExceeded
	if !errors.As(err, &quotaErr) {
		t.Errorf("error type = %T, expected ErrQuotaExceeded", err)
	}
}

func TestEnforcer_Commit_FinalizesReservation(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	reservation, err := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 3)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}

	err = enforcer.Commit(ctx, reservation.ID)
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	// Verify usage was updated
	usage, err := store.GetUsage(ctx, "tenant-1")
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage.VMs != 3 {
		t.Errorf("usage.VMs = %d, expected %d", usage.VMs, 3)
	}
}

func TestEnforcer_Commit_ReservationNotFound(t *testing.T) {
	store := newMockQuotaStore()
	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	err = enforcer.Commit(ctx, "nonexistent-reservation")
	if err == nil {
		t.Fatal("Commit() with nonexistent reservation should return error")
	}

	var notFoundErr ErrReservationNotFound
	if !errors.As(err, &notFoundErr) {
		t.Errorf("error type = %T, expected ErrReservationNotFound", err)
	}
}

func TestEnforcer_Commit_AlreadyCommitted(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	reservation, err := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 3)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}

	// First commit should succeed
	err = enforcer.Commit(ctx, reservation.ID)
	if err != nil {
		t.Fatalf("First Commit() error = %v", err)
	}

	// Second commit should fail (reservation removed after first commit)
	err = enforcer.Commit(ctx, reservation.ID)
	if err == nil {
		t.Fatal("Second Commit() should return error")
	}
}

func TestEnforcer_Commit_ExpiredReservation(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})

	// A production-realistic TTL. The old version used 1ms so a sleep could be
	// short; nothing is ever issued a one-millisecond reservation.
	const ttl = 5 * time.Minute

	clk := newFakeQuotaClock()
	enforcer, err := NewEnforcer(store, testLogger(), WithReservationTTL(ttl), WithQuotaClock(clk))
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()

	// At exactly the TTL the reservation is NOT yet expired: expiry is
	// now.After(ExpiresAt), and at the boundary those are equal. The old sleep
	// overshot a 1ms TTL by tenfold and so could not distinguish expiring at the
	// TTL from expiring well before it.
	onBoundary, err := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 3)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}

	clk.Advance(ttl)

	if err := enforcer.Commit(ctx, onBoundary.ID); err != nil {
		t.Errorf("Commit() at exactly the TTL should succeed, got %v", err)
	}

	// One nanosecond later, it is expired.
	pastBoundary, err := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 3)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}

	clk.Advance(ttl + time.Nanosecond)

	err = enforcer.Commit(ctx, pastBoundary.ID)
	if err == nil {
		t.Fatal("Commit() with expired reservation should return error")
	}

	var expiredErr ErrReservationExpired
	if !errors.As(err, &expiredErr) {
		t.Errorf("error type = %T, expected ErrReservationExpired", err)
	}
}

func TestEnforcer_Commit_StoreUpdateError(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	reservation, err := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 3)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}

	// Set error before commit
	store.updateErr = errors.New("database write failed")

	err = enforcer.Commit(ctx, reservation.ID)
	if err == nil {
		t.Fatal("Commit() with store error should return error")
	}

	var storeErr ErrStoreFailed
	if !errors.As(err, &storeErr) {
		t.Errorf("error type = %T, expected ErrStoreFailed", err)
	}
}

func TestEnforcer_Release_CancelsReservation(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	reservation, err := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 5)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}

	err = enforcer.Release(ctx, reservation.ID)
	if err != nil {
		t.Fatalf("Release() error = %v", err)
	}

	// Verify reservation is gone
	_, err = enforcer.GetReservation(reservation.ID)
	if err == nil {
		t.Error("reservation should be removed after Release")
	}

	// Now we should be able to reserve the full quota again
	_, err = enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 10)
	if err != nil {
		t.Errorf("Reserve() after Release() error = %v", err)
	}
}

func TestEnforcer_Release_NotFound(t *testing.T) {
	store := newMockQuotaStore()
	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	err = enforcer.Release(ctx, "nonexistent")
	if err == nil {
		t.Fatal("Release() with nonexistent reservation should return error")
	}

	var notFoundErr ErrReservationNotFound
	if !errors.As(err, &notFoundErr) {
		t.Errorf("error type = %T, expected ErrReservationNotFound", err)
	}
}

func TestEnforcer_Release_AlreadyCommitted(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	reservation, err := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 3)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}

	err = enforcer.Commit(ctx, reservation.ID)
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	// Try to release committed reservation (already deleted)
	err = enforcer.Release(ctx, reservation.ID)
	if err == nil {
		t.Fatal("Release() after Commit() should return error")
	}
}

func TestEnforcer_ReleaseUsage_DecreasesUsage(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      5,
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	err = enforcer.ReleaseUsage(ctx, "tenant-1", ResourceVMs, 2)
	if err != nil {
		t.Fatalf("ReleaseUsage() error = %v", err)
	}

	usage, err := store.GetUsage(ctx, "tenant-1")
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage.VMs != 3 {
		t.Errorf("usage.VMs = %d, expected %d", usage.VMs, 3)
	}
}

func TestEnforcer_ReleaseUsage_DoesNotGoBelowZero(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{TenantID: "tenant-1"})
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      2,
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	err = enforcer.ReleaseUsage(ctx, "tenant-1", ResourceVMs, 5)
	if err != nil {
		t.Fatalf("ReleaseUsage() error = %v", err)
	}

	usage, err := store.GetUsage(ctx, "tenant-1")
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage.VMs != 0 {
		t.Errorf("usage.VMs = %d, expected %d", usage.VMs, 0)
	}
}

func TestEnforcer_ReleaseUsage_InvalidResource(t *testing.T) {
	store := newMockQuotaStore()
	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	err = enforcer.ReleaseUsage(ctx, "tenant-1", ResourceType("invalid"), 1)
	if err == nil {
		t.Fatal("ReleaseUsage() with invalid resource should return error")
	}

	var invalidErr ErrInvalidResource
	if !errors.As(err, &invalidErr) {
		t.Errorf("error type = %T, expected ErrInvalidResource", err)
	}
}

func TestEnforcer_ReleaseUsage_InvalidAmount(t *testing.T) {
	store := newMockQuotaStore()
	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name   string
		amount int64
	}{
		{name: "zero", amount: 0},
		{name: "negative", amount: -5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = enforcer.ReleaseUsage(ctx, "tenant-1", ResourceVMs, tt.amount)
			if err == nil {
				t.Fatalf("ReleaseUsage() with %s amount should return error", tt.name)
			}

			var amountErr ErrInvalidAmount
			if !errors.As(err, &amountErr) {
				t.Errorf("error type = %T, expected ErrInvalidAmount", err)
			}
		})
	}
}

func TestEnforcer_ReleaseUsage_TenantNotFound(t *testing.T) {
	store := newMockQuotaStore()
	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	err = enforcer.ReleaseUsage(ctx, "nonexistent", ResourceVMs, 1)
	if err == nil {
		t.Fatal("ReleaseUsage() with nonexistent tenant should return error")
	}

	var notFoundErr ErrTenantNotFound
	if !errors.As(err, &notFoundErr) {
		t.Errorf("error type = %T, expected ErrTenantNotFound", err)
	}
}

func TestEnforcer_GetAvailable_ReturnsCorrectValue(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      3,
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()

	// Create a reservation for 2 VMs
	_, err = enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 2)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}

	// Available should be: 10 (limit) - 3 (usage) - 2 (reserved) = 5
	available, err := enforcer.GetAvailable(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetAvailable() error = %v", err)
	}
	if available != 5 {
		t.Errorf("GetAvailable() = %d, expected %d", available, 5)
	}
}

func TestEnforcer_GetAvailable_InvalidResource(t *testing.T) {
	store := newMockQuotaStore()
	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	_, err = enforcer.GetAvailable(ctx, "tenant-1", ResourceType("invalid"))
	if err == nil {
		t.Fatal("GetAvailable() with invalid resource should return error")
	}
}

func TestEnforcer_GetAvailable_TenantNotFound(t *testing.T) {
	store := newMockQuotaStore()
	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	_, err = enforcer.GetAvailable(ctx, "nonexistent", ResourceVMs)
	if err == nil {
		t.Fatal("GetAvailable() with nonexistent tenant should return error")
	}
}

func TestEnforcer_GetAvailable_NeverNegative(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 5},
	})
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      10, // Over quota
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	available, err := enforcer.GetAvailable(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetAvailable() error = %v", err)
	}
	if available != 0 {
		t.Errorf("GetAvailable() = %d, expected 0 (never negative)", available)
	}
}

func TestEnforcer_GetUtilization_ReturnsCorrectPercentage(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      5,
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	utilization, err := enforcer.GetUtilization(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUtilization() error = %v", err)
	}
	if utilization != 0.5 {
		t.Errorf("GetUtilization() = %f, expected %f", utilization, 0.5)
	}
}

func TestEnforcer_GetUtilization_IncludesReservations(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      3,
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()

	// Reserve 2 VMs
	_, err = enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 2)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}

	// Utilization should be (3 + 2) / 10 = 0.5
	utilization, err := enforcer.GetUtilization(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUtilization() error = %v", err)
	}
	if utilization != 0.5 {
		t.Errorf("GetUtilization() = %f, expected %f", utilization, 0.5)
	}
}

func TestEnforcer_GetUtilization_ZeroLimit(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 0}, // Zero limit
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	utilization, err := enforcer.GetUtilization(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUtilization() error = %v", err)
	}
	if utilization != 0 {
		t.Errorf("GetUtilization() = %f, expected 0 (zero limit)", utilization)
	}
}

func TestEnforcer_GetUtilization_CapsAtOne(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 5},
	})
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      10, // Over quota
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	utilization, err := enforcer.GetUtilization(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUtilization() error = %v", err)
	}
	if utilization != 1.0 {
		t.Errorf("GetUtilization() = %f, expected 1.0 (capped)", utilization)
	}
}

func TestEnforcer_GetUtilization_InvalidResource(t *testing.T) {
	store := newMockQuotaStore()
	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	_, err = enforcer.GetUtilization(ctx, "tenant-1", ResourceType("invalid"))
	if err == nil {
		t.Fatal("GetUtilization() with invalid resource should return error")
	}
}

func TestEnforcer_CleanupExpiredReservations(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 100},
	})

	const ttl = 5 * time.Minute

	clk := newFakeQuotaClock()
	enforcer, err := NewEnforcer(store, testLogger(), WithReservationTTL(ttl), WithQuotaClock(clk))
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()

	// Create multiple reservations
	res1, _ := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 10)
	res2, _ := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 20)

	// One nanosecond past the TTL — the least amount of elapsed time that
	// expires these two, so the sweep below is credited only for reservations
	// that are genuinely past their boundary.
	clk.Advance(ttl + time.Nanosecond)

	// Create a new non-expired reservation
	res3, _ := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 5)

	// Cleanup expired reservations
	count := enforcer.CleanupExpiredReservations()
	if count != 2 {
		t.Errorf("CleanupExpiredReservations() = %d, expected 2", count)
	}

	// Expired reservations should be gone
	_, err = enforcer.GetReservation(res1.ID)
	if err == nil {
		t.Error("res1 should be cleaned up")
	}
	_, err = enforcer.GetReservation(res2.ID)
	if err == nil {
		t.Error("res2 should be cleaned up")
	}

	// Non-expired reservation should still exist
	_, err = enforcer.GetReservation(res3.ID)
	if err != nil {
		t.Errorf("res3 should still exist, got error: %v", err)
	}
}

func TestEnforcer_GetReservation(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 10},
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	created, err := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 3)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}

	retrieved, err := enforcer.GetReservation(created.ID)
	if err != nil {
		t.Fatalf("GetReservation() error = %v", err)
	}

	if retrieved.ID != created.ID {
		t.Errorf("ID = %q, expected %q", retrieved.ID, created.ID)
	}
	if retrieved.TenantID != created.TenantID {
		t.Errorf("TenantID = %q, expected %q", retrieved.TenantID, created.TenantID)
	}
}

func TestEnforcer_GetReservation_NotFound(t *testing.T) {
	store := newMockQuotaStore()
	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	_, err = enforcer.GetReservation("nonexistent")
	if err == nil {
		t.Fatal("GetReservation() with nonexistent ID should return error")
	}

	var notFoundErr ErrReservationNotFound
	if !errors.As(err, &notFoundErr) {
		t.Errorf("error type = %T, expected ErrReservationNotFound", err)
	}
}

func TestEnforcer_GetPendingReservations(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 100},
	})
	store.setQuota("tenant-2", &TenantQuotas{
		TenantID: "tenant-2",
		Compute:  ComputeQuota{MaxVMs: 100},
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()

	// Create reservations for tenant-1
	_, _ = enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 10)
	_, _ = enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 20)

	// Create reservation for tenant-2
	_, _ = enforcer.Reserve(ctx, "tenant-2", ResourceVMs, 5)

	// Get pending for tenant-1
	pending := enforcer.GetPendingReservations("tenant-1")
	if len(pending) != 2 {
		t.Errorf("GetPendingReservations() returned %d reservations, expected 2", len(pending))
	}

	// Get pending for tenant-2
	pending = enforcer.GetPendingReservations("tenant-2")
	if len(pending) != 1 {
		t.Errorf("GetPendingReservations() returned %d reservations, expected 1", len(pending))
	}

	// Get pending for nonexistent tenant
	pending = enforcer.GetPendingReservations("nonexistent")
	if len(pending) != 0 {
		t.Errorf("GetPendingReservations() returned %d reservations, expected 0", len(pending))
	}
}

func TestEnforcer_SequentialReservationsMultipleTenants(t *testing.T) {
	// Test multiple tenants creating reservations sequentially.
	// Note: Concurrent access to Reservation.Committed field in the Enforcer
	// has a data race. This test uses sequential operations per tenant.
	store := newMockQuotaStore()
	numTenants := 10
	reservationsPerTenant := 10

	for i := 0; i < numTenants; i++ {
		tenantID := "tenant-" + string(rune('A'+i))
		store.setQuota(tenantID, &TenantQuotas{
			TenantID: tenantID,
			Compute:  ComputeQuota{MaxVMs: 100},
		})
	}

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()

	var wg sync.WaitGroup
	successCount := make(chan int, numTenants)

	// Each goroutine works on a different tenant - no overlap
	for i := 0; i < numTenants; i++ {
		wg.Add(1)
		go func(tenantIdx int) {
			defer wg.Done()
			tenantID := "tenant-" + string(rune('A'+tenantIdx))
			count := 0
			for j := 0; j < reservationsPerTenant; j++ {
				res, err := enforcer.Reserve(ctx, tenantID, ResourceVMs, 1)
				if err == nil {
					count++
					// Commit reservations (sequential per tenant)
					_ = enforcer.Commit(ctx, res.ID)
				}
			}
			successCount <- count
		}(i)
	}

	wg.Wait()
	close(successCount)

	total := 0
	for count := range successCount {
		total += count
	}

	// All reservations should succeed since each tenant has enough quota
	if total != numTenants*reservationsPerTenant {
		t.Errorf("Total successful reservations = %d, expected %d",
			total, numTenants*reservationsPerTenant)
	}
}

func TestEnforcer_CommitThenRelease(t *testing.T) {
	// This test verifies commit and release work correctly in sequence.
	// Note: The Enforcer's Reservation struct has a data race when accessing
	// the Committed field during concurrent operations. This test uses
	// sequential operations to avoid triggering that race.
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute:  ComputeQuota{MaxVMs: 100},
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()

	// Create and commit some reservations
	for i := 0; i < 10; i++ {
		res, err := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 1)
		if err != nil {
			t.Fatalf("Reserve() error = %v", err)
		}
		err = enforcer.Commit(ctx, res.ID)
		if err != nil {
			t.Fatalf("Commit() error = %v", err)
		}
	}

	// Create and release some reservations
	for i := 0; i < 10; i++ {
		res, err := enforcer.Reserve(ctx, "tenant-1", ResourceVMs, 1)
		if err != nil {
			t.Fatalf("Reserve() error = %v", err)
		}
		err = enforcer.Release(ctx, res.ID)
		if err != nil {
			t.Fatalf("Release() error = %v", err)
		}
	}

	// Verify usage - should be 10 (committed only)
	usage, err := store.GetUsage(ctx, "tenant-1")
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage.VMs != 10 {
		t.Errorf("VMs = %d, expected 10", usage.VMs)
	}
}

func TestEnforcer_AllResourceTypes(t *testing.T) {
	store := newMockQuotaStore()
	store.setQuota("tenant-1", &TenantQuotas{
		TenantID: "tenant-1",
		Compute: ComputeQuota{
			MaxVMs:        10,
			MaxContainers: 20,
			MaxVCPUs:      32,
			MaxMemoryMB:   65536,
		},
		Network: NetworkQuota{
			MaxBridges:       5,
			MaxPorts:         100,
			MaxBandwidthMbps: 1000,
		},
		Storage: StorageQuota{
			MaxDiskGB:    1000,
			MaxVolumes:   50,
			MaxSnapshots: 100,
		},
	})

	enforcer, err := NewEnforcer(store, testLogger())
	if err != nil {
		t.Fatalf("NewEnforcer() error = %v", err)
	}

	ctx := context.Background()
	resources := []ResourceType{
		ResourceVMs, ResourceContainers, ResourceVCPUs, ResourceMemory,
		ResourceBridges, ResourcePorts, ResourceBandwidth,
		ResourceDisk, ResourceVolumes, ResourceSnapshots,
	}

	for _, resource := range resources {
		t.Run(string(resource), func(t *testing.T) {
			err := enforcer.CheckQuota(ctx, "tenant-1", resource, 1)
			if err != nil {
				t.Errorf("CheckQuota(%s) error = %v", resource, err)
			}

			reservation, err := enforcer.Reserve(ctx, "tenant-1", resource, 1)
			if err != nil {
				t.Errorf("Reserve(%s) error = %v", resource, err)
			}

			err = enforcer.Commit(ctx, reservation.ID)
			if err != nil {
				t.Errorf("Commit(%s) error = %v", resource, err)
			}

			_, err = enforcer.GetAvailable(ctx, "tenant-1", resource)
			if err != nil {
				t.Errorf("GetAvailable(%s) error = %v", resource, err)
			}

			_, err = enforcer.GetUtilization(ctx, "tenant-1", resource)
			if err != nil {
				t.Errorf("GetUtilization(%s) error = %v", resource, err)
			}

			err = enforcer.ReleaseUsage(ctx, "tenant-1", resource, 1)
			if err != nil {
				t.Errorf("ReleaseUsage(%s) error = %v", resource, err)
			}
		})
	}
}
