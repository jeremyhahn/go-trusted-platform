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

package cluster

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestCRLDAO_Create(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	now := time.Now().UTC()
	crl := &CRL{
		CRLID:      "test-crl-1",
		DER:        []byte("test-crl-der"),
		Issuer:     "CN=Test CA",
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		TenantID:   "tenant1",
	}

	err := dao.Create(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if crl.Version != 1 {
		t.Errorf("expected version 1, got %d", crl.Version)
	}

	if crl.EntityID() == 0 {
		t.Error("expected entity ID to be set")
	}
}

func TestCRLDAO_Create_NilCRL(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	err := dao.Create(ctx, nil)

	if err == nil {
		t.Fatal("expected error for nil CRL")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestCRLDAO_Create_EmptyID(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	crl := &CRL{
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}

	err := dao.Create(ctx, crl)

	if err == nil {
		t.Fatal("expected error for empty CRL ID")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestCRLDAO_Get(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	now := time.Now().UTC()
	crl := &CRL{
		CRLID:      "test-crl-1",
		DER:        []byte("test-crl-der"),
		Issuer:     "CN=Test CA",
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		TenantID:   "tenant1",
	}

	err := dao.Create(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	retrieved, err := dao.Get(ctx, "test-crl-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.CRLID != crl.CRLID {
		t.Errorf("expected CRLID %s, got %s", crl.CRLID, retrieved.CRLID)
	}

	if retrieved.Issuer != crl.Issuer {
		t.Errorf("expected Issuer %s, got %s", crl.Issuer, retrieved.Issuer)
	}

	if string(retrieved.DER) != string(crl.DER) {
		t.Error("DER mismatch")
	}
}

func TestCRLDAO_Get_NotFound(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	_, err := dao.Get(ctx, "non-existent", "tenant1")

	if err == nil {
		t.Fatal("expected error for non-existent CRL")
	}

	if _, ok := err.(ErrCRLNotFound); !ok {
		t.Errorf("expected ErrCRLNotFound, got %T", err)
	}
}

func TestCRLDAO_Get_EmptyID(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	_, err := dao.Get(ctx, "", "tenant1")

	if err == nil {
		t.Fatal("expected error for empty CRL ID")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestCRLDAO_GetCurrent(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	now := time.Now().UTC()
	crl := &CRL{
		CRLID:      CurrentCRLID,
		DER:        []byte("current-crl-der"),
		Issuer:     "CN=Test CA",
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		TenantID:   "tenant1",
	}

	err := dao.Create(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	retrieved, err := dao.GetCurrent(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.CRLID != CurrentCRLID {
		t.Errorf("expected CRLID %s, got %s", CurrentCRLID, retrieved.CRLID)
	}
}

func TestCRLDAO_GetCurrent_NotFound(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	_, err := dao.GetCurrent(ctx, "tenant1")

	if err == nil {
		t.Fatal("expected error when no current CRL exists")
	}

	if _, ok := err.(ErrCRLNotFound); !ok {
		t.Errorf("expected ErrCRLNotFound, got %T", err)
	}
}

func TestCRLDAO_Update(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	now := time.Now().UTC()
	crl := &CRL{
		CRLID:      "test-crl-1",
		DER:        []byte("original-der"),
		Issuer:     "CN=Test CA",
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		TenantID:   "tenant1",
	}

	err := dao.Create(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	crl.DER = []byte("updated-der")
	err = dao.Update(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error on update, got %v", err)
	}

	if crl.Version != 2 {
		t.Errorf("expected version 2, got %d", crl.Version)
	}

	retrieved, err := dao.Get(ctx, "test-crl-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if string(retrieved.DER) != "updated-der" {
		t.Errorf("expected updated DER, got %s", string(retrieved.DER))
	}
}

func TestCRLDAO_Update_NotFound(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	crl := &CRL{
		CRLID:    "non-existent",
		TenantID: "tenant1",
	}

	err := dao.Update(ctx, crl)

	if err == nil {
		t.Fatal("expected error for non-existent CRL")
	}

	if _, ok := err.(ErrCRLNotFound); !ok {
		t.Errorf("expected ErrCRLNotFound, got %T", err)
	}
}

func TestCRLDAO_Update_VersionConflict(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger, WithCRLOptimisticLocking(true))

	ctx := context.Background()
	now := time.Now().UTC()
	crl := &CRL{
		CRLID:      "test-crl-1",
		DER:        []byte("original-der"),
		Issuer:     "CN=Test CA",
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		TenantID:   "tenant1",
	}

	err := dao.Create(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	// Simulate concurrent update by setting wrong version
	crl.Version = 5
	err = dao.Update(ctx, crl)

	if err == nil {
		t.Fatal("expected version conflict error")
	}

	if _, ok := err.(ErrVersionConflict); !ok {
		t.Errorf("expected ErrVersionConflict, got %T", err)
	}
}

func TestCRLDAO_Delete(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	crl := &CRL{
		CRLID:    "test-crl-1",
		DER:      []byte("test-der"),
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}

	err := dao.Create(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	err = dao.Delete(ctx, "test-crl-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error on delete, got %v", err)
	}

	_, err = dao.Get(ctx, "test-crl-1", "tenant1")
	if _, ok := err.(ErrCRLNotFound); !ok {
		t.Errorf("expected ErrCRLNotFound after delete, got %T", err)
	}
}

func TestCRLDAO_Delete_NotFound(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	err := dao.Delete(ctx, "non-existent", "tenant1")

	if err == nil {
		t.Fatal("expected error for non-existent CRL")
	}

	if _, ok := err.(ErrCRLNotFound); !ok {
		t.Errorf("expected ErrCRLNotFound, got %T", err)
	}
}

func TestCRLDAO_Delete_EmptyID(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	err := dao.Delete(ctx, "", "tenant1")

	if err == nil {
		t.Fatal("expected error for empty CRL ID")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestCRLDAO_List(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()

	// Create multiple CRLs
	for i := 1; i <= 5; i++ {
		crl := &CRL{
			CRLID:    "crl-" + string(rune('0'+i)),
			DER:      []byte("test-der"),
			Issuer:   "CN=Test CA",
			TenantID: "tenant1",
		}
		err := dao.Create(ctx, crl)
		if err != nil {
			t.Fatalf("expected no error on create, got %v", err)
		}
	}

	crls, err := dao.List(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(crls) != 5 {
		t.Errorf("expected 5 CRLs, got %d", len(crls))
	}
}

func TestCRLDAO_List_TenantFilter(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()

	// Create CRLs for different tenants
	for i := 1; i <= 3; i++ {
		crl := &CRL{
			CRLID:    "crl-t1-" + string(rune('0'+i)),
			DER:      []byte("test-der"),
			Issuer:   "CN=Test CA",
			TenantID: "tenant1",
		}
		err := dao.Create(ctx, crl)
		if err != nil {
			t.Fatalf("expected no error on create, got %v", err)
		}
	}

	for i := 1; i <= 2; i++ {
		crl := &CRL{
			CRLID:    "crl-t2-" + string(rune('0'+i)),
			DER:      []byte("test-der"),
			Issuer:   "CN=Test CA",
			TenantID: "tenant2",
		}
		err := dao.Create(ctx, crl)
		if err != nil {
			t.Fatalf("expected no error on create, got %v", err)
		}
	}

	// List for tenant1
	crls1, err := dao.List(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(crls1) != 3 {
		t.Errorf("expected 3 CRLs for tenant1, got %d", len(crls1))
	}

	// List for tenant2
	crls2, err := dao.List(ctx, "tenant2")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(crls2) != 2 {
		t.Errorf("expected 2 CRLs for tenant2, got %d", len(crls2))
	}

	// List for all tenants
	allCRLs, err := dao.List(ctx, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(allCRLs) != 5 {
		t.Errorf("expected 5 CRLs total, got %d", len(allCRLs))
	}
}

func TestCRLDAO_SaveCurrent(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	now := time.Now().UTC()
	crl := &CRL{
		CRLID:      "will-be-overwritten",
		DER:        []byte("current-crl-der"),
		Issuer:     "CN=Test CA",
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		TenantID:   "tenant1",
	}

	err := dao.SaveCurrent(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if crl.CRLID != CurrentCRLID {
		t.Errorf("expected CRLID to be %s, got %s", CurrentCRLID, crl.CRLID)
	}

	retrieved, err := dao.GetCurrent(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if string(retrieved.DER) != string(crl.DER) {
		t.Error("DER mismatch")
	}
}

func TestCRLDAO_Count(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()

	// Create CRLs
	for i := 1; i <= 5; i++ {
		crl := &CRL{
			CRLID:    "crl-" + string(rune('0'+i)),
			DER:      []byte("test-der"),
			Issuer:   "CN=Test CA",
			TenantID: "tenant1",
		}
		err := dao.Create(ctx, crl)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	count, err := dao.Count(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if count != 5 {
		t.Errorf("expected count 5, got %d", count)
	}
}

func TestCRLDAO_Options(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()

	dao := NewCRLDAO(
		storage,
		logger,
		WithCRLRequestTimeout(5*time.Second),
		WithCRLOptimisticLocking(false),
	)

	if dao.requestTimeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", dao.requestTimeout)
	}

	if dao.enableOptimisticLocking {
		t.Error("expected optimistic locking to be disabled")
	}
}

func TestCRLIDToEntityID(t *testing.T) {
	id1 := crlIDToEntityID("crl-1", "tenant1")
	id2 := crlIDToEntityID("crl-1", "tenant1")
	id3 := crlIDToEntityID("crl-2", "tenant1")
	id4 := crlIDToEntityID("crl-1", "tenant2")

	// Same ID and tenant should produce same entity ID
	if id1 != id2 {
		t.Errorf("expected same entity ID, got %d and %d", id1, id2)
	}

	// Different CRL ID should produce different entity ID
	if id1 == id3 {
		t.Error("expected different entity ID for different CRL ID")
	}

	// Different tenant should produce different entity ID
	if id1 == id4 {
		t.Error("expected different entity ID for different tenant")
	}

	// ID should not be zero
	if id1 == 0 {
		t.Error("expected non-zero ID")
	}
}

func TestCRL_IsExpired(t *testing.T) {
	now := time.Now().UTC()

	expiredCRL := &CRL{NextUpdate: now.Add(-1 * time.Hour)}
	if !expiredCRL.IsExpired() {
		t.Error("expected IsExpired() to return true")
	}

	validCRL := &CRL{NextUpdate: now.Add(1 * time.Hour)}
	if validCRL.IsExpired() {
		t.Error("expected IsExpired() to return false")
	}
}

func TestCRLDAO_StorageErrors(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	crl := &CRL{
		CRLID:    "test-crl",
		DER:      []byte("test-der"),
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}

	// Test Put error
	storage.SetPutError(ErrOperationFailed{Operation: "put"})
	err := dao.Create(ctx, crl)
	if err == nil {
		t.Fatal("expected error from storage")
	}
	storage.SetPutError(nil)

	// Test Get error
	storage.SetGetError(ErrOperationFailed{Operation: "get"})
	_, err = dao.Get(ctx, "test-crl", "tenant1")
	if err == nil {
		t.Fatal("expected error from storage")
	}
	storage.SetGetError(nil)

	// Test List error
	storage.SetListError(ErrOperationFailed{Operation: "list"})
	_, err = dao.List(ctx, "tenant1")
	if err == nil {
		t.Fatal("expected error from storage")
	}
	storage.SetListError(nil)
}

func TestCRLDAO_Concurrent(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent creates
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			crl := &CRL{
				CRLID:    "crl-" + string(rune('A'+id)),
				DER:      []byte("test-der"),
				Issuer:   "CN=Test CA",
				TenantID: "tenant1",
			}
			err := dao.Create(ctx, crl)
			if err != nil {
				t.Errorf("unexpected error in goroutine %d: %v", id, err)
			}
		}(i)
	}
	wg.Wait()

	// Verify all CRLs were created
	count, err := dao.Count(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != numGoroutines {
		t.Errorf("expected %d CRLs, got %d", numGoroutines, count)
	}
}

func TestNewCRL(t *testing.T) {
	now := time.Now().UTC()
	nextUpdate := now.Add(24 * time.Hour)

	crl := NewCRL("test-crl", []byte("test-der"), "CN=Issuer", now, nextUpdate, "tenant1")

	if crl.CRLID != "test-crl" {
		t.Errorf("expected CRLID test-crl, got %s", crl.CRLID)
	}

	if string(crl.DER) != "test-der" {
		t.Error("DER mismatch")
	}

	if crl.Issuer != "CN=Issuer" {
		t.Errorf("expected Issuer CN=Issuer, got %s", crl.Issuer)
	}

	if crl.TenantID != "tenant1" {
		t.Errorf("expected TenantID tenant1, got %s", crl.TenantID)
	}

	if crl.Version != 1 {
		t.Errorf("expected Version 1, got %d", crl.Version)
	}

	if crl.RevokedCertificates == nil {
		t.Error("expected RevokedCertificates to be initialized")
	}
}

func TestCRL_EntityID(t *testing.T) {
	crl := &CRL{}

	// Initially should be 0
	if crl.EntityID() != 0 {
		t.Errorf("expected EntityID 0, got %d", crl.EntityID())
	}

	// Set and verify
	crl.SetEntityID(12345)
	if crl.EntityID() != 12345 {
		t.Errorf("expected EntityID 12345, got %d", crl.EntityID())
	}
}

// BenchmarkCRLDAO_Create benchmarks CRL creation
func BenchmarkCRLDAO_Create(b *testing.B) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crl := &CRL{
			CRLID:    "crl-" + string(rune('A'+i%26)),
			DER:      []byte("test-der"),
			Issuer:   "CN=Test CA",
			TenantID: "tenant1",
		}
		_ = dao.Create(ctx, crl)
	}
}

// BenchmarkCRLDAO_Get benchmarks CRL retrieval
func BenchmarkCRLDAO_Get(b *testing.B) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	crl := &CRL{
		CRLID:    "test-crl",
		DER:      []byte("test-der"),
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}
	_ = dao.Create(ctx, crl)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dao.Get(ctx, "test-crl", "tenant1")
	}
}

// BenchmarkCRLIDToEntityID benchmarks the hash function
func BenchmarkCRLIDToEntityID(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = crlIDToEntityID("test-crl-id", "tenant1")
	}
}
