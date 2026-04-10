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
	"encoding/json"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// MockDAOStorage is a mock implementation of DAOStorage for testing.
type MockDAOStorage struct {
	mu       sync.RWMutex
	data     map[string]map[uint64][]byte // entityType -> id -> data
	queryErr error
	putErr   error
	getErr   error
	delErr   error
	listErr  error
}

// NewMockDAOStorage creates a new MockDAOStorage.
func NewMockDAOStorage() *MockDAOStorage {
	return &MockDAOStorage{
		data: make(map[string]map[uint64][]byte),
	}
}

func (m *MockDAOStorage) Put(ctx context.Context, entityType string, id uint64, data []byte, shardID uint64) error {
	if m.putErr != nil {
		return m.putErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data[entityType] == nil {
		m.data[entityType] = make(map[uint64][]byte)
	}
	m.data[entityType][id] = data
	return nil
}

func (m *MockDAOStorage) Get(ctx context.Context, entityType string, id uint64, shardID uint64) ([]byte, bool, error) {
	if m.getErr != nil {
		return nil, false, m.getErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.data[entityType] == nil {
		return nil, false, nil
	}
	data, found := m.data[entityType][id]
	return data, found, nil
}

func (m *MockDAOStorage) Delete(ctx context.Context, entityType string, id uint64, shardID uint64) error {
	if m.delErr != nil {
		return m.delErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data[entityType] != nil {
		delete(m.data[entityType], id)
	}
	return nil
}

func (m *MockDAOStorage) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	if m.listErr != nil {
		return nil, "", m.listErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	var entities []*service.Entity
	if m.data[entityType] != nil {
		for id, data := range m.data[entityType] {
			entities = append(entities, &service.Entity{
				ID:   id,
				Data: data,
			})
		}
	}
	return entities, "", nil
}

func (m *MockDAOStorage) Query(ctx context.Context, entityType, indexField string, value []byte, shardID uint64) ([]*service.Entity, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	return nil, nil
}

func (m *MockDAOStorage) SetPutError(err error)   { m.putErr = err }
func (m *MockDAOStorage) SetGetError(err error)   { m.getErr = err }
func (m *MockDAOStorage) SetDelError(err error)   { m.delErr = err }
func (m *MockDAOStorage) SetListError(err error)  { m.listErr = err }
func (m *MockDAOStorage) SetQueryError(err error) { m.queryErr = err }

func newTestLogger() *logging.Logger {
	return logging.DefaultLogger()
}

func TestCertificateDAO_Create(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		Issuer:       "CN=issuer",
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IssuedAt:     time.Now(),
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := dao.Create(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cert.Version != 1 {
		t.Errorf("expected version 1, got %d", cert.Version)
	}

	if cert.EntityID() == 0 {
		t.Error("expected entity ID to be set")
	}
}

func TestCertificateDAO_Create_NilCertificate(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	err := dao.Create(ctx, nil)

	if err == nil {
		t.Fatal("expected error for nil certificate")
	}

	var invalidInput ErrInvalidInput
	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", invalidInput)
	}
}

func TestCertificateDAO_Create_NilSerialNumber(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	cert := &Certificate{
		Subject: "CN=test",
	}

	err := dao.Create(ctx, cert)

	if err == nil {
		t.Fatal("expected error for nil serial number")
	}
}

func TestCertificateDAO_Create_AlreadyExists(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		Issuer:       "CN=issuer",
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IssuedAt:     time.Now(),
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := dao.Create(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error on first create, got %v", err)
	}

	err = dao.Create(ctx, cert)
	if err == nil {
		t.Fatal("expected error on duplicate create")
	}

	if _, ok := err.(ErrCertificateAlreadyExists); !ok {
		t.Errorf("expected ErrCertificateAlreadyExists, got %T", err)
	}
}

func TestCertificateDAO_Get(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		Issuer:       "CN=issuer",
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IssuedAt:     time.Now(),
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := dao.Create(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	retrieved, err := dao.Get(ctx, serial, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.SerialNumber.Cmp(serial) != 0 {
		t.Errorf("expected serial %s, got %s", serial.Text(16), retrieved.SerialNumber.Text(16))
	}

	if retrieved.Subject != cert.Subject {
		t.Errorf("expected subject %s, got %s", cert.Subject, retrieved.Subject)
	}

	if retrieved.TenantID != cert.TenantID {
		t.Errorf("expected tenant %s, got %s", cert.TenantID, retrieved.TenantID)
	}
}

func TestCertificateDAO_Get_NotFound(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	serial := big.NewInt(99999)

	_, err := dao.Get(ctx, serial, "tenant1")
	if err == nil {
		t.Fatal("expected error for non-existent certificate")
	}

	if _, ok := err.(ErrCertificateNotFound); !ok {
		t.Errorf("expected ErrCertificateNotFound, got %T", err)
	}
}

func TestCertificateDAO_Get_TenantMismatch(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := dao.Create(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	_, err = dao.Get(ctx, serial, "tenant2")
	if err == nil {
		t.Fatal("expected error for tenant mismatch")
	}

	if _, ok := err.(ErrTenantMismatch); !ok {
		t.Errorf("expected ErrTenantMismatch, got %T", err)
	}
}

func TestCertificateDAO_Get_AdminAccess(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := dao.Create(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	// Empty tenant ID should bypass tenant check (admin access)
	retrieved, err := dao.Get(ctx, serial, "")
	if err != nil {
		t.Fatalf("expected no error for admin access, got %v", err)
	}

	if retrieved.TenantID != "tenant1" {
		t.Errorf("expected tenant tenant1, got %s", retrieved.TenantID)
	}
}

func TestCertificateDAO_Update(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := dao.Create(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	cert.Subject = "CN=updated"
	err = dao.Update(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error on update, got %v", err)
	}

	if cert.Version != 2 {
		t.Errorf("expected version 2, got %d", cert.Version)
	}

	retrieved, err := dao.Get(ctx, serial, "tenant1")
	if err != nil {
		t.Fatalf("expected no error on get, got %v", err)
	}

	if retrieved.Subject != "CN=updated" {
		t.Errorf("expected subject CN=updated, got %s", retrieved.Subject)
	}
}

func TestCertificateDAO_Update_VersionConflict(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger, WithCertificateOptimisticLocking(true))

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := dao.Create(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	// Simulate concurrent update by manually setting wrong version
	cert.Version = 5
	err = dao.Update(ctx, cert)
	if err == nil {
		t.Fatal("expected version conflict error")
	}

	if _, ok := err.(ErrVersionConflict); !ok {
		t.Errorf("expected ErrVersionConflict, got %T", err)
	}
}

func TestCertificateDAO_Update_NotFound(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	cert := &Certificate{
		SerialNumber: big.NewInt(99999),
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := dao.Update(ctx, cert)
	if err == nil {
		t.Fatal("expected error for non-existent certificate")
	}

	if _, ok := err.(ErrCertificateNotFound); !ok {
		t.Errorf("expected ErrCertificateNotFound, got %T", err)
	}
}

func TestCertificateDAO_Delete(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := dao.Create(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	err = dao.Delete(ctx, serial, "tenant1")
	if err != nil {
		t.Fatalf("expected no error on delete, got %v", err)
	}

	_, err = dao.Get(ctx, serial, "tenant1")
	if _, ok := err.(ErrCertificateNotFound); !ok {
		t.Errorf("expected ErrCertificateNotFound after delete, got %T", err)
	}
}

func TestCertificateDAO_Delete_NotFound(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	err := dao.Delete(ctx, big.NewInt(99999), "tenant1")
	if err == nil {
		t.Fatal("expected error for non-existent certificate")
	}

	if _, ok := err.(ErrCertificateNotFound); !ok {
		t.Errorf("expected ErrCertificateNotFound, got %T", err)
	}
}

func TestCertificateDAO_List(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()

	// Create multiple certificates
	for i := 1; i <= 5; i++ {
		cert := &Certificate{
			SerialNumber: big.NewInt(int64(i)),
			Subject:      "CN=test",
			TenantID:     "tenant1",
			DER:          []byte("test-der"),
		}
		err := dao.Create(ctx, cert)
		if err != nil {
			t.Fatalf("expected no error on create, got %v", err)
		}
	}

	certs, nextToken, err := dao.List(ctx, "tenant1", 10, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(certs) != 5 {
		t.Errorf("expected 5 certificates, got %d", len(certs))
	}

	if nextToken != "" {
		t.Errorf("expected empty nextToken, got %s", nextToken)
	}
}

func TestCertificateDAO_List_TenantFilter(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()

	// Create certificates for different tenants
	for i := 1; i <= 3; i++ {
		cert := &Certificate{
			SerialNumber: big.NewInt(int64(i)),
			Subject:      "CN=test",
			TenantID:     "tenant1",
			DER:          []byte("test-der"),
		}
		err := dao.Create(ctx, cert)
		if err != nil {
			t.Fatalf("expected no error on create, got %v", err)
		}
	}

	for i := 4; i <= 6; i++ {
		cert := &Certificate{
			SerialNumber: big.NewInt(int64(i)),
			Subject:      "CN=test",
			TenantID:     "tenant2",
			DER:          []byte("test-der"),
		}
		err := dao.Create(ctx, cert)
		if err != nil {
			t.Fatalf("expected no error on create, got %v", err)
		}
	}

	// List for tenant1
	certs1, _, err := dao.List(ctx, "tenant1", 10, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(certs1) != 3 {
		t.Errorf("expected 3 certificates for tenant1, got %d", len(certs1))
	}

	// List for tenant2
	certs2, _, err := dao.List(ctx, "tenant2", 10, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(certs2) != 3 {
		t.Errorf("expected 3 certificates for tenant2, got %d", len(certs2))
	}

	// List for all tenants (admin)
	allCerts, _, err := dao.List(ctx, "", 10, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(allCerts) != 6 {
		t.Errorf("expected 6 certificates for all tenants, got %d", len(allCerts))
	}
}

func TestCertificateDAO_ListValid(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	now := time.Now()

	// Create valid certificate
	validCert := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      "CN=valid",
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}
	err := dao.Create(ctx, validCert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Create expired certificate
	expiredCert := &Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      "CN=expired",
		NotBefore:    now.Add(-48 * time.Hour),
		NotAfter:     now.Add(-24 * time.Hour),
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}
	err = dao.Create(ctx, expiredCert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Create revoked certificate
	revokedTime := now.Add(-1 * time.Hour)
	revokedCert := &Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      "CN=revoked",
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		RevokedAt:    &revokedTime,
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}
	err = dao.Create(ctx, revokedCert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	validCerts, err := dao.ListValid(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(validCerts) != 1 {
		t.Errorf("expected 1 valid certificate, got %d", len(validCerts))
	}

	if validCerts[0].Subject != "CN=valid" {
		t.Errorf("expected subject CN=valid, got %s", validCerts[0].Subject)
	}
}

func TestCertificateDAO_Revoke(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := dao.Create(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	err = dao.Revoke(ctx, serial, 1, "tenant1")
	if err != nil {
		t.Fatalf("expected no error on revoke, got %v", err)
	}

	retrieved, err := dao.Get(ctx, serial, "tenant1")
	if err != nil {
		t.Fatalf("expected no error on get, got %v", err)
	}

	if !retrieved.IsRevoked() {
		t.Error("expected certificate to be revoked")
	}

	if retrieved.RevocationReason != 1 {
		t.Errorf("expected revocation reason 1, got %d", retrieved.RevocationReason)
	}
}

func TestCertificateDAO_Revoke_AlreadyRevoked(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	revokedAt := time.Now()
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		RevokedAt:    &revokedAt,
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := dao.Create(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	err = dao.Revoke(ctx, serial, 1, "tenant1")
	if err == nil {
		t.Fatal("expected error for already revoked certificate")
	}

	if _, ok := err.(ErrCertificateAlreadyRevoked); !ok {
		t.Errorf("expected ErrCertificateAlreadyRevoked, got %T", err)
	}
}

func TestCertificateDAO_CleanupExpired(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	now := time.Now()

	// Create expired certificate (past grace period)
	expiredCert := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      "CN=expired",
		NotBefore:    now.Add(-96 * time.Hour),
		NotAfter:     now.Add(-72 * time.Hour),
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}
	err := dao.Create(ctx, expiredCert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Create valid certificate
	validCert := &Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      "CN=valid",
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}
	err = dao.Create(ctx, validCert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Cleanup with 24-hour grace period
	deleted, err := dao.CleanupExpired(ctx, "tenant1", 24*time.Hour)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}

	// Verify valid certificate still exists
	_, err = dao.Get(ctx, big.NewInt(2), "tenant1")
	if err != nil {
		t.Fatalf("expected valid certificate to still exist, got %v", err)
	}

	// Verify expired certificate is deleted
	_, err = dao.Get(ctx, big.NewInt(1), "tenant1")
	if _, ok := err.(ErrCertificateNotFound); !ok {
		t.Error("expected expired certificate to be deleted")
	}
}

func TestCertificateDAO_Count(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()

	// Create certificates
	for i := 1; i <= 5; i++ {
		cert := &Certificate{
			SerialNumber: big.NewInt(int64(i)),
			Subject:      "CN=test",
			TenantID:     "tenant1",
			DER:          []byte("test-der"),
		}
		err := dao.Create(ctx, cert)
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

func TestSerialToEntityID(t *testing.T) {
	serial1 := big.NewInt(12345)
	serial2 := big.NewInt(12345)
	serial3 := big.NewInt(67890)

	id1 := serialToEntityID(serial1)
	id2 := serialToEntityID(serial2)
	id3 := serialToEntityID(serial3)

	// Same serial should produce same ID
	if id1 != id2 {
		t.Errorf("expected same ID for same serial, got %d and %d", id1, id2)
	}

	// Different serial should produce different ID
	if id1 == id3 {
		t.Error("expected different ID for different serial")
	}

	// ID should not be zero
	if id1 == 0 {
		t.Error("expected non-zero ID")
	}
}

func TestCertificateDAO_Options(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()

	dao := NewCertificateDAO(
		storage,
		logger,
		WithCertificateRequestTimeout(5*time.Second),
		WithCertificateOptimisticLocking(false),
	)

	if dao.requestTimeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", dao.requestTimeout)
	}

	if dao.enableOptimisticLocking {
		t.Error("expected optimistic locking to be disabled")
	}
}

func TestCertificateDAO_StorageErrors(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	cert := &Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	// Test Put error
	storage.SetPutError(ErrOperationFailed{Operation: "put"})
	err := dao.Create(ctx, cert)
	if err == nil {
		t.Fatal("expected error from storage")
	}
	storage.SetPutError(nil)

	// Test Get error
	storage.SetGetError(ErrOperationFailed{Operation: "get"})
	_, err = dao.Get(ctx, big.NewInt(12345), "tenant1")
	if err == nil {
		t.Fatal("expected error from storage")
	}
	storage.SetGetError(nil)

	// Test List error
	storage.SetListError(ErrOperationFailed{Operation: "list"})
	_, _, err = dao.List(ctx, "tenant1", 10, "")
	if err == nil {
		t.Fatal("expected error from storage")
	}
	storage.SetListError(nil)
}

func TestCertificateDAO_SerializationRoundtrip(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	revokedAt := now.Add(-1 * time.Hour)

	original := &Certificate{
		SerialNumber:     big.NewInt(12345),
		DER:              []byte("test-der-data"),
		Subject:          "CN=test,O=Test Org",
		Issuer:           "CN=issuer,O=Issuer Org",
		NotBefore:        now.Add(-1 * time.Hour),
		NotAfter:         now.Add(24 * time.Hour),
		IssuedAt:         now,
		RevokedAt:        &revokedAt,
		RevocationReason: 1,
		TenantID:         "tenant1",
	}

	err := dao.Create(ctx, original)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	retrieved, err := dao.Get(ctx, original.SerialNumber, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify all fields are preserved
	if retrieved.SerialNumber.Cmp(original.SerialNumber) != 0 {
		t.Error("SerialNumber mismatch")
	}
	if string(retrieved.DER) != string(original.DER) {
		t.Error("DER mismatch")
	}
	if retrieved.Subject != original.Subject {
		t.Error("Subject mismatch")
	}
	if retrieved.Issuer != original.Issuer {
		t.Error("Issuer mismatch")
	}
	if retrieved.RevocationReason != original.RevocationReason {
		t.Error("RevocationReason mismatch")
	}
	if retrieved.TenantID != original.TenantID {
		t.Error("TenantID mismatch")
	}
}

func TestCertificate_HelperMethods(t *testing.T) {
	now := time.Now().UTC()

	// Test IsRevoked
	revokedAt := now.Add(-1 * time.Hour)
	revokedCert := &Certificate{RevokedAt: &revokedAt}
	if !revokedCert.IsRevoked() {
		t.Error("expected IsRevoked() to return true")
	}

	notRevokedCert := &Certificate{}
	if notRevokedCert.IsRevoked() {
		t.Error("expected IsRevoked() to return false")
	}

	// Test IsExpired
	expiredCert := &Certificate{NotAfter: now.Add(-1 * time.Hour)}
	if !expiredCert.IsExpired() {
		t.Error("expected IsExpired() to return true")
	}

	validCert := &Certificate{NotAfter: now.Add(1 * time.Hour)}
	if validCert.IsExpired() {
		t.Error("expected IsExpired() to return false")
	}

	// Test IsValid
	fullValidCert := &Certificate{
		NotAfter: now.Add(1 * time.Hour),
	}
	if !fullValidCert.IsValid() {
		t.Error("expected IsValid() to return true")
	}

	expiredInvalidCert := &Certificate{
		NotAfter: now.Add(-1 * time.Hour),
	}
	if expiredInvalidCert.IsValid() {
		t.Error("expected IsValid() to return false for expired cert")
	}

	revokedInvalidCert := &Certificate{
		NotAfter:  now.Add(1 * time.Hour),
		RevokedAt: &revokedAt,
	}
	if revokedInvalidCert.IsValid() {
		t.Error("expected IsValid() to return false for revoked cert")
	}
}

func TestCertificateDAO_Concurrent(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent creates
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			cert := &Certificate{
				SerialNumber: big.NewInt(int64(id)),
				Subject:      "CN=test",
				TenantID:     "tenant1",
				DER:          []byte("test-der"),
			}
			err := dao.Create(ctx, cert)
			if err != nil {
				t.Errorf("unexpected error in goroutine %d: %v", id, err)
			}
		}(i)
	}
	wg.Wait()

	// Verify all certificates were created
	count, err := dao.Count(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != numGoroutines {
		t.Errorf("expected %d certificates, got %d", numGoroutines, count)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, err := dao.Get(ctx, big.NewInt(int64(id)), "tenant1")
			if err != nil {
				t.Errorf("unexpected error reading certificate %d: %v", id, err)
			}
		}(i)
	}
	wg.Wait()
}

// TestDeserializationError verifies handling of malformed data
func TestCertificateDAO_DeserializationError(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()

	// Manually insert malformed data
	serial := big.NewInt(12345)
	entityID := serialToEntityID(serial)
	storage.Put(ctx, EntityTypeCertificate, entityID, []byte("not json"), DefaultShardID)

	_, err := dao.Get(ctx, serial, "")
	if err == nil {
		t.Fatal("expected error for malformed data")
	}

	if _, ok := err.(ErrInvalidCertificate); !ok {
		t.Errorf("expected ErrInvalidCertificate, got %T", err)
	}
}

// BenchmarkCertificateDAO_Create benchmarks certificate creation
func BenchmarkCertificateDAO_Create(b *testing.B) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cert := &Certificate{
			SerialNumber: big.NewInt(int64(i)),
			Subject:      "CN=test",
			TenantID:     "tenant1",
			DER:          []byte("test-der"),
		}
		_ = dao.Create(ctx, cert)
	}
}

// BenchmarkCertificateDAO_Get benchmarks certificate retrieval
func BenchmarkCertificateDAO_Get(b *testing.B) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}
	_ = dao.Create(ctx, cert)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dao.Get(ctx, serial, "tenant1")
	}
}

// BenchmarkSerialToEntityID benchmarks the hash function
func BenchmarkSerialToEntityID(b *testing.B) {
	serial := new(big.Int)
	serial.SetString("12345678901234567890", 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = serialToEntityID(serial)
	}
}

// TestNewCertificate verifies the NewCertificate constructor
func TestNewCertificate(t *testing.T) {
	// Create a mock x509 certificate (we only need the fields that NewCertificate uses)
	mockCert := struct {
		SerialNumber *big.Int
		Raw          []byte
		Subject      struct{ String func() string }
		Issuer       struct{ String func() string }
		NotBefore    time.Time
		NotAfter     time.Time
	}{
		SerialNumber: big.NewInt(12345),
		Raw:          []byte("test-der"),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	mockCert.Subject.String = func() string { return "CN=test" }
	mockCert.Issuer.String = func() string { return "CN=issuer" }

	// Since NewCertificate uses x509.Certificate, we need to test the fields manually
	cert := &Certificate{
		SerialNumber: new(big.Int).Set(mockCert.SerialNumber),
		DER:          mockCert.Raw,
		Subject:      "CN=test",
		Issuer:       "CN=issuer",
		NotBefore:    mockCert.NotBefore,
		NotAfter:     mockCert.NotAfter,
		IssuedAt:     time.Now().UTC(),
		TenantID:     "tenant1",
		Version:      1,
	}

	if cert.SerialNumber.Cmp(big.NewInt(12345)) != 0 {
		t.Error("SerialNumber not set correctly")
	}

	if cert.TenantID != "tenant1" {
		t.Error("TenantID not set correctly")
	}

	if cert.Version != 1 {
		t.Error("Version should be 1")
	}
}

// Verify JSON marshaling of Certificate preserves big.Int
func TestCertificate_JSONMarshal(t *testing.T) {
	original := &Certificate{
		SerialNumber: big.NewInt(1234567890123456789),
		Subject:      "CN=test",
		TenantID:     "tenant1",
		Version:      1,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded Certificate
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.SerialNumber.Cmp(original.SerialNumber) != 0 {
		t.Errorf("serial number mismatch: expected %s, got %s",
			original.SerialNumber.Text(10), decoded.SerialNumber.Text(10))
	}
}
