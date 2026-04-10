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
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	"github.com/jeremyhahn/go-trusted-ca/pkg/acme/entities"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock ObjectStorage Client
// =============================================================================

// mockObjectStorage is a thread-safe in-memory ObjectStorage implementation
// for unit testing. It supports PutObject, GetObject, DeleteObject, and
// ListObjects; all other methods return nil (unused by genericDAO).
type mockObjectStorage struct {
	mu      sync.RWMutex
	objects map[string][]byte
}

func newMockObjectStorage() *mockObjectStorage {
	return &mockObjectStorage{
		objects: make(map[string][]byte),
	}
}

func (m *mockObjectStorage) PutObject(_ context.Context, req *objectstorage.PutObjectRequest) (*objectstorage.PutObjectResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[req.Key] = req.Value
	return &objectstorage.PutObjectResponse{Key: req.Key}, nil
}

func (m *mockObjectStorage) GetObject(_ context.Context, req *objectstorage.GetObjectRequest) (*objectstorage.GetObjectResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.objects[req.Key]
	if !ok {
		return nil, errors.New("not found")
	}
	return &objectstorage.GetObjectResponse{Key: req.Key, Value: data}, nil
}

func (m *mockObjectStorage) DeleteObject(_ context.Context, req *objectstorage.DeleteObjectRequest) (*objectstorage.DeleteObjectResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, req.Key)
	return &objectstorage.DeleteObjectResponse{}, nil
}

func (m *mockObjectStorage) HeadObject(context.Context, *objectstorage.HeadObjectRequest) (*objectstorage.HeadObjectResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) ListObjects(_ context.Context, req *objectstorage.ListObjectsRequest) (*objectstorage.ListObjectsResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var objs []*objectstorage.ObjectSummary
	for key := range m.objects {
		if strings.HasPrefix(key, req.Prefix) {
			objs = append(objs, &objectstorage.ObjectSummary{Key: key})
		}
	}
	return &objectstorage.ListObjectsResponse{Objects: objs}, nil
}

func (m *mockObjectStorage) ListByTag(context.Context, *objectstorage.ListByTagRequest) (*objectstorage.ListByTagResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) ListByTenant(context.Context, *objectstorage.ListByTenantRequest) (*objectstorage.ListByTenantResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) CopyObject(context.Context, *objectstorage.CopyObjectRequest) (*objectstorage.CopyObjectResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) ReplicateObject(context.Context, *objectstorage.ReplicateObjectRequest) (*objectstorage.ReplicateObjectResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) MigrateObject(context.Context, *objectstorage.MigrateObjectRequest) (*objectstorage.MigrateObjectResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) ArchiveObject(context.Context, *objectstorage.ArchiveObjectRequest) (*objectstorage.ArchiveObjectResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) RestoreObject(context.Context, *objectstorage.RestoreObjectRequest) (*objectstorage.RestoreObjectResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) VerifyObject(context.Context, *objectstorage.VerifyObjectRequest) (*objectstorage.VerifyObjectResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) SetObjectPolicy(context.Context, *objectstorage.SetObjectPolicyRequest) (*objectstorage.SetObjectPolicyResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) GetObjectPolicy(context.Context, *objectstorage.GetObjectPolicyRequest) (*objectstorage.GetObjectPolicyResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) ListBackends(context.Context, *objectstorage.ListBackendsRequest) (*objectstorage.ListBackendsResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) GetBackendHealth(context.Context, *objectstorage.GetBackendHealthRequest) (*objectstorage.GetBackendHealthResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) GetTenantUsage(context.Context, *objectstorage.GetTenantUsageRequest) (*objectstorage.GetTenantUsageResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) GetTenantQuotas(context.Context, *objectstorage.GetTenantQuotasRequest) (*objectstorage.GetTenantQuotasResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) SetTenantQuotas(context.Context, *objectstorage.SetTenantQuotasRequest) (*objectstorage.SetTenantQuotasResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) BatchPutObjects(context.Context, *objectstorage.BatchPutObjectsRequest) (*objectstorage.BatchPutObjectsResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) BatchGetObjects(context.Context, *objectstorage.BatchGetObjectsRequest) (*objectstorage.BatchGetObjectsResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) BatchDeleteObjects(context.Context, *objectstorage.BatchDeleteObjectsRequest) (*objectstorage.BatchDeleteObjectsResponse, error) {
	return nil, nil
}

func (m *mockObjectStorage) StreamPutObject(context.Context, objectstorage.StreamPutOptions) (objectstorage.StreamPutWriter, error) {
	return nil, nil
}

func (m *mockObjectStorage) StreamGetObject(context.Context, *objectstorage.GetObjectRequest) (objectstorage.StreamGetReader, error) {
	return nil, nil
}

// =============================================================================
// TenantAwareFactory Construction Tests
// =============================================================================

// TestNewTenantAwareFactory verifies successful construction.
func TestNewTenantAwareFactory(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)
	assert.NotNil(t, factory)
}

// TestNewTenantAwareFactory_NilStorage verifies that a nil storage returns NilStorageError.
func TestNewTenantAwareFactory_NilStorage(t *testing.T) {
	_, err := NewTenantAwareFactory(nil)
	require.Error(t, err)
	var storErr NilStorageError
	assert.True(t, errors.As(err, &storErr))
}

// =============================================================================
// GetTenantID Tests
// =============================================================================

// TestTenantAwareFactory_GetTenantID_Empty verifies GetTenantID returns empty for global factory.
func TestTenantAwareFactory_GetTenantID_Empty(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)
	assert.Equal(t, "", factory.GetTenantID())
}

// =============================================================================
// TenantDAO Tests
// =============================================================================

// TestTenantAwareFactory_TenantDAO verifies that TenantDAO returns a working DAO.
func TestTenantAwareFactory_TenantDAO(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	tenantDAO, err := factory.TenantDAO()
	require.NoError(t, err)
	assert.NotNil(t, tenantDAO)
}

// TestTenantAwareFactory_TenantDAO_RoundTrip verifies Save and Get round-trip for tenants.
func TestTenantAwareFactory_TenantDAO_RoundTrip(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	tenantDAO, err := factory.TenantDAO()
	require.NoError(t, err)

	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	tenant := &entities.Tenant{
		NumericID: 42,
		ID:        "test-tenant-001",
		Name:      "Test Tenant",
		Status:    entities.TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	tenant.SetEntityID(42)

	err = tenantDAO.Save(ctx, tenant)
	require.NoError(t, err)

	loaded, err := tenantDAO.Get(ctx, 42)
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, loaded.ID)
	assert.Equal(t, tenant.Name, loaded.Name)
	assert.Equal(t, tenant.Status, loaded.Status)
}

// =============================================================================
// ForTenant Tests
// =============================================================================

// TestTenantAwareFactory_ForTenant verifies that ForTenant returns a valid Factory.
func TestTenantAwareFactory_ForTenant(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	tenantFactory, err := factory.ForTenant("tenant-abc")
	require.NoError(t, err)
	assert.NotNil(t, tenantFactory)
}

// TestTenantAwareFactory_ForTenant_EmptyID verifies error on empty tenant ID.
func TestTenantAwareFactory_ForTenant_EmptyID(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	_, err = factory.ForTenant("")
	require.Error(t, err)
	var tidErr InvalidTenantIDError
	assert.True(t, errors.As(err, &tidErr))
}

// TestTenantAwareFactory_ForTenant_Isolation verifies that DAOs from different
// tenant scopes produce different storage keys and do not cross-pollinate data.
func TestTenantAwareFactory_ForTenant_Isolation(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	factoryA, err := factory.ForTenant("tenant-a")
	require.NoError(t, err)

	factoryB, err := factory.ForTenant("tenant-b")
	require.NoError(t, err)

	ctx := context.Background()

	// Save an account through tenant-a
	daoA, err := factoryA.AccountDAO()
	require.NoError(t, err)

	account := &entities.ACMEAccount{}
	account.SetEntityID(100)
	err = daoA.Save(ctx, account)
	require.NoError(t, err)

	// Verify tenant-a can read it
	loaded, err := daoA.Get(ctx, 100)
	require.NoError(t, err)
	assert.Equal(t, uint64(100), loaded.EntityID())

	// Verify tenant-b cannot see tenant-a's data
	daoB, err := factoryB.AccountDAO()
	require.NoError(t, err)

	_, err = daoB.Get(ctx, 100)
	require.Error(t, err, "tenant-b should not see tenant-a's data")
}

// TestTenantAwareFactory_ForTenant_AllDAOs verifies that all DAO factory methods
// return non-nil DAOs when called on a tenant-scoped factory.
func TestTenantAwareFactory_ForTenant_AllDAOs(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	tenantFactory, err := factory.ForTenant("tenant-xyz")
	require.NoError(t, err)

	t.Run("AccountDAO", func(t *testing.T) {
		d, err := tenantFactory.AccountDAO()
		require.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("OrderDAO", func(t *testing.T) {
		d, err := tenantFactory.OrderDAO(1)
		require.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("OrderDAO_ZeroID", func(t *testing.T) {
		_, err := tenantFactory.OrderDAO(0)
		require.Error(t, err)
	})

	t.Run("AuthorizationDAO", func(t *testing.T) {
		d, err := tenantFactory.AuthorizationDAO(1)
		require.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("AuthorizationDAO_ZeroID", func(t *testing.T) {
		_, err := tenantFactory.AuthorizationDAO(0)
		require.Error(t, err)
	})

	t.Run("ChallengeDAO", func(t *testing.T) {
		d, err := tenantFactory.ChallengeDAO(1)
		require.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("ChallengeDAO_ZeroID", func(t *testing.T) {
		_, err := tenantFactory.ChallengeDAO(0)
		require.Error(t, err)
	})

	t.Run("CertificateDAO", func(t *testing.T) {
		d, err := tenantFactory.CertificateDAO()
		require.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("NonceDAO", func(t *testing.T) {
		d, err := tenantFactory.NonceDAO()
		require.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("ExternalAccountBindingDAO", func(t *testing.T) {
		d, err := tenantFactory.ExternalAccountBindingDAO()
		require.NoError(t, err)
		assert.NotNil(t, d)
	})
}

// =============================================================================
// Error Type Tests
// =============================================================================

// TestInvalidTenantIDError verifies the error message.
func TestInvalidTenantIDError(t *testing.T) {
	err := InvalidTenantIDError{}
	assert.Equal(t, "quicbaas: tenant ID must not be empty", err.Error())
}

// TestTenantDEKProvisionError verifies the error message and unwrap.
func TestTenantDEKProvisionError(t *testing.T) {
	cause := errors.New("connection refused")
	err := TenantDEKProvisionError{TenantID: "t1", Cause: cause}
	assert.Contains(t, err.Error(), "t1")
	assert.Contains(t, err.Error(), "connection refused")
	assert.Equal(t, cause, errors.Unwrap(err))
}

// TestTenantDEKDeprovisionError verifies the error message and unwrap.
func TestTenantDEKDeprovisionError(t *testing.T) {
	cause := errors.New("timeout")
	err := TenantDEKDeprovisionError{TenantID: "t2", Cause: cause}
	assert.Contains(t, err.Error(), "t2")
	assert.Contains(t, err.Error(), "timeout")
	assert.Equal(t, cause, errors.Unwrap(err))
}
