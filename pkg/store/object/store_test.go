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

package object

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
)

func TestObjectStore(t *testing.T) {

	data := []byte("test")

	store := createStore(t)

	objectKey := []byte("test/path.txt")

	// Save the object
	err := store.Save(objectKey, data)
	assert.Nil(t, err)

	// Get the persisted object
	persisted, err := store.Get(objectKey)
	assert.Nil(t, err)
	assert.Equal(t, data, persisted)

	// Ensure it exists
	exists := store.Exists(objectKey)
	assert.True(t, exists)

	// Delete the object
	err = store.Delete(objectKey)
	assert.Nil(t, err)

	// Ensure it's deleted
	_, err = store.Get(objectKey)
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrObjectNotFound))
}

func TestCount(t *testing.T) {
	store := createStore(t)

	// Save some test objects
	err := store.Save([]byte("count_test/file1.txt"), []byte("data1"))
	assert.Nil(t, err)
	err = store.Save([]byte("count_test/file2.txt"), []byte("data2"))
	assert.Nil(t, err)

	// Count objects in the count_test partition
	partition := "count_test"
	count, err := store.Count(&partition)
	assert.Nil(t, err)
	assert.Equal(t, 2, count)

	// Count all objects (nil partition)
	count, err = store.Count(nil)
	assert.Nil(t, err)
	assert.GreaterOrEqual(t, count, 2)

	// Cleanup
	store.Delete([]byte("count_test/file1.txt"))
	store.Delete([]byte("count_test/file2.txt"))
}

func TestObjectStoreNilStorage(t *testing.T) {
	logger := logging.DefaultLogger()
	_, err := NewObjectStore(logger, nil, "tmp/testdata", nil)
	assert.NotNil(t, err)
	assert.Equal(t, ErrStorageNil, err)
}

func TestObjectStoreNotFound(t *testing.T) {
	store := createStore(t)

	_, err := store.Get([]byte("nonexistent/key"))
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrObjectNotFound))
}

func TestObjectStoreDeleteNotFound(t *testing.T) {
	store := createStore(t)

	err := store.Delete([]byte("nonexistent/key"))
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrObjectNotFound))
}

func TestMultipleObjectStoresShareStorage(t *testing.T) {
	logger := logging.DefaultLogger()

	// Create shared in-memory storage
	storage := NewMemoryClient()

	// Create two ObjectStores with different partitions sharing the same storage
	store1, err := NewObjectStore(logger, storage, "tmp/testdata", nil) // objects partition
	assert.Nil(t, err)

	partition2 := "certificates"
	store2, err := NewObjectStore(logger, storage, "tmp/testdata", &partition2)
	assert.Nil(t, err)

	// Write to store1
	err = store1.Save([]byte("file1.txt"), []byte("data1"))
	assert.Nil(t, err)

	// Write to store2
	err = store2.Save([]byte("file2.txt"), []byte("data2"))
	assert.Nil(t, err)

	// Read from store1 - should find file1
	data1, err := store1.Get([]byte("file1.txt"))
	assert.Nil(t, err)
	assert.Equal(t, []byte("data1"), data1)

	// Read from store2 - should find file2
	data2, err := store2.Get([]byte("file2.txt"))
	assert.Nil(t, err)
	assert.Equal(t, []byte("data2"), data2)

	// Store1 should NOT find file2 (different partition)
	_, err = store1.Get([]byte("file2.txt"))
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrObjectNotFound))

	// Store2 should NOT find file1 (different partition)
	_, err = store2.Get([]byte("file1.txt"))
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrObjectNotFound))
}

// TestGetterMethods tests the ObjectStorageClient(), Home(), and Partition() methods
func TestGetterMethods(t *testing.T) {
	logger := logging.DefaultLogger()
	storage := NewMemoryClient()

	rootDir := "tmp/testdata"
	partition := "test_partition"
	store, err := NewObjectStore(logger, storage, rootDir, &partition)
	assert.Nil(t, err)

	// Test ObjectStorageClient()
	assert.Equal(t, storage, store.ObjectStorageClient())

	// Test Partition()
	assert.Equal(t, partition, store.Partition())

	// Test Home()
	expectedHome := "tmp/testdata/test_partition"
	assert.Equal(t, expectedHome, store.Home())
}

// TestNewObjectStorePathNormalization tests path normalization in NewObjectStore
func TestNewObjectStorePathNormalization(t *testing.T) {
	logger := logging.DefaultLogger()
	storage := NewMemoryClient()

	// Test with leading slash
	store, err := NewObjectStore(logger, storage, "/tmp/testdata", nil)
	assert.Nil(t, err)
	assert.Equal(t, "tmp/testdata/objects", store.Home())

	// Test with trailing slash
	store, err = NewObjectStore(logger, storage, "tmp/testdata/", nil)
	assert.Nil(t, err)
	assert.Equal(t, "tmp/testdata/objects", store.Home())

	// Test with both
	store, err = NewObjectStore(logger, storage, "/tmp/testdata/", nil)
	assert.Nil(t, err)
	assert.Equal(t, "tmp/testdata/objects", store.Home())
}

// TestExistsWithError tests error handling in Exists
func TestExistsWithError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockStorage := &mockObjectStorageClient{errOnHead: true}

	store, err := NewObjectStore(logger, mockStorage, "tmp/testdata", nil)
	assert.Nil(t, err)

	// Should return false when HeadObject returns an error
	exists := store.Exists([]byte("test/key"))
	assert.False(t, exists)
}

// TestDeleteWithExistsError tests Delete when HeadObject check fails
func TestDeleteWithExistsError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockStorage := &mockObjectStorageClient{errOnHead: true}

	store, err := NewObjectStore(logger, mockStorage, "tmp/testdata", nil)
	assert.Nil(t, err)

	err = store.Delete([]byte("test/key"))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "head error")
}

// TestCountWithError tests Count when ListObjects fails
func TestCountWithError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockStorage := &mockObjectStorageClient{errOnList: true}

	store, err := NewObjectStore(logger, mockStorage, "tmp/testdata", nil)
	assert.Nil(t, err)

	count, err := store.Count(nil)
	assert.NotNil(t, err)
	assert.Equal(t, 0, count)
	assert.Contains(t, err.Error(), "list error")
}

// TestSaveWithError tests Save when PutObject fails
func TestSaveWithError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockStorage := &mockObjectStorageClient{errOnPut: true}

	store, err := NewObjectStore(logger, mockStorage, "tmp/testdata", nil)
	assert.Nil(t, err)

	err = store.Save([]byte("test/key"), []byte("test data"))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "put error")
}

// TestGetWithGenericError tests Get when GetObject returns a non "not found" error
func TestGetWithGenericError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockStorage := &mockObjectStorageClient{errOnGet: true}

	store, err := NewObjectStore(logger, mockStorage, "tmp/testdata", nil)
	assert.Nil(t, err)

	_, err = store.Get([]byte("test/key"))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "get error")
}

// TestList tests the List method
func TestList(t *testing.T) {
	store := createStore(t)

	// Save some test objects
	err := store.Save([]byte("list_test/file1.txt"), []byte("data1"))
	assert.Nil(t, err)
	err = store.Save([]byte("list_test/file2.txt"), []byte("data2"))
	assert.Nil(t, err)

	// List objects
	keys, err := store.List("")
	assert.Nil(t, err)
	assert.GreaterOrEqual(t, len(keys), 2)

	// Cleanup
	store.Delete([]byte("list_test/file1.txt"))
	store.Delete([]byte("list_test/file2.txt"))
}

// TestListWithError tests List when ListObjects fails
func TestListWithError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockStorage := &mockObjectStorageClient{errOnList: true}

	store, err := NewObjectStore(logger, mockStorage, "tmp/testdata", nil)
	assert.Nil(t, err)

	keys, err := store.List("")
	assert.NotNil(t, err)
	assert.Nil(t, keys)
	assert.Contains(t, err.Error(), "list error")
}

func createStore(t *testing.T) ObjectStorer {
	logger := logging.DefaultLogger()

	// Use in-memory ObjectStorage client for testing
	storage := NewMemoryClient()

	rootDir := "tmp/testdata"

	store, err := NewObjectStore(logger, storage, rootDir, nil)
	if err != nil {
		t.Fatalf("Failed to create object store: %v", err)
	}

	return store
}

// mockObjectStorageClient is a mock ObjectStorage client for testing error paths.
// It implements objectstorage.Client with configurable error behavior.
type mockObjectStorageClient struct {
	errOnHead   bool
	errOnList   bool
	errOnPut    bool
	errOnGet    bool
	errOnDelete bool
}

func (m *mockObjectStorageClient) PutObject(ctx context.Context, req *objectstorage.PutObjectRequest) (*objectstorage.PutObjectResponse, error) {
	if m.errOnPut {
		return nil, errors.New("put error")
	}
	return &objectstorage.PutObjectResponse{Key: req.Key}, nil
}

func (m *mockObjectStorageClient) GetObject(ctx context.Context, req *objectstorage.GetObjectRequest) (*objectstorage.GetObjectResponse, error) {
	if m.errOnGet {
		return nil, errors.New("get error")
	}
	return nil, errors.New("not implemented in mock")
}

func (m *mockObjectStorageClient) DeleteObject(ctx context.Context, req *objectstorage.DeleteObjectRequest) (*objectstorage.DeleteObjectResponse, error) {
	if m.errOnDelete {
		return nil, errors.New("delete error")
	}
	return &objectstorage.DeleteObjectResponse{Key: req.Key, Success: true}, nil
}

func (m *mockObjectStorageClient) HeadObject(ctx context.Context, req *objectstorage.HeadObjectRequest) (*objectstorage.HeadObjectResponse, error) {
	if m.errOnHead {
		return nil, errors.New("head error")
	}
	return &objectstorage.HeadObjectResponse{Key: req.Key, Exists: false}, nil
}

func (m *mockObjectStorageClient) ListObjects(ctx context.Context, req *objectstorage.ListObjectsRequest) (*objectstorage.ListObjectsResponse, error) {
	if m.errOnList {
		return nil, errors.New("list error")
	}
	return &objectstorage.ListObjectsResponse{Objects: []*objectstorage.ObjectSummary{}}, nil
}

func (m *mockObjectStorageClient) ListByTag(ctx context.Context, req *objectstorage.ListByTagRequest) (*objectstorage.ListByTagResponse, error) {
	return &objectstorage.ListByTagResponse{}, nil
}

func (m *mockObjectStorageClient) ListByTenant(ctx context.Context, req *objectstorage.ListByTenantRequest) (*objectstorage.ListByTenantResponse, error) {
	return &objectstorage.ListByTenantResponse{}, nil
}

func (m *mockObjectStorageClient) CopyObject(ctx context.Context, req *objectstorage.CopyObjectRequest) (*objectstorage.CopyObjectResponse, error) {
	return &objectstorage.CopyObjectResponse{}, nil
}

func (m *mockObjectStorageClient) ReplicateObject(ctx context.Context, req *objectstorage.ReplicateObjectRequest) (*objectstorage.ReplicateObjectResponse, error) {
	return &objectstorage.ReplicateObjectResponse{}, nil
}

func (m *mockObjectStorageClient) MigrateObject(ctx context.Context, req *objectstorage.MigrateObjectRequest) (*objectstorage.MigrateObjectResponse, error) {
	return &objectstorage.MigrateObjectResponse{}, nil
}

func (m *mockObjectStorageClient) ArchiveObject(ctx context.Context, req *objectstorage.ArchiveObjectRequest) (*objectstorage.ArchiveObjectResponse, error) {
	return &objectstorage.ArchiveObjectResponse{}, nil
}

func (m *mockObjectStorageClient) RestoreObject(ctx context.Context, req *objectstorage.RestoreObjectRequest) (*objectstorage.RestoreObjectResponse, error) {
	return &objectstorage.RestoreObjectResponse{}, nil
}

func (m *mockObjectStorageClient) VerifyObject(ctx context.Context, req *objectstorage.VerifyObjectRequest) (*objectstorage.VerifyObjectResponse, error) {
	return &objectstorage.VerifyObjectResponse{}, nil
}

func (m *mockObjectStorageClient) SetObjectPolicy(ctx context.Context, req *objectstorage.SetObjectPolicyRequest) (*objectstorage.SetObjectPolicyResponse, error) {
	return &objectstorage.SetObjectPolicyResponse{}, nil
}

func (m *mockObjectStorageClient) GetObjectPolicy(ctx context.Context, req *objectstorage.GetObjectPolicyRequest) (*objectstorage.GetObjectPolicyResponse, error) {
	return &objectstorage.GetObjectPolicyResponse{}, nil
}

func (m *mockObjectStorageClient) ListBackends(ctx context.Context, req *objectstorage.ListBackendsRequest) (*objectstorage.ListBackendsResponse, error) {
	return &objectstorage.ListBackendsResponse{}, nil
}

func (m *mockObjectStorageClient) GetBackendHealth(ctx context.Context, req *objectstorage.GetBackendHealthRequest) (*objectstorage.GetBackendHealthResponse, error) {
	return &objectstorage.GetBackendHealthResponse{}, nil
}

func (m *mockObjectStorageClient) GetTenantUsage(ctx context.Context, req *objectstorage.GetTenantUsageRequest) (*objectstorage.GetTenantUsageResponse, error) {
	return &objectstorage.GetTenantUsageResponse{}, nil
}

func (m *mockObjectStorageClient) GetTenantQuotas(ctx context.Context, req *objectstorage.GetTenantQuotasRequest) (*objectstorage.GetTenantQuotasResponse, error) {
	return &objectstorage.GetTenantQuotasResponse{}, nil
}

func (m *mockObjectStorageClient) SetTenantQuotas(ctx context.Context, req *objectstorage.SetTenantQuotasRequest) (*objectstorage.SetTenantQuotasResponse, error) {
	return &objectstorage.SetTenantQuotasResponse{}, nil
}

func (m *mockObjectStorageClient) BatchPutObjects(ctx context.Context, req *objectstorage.BatchPutObjectsRequest) (*objectstorage.BatchPutObjectsResponse, error) {
	return &objectstorage.BatchPutObjectsResponse{}, nil
}

func (m *mockObjectStorageClient) BatchGetObjects(ctx context.Context, req *objectstorage.BatchGetObjectsRequest) (*objectstorage.BatchGetObjectsResponse, error) {
	return &objectstorage.BatchGetObjectsResponse{}, nil
}

func (m *mockObjectStorageClient) BatchDeleteObjects(ctx context.Context, req *objectstorage.BatchDeleteObjectsRequest) (*objectstorage.BatchDeleteObjectsResponse, error) {
	return &objectstorage.BatchDeleteObjectsResponse{}, nil
}

func (m *mockObjectStorageClient) StreamPutObject(ctx context.Context, opts objectstorage.StreamPutOptions) (objectstorage.StreamPutWriter, error) {
	return nil, errors.New("not implemented in mock")
}

func (m *mockObjectStorageClient) StreamGetObject(ctx context.Context, req *objectstorage.GetObjectRequest) (objectstorage.StreamGetReader, error) {
	return nil, errors.New("not implemented in mock")
}
