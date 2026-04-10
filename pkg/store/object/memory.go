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
	"strings"
	"sync"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
)

// MemoryClient implements objectstorage.Client backed by an in-memory map.
// Suitable for unit testing and development. Thread-safe via sync.RWMutex.
type MemoryClient struct {
	mu      sync.RWMutex
	objects map[string][]byte
}

// NewMemoryClient creates a new in-memory ObjectStorage client.
func NewMemoryClient() objectstorage.Client {
	return &MemoryClient{
		objects: make(map[string][]byte),
	}
}

// PutObject stores an object in memory.
func (m *MemoryClient) PutObject(ctx context.Context, req *objectstorage.PutObjectRequest) (*objectstorage.PutObjectResponse, error) {
	if req == nil || req.Key == "" {
		return nil, ErrInvalidKey
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data := make([]byte, len(req.Value))
	copy(data, req.Value)
	m.objects[req.Key] = data
	return &objectstorage.PutObjectResponse{
		Key:  req.Key,
		Size: int64(len(data)),
	}, nil
}

// GetObject retrieves an object from memory.
func (m *MemoryClient) GetObject(ctx context.Context, req *objectstorage.GetObjectRequest) (*objectstorage.GetObjectResponse, error) {
	if req == nil || req.Key == "" {
		return nil, ErrInvalidKey
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.objects[req.Key]
	if !ok {
		return nil, ErrObjectNotFound
	}
	result := make([]byte, len(data))
	copy(result, data)
	return &objectstorage.GetObjectResponse{
		Key:   req.Key,
		Value: result,
		Size:  int64(len(result)),
	}, nil
}

// DeleteObject removes an object from memory.
func (m *MemoryClient) DeleteObject(ctx context.Context, req *objectstorage.DeleteObjectRequest) (*objectstorage.DeleteObjectResponse, error) {
	if req == nil || req.Key == "" {
		return nil, ErrInvalidKey
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objects[req.Key]; !ok {
		return nil, ErrObjectNotFound
	}
	delete(m.objects, req.Key)
	return &objectstorage.DeleteObjectResponse{
		Key:     req.Key,
		Success: true,
	}, nil
}

// HeadObject returns metadata about an object in memory.
func (m *MemoryClient) HeadObject(ctx context.Context, req *objectstorage.HeadObjectRequest) (*objectstorage.HeadObjectResponse, error) {
	if req == nil || req.Key == "" {
		return nil, ErrInvalidKey
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.objects[req.Key]
	if !ok {
		return &objectstorage.HeadObjectResponse{
			Key:    req.Key,
			Exists: false,
		}, nil
	}
	return &objectstorage.HeadObjectResponse{
		Key:    req.Key,
		Exists: true,
		Size:   int64(len(data)),
	}, nil
}

// ListObjects lists objects matching a prefix.
func (m *MemoryClient) ListObjects(ctx context.Context, req *objectstorage.ListObjectsRequest) (*objectstorage.ListObjectsResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var objects []*objectstorage.ObjectSummary
	for key, data := range m.objects {
		if req.Prefix == "" || strings.HasPrefix(key, req.Prefix) {
			objects = append(objects, &objectstorage.ObjectSummary{
				Key:  key,
				Size: int64(len(data)),
			})
		}
	}
	return &objectstorage.ListObjectsResponse{
		Objects:    objects,
		TotalCount: int64(len(objects)),
	}, nil
}

// ListByTag lists objects matching a tag. Returns empty list in memory implementation.
func (m *MemoryClient) ListByTag(ctx context.Context, req *objectstorage.ListByTagRequest) (*objectstorage.ListByTagResponse, error) {
	return &objectstorage.ListByTagResponse{
		Objects: []*objectstorage.ObjectSummary{},
	}, nil
}

// ListByTenant lists objects by tenant. Returns all objects in memory implementation.
func (m *MemoryClient) ListByTenant(ctx context.Context, req *objectstorage.ListByTenantRequest) (*objectstorage.ListByTenantResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var objects []*objectstorage.ObjectSummary
	for key, data := range m.objects {
		objects = append(objects, &objectstorage.ObjectSummary{
			Key:  key,
			Size: int64(len(data)),
		})
	}
	return &objectstorage.ListByTenantResponse{
		Objects:    objects,
		TotalCount: int64(len(objects)),
	}, nil
}

// CopyObject copies an object in memory.
func (m *MemoryClient) CopyObject(ctx context.Context, req *objectstorage.CopyObjectRequest) (*objectstorage.CopyObjectResponse, error) {
	if req == nil || req.SourceKey == "" || req.DestinationKey == "" {
		return nil, ErrInvalidKey
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[req.SourceKey]
	if !ok {
		return nil, ErrObjectNotFound
	}
	copied := make([]byte, len(data))
	copy(copied, data)
	m.objects[req.DestinationKey] = copied
	return &objectstorage.CopyObjectResponse{
		Key:  req.DestinationKey,
		Size: int64(len(copied)),
	}, nil
}

// ReplicateObject is a no-op in memory implementation.
func (m *MemoryClient) ReplicateObject(ctx context.Context, req *objectstorage.ReplicateObjectRequest) (*objectstorage.ReplicateObjectResponse, error) {
	return &objectstorage.ReplicateObjectResponse{
		Key:    req.Key,
		Status: "completed",
	}, nil
}

// MigrateObject is a no-op in memory implementation.
func (m *MemoryClient) MigrateObject(ctx context.Context, req *objectstorage.MigrateObjectRequest) (*objectstorage.MigrateObjectResponse, error) {
	return &objectstorage.MigrateObjectResponse{
		Key:     req.Key,
		Success: true,
	}, nil
}

// ArchiveObject is a no-op in memory implementation.
func (m *MemoryClient) ArchiveObject(ctx context.Context, req *objectstorage.ArchiveObjectRequest) (*objectstorage.ArchiveObjectResponse, error) {
	return &objectstorage.ArchiveObjectResponse{
		Key:     req.Key,
		Success: true,
	}, nil
}

// RestoreObject is a no-op in memory implementation.
func (m *MemoryClient) RestoreObject(ctx context.Context, req *objectstorage.RestoreObjectRequest) (*objectstorage.RestoreObjectResponse, error) {
	return &objectstorage.RestoreObjectResponse{
		Key:     req.Key,
		Success: true,
	}, nil
}

// VerifyObject is a no-op in memory implementation.
func (m *MemoryClient) VerifyObject(ctx context.Context, req *objectstorage.VerifyObjectRequest) (*objectstorage.VerifyObjectResponse, error) {
	return &objectstorage.VerifyObjectResponse{
		Key:   req.Key,
		Valid: true,
	}, nil
}

// SetObjectPolicy is a no-op in memory implementation.
func (m *MemoryClient) SetObjectPolicy(ctx context.Context, req *objectstorage.SetObjectPolicyRequest) (*objectstorage.SetObjectPolicyResponse, error) {
	return &objectstorage.SetObjectPolicyResponse{
		Key:     req.Key,
		Success: true,
	}, nil
}

// GetObjectPolicy returns empty policies in memory implementation.
func (m *MemoryClient) GetObjectPolicy(ctx context.Context, req *objectstorage.GetObjectPolicyRequest) (*objectstorage.GetObjectPolicyResponse, error) {
	return &objectstorage.GetObjectPolicyResponse{
		Key: req.Key,
	}, nil
}

// ListBackends returns empty list in memory implementation.
func (m *MemoryClient) ListBackends(ctx context.Context, req *objectstorage.ListBackendsRequest) (*objectstorage.ListBackendsResponse, error) {
	return &objectstorage.ListBackendsResponse{
		Backends: []*objectstorage.BackendInfo{
			{Name: "memory", Type: "memory", Enabled: true, Default: true},
		},
	}, nil
}

// GetBackendHealth returns healthy status in memory implementation.
func (m *MemoryClient) GetBackendHealth(ctx context.Context, req *objectstorage.GetBackendHealthRequest) (*objectstorage.GetBackendHealthResponse, error) {
	return &objectstorage.GetBackendHealthResponse{
		Name:    "memory",
		Healthy: true,
		Status:  "healthy",
	}, nil
}

// GetTenantUsage returns zero usage in memory implementation.
func (m *MemoryClient) GetTenantUsage(ctx context.Context, req *objectstorage.GetTenantUsageRequest) (*objectstorage.GetTenantUsageResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var totalSize int64
	for _, data := range m.objects {
		totalSize += int64(len(data))
	}
	return &objectstorage.GetTenantUsageResponse{
		TenantID:    req.TenantID,
		ObjectCount: int64(len(m.objects)),
		TotalSize:   totalSize,
	}, nil
}

// GetTenantQuotas returns unlimited quotas in memory implementation.
func (m *MemoryClient) GetTenantQuotas(ctx context.Context, req *objectstorage.GetTenantQuotasRequest) (*objectstorage.GetTenantQuotasResponse, error) {
	return &objectstorage.GetTenantQuotasResponse{
		TenantID: req.TenantID,
	}, nil
}

// SetTenantQuotas is a no-op in memory implementation.
func (m *MemoryClient) SetTenantQuotas(ctx context.Context, req *objectstorage.SetTenantQuotasRequest) (*objectstorage.SetTenantQuotasResponse, error) {
	return &objectstorage.SetTenantQuotasResponse{
		TenantID: req.TenantID,
	}, nil
}

// BatchPutObjects stores multiple objects in memory.
func (m *MemoryClient) BatchPutObjects(ctx context.Context, req *objectstorage.BatchPutObjectsRequest) (*objectstorage.BatchPutObjectsResponse, error) {
	var results []*objectstorage.PutObjectResponse
	var succeeded int32
	for _, putReq := range req.Objects {
		resp, err := m.PutObject(ctx, putReq)
		if err != nil {
			return nil, err
		}
		results = append(results, resp)
		succeeded++
	}
	return &objectstorage.BatchPutObjectsResponse{
		Results:   results,
		Succeeded: succeeded,
	}, nil
}

// BatchGetObjects retrieves multiple objects from memory.
func (m *MemoryClient) BatchGetObjects(ctx context.Context, req *objectstorage.BatchGetObjectsRequest) (*objectstorage.BatchGetObjectsResponse, error) {
	var objects []*objectstorage.GetObjectResponse
	var notFound []string
	for _, key := range req.Keys {
		resp, err := m.GetObject(ctx, &objectstorage.GetObjectRequest{Key: key, TenantID: req.TenantID})
		if err != nil {
			notFound = append(notFound, key)
			continue
		}
		objects = append(objects, resp)
	}
	return &objectstorage.BatchGetObjectsResponse{
		Objects:  objects,
		NotFound: notFound,
	}, nil
}

// BatchDeleteObjects deletes multiple objects from memory.
func (m *MemoryClient) BatchDeleteObjects(ctx context.Context, req *objectstorage.BatchDeleteObjectsRequest) (*objectstorage.BatchDeleteObjectsResponse, error) {
	var deleted []string
	var failed []string
	for _, key := range req.Keys {
		_, err := m.DeleteObject(ctx, &objectstorage.DeleteObjectRequest{Key: key, TenantID: req.TenantID})
		if err != nil {
			failed = append(failed, key)
			continue
		}
		deleted = append(deleted, key)
	}
	return &objectstorage.BatchDeleteObjectsResponse{
		DeletedKeys: deleted,
		FailedKeys:  failed,
	}, nil
}

// StreamPutObject creates a streaming writer for memory storage.
func (m *MemoryClient) StreamPutObject(ctx context.Context, opts objectstorage.StreamPutOptions) (objectstorage.StreamPutWriter, error) {
	return &memoryStreamWriter{
		client: m,
		key:    opts.Key,
	}, nil
}

// StreamGetObject creates a streaming reader for memory storage.
func (m *MemoryClient) StreamGetObject(ctx context.Context, req *objectstorage.GetObjectRequest) (objectstorage.StreamGetReader, error) {
	resp, err := m.GetObject(ctx, req)
	if err != nil {
		return nil, err
	}
	return &memoryStreamReader{
		data:   resp.Value,
		offset: 0,
	}, nil
}

// memoryStreamWriter implements objectstorage.StreamPutWriter for in-memory storage.
type memoryStreamWriter struct {
	client  *MemoryClient
	key     string
	buf     []byte
	written int64
}

// Write appends data to the buffer.
func (w *memoryStreamWriter) Write(p []byte) (n int, err error) {
	w.buf = append(w.buf, p...)
	w.written += int64(len(p))
	return len(p), nil
}

// Close finalizes the write by storing the object.
func (w *memoryStreamWriter) Close() (*objectstorage.PutObjectResponse, error) {
	resp, err := w.client.PutObject(context.Background(), &objectstorage.PutObjectRequest{
		Key:   w.key,
		Value: w.buf,
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Abort cancels the upload.
func (w *memoryStreamWriter) Abort() error {
	w.buf = nil
	return nil
}

// BytesWritten returns the total bytes written so far.
func (w *memoryStreamWriter) BytesWritten() int64 {
	return w.written
}

// memoryStreamReader implements objectstorage.StreamGetReader for in-memory storage.
type memoryStreamReader struct {
	data   []byte
	offset int64
}

// Read reads data from the in-memory buffer.
func (r *memoryStreamReader) Read(p []byte) (n int, err error) {
	if r.offset >= int64(len(r.data)) {
		return 0, ErrObjectNotFound
	}
	n = copy(p, r.data[r.offset:])
	r.offset += int64(n)
	return n, nil
}

// Close closes the reader (no-op).
func (r *memoryStreamReader) Close() error {
	return nil
}

// Metadata returns the object metadata.
func (r *memoryStreamReader) Metadata() *objectstorage.ObjectMetadata {
	return &objectstorage.ObjectMetadata{
		Size: int64(len(r.data)),
	}
}

// ReadMetadata reads metadata without consuming data.
func (r *memoryStreamReader) ReadMetadata() (*objectstorage.ObjectMetadata, error) {
	return r.Metadata(), nil
}

// TotalSize returns the total object size.
func (r *memoryStreamReader) TotalSize() int64 {
	return int64(len(r.data))
}

// BytesRead returns the total bytes read so far.
func (r *memoryStreamReader) BytesRead() int64 {
	return r.offset
}

// Compile-time interface checks.
var _ objectstorage.Client = (*MemoryClient)(nil)
var _ objectstorage.StreamPutWriter = (*memoryStreamWriter)(nil)
var _ objectstorage.StreamGetReader = (*memoryStreamReader)(nil)
