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

package registry

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Mock QuicBaaS storage client for testing
type mockStorageClient struct {
	mu      sync.RWMutex
	data    map[string][]byte
	putErr  error
	getErr  error
	delErr  error
	listErr error
}

func newMockStorageClient() *mockStorageClient {
	return &mockStorageClient{
		data: make(map[string][]byte),
	}
}

func (m *mockStorageClient) Put(ctx context.Context, entityType, key string, value []byte, ttl time.Duration) error {
	if m.putErr != nil {
		return m.putErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[entityType+":"+key] = value
	return nil
}

func (m *mockStorageClient) Get(ctx context.Context, entityType, key string) ([]byte, bool, error) {
	if m.getErr != nil {
		return nil, false, m.getErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, ok := m.data[entityType+":"+key]
	return value, ok, nil
}

func (m *mockStorageClient) Delete(ctx context.Context, entityType, key string) error {
	if m.delErr != nil {
		return m.delErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, entityType+":"+key)
	return nil
}

func (m *mockStorageClient) List(ctx context.Context, entityType, prefix string, limit int, cursor string) ([]string, string, bool, error) {
	if m.listErr != nil {
		return nil, "", false, m.listErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string
	fullPrefix := entityType + ":"
	if prefix != "" {
		fullPrefix = entityType + ":" + prefix
	}

	for key := range m.data {
		if strings.HasPrefix(key, fullPrefix) {
			keys = append(keys, strings.TrimPrefix(key, entityType+":"))
		}
	}

	sort.Strings(keys)

	// Resume at the cursor this mock hands out: the first key of the
	// next page.
	if cursor != "" {
		keys = keys[sort.SearchStrings(keys, cursor):]
	}

	// Apply limit
	if limit > 0 && len(keys) > limit {
		return keys[:limit], keys[limit], true, nil
	}

	return keys, "", false, nil
}

// Tests for NewQuicBaaSStorage

func TestNewQuicBaaSStorage_Namespace(t *testing.T) {
	tests := []struct {
		name string
		opts []StorageOption
		want string
	}{
		{name: "default", want: "registry"},
		{name: "custom", opts: []StorageOption{WithStorageNamespace("custom-ns")}, want: "custom-ns"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage, err := NewQuicBaaSStorage(newMockStorageClient(), tt.opts...)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if storage.namespace != tt.want {
				t.Errorf("expected namespace %q, got %q", tt.want, storage.namespace)
			}
		})
	}
}

func TestNewQuicBaaSStorage_NilClient(t *testing.T) {
	_, err := NewQuicBaaSStorage(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
	var nilErr ErrNilClient
	if !errors.As(err, &nilErr) {
		t.Errorf("expected ErrNilClient, got %T", err)
	}
}

// Tests for blob operations

func TestStoreBlob_Success(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	digest := "sha256:abc123def456"
	content := []byte("blob content")

	err := storage.StoreBlob(ctx, digest, content)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify blob was stored
	retrieved, err := storage.GetBlob(ctx, digest)
	if err != nil {
		t.Fatalf("failed to get blob: %v", err)
	}
	if !bytes.Equal(retrieved, content) {
		t.Error("retrieved content does not match original")
	}
}

// TestStorage_NilContext checks that every operation refuses a nil context
// with an ErrNilContext naming the operation.
func TestStorage_NilContext(t *testing.T) {
	var nilCtx context.Context
	ops := map[string]func(s *QuicBaaSStorage) error{
		"StoreBlob": func(s *QuicBaaSStorage) error {
			return s.StoreBlob(nilCtx, "sha256:test", []byte("content"))
		},
		"GetBlob": func(s *QuicBaaSStorage) error {
			_, err := s.GetBlob(nilCtx, "sha256:test123")
			return err
		},
		"DeleteBlob": func(s *QuicBaaSStorage) error {
			return s.DeleteBlob(nilCtx, "sha256:test123")
		},
		"BlobExists": func(s *QuicBaaSStorage) error {
			_, err := s.BlobExists(nilCtx, "sha256:test123")
			return err
		},
		"StoreManifest": func(s *QuicBaaSStorage) error {
			return s.StoreManifest(nilCtx, "test:latest", &ImageManifest{SchemaVersion: 2})
		},
		"GetManifest": func(s *QuicBaaSStorage) error {
			_, err := s.GetManifest(nilCtx, "test:latest")
			return err
		},
		"DeleteManifest": func(s *QuicBaaSStorage) error {
			return s.DeleteManifest(nilCtx, "test:latest")
		},
		"ManifestExists": func(s *QuicBaaSStorage) error {
			_, err := s.ManifestExists(nilCtx, "test:latest")
			return err
		},
		"ListManifests": func(s *QuicBaaSStorage) error {
			_, err := s.ListManifests(nilCtx, ListOptions{})
			return err
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			storage, _ := NewQuicBaaSStorage(newMockStorageClient())

			err := op(storage)
			var nilCtxErr ErrNilContext
			if !errors.As(err, &nilCtxErr) {
				t.Fatalf("expected ErrNilContext, got %T (%v)", err, err)
			}
			if nilCtxErr.Operation != name {
				t.Errorf("expected operation %q, got %q", name, nilCtxErr.Operation)
			}
		})
	}
}

func TestStoreBlob_InvalidDigest(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()

	tests := []struct {
		name   string
		digest string
	}{
		{"empty digest", ""},
		{"no colon", "sha256abc123"},
		{"empty algorithm", ":abc123"},
		{"empty hash", "sha256:"},
		{"invalid algorithm", "md5:abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.StoreBlob(ctx, tt.digest, []byte("content"))
			if err == nil {
				t.Error("expected error for invalid digest")
			}
		})
	}
}

func TestStoreBlob_StorageError(t *testing.T) {
	client := newMockStorageClient()
	client.putErr = errors.New("storage unavailable")
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	err := storage.StoreBlob(ctx, "sha256:test123", []byte("content"))
	if err == nil {
		t.Fatal("expected error for storage failure")
	}
	var storageErr ErrStorageError
	if !errors.As(err, &storageErr) {
		t.Errorf("expected ErrStorageError, got %T", err)
	}
}

// TestStorage_Closed checks that every operation refuses a closed storage
// with ErrRegistryClosed.
func TestStorage_Closed(t *testing.T) {
	ctx := context.Background()
	ops := map[string]func(s *QuicBaaSStorage) error{
		"StoreBlob": func(s *QuicBaaSStorage) error {
			return s.StoreBlob(ctx, "sha256:test", []byte("content"))
		},
		"GetBlob": func(s *QuicBaaSStorage) error {
			_, err := s.GetBlob(ctx, "sha256:test123")
			return err
		},
		"DeleteBlob": func(s *QuicBaaSStorage) error {
			return s.DeleteBlob(ctx, "sha256:test123")
		},
		"BlobExists": func(s *QuicBaaSStorage) error {
			_, err := s.BlobExists(ctx, "sha256:test123")
			return err
		},
		"StoreManifest": func(s *QuicBaaSStorage) error {
			return s.StoreManifest(ctx, "test:latest", &ImageManifest{SchemaVersion: 2})
		},
		"GetManifest": func(s *QuicBaaSStorage) error {
			_, err := s.GetManifest(ctx, "test:latest")
			return err
		},
		"DeleteManifest": func(s *QuicBaaSStorage) error {
			return s.DeleteManifest(ctx, "test:latest")
		},
		"ManifestExists": func(s *QuicBaaSStorage) error {
			_, err := s.ManifestExists(ctx, "test:latest")
			return err
		},
		"ListManifests": func(s *QuicBaaSStorage) error {
			_, err := s.ListManifests(ctx, ListOptions{})
			return err
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			storage, _ := NewQuicBaaSStorage(newMockStorageClient())
			_ = storage.Close()

			err := op(storage)
			var closedErr ErrRegistryClosed
			if !errors.As(err, &closedErr) {
				t.Errorf("expected ErrRegistryClosed, got %T (%v)", err, err)
			}
		})
	}
}

func TestGetBlob_NotFound(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	_, err := storage.GetBlob(ctx, "sha256:nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent blob")
	}
	var notFoundErr ErrBlobNotFound
	if !errors.As(err, &notFoundErr) {
		t.Errorf("expected ErrBlobNotFound, got %T", err)
	}
}

func TestGetBlob_StorageError(t *testing.T) {
	client := newMockStorageClient()
	client.getErr = errors.New("storage unavailable")
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	_, err := storage.GetBlob(ctx, "sha256:test123")
	if err == nil {
		t.Fatal("expected error for storage failure")
	}
	var storageErr ErrStorageError
	if !errors.As(err, &storageErr) {
		t.Errorf("expected ErrStorageError, got %T", err)
	}
}

func TestGetBlob_InvalidDigest(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	tests := []struct {
		name   string
		digest string
	}{
		{"empty digest", ""},
		{"no colon", "sha256abc123"},
		{"empty algorithm", ":abc123"},
		{"empty hash", "sha256:"},
		{"invalid algorithm", "md5:abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := storage.GetBlob(ctx, tt.digest)
			if err == nil {
				t.Error("expected error for invalid digest")
			}
		})
	}
}

func TestDeleteBlob_Success(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	digest := "sha256:to-delete"

	// Store blob first
	_ = storage.StoreBlob(ctx, digest, []byte("content"))

	// Delete blob
	err := storage.DeleteBlob(ctx, digest)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify blob was deleted
	_, err = storage.GetBlob(ctx, digest)
	if err == nil {
		t.Error("expected error for deleted blob")
	}
}

func TestDeleteBlob_StorageError(t *testing.T) {
	client := newMockStorageClient()
	client.delErr = errors.New("delete failed")
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	err := storage.DeleteBlob(ctx, "sha256:test123")
	if err == nil {
		t.Fatal("expected error for storage failure")
	}
	var storageErr ErrStorageError
	if !errors.As(err, &storageErr) {
		t.Errorf("expected ErrStorageError, got %T", err)
	}
}

func TestDeleteBlob_InvalidDigest(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	tests := []struct {
		name   string
		digest string
	}{
		{"empty digest", ""},
		{"no colon", "sha256abc123"},
		{"empty algorithm", ":abc123"},
		{"empty hash", "sha256:"},
		{"invalid algorithm", "md5:abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.DeleteBlob(ctx, tt.digest)
			if err == nil {
				t.Error("expected error for invalid digest")
			}
		})
	}
}

func TestBlobExists_Success(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	digest := "sha256:exists"

	// Initially should not exist
	exists, err := storage.BlobExists(ctx, digest)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if exists {
		t.Error("expected blob to not exist")
	}

	// Store blob
	_ = storage.StoreBlob(ctx, digest, []byte("content"))

	// Should exist now
	exists, err = storage.BlobExists(ctx, digest)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !exists {
		t.Error("expected blob to exist")
	}
}

func TestBlobExists_InvalidDigest(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	tests := []struct {
		name   string
		digest string
	}{
		{"empty digest", ""},
		{"no colon", "sha256abc123"},
		{"empty algorithm", ":abc123"},
		{"empty hash", "sha256:"},
		{"invalid algorithm", "md5:abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := storage.BlobExists(ctx, tt.digest)
			if err == nil {
				t.Error("expected error for invalid digest")
			}
		})
	}
}

func TestBlobExists_StorageError(t *testing.T) {
	client := newMockStorageClient()
	client.getErr = errors.New("storage unavailable")
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	_, err := storage.BlobExists(ctx, "sha256:test123")
	if err == nil {
		t.Fatal("expected error for storage failure")
	}
	var storageErr ErrStorageError
	if !errors.As(err, &storageErr) {
		t.Errorf("expected ErrStorageError, got %T", err)
	}
}

// Tests for manifest operations

func TestStoreManifest_Success(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	ref := "myrepo/myimage:latest"
	manifest := &ImageManifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Config: Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    "sha256:config123",
			Size:      1024,
		},
		Layers: []Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Digest:    "sha256:layer1",
				Size:      4096,
			},
		},
	}

	err := storage.StoreManifest(ctx, ref, manifest)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify manifest was stored
	retrieved, err := storage.GetManifest(ctx, ref)
	if err != nil {
		t.Fatalf("failed to get manifest: %v", err)
	}
	if retrieved.SchemaVersion != manifest.SchemaVersion {
		t.Error("schema version mismatch")
	}
	if retrieved.Reference != ref {
		t.Errorf("expected reference %s, got %s", ref, retrieved.Reference)
	}
	if retrieved.CreatedAt.IsZero() {
		t.Error("expected non-zero created_at")
	}
}

func TestStoreManifest_NilManifest(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	err := storage.StoreManifest(ctx, "test:latest", nil)
	if err == nil {
		t.Fatal("expected error for nil manifest")
	}
	var invalidErr ErrInvalidManifest
	if !errors.As(err, &invalidErr) {
		t.Errorf("expected ErrInvalidManifest, got %T", err)
	}
}

func TestStoreManifest_EmptyReference(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	manifest := &ImageManifest{SchemaVersion: 2}
	err := storage.StoreManifest(ctx, "", manifest)
	if err == nil {
		t.Fatal("expected error for empty reference")
	}
	var refErr ErrInvalidImageRef
	if !errors.As(err, &refErr) {
		t.Errorf("expected ErrInvalidImageRef, got %T", err)
	}
}

func TestStoreManifest_StorageError(t *testing.T) {
	client := newMockStorageClient()
	client.putErr = errors.New("storage unavailable")
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	manifest := &ImageManifest{SchemaVersion: 2}
	err := storage.StoreManifest(ctx, "test:latest", manifest)
	if err == nil {
		t.Fatal("expected error for storage failure")
	}
}

func TestStoreManifest_DigestReference(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	// Use a digest reference to ensure the tag storage branch is NOT taken
	ref := "repo@sha256:abc123def456"
	manifest := &ImageManifest{
		SchemaVersion: 2,
		Config: Descriptor{
			Digest: "sha256:config123",
		},
	}

	err := storage.StoreManifest(ctx, ref, manifest)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify manifest was stored
	retrieved, err := storage.GetManifest(ctx, ref)
	if err != nil {
		t.Fatalf("failed to get manifest: %v", err)
	}
	if retrieved.Reference != ref {
		t.Errorf("expected reference %s, got %s", ref, retrieved.Reference)
	}
}

func TestStoreManifest_PreservesCreatedAt(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	ref := "test:latest"
	originalCreatedAt := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	manifest := &ImageManifest{
		SchemaVersion: 2,
		CreatedAt:     originalCreatedAt,
	}

	err := storage.StoreManifest(ctx, ref, manifest)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify CreatedAt was preserved
	retrieved, err := storage.GetManifest(ctx, ref)
	if err != nil {
		t.Fatalf("failed to get manifest: %v", err)
	}
	if !retrieved.CreatedAt.Equal(originalCreatedAt) {
		t.Errorf("expected CreatedAt %v, got %v", originalCreatedAt, retrieved.CreatedAt)
	}
}

func TestStoreManifest_StoreTagError(t *testing.T) {
	// This test verifies that storeTag errors are properly propagated
	client := &entityTypeMockStorageClient{
		mockStorageClient:  newMockStorageClient(),
		errorOnEntityTypes: map[string]error{entityTypeTag: errors.New("tag storage error")},
	}
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	// Use a tag reference (not digest) to trigger the storeTag path
	ref := "myrepo:latest"
	manifest := &ImageManifest{
		SchemaVersion: 2,
		Config: Descriptor{
			Digest: "sha256:config123",
		},
	}

	err := storage.StoreManifest(ctx, ref, manifest)
	if err == nil {
		t.Fatal("expected error for tag storage failure")
	}
}

// entityTypeMockStorageClient allows errors based on entity type
type entityTypeMockStorageClient struct {
	*mockStorageClient
	errorOnEntityTypes map[string]error
}

func (m *entityTypeMockStorageClient) Put(ctx context.Context, entityType, key string, value []byte, ttl time.Duration) error {
	if err, ok := m.errorOnEntityTypes[entityType]; ok {
		return err
	}
	return m.mockStorageClient.Put(ctx, entityType, key, value, ttl)
}

func TestGetManifest_NotFound(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	_, err := storage.GetManifest(ctx, "nonexistent:latest")
	if err == nil {
		t.Fatal("expected error for nonexistent manifest")
	}
	var notFoundErr ErrManifestNotFound
	if !errors.As(err, &notFoundErr) {
		t.Errorf("expected ErrManifestNotFound, got %T", err)
	}
}

func TestGetManifest_EmptyReference(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	_, err := storage.GetManifest(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty reference")
	}
	var refErr ErrInvalidImageRef
	if !errors.As(err, &refErr) {
		t.Errorf("expected ErrInvalidImageRef, got %T", err)
	}
}

func TestGetManifest_StorageError(t *testing.T) {
	client := newMockStorageClient()
	client.getErr = errors.New("storage unavailable")
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	_, err := storage.GetManifest(ctx, "test:latest")
	if err == nil {
		t.Fatal("expected error for storage failure")
	}
	var storageErr ErrStorageError
	if !errors.As(err, &storageErr) {
		t.Errorf("expected ErrStorageError, got %T", err)
	}
}

func TestGetManifest_UnmarshalError(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	// Store invalid JSON directly to trigger unmarshal error
	key := "registry/manifests/test:latest"
	client.data[entityTypeManifest+":"+key] = []byte("invalid json{{{")

	_, err := storage.GetManifest(ctx, "test:latest")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	var storageErr ErrStorageError
	if !errors.As(err, &storageErr) {
		t.Errorf("expected ErrStorageError, got %T", err)
	}
}

func TestDeleteManifest_Success(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	ref := "to-delete:latest"
	manifest := &ImageManifest{SchemaVersion: 2}

	// Store first
	_ = storage.StoreManifest(ctx, ref, manifest)

	// Delete
	err := storage.DeleteManifest(ctx, ref)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify deletion
	_, err = storage.GetManifest(ctx, ref)
	if err == nil {
		t.Error("expected error for deleted manifest")
	}
}

func TestDeleteManifest_EmptyReference(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	err := storage.DeleteManifest(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty reference")
	}
	var refErr ErrInvalidImageRef
	if !errors.As(err, &refErr) {
		t.Errorf("expected ErrInvalidImageRef, got %T", err)
	}
}

func TestDeleteManifest_StorageError(t *testing.T) {
	client := newMockStorageClient()
	client.delErr = errors.New("delete failed")
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	err := storage.DeleteManifest(ctx, "test:latest")
	if err == nil {
		t.Fatal("expected error for storage failure")
	}
	var storageErr ErrStorageError
	if !errors.As(err, &storageErr) {
		t.Errorf("expected ErrStorageError, got %T", err)
	}
}

func TestDeleteManifest_DigestReference(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	// Use a digest reference to test the !isDigestReference branch is NOT taken
	ref := "repo@sha256:abc123def456"
	manifest := &ImageManifest{SchemaVersion: 2}

	// Store first
	_ = storage.StoreManifest(ctx, ref, manifest)

	// Delete - should not try to delete a tag
	err := storage.DeleteManifest(ctx, ref)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestManifestExists_Success(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	ref := "exists:latest"

	// Initially should not exist
	exists, err := storage.ManifestExists(ctx, ref)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if exists {
		t.Error("expected manifest to not exist")
	}

	// Store manifest
	manifest := &ImageManifest{SchemaVersion: 2}
	_ = storage.StoreManifest(ctx, ref, manifest)

	// Should exist now
	exists, err = storage.ManifestExists(ctx, ref)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !exists {
		t.Error("expected manifest to exist")
	}
}

func TestManifestExists_EmptyReference(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	_, err := storage.ManifestExists(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty reference")
	}
	var refErr ErrInvalidImageRef
	if !errors.As(err, &refErr) {
		t.Errorf("expected ErrInvalidImageRef, got %T", err)
	}
}

func TestManifestExists_StorageError(t *testing.T) {
	client := newMockStorageClient()
	client.getErr = errors.New("storage unavailable")
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	_, err := storage.ManifestExists(ctx, "test:latest")
	if err == nil {
		t.Fatal("expected error for storage failure")
	}
	var storageErr ErrStorageError
	if !errors.As(err, &storageErr) {
		t.Errorf("expected ErrStorageError, got %T", err)
	}
}

// Tests for ListManifests

func TestListManifests_Success(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()

	// Store some manifests
	for i := 0; i < 5; i++ {
		ref := "repo" + string(rune('A'+i)) + ":latest"
		manifest := &ImageManifest{SchemaVersion: 2}
		_ = storage.StoreManifest(ctx, ref, manifest)
	}

	// List all
	result, err := storage.ListManifests(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(result.Manifests) != 5 {
		t.Errorf("expected 5 manifests, got %d", len(result.Manifests))
	}
}

func TestListManifests_WithLimit(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()

	// Store some manifests
	for i := 0; i < 10; i++ {
		ref := "repo" + string(rune('A'+i)) + ":latest"
		manifest := &ImageManifest{SchemaVersion: 2}
		_ = storage.StoreManifest(ctx, ref, manifest)
	}

	// List with limit
	result, err := storage.ListManifests(ctx, ListOptions{Limit: 3})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(result.Manifests) != 3 {
		t.Errorf("expected 3 manifests, got %d", len(result.Manifests))
	}
	if !result.HasMore {
		t.Error("expected has_more to be true")
	}
}

func TestListManifests_StorageError(t *testing.T) {
	client := newMockStorageClient()
	client.listErr = errors.New("list failed")
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	_, err := storage.ListManifests(ctx, ListOptions{})
	if err == nil {
		t.Fatal("expected error for storage failure")
	}
}

func TestListManifests_Filters(t *testing.T) {
	tests := map[string]ListOptions{
		"repository":            {Repository: "myrepo"},
		"prefix":                {Prefix: "app"},
		"repository and prefix": {Repository: "myrepo", Prefix: "app"},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			storage, _ := NewQuicBaaSStorage(newMockStorageClient())
			ctx := context.Background()
			for _, ref := range []string{"myrepo/app/image1:latest", "myrepo/other/image:latest", "app/image:v1"} {
				_ = storage.StoreManifest(ctx, ref, &ImageManifest{SchemaVersion: 2})
			}

			result, err := storage.ListManifests(ctx, opts)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
		})
	}
}

func TestListManifests_SkipsInvalidManifests(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()

	// Store a valid manifest
	validRef := "valid:latest"
	validManifest := &ImageManifest{SchemaVersion: 2}
	_ = storage.StoreManifest(ctx, validRef, validManifest)

	// Store invalid JSON directly to simulate corrupt data
	invalidKey := "registry/manifests/invalid:latest"
	client.data[entityTypeManifest+":"+invalidKey] = []byte("not valid json{{{")

	// List should return only the valid manifest and skip the invalid one
	result, err := storage.ListManifests(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(result.Manifests) != 1 {
		t.Errorf("expected 1 valid manifest, got %d", len(result.Manifests))
	}
}

func TestListManifests_SkipsDeletedDuringList(t *testing.T) {
	// This test verifies that ListManifests handles the case where a manifest
	// is deleted between the List call and the Get call (not found = continue)
	client := &conditionalMockStorageClient{
		mockStorageClient: newMockStorageClient(),
		skipOnGet:         make(map[string]bool),
	}
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()

	// Store some manifests
	for i := 0; i < 3; i++ {
		ref := "repo" + string(rune('A'+i)) + ":latest"
		manifest := &ImageManifest{SchemaVersion: 2}
		_ = storage.StoreManifest(ctx, ref, manifest)
	}

	// Mark one manifest to be "not found" on Get (simulating deletion during listing)
	client.skipOnGet["registry/manifests/repoB:latest"] = true

	result, err := storage.ListManifests(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// Should have 2 manifests (3 stored - 1 skipped)
	if len(result.Manifests) != 2 {
		t.Errorf("expected 2 manifests, got %d", len(result.Manifests))
	}
}

func TestListManifests_SkipsOnGetError(t *testing.T) {
	// This test verifies that ListManifests handles Get errors during iteration
	client := &conditionalMockStorageClient{
		mockStorageClient: newMockStorageClient(),
		errorOnGet:        make(map[string]bool),
	}
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()

	// Store some manifests
	for i := 0; i < 3; i++ {
		ref := "repo" + string(rune('A'+i)) + ":latest"
		manifest := &ImageManifest{SchemaVersion: 2}
		_ = storage.StoreManifest(ctx, ref, manifest)
	}

	// Mark one manifest to error on Get
	client.errorOnGet["registry/manifests/repoB:latest"] = true

	result, err := storage.ListManifests(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// Should have 2 manifests (3 stored - 1 errored)
	if len(result.Manifests) != 2 {
		t.Errorf("expected 2 manifests, got %d", len(result.Manifests))
	}
}

// conditionalMockStorageClient extends mockStorageClient to allow
// conditional behavior for specific keys
type conditionalMockStorageClient struct {
	*mockStorageClient
	skipOnGet  map[string]bool
	errorOnGet map[string]bool
}

func (m *conditionalMockStorageClient) Get(ctx context.Context, entityType, key string) ([]byte, bool, error) {
	if m.errorOnGet != nil && m.errorOnGet[key] {
		return nil, false, errors.New("conditional error")
	}
	if m.skipOnGet != nil && m.skipOnGet[key] {
		return nil, false, nil
	}
	return m.mockStorageClient.Get(ctx, entityType, key)
}

// Tests for helper functions

func TestValidateDigest(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	tests := []struct {
		name      string
		digest    string
		expectErr bool
	}{
		{"valid sha256", "sha256:abc123def456", false},
		{"valid sha512", "sha512:abc123def456", false},
		{"valid sha384", "sha384:abc123def456", false},
		{"empty", "", true},
		{"no colon", "sha256abc123", true},
		{"empty algorithm", ":abc123", true},
		{"empty hash", "sha256:", true},
		{"invalid algorithm", "md5:abc123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.validateDigest(tt.digest)
			if tt.expectErr && err == nil {
				t.Error("expected error")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestIsDigestReference(t *testing.T) {
	tests := []struct {
		ref      string
		expected bool
	}{
		{"nginx@sha256:abc123", true},
		{"nginx@sha384:abc123", true},
		{"nginx@sha512:abc123", true},
		{"sha256:abc123", true},
		{"nginx:latest", false},
		{"nginx:v1.0", false},
		{"library/nginx:latest", false},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			result := isDigestReference(tt.ref)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestNormalizeDigest(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sha256:abc123", "sha256/abc123"},
		{"sha512:def456", "sha512/def456"},
		{"nocolon", "nocolon"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeDigest(tt.input)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// Tests for Close

func TestClose(t *testing.T) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	err := storage.Close()
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Operations should fail after close
	ctx := context.Background()
	_, err = storage.GetBlob(ctx, "sha256:test")
	if err == nil {
		t.Error("expected error for closed storage")
	}
}

// Benchmark tests

func BenchmarkStoreBlob(b *testing.B) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	content := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		digest := "sha256:bench" + string(rune('0'+i%10))
		_ = storage.StoreBlob(ctx, digest, content)
	}
}

func BenchmarkGetBlob(b *testing.B) {
	client := newMockStorageClient()
	storage, _ := NewQuicBaaSStorage(client)

	ctx := context.Background()
	digest := "sha256:benchget"
	content := make([]byte, 1024)
	_ = storage.StoreBlob(ctx, digest, content)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = storage.GetBlob(ctx, digest)
	}
}
