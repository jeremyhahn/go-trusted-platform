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
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const (
	PARTITION_OBJECTS = "objects"
)

var (
	ErrObjectNotFound = errors.New("store/object: object not found")
	ErrStorageNil     = errors.New("store/object: storage cannot be nil")
	ErrInvalidKey     = errors.New("store/object: key cannot be empty")
)

// ObjectStorer defines the interface for object storage operations.
// All operations use key prefixes constructed from rootDir and partition
// to provide namespace isolation across different ObjectStore instances.
type ObjectStorer interface {
	Count(partition *string) (int, error)
	Delete(key []byte) error
	Exists(key []byte) bool
	Get(key []byte) ([]byte, error)
	Home() string
	List(prefix string) ([]string, error)
	Partition() string
	Save(key, data []byte) error
	ObjectStorageClient() objectstorage.Client
}

// ObjectStore wraps a QuicBaaS ObjectStorage client, adding rootDir/partition
// key prefixing for namespace isolation. Multiple ObjectStores can share the
// same ObjectStorage client since they use different key prefixes.
// DefaultBackend is the name of the default object storage backend.
const DefaultBackend = "default"

// DefaultNamespace is the namespace prefix for object keys in QuicBaaS ObjectStorage.
// Keys are formatted as "namespace:path" per the QuicBaaS catalog key format.
const DefaultNamespace = "platform"

type ObjectStore struct {
	logger    *logging.Logger
	storage   objectstorage.Client
	tenantID  string
	backend   string
	namespace string
	rootDir   string
	partition string
	ObjectStorer
}

// NewObjectStore creates a new object store backed by a QuicBaaS ObjectStorage client.
// The rootDir and partition are prepended to all keys to create the full path.
// Multiple ObjectStores can share the same storage client since they use
// different key prefixes.
func NewObjectStore(
	logger *logging.Logger,
	storage objectstorage.Client,
	rootDir string,
	partition *string) (ObjectStorer, error) {

	if storage == nil {
		return nil, ErrStorageNil
	}

	var partitionName string
	if partition == nil {
		partitionName = PARTITION_OBJECTS
	} else {
		partitionName = *partition
	}
	// Normalize: strip leading slashes from rootDir for relative key construction
	rootDir = strings.TrimLeft(rootDir, "/")
	if len(rootDir) > 0 && rootDir[len(rootDir)-1] == '/' {
		rootDir = strings.TrimRight(rootDir, "/")
	}

	return &ObjectStore{
		logger:    logger,
		storage:   storage,
		backend:   DefaultBackend,
		namespace: DefaultNamespace,
		rootDir:   rootDir,
		partition: partitionName,
	}, nil
}

// NewObjectStoreWithTenant creates a new object store with tenant isolation.
func NewObjectStoreWithTenant(
	logger *logging.Logger,
	storage objectstorage.Client,
	rootDir string,
	partition *string,
	tenantID string) (ObjectStorer, error) {

	store, err := NewObjectStore(logger, storage, rootDir, partition)
	if err != nil {
		return nil, err
	}
	store.(*ObjectStore).tenantID = tenantID
	return store, nil
}

// ObjectStorageClient returns the underlying QuicBaaS ObjectStorage client.
func (store *ObjectStore) ObjectStorageClient() objectstorage.Client {
	return store.storage
}

// Home returns the object store's home directory (relative path)
func (store *ObjectStore) Home() string {
	return filepath.Join(store.rootDir, store.partition)
}

// Partition returns the object store's partition name
func (store *ObjectStore) Partition() string {
	return store.partition
}

// buildKey constructs a key in QuicBaaS ObjectStorage "namespace:path" format.
// The namespace is the store's namespace (default "platform").
// The path is rootDir/partition/key joined with forward slashes.
func (store *ObjectStore) buildKey(key []byte) string {
	trimmed := strings.TrimLeft(string(key), "/")
	path := filepath.Join(store.rootDir, store.partition, trimmed)
	return store.namespace + ":" + path
}

// Save stores an object in the object store. If the object key contains forward slashes,
// a directory hierarchy will be created to match the key.
func (store *ObjectStore) Save(key, data []byte) error {
	fullKey := store.buildKey(key)
	_, err := store.storage.PutObject(context.Background(), &objectstorage.PutObjectRequest{
		Key:           fullKey,
		Value:         data,
		TenantID:      store.tenantID,
		TargetBackend: store.backend,
	})
	if err != nil {
		store.logger.Error(err, slog.String("key", fullKey))
		return err
	}
	return nil
}

// Get retrieves an object from the object store. ErrObjectNotFound is
// returned if the object could not be found.
func (store *ObjectStore) Get(key []byte) ([]byte, error) {
	fullKey := store.buildKey(key)
	resp, err := store.storage.GetObject(context.Background(), &objectstorage.GetObjectRequest{
		Key:      fullKey,
		TenantID: store.tenantID,
	})
	if err != nil {
		if isNotFoundError(err) {
			return nil, ErrObjectNotFound
		}
		store.logger.Error(err, slog.String("key", fullKey))
		return nil, err
	}
	return resp.Value, nil
}

// Delete removes an object from the object store. ErrObjectNotFound is returned
// if the provided object key could not be found.
func (store *ObjectStore) Delete(key []byte) error {
	fullKey := store.buildKey(key)
	resp, err := store.storage.HeadObject(context.Background(), &objectstorage.HeadObjectRequest{
		Key:      fullKey,
		TenantID: store.tenantID,
	})
	if err != nil {
		store.logger.Error(err, slog.String("key", fullKey))
		return err
	}
	if !resp.Exists {
		return ErrObjectNotFound
	}
	_, err = store.storage.DeleteObject(context.Background(), &objectstorage.DeleteObjectRequest{
		Key:      fullKey,
		TenantID: store.tenantID,
	})
	return err
}

// Exists returns true if the object with the provided key exists
func (store *ObjectStore) Exists(key []byte) bool {
	fullKey := store.buildKey(key)
	resp, err := store.storage.HeadObject(context.Background(), &objectstorage.HeadObjectRequest{
		Key:      fullKey,
		TenantID: store.tenantID,
	})
	if err != nil {
		return false
	}
	return resp.Exists
}

// Count returns the number of objects in the object store or partition.
func (store *ObjectStore) Count(partition *string) (int, error) {
	path := filepath.Join(store.rootDir, store.partition)
	if partition != nil {
		trimmed := strings.TrimLeft(*partition, "/")
		path = filepath.Join(path, trimmed)
	}
	prefix := store.namespace + ":" + path
	resp, err := store.storage.ListObjects(context.Background(), &objectstorage.ListObjectsRequest{
		Prefix:   prefix,
		TenantID: store.tenantID,
	})
	if err != nil {
		return 0, err
	}
	return len(resp.Objects), nil
}

// List returns all object keys matching the given prefix.
// The prefix is relative to the object store's home directory.
func (store *ObjectStore) List(prefix string) ([]string, error) {
	path := filepath.Join(store.rootDir, store.partition)
	if prefix != "" {
		path = filepath.Join(path, strings.TrimLeft(prefix, "/"))
	}
	fullPrefix := store.namespace + ":" + path
	resp, err := store.storage.ListObjects(context.Background(), &objectstorage.ListObjectsRequest{
		Prefix:   fullPrefix,
		TenantID: store.tenantID,
	})
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(resp.Objects))
	for _, obj := range resp.Objects {
		keys = append(keys, obj.Key)
	}
	return keys, nil
}

// isNotFoundError checks if an error indicates a key was not found.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrObjectNotFound) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "does not exist") ||
		strings.Contains(errStr, "no such file") ||
		strings.Contains(errStr, "NoSuchKey") ||
		strings.Contains(errStr, "404")
}
