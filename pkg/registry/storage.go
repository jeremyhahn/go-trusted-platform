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
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// Entity type prefixes for QuicBaaS storage.
	entityTypeBlob     = "registry_blob"
	entityTypeManifest = "registry_manifest"
	entityTypeTag      = "registry_tag"

	// Default TTL for blobs (0 = no expiration).
	defaultBlobTTL = 0
)

// ImageManifest represents an OCI image manifest.
type ImageManifest struct {
	// SchemaVersion is the image manifest schema version.
	SchemaVersion int `json:"schemaVersion"`

	// MediaType is the manifest media type.
	MediaType string `json:"mediaType"`

	// Config is the image configuration descriptor.
	Config Descriptor `json:"config"`

	// Layers are the layer descriptors.
	Layers []Descriptor `json:"layers"`

	// Annotations are optional annotations.
	Annotations map[string]string `json:"annotations,omitempty"`

	// Reference is the image reference (repository:tag or digest).
	Reference string `json:"reference,omitempty"`

	// CreatedAt is when the manifest was stored.
	CreatedAt time.Time `json:"created_at,omitempty"`

	// UpdatedAt is when the manifest was last updated.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Descriptor describes a content-addressable blob.
type Descriptor struct {
	// MediaType is the media type of the referenced content.
	MediaType string `json:"mediaType"`

	// Digest is the content digest.
	Digest string `json:"digest"`

	// Size is the size in bytes.
	Size int64 `json:"size"`

	// Annotations are optional annotations.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ListOptions configures manifest listing behavior.
type ListOptions struct {
	// Repository filters by repository name.
	Repository string

	// Prefix filters by reference prefix.
	Prefix string

	// Limit is the maximum number of results to return.
	Limit int

	// Cursor is the pagination cursor from a previous query.
	Cursor string

	// IncludeTags includes tag information in results.
	IncludeTags bool
}

// ListResult contains the results of a manifest list operation.
type ListResult struct {
	// Manifests are the matching manifests.
	Manifests []ImageManifest

	// NextCursor is the cursor for the next page of results.
	NextCursor string

	// HasMore indicates if there are more results.
	HasMore bool
}

// QuicBaaSStorage provides QuicBaaS-backed storage for the registry.
type QuicBaaSStorage struct {
	client    QuicBaaSStorageClient
	namespace string
	closed    atomic.Bool
}

// QuicBaaSStorageClient defines the QuicBaaS client interface for storage operations.
type QuicBaaSStorageClient interface {
	// Put stores a key-value pair with optional TTL.
	Put(ctx context.Context, entityType, key string, value []byte, ttl time.Duration) error

	// Get retrieves a value by key.
	Get(ctx context.Context, entityType, key string) ([]byte, bool, error)

	// Delete removes a key.
	Delete(ctx context.Context, entityType, key string) error

	// List lists keys matching a prefix.
	List(ctx context.Context, entityType, prefix string, limit int, cursor string) (keys []string, nextCursor string, hasMore bool, err error)
}

// StorageOption is a functional option for configuring QuicBaaSStorage.
type StorageOption func(*QuicBaaSStorage)

// WithNamespace sets the storage namespace.
func WithStorageNamespace(ns string) StorageOption {
	return func(s *QuicBaaSStorage) {
		s.namespace = ns
	}
}

// NewQuicBaaSStorage creates a new QuicBaaSStorage instance.
func NewQuicBaaSStorage(client QuicBaaSStorageClient, opts ...StorageOption) (*QuicBaaSStorage, error) {
	if client == nil {
		return nil, ErrNilClient{Client: "quicbaas"}
	}

	s := &QuicBaaSStorage{
		client:    client,
		namespace: "registry",
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// StoreBlob stores a blob by its digest.
func (s *QuicBaaSStorage) StoreBlob(ctx context.Context, digest string, content []byte) error {
	if ctx == nil {
		return ErrNilContext{Operation: "StoreBlob"}
	}
	if err := s.validateDigest(digest); err != nil {
		return err
	}
	if s.closed.Load() {
		return ErrRegistryClosed{}
	}

	key := s.blobKey(digest)
	if err := s.client.Put(ctx, entityTypeBlob, key, content, defaultBlobTTL); err != nil {
		return ErrStorageError{Operation: "store_blob", Key: digest, Cause: err}
	}

	return nil
}

// GetBlob retrieves a blob by its digest.
func (s *QuicBaaSStorage) GetBlob(ctx context.Context, digest string) ([]byte, error) {
	if ctx == nil {
		return nil, ErrNilContext{Operation: "GetBlob"}
	}
	if err := s.validateDigest(digest); err != nil {
		return nil, err
	}
	if s.closed.Load() {
		return nil, ErrRegistryClosed{}
	}

	key := s.blobKey(digest)
	content, found, err := s.client.Get(ctx, entityTypeBlob, key)
	if err != nil {
		return nil, ErrStorageError{Operation: "get_blob", Key: digest, Cause: err}
	}
	if !found {
		return nil, ErrBlobNotFound{Digest: digest}
	}

	return content, nil
}

// DeleteBlob removes a blob by its digest.
func (s *QuicBaaSStorage) DeleteBlob(ctx context.Context, digest string) error {
	if ctx == nil {
		return ErrNilContext{Operation: "DeleteBlob"}
	}
	if err := s.validateDigest(digest); err != nil {
		return err
	}
	if s.closed.Load() {
		return ErrRegistryClosed{}
	}

	key := s.blobKey(digest)
	if err := s.client.Delete(ctx, entityTypeBlob, key); err != nil {
		return ErrStorageError{Operation: "delete_blob", Key: digest, Cause: err}
	}

	return nil
}

// BlobExists checks if a blob exists.
func (s *QuicBaaSStorage) BlobExists(ctx context.Context, digest string) (bool, error) {
	if ctx == nil {
		return false, ErrNilContext{Operation: "BlobExists"}
	}
	if err := s.validateDigest(digest); err != nil {
		return false, err
	}
	if s.closed.Load() {
		return false, ErrRegistryClosed{}
	}

	key := s.blobKey(digest)
	_, found, err := s.client.Get(ctx, entityTypeBlob, key)
	if err != nil {
		return false, ErrStorageError{Operation: "blob_exists", Key: digest, Cause: err}
	}

	return found, nil
}

// StoreManifest stores an image manifest.
func (s *QuicBaaSStorage) StoreManifest(ctx context.Context, ref string, manifest *ImageManifest) error {
	if ctx == nil {
		return ErrNilContext{Operation: "StoreManifest"}
	}
	if err := s.validateReference(ref); err != nil {
		return err
	}
	if manifest == nil {
		return ErrInvalidManifest{Reference: ref, Reason: "manifest is nil"}
	}
	if s.closed.Load() {
		return ErrRegistryClosed{}
	}

	// Set metadata
	now := time.Now().UTC()
	manifest.Reference = ref
	if manifest.CreatedAt.IsZero() {
		manifest.CreatedAt = now
	}
	manifest.UpdatedAt = now

	// Serialize manifest
	data, err := json.Marshal(manifest)
	if err != nil {
		return ErrStorageError{Operation: "marshal_manifest", Cause: err}
	}

	// Store manifest by reference
	key := s.manifestKey(ref)
	if err := s.client.Put(ctx, entityTypeManifest, key, data, 0); err != nil {
		return ErrStorageError{Operation: "store_manifest", Key: ref, Cause: err}
	}

	// If reference is a tag (not a digest), store tag mapping
	if !isDigestReference(ref) {
		if err := s.storeTag(ctx, ref, manifest.Config.Digest); err != nil {
			return err
		}
	}

	return nil
}

// GetManifest retrieves an image manifest.
func (s *QuicBaaSStorage) GetManifest(ctx context.Context, ref string) (*ImageManifest, error) {
	if ctx == nil {
		return nil, ErrNilContext{Operation: "GetManifest"}
	}
	if err := s.validateReference(ref); err != nil {
		return nil, err
	}
	if s.closed.Load() {
		return nil, ErrRegistryClosed{}
	}

	key := s.manifestKey(ref)
	data, found, err := s.client.Get(ctx, entityTypeManifest, key)
	if err != nil {
		return nil, ErrStorageError{Operation: "get_manifest", Key: ref, Cause: err}
	}
	if !found {
		return nil, ErrManifestNotFound{Reference: ref}
	}

	var manifest ImageManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, ErrStorageError{Operation: "unmarshal_manifest", Cause: err}
	}

	return &manifest, nil
}

// DeleteManifest removes an image manifest.
func (s *QuicBaaSStorage) DeleteManifest(ctx context.Context, ref string) error {
	if ctx == nil {
		return ErrNilContext{Operation: "DeleteManifest"}
	}
	if err := s.validateReference(ref); err != nil {
		return err
	}
	if s.closed.Load() {
		return ErrRegistryClosed{}
	}

	key := s.manifestKey(ref)
	if err := s.client.Delete(ctx, entityTypeManifest, key); err != nil {
		return ErrStorageError{Operation: "delete_manifest", Key: ref, Cause: err}
	}

	// Remove tag if applicable
	if !isDigestReference(ref) {
		_ = s.deleteTag(ctx, ref)
	}

	return nil
}

// ManifestExists checks if a manifest exists.
func (s *QuicBaaSStorage) ManifestExists(ctx context.Context, ref string) (bool, error) {
	if ctx == nil {
		return false, ErrNilContext{Operation: "ManifestExists"}
	}
	if err := s.validateReference(ref); err != nil {
		return false, err
	}
	if s.closed.Load() {
		return false, ErrRegistryClosed{}
	}

	key := s.manifestKey(ref)
	_, found, err := s.client.Get(ctx, entityTypeManifest, key)
	if err != nil {
		return false, ErrStorageError{Operation: "manifest_exists", Key: ref, Cause: err}
	}

	return found, nil
}

// ListManifests lists manifests matching the given options.
func (s *QuicBaaSStorage) ListManifests(ctx context.Context, opts ListOptions) (*ListResult, error) {
	if ctx == nil {
		return nil, ErrNilContext{Operation: "ListManifests"}
	}
	if s.closed.Load() {
		return nil, ErrRegistryClosed{}
	}

	// Build prefix for listing
	prefix := s.namespace
	if opts.Repository != "" {
		prefix = s.namespace + "/" + opts.Repository
	}
	if opts.Prefix != "" {
		prefix = prefix + "/" + opts.Prefix
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}

	// List manifest keys
	keys, nextCursor, hasMore, err := s.client.List(ctx, entityTypeManifest, prefix, limit, opts.Cursor)
	if err != nil {
		return nil, ErrStorageError{Operation: "list_manifests", Cause: err}
	}

	// Fetch manifests
	manifests := make([]ImageManifest, 0, len(keys))
	for _, key := range keys {
		data, found, err := s.client.Get(ctx, entityTypeManifest, key)
		if err != nil {
			continue
		}
		if !found {
			continue
		}

		var manifest ImageManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			continue
		}
		manifests = append(manifests, manifest)
	}

	return &ListResult{
		Manifests:  manifests,
		NextCursor: nextCursor,
		HasMore:    hasMore,
	}, nil
}

// Close closes the storage.
func (s *QuicBaaSStorage) Close() error {
	s.closed.Store(true)
	return nil
}

// Helper methods

// blobKey generates the storage key for a blob.
func (s *QuicBaaSStorage) blobKey(digest string) string {
	return s.namespace + "/blobs/" + normalizeDigest(digest)
}

// manifestKey generates the storage key for a manifest.
func (s *QuicBaaSStorage) manifestKey(ref string) string {
	return s.namespace + "/manifests/" + ref
}

// tagKey generates the storage key for a tag.
func (s *QuicBaaSStorage) tagKey(ref string) string {
	return s.namespace + "/tags/" + ref
}

// storeTag stores a tag-to-digest mapping.
func (s *QuicBaaSStorage) storeTag(ctx context.Context, ref, digest string) error {
	key := s.tagKey(ref)
	return s.client.Put(ctx, entityTypeTag, key, []byte(digest), 0)
}

// deleteTag removes a tag mapping.
func (s *QuicBaaSStorage) deleteTag(ctx context.Context, ref string) error {
	key := s.tagKey(ref)
	return s.client.Delete(ctx, entityTypeTag, key)
}

// validateDigest validates a content digest.
func (s *QuicBaaSStorage) validateDigest(digest string) error {
	if digest == "" {
		return ErrInvalidDigest{Reason: "digest is empty"}
	}
	// Basic validation: should be algorithm:hash format
	if !strings.Contains(digest, ":") {
		return ErrInvalidDigest{Digest: digest, Reason: "missing algorithm prefix"}
	}
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ErrInvalidDigest{Digest: digest, Reason: "invalid format"}
	}
	// Validate algorithm
	switch parts[0] {
	case "sha256", "sha512", "sha384":
		// Valid algorithms
	default:
		return ErrInvalidDigest{Digest: digest, Reason: "unsupported algorithm: " + parts[0]}
	}
	return nil
}

// validateReference validates an image reference.
func (s *QuicBaaSStorage) validateReference(ref string) error {
	if ref == "" {
		return ErrInvalidImageRef{Reason: "reference is empty"}
	}
	// References can be:
	// - repository:tag (e.g., "nginx:latest")
	// - repository@digest (e.g., "nginx@sha256:...")
	// - Just a digest (e.g., "sha256:...")
	return nil
}

// normalizeDigest normalizes a digest for storage key use.
func normalizeDigest(digest string) string {
	// Replace colon with slash for key compatibility
	return strings.ReplaceAll(digest, ":", "/")
}

// isDigestReference checks if a reference is a digest (not a tag).
func isDigestReference(ref string) bool {
	return strings.Contains(ref, "@sha256:") ||
		strings.Contains(ref, "@sha384:") ||
		strings.Contains(ref, "@sha512:") ||
		strings.HasPrefix(ref, "sha256:") ||
		strings.HasPrefix(ref, "sha384:") ||
		strings.HasPrefix(ref, "sha512:")
}
