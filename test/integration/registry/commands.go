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

//go:build integration

package registry

import (
	"context"
	"time"
)

// RegistryCommands defines the central command set for Registry integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Socket) implements this interface.
// Tests are written once against this interface and run against all protocols.
type RegistryCommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Image Management Commands (platformctl registry ...)
	Push(ctx context.Context, ref string, opts PushOptions) (*PushResult, error)
	Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error)
	List(ctx context.Context, opts ListOptions) (*ListResult, error)
	Delete(ctx context.Context, ref string, opts DeleteOptions) (*DeleteResult, error)
	Inspect(ctx context.Context, ref string) (*InspectResult, error)
	Status(ctx context.Context) (*StatusResult, error)
	Tag(ctx context.Context, sourceRef, targetRef string) (*TagResult, error)

	// Attestation Commands (platformctl registry attestation ...)
	VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error)
	GetSession(ctx context.Context, clientID string) (*SessionResult, error)
	InvalidateSession(ctx context.Context, clientID string) error

	// Encryption Commands (platformctl registry encrypt ...)
	EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error)
	DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error)
}

// PushOptions contains options for pushing an image to the registry.
type PushOptions struct {
	// Encrypt indicates whether to encrypt the image
	Encrypt bool

	// KeyID is the encryption key ID (required if Encrypt is true)
	KeyID string

	// AllowOverwrite allows overwriting an existing image
	AllowOverwrite bool

	// SignImage indicates whether to sign the image
	SignImage bool

	// SigningKeyID is the key ID for image signing
	SigningKeyID string

	// Annotations are metadata to add to the manifest
	Annotations map[string]string

	// Timeout overrides the default operation timeout
	Timeout time.Duration

	// ImageData is the image content for push operations
	ImageData []byte

	// Layers are the layer contents for the image
	Layers []LayerData

	// Config is the image configuration
	Config []byte
}

// LayerData represents a single image layer for push operations.
type LayerData struct {
	// MediaType is the layer media type
	MediaType string

	// Content is the layer content
	Content []byte

	// Annotations are layer-specific annotations
	Annotations map[string]string
}

// PushResult contains the result of a push operation.
type PushResult struct {
	// Reference is the pushed image reference
	Reference string

	// Digest is the manifest digest
	Digest string

	// Size is the total size in bytes
	Size int64

	// Encrypted indicates whether the image was encrypted
	Encrypted bool

	// Signed indicates whether the image was signed
	Signed bool

	// PushedAt is when the image was pushed
	PushedAt time.Time
}

// PullOptions contains options for pulling an image from the registry.
type PullOptions struct {
	// DecryptIfEncrypted will attempt to decrypt encrypted images
	DecryptIfEncrypted bool

	// VerifySignature will verify the image signature if signed
	VerifySignature bool

	// Platform specifies the target platform (e.g., "linux/amd64")
	Platform string

	// Timeout overrides the default operation timeout
	Timeout time.Duration
}

// PullResult contains the result of a pull operation.
type PullResult struct {
	// Reference is the pulled image reference
	Reference string

	// Manifest is the image manifest
	Manifest *ImageManifest

	// Config is the image configuration
	Config []byte

	// Layers are the pulled layer data
	Layers []LayerData

	// Encrypted indicates whether the image was encrypted
	Encrypted bool

	// Signed indicates whether the image was signed
	Signed bool

	// SignatureValid indicates whether the signature was verified
	SignatureValid bool

	// PulledAt is when the image was pulled
	PulledAt time.Time
}

// ListOptions contains options for listing images in the registry.
type ListOptions struct {
	// Repository filters by repository name
	Repository string

	// TagPrefix filters tags by prefix
	TagPrefix string

	// Limit limits the number of results
	Limit int

	// Cursor is the pagination cursor
	Cursor string

	// IncludeEncrypted includes encrypted images
	IncludeEncrypted bool

	// SortBy specifies the sort field
	SortBy string

	// SortDesc reverses the sort order
	SortDesc bool
}

// ListResult contains the result of a list operation.
type ListResult struct {
	// Images are the matching image manifests
	Images []ImageManifest

	// TotalCount is the total number of matching images
	TotalCount int

	// HasMore indicates if there are more results
	HasMore bool

	// NextCursor is the cursor for the next page
	NextCursor string
}

// ImageManifest represents an OCI image manifest.
type ImageManifest struct {
	// SchemaVersion is the image manifest schema version
	SchemaVersion int

	// MediaType is the manifest media type
	MediaType string

	// Config is the image configuration descriptor
	Config Descriptor

	// Layers are the layer descriptors
	Layers []Descriptor

	// Annotations are optional annotations
	Annotations map[string]string

	// Reference is the image reference (repository:tag or digest)
	Reference string

	// Digest is the manifest content digest
	Digest string

	// Size is the manifest size in bytes
	Size int64

	// CreatedAt is when the manifest was stored
	CreatedAt time.Time

	// UpdatedAt is when the manifest was last updated
	UpdatedAt time.Time

	// Encrypted indicates whether the image is encrypted
	Encrypted bool

	// Signed indicates whether the image is signed
	Signed bool
}

// Descriptor describes a content-addressable blob.
type Descriptor struct {
	// MediaType is the media type of the referenced content
	MediaType string

	// Digest is the content digest
	Digest string

	// Size is the size in bytes
	Size int64

	// Annotations are optional annotations
	Annotations map[string]string
}

// DeleteOptions contains options for deleting an image.
type DeleteOptions struct {
	// Force skips confirmation
	Force bool

	// DeleteLayers also deletes orphaned layers
	DeleteLayers bool
}

// DeleteResult contains the result of a delete operation.
type DeleteResult struct {
	// Reference is the deleted image reference
	Reference string

	// Digest is the deleted manifest digest
	Digest string

	// DeletedAt is when the image was deleted
	DeletedAt time.Time

	// LayersDeleted is the number of orphaned layers deleted
	LayersDeleted int
}

// InspectResult contains detailed image information.
type InspectResult struct {
	// Reference is the image reference
	Reference string

	// Manifest is the image manifest
	Manifest *ImageManifest

	// Config is the parsed image configuration
	Config *ImageConfig

	// TotalSize is the total size of all layers
	TotalSize int64

	// LayerCount is the number of layers
	LayerCount int

	// Encrypted indicates whether the image is encrypted
	Encrypted bool

	// EncryptionKeyID is the encryption key ID if encrypted
	EncryptionKeyID string

	// Signed indicates whether the image is signed
	Signed bool

	// SigningKeyID is the signing key ID if signed
	SigningKeyID string

	// SignatureValid indicates whether the signature was verified
	SignatureValid bool
}

// ImageConfig represents the image configuration.
type ImageConfig struct {
	// Architecture is the CPU architecture
	Architecture string

	// OS is the operating system
	OS string

	// Author is the image author
	Author string

	// Created is when the image was created
	Created time.Time

	// Entrypoint is the default entrypoint
	Entrypoint []string

	// Cmd is the default command
	Cmd []string

	// Env are environment variables
	Env []string

	// WorkingDir is the working directory
	WorkingDir string

	// Labels are image labels
	Labels map[string]string

	// ExposedPorts are exposed ports
	ExposedPorts []string

	// Volumes are volume mount points
	Volumes []string
}

// StatusResult contains registry status information.
type StatusResult struct {
	// Healthy indicates whether the registry is healthy
	Healthy bool

	// Status is the current status (e.g., "running", "degraded")
	Status string

	// Version is the registry version
	Version string

	// Uptime is the registry uptime
	Uptime time.Duration

	// ImageCount is the total number of images
	ImageCount int

	// TotalSize is the total storage size
	TotalSize int64

	// ActiveConnections is the number of active connections
	ActiveConnections int

	// AttestationEnabled indicates whether attestation is required
	AttestationEnabled bool

	// EncryptionEnabled indicates whether encryption is enabled
	EncryptionEnabled bool

	// StorageBackend is the storage backend type
	StorageBackend string

	// StorageStatus is the storage backend status
	StorageStatus string
}

// TagResult contains the result of a tag operation.
type TagResult struct {
	// SourceReference is the source image reference
	SourceReference string

	// TargetReference is the target image reference (new tag)
	TargetReference string

	// Digest is the manifest digest (same for both)
	Digest string

	// TaggedAt is when the tag was created
	TaggedAt time.Time
}

// VerifyClientOptions contains options for client attestation verification.
type VerifyClientOptions struct {
	// ClientID identifies the client
	ClientID string

	// AIK is the Attestation Identity Key
	AIK []byte

	// Quote is the TPM quote
	Quote []byte

	// Signature is the quote signature
	Signature []byte

	// Nonce is the attestation nonce
	Nonce []byte

	// PCRs are the PCR values
	PCRs map[int][]byte

	// EventLog is the measurement event log
	EventLog []byte

	// Timestamp is when the quote was generated
	Timestamp time.Time
}

// VerifyClientResult contains the result of client verification.
type VerifyClientResult struct {
	// Verified indicates whether the client was verified
	Verified bool

	// ClientID is the verified client ID
	ClientID string

	// SessionID is the created session ID
	SessionID string

	// ValidUntil is when the session expires
	ValidUntil time.Time

	// Permissions are the granted permissions
	Permissions []string

	// Reason is the reason if verification failed
	Reason string
}

// SessionResult contains session information.
type SessionResult struct {
	// ClientID is the client ID
	ClientID string

	// SessionID is the session ID
	SessionID string

	// AIK is the client's AIK fingerprint
	AIK string

	// PCRs are the verified PCR values
	PCRs map[int][]byte

	// ValidUntil is when the session expires
	ValidUntil time.Time

	// Permissions are the granted permissions
	Permissions []string

	// CreatedAt is when the session was created
	CreatedAt time.Time
}

// EncryptImageResult contains the result of an image encryption operation.
type EncryptImageResult struct {
	// Reference is the encrypted image reference
	Reference string

	// KeyID is the encryption key ID used
	KeyID string

	// EncryptedAt is when the image was encrypted
	EncryptedAt time.Time

	// LayersEncrypted is the number of layers encrypted
	LayersEncrypted int
}

// DecryptImageResult contains the result of an image decryption operation.
type DecryptImageResult struct {
	// Reference is the decrypted image reference
	Reference string

	// KeyID is the decryption key ID used
	KeyID string

	// DecryptedAt is when the image was decrypted
	DecryptedAt time.Time

	// Manifest is the decrypted image manifest
	Manifest *ImageManifest

	// Layers are the decrypted layer data
	Layers []LayerData
}
