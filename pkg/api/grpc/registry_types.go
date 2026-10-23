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

package grpc

import (
	"context"
	"io"
	"time"
)

// RegistryService defines the interface for registry operations.
// This interface is implemented by registry service providers and used by the gRPC service.
type RegistryService interface {
	// Push pushes an artifact to the registry.
	Push(ctx context.Context, req *RegistryPushRequest) (*RegistryPushResponse, error)

	// PushStream handles streaming push of artifact data.
	PushStream(ctx context.Context, metadata *RegistryPushMetadata, reader io.Reader) (*RegistryPushResponse, error)

	// Pull pulls an artifact from the registry.
	Pull(ctx context.Context, req *RegistryPullRequest) (*RegistryPullResponse, error)

	// PullStream returns a reader for streaming artifact data.
	PullStream(ctx context.Context, req *RegistryPullRequest) (*RegistryPullStreamResponse, error)

	// List returns a paginated list of artifacts.
	List(ctx context.Context, req *RegistryListRequest) (*RegistryListResponse, error)

	// Inspect retrieves detailed metadata about an artifact.
	Inspect(ctx context.Context, req *RegistryInspectRequest) (*RegistryInspectResponse, error)

	// Delete removes an artifact from the registry.
	Delete(ctx context.Context, req *RegistryDeleteRequest) (*RegistryDeleteResponse, error)

	// Status returns the current status of the registry.
	Status(ctx context.Context) (*RegistryStatusResponse, error)
}

// =============================================================================
// Artifact Types
// =============================================================================

// ArtifactType defines the type of artifact stored in the registry.
type ArtifactType int32

const (
	ArtifactTypeUnspecified    ArtifactType = 0
	ArtifactTypeContainerImage ArtifactType = 1
	ArtifactTypeHelmChart      ArtifactType = 2
	ArtifactTypeOCIArtifact    ArtifactType = 3
	ArtifactTypeWASMModule     ArtifactType = 4
	ArtifactTypeBinary         ArtifactType = 5
)

// ArtifactState represents the state of an artifact.
type ArtifactState int32

const (
	ArtifactStateUnspecified ArtifactState = 0
	ArtifactStateUploading   ArtifactState = 1
	ArtifactStateAvailable   ArtifactState = 2
	ArtifactStateQuarantined ArtifactState = 3
	ArtifactStateDeleting    ArtifactState = 4
	ArtifactStateDeleted     ArtifactState = 5
)

// CompressionType defines the compression algorithm used for artifacts.
type CompressionType int32

const (
	CompressionTypeUnspecified CompressionType = 0
	CompressionTypeNone        CompressionType = 1
	CompressionTypeGzip        CompressionType = 2
	CompressionTypeZstd        CompressionType = 3
)

// VulnerabilitySeverity defines the severity level of a vulnerability.
type VulnerabilitySeverity int32

const (
	VulnerabilitySeverityUnspecified VulnerabilitySeverity = 0
	VulnerabilitySeverityLow         VulnerabilitySeverity = 1
	VulnerabilitySeverityMedium      VulnerabilitySeverity = 2
	VulnerabilitySeverityHigh        VulnerabilitySeverity = 3
	VulnerabilitySeverityCritical    VulnerabilitySeverity = 4
)

// HealthStatus defines the health status of the registry.
type RegistryHealthStatus int32

const (
	RegistryHealthStatusUnspecified RegistryHealthStatus = 0
	RegistryHealthStatusHealthy     RegistryHealthStatus = 1
	RegistryHealthStatusDegraded    RegistryHealthStatus = 2
	RegistryHealthStatusUnhealthy   RegistryHealthStatus = 3
)

// =============================================================================
// Artifact Data Types
// =============================================================================

// RegistryArtifactLayer represents a single layer of a container image or artifact.
type RegistryArtifactLayer struct {
	Digest      string
	Size        int64
	MediaType   string
	Compression CompressionType
	Annotations map[string]string
}

// RegistryArtifactManifest represents the manifest of a container image or artifact.
type RegistryArtifactManifest struct {
	Digest       string
	MediaType    string
	Size         int64
	ConfigDigest string
	Layers       []*RegistryArtifactLayer
	Annotations  map[string]string
}

// RegistryArtifact represents an artifact stored in the registry.
type RegistryArtifact struct {
	ID           string
	Repository   string
	Tag          string
	Digest       string
	Type         ArtifactType
	State        ArtifactState
	Size         int64
	Manifest     *RegistryArtifactManifest
	Labels       map[string]string
	Annotations  map[string]string
	OS           string
	Architecture string
	Author       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	PushedAt     time.Time
	LastPulledAt time.Time
	PullCount    int64
}

// RegistryArtifactSignature represents a signature attached to an artifact.
type RegistryArtifactSignature struct {
	KeyID     string
	Algorithm string
	Signature []byte
	SignedAt  time.Time
	Signer    string
}

// RegistryVulnerability represents a security vulnerability found in an artifact.
type RegistryVulnerability struct {
	ID             string
	Severity       VulnerabilitySeverity
	PackageName    string
	PackageVersion string
	FixedVersion   string
	Description    string
	Link           string
}

// RegistryScanResult represents the result of a vulnerability scan.
type RegistryScanResult struct {
	Scanner         string
	ScannedAt       time.Time
	Vulnerabilities []*RegistryVulnerability
	LowCount        int32
	MediumCount     int32
	HighCount       int32
	CriticalCount   int32
}

// RegistryArtifactDetail provides comprehensive information about an artifact.
type RegistryArtifactDetail struct {
	Artifact   *RegistryArtifact
	Signatures []*RegistryArtifactSignature
	ScanResult *RegistryScanResult
	Tags       []string
}

// RegistryStorageStats contains storage usage statistics.
type RegistryStorageStats struct {
	TotalBytes      int64
	UsedBytes       int64
	AvailableBytes  int64
	ArtifactCount   int64
	LayerCount      int64
	RepositoryCount int64
}

// RegistryComponentHealth represents the health of a registry component.
type RegistryComponentHealth struct {
	Name      string
	Status    RegistryHealthStatus
	Message   string
	LastCheck time.Time
	Details   map[string]string
}

// =============================================================================
// Push Request/Response Types
// =============================================================================

// RegistryPushMetadata contains metadata for the push operation.
type RegistryPushMetadata struct {
	Repository   string
	Tag          string
	Type         ArtifactType
	MediaType    string
	TotalSize    int64
	Digest       string
	Labels       map[string]string
	Annotations  map[string]string
	OS           string
	Architecture string
}

// RegistryPushRequest represents a push request.
type RegistryPushRequest struct {
	Metadata *RegistryPushMetadata
	Data     []byte
}

// RegistryPushResponse represents a push response.
type RegistryPushResponse struct {
	Artifact      *RegistryArtifact
	BytesReceived int64
	Timestamp     time.Time
}

// =============================================================================
// Pull Request/Response Types
// =============================================================================

// RegistryPullRequest represents a pull request.
type RegistryPullRequest struct {
	Repository string
	Reference  string
	Digest     string
}

// RegistryPullResponse represents a pull response.
type RegistryPullResponse struct {
	Artifact  *RegistryArtifact
	TotalSize int64
	Data      []byte
}

// RegistryPullStreamResponse represents a streaming pull response.
type RegistryPullStreamResponse struct {
	Artifact  *RegistryArtifact
	TotalSize int64
	Reader    io.Reader
}

// =============================================================================
// List Request/Response Types
// =============================================================================

// RegistryLabelSelector for filtering artifacts.
type RegistryLabelSelector struct {
	MatchLabels      map[string]string
	MatchExpressions []string
}

// RegistryListRequest represents a list artifacts request.
type RegistryListRequest struct {
	Repository string
	Type       ArtifactType
	Selector   *RegistryLabelSelector
	Limit      int32
	Offset     int32
	Cursor     string
	SortBy     string
	Ascending  bool
}

// RegistryPaginationResponse contains pagination information.
type RegistryPaginationResponse struct {
	Page       uint32
	PageSize   uint32
	TotalPages uint32
	TotalItems uint64
}

// RegistryListResponse represents a list artifacts response.
type RegistryListResponse struct {
	Artifacts  []*RegistryArtifact
	Total      int32
	NextCursor string
	HasMore    bool
	Pagination *RegistryPaginationResponse
}

// =============================================================================
// Inspect Request/Response Types
// =============================================================================

// RegistryInspectRequest represents an inspect artifact request.
type RegistryInspectRequest struct {
	Repository        string
	Reference         string
	Digest            string
	IncludeSignatures bool
	IncludeScanResult bool
}

// RegistryInspectResponse represents an inspect artifact response.
type RegistryInspectResponse struct {
	Detail *RegistryArtifactDetail
}

// =============================================================================
// Delete Request/Response Types
// =============================================================================

// RegistryDeleteRequest represents a delete artifact request.
type RegistryDeleteRequest struct {
	Repository string
	Reference  string
	Digest     string
	Force      bool
}

// RegistryDeleteResponse represents a delete artifact response.
type RegistryDeleteResponse struct {
	Digest     string
	BytesFreed int64
	Timestamp  time.Time
}

// =============================================================================
// Status Request/Response Types
// =============================================================================

// RegistryStatusResponse represents the registry status.
type RegistryStatusResponse struct {
	Health     RegistryHealthStatus
	Version    string
	Storage    *RegistryStorageStats
	ReadOnly   bool
	Components []*RegistryComponentHealth
	StartedAt  time.Time
	Timestamp  time.Time
}

// =============================================================================
// Registry Error Types
// =============================================================================

// ErrNilRegistryService is returned when the registry service is nil.
type ErrNilRegistryService struct{}

func (e ErrNilRegistryService) Error() string {
	return "registry service is nil"
}

// ErrMissingRepository is returned when a repository is required but not provided.
type ErrMissingRepository struct{}

func (e ErrMissingRepository) Error() string {
	return "repository is required"
}

// ErrMissingReference is returned when a reference is required but not provided.
type ErrMissingReference struct{}

func (e ErrMissingReference) Error() string {
	return "reference (tag or digest) is required"
}

// ErrMissingPushMetadata is returned when push metadata is required but not provided.
type ErrMissingPushMetadata struct{}

func (e ErrMissingPushMetadata) Error() string {
	return "push metadata is required"
}

// ErrArtifactNotFound is returned when an artifact is not found.
type ErrArtifactNotFound struct {
	Repository string
	Reference  string
}

func (e ErrArtifactNotFound) Error() string {
	return "artifact not found: " + e.Repository + ":" + e.Reference
}

// ErrArtifactAlreadyExists is returned when an artifact already exists.
type ErrArtifactAlreadyExists struct {
	Repository string
	Reference  string
}

func (e ErrArtifactAlreadyExists) Error() string {
	return "artifact already exists: " + e.Repository + ":" + e.Reference
}

// ErrRegistryOperationFailed is returned when a registry operation fails.
type ErrRegistryOperationFailed struct {
	Operation string
	Reason    string
}

func (e ErrRegistryOperationFailed) Error() string {
	return "registry operation " + e.Operation + " failed: " + e.Reason
}

// ErrInvalidArtifactDigest is returned when an artifact digest is invalid.
type ErrInvalidArtifactDigest struct {
	Digest string
}

func (e ErrInvalidArtifactDigest) Error() string {
	return "invalid artifact digest: " + e.Digest
}

// ErrInvalidArtifactReference is returned when a repository or tag does not
// follow the OCI distribution-spec reference grammar. It is a caller error.
type ErrInvalidArtifactReference struct {
	Reference string
	Reason    string
}

func (e ErrInvalidArtifactReference) Error() string {
	return "invalid artifact reference " + e.Reference + ": " + e.Reason
}

// ErrStreamClosed is returned when a stream is unexpectedly closed.
type ErrStreamClosed struct{}

func (e ErrStreamClosed) Error() string {
	return "stream closed unexpectedly"
}
