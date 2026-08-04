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

// RegistryStatusResult contains the status of the registry.
type RegistryStatusResult struct {
	Health     HealthStatus       `json:"health" yaml:"health"`
	Version    string             `json:"version" yaml:"version"`
	Storage    *StorageStats      `json:"storage,omitempty" yaml:"storage,omitempty"`
	Components []*ComponentStatus `json:"components,omitempty" yaml:"components,omitempty"`
	StartedAt  int64              `json:"started_at,omitempty" yaml:"started_at,omitempty"`
	Timestamp  int64              `json:"timestamp,omitempty" yaml:"timestamp,omitempty"`
}

// StorageStats contains registry storage statistics.
type StorageStats struct {
	UsedBytes       int64 `json:"used_bytes" yaml:"used_bytes"`
	TotalBytes      int64 `json:"total_bytes" yaml:"total_bytes"`
	ArtifactCount   int64 `json:"artifact_count" yaml:"artifact_count"`
	LayerCount      int64 `json:"layer_count" yaml:"layer_count"`
	RepositoryCount int64 `json:"repository_count" yaml:"repository_count"`
}

// ComponentStatus represents the status of a registry component.
type ComponentStatus struct {
	Name   string       `json:"name" yaml:"name"`
	Status HealthStatus `json:"status" yaml:"status"`
}

// Artifact represents a registry artifact.
type Artifact struct {
	Repository   string            `json:"repository" yaml:"repository"`
	Tag          string            `json:"tag,omitempty" yaml:"tag,omitempty"`
	Digest       string            `json:"digest" yaml:"digest"`
	Size         int64             `json:"size" yaml:"size"`
	OS           string            `json:"os,omitempty" yaml:"os,omitempty"`
	Architecture string            `json:"architecture,omitempty" yaml:"architecture,omitempty"`
	CreatedAt    int64             `json:"created_at,omitempty" yaml:"created_at,omitempty"`
	PushedAt     int64             `json:"pushed_at,omitempty" yaml:"pushed_at,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	LayerCount   int               `json:"layer_count" yaml:"layer_count"`
}

// ListArtifactsResult contains the result of listing artifacts.
type ListArtifactsResult struct {
	Artifacts  []*Artifact `json:"artifacts" yaml:"artifacts"`
	Total      int32       `json:"total" yaml:"total"`
	HasMore    bool        `json:"has_more" yaml:"has_more"`
	NextCursor string      `json:"next_cursor,omitempty" yaml:"next_cursor,omitempty"`
}

// ArtifactDetail contains detailed information about an artifact.
type ArtifactDetail struct {
	Artifact   *Artifact          `json:"artifact,omitempty" yaml:"artifact,omitempty"`
	Manifest   *ManifestInfo      `json:"manifest,omitempty" yaml:"manifest,omitempty"`
	Signatures []*SignatureDetail `json:"signatures,omitempty" yaml:"signatures,omitempty"`
}

// ManifestInfo contains manifest details.
type ManifestInfo struct {
	MediaType    string       `json:"media_type" yaml:"media_type"`
	ConfigDigest string       `json:"config_digest" yaml:"config_digest"`
	Size         int64        `json:"size" yaml:"size"`
	Layers       []*LayerInfo `json:"layers,omitempty" yaml:"layers,omitempty"`
}

// LayerInfo contains information about a manifest layer.
type LayerInfo struct {
	Digest    string `json:"digest" yaml:"digest"`
	Size      int64  `json:"size" yaml:"size"`
	MediaType string `json:"media_type" yaml:"media_type"`
}

// SignatureDetail contains signature information.
type SignatureDetail struct {
	Signer    string `json:"signer" yaml:"signer"`
	KeyID     string `json:"key_id" yaml:"key_id"`
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	SignedAt  int64  `json:"signed_at,omitempty" yaml:"signed_at,omitempty"`
}

// DeleteResult contains the result of a delete operation.
type DeleteResult struct {
	Digest     string `json:"digest" yaml:"digest"`
	Success    bool   `json:"success" yaml:"success"`
	Message    string `json:"message,omitempty" yaml:"message,omitempty"`
	BytesFreed int64  `json:"bytes_freed" yaml:"bytes_freed"`
	Timestamp  int64  `json:"timestamp,omitempty" yaml:"timestamp,omitempty"`
}
