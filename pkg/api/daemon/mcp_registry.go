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

package daemon

import (
	"context"
	"time"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
)

// =============================================================================
// MCP Registry bridge
// =============================================================================
//
// MCPServiceProvider implements mcp.RegistryProvider by delegating to the
// same grpcapi.RegistryService that powers the gRPC RegistryServiceServer.
// This keeps the MCP and gRPC surfaces in lockstep: AI/LLM clients calling
// platform_registry_list hit the exact same code path as a gRPC List RPC.
//
// Streaming Push/Pull RPCs are intentionally not exposed via MCP. Their
// payloads are binary chunks that are a poor fit for the JSON-RPC tool
// surface; clients that need the bytes use the gRPC or REST adapter
// directly. The MCP surface covers list/inspect/delete/status — the
// JSON-shaped read & lifecycle operations.

// ErrRegistryNotConfigured indicates that no RegistryService is wired
// into the MCPServiceProvider. Callers should treat this the same way
// the gRPC RegistryService treats a nil service (FailedPrecondition).
type ErrRegistryNotConfigured struct{}

// Error returns a human-readable description of the error.
func (ErrRegistryNotConfigured) Error() string {
	return "registry service not configured"
}

// ErrRegistryRepositoryRequired indicates that an MCP request was missing
// the required `repository` argument.
type ErrRegistryRepositoryRequired struct{}

// Error returns a human-readable description of the error.
func (ErrRegistryRepositoryRequired) Error() string {
	return "registry: repository is required"
}

// ErrRegistryReferenceRequired indicates that an MCP request was missing
// both `reference` and `digest`. At least one is needed to identify a
// specific artifact.
type ErrRegistryReferenceRequired struct{}

// Error returns a human-readable description of the error.
func (ErrRegistryReferenceRequired) Error() string {
	return "registry: reference (tag) or digest is required"
}

// SetRegistryService injects the registry service after construction.
// The daemon wires the same grpcapi.RegistryService that powers the
// gRPC RegistryServiceServer so the MCP and gRPC surfaces stay in
// lockstep.
func (p *MCPServiceProvider) SetRegistryService(svc grpcapi.RegistryService) {
	p.registryService = svc
}

// =============================================================================
// List
// =============================================================================

// RegistryList returns a paginated set of artifacts. `repository` and
// `artifactType` are optional filters; pass empty / 0 to disable.
func (p *MCPServiceProvider) RegistryList(ctx context.Context, repository string, artifactType int32, limit, offset int32) (interface{}, error) {
	if p.registryService == nil {
		return nil, ErrRegistryNotConfigured{}
	}
	req := &grpcapi.RegistryListRequest{
		Repository: repository,
		Type:       grpcapi.ArtifactType(artifactType),
		Limit:      limit,
		Offset:     offset,
	}
	resp, err := p.registryService.List(ctx, req)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"total":       resp.Total,
		"has_more":    resp.HasMore,
		"next_cursor": resp.NextCursor,
		"artifacts":   registryArtifactsJSON(resp.Artifacts),
	}
	if resp.Pagination != nil {
		out["pagination"] = map[string]interface{}{
			"page":        resp.Pagination.Page,
			"page_size":   resp.Pagination.PageSize,
			"total_pages": resp.Pagination.TotalPages,
			"total_items": resp.Pagination.TotalItems,
		}
	}
	return out, nil
}

// =============================================================================
// Inspect
// =============================================================================

// RegistryInspect returns detailed metadata for a single artifact.
func (p *MCPServiceProvider) RegistryInspect(ctx context.Context, repository, reference, digest string, includeSignatures, includeScanResult bool) (interface{}, error) {
	if p.registryService == nil {
		return nil, ErrRegistryNotConfigured{}
	}
	if repository == "" {
		return nil, ErrRegistryRepositoryRequired{}
	}
	if reference == "" && digest == "" {
		return nil, ErrRegistryReferenceRequired{}
	}
	req := &grpcapi.RegistryInspectRequest{
		Repository:        repository,
		Reference:         reference,
		Digest:            digest,
		IncludeSignatures: includeSignatures,
		IncludeScanResult: includeScanResult,
	}
	resp, err := p.registryService.Inspect(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Detail == nil {
		return map[string]interface{}{
			"repository": repository,
			"reference":  reference,
			"digest":     digest,
		}, nil
	}
	return registryDetailJSON(resp.Detail), nil
}

// =============================================================================
// Delete
// =============================================================================

// RegistryDelete removes an artifact from the registry.
func (p *MCPServiceProvider) RegistryDelete(ctx context.Context, repository, reference, digest string, force bool) (interface{}, error) {
	if p.registryService == nil {
		return nil, ErrRegistryNotConfigured{}
	}
	if repository == "" {
		return nil, ErrRegistryRepositoryRequired{}
	}
	if reference == "" && digest == "" {
		return nil, ErrRegistryReferenceRequired{}
	}
	req := &grpcapi.RegistryDeleteRequest{
		Repository: repository,
		Reference:  reference,
		Digest:     digest,
		Force:      force,
	}
	resp, err := p.registryService.Delete(ctx, req)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"repository":  repository,
		"reference":   reference,
		"digest":      resp.Digest,
		"bytes_freed": resp.BytesFreed,
		"timestamp":   registryTimeJSON(resp.Timestamp),
	}
	return out, nil
}

// =============================================================================
// Status
// =============================================================================

// RegistryStatus returns registry health, version, and storage stats.
func (p *MCPServiceProvider) RegistryStatus(ctx context.Context) (interface{}, error) {
	if p.registryService == nil {
		return nil, ErrRegistryNotConfigured{}
	}
	resp, err := p.registryService.Status(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"health":     registryHealthString(resp.Health),
		"version":    resp.Version,
		"read_only":  resp.ReadOnly,
		"started_at": registryTimeJSON(resp.StartedAt),
		"timestamp":  registryTimeJSON(resp.Timestamp),
	}
	if resp.Storage != nil {
		out["storage"] = map[string]interface{}{
			"total_bytes":      resp.Storage.TotalBytes,
			"used_bytes":       resp.Storage.UsedBytes,
			"available_bytes":  resp.Storage.AvailableBytes,
			"artifact_count":   resp.Storage.ArtifactCount,
			"layer_count":      resp.Storage.LayerCount,
			"repository_count": resp.Storage.RepositoryCount,
		}
	}
	if len(resp.Components) > 0 {
		comps := make([]map[string]interface{}, 0, len(resp.Components))
		for _, c := range resp.Components {
			if c == nil {
				continue
			}
			comps = append(comps, map[string]interface{}{
				"name":       c.Name,
				"status":     registryHealthString(c.Status),
				"message":    c.Message,
				"last_check": registryTimeJSON(c.LastCheck),
				"details":    c.Details,
			})
		}
		out["components"] = comps
	}
	return out, nil
}

// =============================================================================
// Helpers
// =============================================================================

// registryArtifactJSON formats a single artifact as a JSON-friendly map
// matching the proto Artifact field names. Mirrors the gRPC response
// shape so MCP clients see the same fields gRPC clients already know.
func registryArtifactJSON(a *grpcapi.RegistryArtifact) map[string]interface{} {
	if a == nil {
		return nil
	}
	out := map[string]interface{}{
		"id":             a.ID,
		"repository":     a.Repository,
		"tag":            a.Tag,
		"digest":         a.Digest,
		"type":           registryArtifactTypeString(a.Type),
		"state":          registryArtifactStateString(a.State),
		"size":           a.Size,
		"labels":         a.Labels,
		"annotations":    a.Annotations,
		"os":             a.OS,
		"architecture":   a.Architecture,
		"author":         a.Author,
		"created_at":     registryTimeJSON(a.CreatedAt),
		"updated_at":     registryTimeJSON(a.UpdatedAt),
		"pushed_at":      registryTimeJSON(a.PushedAt),
		"last_pulled_at": registryTimeJSON(a.LastPulledAt),
		"pull_count":     a.PullCount,
	}
	if a.Manifest != nil {
		out["manifest"] = registryManifestJSON(a.Manifest)
	}
	return out
}

// registryArtifactsJSON formats a slice of artifacts.
func registryArtifactsJSON(artifacts []*grpcapi.RegistryArtifact) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(artifacts))
	for _, a := range artifacts {
		if a == nil {
			continue
		}
		out = append(out, registryArtifactJSON(a))
	}
	return out
}

// registryManifestJSON formats an artifact manifest.
func registryManifestJSON(m *grpcapi.RegistryArtifactManifest) map[string]interface{} {
	if m == nil {
		return nil
	}
	layers := make([]map[string]interface{}, 0, len(m.Layers))
	for _, l := range m.Layers {
		if l == nil {
			continue
		}
		layers = append(layers, map[string]interface{}{
			"digest":      l.Digest,
			"size":        l.Size,
			"media_type":  l.MediaType,
			"compression": registryCompressionString(l.Compression),
			"annotations": l.Annotations,
		})
	}
	return map[string]interface{}{
		"digest":        m.Digest,
		"media_type":    m.MediaType,
		"size":          m.Size,
		"config_digest": m.ConfigDigest,
		"layers":        layers,
		"annotations":   m.Annotations,
	}
}

// registryDetailJSON formats an inspect response detail block.
func registryDetailJSON(d *grpcapi.RegistryArtifactDetail) map[string]interface{} {
	if d == nil {
		return nil
	}
	out := map[string]interface{}{
		"artifact": registryArtifactJSON(d.Artifact),
		"tags":     d.Tags,
	}
	if len(d.Signatures) > 0 {
		sigs := make([]map[string]interface{}, 0, len(d.Signatures))
		for _, s := range d.Signatures {
			if s == nil {
				continue
			}
			sigs = append(sigs, map[string]interface{}{
				"key_id":    s.KeyID,
				"algorithm": s.Algorithm,
				"signature": s.Signature,
				"signed_at": registryTimeJSON(s.SignedAt),
				"signer":    s.Signer,
			})
		}
		out["signatures"] = sigs
	}
	if d.ScanResult != nil {
		vulns := make([]map[string]interface{}, 0, len(d.ScanResult.Vulnerabilities))
		for _, v := range d.ScanResult.Vulnerabilities {
			if v == nil {
				continue
			}
			vulns = append(vulns, map[string]interface{}{
				"id":              v.ID,
				"severity":        registryVulnSeverityString(v.Severity),
				"package_name":    v.PackageName,
				"package_version": v.PackageVersion,
				"fixed_version":   v.FixedVersion,
				"description":     v.Description,
				"link":            v.Link,
			})
		}
		out["scan_result"] = map[string]interface{}{
			"scanner":         d.ScanResult.Scanner,
			"scanned_at":      registryTimeJSON(d.ScanResult.ScannedAt),
			"vulnerabilities": vulns,
			"low_count":       d.ScanResult.LowCount,
			"medium_count":    d.ScanResult.MediumCount,
			"high_count":      d.ScanResult.HighCount,
			"critical_count":  d.ScanResult.CriticalCount,
		}
	}
	return out
}

// registryTimeJSON returns a millisecond-precision UNIX timestamp for
// JSON serialization. Returns 0 for the zero value so MCP clients can
// distinguish "unset" from "epoch".
func registryTimeJSON(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// registryArtifactTypeString maps the integer enum to a stable, human
// friendly string. Map-based dispatch keeps lookup O(1).
var registryArtifactTypeStrings = map[grpcapi.ArtifactType]string{
	grpcapi.ArtifactTypeUnspecified:    "unspecified",
	grpcapi.ArtifactTypeContainerImage: "container_image",
	grpcapi.ArtifactTypeHelmChart:      "helm_chart",
	grpcapi.ArtifactTypeOCIArtifact:    "oci_artifact",
	grpcapi.ArtifactTypeWASMModule:     "wasm_module",
	grpcapi.ArtifactTypeBinary:         "binary",
}

func registryArtifactTypeString(t grpcapi.ArtifactType) string {
	if s, ok := registryArtifactTypeStrings[t]; ok {
		return s
	}
	return "unspecified"
}

var registryArtifactStateStrings = map[grpcapi.ArtifactState]string{
	grpcapi.ArtifactStateUnspecified: "unspecified",
	grpcapi.ArtifactStateUploading:   "uploading",
	grpcapi.ArtifactStateAvailable:   "available",
	grpcapi.ArtifactStateQuarantined: "quarantined",
	grpcapi.ArtifactStateDeleting:    "deleting",
	grpcapi.ArtifactStateDeleted:     "deleted",
}

func registryArtifactStateString(s grpcapi.ArtifactState) string {
	if v, ok := registryArtifactStateStrings[s]; ok {
		return v
	}
	return "unspecified"
}

var registryCompressionStrings = map[grpcapi.CompressionType]string{
	grpcapi.CompressionTypeUnspecified: "unspecified",
	grpcapi.CompressionTypeNone:        "none",
	grpcapi.CompressionTypeGzip:        "gzip",
	grpcapi.CompressionTypeZstd:        "zstd",
}

func registryCompressionString(c grpcapi.CompressionType) string {
	if v, ok := registryCompressionStrings[c]; ok {
		return v
	}
	return "unspecified"
}

var registryHealthStrings = map[grpcapi.RegistryHealthStatus]string{
	grpcapi.RegistryHealthStatusUnspecified: "unspecified",
	grpcapi.RegistryHealthStatusHealthy:     "healthy",
	grpcapi.RegistryHealthStatusDegraded:    "degraded",
	grpcapi.RegistryHealthStatusUnhealthy:   "unhealthy",
}

func registryHealthString(h grpcapi.RegistryHealthStatus) string {
	if v, ok := registryHealthStrings[h]; ok {
		return v
	}
	return "unspecified"
}

var registryVulnSeverityStrings = map[grpcapi.VulnerabilitySeverity]string{
	grpcapi.VulnerabilitySeverityUnspecified: "unspecified",
	grpcapi.VulnerabilitySeverityLow:         "low",
	grpcapi.VulnerabilitySeverityMedium:      "medium",
	grpcapi.VulnerabilitySeverityHigh:        "high",
	grpcapi.VulnerabilitySeverityCritical:    "critical",
}

func registryVulnSeverityString(s grpcapi.VulnerabilitySeverity) string {
	if v, ok := registryVulnSeverityStrings[s]; ok {
		return v
	}
	return "unspecified"
}
