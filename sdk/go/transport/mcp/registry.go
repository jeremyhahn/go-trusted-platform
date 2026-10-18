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

package mcp

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Registry MCP mapping. The daemon's platform_registry_* tools
// (pkg/api/mcp/registry_tools.go) answer with the JSON views in
// pkg/api/daemon/mcp_registry.go: enums as lower-case names
// ("container_image", "healthy") and times as Unix milliseconds, 0 when
// unset. Push and Pull are client and server streams, which an MCP tool
// call cannot carry (docs/registry/api.md §4), so they stay unmapped.

func init() {
	for method, tool := range map[string]string{
		platformv1.RegistryService_List_FullMethodName:    "platform_registry_list",
		platformv1.RegistryService_Inspect_FullMethodName: "platform_registry_inspect",
		platformv1.RegistryService_Delete_FullMethodName:  "platform_registry_delete",
		platformv1.RegistryService_Status_FullMethodName:  "platform_registry_status",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}

	for method, build := range map[string]mcpArgBuilder{
		platformv1.RegistryService_List_FullMethodName:    buildRegistryListArgs,
		platformv1.RegistryService_Inspect_FullMethodName: buildRegistryInspectArgs,
		platformv1.RegistryService_Delete_FullMethodName:  buildRegistryDeleteArgs,
		platformv1.RegistryService_Status_FullMethodName:  buildRegistryStatusArgs,
	} {
		mcpArgBuilders[method] = build
	}

	for method, decode := range map[string]mcpReplyDecoder{
		platformv1.RegistryService_List_FullMethodName:    decodeRegistryListResult,
		platformv1.RegistryService_Inspect_FullMethodName: decodeRegistryInspectResult,
		platformv1.RegistryService_Delete_FullMethodName:  decodeRegistryDeleteResult,
		platformv1.RegistryService_Status_FullMethodName:  decodeRegistryStatusResult,
	} {
		mcpReplyDecoders[method] = decode
	}
}

// buildRegistryListArgs carries every ListArtifactsRequest field: the
// repository and type filters, the limit/offset or cursor page, the sort
// order and, when set, the label selector as match_labels and
// match_expressions.
func buildRegistryListArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.ListArtifactsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.RegistryService_List_FullMethodName}
	}
	out := map[string]interface{}{
		"repository":    in.GetRepository(),
		"artifact_type": int32(in.GetType()),
		"limit":         in.GetLimit(),
		"offset":        in.GetOffset(),
		"cursor":        in.GetCursor(),
		"sort_by":       in.GetSortBy(),
		"ascending":     in.GetAscending(),
	}
	if selector := in.GetSelector(); selector != nil {
		out["match_labels"] = selector.GetMatchLabels()
		out["match_expressions"] = selector.GetMatchExpressions()
	}
	return out, nil
}

func buildRegistryInspectArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.InspectArtifactRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.RegistryService_Inspect_FullMethodName}
	}
	return map[string]interface{}{
		"repository":          in.GetRepository(),
		"reference":           in.GetReference(),
		"digest":              in.GetDigest(),
		"include_signatures":  in.GetIncludeSignatures(),
		"include_scan_result": in.GetIncludeScanResult(),
	}, nil
}

func buildRegistryDeleteArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.DeleteArtifactRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.RegistryService_Delete_FullMethodName}
	}
	return map[string]interface{}{
		"repository": in.GetRepository(),
		"reference":  in.GetReference(),
		"digest":     in.GetDigest(),
		"force":      in.GetForce(),
	}, nil
}

func buildRegistryStatusArgs(args interface{}) (map[string]interface{}, error) {
	if _, ok := args.(*platformv1.RegistryStatusRequest); !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.RegistryService_Status_FullMethodName}
	}
	return map[string]interface{}{}, nil
}

// registryEnum maps a lower-case enum name from a registry tool result
// onto its platformv1 value by the generated prefix, so "container_image"
// becomes ARTIFACT_TYPE_CONTAINER_IMAGE. An absent name is the zero value.
func registryEnum(field, prefix, name string, values map[string]int32) (int32, error) {
	if name == "" {
		return 0, nil
	}
	value, ok := values[prefix+strings.ToUpper(name)]
	if !ok {
		return 0, ErrUnknownRegistryEnum{Field: field, Value: name}
	}
	return value, nil
}

// registryTime maps a Unix-millisecond time onto a timestamp; 0 is unset.
func registryTime(ms int64) *timestamppb.Timestamp {
	if ms == 0 {
		return nil
	}
	return timestamppb.New(time.UnixMilli(ms))
}

type registryLayerWire struct {
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	MediaType   string            `json:"media_type"`
	Compression string            `json:"compression"`
	Annotations map[string]string `json:"annotations"`
}

type registryManifestWire struct {
	Digest       string              `json:"digest"`
	MediaType    string              `json:"media_type"`
	Size         int64               `json:"size"`
	ConfigDigest string              `json:"config_digest"`
	Layers       []registryLayerWire `json:"layers"`
	Annotations  map[string]string   `json:"annotations"`
}

func (w *registryManifestWire) toPb() (*platformv1.ArtifactManifest, error) {
	if w == nil {
		return nil, nil
	}
	layers := make([]*platformv1.ArtifactLayer, 0, len(w.Layers))
	for _, l := range w.Layers {
		compression, err := registryEnum("compression", "COMPRESSION_TYPE_", l.Compression, platformv1.CompressionType_value)
		if err != nil {
			return nil, err
		}
		layers = append(layers, &platformv1.ArtifactLayer{
			Digest:      l.Digest,
			Size:        l.Size,
			MediaType:   l.MediaType,
			Compression: platformv1.CompressionType(compression),
			Annotations: l.Annotations,
		})
	}
	return &platformv1.ArtifactManifest{
		Digest:       w.Digest,
		MediaType:    w.MediaType,
		Size:         w.Size,
		ConfigDigest: w.ConfigDigest,
		Layers:       layers,
		Annotations:  w.Annotations,
	}, nil
}

type registryArtifactWire struct {
	ID           string                `json:"id"`
	Repository   string                `json:"repository"`
	Tag          string                `json:"tag"`
	Digest       string                `json:"digest"`
	Type         string                `json:"type"`
	State        string                `json:"state"`
	Size         int64                 `json:"size"`
	Manifest     *registryManifestWire `json:"manifest"`
	Labels       map[string]string     `json:"labels"`
	Annotations  map[string]string     `json:"annotations"`
	OS           string                `json:"os"`
	Architecture string                `json:"architecture"`
	Author       string                `json:"author"`
	CreatedAt    int64                 `json:"created_at"`
	UpdatedAt    int64                 `json:"updated_at"`
	PushedAt     int64                 `json:"pushed_at"`
	LastPulledAt int64                 `json:"last_pulled_at"`
	PullCount    int64                 `json:"pull_count"`
}

func (w *registryArtifactWire) toPb() (*platformv1.Artifact, error) {
	if w == nil {
		return nil, nil
	}
	artifactType, err := registryEnum("artifact type", "ARTIFACT_TYPE_", w.Type, platformv1.ArtifactType_value)
	if err != nil {
		return nil, err
	}
	state, err := registryEnum("artifact state", "ARTIFACT_STATE_", w.State, platformv1.ArtifactState_value)
	if err != nil {
		return nil, err
	}
	manifest, err := w.Manifest.toPb()
	if err != nil {
		return nil, err
	}
	return &platformv1.Artifact{
		Id:           w.ID,
		Repository:   w.Repository,
		Tag:          w.Tag,
		Digest:       w.Digest,
		Type:         platformv1.ArtifactType(artifactType),
		State:        platformv1.ArtifactState(state),
		Size:         w.Size,
		Manifest:     manifest,
		Labels:       w.Labels,
		Annotations:  w.Annotations,
		Os:           w.OS,
		Architecture: w.Architecture,
		Author:       w.Author,
		CreatedAt:    registryTime(w.CreatedAt),
		UpdatedAt:    registryTime(w.UpdatedAt),
		PushedAt:     registryTime(w.PushedAt),
		LastPulledAt: registryTime(w.LastPulledAt),
		PullCount:    w.PullCount,
	}, nil
}

type registryPaginationWire struct {
	Page       uint32 `json:"page"`
	PageSize   uint32 `json:"page_size"`
	TotalPages uint32 `json:"total_pages"`
	TotalItems uint64 `json:"total_items"`
}

type registryListWire struct {
	Total      int32                   `json:"total"`
	HasMore    bool                    `json:"has_more"`
	NextCursor string                  `json:"next_cursor"`
	Artifacts  []registryArtifactWire  `json:"artifacts"`
	Pagination *registryPaginationWire `json:"pagination"`
}

func decodeRegistryListResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListArtifactsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.RegistryService_List_FullMethodName}
	}
	var wire registryListWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	artifacts := make([]*platformv1.Artifact, 0, len(wire.Artifacts))
	for i := range wire.Artifacts {
		artifact, err := wire.Artifacts[i].toPb()
		if err != nil {
			return err
		}
		artifacts = append(artifacts, artifact)
	}
	out.Artifacts = artifacts
	out.Total = wire.Total
	out.HasMore = wire.HasMore
	out.NextCursor = wire.NextCursor
	if p := wire.Pagination; p != nil {
		out.Pagination = &platformv1.PaginationResponse{
			Page:       p.Page,
			PageSize:   p.PageSize,
			TotalPages: p.TotalPages,
			TotalItems: p.TotalItems,
		}
	}
	return nil
}

type registrySignatureWire struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Signature []byte `json:"signature"`
	SignedAt  int64  `json:"signed_at"`
	Signer    string `json:"signer"`
}

type registryVulnerabilityWire struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
	FixedVersion   string `json:"fixed_version"`
	Description    string `json:"description"`
	Link           string `json:"link"`
}

type registryScanWire struct {
	Scanner         string                      `json:"scanner"`
	ScannedAt       int64                       `json:"scanned_at"`
	Vulnerabilities []registryVulnerabilityWire `json:"vulnerabilities"`
	LowCount        int32                       `json:"low_count"`
	MediumCount     int32                       `json:"medium_count"`
	HighCount       int32                       `json:"high_count"`
	CriticalCount   int32                       `json:"critical_count"`
}

func (w *registryScanWire) toPb() (*platformv1.ScanResult, error) {
	if w == nil {
		return nil, nil
	}
	vulns := make([]*platformv1.Vulnerability, 0, len(w.Vulnerabilities))
	for _, v := range w.Vulnerabilities {
		severity, err := registryEnum("vulnerability severity", "VULNERABILITY_SEVERITY_", v.Severity, platformv1.VulnerabilitySeverity_value)
		if err != nil {
			return nil, err
		}
		vulns = append(vulns, &platformv1.Vulnerability{
			Id:             v.ID,
			Severity:       platformv1.VulnerabilitySeverity(severity),
			PackageName:    v.PackageName,
			PackageVersion: v.PackageVersion,
			FixedVersion:   v.FixedVersion,
			Description:    v.Description,
			Link:           v.Link,
		})
	}
	return &platformv1.ScanResult{
		Scanner:         w.Scanner,
		ScannedAt:       registryTime(w.ScannedAt),
		Vulnerabilities: vulns,
		LowCount:        w.LowCount,
		MediumCount:     w.MediumCount,
		HighCount:       w.HighCount,
		CriticalCount:   w.CriticalCount,
	}, nil
}

type registryDetailWire struct {
	Artifact   *registryArtifactWire   `json:"artifact"`
	Tags       []string                `json:"tags"`
	Signatures []registrySignatureWire `json:"signatures"`
	ScanResult *registryScanWire       `json:"scan_result"`
}

// decodeRegistryInspectResult maps the artifact detail. The daemon answers
// an inspect that found no detail with only the request's own coordinates
// and no "artifact" key; that maps to an empty detail.
func decodeRegistryInspectResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.InspectArtifactResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.RegistryService_Inspect_FullMethodName}
	}
	var wire registryDetailWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	if wire.Artifact == nil {
		out.Detail = nil
		return nil
	}
	artifact, err := wire.Artifact.toPb()
	if err != nil {
		return err
	}
	scan, err := wire.ScanResult.toPb()
	if err != nil {
		return err
	}
	signatures := make([]*platformv1.ArtifactSignature, 0, len(wire.Signatures))
	for _, s := range wire.Signatures {
		signatures = append(signatures, &platformv1.ArtifactSignature{
			KeyId:     s.KeyID,
			Algorithm: s.Algorithm,
			Signature: s.Signature,
			SignedAt:  registryTime(s.SignedAt),
			Signer:    s.Signer,
		})
	}
	out.Detail = &platformv1.ArtifactDetail{
		Artifact:   artifact,
		Signatures: signatures,
		ScanResult: scan,
		Tags:       wire.Tags,
	}
	return nil
}

type registryDeleteWire struct {
	Digest     string `json:"digest"`
	BytesFreed int64  `json:"bytes_freed"`
	Timestamp  int64  `json:"timestamp"`
}

func decodeRegistryDeleteResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DeleteArtifactResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.RegistryService_Delete_FullMethodName}
	}
	var wire registryDeleteWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Digest = wire.Digest
	out.BytesFreed = wire.BytesFreed
	out.Timestamp = registryTime(wire.Timestamp)
	return nil
}

type registryStorageWire struct {
	TotalBytes      int64 `json:"total_bytes"`
	UsedBytes       int64 `json:"used_bytes"`
	AvailableBytes  int64 `json:"available_bytes"`
	ArtifactCount   int64 `json:"artifact_count"`
	LayerCount      int64 `json:"layer_count"`
	RepositoryCount int64 `json:"repository_count"`
}

type registryComponentWire struct {
	Name      string            `json:"name"`
	Status    string            `json:"status"`
	Message   string            `json:"message"`
	LastCheck int64             `json:"last_check"`
	Details   map[string]string `json:"details"`
}

type registryStatusWire struct {
	Health     string                  `json:"health"`
	Version    string                  `json:"version"`
	ReadOnly   bool                    `json:"read_only"`
	StartedAt  int64                   `json:"started_at"`
	Timestamp  int64                   `json:"timestamp"`
	Storage    *registryStorageWire    `json:"storage"`
	Components []registryComponentWire `json:"components"`
}

func decodeRegistryStatusResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.RegistryStatusResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.RegistryService_Status_FullMethodName}
	}
	var wire registryStatusWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	health, err := registryEnum("health", "HEALTH_STATUS_", wire.Health, platformv1.HealthStatus_value)
	if err != nil {
		return err
	}
	components := make([]*platformv1.ComponentHealth, 0, len(wire.Components))
	for _, c := range wire.Components {
		componentHealth, err := registryEnum("health", "HEALTH_STATUS_", c.Status, platformv1.HealthStatus_value)
		if err != nil {
			return err
		}
		components = append(components, &platformv1.ComponentHealth{
			Name:      c.Name,
			Status:    platformv1.HealthStatus(componentHealth),
			Message:   c.Message,
			LastCheck: registryTime(c.LastCheck),
			Details:   c.Details,
		})
	}
	out.Health = platformv1.HealthStatus(health)
	out.Version = wire.Version
	out.ReadOnly = wire.ReadOnly
	out.StartedAt = registryTime(wire.StartedAt)
	out.Timestamp = registryTime(wire.Timestamp)
	out.Components = components
	if s := wire.Storage; s != nil {
		out.Storage = &platformv1.StorageStats{
			TotalBytes:      s.TotalBytes,
			UsedBytes:       s.UsedBytes,
			AvailableBytes:  s.AvailableBytes,
			ArtifactCount:   s.ArtifactCount,
			LayerCount:      s.LayerCount,
			RepositoryCount: s.RepositoryCount,
		}
	}
	return nil
}
