// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"encoding/json"
	"net/http"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Registry reads (#1970). The webservice serves the registry's List, Status
// and Inspect under /api/v1/compute/images. List answers {images, total} of
// ImageSummary (snake_case, RFC 3339 strings); Status and Inspect answer the
// PascalCase Go structs RegistryStatusResponse and RegistryArtifactDetail.
// Each reply has a decoder that places the payload on the pb response. An
// empty Inspect repository or reference is refused by the templated path
// substitution with InvalidArgument before any request.
func init() {
	templatedRouteTable[platformv1.RegistryService_List_FullMethodName] = templatedRoute{
		path:   "/api/v1/compute/images",
		method: http.MethodGet,
		queryParams: []queryParam{
			{name: "repository", field: "repository"},
			{name: "limit", field: "limit"},
			{name: "offset", field: "offset"},
		},
	}
	templatedRouteTable[platformv1.RegistryService_Status_FullMethodName] = templatedRoute{
		path:   "/api/v1/compute/images/status",
		method: http.MethodGet,
	}
	templatedRouteTable[platformv1.RegistryService_Inspect_FullMethodName] = templatedRoute{
		path:   "/api/v1/compute/images/{repository}:{reference}",
		method: http.MethodGet,
		pathParams: []pathParam{
			{placeholder: "{repository}", field: "repository"},
			{placeholder: "{reference}", field: "reference"},
		},
	}

	restResponseDecoders[platformv1.RegistryService_List_FullMethodName] = decodeRegistryList
	restResponseDecoders[platformv1.RegistryService_Status_FullMethodName] = decodeRegistryStatus
	restResponseDecoders[platformv1.RegistryService_Inspect_FullMethodName] = decodeRegistryInspect
}

// registryTimestamp maps a zero time to an unset timestamp.
func registryTimestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// registryRFC3339 parses an ImageSummary timestamp string; empty or
// unparseable strings leave the timestamp unset.
func registryRFC3339(s string) *timestamppb.Timestamp {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	return registryTimestamp(t)
}

type registryImageSummaryJSON struct {
	Repository  string            `json:"repository"`
	Tag         string            `json:"tag"`
	Digest      string            `json:"digest"`
	MediaType   string            `json:"media_type"`
	Size        int64             `json:"size"`
	Layers      int               `json:"layers"`
	Annotations map[string]string `json:"annotations"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
}

type registryListJSON struct {
	Images []registryImageSummaryJSON `json:"images"`
	Total  int32                      `json:"total"`
}

// decodeRegistryList decodes the {"images": [...], "total": n} payload.
func decodeRegistryList(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ListArtifactsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.RegistryService_List_FullMethodName}
	}
	var in registryListJSON
	if err := json.Unmarshal(raw, &in); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Artifacts = make([]*platformv1.Artifact, 0, len(in.Images))
	for _, img := range in.Images {
		a := &platformv1.Artifact{
			Repository:  img.Repository,
			Tag:         img.Tag,
			Digest:      img.Digest,
			Size:        img.Size,
			Annotations: img.Annotations,
			CreatedAt:   registryRFC3339(img.CreatedAt),
			UpdatedAt:   registryRFC3339(img.UpdatedAt),
		}
		if img.MediaType != "" {
			a.Manifest = &platformv1.ArtifactManifest{MediaType: img.MediaType}
		}
		out.Artifacts = append(out.Artifacts, a)
	}
	out.Total = in.Total
	return nil
}

type registryComponentJSON struct {
	Name      string
	Status    int32
	Message   string
	LastCheck time.Time
	Details   map[string]string
}

type registryStatusJSON struct {
	Health  int32
	Version string
	Storage *struct {
		TotalBytes      int64
		UsedBytes       int64
		AvailableBytes  int64
		ArtifactCount   int64
		LayerCount      int64
		RepositoryCount int64
	}
	ReadOnly   bool
	Components []registryComponentJSON
	StartedAt  time.Time
	Timestamp  time.Time
}

// decodeRegistryStatus places the PascalCase RegistryStatusResponse on the
// pb reply.
func decodeRegistryStatus(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.RegistryStatusResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.RegistryService_Status_FullMethodName}
	}
	var in registryStatusJSON
	if err := json.Unmarshal(raw, &in); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Health = platformv1.HealthStatus(in.Health)
	out.Version = in.Version
	out.ReadOnly = in.ReadOnly
	if in.Storage != nil {
		out.Storage = &platformv1.StorageStats{
			TotalBytes:      in.Storage.TotalBytes,
			UsedBytes:       in.Storage.UsedBytes,
			AvailableBytes:  in.Storage.AvailableBytes,
			ArtifactCount:   in.Storage.ArtifactCount,
			LayerCount:      in.Storage.LayerCount,
			RepositoryCount: in.Storage.RepositoryCount,
		}
	}
	for _, c := range in.Components {
		out.Components = append(out.Components, &platformv1.ComponentHealth{
			Name:      c.Name,
			Status:    platformv1.HealthStatus(c.Status),
			Message:   c.Message,
			LastCheck: registryTimestamp(c.LastCheck),
			Details:   c.Details,
		})
	}
	out.StartedAt = registryTimestamp(in.StartedAt)
	out.Timestamp = registryTimestamp(in.Timestamp)
	out.Status = &platformv1.Status{Success: true}
	return nil
}

type registryLayerJSON struct {
	Digest      string
	Size        int64
	MediaType   string
	Compression int32
	Annotations map[string]string
}

type registryManifestJSON struct {
	Digest       string
	MediaType    string
	Size         int64
	ConfigDigest string
	Layers       []registryLayerJSON
	Annotations  map[string]string
}

type registryArtifactJSON struct {
	ID           string
	Repository   string
	Tag          string
	Digest       string
	Type         int32
	State        int32
	Size         int64
	Manifest     *registryManifestJSON
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

type registrySignatureJSON struct {
	KeyID     string
	Algorithm string
	Signature []byte
	SignedAt  time.Time
	Signer    string
}

type registryVulnerabilityJSON struct {
	ID             string
	Severity       int32
	PackageName    string
	PackageVersion string
	FixedVersion   string
	Description    string
	Link           string
}

type registryScanJSON struct {
	Scanner         string
	ScannedAt       time.Time
	Vulnerabilities []registryVulnerabilityJSON
	LowCount        int32
	MediumCount     int32
	HighCount       int32
	CriticalCount   int32
}

type registryDetailJSON struct {
	Artifact   *registryArtifactJSON
	Signatures []registrySignatureJSON
	ScanResult *registryScanJSON
	Tags       []string
}

func (a *registryArtifactJSON) toPB() *platformv1.Artifact {
	if a == nil {
		return nil
	}
	out := &platformv1.Artifact{
		Id:           a.ID,
		Repository:   a.Repository,
		Tag:          a.Tag,
		Digest:       a.Digest,
		Type:         platformv1.ArtifactType(a.Type),
		State:        platformv1.ArtifactState(a.State),
		Size:         a.Size,
		Labels:       a.Labels,
		Annotations:  a.Annotations,
		Os:           a.OS,
		Architecture: a.Architecture,
		Author:       a.Author,
		CreatedAt:    registryTimestamp(a.CreatedAt),
		UpdatedAt:    registryTimestamp(a.UpdatedAt),
		PushedAt:     registryTimestamp(a.PushedAt),
		LastPulledAt: registryTimestamp(a.LastPulledAt),
		PullCount:    a.PullCount,
	}
	if m := a.Manifest; m != nil {
		man := &platformv1.ArtifactManifest{
			Digest:       m.Digest,
			MediaType:    m.MediaType,
			Size:         m.Size,
			ConfigDigest: m.ConfigDigest,
			Annotations:  m.Annotations,
		}
		for _, l := range m.Layers {
			man.Layers = append(man.Layers, &platformv1.ArtifactLayer{
				Digest:      l.Digest,
				Size:        l.Size,
				MediaType:   l.MediaType,
				Compression: platformv1.CompressionType(l.Compression),
				Annotations: l.Annotations,
			})
		}
		out.Manifest = man
	}
	return out
}

// decodeRegistryInspect places the PascalCase RegistryArtifactDetail on
// InspectArtifactResponse.
func decodeRegistryInspect(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.InspectArtifactResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.RegistryService_Inspect_FullMethodName}
	}
	var in registryDetailJSON
	if err := json.Unmarshal(raw, &in); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	detail := &platformv1.ArtifactDetail{
		Artifact: in.Artifact.toPB(),
		Tags:     in.Tags,
	}
	for _, s := range in.Signatures {
		detail.Signatures = append(detail.Signatures, &platformv1.ArtifactSignature{
			KeyId:     s.KeyID,
			Algorithm: s.Algorithm,
			Signature: s.Signature,
			SignedAt:  registryTimestamp(s.SignedAt),
			Signer:    s.Signer,
		})
	}
	if sr := in.ScanResult; sr != nil {
		scan := &platformv1.ScanResult{
			Scanner:       sr.Scanner,
			ScannedAt:     registryTimestamp(sr.ScannedAt),
			LowCount:      sr.LowCount,
			MediumCount:   sr.MediumCount,
			HighCount:     sr.HighCount,
			CriticalCount: sr.CriticalCount,
		}
		for _, v := range sr.Vulnerabilities {
			scan.Vulnerabilities = append(scan.Vulnerabilities, &platformv1.Vulnerability{
				Id:             v.ID,
				Severity:       platformv1.VulnerabilitySeverity(v.Severity),
				PackageName:    v.PackageName,
				PackageVersion: v.PackageVersion,
				FixedVersion:   v.FixedVersion,
				Description:    v.Description,
				Link:           v.Link,
			})
		}
		detail.ScanResult = scan
	}
	out.Detail = detail
	out.Status = &platformv1.Status{Success: true}
	return nil
}
