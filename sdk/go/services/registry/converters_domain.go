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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// StatusResultFromProto converts a proto RegistryStatusResponse to a domain RegistryStatusResult.
func StatusResultFromProto(resp *platformv1.RegistryStatusResponse) *RegistryStatusResult {
	if resp == nil {
		return nil
	}
	result := &RegistryStatusResult{
		Health:  HealthStatusFromProto(resp.GetHealth()),
		Version: resp.GetVersion(),
	}
	if resp.GetStartedAt() != nil {
		result.StartedAt = resp.GetStartedAt().GetSeconds()
	}
	if resp.GetTimestamp() != nil {
		result.Timestamp = resp.GetTimestamp().GetSeconds()
	}
	if storage := resp.GetStorage(); storage != nil {
		result.Storage = &StorageStats{
			UsedBytes:       storage.GetUsedBytes(),
			TotalBytes:      storage.GetTotalBytes(),
			ArtifactCount:   storage.GetArtifactCount(),
			LayerCount:      storage.GetLayerCount(),
			RepositoryCount: storage.GetRepositoryCount(),
		}
	}
	for _, c := range resp.GetComponents() {
		result.Components = append(result.Components, &ComponentStatus{
			Name:   c.GetName(),
			Status: HealthStatusFromProto(c.GetStatus()),
		})
	}
	return result
}

// ArtifactFromProto converts a proto Artifact to a domain Artifact.
func ArtifactFromProto(a *platformv1.Artifact) *Artifact {
	if a == nil {
		return nil
	}
	art := &Artifact{
		Repository:   a.GetRepository(),
		Tag:          a.GetTag(),
		Digest:       a.GetDigest(),
		Size:         a.GetSize(),
		OS:           a.GetOs(),
		Architecture: a.GetArchitecture(),
		Annotations:  a.GetAnnotations(),
	}
	if a.GetCreatedAt() != nil {
		art.CreatedAt = a.GetCreatedAt().GetSeconds()
	}
	if a.GetPushedAt() != nil {
		art.PushedAt = a.GetPushedAt().GetSeconds()
	}
	if a.GetManifest() != nil {
		art.LayerCount = len(a.GetManifest().GetLayers())
	}
	return art
}

// ListArtifactsResultFromProto converts a proto ListArtifactsResponse to a domain result.
func ListArtifactsResultFromProto(resp *platformv1.ListArtifactsResponse) *ListArtifactsResult {
	if resp == nil {
		return nil
	}
	result := &ListArtifactsResult{
		Artifacts:  make([]*Artifact, 0, len(resp.GetArtifacts())),
		Total:      resp.GetTotal(),
		HasMore:    resp.GetHasMore(),
		NextCursor: resp.GetNextCursor(),
	}
	for _, a := range resp.GetArtifacts() {
		result.Artifacts = append(result.Artifacts, ArtifactFromProto(a))
	}
	return result
}

// ArtifactDetailFromProto converts a proto InspectArtifactResponse to a domain ArtifactDetail.
func ArtifactDetailFromProto(resp *platformv1.InspectArtifactResponse) *ArtifactDetail {
	if resp == nil {
		return nil
	}
	detail := &ArtifactDetail{}
	d := resp.GetDetail()
	if d == nil {
		return detail
	}
	if d.GetArtifact() != nil {
		detail.Artifact = ArtifactFromProto(d.GetArtifact())
	}
	if manifest := d.GetArtifact().GetManifest(); manifest != nil {
		mi := &ManifestInfo{
			MediaType:    manifest.GetMediaType(),
			ConfigDigest: manifest.GetConfigDigest(),
			Size:         manifest.GetSize(),
		}
		for _, layer := range manifest.GetLayers() {
			mi.Layers = append(mi.Layers, &LayerInfo{
				Digest:    layer.GetDigest(),
				Size:      layer.GetSize(),
				MediaType: layer.GetMediaType(),
			})
		}
		detail.Manifest = mi
	}
	for _, sig := range d.GetSignatures() {
		sd := &SignatureDetail{
			Signer:    sig.GetSigner(),
			KeyID:     sig.GetKeyId(),
			Algorithm: sig.GetAlgorithm(),
		}
		if sig.GetSignedAt() != nil {
			sd.SignedAt = sig.GetSignedAt().GetSeconds()
		}
		detail.Signatures = append(detail.Signatures, sd)
	}
	return detail
}

// DeleteResultFromProto converts a proto DeleteArtifactResponse to a domain DeleteResult.
func DeleteResultFromProto(resp *platformv1.DeleteArtifactResponse) *DeleteResult {
	if resp == nil {
		return nil
	}
	result := &DeleteResult{
		Digest:     resp.GetDigest(),
		BytesFreed: resp.GetBytesFreed(),
	}
	if resp.GetStatus() == nil || resp.GetStatus().GetSuccess() {
		result.Success = true
	} else {
		result.Message = resp.GetStatus().GetMessage()
	}
	if resp.GetTimestamp() != nil {
		result.Timestamp = resp.GetTimestamp().GetSeconds()
	}
	return result
}
