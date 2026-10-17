//go:build integration

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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/registry"
	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// splitImageRef splits "name[:tag]" into repository and tag. A colon before
// the last slash belongs to a registry host port, not to the tag.
func splitImageRef(ref string) (string, string) {
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	return ref, "latest"
}

// sha256Digest returns the OCI digest of content.
func sha256Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// pushEnvelope builds the JSON image envelope the registry push transports
// carry: the manifest, the config blob and each layer's bytes.
func pushEnvelope(opts PushOptions) ([]byte, error) {
	config := opts.Config
	if len(config) == 0 {
		config = []byte("{}")
	}
	img := registry.Image{
		Manifest: &registry.ImageManifest{
			SchemaVersion: 2,
			MediaType:     "application/vnd.oci.image.manifest.v1+json",
			Config: registry.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    sha256Digest(config),
				Size:      int64(len(config)),
			},
			Annotations: opts.Annotations,
		},
		Config: config,
	}
	for _, layer := range opts.Layers {
		digest := sha256Digest(layer.Content)
		size := int64(len(layer.Content))
		img.Layers = append(img.Layers, registry.Layer{Digest: digest, MediaType: layer.MediaType, Size: size, Content: layer.Content})
		img.Manifest.Layers = append(img.Manifest.Layers, registry.Descriptor{
			MediaType: layer.MediaType, Digest: digest, Size: size, Annotations: layer.Annotations,
		})
	}
	return json.Marshal(img)
}

// fromRegistryManifest converts the server's manifest to the suite's.
func fromRegistryManifest(ref string, m *registry.ImageManifest) *ImageManifest {
	if m == nil {
		return nil
	}
	out := &ImageManifest{
		SchemaVersion: m.SchemaVersion,
		MediaType:     m.MediaType,
		Config:        Descriptor{MediaType: m.Config.MediaType, Digest: m.Config.Digest, Size: m.Config.Size, Annotations: m.Config.Annotations},
		Annotations:   m.Annotations,
		Reference:     ref,
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
	}
	for _, l := range m.Layers {
		out.Layers = append(out.Layers, Descriptor{MediaType: l.MediaType, Digest: l.Digest, Size: l.Size, Annotations: l.Annotations})
	}
	return out
}

// fromArtifact converts a gRPC artifact to the suite's manifest view.
func fromArtifact(a *pb.Artifact) ImageManifest {
	m := ImageManifest{
		Reference:   a.GetRepository() + ":" + a.GetTag(),
		Digest:      a.GetDigest(),
		Size:        a.GetSize(),
		Annotations: a.GetAnnotations(),
	}
	if a.GetCreatedAt() != nil {
		m.CreatedAt = a.GetCreatedAt().AsTime()
	}
	if a.GetUpdatedAt() != nil {
		m.UpdatedAt = a.GetUpdatedAt().AsTime()
	}
	return m
}

// Push streams the image envelope to RegistryService.Push.
func (g *GRPCAdapter) Push(ctx context.Context, ref string, opts PushOptions) (*PushResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}
	payload, err := pushEnvelope(opts)
	if err != nil {
		return nil, err
	}
	repository, tag := splitImageRef(ref)

	stream, err := g.client.Push(ctx)
	if err != nil {
		return nil, err
	}
	metadata := regsvc.NewPushMetadata(repository, tag, int64(len(payload)))
	metadata.Annotations = maps.Clone(opts.Annotations)
	if opts.AllowOverwrite {
		metadata = regsvc.WithOverwrite(metadata)
	}
	if err := stream.Send(regsvc.NewPushMetadataRequest(metadata)); err != nil {
		return nil, err
	}
	if err := stream.Send(regsvc.NewPushChunkRequest(payload)); err != nil {
		return nil, err
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return nil, err
	}

	result := &PushResult{
		Reference: ref,
		Digest:    resp.GetArtifact().GetDigest(),
		Size:      resp.GetBytesReceived(),
	}
	if resp.GetTimestamp() != nil {
		result.PushedAt = resp.GetTimestamp().AsTime()
	}
	return result, nil
}

// Pull reads RegistryService.Pull's metadata and data chunks and decodes the
// image envelope they carry.
func (g *GRPCAdapter) Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}
	repository, tag := splitImageRef(ref)
	stream, err := g.client.Pull(ctx, regsvc.NewPullRequest(repository, tag, ""))
	if err != nil {
		return nil, err
	}

	var data bytes.Buffer
	for {
		msg, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return nil, recvErr
		}
		data.Write(msg.GetChunk())
	}

	var img registry.Image
	if err := json.Unmarshal(data.Bytes(), &img); err != nil {
		return nil, ErrInvalidResponse{Operation: "Pull", Err: err}
	}
	result := &PullResult{
		Reference: ref,
		Manifest:  fromRegistryManifest(ref, img.Manifest),
		Config:    img.Config,
		PulledAt:  time.Now().UTC(),
	}
	for _, l := range img.Layers {
		result.Layers = append(result.Layers, LayerData{MediaType: l.MediaType, Content: l.Content})
	}
	return result, nil
}

// List calls RegistryService.List.
func (g *GRPCAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	resp, err := g.client.List(ctx, opts.Repository, int32(opts.Limit), opts.Cursor, opts.SortBy, !opts.SortDesc)
	if err != nil {
		return nil, err
	}
	result := &ListResult{
		TotalCount: int(resp.GetTotal()),
		HasMore:    resp.GetHasMore(),
		NextCursor: resp.GetNextCursor(),
	}
	for _, a := range resp.GetArtifacts() {
		result.Images = append(result.Images, fromArtifact(a))
	}
	return result, nil
}

// Delete calls RegistryService.Delete.
func (g *GRPCAdapter) Delete(ctx context.Context, ref string, opts DeleteOptions) (*DeleteResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}
	repository, tag := splitImageRef(ref)
	resp, err := g.client.Delete(ctx, repository, tag, "", opts.Force)
	if err != nil {
		return nil, err
	}
	result := &DeleteResult{Reference: ref, Digest: resp.GetDigest()}
	if resp.GetTimestamp() != nil {
		result.DeletedAt = resp.GetTimestamp().AsTime()
	}
	return result, nil
}

// Inspect calls RegistryService.Inspect.
func (g *GRPCAdapter) Inspect(ctx context.Context, ref string) (*InspectResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}
	repository, tag := splitImageRef(ref)
	resp, err := g.client.Inspect(ctx, repository, tag, "", false)
	if err != nil {
		return nil, err
	}
	artifact := resp.GetDetail().GetArtifact()
	manifest := fromArtifact(artifact)
	manifest.Reference = ref
	return &InspectResult{
		Reference: ref,
		Manifest:  &manifest,
		TotalSize: artifact.GetSize(),
	}, nil
}

// Status calls RegistryService.Status.
func (g *GRPCAdapter) Status(ctx context.Context) (*StatusResult, error) {
	resp, err := g.client.Status(ctx)
	if err != nil {
		return nil, err
	}
	healthy := regsvc.IsHealthy(resp.GetHealth())
	result := &StatusResult{
		Healthy:    healthy,
		Status:     "degraded",
		Version:    resp.GetVersion(),
		ImageCount: int(resp.GetStorage().GetArtifactCount()),
		TotalSize:  resp.GetStorage().GetUsedBytes(),
	}
	if healthy {
		result.Status = "running"
	}
	if resp.GetStartedAt() != nil && resp.GetTimestamp() != nil {
		result.Uptime = resp.GetTimestamp().AsTime().Sub(resp.GetStartedAt().AsTime())
	}
	return result, nil
}

// Tag has no RegistryService call.
func (g *GRPCAdapter) Tag(ctx context.Context, sourceRef, targetRef string) (*TagResult, error) {
	return nil, noSurface(g.Name(), opTag)
}

// VerifyClient has no RegistryService call.
func (g *GRPCAdapter) VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error) {
	return nil, noSurface(g.Name(), opVerifyClient)
}

// GetSession has no RegistryService call.
func (g *GRPCAdapter) GetSession(ctx context.Context, clientID string) (*SessionResult, error) {
	return nil, noSurface(g.Name(), opGetSession)
}

// InvalidateSession has no RegistryService call.
func (g *GRPCAdapter) InvalidateSession(ctx context.Context, clientID string) error {
	return noSurface(g.Name(), opInvalidateSession)
}

// EncryptImage has no RegistryService call.
func (g *GRPCAdapter) EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error) {
	return nil, noSurface(g.Name(), opEncryptImage)
}

// DecryptImage has no RegistryService call.
func (g *GRPCAdapter) DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error) {
	return nil, noSurface(g.Name(), opDecryptImage)
}
