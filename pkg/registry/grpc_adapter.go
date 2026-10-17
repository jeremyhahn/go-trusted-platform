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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// GRPCAdapter wraps a *Registry to satisfy grpcapi.RegistryService.
// It is the bridge between the OCI-style (manifest+layers) Registry
// API and the artifact-stream-based gRPC RegistryService contract.
//
// Wire-format design (Phase 5 first ship):
//
// Every artifact sent over the gRPC stream is the JSON encoding of an
// *Image struct (manifest + config + layers). The grpcapi PushStream
// receives the full JSON in metadata + chunks; PullStream returns the
// JSON as a Reader. This is intentionally NOT OCI-distribution-spec
// compliant — that would require multi-blob streaming with content-
// addressed digests, which is a meaningful follow-up. The simple
// envelope is sufficient for the WebUI and platformctl callers Phase 5
// targets.
type GRPCAdapter struct {
	registry *Registry
	clock    func() time.Time
}

// NewGRPCAdapter returns an adapter ready to be plugged into
// daemon Config.RegistryService.
func NewGRPCAdapter(r *Registry) *GRPCAdapter {
	if r == nil {
		return nil
	}
	return &GRPCAdapter{registry: r, clock: time.Now}
}

// refOf joins Repository + Tag into the colon-delimited reference
// pkg/registry.Registry consumes. Digest-only requests use the digest
// as the reference verbatim so callers can address content by hash.
func refOf(repository, tagOrRef, digest string) string {
	if digest != "" {
		return digest
	}
	if repository == "" {
		return tagOrRef
	}
	if tagOrRef == "" {
		return repository
	}
	return repository + ":" + tagOrRef
}

// Push (non-streaming) decodes the JSON envelope in req.Data and
// hands it to Registry.Push.
func (a *GRPCAdapter) Push(ctx context.Context, req *grpcapi.RegistryPushRequest) (*grpcapi.RegistryPushResponse, error) {
	if req == nil || req.Metadata == nil {
		return nil, grpcapi.ErrMissingPushMetadata{}
	}
	return a.pushImpl(ctx, req.Metadata, req.Data)
}

// PushStream is the streaming variant. The full payload has already
// been concatenated by the gRPC server before this call.
func (a *GRPCAdapter) PushStream(ctx context.Context, metadata *grpcapi.RegistryPushMetadata, reader io.Reader) (*grpcapi.RegistryPushResponse, error) {
	if metadata == nil {
		return nil, grpcapi.ErrMissingPushMetadata{}
	}
	buf, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return a.pushImpl(ctx, metadata, buf)
}

func (a *GRPCAdapter) pushImpl(ctx context.Context, metadata *grpcapi.RegistryPushMetadata, payload []byte) (*grpcapi.RegistryPushResponse, error) {
	if metadata.Repository == "" {
		return nil, grpcapi.ErrMissingRepository{}
	}
	ref := refOf(metadata.Repository, metadata.Tag, "")
	if ref == "" {
		return nil, grpcapi.ErrMissingReference{}
	}
	if len(payload) == 0 {
		return nil, &MessageError{Msg: fmt.Sprintf("registry: empty push payload for %s", ref)}
	}
	var img Image
	if err := json.Unmarshal(payload, &img); err != nil {
		return nil, &WrappedError{Msg: "registry: decode push payload", Err: err}
	}
	if img.Manifest == nil {
		return nil, ErrInvalidManifest{Reference: ref, Reason: "envelope missing manifest"}
	}
	if err := a.registry.Push(ctx, ref, &img, pushOptionsOf(metadata.Annotations)); err != nil {
		if errors.As(err, &ErrImageAlreadyExists{}) {
			return nil, grpcapi.ErrArtifactAlreadyExists{Repository: metadata.Repository, Reference: metadata.Tag}
		}
		var mismatch ErrDigestMismatch
		if errors.As(err, &mismatch) {
			return nil, grpcapi.ErrInvalidArtifactDigest{Digest: mismatch.Expected}
		}
		var invalid ErrInvalidDigest
		if errors.As(err, &invalid) {
			return nil, grpcapi.ErrInvalidArtifactDigest{Digest: invalid.Digest}
		}
		return nil, err
	}
	return &grpcapi.RegistryPushResponse{
		Artifact:      a.manifestToArtifact(metadata.Repository, metadata.Tag, img.Manifest),
		BytesReceived: int64(len(payload)),
		Timestamp:     a.clock().UTC(),
	}, nil
}

// pushOptionsOf turns push-metadata annotations into PushOptions: the
// overwrite, encrypt and sign annotations set AllowOverwrite, Encrypt and
// SignImage, and the key-id annotations name their keys.
func pushOptionsOf(annotations map[string]string) PushOptions {
	return PushOptions{
		Annotations:    annotations,
		AllowOverwrite: annotations[regsvc.AnnotationOverwrite] == "true",
		Encrypt:        annotations[regsvc.AnnotationEncrypt] == "true",
		KeyID:          annotations[regsvc.AnnotationKeyID],
		SignImage:      annotations[regsvc.AnnotationSign] == "true",
		SigningKeyID:   annotations[regsvc.AnnotationSigningKeyID],
	}
}

// Pull returns the JSON envelope of an Image in the response body.
func (a *GRPCAdapter) Pull(ctx context.Context, req *grpcapi.RegistryPullRequest) (*grpcapi.RegistryPullResponse, error) {
	if req == nil {
		return nil, grpcapi.ErrMissingReference{}
	}
	ref := refOf(req.Repository, req.Reference, req.Digest)
	if ref == "" {
		return nil, grpcapi.ErrMissingReference{}
	}
	img, err := a.registry.Pull(ctx, ref, PullOptions{})
	if err != nil {
		return nil, a.mapPullError(req.Repository, req.Reference, err)
	}
	data, err := json.Marshal(img)
	if err != nil {
		return nil, err
	}
	return &grpcapi.RegistryPullResponse{
		Artifact:  a.manifestToArtifact(req.Repository, req.Reference, img.Manifest),
		TotalSize: int64(len(data)),
		Data:      data,
	}, nil
}

// PullStream returns the JSON envelope wrapped in a Reader for the
// gRPC server to chunk over the wire.
func (a *GRPCAdapter) PullStream(ctx context.Context, req *grpcapi.RegistryPullRequest) (*grpcapi.RegistryPullStreamResponse, error) {
	resp, err := a.Pull(ctx, req)
	if err != nil {
		return nil, err
	}
	return &grpcapi.RegistryPullStreamResponse{
		Artifact:  resp.Artifact,
		TotalSize: resp.TotalSize,
		Reader:    bytes.NewReader(resp.Data),
	}, nil
}

// List delegates to Registry.List, then projects the manifests into
// the RegistryArtifact shape consumed by the gRPC service.
func (a *GRPCAdapter) List(ctx context.Context, req *grpcapi.RegistryListRequest) (*grpcapi.RegistryListResponse, error) {
	opts := RegistryListOptions{}
	if req != nil {
		opts.Repository = req.Repository
		opts.Limit = int(req.Limit)
		opts.Offset = int(req.Offset)
	}
	manifests, err := a.registry.List(ctx, opts)
	if err != nil {
		return nil, err
	}
	artifacts := make([]*grpcapi.RegistryArtifact, 0, len(manifests))
	for _, m := range manifests {
		repo, tag := splitRef(m.Reference)
		// Skip the digest-keyed copies the OCI /v2/ PutManifest path
		// stores alongside each tag. They have the form
		// "<name>:sha256:<64-hex>" — splitRef returns
		// (name:sha256, <hex>) for those. Without this filter the
		// WebUI shows two rows per pushed image.
		if endsWithSha256Sentinel(repo) && isHex64(tag) {
			continue
		}
		artifacts = append(artifacts, a.manifestToArtifact(repo, tag, m))
	}
	return &grpcapi.RegistryListResponse{
		Artifacts: artifacts,
		Total:     int32(len(artifacts)),
		HasMore:   false,
	}, nil
}

// Inspect returns full detail for one artifact.
func (a *GRPCAdapter) Inspect(ctx context.Context, req *grpcapi.RegistryInspectRequest) (*grpcapi.RegistryInspectResponse, error) {
	if req == nil {
		return nil, grpcapi.ErrMissingReference{}
	}
	ref := refOf(req.Repository, req.Reference, req.Digest)
	if ref == "" {
		return nil, grpcapi.ErrMissingReference{}
	}
	img, err := a.registry.Pull(ctx, ref, PullOptions{})
	if err != nil {
		return nil, a.mapPullError(req.Repository, req.Reference, err)
	}
	art := a.manifestToArtifact(req.Repository, req.Reference, img.Manifest)
	detail := &grpcapi.RegistryArtifactDetail{
		Artifact: art,
		Tags:     []string{req.Reference},
	}
	if req.IncludeSignatures {
		sigs, err := manifestSignatures(img.Manifest)
		if err != nil {
			return nil, err
		}
		detail.Signatures = sigs
	}
	return &grpcapi.RegistryInspectResponse{Detail: detail}, nil
}

// manifestSignatures reports the signature a manifest carries; Pull has
// already verified it. An unsigned manifest has none. The registry signs on
// the pusher's behalf, so the signer is the signing key.
func manifestSignatures(m *ImageManifest) ([]*grpcapi.RegistryArtifactSignature, error) {
	if !isSigned(m) {
		return nil, nil
	}
	keyID := m.Annotations[ManifestAnnotationSigningKeyID]
	sig, err := base64.StdEncoding.DecodeString(m.Annotations[ManifestAnnotationSignature])
	if err != nil {
		return nil, ErrSignatureInvalid{Reference: m.Reference, KeyID: keyID, Reason: "signature is not base64"}
	}
	return []*grpcapi.RegistryArtifactSignature{{
		KeyID:     keyID,
		Algorithm: m.Annotations[ManifestAnnotationSignatureAlgorithm],
		Signature: sig,
		SignedAt:  m.UpdatedAt,
		Signer:    keyID,
	}}, nil
}

// Delete unbinds the reference from its manifest. Layer GC is a
// follow-up (Registry.Delete intentionally leaves orphan blobs).
func (a *GRPCAdapter) Delete(ctx context.Context, req *grpcapi.RegistryDeleteRequest) (*grpcapi.RegistryDeleteResponse, error) {
	if req == nil {
		return nil, grpcapi.ErrMissingReference{}
	}
	ref := refOf(req.Repository, req.Reference, req.Digest)
	if ref == "" {
		return nil, grpcapi.ErrMissingReference{}
	}
	if err := a.registry.Delete(ctx, ref); err != nil {
		return nil, err
	}
	return &grpcapi.RegistryDeleteResponse{
		Digest:    req.Digest,
		Timestamp: a.clock().UTC(),
	}, nil
}

// Status reports a synthetic health view. A real-storage probe lands
// alongside the cluster-wide forwarder.
func (a *GRPCAdapter) Status(ctx context.Context) (*grpcapi.RegistryStatusResponse, error) {
	manifests, err := a.registry.List(ctx, RegistryListOptions{Limit: 0})
	if err != nil {
		return &grpcapi.RegistryStatusResponse{
			Health:    grpcapi.RegistryHealthStatusUnhealthy,
			Version:   a.registry.version,
			Timestamp: a.clock().UTC(),
			StartedAt: a.registry.startedAt.UTC(),
			Components: []*grpcapi.RegistryComponentHealth{{
				Name:    "storage",
				Status:  grpcapi.RegistryHealthStatusUnhealthy,
				Message: err.Error(),
			}},
		}, nil
	}
	return &grpcapi.RegistryStatusResponse{
		Health: grpcapi.RegistryHealthStatusHealthy,
		Storage: &grpcapi.RegistryStorageStats{
			ArtifactCount: int64(len(manifests)),
		},
		Version:   a.registry.version,
		Timestamp: a.clock().UTC(),
		StartedAt: a.registry.startedAt.UTC(),
	}, nil
}

// manifestToArtifact projects an ImageManifest into the artifact
// shape the gRPC contract speaks. Sizes are summed from layers since
// the manifest doesn't carry a top-level size today.
func (a *GRPCAdapter) manifestToArtifact(repository, tag string, m *ImageManifest) *grpcapi.RegistryArtifact {
	if m == nil {
		return &grpcapi.RegistryArtifact{Repository: repository, Tag: tag}
	}
	var size int64
	layers := make([]*grpcapi.RegistryArtifactLayer, 0, len(m.Layers))
	for _, l := range m.Layers {
		size += l.Size
		layers = append(layers, &grpcapi.RegistryArtifactLayer{
			Digest:      l.Digest,
			Size:        l.Size,
			MediaType:   l.MediaType,
			Annotations: l.Annotations,
		})
	}
	return &grpcapi.RegistryArtifact{
		Repository: repository,
		Tag:        tag,
		Type:       grpcapi.ArtifactTypeContainerImage,
		State:      grpcapi.ArtifactStateAvailable,
		Size:       size,
		Manifest: &grpcapi.RegistryArtifactManifest{
			MediaType:    m.MediaType,
			ConfigDigest: m.Config.Digest,
			Layers:       layers,
		},
		Annotations: m.Annotations,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
		PushedAt:    m.CreatedAt,
	}
}

// mapPullError converts public Registry errors into the artifact-
// shaped gRPC errors so callers see a consistent surface across
// transports.
func (a *GRPCAdapter) mapPullError(repository, reference string, err error) error {
	var notFound ErrImageNotFound
	if errors.As(err, &notFound) {
		return grpcapi.ErrArtifactNotFound{Repository: repository, Reference: reference}
	}
	return err
}

// splitRef parses "repo:tag" back into its components. Used by List
// to populate per-row repository + tag for callers that don't know
// the encoding scheme.
func splitRef(ref string) (string, string) {
	for i := len(ref) - 1; i >= 0; i-- {
		if ref[i] == ':' {
			return ref[:i], ref[i+1:]
		}
	}
	return ref, ""
}

// endsWithSha256Sentinel reports whether ref ends with ":sha256",
// which is how the OCI dist PutManifest path encodes digest-keyed
// duplicate references. Used to filter those out of the user-facing
// list so each pushed image surfaces as a single row.
func endsWithSha256Sentinel(ref string) bool {
	const sentinel = ":sha256"
	if len(ref) < len(sentinel) {
		return false
	}
	return ref[len(ref)-len(sentinel):] == sentinel
}
