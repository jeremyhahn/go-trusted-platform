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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
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
	// startedAt is when the adapter was built; Status measures uptime from it.
	startedAt time.Time
}

// Status component and detail names the registry reports, so clients can
// read the storage backend from the storage component's details.
const (
	StatusComponentStorage = "storage"
	StatusDetailBackend    = "backend"
	StorageBackendQuicBaaS = "quicbaas"
)

// buildVersion is the module version the daemon was built from, or "dev"
// for a build without one.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "dev"
	}
	return info.Main.Version
}

// NewGRPCAdapter returns an adapter ready to be plugged into
// daemon Config.RegistryService.
func NewGRPCAdapter(r *Registry) *GRPCAdapter {
	if r == nil {
		return nil
	}
	return &GRPCAdapter{registry: r, clock: time.Now, startedAt: time.Now().UTC()}
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
	// Decode the config before storing anything, so a malformed config is
	// refused rather than persisted.
	config, err := decodeImageConfig(ref, img.Config)
	if err != nil {
		return nil, err
	}
	if err := a.registry.Push(ctx, ref, &img, pushOptionsOf(metadata.Annotations)); err != nil {
		if errors.As(err, &ErrImageAlreadyExists{}) {
			return nil, grpcapi.ErrArtifactAlreadyExists{Repository: metadata.Repository, Reference: metadata.Tag}
		}
		return nil, a.mapRegistryError(metadata.Repository, metadata.Tag, err)
	}
	artifact, err := a.manifestToArtifact(metadata.Repository, metadata.Tag, img.Manifest)
	if err != nil {
		return nil, err
	}
	applyImageConfig(artifact, config)
	return &grpcapi.RegistryPushResponse{
		Artifact:      artifact,
		BytesReceived: int64(len(payload)),
		Timestamp:     a.clock().UTC(),
	}, nil
}

// pushOptionsOf turns push-metadata annotations into PushOptions; the
// overwrite annotation sets AllowOverwrite.
// Push request annotations a transport sets on the push metadata to ask
// for push options. They travel the way overwrite does, with no proto
// field; PushAnnotationEncrypt is the key the REST handler already sends.
const (
	// PushAnnotationEncrypt is "true" to encrypt the layers on push.
	PushAnnotationEncrypt = "encrypt"
	// PushAnnotationKeyID names the encryption key; empty uses the
	// registry default key.
	PushAnnotationKeyID = "encrypt-key-id"
	// PushAnnotationSign is "true" to ask for the manifest to be signed.
	// A registry built without a signer refuses such a push with
	// ErrSigningNotConfigured.
	PushAnnotationSign = "sign"
	// PushAnnotationSigningKeyID names the signing key; empty uses the
	// registry default signing key.
	PushAnnotationSigningKeyID = "signing-key-id"
)

func pushOptionsOf(annotations map[string]string) PushOptions {
	return PushOptions{
		Annotations:    annotations,
		AllowOverwrite: annotations[regsvc.AnnotationOverwrite] == "true",
		Encrypt:        annotations[PushAnnotationEncrypt] == "true",
		KeyID:          annotations[PushAnnotationKeyID],
		SignImage:      annotations[PushAnnotationSign] == "true",
		SigningKeyID:   annotations[PushAnnotationSigningKeyID],
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
		return nil, a.mapRegistryError(req.Repository, req.Reference, err)
	}
	data, err := json.Marshal(img)
	if err != nil {
		return nil, err
	}
	artifact, err := a.manifestToArtifact(req.Repository, req.Reference, img.Manifest)
	if err != nil {
		return nil, err
	}
	return &grpcapi.RegistryPullResponse{
		Artifact:  artifact,
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
		artifact, err := a.manifestToArtifact(repo, tag, m)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, artifact)
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
		return nil, a.mapRegistryError(req.Repository, req.Reference, err)
	}
	art, err := a.manifestToArtifact(req.Repository, req.Reference, img.Manifest)
	if err != nil {
		return nil, err
	}
	config, err := decodeImageConfig(ref, img.Config)
	if err != nil {
		return nil, err
	}
	applyImageConfig(art, config)
	return &grpcapi.RegistryInspectResponse{
		Detail: &grpcapi.RegistryArtifactDetail{
			Artifact: art,
			Tags:     []string{req.Reference},
		},
	}, nil
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
		return nil, a.mapRegistryError(req.Repository, req.Reference, err)
	}
	return &grpcapi.RegistryDeleteResponse{
		Digest:    req.Digest,
		Timestamp: a.clock().UTC(),
	}, nil
}

// Status reports a synthetic health view. A real-storage probe lands
// alongside the cluster-wide forwarder.
func (a *GRPCAdapter) Status(ctx context.Context) (*grpcapi.RegistryStatusResponse, error) {
	resp := &grpcapi.RegistryStatusResponse{
		Health:    grpcapi.RegistryHealthStatusHealthy,
		Version:   buildVersion(),
		StartedAt: a.startedAt,
		Timestamp: a.clock().UTC(),
	}
	storage := &grpcapi.RegistryComponentHealth{
		Name:      StatusComponentStorage,
		Status:    grpcapi.RegistryHealthStatusHealthy,
		LastCheck: resp.Timestamp,
		Details:   map[string]string{StatusDetailBackend: StorageBackendQuicBaaS},
	}
	resp.Components = []*grpcapi.RegistryComponentHealth{storage}

	manifests, err := a.registry.List(ctx, RegistryListOptions{Limit: 0})
	if err != nil {
		resp.Health = grpcapi.RegistryHealthStatusUnhealthy
		storage.Status = grpcapi.RegistryHealthStatusUnhealthy
		storage.Message = err.Error()
		return resp, nil
	}
	resp.Storage = &grpcapi.RegistryStorageStats{ArtifactCount: int64(len(manifests))}
	return resp, nil
}

// manifestToArtifact projects an ImageManifest into the artifact
// shape the gRPC contract speaks. Sizes are summed from layers since
// the manifest doesn't carry a top-level size today. The digest is the
// sha256 of the manifest the OCI distribution endpoint serves, so it
// equals that endpoint's Docker-Content-Digest.
func (a *GRPCAdapter) manifestToArtifact(repository, tag string, m *ImageManifest) (*grpcapi.RegistryArtifact, error) {
	if m == nil {
		return &grpcapi.RegistryArtifact{Repository: repository, Tag: tag}, nil
	}
	body, err := encodeOCIManifest(m)
	if err != nil {
		return nil, err
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
		Digest:     sha256Digest(body),
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
	}, nil
}

// imageConfigFields are the OCI image config properties (image-spec
// config.md) that the registry reports on an artifact.
type imageConfigFields struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Author       string `json:"author,omitempty"`
}

// decodeImageConfig reads the reported properties from an image config
// blob. An image without a config reports none; a config that is not
// JSON is refused.
func decodeImageConfig(ref string, config []byte) (imageConfigFields, error) {
	var fields imageConfigFields
	if len(config) == 0 {
		return fields, nil
	}
	if err := json.Unmarshal(config, &fields); err != nil {
		return fields, ErrInvalidManifest{Reference: ref, Reason: "image config is not valid JSON"}
	}
	return fields, nil
}

// applyImageConfig sets the artifact's OS, architecture and author from
// the image config fields.
func applyImageConfig(art *grpcapi.RegistryArtifact, fields imageConfigFields) {
	art.OS = fields.OS
	art.Architecture = fields.Architecture
	art.Author = fields.Author
}

// mapRegistryError converts public Registry errors into the artifact-
// shaped gRPC errors so callers see a consistent surface across
// transports.
func (a *GRPCAdapter) mapRegistryError(repository, reference string, err error) error {
	var notFound ErrImageNotFound
	if errors.As(err, &notFound) {
		return grpcapi.ErrArtifactNotFound{Repository: repository, Reference: reference}
	}
	var invalidRef ErrInvalidImageRef
	if errors.As(err, &invalidRef) {
		return grpcapi.ErrInvalidArtifactReference{Reference: invalidRef.Reference, Reason: invalidRef.Reason}
	}
	if errors.As(err, &ErrSigningNotConfigured{}) || errors.As(err, &ErrEncryptionNotConfigured{}) {
		return grpcapi.ErrRegistryNotConfigured{Reason: err.Error()}
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
