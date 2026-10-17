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

// Package registry provides a client for registry service operations.
package registry

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to registry service operations.
type Client struct {
	grpc platformv1.RegistryServiceClient
}

// NewClient creates a new registry service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewRegistryServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new registry service client from a gRPC client.
func NewClientFromGRPC(grpcClient platformv1.RegistryServiceClient) *Client {
	return &Client{grpc: grpcClient}
}

// GRPCClient returns the underlying gRPC client for streaming operations.
func (c *Client) GRPCClient() platformv1.RegistryServiceClient {
	return c.grpc
}

// Status retrieves the registry status.
func (c *Client) Status(ctx context.Context) (*platformv1.RegistryStatusResponse, error) {
	resp, err := c.grpc.Status(ctx, &platformv1.RegistryStatusRequest{})
	if err != nil {
		return nil, &ErrStatusFailed{Cause: err}
	}
	return resp, nil
}

// List lists artifacts in the registry.
func (c *Client) List(ctx context.Context, repository string, limit int32, cursor, sortBy string, ascending bool) (*platformv1.ListArtifactsResponse, error) {
	resp, err := c.grpc.List(ctx, &platformv1.ListArtifactsRequest{
		Repository: repository,
		Limit:      limit,
		Cursor:     cursor,
		SortBy:     sortBy,
		Ascending:  ascending,
	})
	if err != nil {
		return nil, &ErrListFailed{Cause: err}
	}
	return resp, nil
}

// Inspect inspects an artifact.
func (c *Client) Inspect(ctx context.Context, repository, reference, digest string, includeSignatures bool) (*platformv1.InspectArtifactResponse, error) {
	req := &platformv1.InspectArtifactRequest{
		Repository:        repository,
		Reference:         reference,
		Digest:            digest,
		IncludeSignatures: includeSignatures,
	}
	resp, err := c.grpc.Inspect(ctx, req)
	if err != nil {
		return nil, &ErrInspectFailed{Reference: reference, Cause: err}
	}
	return resp, nil
}

// Delete deletes an artifact.
func (c *Client) Delete(ctx context.Context, repository, reference, digest string, force bool) (*platformv1.DeleteArtifactResponse, error) {
	req := &platformv1.DeleteArtifactRequest{
		Repository: repository,
		Reference:  reference,
		Digest:     digest,
		Force:      force,
	}
	resp, err := c.grpc.Delete(ctx, req)
	if err != nil {
		return nil, &ErrDeleteFailed{Reference: reference, Cause: err}
	}
	return resp, nil
}

// AnnotationOverwrite is the push-metadata annotation that asks the
// registry to replace an artifact already stored under the same tag. Its
// value is "true"; any other value, or its absence, refuses the overwrite.
const AnnotationOverwrite = "overwrite"

// WithOverwrite marks metadata so the push replaces an existing tag.
func WithOverwrite(metadata *platformv1.PushMetadata) *platformv1.PushMetadata {
	if metadata.Annotations == nil {
		metadata.Annotations = make(map[string]string, 1)
	}
	metadata.Annotations[AnnotationOverwrite] = "true"
	return metadata
}

// Push-metadata annotations for the rest of the push options. A boolean
// option is on only when its value is "true"; the key IDs travel next to
// them.
const (
	// AnnotationEncrypt asks the registry to encrypt every layer.
	AnnotationEncrypt = "encrypt"
	// AnnotationKeyID names the key the layers are encrypted under.
	AnnotationKeyID = "key-id"
	// AnnotationSign asks the registry to sign the manifest.
	AnnotationSign = "sign"
	// AnnotationSigningKeyID names the key the manifest is signed with.
	AnnotationSigningKeyID = "signing-key-id"
)

// Manifest annotations the registry sets on what it stored. A push
// response carries them in its artifact, so a client reports what the
// registry did rather than what it asked for.
const (
	// ManifestAnnotationEncrypted is "true" on a manifest whose layers
	// are encrypted.
	ManifestAnnotationEncrypted = "org.letstrust.registry.encrypted"
	// ManifestAnnotationKeyID names the key the layers are encrypted under.
	ManifestAnnotationKeyID = "org.letstrust.registry.key-id"
	// ManifestAnnotationSignature carries the signature of a signed
	// manifest. The registry verifies it on every pull, so a pulled artifact
	// that carries it has a signature that verified.
	ManifestAnnotationSignature = "org.letstrust.registry.signature"
)

// IsSigned reports whether a pulled artifact's manifest annotations carry a
// signature.
func IsSigned(annotations map[string]string) bool {
	return annotations[ManifestAnnotationSignature] != ""
}

// WithEncryption marks metadata so the registry encrypts every layer under
// keyID.
func WithEncryption(metadata *platformv1.PushMetadata, keyID string) *platformv1.PushMetadata {
	if metadata.Annotations == nil {
		metadata.Annotations = make(map[string]string, 2)
	}
	metadata.Annotations[AnnotationEncrypt] = "true"
	if keyID != "" {
		metadata.Annotations[AnnotationKeyID] = keyID
	}
	return metadata
}

// WithSigning marks metadata so the registry signs the manifest. An empty
// signingKeyID leaves the choice of key to the registry.
func WithSigning(metadata *platformv1.PushMetadata, signingKeyID string) *platformv1.PushMetadata {
	if metadata.Annotations == nil {
		metadata.Annotations = make(map[string]string, 2)
	}
	metadata.Annotations[AnnotationSign] = "true"
	if signingKeyID != "" {
		metadata.Annotations[AnnotationSigningKeyID] = signingKeyID
	}
	return metadata
}

// NewPushMetadata creates a PushMetadata proto for streaming push operations.
func NewPushMetadata(repository, tag string, totalSize int64) *platformv1.PushMetadata {
	return &platformv1.PushMetadata{
		Repository: repository,
		Tag:        tag,
		Type:       platformv1.ArtifactType_ARTIFACT_TYPE_CONTAINER_IMAGE,
		TotalSize:  totalSize,
	}
}

// NewPushMetadataRequest creates a PushRequest containing metadata.
func NewPushMetadataRequest(metadata *platformv1.PushMetadata) *platformv1.PushRequest {
	return &platformv1.PushRequest{
		Data: &platformv1.PushRequest_Metadata{
			Metadata: metadata,
		},
	}
}

// NewPushChunkRequest creates a PushRequest containing a data chunk.
func NewPushChunkRequest(chunk []byte) *platformv1.PushRequest {
	return &platformv1.PushRequest{
		Data: &platformv1.PushRequest_Chunk{
			Chunk: chunk,
		},
	}
}

// NewPullRequest creates a PullRequest.
func NewPullRequest(repository, reference, digest string) *platformv1.PullRequest {
	return &platformv1.PullRequest{
		Repository: repository,
		Reference:  reference,
		Digest:     digest,
	}
}
