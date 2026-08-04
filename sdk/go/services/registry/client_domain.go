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
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Domain-typed convenience methods
//
// These methods return domain types instead of proto types, enabling callers
// to avoid importing platformv1 directly.

// StatusDomain retrieves the registry status as domain types.
func (c *Client) StatusDomain(ctx context.Context) (*RegistryStatusResult, error) {
	resp, err := c.grpc.Status(ctx, &platformv1.RegistryStatusRequest{})
	if err != nil {
		return nil, &ErrStatusFailed{Cause: err}
	}
	return StatusResultFromProto(resp), nil
}

// ListDomain lists artifacts as domain types.
func (c *Client) ListDomain(ctx context.Context, repository string, limit int32, cursor, sortBy string, ascending bool) (*ListArtifactsResult, error) {
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
	return ListArtifactsResultFromProto(resp), nil
}

// InspectDomain inspects an artifact and returns domain types.
func (c *Client) InspectDomain(ctx context.Context, repository, reference, digest string, includeSignatures bool) (*ArtifactDetail, error) {
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
	return ArtifactDetailFromProto(resp), nil
}

// DeleteDomain deletes an artifact and returns domain types.
func (c *Client) DeleteDomain(ctx context.Context, repository, reference, digest string, force bool) (*DeleteResult, error) {
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
	return DeleteResultFromProto(resp), nil
}

// Push opens a streaming push client for sending artifact data.
// This returns the raw gRPC stream since push is inherently a streaming operation.
func (c *Client) Push(ctx context.Context) (platformv1.RegistryService_PushClient, error) {
	stream, err := c.grpc.Push(ctx)
	if err != nil {
		return nil, &ErrPushFailed{Cause: err}
	}
	return stream, nil
}

// Pull opens a streaming pull client for receiving artifact data.
// This returns the raw gRPC stream since pull is inherently a streaming operation.
func (c *Client) Pull(ctx context.Context, req *platformv1.PullRequest) (platformv1.RegistryService_PullClient, error) {
	stream, err := c.grpc.Pull(ctx, req)
	if err != nil {
		return nil, &ErrPullFailed{Cause: err}
	}
	return stream, nil
}
