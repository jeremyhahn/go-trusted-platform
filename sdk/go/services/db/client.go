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

package db

import (
	"context"
	"io"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Client provides access to database administration operations.
type Client struct {
	grpc platformv1.PlatformDaemonClient
}

// NewClientFromGRPC creates a new database client from a gRPC daemon client.
func NewClientFromGRPC(grpcClient platformv1.PlatformDaemonClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// ListEntityTypes lists all entity types in the database.
func (c *Client) ListEntityTypes(ctx context.Context) (*ListEntityTypesResult, error) {
	resp, err := c.grpc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
	if err != nil {
		return nil, &ErrListEntityTypesFailed{Cause: err}
	}
	return ListEntityTypesResultFromProto(resp), nil
}

// DumpEntityTypes streams entity data from the database.
// The callback is invoked for each entity received from the stream.
// Returns when the stream ends or an error occurs.
func (c *Client) DumpEntityTypes(ctx context.Context, params *DumpParams, callback func(*DumpEntry) error) error {
	stream, err := c.grpc.DumpEntityType(ctx, &platformv1.DumpEntityTypeRequest{
		EntityType: params.EntityType,
		Format:     params.Format,
		Pretty:     params.Pretty,
	})
	if err != nil {
		return &ErrDumpFailed{Cause: err}
	}

	for {
		resp, recvErr := stream.Recv()
		if recvErr == io.EOF {
			return nil
		}
		if recvErr != nil {
			return &ErrDumpStreamFailed{Cause: recvErr}
		}
		if callbackErr := callback(DumpEntryFromProto(resp)); callbackErr != nil {
			return callbackErr
		}
	}
}
