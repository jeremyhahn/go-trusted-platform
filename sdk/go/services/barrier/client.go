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

package barrier

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to barrier storage service operations.
type Client struct {
	grpc platformv1.BarrierServiceClient
}

// NewClient creates a new barrier service client from a transport adapter.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewBarrierServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new barrier service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.BarrierServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// Init initializes the barrier with the given parameters.
func (c *Client) Init(ctx context.Context, params *InitParams) (*InitResult, error) {
	resp, err := c.grpc.Init(ctx, &platformv1.BarrierInitRequest{
		Secret:    params.Secret,
		Threshold: params.Threshold,
		Shares:    params.Shares,
	})
	if err != nil {
		return nil, &ErrInitFailed{Cause: err}
	}
	return InitResultFromProto(resp), nil
}

// Status retrieves the current barrier status.
func (c *Client) Status(ctx context.Context) (*StatusResult, error) {
	resp, err := c.grpc.GetStatus(ctx, &platformv1.BarrierStatusRequest{})
	if err != nil {
		return nil, &ErrStatusFailed{Cause: err}
	}
	return StatusResultFromProto(resp), nil
}

// Unseal attempts to unseal the barrier with the given secret or share.
func (c *Client) Unseal(ctx context.Context, params *UnsealParams) (*UnsealResult, error) {
	resp, err := c.grpc.Unseal(ctx, &platformv1.BarrierUnsealRequest{
		Secret: params.Secret,
	})
	if err != nil {
		return nil, &ErrUnsealFailed{Cause: err}
	}
	return UnsealResultFromProto(resp), nil
}

// Seal seals the barrier.
func (c *Client) Seal(ctx context.Context) (*SealResult, error) {
	resp, err := c.grpc.Seal(ctx, &platformv1.BarrierSealRequest{})
	if err != nil {
		return nil, &ErrSealFailed{Cause: err}
	}
	return SealResultFromProto(resp), nil
}

// Rekey generates new unseal keys for the barrier.
func (c *Client) Rekey(ctx context.Context, params *RekeyParams) (*RekeyResult, error) {
	resp, err := c.grpc.Rekey(ctx, &platformv1.BarrierRekeyRequest{
		Threshold: params.Threshold,
		Shares:    params.Shares,
	})
	if err != nil {
		return nil, &ErrRekeyFailed{Cause: err}
	}
	return RekeyResultFromProto(resp), nil
}
