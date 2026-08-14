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

// Package ntp provides a client for the platform's time-synchronization
// service. The client speaks the platform.v1 NTPService surface over any
// transport.Adapter (gRPC, Unix, REST, QUIC, MCP, embedded), so `platformctl
// ntp ...` behaves identically on every protocol.
package ntp

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to time-synchronization operations.
type Client struct {
	grpc platformv1.NTPServiceClient
}

// NewClient creates a new time-synchronization client from a transport
// adapter.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{grpc: platformv1.NewNTPServiceClient(grpcConn)}, nil
}

// NewClientFromGRPC creates a client from an existing gRPC client, which is
// how the CLI reuses the protocol selected by the global --protocol flag.
func NewClientFromGRPC(grpcClient platformv1.NTPServiceClient) *Client {
	return &Client{grpc: grpcClient}
}

// Status returns the node's current synchronization state.
func (c *Client) Status(ctx context.Context) (*platformv1.NTPStatus, error) {
	resp, err := c.grpc.GetStatus(ctx, &platformv1.GetNTPStatusRequest{})
	if err != nil {
		return nil, &ErrGetStatusFailed{Cause: err}
	}
	return resp.GetStatus(), nil
}

// Sources returns every configured time source and its live state.
func (c *Client) Sources(ctx context.Context) ([]*platformv1.NTPSource, error) {
	resp, err := c.grpc.ListSources(ctx, &platformv1.ListNTPSourcesRequest{})
	if err != nil {
		return nil, &ErrListSourcesFailed{Cause: err}
	}
	return resp.GetSources(), nil
}

// Step forces an immediate clock correction and returns the resulting state.
// It fails when no source is reachable.
func (c *Client) Step(ctx context.Context) (*platformv1.NTPStatus, error) {
	resp, err := c.grpc.Step(ctx, &platformv1.StepNTPClockRequest{})
	if err != nil {
		return nil, &ErrStepFailed{Cause: err}
	}
	return resp.GetStatus(), nil
}
