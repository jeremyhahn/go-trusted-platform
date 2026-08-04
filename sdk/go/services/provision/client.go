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

// Package provision provides a client for the config-delivery provisioning
// service (platform.v1 ConfigDeliveryService): nonce issuance, pre-enrollment
// config fetch, remote Secure Boot digest signing, and provisioning session
// management. It mirrors the sdk/go/services/kms package structure and works
// over every SDK transport (gRPC, Unix, REST, QUIC, MCP, embedded) via the
// transport-agnostic grpc.ClientConnInterface.
package provision

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to config-delivery provisioning operations.
type Client struct {
	grpc platformv1.ConfigDeliveryServiceClient
}

// NewClient creates a new provisioning service client from a transport adapter.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewConfigDeliveryServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new provisioning service client from a gRPC
// client. This is useful when you already have a gRPC client from the
// platform.Client (e.g. client.ConfigDelivery()).
func NewClientFromGRPC(grpcClient platformv1.ConfigDeliveryServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// GetNonce issues a single-use anti-replay nonce for authenticating a
// subsequent FetchConfig or SignDigest request.
func (c *Client) GetNonce(ctx context.Context) (string, error) {
	resp, err := c.grpc.GetNonce(ctx, &platformv1.GetNonceRequest{})
	if err != nil {
		return "", &ErrGetNonceFailed{Cause: err}
	}
	return resp.GetNonce(), nil
}

// FetchConfig authenticates a device (EAB HMAC + nonce, optional EK
// certificate) and resolves its platform configuration. The response carries
// either a delivered config or a pending interactive provisioning session.
func (c *Client) FetchConfig(ctx context.Context, req *platformv1.FetchConfigRequest) (*platformv1.FetchConfigResponse, error) {
	if req == nil {
		return nil, &ErrNilRequest{Op: "FetchConfig"}
	}
	resp, err := c.grpc.FetchConfig(ctx, req)
	if err != nil {
		return nil, &ErrFetchConfigFailed{Cause: err}
	}
	return resp, nil
}

// SignDigest signs a UKI or kernel-module digest with the control-plane
// Secure Boot DB key. The private key never leaves the control plane.
func (c *Client) SignDigest(ctx context.Context, req *platformv1.SignDigestRequest) (*platformv1.SignDigestResponse, error) {
	if req == nil {
		return nil, &ErrNilRequest{Op: "SignDigest"}
	}
	resp, err := c.grpc.SignDigest(ctx, req)
	if err != nil {
		return nil, &ErrSignDigestFailed{Cause: err}
	}
	return resp, nil
}

// PollSession checks whether a pending provisioning session has been
// fulfilled, returning either the delivered config or a pending status.
func (c *Client) PollSession(ctx context.Context, sessionID string) (*platformv1.PollSessionResponse, error) {
	if sessionID == "" {
		return nil, &ErrSessionIDRequired{}
	}
	resp, err := c.grpc.PollSession(ctx, &platformv1.PollSessionRequest{
		SessionId: sessionID,
	})
	if err != nil {
		return nil, &ErrPollSessionFailed{SessionID: sessionID, Cause: err}
	}
	return resp, nil
}

// FulfillSession links a device profile to a pending provisioning session so
// the polling device receives its configuration.
func (c *Client) FulfillSession(ctx context.Context, sessionID string, profileID uint64) (*platformv1.FulfillSessionResponse, error) {
	if sessionID == "" {
		return nil, &ErrSessionIDRequired{}
	}
	if profileID == 0 {
		return nil, &ErrProfileIDRequired{}
	}
	resp, err := c.grpc.FulfillSession(ctx, &platformv1.FulfillSessionRequest{
		SessionId: sessionID,
		ProfileId: profileID,
	})
	if err != nil {
		return nil, &ErrFulfillSessionFailed{SessionID: sessionID, Cause: err}
	}
	return resp, nil
}

// ListSessions returns all active (non-expired) provisioning sessions
// awaiting operator fulfillment.
func (c *Client) ListSessions(ctx context.Context) ([]*platformv1.ProvisioningSession, error) {
	resp, err := c.grpc.ListSessions(ctx, &platformv1.ListSessionsRequest{})
	if err != nil {
		return nil, &ErrListSessionsFailed{Cause: err}
	}
	return resp.GetSessions(), nil
}

// GetSession returns a provisioning session by ID.
func (c *Client) GetSession(ctx context.Context, sessionID string) (*platformv1.ProvisioningSession, error) {
	if sessionID == "" {
		return nil, &ErrSessionIDRequired{}
	}
	resp, err := c.grpc.GetSession(ctx, &platformv1.GetSessionRequest{
		SessionId: sessionID,
	})
	if err != nil {
		return nil, &ErrGetSessionFailed{SessionID: sessionID, Cause: err}
	}
	return resp.GetSession(), nil
}
