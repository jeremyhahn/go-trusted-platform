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

//go:build integration

package invitation

import (
	"context"
	"time"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	// Register every sdk/go transport so the adapter can select any of
	// them by protocol.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// invitationStatusNames maps the wire enum onto the status strings the
// suite asserts on.
var invitationStatusNames = map[platformv1.InvitationStatus]string{
	platformv1.InvitationStatus_INVITATION_STATUS_PENDING:  InvitationStatusPending,
	platformv1.InvitationStatus_INVITATION_STATUS_ACCEPTED: InvitationStatusAccepted,
	platformv1.InvitationStatus_INVITATION_STATUS_EXPIRED:  InvitationStatusExpired,
	platformv1.InvitationStatus_INVITATION_STATUS_REVOKED:  InvitationStatusRevoked,
}

// SDKAdapter drives InvitationCommands through the platform SDK over one
// selected transport, exercising the exact adapter tables (QUIC
// category/sub-opcode map, MCP tool map) the production clients use.
type SDKAdapter struct {
	name     string
	endpoint string
	options  func() *platform.Options
	client   platform.Client
}

// NewGRPCAdapter drives the invitation service over TLS gRPC.
func NewGRPCAdapter() *SDKAdapter {
	endpoint := GetGRPCEndpoint()
	return &SDKAdapter{
		name:     "gRPC",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolGRPC),
				platform.WithGRPCAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewQUICAdapter drives the invitation service over QUIC.
func NewQUICAdapter() *SDKAdapter {
	endpoint := GetQUICEndpoint()
	return &SDKAdapter{
		name:     "QUIC",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolQUIC),
				platform.WithQUICAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewMCPAdapter drives the invitation service over MCP.
func NewMCPAdapter() *SDKAdapter {
	endpoint := GetMCPEndpoint()
	return &SDKAdapter{
		name:     "MCP",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolMCP),
				platform.WithMCPAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewUnixAdapter drives the invitation service over the local Unix socket.
func NewUnixAdapter() *SDKAdapter {
	endpoint := GetSocketPath()
	return &SDKAdapter{
		name:     "Unix",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolUnix),
				platform.WithUnixSocket(endpoint),
			)
		},
	}
}

// Name returns the transport name.
func (a *SDKAdapter) Name() string { return a.name }

// Setup connects the SDK client on the adapter's transport.
func (a *SDKAdapter) Setup(ctx context.Context) error {
	client, err := platform.Connect(ctx, a.options())
	if err != nil {
		return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
	}
	a.client = client
	return nil
}

// Teardown closes the SDK client.
func (a *SDKAdapter) Teardown(ctx context.Context) error {
	if a.client != nil {
		return a.client.Close()
	}
	return nil
}

// CreateInvitation implements InvitationCommands.
func (a *SDKAdapter) CreateInvitation(ctx context.Context, opts CreateInvitationOptions) (*CreateInvitationResult, error) {
	resp, err := a.client.Invitation().CreateInvitation(ctx, &platformv1.CreateInvitationRequest{
		TenantId:         opts.TenantID,
		Email:            opts.Email,
		Role:             opts.Role,
		InvitedById:      opts.UserID,
		ExpiresInSeconds: int64(opts.ExpiresIn / time.Second),
	})
	if err != nil {
		return nil, err
	}
	return &CreateInvitationResult{Invitation: invitationFromProto(resp.GetInvitation())}, nil
}

// GetInvitationByToken implements InvitationCommands.
func (a *SDKAdapter) GetInvitationByToken(ctx context.Context, opts GetByTokenOptions) (*GetInvitationResult, error) {
	resp, err := a.client.Invitation().GetInvitationByToken(ctx, &platformv1.GetInvitationByTokenRequest{
		Token: opts.Token,
	})
	if err != nil {
		return nil, err
	}
	return &GetInvitationResult{Invitation: invitationFromProto(resp.GetInvitation())}, nil
}

// ListInvitations implements InvitationCommands.
func (a *SDKAdapter) ListInvitations(ctx context.Context, opts ListInvitationsOptions) (*ListInvitationsResult, error) {
	req := &platformv1.ListInvitationsRequest{TenantId: opts.TenantID}
	if opts.Limit > 0 {
		req.Pagination = &platformv1.PaginationRequest{
			Page:     uint32(opts.Offset/opts.Limit) + 1,
			PageSize: uint32(opts.Limit),
		}
	}
	resp, err := a.client.Invitation().ListInvitations(ctx, req)
	if err != nil {
		return nil, err
	}
	invitations := make([]*Invitation, 0, len(resp.GetInvitations()))
	for _, inv := range resp.GetInvitations() {
		invitations = append(invitations, invitationFromProto(inv))
	}
	return &ListInvitationsResult{Invitations: invitations, Total: int(resp.GetTotal())}, nil
}

// RevokeInvitation implements InvitationCommands.
func (a *SDKAdapter) RevokeInvitation(ctx context.Context, opts RevokeInvitationOptions) (*RevokeResult, error) {
	resp, err := a.client.Invitation().RevokeInvitation(ctx, &platformv1.RevokeInvitationRequest{
		InvitationId: opts.InvitationID,
		RevokerId:    opts.UserID,
	})
	if err != nil {
		return nil, err
	}
	return &RevokeResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// AcceptInvitation implements InvitationCommands.
func (a *SDKAdapter) AcceptInvitation(ctx context.Context, opts AcceptInvitationOptions) (*AcceptResult, error) {
	resp, err := a.client.Invitation().AcceptInvitation(ctx, &platformv1.AcceptInvitationRequest{
		Token:  opts.Token,
		UserId: opts.UserID,
	})
	if err != nil {
		return nil, err
	}
	return &AcceptResult{
		Success: resp.GetStatus().GetSuccess(),
		UserID:  opts.UserID,
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// invitationFromProto converts the wire invitation into the suite's view.
func invitationFromProto(inv *platformv1.Invitation) *Invitation {
	if inv == nil {
		return nil
	}
	out := &Invitation{
		ID:          inv.GetId(),
		Token:       inv.GetToken(),
		TenantID:    inv.GetTenantId(),
		Email:       inv.GetEmail(),
		Role:        inv.GetRole(),
		Status:      invitationStatusNames[inv.GetStatus()],
		InvitedByID: inv.GetInvitedById(),
		ExpiresAt:   inv.GetExpiresAt().AsTime(),
		CreatedAt:   inv.GetCreatedAt().AsTime(),
	}
	if inv.GetAcceptedAt() != nil {
		acceptedAt := inv.GetAcceptedAt().AsTime()
		out.AcceptedAt = &acceptedAt
	}
	return out
}

// Compile-time check: the SDK adapter satisfies the shared surface.
var _ InvitationCommands = (*SDKAdapter)(nil)
