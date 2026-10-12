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

package mcp

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// Invitation tool wiring
// =============================================================================
//
// These tools mirror the gRPC InvitationService surface so AI/LLM clients can
// drive the same tenant-user invitation workflows over MCP. Tool names follow
// the project convention `platform_invitation_<verb>` and route through a
// map-based dispatcher (O(1) lookup per project conventions).
//
// The MCP server stays decoupled from the daemon: the underlying invitation
// service is exposed via the optional InvitationProvider interface, satisfied
// by the daemon's MCPServiceProvider when a platform InvitationServicer is
// wired in. When a provider is not wired, every invitation tool returns
// ErrInvitationNotConfigured so clients see a clear, structured failure
// rather than a generic "unknown tool" error.

// ErrInvitationNotConfigured indicates the invitation backend is not wired
// into the MCP tool registry. Clients see this when the daemon was started
// without an InvitationServicer available (e.g., DAOFactory does not
// expose an InvitationDAO).
var ErrInvitationNotConfigured = errors.New("invitation: service provider not configured")

// ErrInvitationIDRequired indicates the `invitation_id` argument is
// missing or zero. invitation_id is the primary key for ID-based RPCs.
var ErrInvitationIDRequired = errors.New("invitation: invitation_id is required and must be non-zero")

// ErrInvitationTokenRequired indicates the `token` argument is missing
// or empty. The token is the primary key for token-based RPCs (lookup
// and accept).
var ErrInvitationTokenRequired = errors.New("invitation: token is required")

// ErrInvitationTenantIDRequired indicates the `tenant_id` argument is
// missing or empty.
var ErrInvitationTenantIDRequired = errors.New("invitation: tenant_id is required")

// ErrInvitationEmailRequired indicates the `email` argument is missing
// or empty.
var ErrInvitationEmailRequired = errors.New("invitation: email is required")

// ErrInvitationRoleRequired indicates the `role` argument is missing
// or empty.
var ErrInvitationRoleRequired = errors.New("invitation: role is required")

// ErrInvitationInvitedByIDRequired indicates the `invited_by_id`
// argument is missing or zero. The inviter id is required for audit.
var ErrInvitationInvitedByIDRequired = errors.New("invitation: invited_by_id is required and must be non-zero")

// ErrInvitationUserIDRequired indicates the `user_id` argument is
// missing or zero on accept calls.
var ErrInvitationUserIDRequired = errors.New("invitation: user_id is required and must be non-zero")

// ErrInvitationRevokerIDRequired indicates the `revoker_id` argument
// is missing or zero on revoke calls.
var ErrInvitationRevokerIDRequired = errors.New("invitation: revoker_id is required and must be non-zero")

// InvitationProvider is the optional interface a ServiceProvider can satisfy
// to unlock invitation MCP tools. Implementations are expected to delegate
// to the platform InvitationServicer (the same backing implementation that
// powers the gRPC InvitationServiceServer) so the MCP and gRPC surfaces
// remain in lockstep.
//
// All methods return JSON-friendly results (map[string]interface{} or a
// list thereof) so MCP responses serialize cleanly without further
// post-processing in the registry.
type InvitationProvider interface {
	// CreateInvitation creates a new invitation.
	CreateInvitation(ctx context.Context, tenantID, email, role string, invitedByID uint64, expiresInSeconds int64) (interface{}, error)

	// GetInvitation retrieves an invitation by its ID.
	GetInvitation(ctx context.Context, invitationID uint64) (interface{}, error)

	// GetInvitationByToken retrieves an invitation by its secure token.
	GetInvitationByToken(ctx context.Context, token string) (interface{}, error)

	// ListInvitations lists invitations for a tenant. When pendingOnly is
	// true, only pending invitations are returned.
	ListInvitations(ctx context.Context, tenantID string, pendingOnly bool) (interface{}, error)

	// RevokeInvitation revokes a pending invitation.
	RevokeInvitation(ctx context.Context, invitationID, revokerID uint64) (interface{}, error)

	// AcceptInvitation marks an invitation as accepted.
	AcceptInvitation(ctx context.Context, token string, userID uint64) (interface{}, error)

	// DeleteInvitation permanently removes an invitation.
	DeleteInvitation(ctx context.Context, invitationID uint64) (interface{}, error)
}

// invitationProvider returns the InvitationProvider interface if the
// underlying ServiceProvider implements it, else nil.
func (r *ToolRegistry) invitationProvider() InvitationProvider {
	if p, ok := r.service.(InvitationProvider); ok {
		return p
	}
	return nil
}

// registerInvitationTools registers the platform_invitation_* MCP tools.
// Each tool definition mirrors the equivalent gRPC RPC so AI/LLM clients
// can issue the same calls they would over gRPC.
func (r *ToolRegistry) registerInvitationTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_invitation_create",
		Description: "Create a new invitation for a user to join a tenant",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID the invitation is for",
				},
				"email": map[string]interface{}{
					"type":        "string",
					"description": "Email address of the invited user",
				},
				"role": map[string]interface{}{
					"type":        "string",
					"description": "Role assigned to the user upon acceptance",
				},
				"invited_by_id": map[string]interface{}{
					"type":        "integer",
					"description": "ID of the user creating the invitation",
				},
				"expires_in_seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Custom expiration duration in seconds (optional, defaults to 7 days)",
				},
			},
			"required": []string{"tenant_id", "email", "role", "invited_by_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_invitation_get",
		Description: "Retrieve an invitation by its ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"invitation_id": map[string]interface{}{
					"type":        "integer",
					"description": "ID of the invitation to retrieve",
				},
			},
			"required": []string{"invitation_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_invitation_get_by_token",
		Description: "Retrieve an invitation by its secure token",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"token": map[string]interface{}{
					"type":        "string",
					"description": "Secure token of the invitation",
				},
			},
			"required": []string{"token"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_invitation_list",
		Description: "List invitations for a tenant, optionally restricted to pending invitations",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID to list invitations for",
				},
				"pending_only": map[string]interface{}{
					"type":        "boolean",
					"description": "If true, return only pending invitations",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_invitation_revoke",
		Description: "Revoke a pending invitation",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"invitation_id": map[string]interface{}{
					"type":        "integer",
					"description": "ID of the invitation to revoke",
				},
				"revoker_id": map[string]interface{}{
					"type":        "integer",
					"description": "ID of the user performing the revocation",
				},
			},
			"required": []string{"invitation_id", "revoker_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_invitation_accept",
		Description: "Accept a pending invitation by token",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"token": map[string]interface{}{
					"type":        "string",
					"description": "Secure token of the invitation",
				},
				"user_id": map[string]interface{}{
					"type":        "integer",
					"description": "ID of the user accepting the invitation",
				},
			},
			"required": []string{"token", "user_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_invitation_delete",
		Description: "Permanently delete an invitation",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"invitation_id": map[string]interface{}{
					"type":        "integer",
					"description": "ID of the invitation to delete",
				},
			},
			"required": []string{"invitation_id"},
		},
	})
}

// =============================================================================
// Map-based dispatch
// =============================================================================

// invitationToolHandler dispatches an invitation tool by name.
type invitationToolHandler func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

var invitationToolDispatch = map[string]invitationToolHandler{
	"platform_invitation_create":       (*ToolRegistry).executeInvitationCreate,
	"platform_invitation_get":          (*ToolRegistry).executeInvitationGet,
	"platform_invitation_get_by_token": (*ToolRegistry).executeInvitationGetByToken,
	"platform_invitation_list":         (*ToolRegistry).executeInvitationList,
	"platform_invitation_revoke":       (*ToolRegistry).executeInvitationRevoke,
	"platform_invitation_accept":       (*ToolRegistry).executeInvitationAccept,
	"platform_invitation_delete":       (*ToolRegistry).executeInvitationDelete,
}

// dispatchInvitationTool looks up an invitation tool and invokes it.
// Returns (result, handled, err) so the caller can fall through when
// handled is false (tool name doesn't belong to invitation).
func (r *ToolRegistry) dispatchInvitationTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := invitationToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

// =============================================================================
// Argument helpers
// =============================================================================

// invitationID extracts the required `invitation_id` argument.
func invitationID(args map[string]interface{}) (uint64, error) {
	id := uint64(getInt64(args, "invitation_id"))
	if id == 0 {
		return 0, ErrInvitationIDRequired
	}
	return id, nil
}

// invitationToken extracts the required `token` argument.
func invitationToken(args map[string]interface{}) (string, error) {
	token := getString(args, "token")
	if token == "" {
		return "", ErrInvitationTokenRequired
	}
	return token, nil
}

// =============================================================================
// Executors
// =============================================================================

func (r *ToolRegistry) executeInvitationCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.invitationProvider()
	if p == nil {
		return nil, ErrInvitationNotConfigured
	}
	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrInvitationTenantIDRequired
	}
	email := getString(args, "email")
	if email == "" {
		return nil, ErrInvitationEmailRequired
	}
	role := getString(args, "role")
	if role == "" {
		return nil, ErrInvitationRoleRequired
	}
	invitedByID := uint64(getInt64(args, "invited_by_id"))
	if invitedByID == 0 {
		return nil, ErrInvitationInvitedByIDRequired
	}
	expiresInSeconds := getInt64(args, "expires_in_seconds")
	return p.CreateInvitation(ctx, tenantID, email, role, invitedByID, expiresInSeconds)
}

func (r *ToolRegistry) executeInvitationGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.invitationProvider()
	if p == nil {
		return nil, ErrInvitationNotConfigured
	}
	id, err := invitationID(args)
	if err != nil {
		return nil, err
	}
	return p.GetInvitation(ctx, id)
}

func (r *ToolRegistry) executeInvitationGetByToken(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.invitationProvider()
	if p == nil {
		return nil, ErrInvitationNotConfigured
	}
	token, err := invitationToken(args)
	if err != nil {
		return nil, err
	}
	return p.GetInvitationByToken(ctx, token)
}

func (r *ToolRegistry) executeInvitationList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.invitationProvider()
	if p == nil {
		return nil, ErrInvitationNotConfigured
	}
	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrInvitationTenantIDRequired
	}
	pendingOnly := getBool(args, "pending_only")
	return p.ListInvitations(ctx, tenantID, pendingOnly)
}

func (r *ToolRegistry) executeInvitationRevoke(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.invitationProvider()
	if p == nil {
		return nil, ErrInvitationNotConfigured
	}
	id, err := invitationID(args)
	if err != nil {
		return nil, err
	}
	revokerID := uint64(getInt64(args, "revoker_id"))
	if revokerID == 0 {
		return nil, ErrInvitationRevokerIDRequired
	}
	return p.RevokeInvitation(ctx, id, revokerID)
}

func (r *ToolRegistry) executeInvitationAccept(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.invitationProvider()
	if p == nil {
		return nil, ErrInvitationNotConfigured
	}
	token, err := invitationToken(args)
	if err != nil {
		return nil, err
	}
	userID := uint64(getInt64(args, "user_id"))
	if userID == 0 {
		return nil, ErrInvitationUserIDRequired
	}
	return p.AcceptInvitation(ctx, token, userID)
}

func (r *ToolRegistry) executeInvitationDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.invitationProvider()
	if p == nil {
		return nil, ErrInvitationNotConfigured
	}
	id, err := invitationID(args)
	if err != nil {
		return nil, err
	}
	return p.DeleteInvitation(ctx, id)
}
