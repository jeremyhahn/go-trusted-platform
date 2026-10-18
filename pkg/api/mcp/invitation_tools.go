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
	"maps"
	"slices"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// Invitation tool wiring
// =============================================================================
//
// Every gRPC InvitationService method has one platform_invitation_<verb>
// tool. A tool's arguments are the gRPC request in protojson form (proto
// field names, enums by name, 64-bit integers as JSON numbers or strings)
// and its result is the gRPC response in the same form. Each tool calls the
// gRPC InvitationService servicer, so it validates, answers and fails exactly
// as gRPC does. The permission each tool requires is in authz.go: the scope
// of its gRPC method, or none for the two invitee tools.

// ErrInvitationNotConfigured indicates the invitation backend is not wired
// into the MCP tool registry. Clients see this when the daemon was started
// without an InvitationService servicer.
var ErrInvitationNotConfigured = errors.New("invitation: service provider not configured")

// InvitationProvider is implemented by a ServiceProvider that serves the
// gRPC InvitationService. The platform_invitation_* tools call that servicer.
type InvitationProvider interface {
	// InvitationServiceServer returns the gRPC InvitationService servicer,
	// or nil while no invitation service is wired.
	InvitationServiceServer() platformv1.InvitationServiceServer
}

// invitationTool is one invitation tool and the gRPC method it serves.
type invitationTool struct {
	method      string
	description string
	binding     grpcToolBinding[platformv1.InvitationServiceServer]
}

// invitationTools are the invitation tools bound to the gRPC
// InvitationService.
var invitationTools = map[string]invitationTool{
	"platform_invitation_create": {
		method:      platformv1.InvitationService_CreateInvitation_FullMethodName,
		description: "Create a new invitation for a user to join a tenant",
		binding: grpcToolMethod(platformv1.InvitationServiceServer.CreateInvitation,
			"tenant_id", "email", "role", "invited_by_id"),
	},
	"platform_invitation_get": {
		method:      platformv1.InvitationService_GetInvitation_FullMethodName,
		description: "Retrieve an invitation by its ID",
		binding:     grpcToolMethod(platformv1.InvitationServiceServer.GetInvitation, "invitation_id"),
	},
	"platform_invitation_get_by_token": {
		method:      platformv1.InvitationService_GetInvitationByToken_FullMethodName,
		description: "Retrieve an invitation by its secure token",
		binding:     grpcToolMethod(platformv1.InvitationServiceServer.GetInvitationByToken, "token"),
	},
	"platform_invitation_list": {
		method:      platformv1.InvitationService_ListInvitations_FullMethodName,
		description: "List invitations for a tenant, optionally filtered by status or email",
		binding:     grpcToolMethod(platformv1.InvitationServiceServer.ListInvitations, "tenant_id"),
	},
	"platform_invitation_revoke": {
		method:      platformv1.InvitationService_RevokeInvitation_FullMethodName,
		description: "Revoke a pending invitation",
		binding: grpcToolMethod(platformv1.InvitationServiceServer.RevokeInvitation,
			"invitation_id", "revoker_id"),
	},
	"platform_invitation_accept": {
		method:      platformv1.InvitationService_AcceptInvitation_FullMethodName,
		description: "Accept a pending invitation by token",
		binding:     grpcToolMethod(platformv1.InvitationServiceServer.AcceptInvitation, "token", "user_id"),
	},
	"platform_invitation_delete": {
		method:      platformv1.InvitationService_DeleteInvitation_FullMethodName,
		description: "Permanently delete an invitation",
		binding:     grpcToolMethod(platformv1.InvitationServiceServer.DeleteInvitation, "invitation_id"),
	},
}

// registerInvitationTools registers the platform_invitation_* MCP tools.
func (r *ToolRegistry) registerInvitationTools() {
	for _, name := range slices.Sorted(maps.Keys(invitationTools)) {
		tool := invitationTools[name]
		r.addTool(mcpwire.ToolDefinition{
			Name:        name,
			Description: tool.description,
			InputSchema: tool.binding.schema(),
		})
	}
}

// invitationServiceServer is the gRPC InvitationService servicer the
// invitation tools call, or nil while the service provider serves none.
func (r *ToolRegistry) invitationServiceServer() platformv1.InvitationServiceServer {
	if provider, ok := r.service.(InvitationProvider); ok {
		return provider.InvitationServiceServer()
	}
	return nil
}

// dispatchInvitationTool runs a platform_invitation_* tool. handled is false
// when name is not an invitation tool, so the caller tries the next
// dispatcher.
func (r *ToolRegistry) dispatchInvitationTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	tool, ok := invitationTools[name]
	if !ok {
		return nil, false, nil
	}
	server := r.invitationServiceServer()
	if server == nil {
		return nil, true, ErrInvitationNotConfigured
	}
	result, err := tool.binding.call(server, ctx, args)
	return result, true, err
}
