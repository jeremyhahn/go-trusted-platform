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

// The platform_invitation_* tools (pkg/api/mcp/invitation_tools.go, #704)
// call the daemon's gRPC InvitationService servicer: they take the request
// and return the response in the proto3 JSON mapping with proto field names,
// so the shared protoJSON builder and decoder serve every method.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// invitationToolMap maps each InvitationService gRPC method to the platformd
// MCP tool that serves it.
var invitationToolMap = map[string]string{
	platformv1.InvitationService_CreateInvitation_FullMethodName:     "platform_invitation_create",
	platformv1.InvitationService_GetInvitation_FullMethodName:        "platform_invitation_get",
	platformv1.InvitationService_GetInvitationByToken_FullMethodName: "platform_invitation_get_by_token",
	platformv1.InvitationService_ListInvitations_FullMethodName:      "platform_invitation_list",
	platformv1.InvitationService_RevokeInvitation_FullMethodName:     "platform_invitation_revoke",
	platformv1.InvitationService_AcceptInvitation_FullMethodName:     "platform_invitation_accept",
	platformv1.InvitationService_DeleteInvitation_FullMethodName:     "platform_invitation_delete",
}

func init() {
	for method, tool := range invitationToolMap {
		grpcMethodToMCPToolMap[method] = tool
		mcpArgBuilders[method] = protoJSONArgs(method)
		mcpReplyDecoders[method] = protoJSONReply(method)
	}
}
