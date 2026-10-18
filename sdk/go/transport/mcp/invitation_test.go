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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Every InvitationService method has a tool, an argument builder and a reply
// decoder.
func TestInvitationTools_CoverEveryMethod(t *testing.T) {
	desc := platformv1.InvitationService_ServiceDesc
	for _, m := range desc.Methods {
		method := "/" + desc.ServiceName + "/" + m.MethodName
		assert.NotEmpty(t, MethodTools()[method], "%s has no tool", method)
		assert.Contains(t, mcpArgBuilders, method)
		assert.Contains(t, mcpReplyDecoders, method)
	}
	assert.Len(t, invitationToolMap, len(desc.Methods))
}

// A request travels under its proto field names: IDs as decimal strings and
// an enum by name.
func TestInvitationTools_BuildTheRequestArguments(t *testing.T) {
	build := mcpArgBuilders[platformv1.InvitationService_ListInvitations_FullMethodName]

	args, err := build(&platformv1.ListInvitationsRequest{
		TenantId:     "tenant-1",
		StatusFilter: platformv1.InvitationStatus_INVITATION_STATUS_ACCEPTED,
	})

	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"tenant_id":     "tenant-1",
		"status_filter": "INVITATION_STATUS_ACCEPTED",
	}, args)
}

func TestInvitationTools_RefuseAnArgumentOfAnotherType(t *testing.T) {
	build := mcpArgBuilders[platformv1.InvitationService_AcceptInvitation_FullMethodName]

	_, err := build("tok-1")

	var unexpected ErrUnexpectedArgsType
	require.True(t, errors.As(err, &unexpected), "error = %v", err)
	assert.Equal(t, platformv1.InvitationService_AcceptInvitation_FullMethodName, unexpected.Method)
}

// A tool result decodes into the gRPC response, nested messages included.
func TestInvitationTools_DecodeTheResult(t *testing.T) {
	decode := mcpReplyDecoders[platformv1.InvitationService_ListInvitations_FullMethodName]
	reply := &platformv1.ListInvitationsResponse{}

	err := decode(map[string]interface{}{"invitations": []interface{}{map[string]interface{}{
		"id": "42", "email": "alice@example.com", "status": "INVITATION_STATUS_PENDING",
		"created_at": "2026-01-02T03:04:05Z",
	}}}, reply)

	require.NoError(t, err)
	require.Len(t, reply.GetInvitations(), 1)
	invitation := reply.GetInvitations()[0]
	assert.Equal(t, uint64(42), invitation.GetId())
	assert.Equal(t, "alice@example.com", invitation.GetEmail())
	assert.Equal(t, platformv1.InvitationStatus_INVITATION_STATUS_PENDING, invitation.GetStatus())
	assert.Equal(t, int64(1767323045), invitation.GetCreatedAt().GetSeconds())
}

func TestInvitationTools_RefuseAResultTheResponseCannotHold(t *testing.T) {
	decode := mcpReplyDecoders[platformv1.InvitationService_GetInvitation_FullMethodName]

	err := decode(map[string]interface{}{"invitation": map[string]interface{}{"id": "many"}},
		&platformv1.GetInvitationResponse{})

	var unmarshal ErrUnmarshalFailed
	assert.True(t, errors.As(err, &unmarshal), "error = %v", err)
}
