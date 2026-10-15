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
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// invitationTestProvider serves an InvitationService servicer next to the
// mock service provider.
type invitationTestProvider struct {
	*mockServiceProvider
	server platformv1.InvitationServiceServer
}

func (p invitationTestProvider) InvitationServiceServer() platformv1.InvitationServiceServer {
	return p.server
}

// fakeMCPInvitations answers GetInvitation and records the request; every
// other method is Unimplemented.
type fakeMCPInvitations struct {
	platformv1.UnimplementedInvitationServiceServer
	got *platformv1.GetInvitationRequest
}

func (f *fakeMCPInvitations) GetInvitation(_ context.Context, req *platformv1.GetInvitationRequest) (*platformv1.GetInvitationResponse, error) {
	f.got = req
	return &platformv1.GetInvitationResponse{Invitation: &platformv1.Invitation{
		Id:     req.GetInvitationId(),
		Status: platformv1.InvitationStatus_INVITATION_STATUS_PENDING,
	}}, nil
}

func newInvitationTestRegistry(server platformv1.InvitationServiceServer) *ToolRegistry {
	provider := invitationTestProvider{mockServiceProvider: newMockServiceProvider(), server: server}
	return NewToolRegistry(provider, logging.DefaultLogger())
}

// TestInvitationTools_CoverEveryMethodWithItsGRPCScope requires one tool per
// gRPC InvitationService method, classified with the scope gRPC requires:
// none for the two invitee methods, whose token is the credential.
func TestInvitationTools_CoverEveryMethodWithItsGRPCScope(t *testing.T) {
	permissions := toolPermissionCatalog()
	byMethod := make(map[string]string, len(invitationTools))
	for name, tool := range invitationTools {
		byMethod[tool.method] = name
	}

	for _, desc := range platformv1.InvitationService_ServiceDesc.Methods {
		method := path.Join("/", platformv1.InvitationService_ServiceDesc.ServiceName, desc.MethodName)
		name, ok := byMethod[method]
		require.True(t, ok, "%s has no tool", method)
		permission, classified := permissions[name]
		require.True(t, classified, "%s is not classified", name)
		assert.Equal(t, grpcapi.ScopeForMethod(method), permission, name)
	}
	assert.Len(t, invitationTools, len(platformv1.InvitationService_ServiceDesc.Methods))
}

// TestInvitationTools_AreRegisteredWithTheirSchema requires every tool to be
// listed with the arguments its gRPC request cannot do without.
func TestInvitationTools_AreRegisteredWithTheirSchema(t *testing.T) {
	required := map[string][]string{
		"platform_invitation_create":       {"tenant_id", "email", "role", "invited_by_id"},
		"platform_invitation_get":          {"invitation_id"},
		"platform_invitation_get_by_token": {"token"},
		"platform_invitation_list":         {"tenant_id"},
		"platform_invitation_revoke":       {"invitation_id", "revoker_id"},
		"platform_invitation_accept":       {"token", "user_id"},
		"platform_invitation_delete":       {"invitation_id"},
	}
	registered := make(map[string]map[string]interface{})
	for _, def := range newInvitationTestRegistry(nil).ListTools() {
		registered[def.Name] = def.InputSchema
	}

	require.Len(t, required, len(invitationTools))
	for name, args := range required {
		schema, ok := registered[name]
		require.True(t, ok, "%s is not registered", name)
		assert.ElementsMatch(t, args, schema["required"], name)
	}
}

// TestInvitationTools_CallTheServicer requires a tool to decode its
// arguments into the gRPC request and answer the gRPC response in protojson
// form.
func TestInvitationTools_CallTheServicer(t *testing.T) {
	fake := &fakeMCPInvitations{}
	registry := newInvitationTestRegistry(fake)

	result, err := registry.ExecuteTool(context.Background(), "platform_invitation_get",
		map[string]interface{}{"invitation_id": "42"})

	require.NoError(t, err)
	require.NotNil(t, fake.got)
	assert.Equal(t, uint64(42), fake.got.GetInvitationId())
	assert.Equal(t, map[string]interface{}{"invitation": map[string]interface{}{
		"id": "42", "status": "INVITATION_STATUS_PENDING",
	}}, result)
}

// TestInvitationTools_PassTheServicerStatusThrough requires the servicer's
// gRPC status to reach the caller unchanged.
func TestInvitationTools_PassTheServicerStatusThrough(t *testing.T) {
	registry := newInvitationTestRegistry(&fakeMCPInvitations{})

	_, err := registry.ExecuteTool(context.Background(), "platform_invitation_delete",
		map[string]interface{}{"invitation_id": 1})

	assert.Equal(t, codes.Unimplemented, status.Code(err), "err = %v", err)
}

// TestInvitationTools_RefuseWhenTheInvitationServiceIsNotWired covers a
// provider without InvitationServiceServer and one that serves none.
func TestInvitationTools_RefuseWhenTheInvitationServiceIsNotWired(t *testing.T) {
	for _, provider := range []ServiceProvider{
		newMockServiceProvider(),
		invitationTestProvider{mockServiceProvider: newMockServiceProvider()},
	} {
		registry := NewToolRegistry(provider, logging.DefaultLogger())
		for name := range invitationTools {
			_, err := registry.ExecuteTool(context.Background(), name, map[string]interface{}{})
			require.ErrorIs(t, err, ErrInvitationNotConfigured, name)
		}
	}
}

// TestInvitationTools_RejectArgumentsTheRequestDoesNotHave requires an
// argument the gRPC request has no field for to be refused before the
// servicer runs.
func TestInvitationTools_RejectArgumentsTheRequestDoesNotHave(t *testing.T) {
	fake := &fakeMCPInvitations{}
	registry := newInvitationTestRegistry(fake)

	_, err := registry.ExecuteTool(context.Background(), "platform_invitation_get",
		map[string]interface{}{"invitation_id": 1, "tenant_id": "t"})

	var invalid ErrInvalidArgument
	require.ErrorAs(t, err, &invalid)
	assert.Nil(t, fake.got, "the servicer ran for a malformed call")
}
