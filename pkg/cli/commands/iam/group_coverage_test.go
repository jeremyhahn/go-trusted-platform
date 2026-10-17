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

package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	iamsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
)

// fakeIAMGRPC records the IAM requests the CLI sends. Methods the tests do
// not override panic through the nil embedded interface.
type fakeIAMGRPC struct {
	platformv1.PlatformIAMServiceClient

	err       error
	addReq    *platformv1.AddGroupMemberRequest
	removeReq *platformv1.RemoveGroupMemberRequest
	checkReq  *platformv1.CheckIAMPermissionRequest
	checkResp *platformv1.CheckIAMPermissionResponse
}

func (f *fakeIAMGRPC) AddGroupMember(_ context.Context, in *platformv1.AddGroupMemberRequest, _ ...grpc.CallOption) (*platformv1.AddGroupMemberResponse, error) {
	f.addReq = in
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.AddGroupMemberResponse{}, nil
}

func (f *fakeIAMGRPC) RemoveGroupMember(_ context.Context, in *platformv1.RemoveGroupMemberRequest, _ ...grpc.CallOption) (*platformv1.RemoveGroupMemberResponse, error) {
	f.removeReq = in
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.RemoveGroupMemberResponse{}, nil
}

func (f *fakeIAMGRPC) CheckPermission(_ context.Context, in *platformv1.CheckIAMPermissionRequest, _ ...grpc.CallOption) (*platformv1.CheckIAMPermissionResponse, error) {
	f.checkReq = in
	if f.err != nil {
		return nil, f.err
	}
	return f.checkResp, nil
}

// =============================================================================
// Group Command Structure Coverage
// =============================================================================

func TestGroupGetCommand_HasRunE(t *testing.T) {
	cmd := newGroupGetCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Contains(t, cmd.Use, "get")
	assert.NotNil(t, cmd.RunE)
	assert.NotEmpty(t, cmd.Long)
}

func TestGroupDeleteCommand_HasRunE(t *testing.T) {
	cmd := newGroupDeleteCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Contains(t, cmd.Use, "delete")
	assert.NotNil(t, cmd.RunE)
	assert.NotEmpty(t, cmd.Long)
}

// =============================================================================
// Group membership
// =============================================================================

func TestGroupMembershipCommands_ReachTheDaemon(t *testing.T) {
	commands := map[string]func(func() *cli.CommonFlags) *cobra.Command{
		"add-member":    newGroupAddMemberCommand,
		"remove-member": newGroupRemoveMemberCommand,
	}
	for name, build := range commands {
		t.Run(name, func(t *testing.T) {
			cmd := build(noCtxFlags)
			assert.Contains(t, cmd.Use, name)
			assert.NotEmpty(t, cmd.Long)
			cmd.SetArgs([]string{"tenant-1", "group-1", "user-1"})
			assertNoCtxErr(t, cmd.Execute())
		})
	}
}

func TestRunGroupMembership_RejectsMissingIDs(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		groupID  string
		userID   string
		want     error
	}{
		{"tenant", "", "g", "u", ErrMissingTenantID{}},
		{"group", "t", "", "u", ErrMissingGroupID{}},
		{"user", "t", "g", "", ErrMissingUserID{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runGroupMembership(noCtxFlags(), addGroupMember, tt.tenantID, tt.groupID, tt.userID)
			assert.IsType(t, tt.want, err)
		})
	}
}

func TestGroupMembershipChange_SendsTheRequest(t *testing.T) {
	fake := &fakeIAMGRPC{}
	client := iamsvc.NewClientFromGRPC(fake)

	require.NoError(t, addGroupMember.apply(client, context.Background(), "t-1", "g-1", "u-1"))
	require.NotNil(t, fake.addReq)
	assert.Equal(t, "t-1", fake.addReq.GetTenantId())
	assert.Equal(t, "g-1", fake.addReq.GetGroupId())
	assert.Equal(t, "u-1", fake.addReq.GetUserId())

	require.NoError(t, removeGroupMember.apply(client, context.Background(), "t-2", "g-2", "u-2"))
	require.NotNil(t, fake.removeReq)
	assert.Equal(t, "t-2", fake.removeReq.GetTenantId())
	assert.Equal(t, "g-2", fake.removeReq.GetGroupId())
	assert.Equal(t, "u-2", fake.removeReq.GetUserId())
}

func TestGroupMembershipChange_ReturnsTheDaemonError(t *testing.T) {
	rpcErr := errors.New("user not found")
	client := iamsvc.NewClientFromGRPC(&fakeIAMGRPC{err: rpcErr})

	assert.ErrorIs(t, addGroupMember.apply(client, context.Background(), "t", "g", "u"), rpcErr)
	assert.ErrorIs(t, removeGroupMember.apply(client, context.Background(), "t", "g", "u"), rpcErr)
}

// =============================================================================
// Permission check
// =============================================================================

func TestPermissionCheckRequest_Validate(t *testing.T) {
	valid := permissionCheckRequest{tenantID: "t", subjectID: "s", action: "read", resource: "users"}
	assert.NoError(t, valid.validate())

	missingTenant := valid
	missingTenant.tenantID = ""
	assert.IsType(t, ErrMissingTenantID{}, missingTenant.validate())

	for name, clear := range map[string]func(r *permissionCheckRequest){
		"subject":  func(r *permissionCheckRequest) { r.subjectID = "" },
		"action":   func(r *permissionCheckRequest) { r.action = "" },
		"resource": func(r *permissionCheckRequest) { r.resource = "" },
	} {
		t.Run(name, func(t *testing.T) {
			r := valid
			clear(&r)
			var msgErr *MessageError
			assert.ErrorAs(t, r.validate(), &msgErr)
		})
	}
}

func TestPermissionCheckCommand_RequiresTenant(t *testing.T) {
	cmd := newPermissionCheckCommand(noCtxFlags)
	cmd.SetArgs([]string{"--subject", "s", "--action", "read", "--resource", "users"})
	assert.IsType(t, ErrMissingTenantID{}, cmd.Execute())
}

func TestPermissionCheckCommand_ReachesTheDaemon(t *testing.T) {
	cmd := newPermissionCheckCommand(noCtxFlags)
	cmd.SetArgs([]string{"--tenant", "t", "--subject", "s", "--action", "read", "--resource", "users"})
	assertNoCtxErr(t, cmd.Execute())
}

func TestCheckPermission_SendsEveryFieldAndReturnsTheAnswer(t *testing.T) {
	fake := &fakeIAMGRPC{checkResp: &platformv1.CheckIAMPermissionResponse{
		Allowed:          true,
		MatchedPolicy:    "p-1",
		MatchedRule:      "r-1",
		Reason:           "role grants users:read",
		EvaluationTimeNs: 42,
	}}
	req := &permissionCheckRequest{
		tenantID:   "t-1",
		subjectID:  "u-1",
		roles:      "role-a,role-b",
		groups:     "ops",
		action:     "read",
		resource:   "users",
		context:    "ip=10.0.0.1",
		attributes: "dept=eng",
	}

	result, err := checkPermission(context.Background(), iamsvc.NewClientFromGRPC(fake), req)
	require.NoError(t, err)

	require.NotNil(t, fake.checkReq)
	assert.Equal(t, "t-1", fake.checkReq.GetTenantId())
	assert.Equal(t, "u-1", fake.checkReq.GetSubjectId())
	assert.Equal(t, []string{"role-a", "role-b"}, fake.checkReq.GetRoles())
	assert.Equal(t, []string{"ops"}, fake.checkReq.GetGroups())
	assert.Equal(t, "read", fake.checkReq.GetAction())
	assert.Equal(t, "users", fake.checkReq.GetResource())
	assert.Equal(t, map[string]string{"ip": "10.0.0.1"}, fake.checkReq.GetContext())
	assert.Equal(t, map[string]string{"dept": "eng"}, fake.checkReq.GetAttributes())

	assert.Equal(t, &PermissionCheckResult{
		Allowed:          true,
		MatchedPolicy:    "p-1",
		MatchedRule:      "r-1",
		Reason:           "role grants users:read",
		EvaluationTimeNs: 42,
	}, result)
}

func TestCheckPermission_WrapsTheDaemonError(t *testing.T) {
	rpcErr := errors.New("tenant not found")
	req := &permissionCheckRequest{tenantID: "t", subjectID: "s", action: "read", resource: "users"}

	result, err := checkPermission(context.Background(), iamsvc.NewClientFromGRPC(&fakeIAMGRPC{err: rpcErr}), req)
	assert.Nil(t, result)
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to check permission", wrapped.Msg)
	assert.ErrorIs(t, err, rpcErr)
}
