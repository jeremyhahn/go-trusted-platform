package iam

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// statusReply is the part every status-only IAM reply shares: the outcome.
type statusReply interface {
	GetStatus() *platformv1.Status
}

// statusReplyCase drives one status-only IAM RPC through the SDK REST client.
// mock wires the IAM client call the route must reach and records its
// arguments into got; invoke sends the RPC.
type statusReplyCase struct {
	name        string
	wantMessage string
	wantArgs    []string
	mock        func(client *mockIAMClient, got *[]string, err error)
	invoke      func(client platformv1.PlatformIAMServiceClient) (statusReply, error)
}

func statusReplyCases() []statusReplyCase {
	ctx := context.Background()
	return []statusReplyCase{
		{
			name: "DeleteUser", wantMessage: "user deleted successfully",
			wantArgs: []string{"tenant-a", "user-1"},
			mock: func(c *mockIAMClient, got *[]string, err error) {
				c.deleteUserFn = func(_ context.Context, tenantID, userID string) error {
					*got = []string{tenantID, userID}
					return err
				}
			},
			invoke: func(c platformv1.PlatformIAMServiceClient) (statusReply, error) {
				return c.DeleteUser(ctx, &platformv1.DeleteIAMUserRequest{TenantId: "tenant-a", UserId: "user-1"})
			},
		},
		{
			name: "AssignRole", wantMessage: "role assigned successfully",
			wantArgs: []string{"tenant-a", "user-1", "writer"},
			mock: func(c *mockIAMClient, got *[]string, err error) {
				c.assignRoleFn = func(_ context.Context, tenantID, userID, roleID string) error {
					*got = []string{tenantID, userID, roleID}
					return err
				}
			},
			invoke: func(c platformv1.PlatformIAMServiceClient) (statusReply, error) {
				return c.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{TenantId: "tenant-a", UserId: "user-1", RoleId: "writer"})
			},
		},
		{
			name: "RevokeRole", wantMessage: "role revoked successfully",
			wantArgs: []string{"tenant-a", "user-1", "writer"},
			mock: func(c *mockIAMClient, got *[]string, err error) {
				c.revokeRoleFn = func(_ context.Context, tenantID, userID, roleID string) error {
					*got = []string{tenantID, userID, roleID}
					return err
				}
			},
			invoke: func(c platformv1.PlatformIAMServiceClient) (statusReply, error) {
				return c.RevokeRole(ctx, &platformv1.RevokeIAMRoleRequest{TenantId: "tenant-a", UserId: "user-1", RoleId: "writer"})
			},
		},
		{
			name: "DeleteRole", wantMessage: "role deleted successfully",
			wantArgs: []string{"tenant-a", "writer"},
			mock: func(c *mockIAMClient, got *[]string, err error) {
				c.deleteRoleFn = func(_ context.Context, tenantID, roleID string) error {
					*got = []string{tenantID, roleID}
					return err
				}
			},
			invoke: func(c platformv1.PlatformIAMServiceClient) (statusReply, error) {
				return c.DeleteRole(ctx, &platformv1.DeleteIAMRoleRequest{TenantId: "tenant-a", RoleId: "writer"})
			},
		},
		{
			name: "DeleteGroup", wantMessage: "group deleted successfully",
			wantArgs: []string{"tenant-a", "docs"},
			mock: func(c *mockIAMClient, got *[]string, err error) {
				c.deleteGroupFn = func(_ context.Context, tenantID, groupID string) error {
					*got = []string{tenantID, groupID}
					return err
				}
			},
			invoke: func(c platformv1.PlatformIAMServiceClient) (statusReply, error) {
				return c.DeleteGroup(ctx, &platformv1.DeleteIAMGroupRequest{TenantId: "tenant-a", GroupId: "docs"})
			},
		},
		{
			name: "AddGroupMember", wantMessage: "member added successfully",
			wantArgs: []string{"tenant-a", "docs", "user-1"},
			mock: func(c *mockIAMClient, got *[]string, err error) {
				c.addGroupMemberFn = func(_ context.Context, tenantID, groupID, userID string) error {
					*got = []string{tenantID, groupID, userID}
					return err
				}
			},
			invoke: func(c platformv1.PlatformIAMServiceClient) (statusReply, error) {
				return c.AddGroupMember(ctx, &platformv1.AddGroupMemberRequest{TenantId: "tenant-a", GroupId: "docs", UserId: "user-1"})
			},
		},
		{
			name: "RemoveGroupMember", wantMessage: "member removed successfully",
			wantArgs: []string{"tenant-a", "docs", "user-1"},
			mock: func(c *mockIAMClient, got *[]string, err error) {
				c.removeGroupMemberFn = func(_ context.Context, tenantID, groupID, userID string) error {
					*got = []string{tenantID, groupID, userID}
					return err
				}
			},
			invoke: func(c platformv1.PlatformIAMServiceClient) (statusReply, error) {
				return c.RemoveGroupMember(ctx, &platformv1.RemoveGroupMemberRequest{TenantId: "tenant-a", GroupId: "docs", UserId: "user-1"})
			},
		},
	}
}

// TestStatusRepliesOverSDKREST_RoundTrip drives every status-only IAM RPC the
// SDK sends over REST through the real IAM router and decodes the reply. The
// handlers answer the proto shape ({"status": {...}, "timestamp": ...}), so the
// SDK sees the outcome the gRPC service reports instead of an empty status
// (#445).
func TestStatusRepliesOverSDKREST_RoundTrip(t *testing.T) {
	t.Parallel()
	for _, tc := range statusReplyCases() {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			iamClient := &mockIAMClient{}
			tc.mock(iamClient, &got, nil)
			conn := sdkRESTConnection(t, adminSessionIAMServer(t, iamClient, &mockPEPClient{}))

			reply, err := tc.invoke(platformv1.NewPlatformIAMServiceClient(conn))
			require.NoError(t, err)

			assert.Equal(t, tc.wantArgs, got)
			assert.True(t, reply.GetStatus().GetSuccess(), "the SDK decoded no success status")
			assert.Equal(t, tc.wantMessage, reply.GetStatus().GetMessage())
		})
	}
}

// TestStatusRepliesOverSDKREST_ServiceErrors pins the error half: a failure in
// the IAM service reaches the SDK as its gRPC code, not as a reply.
func TestStatusRepliesOverSDKREST_ServiceErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range statusReplyCases() {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			iamClient := &mockIAMClient{}
			tc.mock(iamClient, &got, status.Error(codes.NotFound, "not found"))
			conn := sdkRESTConnection(t, adminSessionIAMServer(t, iamClient, &mockPEPClient{}))

			reply, err := tc.invoke(platformv1.NewPlatformIAMServiceClient(conn))

			require.Error(t, err)
			assert.Equal(t, codes.NotFound, status.Code(err))
			assert.Nil(t, reply.GetStatus())
			assert.Equal(t, tc.wantArgs, got)
		})
	}
}
