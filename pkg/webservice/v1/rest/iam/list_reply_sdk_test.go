package iam

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// listReply is what every IAM list reply carries beside its items.
type listReply interface {
	GetPagination() *platformv1.PaginationResponse
	GetTotal() int64
	GetTimestamp() *timestamppb.Timestamp
}

// listCall is what the handler passed to the IAM client: the tenant and the
// page size, plus the offset for ListTenants, which takes one.
type listCall struct {
	tenant   string
	pageSize int
	offset   int32
}

// listReplyCase drives one IAM list RPC through the SDK REST transport. The
// mock returns two items of a total of three; invoke returns the item IDs the
// SDK decoded.
type listReplyCase struct {
	name          string
	sessionTenant string
	wantCall      listCall
	mock          func(client *mockIAMClient, got *listCall, err error)
	invoke        func(client platformv1.PlatformIAMServiceClient) ([]string, listReply, error)
}

// The SDK REST routes for the IAM lists send no query parameters, so the
// handler applies its default page: page 1, 50 per page, offset 0.
func listReplyCases() []listReplyCase {
	ctx := context.Background()
	return []listReplyCase{
		{
			name: "ListUsers", sessionTenant: "tenant-a",
			wantCall: listCall{tenant: "tenant-a", pageSize: 50},
			mock: func(c *mockIAMClient, got *listCall, err error) {
				c.listUsersFn = func(_ context.Context, tenantID string, req *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
					*got = listCall{tenant: tenantID, pageSize: req.PageSize}
					if err != nil {
						return nil, err
					}
					return &iamsdk.ListUsersResponse{
						Users:      []iamsdk.User{{ID: "item-1"}, {ID: "item-2"}},
						Pagination: iamsdk.PaginationInfo{TotalCount: 3},
					}, nil
				}
			},
			invoke: func(c platformv1.PlatformIAMServiceClient) ([]string, listReply, error) {
				reply, err := c.ListUsers(ctx, &platformv1.ListIAMUsersRequest{TenantId: "tenant-a"})
				var ids []string
				for _, u := range reply.GetUsers() {
					ids = append(ids, u.GetId())
				}
				return ids, reply, err
			},
		},
		{
			name: "ListGroups", sessionTenant: "tenant-a",
			wantCall: listCall{tenant: "tenant-a", pageSize: 50},
			mock: func(c *mockIAMClient, got *listCall, err error) {
				c.listGroupsFn = func(_ context.Context, tenantID string, req *iamsdk.ListGroupsRequest) (*iamsdk.ListGroupsResponse, error) {
					*got = listCall{tenant: tenantID, pageSize: req.PageSize}
					if err != nil {
						return nil, err
					}
					return &iamsdk.ListGroupsResponse{
						Groups:     []iamsdk.Group{{ID: "item-1"}, {ID: "item-2"}},
						Pagination: iamsdk.PaginationInfo{TotalCount: 3},
					}, nil
				}
			},
			invoke: func(c platformv1.PlatformIAMServiceClient) ([]string, listReply, error) {
				reply, err := c.ListGroups(ctx, &platformv1.ListIAMGroupsRequest{TenantId: "tenant-a"})
				var ids []string
				for _, g := range reply.GetGroups() {
					ids = append(ids, g.GetId())
				}
				return ids, reply, err
			},
		},
		{
			name: "ListRoles", sessionTenant: "tenant-a",
			wantCall: listCall{tenant: "tenant-a", pageSize: 50},
			mock: func(c *mockIAMClient, got *listCall, err error) {
				c.listRolesFn = func(_ context.Context, tenantID string, req *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
					*got = listCall{tenant: tenantID, pageSize: req.PageSize}
					if err != nil {
						return nil, err
					}
					return &iamsdk.ListRolesResponse{
						Roles:      []iamsdk.Role{{ID: "item-1"}, {ID: "item-2"}},
						Pagination: iamsdk.PaginationInfo{TotalCount: 3},
					}, nil
				}
			},
			invoke: func(c platformv1.PlatformIAMServiceClient) ([]string, listReply, error) {
				reply, err := c.ListRoles(ctx, &platformv1.ListIAMRolesRequest{TenantId: "tenant-a"})
				var ids []string
				for _, r := range reply.GetRoles() {
					ids = append(ids, r.GetId())
				}
				return ids, reply, err
			},
		},
		{
			// GET /iam/tenants is system-only, so the session is a system admin.
			name: "ListTenants", sessionTenant: "system",
			wantCall: listCall{pageSize: 50},
			mock: func(c *mockIAMClient, got *listCall, err error) {
				c.listTenantsFn = func(_ context.Context, limit, offset int32) (*ListTenantsResponse, error) {
					*got = listCall{pageSize: int(limit), offset: offset}
					if err != nil {
						return nil, err
					}
					return &ListTenantsResponse{
						PaginatedResponse: PaginatedResponse{Total: 3},
						Tenants:           []TenantResponse{{ID: "item-1"}, {ID: "item-2"}},
					}, nil
				}
			},
			invoke: func(c platformv1.PlatformIAMServiceClient) ([]string, listReply, error) {
				reply, err := c.ListTenants(ctx, &platformv1.ListIAMTenantsRequest{})
				var ids []string
				for _, tenant := range reply.GetTenants() {
					ids = append(ids, tenant.GetId())
				}
				return ids, reply, err
			},
		},
	}
}

// TestListRepliesOverSDKREST_RoundTrip drives each IAM list RPC the SDK
// routes over REST through the real IAM router, and checks the SDK decodes
// the items, the pagination, the total and the timestamp of the proto reply.
func TestListRepliesOverSDKREST_RoundTrip(t *testing.T) {
	for _, tc := range listReplyCases() {
		t.Run(tc.name, func(t *testing.T) {
			var got listCall
			iamClient := &mockIAMClient{}
			tc.mock(iamClient, &got, nil)
			conn := sdkRESTConnection(t, adminSessionIAMServerIn(t, tc.sessionTenant, iamClient, &mockPEPClient{}))

			ids, reply, err := tc.invoke(platformv1.NewPlatformIAMServiceClient(conn))
			require.NoError(t, err)

			assert.Equal(t, tc.wantCall, got)
			assert.Equal(t, []string{"item-1", "item-2"}, ids)
			assert.Equal(t, int64(3), reply.GetTotal())
			assert.Equal(t, uint32(1), reply.GetPagination().GetPage())
			assert.Equal(t, uint32(50), reply.GetPagination().GetPageSize())
			assert.Equal(t, uint32(1), reply.GetPagination().GetTotalPages())
			assert.Equal(t, uint64(3), reply.GetPagination().GetTotalItems())
			assert.NotNil(t, reply.GetTimestamp(), "the SDK decoded no timestamp")
		})
	}
}

// TestListRepliesOverSDKREST_ServiceErrors checks a NotFound from the IAM
// client reaches the SDK caller as codes.NotFound with no reply.
func TestListRepliesOverSDKREST_ServiceErrors(t *testing.T) {
	for _, tc := range listReplyCases() {
		t.Run(tc.name, func(t *testing.T) {
			var got listCall
			iamClient := &mockIAMClient{}
			tc.mock(iamClient, &got, status.Error(codes.NotFound, "not found"))
			conn := sdkRESTConnection(t, adminSessionIAMServerIn(t, tc.sessionTenant, iamClient, &mockPEPClient{}))

			ids, reply, err := tc.invoke(platformv1.NewPlatformIAMServiceClient(conn))

			require.Error(t, err)
			assert.Equal(t, codes.NotFound, status.Code(err))
			assert.Empty(t, ids)
			assert.Nil(t, reply.GetPagination())
			assert.Equal(t, tc.wantCall, got)
		})
	}
}
