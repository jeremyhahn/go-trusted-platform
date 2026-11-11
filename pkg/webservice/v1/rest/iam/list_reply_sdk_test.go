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

// These requests set no pagination and no filter, so the SDK REST routes
// send no query parameters and the handler applies its default page: page 1,
// 50 per page, offset 0.
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
	t.Parallel()
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

// TestListRepliesOverSDKREST_FiltersAndPagination sends nonzero pagination
// and filters through the SDK's REST adapter to the real router: the
// handlers read them from the query string only, so they must reach the IAM
// client and the reply must report the page that was asked for.
func TestListRepliesOverSDKREST_FiltersAndPagination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pagination := func() *platformv1.PaginationRequest {
		return &platformv1.PaginationRequest{Page: 1, PageSize: 10}
	}

	t.Run("ListUsers", func(t *testing.T) {
		var got iamsdk.ListUsersRequest
		iamClient := &mockIAMClient{
			listUsersFn: func(_ context.Context, _ string, req *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
				got = *req
				return &iamsdk.ListUsersResponse{
					Users:      []iamsdk.User{{ID: "item-1"}},
					Pagination: iamsdk.PaginationInfo{TotalCount: 21},
				}, nil
			},
		}
		conn := sdkRESTConnection(t, adminSessionIAMServerIn(t, "tenant-a", iamClient, &mockPEPClient{}))

		reply, err := platformv1.NewPlatformIAMServiceClient(conn).ListUsers(ctx, &platformv1.ListIAMUsersRequest{
			TenantId:    "tenant-a",
			Pagination:  pagination(),
			EmailFilter: "alice@example.com",
			RoleFilter:  "role-1",
			GroupFilter: "group-1",
		})
		require.NoError(t, err)

		assert.EqualValues(t, 10, got.PageSize)
		assert.EqualValues(t, "alice@example.com", got.Filter)
		assert.EqualValues(t, "role-1", got.RoleID)
		assert.EqualValues(t, "group-1", got.GroupID)
		assert.Equal(t, uint32(1), reply.GetPagination().GetPage())
		assert.Equal(t, uint32(10), reply.GetPagination().GetPageSize())
	})

	t.Run("ListRoles", func(t *testing.T) {
		var got iamsdk.ListRolesRequest
		iamClient := &mockIAMClient{
			listRolesFn: func(_ context.Context, _ string, req *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
				got = *req
				return &iamsdk.ListRolesResponse{
					Roles:      []iamsdk.Role{{ID: "item-1"}},
					Pagination: iamsdk.PaginationInfo{TotalCount: 21},
				}, nil
			},
		}
		conn := sdkRESTConnection(t, adminSessionIAMServerIn(t, "tenant-a", iamClient, &mockPEPClient{}))

		reply, err := platformv1.NewPlatformIAMServiceClient(conn).ListRoles(ctx, &platformv1.ListIAMRolesRequest{
			TenantId:   "tenant-a",
			Pagination: pagination(),
		})
		require.NoError(t, err)

		assert.EqualValues(t, 10, got.PageSize)
		assert.Equal(t, uint32(1), reply.GetPagination().GetPage())
		assert.Equal(t, uint32(10), reply.GetPagination().GetPageSize())
	})

	t.Run("ListGroups", func(t *testing.T) {
		var got iamsdk.ListGroupsRequest
		iamClient := &mockIAMClient{
			listGroupsFn: func(_ context.Context, _ string, req *iamsdk.ListGroupsRequest) (*iamsdk.ListGroupsResponse, error) {
				got = *req
				return &iamsdk.ListGroupsResponse{
					Groups:     []iamsdk.Group{{ID: "item-1"}},
					Pagination: iamsdk.PaginationInfo{TotalCount: 21},
				}, nil
			},
		}
		conn := sdkRESTConnection(t, adminSessionIAMServerIn(t, "tenant-a", iamClient, &mockPEPClient{}))

		reply, err := platformv1.NewPlatformIAMServiceClient(conn).ListGroups(ctx, &platformv1.ListIAMGroupsRequest{
			TenantId:   "tenant-a",
			Pagination: pagination(),
		})
		require.NoError(t, err)

		assert.EqualValues(t, 10, got.PageSize)
		assert.Equal(t, uint32(1), reply.GetPagination().GetPage())
		assert.Equal(t, uint32(10), reply.GetPagination().GetPageSize())
	})
}

// TestListRepliesOverSDKREST_LaterPagesRefused shows that the list handlers
// whose IAM call takes no offset (ListUsers, ListGroups, ListRoles) refuse a
// later page with 400 before IAM is asked, instead of answering the first
// page labelled as the requested one; the first page and a request without
// pagination are still served.
func TestListRepliesOverSDKREST_LaterPagesRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	type invoke func(client platformv1.PlatformIAMServiceClient, p *platformv1.PaginationRequest) error
	cases := []struct {
		name   string
		mock   func(calls *int) *mockIAMClient
		invoke invoke
	}{
		{
			name: "ListUsers",
			mock: func(calls *int) *mockIAMClient {
				return &mockIAMClient{
					listUsersFn: func(context.Context, string, *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
						*calls++
						return &iamsdk.ListUsersResponse{Users: []iamsdk.User{{ID: "item-1"}}}, nil
					},
				}
			},
			invoke: func(client platformv1.PlatformIAMServiceClient, p *platformv1.PaginationRequest) error {
				_, err := client.ListUsers(ctx, &platformv1.ListIAMUsersRequest{TenantId: "tenant-a", Pagination: p})
				return err
			},
		},
		{
			name: "ListGroups",
			mock: func(calls *int) *mockIAMClient {
				return &mockIAMClient{
					listGroupsFn: func(context.Context, string, *iamsdk.ListGroupsRequest) (*iamsdk.ListGroupsResponse, error) {
						*calls++
						return &iamsdk.ListGroupsResponse{Groups: []iamsdk.Group{{ID: "item-1"}}}, nil
					},
				}
			},
			invoke: func(client platformv1.PlatformIAMServiceClient, p *platformv1.PaginationRequest) error {
				_, err := client.ListGroups(ctx, &platformv1.ListIAMGroupsRequest{TenantId: "tenant-a", Pagination: p})
				return err
			},
		},
		{
			name: "ListRoles",
			mock: func(calls *int) *mockIAMClient {
				return &mockIAMClient{
					listRolesFn: func(context.Context, string, *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
						*calls++
						return &iamsdk.ListRolesResponse{Roles: []iamsdk.Role{{ID: "item-1"}}}, nil
					},
				}
			},
			invoke: func(client platformv1.PlatformIAMServiceClient, p *platformv1.PaginationRequest) error {
				_, err := client.ListRoles(ctx, &platformv1.ListIAMRolesRequest{TenantId: "tenant-a", Pagination: p})
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls int
			conn := sdkRESTConnection(t, adminSessionIAMServerIn(t, "tenant-a", tc.mock(&calls), &mockPEPClient{}))
			client := platformv1.NewPlatformIAMServiceClient(conn)

			// Page 2 of 10 is offset=10.
			err := tc.invoke(client, &platformv1.PaginationRequest{Page: 2, PageSize: 10})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
			assert.Zero(t, calls, "IAM was asked for a page the handler cannot serve")

			// Page 214748366 of 10 is offset=2147483650, above MaxInt32.
			err = tc.invoke(client, &platformv1.PaginationRequest{Page: 214748366, PageSize: 10})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
			assert.Zero(t, calls, "IAM was asked for an out-of-range page the handler cannot serve")

			require.NoError(t, tc.invoke(client, &platformv1.PaginationRequest{Page: 1, PageSize: 10}))
			require.NoError(t, tc.invoke(client, nil))
			assert.Equal(t, 2, calls)
		})
	}
}

// TestListTenantsOverSDKREST_OverflowingOffsetRefused sends a page whose
// offset is above MaxInt32 through the SDK's REST adapter: the handler must
// refuse it with InvalidArgument, not serve the first page.
func TestListTenantsOverSDKREST_OverflowingOffsetRefused(t *testing.T) {
	t.Parallel()
	var calls int
	iamClient := &mockIAMClient{
		listTenantsFn: func(context.Context, int32, int32) (*ListTenantsResponse, error) {
			calls++
			return &ListTenantsResponse{}, nil
		},
	}
	conn := sdkRESTConnection(t, adminSessionIAMServerIn(t, "system", iamClient, &mockPEPClient{}))

	// Page 214748366 of 10 is offset=2147483650, above MaxInt32.
	_, err := platformv1.NewPlatformIAMServiceClient(conn).ListTenants(context.Background(), &platformv1.ListIAMTenantsRequest{
		Pagination: &platformv1.PaginationRequest{Page: 214748366, PageSize: 10},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
	assert.Zero(t, calls, "IAM was asked for a page from an out-of-range offset")
}

// TestListRepliesOverSDKREST_ServiceErrors checks a NotFound from the IAM
// client reaches the SDK caller as codes.NotFound with no reply.
func TestListRepliesOverSDKREST_ServiceErrors(t *testing.T) {
	t.Parallel()
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
