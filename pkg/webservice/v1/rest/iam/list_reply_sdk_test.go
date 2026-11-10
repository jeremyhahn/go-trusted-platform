package iam

import (
	"context"
	"fmt"
	"strconv"
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
		return &platformv1.PaginationRequest{Page: 3, PageSize: 10}
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
		assert.Equal(t, uint32(3), reply.GetPagination().GetPage())
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
		assert.Equal(t, uint32(3), reply.GetPagination().GetPage())
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
		assert.Equal(t, uint32(3), reply.GetPagination().GetPage())
		assert.Equal(t, uint32(10), reply.GetPagination().GetPageSize())
	})
}

// pagedRecordTotal is how many records the paging mock backend holds.
const pagedRecordTotal = 25

// pagedRecordID is the ID of the n-th record (from 1) of the paging mock
// backend.
func pagedRecordID(n int) string {
	return fmt.Sprintf("item-%02d", n)
}

// pagedRecordIDs is the IDs of the records first to last, both included.
func pagedRecordIDs(first, last int) []string {
	ids := make([]string, 0, last-first+1)
	for n := first; n <= last; n++ {
		ids = append(ids, pagedRecordID(n))
	}
	return ids
}

// pagedBackendPage serves one page of the mock backend as the IAM client
// does: pageSize records from the position the opaque page token names, with
// the token of the next page while there is one.
func pagedBackendPage(pageSize int, pageToken string) ([]string, iamsdk.PaginationInfo) {
	start := 0
	if pageToken != "" {
		parsed, err := strconv.Atoi(pageToken)
		if err != nil {
			panic(fmt.Sprintf("page token %q was not issued by the mock backend", pageToken))
		}
		start = parsed
	}
	if pageSize <= 0 {
		pageSize = pagedRecordTotal
	}
	end := min(start+pageSize, pagedRecordTotal)
	info := iamsdk.PaginationInfo{TotalCount: pagedRecordTotal}
	if end < pagedRecordTotal {
		info.HasMore = true
		info.NextPageToken = strconv.Itoa(end)
	}
	if start >= end {
		return nil, info
	}
	return pagedRecordIDs(start+1, end), info
}

// TestListRepliesOverSDKREST_PagesCarryDistinctRecords asks the tenant-scoped
// list routes for consecutive pages through the SDK REST adapter. The backend
// pages by opaque token, so the handlers have to serve the requested offset
// from its pages: every page carries its own records, and a page past the end
// is empty.
func TestListRepliesOverSDKREST_PagesCarryDistinctRecords(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	type pageReply struct {
		ids      []string
		page     uint32
		pageSize uint32
		total    int64
	}
	pages := []struct {
		page uint32
		want []string
	}{
		{page: 1, want: pagedRecordIDs(1, 10)},
		{page: 2, want: pagedRecordIDs(11, 20)},
		{page: 3, want: pagedRecordIDs(21, 25)},
		{page: 4, want: []string{}},
	}
	assertPages := func(t *testing.T, list func(page uint32) (pageReply, error)) {
		t.Helper()
		seen := map[string]uint32{}
		for _, tc := range pages {
			reply, err := list(tc.page)
			require.NoError(t, err, "page %d", tc.page)

			got := reply.ids
			if got == nil {
				got = []string{}
			}
			assert.Equal(t, tc.want, got, "records of page %d", tc.page)
			for _, id := range got {
				if first, dup := seen[id]; dup {
					assert.Failf(t, "record on two pages", "%s is on page %d and page %d", id, first, tc.page)
					continue
				}
				seen[id] = tc.page
			}
			assert.Equal(t, tc.page, reply.page, "page of page %d", tc.page)
			assert.Equal(t, uint32(10), reply.pageSize, "page size of page %d", tc.page)
			assert.EqualValues(t, pagedRecordTotal, reply.total, "total of page %d", tc.page)
		}
	}
	pagination := func(page uint32) *platformv1.PaginationRequest {
		return &platformv1.PaginationRequest{Page: page, PageSize: 10}
	}

	t.Run("ListUsers", func(t *testing.T) {
		var calls []iamsdk.ListUsersRequest
		iamClient := &mockIAMClient{
			listUsersFn: func(_ context.Context, _ string, req *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
				calls = append(calls, *req)
				ids, info := pagedBackendPage(req.PageSize, req.PageToken)
				users := make([]iamsdk.User, 0, len(ids))
				for _, id := range ids {
					users = append(users, iamsdk.User{ID: id})
				}
				return &iamsdk.ListUsersResponse{Users: users, Pagination: info}, nil
			},
		}
		client := platformv1.NewPlatformIAMServiceClient(
			sdkRESTConnection(t, adminSessionIAMServerIn(t, "tenant-a", iamClient, &mockPEPClient{})))

		assertPages(t, func(page uint32) (pageReply, error) {
			reply, err := client.ListUsers(ctx, &platformv1.ListIAMUsersRequest{
				TenantId:    "tenant-a",
				Pagination:  pagination(page),
				EmailFilter: "alice@example.com",
				RoleFilter:  "role-1",
				GroupFilter: "group-1",
			})
			if err != nil {
				return pageReply{}, err
			}
			out := pageReply{
				page:     reply.GetPagination().GetPage(),
				pageSize: reply.GetPagination().GetPageSize(),
				total:    int64(reply.GetTotal()),
			}
			for _, user := range reply.GetUsers() {
				out.ids = append(out.ids, user.GetId())
			}
			return out, nil
		})

		// Pages 2 to 4 each need more than one backend page.
		assert.Greater(t, len(calls), len(pages))
		for i, call := range calls {
			assert.EqualValues(t, "alice@example.com", call.Filter, "backend call %d", i)
			assert.EqualValues(t, "role-1", call.RoleID, "backend call %d", i)
			assert.EqualValues(t, "group-1", call.GroupID, "backend call %d", i)
		}
	})

	t.Run("ListRoles", func(t *testing.T) {
		iamClient := &mockIAMClient{
			listRolesFn: func(_ context.Context, _ string, req *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
				ids, info := pagedBackendPage(req.PageSize, req.PageToken)
				roles := make([]iamsdk.Role, 0, len(ids))
				for _, id := range ids {
					roles = append(roles, iamsdk.Role{ID: id})
				}
				return &iamsdk.ListRolesResponse{Roles: roles, Pagination: info}, nil
			},
		}
		client := platformv1.NewPlatformIAMServiceClient(
			sdkRESTConnection(t, adminSessionIAMServerIn(t, "tenant-a", iamClient, &mockPEPClient{})))

		assertPages(t, func(page uint32) (pageReply, error) {
			reply, err := client.ListRoles(ctx, &platformv1.ListIAMRolesRequest{
				TenantId:   "tenant-a",
				Pagination: pagination(page),
			})
			if err != nil {
				return pageReply{}, err
			}
			out := pageReply{
				page:     reply.GetPagination().GetPage(),
				pageSize: reply.GetPagination().GetPageSize(),
				total:    int64(reply.GetTotal()),
			}
			for _, role := range reply.GetRoles() {
				out.ids = append(out.ids, role.GetId())
			}
			return out, nil
		})
	})

	t.Run("ListGroups", func(t *testing.T) {
		iamClient := &mockIAMClient{
			listGroupsFn: func(_ context.Context, _ string, req *iamsdk.ListGroupsRequest) (*iamsdk.ListGroupsResponse, error) {
				ids, info := pagedBackendPage(req.PageSize, req.PageToken)
				groups := make([]iamsdk.Group, 0, len(ids))
				for _, id := range ids {
					groups = append(groups, iamsdk.Group{ID: id})
				}
				return &iamsdk.ListGroupsResponse{Groups: groups, Pagination: info}, nil
			},
		}
		client := platformv1.NewPlatformIAMServiceClient(
			sdkRESTConnection(t, adminSessionIAMServerIn(t, "tenant-a", iamClient, &mockPEPClient{})))

		assertPages(t, func(page uint32) (pageReply, error) {
			reply, err := client.ListGroups(ctx, &platformv1.ListIAMGroupsRequest{
				TenantId:   "tenant-a",
				Pagination: pagination(page),
			})
			if err != nil {
				return pageReply{}, err
			}
			out := pageReply{
				page:     reply.GetPagination().GetPage(),
				pageSize: reply.GetPagination().GetPageSize(),
				total:    int64(reply.GetTotal()),
			}
			for _, group := range reply.GetGroups() {
				out.ids = append(out.ids, group.GetId())
			}
			return out, nil
		})
	})
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
