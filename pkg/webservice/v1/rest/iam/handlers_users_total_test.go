package iam

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// numberedUsers builds n users of one tenant, user-000 onwards.
func numberedUsers(tenantID string, n int) []iamsdk.User {
	users := make([]iamsdk.User, 0, n)
	for i := 0; i < n; i++ {
		users = append(users, iamsdk.User{
			ID:       fmt.Sprintf("user-%03d", i),
			TenantID: tenantID,
			Email:    fmt.Sprintf("user%03d@example.com", i),
		})
	}
	return users
}

// listUsersAt calls ListUsers for tenant-1 with the given query string and an
// IAM that answers resp whatever it is asked.
func listUsersAt(t *testing.T, query string, resp *iamsdk.ListUsersResponse) *mockHttpWriter {
	t.Helper()
	iamClient := &mockIAMClient{
		listUsersFn: func(ctx context.Context, tenantID string, req *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			return resp, nil
		},
	}
	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})
	target := "/api/v1/iam/tenants/tenant-1/users"
	if query != "" {
		target += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1"})
	handlers.ListUsers(httptest.NewRecorder(), req)
	return writer
}

func userIDs(reply *platformv1.ListIAMUsersResponse) []string {
	ids := make([]string, 0, len(reply.GetUsers()))
	for _, u := range reply.GetUsers() {
		ids = append(ids, u.GetId())
	}
	return ids
}

// The embedded IAM ignores the page size and lists the store's first 100
// users with no total: a tenant of 150 users must not be reported as 100.
func TestListUsers_RefusesATotalFromAFullEmbeddedPage(t *testing.T) {
	t.Parallel()
	all := numberedUsers("tenant-1", 150)
	writer := listUsersAt(t, "limit=50", &iamsdk.ListUsersResponse{
		Users:      all[:100],
		Pagination: iamsdk.PaginationInfo{},
	})

	assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
	var unknown ErrIAMUserTotalUnknown
	require.ErrorAs(t, writer.lastError, &unknown)
	assert.Equal(t, "tenant-1", unknown.TenantID)
	assert.Equal(t, 100, unknown.Listed)
	assert.Nil(t, writer.lastPayload, "no reply may carry the page length as the total")
}

func TestListUsers_RefusesAPageThatHasMoreWithoutACount(t *testing.T) {
	t.Parallel()
	writer := listUsersAt(t, "", &iamsdk.ListUsersResponse{
		Users:      numberedUsers("tenant-1", 50),
		Pagination: iamsdk.PaginationInfo{HasMore: true, NextPageToken: "page-2"},
	})

	assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
	var unknown ErrIAMUserTotalUnknown
	require.ErrorAs(t, writer.lastError, &unknown)
	assert.Equal(t, "tenant-1", unknown.TenantID)
	assert.Equal(t, 50, unknown.Listed)
	assert.Nil(t, writer.lastPayload)
}

func TestListUsers_ReportsTheIAMTotalPastOnePage(t *testing.T) {
	t.Parallel()
	all := numberedUsers("tenant-1", 150)
	writer := listUsersAt(t, "limit=50&offset=50", &iamsdk.ListUsersResponse{
		Users: all[50:100],
		Pagination: iamsdk.PaginationInfo{
			TotalCount: 150, PageSize: 50, HasMore: true, NextPageToken: "page-2",
		},
	})

	require.Equal(t, http.StatusOK, writer.lastStatus)
	reply := &platformv1.ListIAMUsersResponse{}
	decodeProtoReply(t, writer, reply)
	assert.Equal(t, int64(150), reply.GetTotal())
	assert.Equal(t, uint64(150), reply.GetPagination().GetTotalItems())
	assert.Equal(t, uint32(3), reply.GetPagination().GetTotalPages())
	assert.Equal(t, uint32(2), reply.GetPagination().GetPage())
	assert.Len(t, reply.GetUsers(), 50)
}

func TestListUsers_PagesACompleteListWithoutACount(t *testing.T) {
	t.Parallel()
	all := numberedUsers("tenant-1", 60)
	tests := []struct {
		name       string
		query      string
		wantIDs    []string
		wantPage   uint32
		wantPages  uint32
		wantLength int
	}{
		{
			name:       "the third page of 25 holds the last ten",
			query:      "limit=25&offset=50",
			wantIDs:    userIDs(&platformv1.ListIAMUsersResponse{Users: protoUsers(all[50:60])}),
			wantPage:   3,
			wantPages:  3,
			wantLength: 10,
		},
		{
			name:       "an offset past the list answers no users",
			query:      "limit=25&offset=75",
			wantIDs:    []string{},
			wantPage:   4,
			wantPages:  3,
			wantLength: 0,
		},
		{
			name:       "the default page holds the first fifty",
			query:      "",
			wantIDs:    userIDs(&platformv1.ListIAMUsersResponse{Users: protoUsers(all[:50])}),
			wantPage:   1,
			wantPages:  2,
			wantLength: 50,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			writer := listUsersAt(t, tt.query, &iamsdk.ListUsersResponse{Users: all})

			require.Equal(t, http.StatusOK, writer.lastStatus)
			reply := &platformv1.ListIAMUsersResponse{}
			decodeProtoReply(t, writer, reply)
			assert.Len(t, reply.GetUsers(), tt.wantLength)
			assert.Equal(t, tt.wantIDs, userIDs(reply))
			assert.Equal(t, int64(60), reply.GetTotal())
			assert.Equal(t, uint64(60), reply.GetPagination().GetTotalItems())
			assert.Equal(t, tt.wantPage, reply.GetPagination().GetPage())
			assert.Equal(t, tt.wantPages, reply.GetPagination().GetTotalPages())
		})
	}
}

func TestListUsers_CountsACompleteListJustUnderTheEmbeddedCap(t *testing.T) {
	t.Parallel()
	writer := listUsersAt(t, "", &iamsdk.ListUsersResponse{Users: numberedUsers("tenant-1", 99)})

	require.Equal(t, http.StatusOK, writer.lastStatus)
	reply := &platformv1.ListIAMUsersResponse{}
	decodeProtoReply(t, writer, reply)
	assert.Equal(t, int64(99), reply.GetTotal())
	assert.Len(t, reply.GetUsers(), 50)
	assert.Equal(t, uint32(2), reply.GetPagination().GetTotalPages())
}

func protoUsers(users []iamsdk.User) []*platformv1.IAMUser {
	out := make([]*platformv1.IAMUser, 0, len(users))
	for i := range users {
		out = append(out, UserToProto(&users[i]))
	}
	return out
}
