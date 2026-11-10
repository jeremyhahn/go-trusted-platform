package iam

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// listUsersFilterCall is the filters the handler passed to the IAM client.
type listUsersFilterCall struct {
	email string
	role  string
	group string
}

// filteringUserList returns an IAM client whose user list applies the
// request's filters to two users of tenant-a, the way the backend does, and
// records the filters of every request it was given.
func filteringUserList(got *[]listUsersFilterCall) *mockIAMClient {
	users := []iamsdk.User{
		{ID: "user-alice", TenantID: "tenant-a", Email: "alice@example.com", Roles: []string{"role-admin"}, Groups: []string{"group-ops"}},
		{ID: "user-bob", TenantID: "tenant-a", Email: "bob@example.com", Roles: []string{"role-viewer"}, Groups: []string{"group-dev"}},
	}
	return &mockIAMClient{
		listUsersFn: func(_ context.Context, _ string, req *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			*got = append(*got, listUsersFilterCall{email: req.Filter, role: req.RoleID, group: req.GroupID})
			var matched []iamsdk.User
			for i := range users {
				u := &users[i]
				if req.Filter != "" && !strings.Contains(u.Email, req.Filter) {
					continue
				}
				if req.RoleID != "" && !slices.Contains(u.Roles, req.RoleID) {
					continue
				}
				if req.GroupID != "" && !slices.Contains(u.Groups, req.GroupID) {
					continue
				}
				matched = append(matched, *u)
			}
			return &iamsdk.ListUsersResponse{
				Users:      matched,
				Pagination: iamsdk.PaginationInfo{TotalCount: len(matched)},
			}, nil
		},
	}
}

// TestListUsersOverSDKREST_FiltersReachTheHandler drives the SDK's ListUsers
// with each filter through the SDK REST transport and the real IAM router,
// and checks the handler hands the filter to the IAM client, so the SDK
// caller gets the filtered list and not every user of the tenant.
func TestListUsersOverSDKREST_FiltersReachTheHandler(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		req     *platformv1.ListIAMUsersRequest
		want    listUsersFilterCall
		wantIDs []string
	}{
		{"email", &platformv1.ListIAMUsersRequest{TenantId: "tenant-a", EmailFilter: "alice@example.com"}, listUsersFilterCall{email: "alice@example.com"}, []string{"user-alice"}},
		{"role", &platformv1.ListIAMUsersRequest{TenantId: "tenant-a", RoleFilter: "role-viewer"}, listUsersFilterCall{role: "role-viewer"}, []string{"user-bob"}},
		{"group", &platformv1.ListIAMUsersRequest{TenantId: "tenant-a", GroupFilter: "group-ops"}, listUsersFilterCall{group: "group-ops"}, []string{"user-alice"}},
		{"all three", &platformv1.ListIAMUsersRequest{TenantId: "tenant-a", EmailFilter: "bob@example.com", RoleFilter: "role-viewer", GroupFilter: "group-dev"}, listUsersFilterCall{email: "bob@example.com", role: "role-viewer", group: "group-dev"}, []string{"user-bob"}},
		{"no filter", &platformv1.ListIAMUsersRequest{TenantId: "tenant-a"}, listUsersFilterCall{}, []string{"user-alice", "user-bob"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []listUsersFilterCall
			conn := sdkRESTConnection(t, adminSessionIAMServerIn(t, "tenant-a", filteringUserList(&got), &mockPEPClient{}))

			reply, err := platformv1.NewPlatformIAMServiceClient(conn).ListUsers(context.Background(), tc.req)
			require.NoError(t, err)

			var ids []string
			for _, u := range reply.GetUsers() {
				ids = append(ids, u.GetId())
			}
			require.Len(t, got, 1)
			assert.Equal(t, tc.want, got[0], "the handler must pass the SDK caller's filters to the IAM client")
			assert.Equal(t, tc.wantIDs, ids, "the SDK caller must get the filtered list")
			assert.Equal(t, int64(len(tc.wantIDs)), reply.GetTotal())
		})
	}
}
