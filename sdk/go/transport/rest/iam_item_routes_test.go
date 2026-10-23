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

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// iamItemOperations are the PlatformIAMService item rows #416 repairs. Each
// used to send a COLLECTION path (DELETE /api/v1/iam/users, POST
// /api/v1/iam/roles/assign, ...) that the server either 404s or, worse,
// routes to a sibling handler; the server's real route is an ITEM path with
// the identifiers in it (pkg/webservice/v1/rest/iam/router.go). #379's shape
// on the mutating verbs, found by #400's fixture. The four updates had no row
// at all and fell back to a /api/v1/platformiam/... path nothing serves
// (#401). All but the two tenant records are on the tenant-scoped tree,
// tenant_id in the path (#401).
var iamItemOperations = []struct {
	name       string
	grpcMethod string
	req        proto.Message
	resp       proto.Message
	wantMethod string
	wantPath   string
	stripped   []string // proto JSON field names that must leave the body for the path
	zero       proto.Message
}{
	{
		name:       "DeleteUser",
		grpcMethod: "/platform.v1.PlatformIAMService/DeleteUser",
		req:        &platformv1.DeleteIAMUserRequest{TenantId: "acme", UserId: "u-7"},
		resp:       &platformv1.DeleteIAMUserResponse{},
		wantMethod: http.MethodDelete,
		wantPath:   "/api/v1/iam/tenants/acme/users/u-7",
		stripped:   []string{"tenant_id", "user_id"},
		zero:       &platformv1.DeleteIAMUserRequest{TenantId: "acme"},
	},
	{
		name:       "DeleteRole",
		grpcMethod: "/platform.v1.PlatformIAMService/DeleteRole",
		req:        &platformv1.DeleteIAMRoleRequest{TenantId: "acme", RoleId: "r-2"},
		resp:       &platformv1.DeleteIAMRoleResponse{},
		wantMethod: http.MethodDelete,
		wantPath:   "/api/v1/iam/tenants/acme/roles/r-2",
		stripped:   []string{"tenant_id", "role_id"},
		zero:       &platformv1.DeleteIAMRoleRequest{TenantId: "acme"},
	},
	{
		name:       "DeleteGroup",
		grpcMethod: "/platform.v1.PlatformIAMService/DeleteGroup",
		req:        &platformv1.DeleteIAMGroupRequest{TenantId: "acme", GroupId: "g-3"},
		resp:       &platformv1.DeleteIAMGroupResponse{},
		wantMethod: http.MethodDelete,
		wantPath:   "/api/v1/iam/tenants/acme/groups/g-3",
		stripped:   []string{"tenant_id", "group_id"},
		zero:       &platformv1.DeleteIAMGroupRequest{TenantId: "acme"},
	},
	{
		name:       "DeleteTenant",
		grpcMethod: "/platform.v1.PlatformIAMService/DeleteTenant",
		req:        &platformv1.DeleteIAMTenantRequest{TenantId: "acme-prod"},
		resp:       &platformv1.DeleteIAMTenantResponse{},
		wantMethod: http.MethodDelete,
		wantPath:   "/api/v1/iam/tenants/acme-prod",
		stripped:   []string{"tenant_id"},
		zero:       &platformv1.DeleteIAMTenantRequest{},
	},
	{
		name:       "AssignRole",
		grpcMethod: "/platform.v1.PlatformIAMService/AssignRole",
		req:        &platformv1.AssignIAMRoleRequest{TenantId: "acme", UserId: "u-7", RoleId: "r-2"},
		resp:       &platformv1.AssignIAMRoleResponse{},
		wantMethod: http.MethodPost,
		wantPath:   "/api/v1/iam/tenants/acme/users/u-7/roles/r-2",
		stripped:   []string{"tenant_id", "user_id", "role_id"},
		zero:       &platformv1.AssignIAMRoleRequest{TenantId: "acme", UserId: "u-7"},
	},
	{
		name:       "RevokeRole",
		grpcMethod: "/platform.v1.PlatformIAMService/RevokeRole",
		req:        &platformv1.RevokeIAMRoleRequest{TenantId: "acme", UserId: "u-7", RoleId: "r-2"},
		resp:       &platformv1.RevokeIAMRoleResponse{},
		wantMethod: http.MethodDelete,
		wantPath:   "/api/v1/iam/tenants/acme/users/u-7/roles/r-2",
		stripped:   []string{"tenant_id", "user_id", "role_id"},
		zero:       &platformv1.RevokeIAMRoleRequest{TenantId: "acme", RoleId: "r-2"},
	},
	{
		name:       "AddGroupMember",
		grpcMethod: "/platform.v1.PlatformIAMService/AddGroupMember",
		req:        &platformv1.AddGroupMemberRequest{TenantId: "acme", GroupId: "g-3", UserId: "u-7"},
		resp:       &platformv1.AddGroupMemberResponse{},
		wantMethod: http.MethodPost,
		wantPath:   "/api/v1/iam/tenants/acme/groups/g-3/members/u-7",
		stripped:   []string{"tenant_id", "group_id", "user_id"},
		zero:       &platformv1.AddGroupMemberRequest{TenantId: "acme", GroupId: "g-3"},
	},
	{
		name:       "UpdateUser",
		grpcMethod: "/platform.v1.PlatformIAMService/UpdateUser",
		req:        &platformv1.UpdateIAMUserRequest{TenantId: "acme", UserId: "u-7", Email: "u7@example.test"},
		resp:       &platformv1.IAMUserResponse{},
		wantMethod: http.MethodPut,
		wantPath:   "/api/v1/iam/tenants/acme/users/u-7",
		stripped:   []string{"tenant_id", "user_id"},
		zero:       &platformv1.UpdateIAMUserRequest{TenantId: "acme", Email: "u7@example.test"},
	},
	{
		name:       "UpdateRole",
		grpcMethod: "/platform.v1.PlatformIAMService/UpdateRole",
		req:        &platformv1.UpdateIAMRoleRequest{TenantId: "acme", RoleId: "r-2", Description: "ops"},
		resp:       &platformv1.IAMRoleResponse{},
		wantMethod: http.MethodPut,
		wantPath:   "/api/v1/iam/tenants/acme/roles/r-2",
		stripped:   []string{"tenant_id", "role_id"},
		zero:       &platformv1.UpdateIAMRoleRequest{TenantId: "acme", Description: "ops"},
	},
	{
		name:       "UpdateGroup",
		grpcMethod: "/platform.v1.PlatformIAMService/UpdateGroup",
		req:        &platformv1.UpdateIAMGroupRequest{TenantId: "acme", GroupId: "g-3", Name: "ops"},
		resp:       &platformv1.IAMGroupResponse{},
		wantMethod: http.MethodPut,
		wantPath:   "/api/v1/iam/tenants/acme/groups/g-3",
		stripped:   []string{"tenant_id", "group_id"},
		zero:       &platformv1.UpdateIAMGroupRequest{TenantId: "acme", Name: "ops"},
	},
	{
		name:       "UpdateTenant",
		grpcMethod: "/platform.v1.PlatformIAMService/UpdateTenant",
		req:        &platformv1.UpdateIAMTenantRequest{TenantId: "acme-prod", Name: "Acme"},
		resp:       &platformv1.IAMTenantResponse{},
		wantMethod: http.MethodPut,
		wantPath:   "/api/v1/iam/tenants/acme-prod",
		stripped:   []string{"tenant_id"},
		zero:       &platformv1.UpdateIAMTenantRequest{Name: "Acme"},
	},
}

// TestIAMItemOperations_IdentifiersTravelInThePath asserts, per row, the
// method and item path the server registers, and that every identifier left
// the body for the path.
func TestIAMItemOperations_IdentifiersTravelInThePath(t *testing.T) {
	for _, tc := range iamItemOperations {
		t.Run(tc.name, func(t *testing.T) {
			var captured struct {
				method string
				path   string
				body   map[string]interface{}
			}
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				captured.method = r.Method
				captured.path = r.URL.Path
				_ = json.NewDecoder(r.Body).Decode(&captured.body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
			})

			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.method != tc.wantMethod {
				t.Errorf("method = %q, want %q", captured.method, tc.wantMethod)
			}
			if captured.path != tc.wantPath {
				t.Errorf("path = %q, want %q", captured.path, tc.wantPath)
			}
			for _, field := range tc.stripped {
				if _, has := captured.body[field]; has {
					t.Errorf("identifier %q travels in the body as well as the path: %v", field, captured.body)
				}
			}
		})
	}
}

// TestIAMItemOperations_MissingIdentifierRejectedBeforeTheWire: with an
// identifier empty the request must not leave the client. The collection-path
// rows produced a shorter, valid-looking URL instead (DELETE /iam/users with
// no id; POST /iam/groups/members routed to DeleteGroup(id="members") in the
// RemoveGroupMember case, #415); a placeholder left unfilled must be an
// error, never a different route.
func TestIAMItemOperations_MissingIdentifierRejectedBeforeTheWire(t *testing.T) {
	for _, tc := range iamItemOperations {
		t.Run(tc.name, func(t *testing.T) {
			var apiHits int
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health/live" {
					apiHits++
				}
				w.WriteHeader(http.StatusOK)
			})

			err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.zero, tc.resp)
			if err == nil {
				t.Fatal("expected an error for the missing identifier, got nil")
			}
			if st, _ := status.FromError(err); st == nil || st.Code() != codes.InvalidArgument {
				t.Errorf("status = %v, want InvalidArgument", st)
			}
			if apiHits != 0 {
				t.Errorf("server saw %d API hits; want 0 -- the request must not leave the client", apiHits)
			}
		})
	}
}
