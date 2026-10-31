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
	// The tenant-scoped collections and CheckPermission: the daemon's tenant
	// guard reads the tenant from the path, so it must not stay in the body.
	{
		name:       "CreateUser",
		grpcMethod: "/platform.v1.PlatformIAMService/CreateUser",
		req:        &platformv1.CreateIAMUserRequest{TenantId: "acme"},
		resp:       &platformv1.IAMUserResponse{},
		wantMethod: http.MethodPost,
		wantPath:   "/api/v1/iam/tenants/acme/users",
		stripped:   []string{"tenant_id"},
		zero:       &platformv1.CreateIAMUserRequest{},
	},
	{
		name:       "ListUsers",
		grpcMethod: "/platform.v1.PlatformIAMService/ListUsers",
		req:        &platformv1.ListIAMUsersRequest{TenantId: "acme"},
		resp:       &platformv1.ListIAMUsersResponse{},
		wantMethod: http.MethodGet,
		wantPath:   "/api/v1/iam/tenants/acme/users",
		stripped:   []string{"tenant_id"},
		zero:       &platformv1.ListIAMUsersRequest{},
	},
	{
		name:       "CreateRole",
		grpcMethod: "/platform.v1.PlatformIAMService/CreateRole",
		req:        &platformv1.CreateIAMRoleRequest{TenantId: "acme"},
		resp:       &platformv1.IAMRoleResponse{},
		wantMethod: http.MethodPost,
		wantPath:   "/api/v1/iam/tenants/acme/roles",
		stripped:   []string{"tenant_id"},
		zero:       &platformv1.CreateIAMRoleRequest{},
	},
	{
		name:       "ListRoles",
		grpcMethod: "/platform.v1.PlatformIAMService/ListRoles",
		req:        &platformv1.ListIAMRolesRequest{TenantId: "acme"},
		resp:       &platformv1.ListIAMRolesResponse{},
		wantMethod: http.MethodGet,
		wantPath:   "/api/v1/iam/tenants/acme/roles",
		stripped:   []string{"tenant_id"},
		zero:       &platformv1.ListIAMRolesRequest{},
	},
	{
		name:       "CreateGroup",
		grpcMethod: "/platform.v1.PlatformIAMService/CreateGroup",
		req:        &platformv1.CreateIAMGroupRequest{TenantId: "acme"},
		resp:       &platformv1.IAMGroupResponse{},
		wantMethod: http.MethodPost,
		wantPath:   "/api/v1/iam/tenants/acme/groups",
		stripped:   []string{"tenant_id"},
		zero:       &platformv1.CreateIAMGroupRequest{},
	},
	{
		name:       "ListGroups",
		grpcMethod: "/platform.v1.PlatformIAMService/ListGroups",
		req:        &platformv1.ListIAMGroupsRequest{TenantId: "acme"},
		resp:       &platformv1.ListIAMGroupsResponse{},
		wantMethod: http.MethodGet,
		wantPath:   "/api/v1/iam/tenants/acme/groups",
		stripped:   []string{"tenant_id"},
		zero:       &platformv1.ListIAMGroupsRequest{},
	},
	{
		name:       "CheckPermission",
		grpcMethod: "/platform.v1.PlatformIAMService/CheckPermission",
		req:        &platformv1.CheckIAMPermissionRequest{TenantId: "acme"},
		resp:       &platformv1.CheckIAMPermissionResponse{},
		wantMethod: http.MethodPost,
		wantPath:   "/api/v1/iam/tenants/acme/permissions/check",
		stripped:   []string{"tenant_id"},
		zero:       &platformv1.CheckIAMPermissionRequest{},
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

// iamAdapterReplying returns an adapter whose requests are served in memory
// by handler, through the fake round tripper: no port is bound.
func iamAdapterReplying(t *testing.T, handler http.HandlerFunc) *Adapter {
	t.Helper()
	a, err := NewWithRoundTripper("https://daemon.invalid", handlerTransport{handler: handler}, "tok")
	if err != nil {
		t.Fatalf("NewWithRoundTripper: %v", err)
	}
	return a
}

// TestIAMItemOperations_ReplyCarriesTheDecodedResource pins the success path
// of the tenant-scoped item updates: the request leaves on the item route,
// and the daemon's resource payload lands in the reply's resource field.
func TestIAMItemOperations_ReplyCarriesTheDecodedResource(t *testing.T) {
	tests := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
		payload    string
		wantPath   string
		want       proto.Message
	}{
		{
			name:       "UpdateUser",
			grpcMethod: "/platform.v1.PlatformIAMService/UpdateUser",
			req:        &platformv1.UpdateIAMUserRequest{TenantId: "acme", UserId: "u-7", Email: "u7@example.test"},
			resp:       &platformv1.IAMUserResponse{},
			payload:    `{"id":"u-7","tenant_id":"acme","email":"u7@example.test"}`,
			wantPath:   "/api/v1/iam/tenants/acme/users/u-7",
			want: &platformv1.IAMUserResponse{User: &platformv1.IAMUser{
				Id: "u-7", TenantId: "acme", Email: "u7@example.test",
			}},
		},
		{
			name:       "UpdateRole",
			grpcMethod: "/platform.v1.PlatformIAMService/UpdateRole",
			req:        &platformv1.UpdateIAMRoleRequest{TenantId: "acme", RoleId: "r-2", Description: "ops"},
			resp:       &platformv1.IAMRoleResponse{},
			payload:    `{"id":"r-2","description":"ops"}`,
			wantPath:   "/api/v1/iam/tenants/acme/roles/r-2",
			want:       &platformv1.IAMRoleResponse{Role: &platformv1.IAMRole{Id: "r-2", Description: "ops"}},
		},
		{
			name:       "UpdateGroup",
			grpcMethod: "/platform.v1.PlatformIAMService/UpdateGroup",
			req:        &platformv1.UpdateIAMGroupRequest{TenantId: "acme", GroupId: "g-3", Name: "ops"},
			resp:       &platformv1.IAMGroupResponse{},
			payload:    `{"id":"g-3","name":"ops"}`,
			wantPath:   "/api/v1/iam/tenants/acme/groups/g-3",
			want:       &platformv1.IAMGroupResponse{Group: &platformv1.IAMGroup{Id: "g-3", Name: "ops"}},
		},
		{
			name:       "UpdateTenant",
			grpcMethod: "/platform.v1.PlatformIAMService/UpdateTenant",
			req:        &platformv1.UpdateIAMTenantRequest{TenantId: "acme-prod", Name: "Acme"},
			resp:       &platformv1.IAMTenantResponse{},
			payload:    `{"id":"acme-prod","name":"Acme"}`,
			wantPath:   "/api/v1/iam/tenants/acme-prod",
			want:       &platformv1.IAMTenantResponse{Tenant: &platformv1.IAMTenant{Id: "acme-prod", Name: "Acme"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod, gotPath string
			a := iamAdapterReplying(t, func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"success":true,"payload":` + tc.payload + `}`))
			})

			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if gotMethod != http.MethodPut {
				t.Errorf("method = %q, want %q", gotMethod, http.MethodPut)
			}
			if gotPath != tc.wantPath {
				t.Errorf("path = %q, want %q", gotPath, tc.wantPath)
			}
			if !proto.Equal(tc.resp, tc.want) {
				t.Errorf("reply = %v, want %v", tc.resp, tc.want)
			}
		})
	}
}

// TestIAMItemOperations_ServerErrorsSurfaceAsStatus pins the failure path of
// the tenant-scoped item routes: an HTTP error status and an undecodable
// resource payload each reach the caller as the gRPC code it maps to, and a
// DELETE refused with 409 (the item is still referenced) is a failed
// precondition rather than an abort.
func TestIAMItemOperations_ServerErrorsSurfaceAsStatus(t *testing.T) {
	tests := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
		httpStatus int
		body       string
		wantCode   codes.Code
	}{
		{
			name:       "DeleteRole still assigned",
			grpcMethod: "/platform.v1.PlatformIAMService/DeleteRole",
			req:        &platformv1.DeleteIAMRoleRequest{TenantId: "acme", RoleId: "r-2"},
			resp:       &platformv1.DeleteIAMRoleResponse{},
			httpStatus: http.StatusConflict,
			body:       `{"success":false,"error":"role is assigned"}`,
			wantCode:   codes.FailedPrecondition,
		},
		{
			name:       "DeleteUser unknown",
			grpcMethod: "/platform.v1.PlatformIAMService/DeleteUser",
			req:        &platformv1.DeleteIAMUserRequest{TenantId: "acme", UserId: "u-404"},
			resp:       &platformv1.DeleteIAMUserResponse{},
			httpStatus: http.StatusNotFound,
			body:       `{"success":false,"error":"user not found"}`,
			wantCode:   codes.NotFound,
		},
		{
			name:       "UpdateGroup outside the caller's tenant",
			grpcMethod: "/platform.v1.PlatformIAMService/UpdateGroup",
			req:        &platformv1.UpdateIAMGroupRequest{TenantId: "other", GroupId: "g-3", Name: "ops"},
			resp:       &platformv1.IAMGroupResponse{},
			httpStatus: http.StatusForbidden,
			body:       `{"success":false,"error":"tenant mismatch"}`,
			wantCode:   codes.PermissionDenied,
		},
		{
			name:       "UpdateUser undecodable resource",
			grpcMethod: "/platform.v1.PlatformIAMService/UpdateUser",
			req:        &platformv1.UpdateIAMUserRequest{TenantId: "acme", UserId: "u-7", Email: "u7@example.test"},
			resp:       &platformv1.IAMUserResponse{},
			httpStatus: http.StatusOK,
			body:       `{"success":true,"payload":{"id":7}}`,
			wantCode:   codes.Internal,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := iamAdapterReplying(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.httpStatus)
				_, _ = w.Write([]byte(tc.body))
			})

			err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("error %v (%T) carries no gRPC status", err, err)
			}
			if st.Code() != tc.wantCode {
				t.Errorf("code = %v, want %v (message %q)", st.Code(), tc.wantCode, st.Message())
			}
		})
	}
}
