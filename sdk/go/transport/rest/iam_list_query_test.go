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
	"net/url"
	"reflect"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestIAMListRoutes_ParametersTravelInTheQuery pins the query the IAM list
// routes send. The daemon's list handlers read limit, offset and the user
// filters from the query string only, so a field left in the GET body is
// silently ignored.
func TestIAMListRoutes_ParametersTravelInTheQuery(t *testing.T) {
	tests := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
		wantPath   string
		wantQuery  url.Values
	}{
		{
			name:       "ListUsers sends pagination and every filter",
			grpcMethod: "/platform.v1.PlatformIAMService/ListUsers",
			req: &platformv1.ListIAMUsersRequest{
				TenantId:    "tenant-a",
				Pagination:  &platformv1.PaginationRequest{Page: 1, PageSize: 10},
				EmailFilter: "alice@example.com",
				RoleFilter:  "role-1",
				GroupFilter: "group-1",
			},
			resp:     &platformv1.ListIAMUsersResponse{},
			wantPath: "/api/v1/iam/tenants/tenant-a/users",
			wantQuery: url.Values{
				"limit": {"10"},
				"email": {"alice@example.com"},
				"role":  {"role-1"},
				"group": {"group-1"},
			},
		},
		{
			name:       "ListRoles sends pagination",
			grpcMethod: "/platform.v1.PlatformIAMService/ListRoles",
			req: &platformv1.ListIAMRolesRequest{
				TenantId:   "tenant-a",
				Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 10},
			},
			resp:      &platformv1.ListIAMRolesResponse{},
			wantPath:  "/api/v1/iam/tenants/tenant-a/roles",
			wantQuery: url.Values{"limit": {"10"}},
		},
		{
			name:       "ListGroups sends pagination",
			grpcMethod: "/platform.v1.PlatformIAMService/ListGroups",
			req: &platformv1.ListIAMGroupsRequest{
				TenantId:   "tenant-a",
				Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 10},
			},
			resp:      &platformv1.ListIAMGroupsResponse{},
			wantPath:  "/api/v1/iam/tenants/tenant-a/groups",
			wantQuery: url.Values{"limit": {"10"}},
		},
		{
			name:       "no pagination and no filters sends no query",
			grpcMethod: "/platform.v1.PlatformIAMService/ListUsers",
			req:        &platformv1.ListIAMUsersRequest{TenantId: "tenant-a"},
			resp:       &platformv1.ListIAMUsersResponse{},
			wantPath:   "/api/v1/iam/tenants/tenant-a/users",
			wantQuery:  url.Values{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var captured struct {
				path  string
				query url.Values
				body  map[string]interface{}
			}
			a := iamAdapterReplying(t, func(w http.ResponseWriter, r *http.Request) {
				captured.path = r.URL.Path
				captured.query = r.URL.Query()
				_ = json.NewDecoder(r.Body).Decode(&captured.body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
			})

			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.path != tc.wantPath {
				t.Errorf("path = %q, want %q", captured.path, tc.wantPath)
			}
			if !reflect.DeepEqual(captured.query, tc.wantQuery) {
				t.Errorf("query = %v, want %v", captured.query, tc.wantQuery)
			}
			for _, field := range []string{
				"pagination",
				"email_filter", "emailFilter",
				"role_filter", "roleFilter",
				"group_filter", "groupFilter",
				"tenant_id", "tenantId",
			} {
				if _, has := captured.body[field]; has {
					t.Errorf("field %q travels in the body as well as the URL: %v", field, captured.body)
				}
			}
		})
	}
}

// TestIAMListRoutes_RefusePagesBeyondTheFirst pins that the adapter refuses
// a page past the first instead of sending it: the REST handlers apply the
// limit but not the offset to the IAM lookup, so page 3 would come back
// holding the records of page 1 under page 3's metadata.
func TestIAMListRoutes_RefusePagesBeyondTheFirst(t *testing.T) {
	tests := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
	}{
		{
			name:       "ListUsers",
			grpcMethod: "/platform.v1.PlatformIAMService/ListUsers",
			req: &platformv1.ListIAMUsersRequest{
				TenantId:   "tenant-a",
				Pagination: &platformv1.PaginationRequest{Page: 3, PageSize: 10},
			},
			resp: &platformv1.ListIAMUsersResponse{},
		},
		{
			name:       "ListRoles",
			grpcMethod: "/platform.v1.PlatformIAMService/ListRoles",
			req: &platformv1.ListIAMRolesRequest{
				TenantId:   "tenant-a",
				Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 10},
			},
			resp: &platformv1.ListIAMRolesResponse{},
		},
		{
			name:       "ListGroups",
			grpcMethod: "/platform.v1.PlatformIAMService/ListGroups",
			req: &platformv1.ListIAMGroupsRequest{
				TenantId:   "tenant-a",
				Pagination: &platformv1.PaginationRequest{Page: 3},
			},
			resp: &platformv1.ListIAMGroupsResponse{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			a := iamAdapterReplying(t, func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
			})

			err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp)
			if status.Code(err) != codes.Unimplemented {
				t.Fatalf("Invoke error = %v, want code %v", err, codes.Unimplemented)
			}
			if reached {
				t.Errorf("a page beyond the first reached the server")
			}
		})
	}
}
