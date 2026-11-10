// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestIAMListUsers_FiltersTravelInTheQuery: the daemon's user-list handler
// reads its filters from the query parameters email, role and group, never
// from the GET body, so the SDK must send each filter there. A filter left
// in the body is ignored and the caller gets the unfiltered list.
func TestIAMListUsers_FiltersTravelInTheQuery(t *testing.T) {
	cases := []struct {
		name string
		req  *platformv1.ListIAMUsersRequest
		want string
	}{
		{"email", &platformv1.ListIAMUsersRequest{TenantId: "tenant-a", EmailFilter: "alice@example.com"}, "email=alice%40example.com"},
		{"role", &platformv1.ListIAMUsersRequest{TenantId: "tenant-a", RoleFilter: "role-admin"}, "role=role-admin"},
		{"group", &platformv1.ListIAMUsersRequest{TenantId: "tenant-a", GroupFilter: "group-ops"}, "group=group-ops"},
		{"all three", &platformv1.ListIAMUsersRequest{TenantId: "tenant-a", EmailFilter: "alice@example.com", RoleFilter: "role-admin", GroupFilter: "group-ops"}, "email=alice%40example.com&group=group-ops&role=role-admin"},
		{"no filter", &platformv1.ListIAMUsersRequest{TenantId: "tenant-a"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured struct {
				path  string
				query url.Values
				body  map[string]interface{}
			}
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health/live" {
					captured.path = r.URL.Path
					captured.query = r.URL.Query()
					_ = json.NewDecoder(r.Body).Decode(&captured.body)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
			})

			err := a.Connection().Invoke(context.Background(), "/platform.v1.PlatformIAMService/ListUsers", tc.req, &platformv1.ListIAMUsersResponse{})
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.path != "/api/v1/iam/tenants/tenant-a/users" {
				t.Errorf("path = %q, want %q", captured.path, "/api/v1/iam/tenants/tenant-a/users")
			}
			if got := captured.query.Encode(); got != tc.want {
				t.Errorf("query = %q, want %q", got, tc.want)
			}
			for _, field := range []string{"email_filter", "emailFilter", "role_filter", "roleFilter", "group_filter", "groupFilter"} {
				if _, has := captured.body[field]; has {
					t.Errorf("filter %q travels in the body, where the handler does not read it: %v", field, captured.body)
				}
			}
		})
	}
}
