//go:build integration

package iam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRESTAdapterDecode checks that the adapter unwraps the
// {"code","error","success","payload"} envelope the IAM REST handlers write
// for user, group and role Create/Get/Update.
func TestRESTAdapterDecode(t *testing.T) {
	const tenant = "system"
	user := map[string]interface{}{"id": "u-1", "tenant_id": tenant, "email": "u1@example.com", "name": "User One"}
	group := map[string]interface{}{"id": "g-1", "tenant_id": tenant, "name": "Group One"}
	role := map[string]interface{}{"id": "r-1", "tenant_id": tenant, "name": "Role One"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload interface{}
		switch {
		case strings.Contains(r.URL.Path, "/users"):
			payload = user
		case strings.Contains(r.URL.Path, "/groups"):
			payload = group
		case strings.Contains(r.URL.Path, "/roles"):
			payload = role
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusOK,
			"error":   "",
			"success": true,
			"payload": payload,
		})
	}))
	defer srv.Close()

	a := &RESTAdapter{endpoint: srv.URL, client: srv.Client()}
	ctx := context.Background()

	checkUser := func(t *testing.T, got *User) {
		t.Helper()
		if got.ID != "u-1" || got.TenantID != tenant || got.Email != "u1@example.com" {
			t.Fatalf("user did not round-trip: got ID=%q TenantID=%q Email=%q", got.ID, got.TenantID, got.Email)
		}
	}
	checkNamed := func(t *testing.T, kind, gotID, gotName, wantID, wantName string) {
		t.Helper()
		if gotID != wantID || gotName != wantName {
			t.Fatalf("%s did not round-trip: got ID=%q Name=%q, want ID=%q Name=%q", kind, gotID, gotName, wantID, wantName)
		}
	}

	t.Run("CreateUser", func(t *testing.T) {
		res, err := a.CreateUser(ctx, CreateUserOptions{TenantID: tenant, Email: "u1@example.com"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		checkUser(t, res.User)
	})
	t.Run("GetUser", func(t *testing.T) {
		res, err := a.GetUser(ctx, GetUserOptions{TenantID: tenant, UserID: "u-1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		checkUser(t, res.User)
	})
	t.Run("UpdateUser", func(t *testing.T) {
		res, err := a.UpdateUser(ctx, UpdateUserOptions{TenantID: tenant, UserID: "u-1", Name: "User One"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		checkUser(t, res.User)
	})

	t.Run("CreateGroup", func(t *testing.T) {
		res, err := a.CreateGroup(ctx, CreateGroupOptions{TenantID: tenant, ID: "g-1", Name: "Group One"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		checkNamed(t, "group", res.Group.ID, res.Group.Name, "g-1", "Group One")
	})
	t.Run("GetGroup", func(t *testing.T) {
		res, err := a.GetGroup(ctx, GetGroupOptions{TenantID: tenant, GroupID: "g-1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		checkNamed(t, "group", res.Group.ID, res.Group.Name, "g-1", "Group One")
	})
	t.Run("UpdateGroup", func(t *testing.T) {
		res, err := a.UpdateGroup(ctx, UpdateGroupOptions{TenantID: tenant, GroupID: "g-1", Name: "Group One"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		checkNamed(t, "group", res.Group.ID, res.Group.Name, "g-1", "Group One")
	})

	t.Run("CreateRole", func(t *testing.T) {
		res, err := a.CreateRole(ctx, CreateRoleOptions{TenantID: tenant, ID: "r-1", Name: "Role One"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		checkNamed(t, "role", res.Role.ID, res.Role.Name, "r-1", "Role One")
	})
	t.Run("GetRole", func(t *testing.T) {
		res, err := a.GetRole(ctx, GetRoleOptions{TenantID: tenant, RoleID: "r-1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		checkNamed(t, "role", res.Role.ID, res.Role.Name, "r-1", "Role One")
	})
	t.Run("UpdateRole", func(t *testing.T) {
		res, err := a.UpdateRole(ctx, UpdateRoleOptions{TenantID: tenant, RoleID: "r-1", Name: "Role One"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		checkNamed(t, "role", res.Role.ID, res.Role.Name, "r-1", "Role One")
	})
}
