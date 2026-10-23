//go:build integration

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

package iam

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// tenantOwnerRole is the role the registration mirror gives a tenant owner
// (service.DefaultTenantOwnerRole).
const tenantOwnerRole = "admin"

// TestIAMTenantDefaultRoles_OwnerMirrorSucceeds is the #641 regression: a
// tenant created through the platform tenant API carries its default IAM
// roles, so the user the registration mirror creates there - an owner holding
// the admin role - is accepted and appears in the tenant's IAM user list, on
// every protocol.
//
// The integration platformd runs without webservices, so WebAuthn
// registration itself cannot run here; this exercises the IAM operation the
// mirror performs, on a tenant created the way registration creates one.
func TestIAMTenantDefaultRoles_OwnerMirrorSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rest := NewRESTAdapter()
	helpers.RequireAdapterSetup(t, "iam", "REST", rest.Setup(ctx))
	defer func() {
		_ = rest.Teardown(ctx)
	}()
	tenantID := createPlatformTenant(t, ctx, rest)

	adapters := map[string]func() IAMCommands{
		"CLI":  func() IAMCommands { return NewCLIAdapter() },
		"REST": func() IAMCommands { return NewRESTAdapter() },
		"gRPC": func() IAMCommands { return NewGRPCAdapter() },
		"QUIC": func() IAMCommands { return NewQUICAdapter() },
		"MCP":  func() IAMCommands { return NewMCPAdapter() },
		"Unix": func() IAMCommands { return NewUnixAdapter() },
	}
	for name, newAdapter := range adapters {
		t.Run(name, func(t *testing.T) {
			adapter := newAdapter()
			helpers.RequireAdapterSetup(t, "iam", name, adapter.Setup(ctx))
			defer func() {
				_ = adapter.Teardown(ctx)
			}()
			testOwnerMirrorSucceeds(t, ctx, adapter, tenantID)
		})
	}
}

// testOwnerMirrorSucceeds creates an admin-role user in tenantID, as the
// registration mirror does, and expects to find it in the IAM user list.
func testOwnerMirrorSucceeds(t *testing.T, ctx context.Context, adapter IAMCommands, tenantID string) {
	email := GenerateTestEmail("owner-" + uuid.New().String()[:8])

	created, err := adapter.CreateUser(ctx, CreateUserOptions{
		TenantID: tenantID,
		Email:    email,
		Name:     "Tenant Owner",
		Roles:    []string{tenantOwnerRole},
	})
	if err != nil {
		t.Fatalf("CreateUser with role %q in a new platform tenant failed (default roles missing?): %v", tenantOwnerRole, err)
	}

	listed, err := adapter.ListUsers(ctx, ListUsersOptions{TenantID: tenantID, Limit: 100})
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	for _, user := range listed.Users {
		if strings.EqualFold(user.Email, email) {
			if user.ID != created.User.ID {
				t.Errorf("listed user ID = %s, want %s", user.ID, created.User.ID)
			}
			return
		}
	}
	t.Fatalf("user %s is missing from the IAM users of tenant %s (%d listed)", email, tenantID, len(listed.Users))
}

// createPlatformTenant creates a tenant through the platform tenant API -
// the tenant.Manager path that provisions the default IAM roles - and deletes
// it when the test ends.
func createPlatformTenant(t *testing.T, ctx context.Context, adapter *RESTAdapter) string {
	t.Helper()

	request := map[string]string{"name": "iam-roles-" + uuid.New().String()[:8]}
	body, err := adapter.doRequest(ctx, http.MethodPost, "/api/v1/tenants", request)
	if err != nil {
		t.Fatalf("creating a platform tenant failed: %v", err)
	}

	var tenant struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &tenant); err != nil || tenant.ID == "" {
		t.Fatalf("unexpected create tenant response %q: %v", body, err)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := adapter.doRequest(cleanupCtx, http.MethodDelete, "/api/v1/tenants/"+tenant.ID, nil); err != nil {
			t.Logf("deleting tenant %s failed: %v", tenant.ID, err)
		}
	})
	return tenant.ID
}
