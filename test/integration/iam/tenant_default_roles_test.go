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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// tenantOwnerRole is the role the registration mirror gives a tenant owner
// (service.DefaultTenantOwnerRole).
const tenantOwnerRole = "admin"

// TestIAMTenantDefaultRoles_OwnerMirrorSucceeds is the #641 regression: an
// IAM tenant carries its default IAM roles, so the user the registration
// mirror creates there - an owner holding the admin role - is accepted and
// appears in the tenant's IAM user list, on every protocol.
//
// REST, gRPC, QUIC and MCP act as the caller bound to helpers.ForeignTenantID
// by the harness tenant credential: the server refuses a tenant-bound caller,
// the system tenant included, on another tenant's IAM data (go-qrdb #683), so
// a tenant-bound caller can only show this in its own tenant. The CLI and the
// Unix socket are the unbound operator. The Unix operator creates the IAM
// tenant first, through the CreateTenant rpc that provisions the default roles.
//
// The integration platformd runs without webservices, so WebAuthn
// registration itself cannot run here; this exercises the IAM operation the
// mirror performs.
func TestIAMTenantDefaultRoles_OwnerMirrorSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	operator := NewUnixAdapter()
	helpers.RequireAdapterSetup(t, "iam", "Unix", operator.Setup(ctx))
	defer func() {
		_ = operator.Teardown(ctx)
	}()
	tenantID := helpers.ForeignTenantID
	helpers.EnsureIAMTenant(t, ctx, operator.client, tenantID)

	adapters := map[string]func() IAMCommands{
		"CLI":  func() IAMCommands { return NewCLIAdapter() },
		"REST": func() IAMCommands { return NewTenantRESTAdapter() },
		"gRPC": func() IAMCommands { return NewTenantGRPCAdapter() },
		"QUIC": func() IAMCommands { return NewTenantQUICAdapter() },
		"MCP":  func() IAMCommands { return NewTenantMCPAdapter() },
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
		t.Fatalf("CreateUser with role %q in tenant %q failed (default roles missing?): %v", tenantOwnerRole, tenantID, err)
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
