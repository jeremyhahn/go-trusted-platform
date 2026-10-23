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
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// tenantOwnerRole is the role the registration mirror gives a tenant owner
// (service.DefaultTenantOwnerRole).
const tenantOwnerRole = "admin"

// TestIAMTenantDefaultRoles_OwnerMirrorSucceeds is the #641 regression: a
// tenant created through the platform tenant API carries its default IAM
// roles, so the user the registration mirror creates there - an owner holding
// the admin role - is accepted and appears in the tenant's IAM user list.
// The tenant-unbound operator (CLI, Unix) creates it; every system-bound
// transport (REST, gRPC, QUIC, MCP) gets its documented cross-tenant refusal.
//
// The integration platformd's webservice listener has no WebAuthn configured,
// so WebAuthn registration itself cannot run here; this exercises the IAM operation the
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

	// The CLI and the Unix socket are the local operator, which is not bound
	// to a tenant, so they create the owner in the new tenant.
	operators := map[string]func() IAMCommands{
		"CLI":  func() IAMCommands { return NewCLIAdapter() },
		"Unix": func() IAMCommands { return NewUnixAdapter() },
	}
	for name, newAdapter := range operators {
		t.Run(name, func(t *testing.T) {
			adapter := newAdapter()
			helpers.RequireAdapterSetup(t, "iam", name, adapter.Setup(ctx))
			defer func() {
				_ = adapter.Teardown(ctx)
			}()
			testOwnerMirrorSucceeds(t, ctx, adapter, tenantID)
		})
	}

	// REST, gRPC, QUIC and MCP dial with the harness admin credential, which
	// is bound to the system tenant (helpers.HarnessTenantID). A tenant-bound
	// caller naming another tenant is refused, the system tenant included:
	// docs/iam/api.md §8 (tenant-binding table: REST 403 from
	// RequireOwnTenant; gRPC, QUIC and MCP PermissionDenied,
	// ErrIAMTenantForbidden) and docs/auth/architecture.md §6c (nothing relies
	// on a system admin reaching tenant data; RequireOwnTenant denies it).
	//
	// The harness has no credential bound to a tenant created here: its one
	// tenant-bound credential is pinned to helpers.ForeignTenantID, while the
	// platform tenant API assigns a fresh ID. The default roles are proven
	// by the operator subtests above.
	operator := NewUnixAdapter()
	helpers.RequireAdapterSetup(t, "iam", "Unix", operator.Setup(ctx))
	defer func() {
		_ = operator.Teardown(ctx)
	}()
	systemBound := map[string]struct {
		newAdapter func() IAMCommands
		refused    func(error) bool
	}{
		"REST": {func() IAMCommands { return NewRESTAdapter() }, isRESTForbidden},
		"gRPC": {func() IAMCommands { return NewGRPCAdapter() }, isGRPCPermissionDenied},
		"QUIC": {func() IAMCommands { return NewQUICAdapter() }, isQUICPermissionDenied},
		"MCP":  {func() IAMCommands { return NewMCPAdapter() }, isMCPPermissionDenied},
	}
	for name, transport := range systemBound {
		t.Run(name, func(t *testing.T) {
			adapter := transport.newAdapter()
			helpers.RequireAdapterSetup(t, "iam", name, adapter.Setup(ctx))
			defer func() {
				_ = adapter.Teardown(ctx)
			}()
			testOwnerMirrorRefused(t, ctx, adapter, operator, tenantID, transport.refused)
		})
	}
}

// testOwnerMirrorRefused asserts the system-tenant caller is refused creating
// the owner in another tenant with the transport's typed refusal, and that the
// operator finds no such user afterwards.
func testOwnerMirrorRefused(t *testing.T, ctx context.Context, adapter, operator IAMCommands, tenantID string, refused func(error) bool) {
	t.Helper()

	email := GenerateTestEmail("owner-" + uuid.New().String()[:8])
	_, err := adapter.CreateUser(ctx, CreateUserOptions{
		TenantID: tenantID,
		Email:    email,
		Name:     "Tenant Owner",
		Roles:    []string{tenantOwnerRole},
	})
	if err == nil {
		t.Fatalf("a system-tenant caller created a user in tenant %s", tenantID)
	}
	if !refused(err) {
		t.Fatalf("creating a user in tenant %s: want the cross-tenant refusal, got %v", tenantID, err)
	}

	listed, err := operator.ListUsers(ctx, ListUsersOptions{TenantID: tenantID, Limit: 100})
	if err != nil {
		t.Fatalf("the operator lists users in tenant %s: %v", tenantID, err)
	}
	for _, user := range listed.Users {
		if strings.EqualFold(user.Email, email) {
			t.Fatalf("a refused create left user %s in tenant %s", email, tenantID)
		}
	}
}

func isRESTForbidden(err error) bool {
	var restErr *RESTAdapterError
	return errors.As(err, &restErr) && restErr.StatusCode == http.StatusForbidden
}

func isGRPCPermissionDenied(err error) bool {
	return status.Code(err) == codes.PermissionDenied
}

func isQUICPermissionDenied(err error) bool {
	var quicErr ErrQUICStatus
	return errors.As(err, &quicErr) && quicErr.Status == quicwire.StatusPermissionDenied
}

func isMCPPermissionDenied(err error) bool {
	var mcpErr *MCPAdapterError
	return errors.As(err, &mcpErr) && mcpErr.Code == mcpwire.PermissionDenied
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
