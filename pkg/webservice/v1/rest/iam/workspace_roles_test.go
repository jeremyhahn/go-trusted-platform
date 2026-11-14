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
	"errors"
	"slices"
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
)

func TestWorkspaceRoleResolverReadsTheRolesOfTheWorkspaceUser(t *testing.T) {
	t.Parallel()
	var gotTenant, gotEmail string
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, tenantID, email string) (*iamsdk.User, error) {
			gotTenant, gotEmail = tenantID, email
			return &iamsdk.User{Email: email, Roles: []string{"member"}}, nil
		},
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if gotTenant != "workspace-a" || gotEmail != "operator@platform" {
		t.Fatalf("expected the workspace user to be looked up, got tenant %q email %q", gotTenant, gotEmail)
	}
	if !slices.Equal(roles, []string{"member"}) {
		t.Fatalf("expected the workspace roles, got %v", roles)
	}
}

func TestWorkspaceRoleResolverAnswersNoRolesForAPrincipalTheWorkspaceDoesNotHold(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: func(context.Context, string, string) (*iamsdk.User, error) {
			return nil, sdkerrors.NewNotFound("iam.user.get_by_email", "user not found")
		},
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "invited@platform")
	if err != nil {
		t.Fatalf("a principal the workspace does not hold must answer no roles, not an error: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("expected no roles, got %v", roles)
	}
}

func TestWorkspaceRoleResolverReturnsALookupFailure(t *testing.T) {
	t.Parallel()
	cause := errors.New("iam unavailable")
	client := &mockIAMClient{
		getByEmailFn: func(context.Context, string, string) (*iamsdk.User, error) {
			return nil, cause
		},
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
	if !errors.Is(err, cause) {
		t.Fatalf("expected the lookup failure to be returned, got %v", err)
	}
	if roles != nil {
		t.Fatalf("a failed lookup must grant no roles, got %v", roles)
	}
}

// TestWorkspaceRoleResolverPrincipalTellsAGoneUserFromOneWithoutRoles: a
// session refresh fails closed on a user IAM no longer holds, so Principal
// must tell that apart from a held user with no roles (#646).
func TestWorkspaceRoleResolverPrincipalTellsAGoneUserFromOneWithoutRoles(t *testing.T) {
	t.Parallel()
	cause := errors.New("iam unavailable")
	users := map[string]*iamsdk.User{
		"admin@platform": {Email: "admin@platform", Roles: []string{"admin"}},
		"plain@platform": {Email: "plain@platform"},
	}
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, tenantID, email string) (*iamsdk.User, error) {
			if email == "broken@platform" {
				return nil, cause
			}
			if user, ok := users[email]; ok && tenantID == "workspace-a" {
				return user, nil
			}
			return nil, sdkerrors.NewNotFound("iam.user.get_by_email", "user not found")
		},
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	ctx := context.Background()

	roles, found, err := resolver.Principal(ctx, "workspace-a", "admin@platform")
	if err != nil || !found || len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("held admin: got roles=%v found=%v err=%v", roles, found, err)
	}
	roles, found, err = resolver.Principal(ctx, "workspace-a", "plain@platform")
	if err != nil || !found || len(roles) != 0 {
		t.Fatalf("held user without roles: got roles=%v found=%v err=%v", roles, found, err)
	}
	for _, gone := range [][2]string{{"workspace-a", "gone@platform"}, {"workspace-b", "admin@platform"}} {
		roles, found, err = resolver.Principal(ctx, gone[0], gone[1])
		if err != nil || found || roles != nil {
			t.Fatalf("%s in %s is not held: got roles=%v found=%v err=%v", gone[1], gone[0], roles, found, err)
		}
	}
	roles, found, err = resolver.Principal(ctx, "workspace-a", "broken@platform")
	if !errors.Is(err, cause) || found || roles != nil {
		t.Fatalf("a failed lookup must be returned and grant nothing: got roles=%v found=%v err=%v", roles, found, err)
	}
}

// A workspace account IAM holds as suspended, disabled or locked cannot
// sign in to the workspace: FIDO2 authenticates the principal in the
// operating tenant, and the login driver then asks Roles for the
// workspace's roles, so Roles must refuse it with an error that aborts the
// login, as Principal refuses it at refresh. An active account keeps its
// roles (#646, Codex P1 on #1906).
func TestWorkspaceRoleResolverRolesRefusesAnInactiveWorkspaceAccount(t *testing.T) {
	t.Parallel()
	users := map[string]*iamsdk.User{
		"active@platform":    {Email: "active@platform", Roles: []string{"admin"}, Lifecycle: "active"},
		"suspended@platform": {Email: "suspended@platform", Roles: []string{"admin"}, Lifecycle: "suspended"},
		"disabled@platform":  {Email: "disabled@platform", Roles: []string{"admin"}, Lifecycle: "disabled"},
		"locked@platform":    {Email: "locked@platform", Roles: []string{"admin"}, Lifecycle: "locked"},
		"held@platform":      {Email: "held@platform", Roles: []string{"admin"}, Status: iamsdk.UserStatusSuspended},
	}
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, tenantID, email string) (*iamsdk.User, error) {
			if user, ok := users[email]; ok && tenantID == "workspace-a" {
				return user, nil
			}
			return nil, sdkerrors.NewNotFound("iam.user.get_by_email", "user not found")
		},
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	ctx := context.Background()

	roles, err := resolver.Roles(ctx, "workspace-a", "active@platform")
	if err != nil || len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("active account: got roles=%v err=%v", roles, err)
	}
	for _, subject := range []string{"suspended@platform", "disabled@platform", "locked@platform", "held@platform"} {
		roles, err = resolver.Roles(ctx, "workspace-a", subject)
		var inactive ErrInactiveAccount
		if !errors.As(err, &inactive) || roles != nil {
			t.Fatalf("%s must be refused: got roles=%v err=%v", subject, roles, err)
		}
		if inactive.TenantID != "workspace-a" || inactive.Subject != subject {
			t.Fatalf("%s: error names %q in %q", subject, inactive.Subject, inactive.TenantID)
		}
		_, found, perr := resolver.Principal(ctx, "workspace-a", subject)
		if perr != nil || found {
			t.Fatalf("%s: Principal must keep failing closed: found=%v err=%v", subject, found, perr)
		}
	}
}

func TestNewWorkspaceRoleResolverRefusesANilClient(t *testing.T) {
	t.Parallel()
	resolver, err := NewWorkspaceRoleResolver(nil)
	if !errors.As(err, new(ErrRoleResolverClientMissing)) {
		t.Fatalf("expected ErrRoleResolverClientMissing, got %v", err)
	}
	if resolver != nil {
		t.Fatalf("expected no resolver, got %+v", resolver)
	}
}
