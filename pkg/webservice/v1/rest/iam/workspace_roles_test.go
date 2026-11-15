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

// IAM stores a user's roles as canonical role IDs, and built-in roles carry
// tenant-specific UUIDs, while the session guards compare role names. These
// IDs stand in for that: the fake listing below answers them on two pages.
const (
	adminRoleID    = "8f0c2a4e-1b7d-4c3a-9e55-0d6f1a2b3c4d"
	operatorRoleID = "3c9d7e1f-5a2b-4f60-8d1e-7b6a5c4d3e2f"
	memberRoleID   = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
)

// workspaceRoleListing returns a ListRoles fake that pages the workspace's
// roles (a built-in admin on the first page, a custom operator and member on
// the second) and counts its calls. It refuses a request that leaves out the
// system roles or names another tenant.
func workspaceRoleListing(t *testing.T, calls *int) func(context.Context, string, *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
	t.Helper()
	return func(_ context.Context, tenantID string, req *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
		if calls != nil {
			*calls++
		}
		if tenantID != "workspace-a" || req == nil || !req.IncludeSystem {
			return nil, errors.New("role listing must name the workspace and include the system roles")
		}
		if req.PageToken == "" {
			return &iamsdk.ListRolesResponse{
				Roles:      []iamsdk.Role{{ID: adminRoleID, Name: "admin"}},
				Pagination: iamsdk.PaginationInfo{HasMore: true, NextPageToken: "p2"},
			}, nil
		}
		return &iamsdk.ListRolesResponse{Roles: []iamsdk.Role{
			{ID: operatorRoleID, Name: "operator"},
			{ID: memberRoleID, Name: "member"},
		}}, nil
	}
}

// A user stored with role IDs answers the role names the session guards
// check, from both Roles (login) and Principal (refresh), across pages of the
// role listing (#646, Codex P1 on #1906).
func TestWorkspaceRoleResolverAnswersRoleNamesForStoredRoleIDs(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{adminRoleID, operatorRoleID}}, nil
		},
		listRolesFn: workspaceRoleListing(t, nil),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	ctx := context.Background()

	roles, err := resolver.Roles(ctx, "workspace-a", "admin@platform")
	if err != nil || !slices.Equal(roles, []string{"admin", "operator"}) {
		t.Fatalf("Roles: got %v err=%v, want [admin operator]", roles, err)
	}
	roles, found, err := resolver.Principal(ctx, "workspace-a", "admin@platform")
	if err != nil || !found || !slices.Equal(roles, []string{"admin", "operator"}) {
		t.Fatalf("Principal: got %v found=%v err=%v, want [admin operator]", roles, found, err)
	}
}

// A role the user already holds by name stays as it is.
func TestWorkspaceRoleResolverKeepsARoleGivenByName(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{"admin", memberRoleID}}, nil
		},
		listRolesFn: workspaceRoleListing(t, nil),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	roles, found, err := resolver.Principal(context.Background(), "workspace-a", "admin@platform")
	if err != nil || !found || !slices.Equal(roles, []string{"admin", "member"}) {
		t.Fatalf("Principal: got %v found=%v err=%v, want [admin member]", roles, found, err)
	}
}

// A role reference the workspace's role listing does not hold is an error,
// never a guessed name.
func TestWorkspaceRoleResolverRefusesARoleTheWorkspaceDoesNotHold(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{adminRoleID, "0e0e0e0e-dead-4bee-8f00-123456789abc"}}, nil
		},
		listRolesFn: workspaceRoleListing(t, nil),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	ctx := context.Background()
	roles, found, err := resolver.Principal(ctx, "workspace-a", "admin@platform")
	if err == nil || found || roles != nil {
		t.Fatalf("Principal: an unknown role must fail: got %v found=%v err=%v", roles, found, err)
	}
	roles, err = resolver.Roles(ctx, "workspace-a", "admin@platform")
	if err == nil || roles != nil {
		t.Fatalf("Roles: an unknown role must fail: got %v err=%v", roles, err)
	}
}

// A role listing failure is returned from both lookups and grants nothing.
func TestWorkspaceRoleResolverReturnsARoleListingFailure(t *testing.T) {
	t.Parallel()
	cause := errors.New("role listing unavailable")
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{adminRoleID}}, nil
		},
		listRolesFn: func(context.Context, string, *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
			return nil, cause
		},
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	ctx := context.Background()
	roles, err := resolver.Roles(ctx, "workspace-a", "admin@platform")
	if !errors.Is(err, cause) || roles != nil {
		t.Fatalf("Roles: got %v err=%v, want the listing failure", roles, err)
	}
	roles, found, err := resolver.Principal(ctx, "workspace-a", "admin@platform")
	if !errors.Is(err, cause) || found || roles != nil {
		t.Fatalf("Principal: got %v found=%v err=%v, want the listing failure", roles, found, err)
	}
}

// A user with no roles costs no role listing.
func TestWorkspaceRoleResolverListsNoRolesForAUserWithoutRoles(t *testing.T) {
	t.Parallel()
	calls := 0
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email}, nil
		},
		listRolesFn: workspaceRoleListing(t, &calls),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	roles, found, err := resolver.Principal(context.Background(), "workspace-a", "plain@platform")
	if err != nil || !found || len(roles) != 0 || calls != 0 {
		t.Fatalf("got %v found=%v err=%v listings=%d, want no roles and no listing", roles, found, err, calls)
	}
}

func TestWorkspaceRoleResolverReadsTheRolesOfTheWorkspaceUser(t *testing.T) {
	t.Parallel()
	var gotTenant, gotEmail string
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, tenantID, email string) (*iamsdk.User, error) {
			gotTenant, gotEmail = tenantID, email
			return &iamsdk.User{Email: email, Roles: []string{memberRoleID}}, nil
		},
		listRolesFn: workspaceRoleListing(t, nil),
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
		"admin@platform": {Email: "admin@platform", Roles: []string{adminRoleID}},
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
		listRolesFn: workspaceRoleListing(t, nil),
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
		"active@platform":    {Email: "active@platform", Roles: []string{adminRoleID}, Lifecycle: "active"},
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
		listRolesFn: workspaceRoleListing(t, nil),
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
