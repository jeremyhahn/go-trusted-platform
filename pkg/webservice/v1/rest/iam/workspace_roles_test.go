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
	"fmt"
	"slices"
	"strings"
	"testing"

	quicbaasiam "github.com/jeremyhahn/go-quicbaas/pkg/iam"
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

// workspaceRoleCount is the number of roles the fake workspace holds: more
// than one ListRoles page, so a resolver that reads only the first page of the
// listing misses the roles past it.
const workspaceRoleCount = 150

// lateRoleID is the ID of role number 140 of the fake workspace, beyond the
// first page of a 100-role listing.
const lateRoleID = "00000000-0000-4000-8000-000000000140"

// workspaceRoles answers the roles of the fake workspace by ID: the three named
// roles plus workspaceRoleCount numbered ones ("role-<n>").
func workspaceRoles() map[string]string {
	roles := map[string]string{
		adminRoleID:    "admin",
		operatorRoleID: "operator",
		memberRoleID:   "member",
	}
	for i := 1; i <= workspaceRoleCount; i++ {
		roles[fmt.Sprintf("00000000-0000-4000-8000-%012d", i)] = fmt.Sprintf("role-%d", i)
	}
	return roles
}

// workspaceRoleLookup is a GetRole fake over workspaceRoles. It counts the
// lookups in calls (when not nil) and answers an ID the workspace does not
// hold with the SDK's not-found error.
func workspaceRoleLookup(t *testing.T, calls *int) func(context.Context, string, string) (*iamsdk.Role, error) {
	t.Helper()
	roles := workspaceRoles()
	return func(_ context.Context, tenantID, roleID string) (*iamsdk.Role, error) {
		if calls != nil {
			*calls++
		}
		if tenantID != "workspace-a" {
			return nil, errors.New("role lookup must name the workspace")
		}
		name, ok := roles[roleID]
		if !ok {
			return nil, sdkerrors.NewNotFound("iam.role.get", "role not found")
		}
		return &iamsdk.Role{ID: roleID, Name: name}, nil
	}
}

// noRoleListing fails the test if the resolver lists the workspace's roles:
// the listing answers only its first page, so the resolver must look each
// role up instead.
func noRoleListing(t *testing.T) func(context.Context, string, *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
	t.Helper()
	return func(context.Context, string, *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
		t.Errorf("the role resolver must not list the workspace's roles")
		return nil, errors.New("role listing called")
	}
}

// TestWorkspaceRoleResolverAnswersRoleNamesForStoredRoleIDs checks that the
// role IDs stored on a workspace user come back as the role names the session
// guards check.
func TestWorkspaceRoleResolverAnswersRoleNamesForStoredRoleIDs(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{adminRoleID, operatorRoleID}}, nil
		},
		getRoleFn:   workspaceRoleLookup(t, nil),
		listRolesFn: noRoleListing(t),
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

// TestWorkspaceRoleResolverNamesARoleBeyondTheFirstListingPage checks that a
// role past the first 100 of a 150-role workspace still resolves to its name,
// through GetRole and without listing the roles (Codex P1, #1906).
func TestWorkspaceRoleResolverNamesARoleBeyondTheFirstListingPage(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{lateRoleID}}, nil
		},
		getRoleFn:   workspaceRoleLookup(t, nil),
		listRolesFn: noRoleListing(t),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	ctx := context.Background()

	roles, err := resolver.Roles(ctx, "workspace-a", "late@platform")
	if err != nil || !slices.Equal(roles, []string{"role-140"}) {
		t.Fatalf("Roles: got %v err=%v, want [role-140]", roles, err)
	}
	roles, found, err := resolver.Principal(ctx, "workspace-a", "late@platform")
	if err != nil || !found || !slices.Equal(roles, []string{"role-140"}) {
		t.Fatalf("Principal: got %v found=%v err=%v, want [role-140]", roles, found, err)
	}
}

// TestWorkspaceRoleResolverKeepsARoleGivenByName checks that a reference that
// is already a role name is kept as it is, with no GetRole call for it.
func TestWorkspaceRoleResolverKeepsARoleGivenByName(t *testing.T) {
	t.Parallel()
	var lookups int
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{"admin", memberRoleID}}, nil
		},
		getRoleFn:   workspaceRoleLookup(t, &lookups),
		listRolesFn: noRoleListing(t),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	roles, found, err := resolver.Principal(context.Background(), "workspace-a", "admin@platform")
	if err != nil || !found || !slices.Equal(roles, []string{"admin", "member"}) {
		t.Fatalf("Principal: got %v found=%v err=%v, want [admin member]", roles, found, err)
	}
	if lookups != 1 {
		t.Fatalf("GetRole calls: got %d, want 1 (the role ID only, not the role name)", lookups)
	}
}

// TestWorkspaceRoleResolverRefusesARoleTheWorkspaceDoesNotHold checks that a
// stored role ID GetRole does not find fails the login with "holds no role".
func TestWorkspaceRoleResolverRefusesARoleTheWorkspaceDoesNotHold(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{adminRoleID, "0e0e0e0e-dead-4bee-8f00-123456789abc"}}, nil
		},
		getRoleFn:   workspaceRoleLookup(t, nil),
		listRolesFn: noRoleListing(t),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	ctx := context.Background()
	roles, found, err := resolver.Principal(ctx, "workspace-a", "admin@platform")
	if err == nil || found || roles != nil || !strings.Contains(err.Error(), "holds no role") {
		t.Fatalf("Principal: an unknown role must fail with holds no role: got %v found=%v err=%v", roles, found, err)
	}
	roles, err = resolver.Roles(ctx, "workspace-a", "admin@platform")
	if err == nil || roles != nil || !strings.Contains(err.Error(), "holds no role") {
		t.Fatalf("Roles: an unknown role must fail with holds no role: got %v err=%v", roles, err)
	}
}

// TestWorkspaceRoleResolverReturnsARoleLookupFailure checks that a GetRole
// failure other than not-found comes back as it is.
func TestWorkspaceRoleResolverReturnsARoleLookupFailure(t *testing.T) {
	t.Parallel()
	cause := errors.New("role lookup unavailable")
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{adminRoleID}}, nil
		},
		getRoleFn: func(context.Context, string, string) (*iamsdk.Role, error) {
			return nil, cause
		},
		listRolesFn: noRoleListing(t),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	ctx := context.Background()
	roles, err := resolver.Roles(ctx, "workspace-a", "admin@platform")
	if !errors.Is(err, cause) || roles != nil {
		t.Fatalf("Roles: got %v err=%v, want the lookup failure", roles, err)
	}
	roles, found, err := resolver.Principal(ctx, "workspace-a", "admin@platform")
	if !errors.Is(err, cause) || found || roles != nil {
		t.Fatalf("Principal: got %v found=%v err=%v, want the lookup failure", roles, found, err)
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
		getRoleFn:   workspaceRoleLookup(t, &calls),
		listRolesFn: noRoleListing(t),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	roles, found, err := resolver.Principal(context.Background(), "workspace-a", "plain@platform")
	if err != nil || !found || len(roles) != 0 || calls != 0 {
		t.Fatalf("got %v found=%v err=%v lookups=%d, want no roles and no lookup", roles, found, err, calls)
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
		getRoleFn:   workspaceRoleLookup(t, nil),
		listRolesFn: noRoleListing(t),
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
		getRoleFn:   workspaceRoleLookup(t, nil),
		listRolesFn: noRoleListing(t),
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
		getRoleFn:   workspaceRoleLookup(t, nil),
		listRolesFn: noRoleListing(t),
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

// pagedRoles serves first on the first ListRoles page and second on the page
// the first one's "p2" token names, the way IAM pages a tenant's roles; a
// non-nil err fails every call.
// Role IDs the GetRole and role-list tests below store on a user. IAM role
// IDs are UUIDs; a reference that is not one is a role name and is never
// looked up (TestWorkspaceRoleResolverKeepsARoleGivenByName).
const (
	ridadmin  = "7d1c6a52-3f4e-4b8a-9c21-0a6e5f3b2d11"
	ridmember = "7d1c6a52-3f4e-4b8a-9c21-0a6e5f3b2d12"
	ridops    = "7d1c6a52-3f4e-4b8a-9c21-0a6e5f3b2d13"
)

func pagedRoles(first, second []iamsdk.Role, err error) func(context.Context, string, *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
	return func(_ context.Context, _ string, req *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
		if err != nil {
			return nil, err
		}
		if req.PageToken == "p2" {
			return &iamsdk.ListRolesResponse{Roles: second}, nil
		}
		return &iamsdk.ListRolesResponse{
			Roles:      first,
			Pagination: iamsdk.PaginationInfo{HasMore: true, NextPageToken: "p2"},
		}, nil
	}
}

func TestWorkspaceRoleResolverNamesTheRolesIAMStoresByID(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{ridadmin}}, nil
		},
		getRoleFn: unroutedGetRole,
		listRolesFn: pagedRoles(
			[]iamsdk.Role{{ID: ridmember, Name: "member"}},
			[]iamsdk.Role{{ID: ridadmin, Name: "admin"}},
			nil,
		),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if !slices.Equal(roles, []string{"admin"}) {
		t.Fatalf("expected the stored role ID to be named admin, got %v", roles)
	}
}

func TestWorkspaceRoleResolverKeepsAReferenceNoRoleIDMatches(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{"admin"}}, nil
		},
		getRoleFn: unroutedGetRole,
		listRolesFn: pagedRoles(
			[]iamsdk.Role{{ID: ridmember, Name: "member"}},
			[]iamsdk.Role{{ID: ridadmin, Name: "admin"}},
			nil,
		),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if !slices.Equal(roles, []string{"admin"}) {
		t.Fatalf("expected a reference no role ID matches to be kept, got %v", roles)
	}
}

func TestWorkspaceRoleResolverReturnsARoleListFailure(t *testing.T) {
	t.Parallel()
	cause := errors.New("roles unavailable")
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{ridadmin}}, nil
		},
		getRoleFn:   unroutedGetRole,
		listRolesFn: pagedRoles(nil, nil, cause),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
	if err == nil {
		t.Fatalf("expected the role list failure to be returned, got roles %v", roles)
	}
	if len(roles) != 0 {
		t.Fatalf("a failed role list must grant no roles, got %v", roles)
	}
}

// unroutedGetRole answers GetRole the way a transport that does not route it
// does (the embedded one), so the resolver names roles from the role list.
func unroutedGetRole(context.Context, string, string) (*iamsdk.Role, error) {
	return nil, sdkerrors.NewUnimplemented("iam.role.get", "method not routed")
}

// failListRoles fails the test if the resolver reads the role list.
func failListRoles(t *testing.T) func(context.Context, string, *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
	t.Helper()
	return func(context.Context, string, *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
		t.Errorf("the resolver must name roles with GetRole, not ListRoles")
		return nil, errors.New("ListRoles called")
	}
}

func TestWorkspaceRoleResolverNamesEachRoleWithGetRole(t *testing.T) {
	t.Parallel()
	names := map[string]string{ridadmin: "admin", ridops: "ops"}
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{ridadmin, ridops}}, nil
		},
		getRoleFn: func(_ context.Context, _, id string) (*iamsdk.Role, error) {
			return &iamsdk.Role{ID: id, Name: names[id]}, nil
		},
		listRolesFn: failListRoles(t),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if !slices.Equal(roles, []string{"admin", "ops"}) {
		t.Fatalf("expected each role ID to be named with GetRole, got %v", roles)
	}
}

func TestWorkspaceRoleResolverKeepsAReferenceGetRoleDoesNotFind(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{"admin"}}, nil
		},
		getRoleFn: func(context.Context, string, string) (*iamsdk.Role, error) {
			return nil, sdkerrors.NewNotFound("iam.role.get", "role not found")
		},
		listRolesFn: failListRoles(t),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if !slices.Equal(roles, []string{"admin"}) {
		t.Fatalf("expected a reference GetRole does not find to be kept, got %v", roles)
	}
}

func TestWorkspaceRoleResolverKeepsAReferenceTheEmbeddedStoreDoesNotFind(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
	}{
		{name: "store error", err: quicbaasiam.ErrRoleNotFound},
		{name: "wrapped store error", err: fmt.Errorf("embedded: %w", quicbaasiam.ErrRoleNotFound)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := &mockIAMClient{
				getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
					return &iamsdk.User{Email: email, Roles: []string{"admin"}}, nil
				},
				getRoleFn: func(context.Context, string, string) (*iamsdk.Role, error) {
					return nil, tc.err
				},
				listRolesFn: failListRoles(t),
			}
			resolver, err := NewWorkspaceRoleResolver(client)
			if err != nil {
				t.Fatalf("NewWorkspaceRoleResolver: %v", err)
			}

			roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
			if err != nil {
				t.Fatalf("Roles: %v", err)
			}
			if !slices.Equal(roles, []string{"admin"}) {
				t.Fatalf("expected a reference the embedded store does not find to be kept, got %v", roles)
			}
		})
	}
}

func TestWorkspaceRoleResolverReturnsAGetRoleFailure(t *testing.T) {
	t.Parallel()
	cause := errors.New("role lookup unavailable")
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{ridadmin}}, nil
		},
		getRoleFn: func(context.Context, string, string) (*iamsdk.Role, error) {
			return nil, cause
		},
		listRolesFn: failListRoles(t),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
	if err == nil {
		t.Fatalf("expected the GetRole failure to be returned, got roles %v", roles)
	}
	if len(roles) != 0 {
		t.Fatalf("a failed role lookup must grant no roles, got %v", roles)
	}
}

func TestWorkspaceRoleResolverListsTheRolesWhenGetRoleIsNotRouted(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{ridadmin, ridmember}}, nil
		},
		getRoleFn: unroutedGetRole,
		listRolesFn: pagedRoles(
			[]iamsdk.Role{{ID: ridmember, Name: "member"}},
			[]iamsdk.Role{{ID: ridadmin, Name: "admin"}},
			nil,
		),
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if !slices.Equal(roles, []string{"admin", "member"}) {
		t.Fatalf("expected the role list to name the IDs when GetRole is not routed, got %v", roles)
	}
}

// A workspace account whose IAM lifecycle is suspended, locked, disabled or
// deleting holds no roles there, whatever roles IAM still lists for it: the
// resolver refuses it before any role is named.
func TestWorkspaceRoleResolverRefusesAnInactiveWorkspaceAccount(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		lifecycle string
		roles     []string
	}{
		{name: "suspended", lifecycle: "suspended", roles: []string{"admin"}},
		{name: "locked", lifecycle: "locked", roles: []string{"admin"}},
		{name: "disabled", lifecycle: "disabled", roles: []string{"admin"}},
		{name: "deleting", lifecycle: "deleting", roles: []string{"admin"}},
		{name: "disabled without roles", lifecycle: "disabled", roles: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := &mockIAMClient{
				getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
					return &iamsdk.User{Email: email, Roles: tc.roles, Lifecycle: tc.lifecycle}, nil
				},
				getRoleFn: func(_ context.Context, _, roleID string) (*iamsdk.Role, error) {
					t.Errorf("GetRole(%q) reached for a %s account", roleID, tc.lifecycle)
					return nil, nil
				},
				listRolesFn: func(_ context.Context, _ string, _ *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
					t.Errorf("ListRoles reached for a %s account", tc.lifecycle)
					return &iamsdk.ListRolesResponse{}, nil
				},
			}
			resolver, err := NewWorkspaceRoleResolver(client)
			if err != nil {
				t.Fatalf("NewWorkspaceRoleResolver: %v", err)
			}

			roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
			if roles != nil {
				t.Fatalf("a %s account must hold no roles, got %v", tc.lifecycle, roles)
			}
			var inactive ErrWorkspaceAccountInactive
			if !errors.As(err, &inactive) {
				t.Fatalf("expected ErrWorkspaceAccountInactive for a %s account, got %v", tc.lifecycle, err)
			}
			if inactive.Lifecycle != tc.lifecycle || inactive.TenantID != "workspace-a" || inactive.Subject != "operator@platform" {
				t.Fatalf("the refusal names %+v, want lifecycle %q in workspace-a for operator@platform", inactive, tc.lifecycle)
			}
		})
	}
}

// An active account, a pending (invited) one and one whose transport sends
// no lifecycle keep their roles.
func TestWorkspaceRoleResolverAdmitsAnActiveOrPendingAccount(t *testing.T) {
	t.Parallel()
	for _, lifecycle := range []string{"active", "pending", ""} {
		t.Run("lifecycle="+lifecycle, func(t *testing.T) {
			t.Parallel()
			client := &mockIAMClient{
				getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
					return &iamsdk.User{Email: email, Roles: []string{"admin"}, Lifecycle: lifecycle}, nil
				},
				getRoleFn:   unroutedGetRole,
				listRolesFn: pagedRoles(nil, nil, nil),
			}
			resolver, err := NewWorkspaceRoleResolver(client)
			if err != nil {
				t.Fatalf("NewWorkspaceRoleResolver: %v", err)
			}

			roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
			if err != nil {
				t.Fatalf("Roles for a %q account: %v", lifecycle, err)
			}
			if !slices.Equal(roles, []string{"admin"}) {
				t.Fatalf("a %q account must keep its roles, got %v", lifecycle, roles)
			}
		})
	}
}
