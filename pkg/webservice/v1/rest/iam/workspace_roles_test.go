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
	"testing"

	quicbaasiam "github.com/jeremyhahn/go-quicbaas/pkg/iam"
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
		getRoleFn:   unroutedGetRole,
		listRolesFn: pagedRoles(nil, nil, nil),
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
			return &iamsdk.User{Email: email, Roles: []string{"rid-admin"}}, nil
		},
		getRoleFn: unroutedGetRole,
		listRolesFn: pagedRoles(
			[]iamsdk.Role{{ID: "rid-member", Name: "member"}},
			[]iamsdk.Role{{ID: "rid-admin", Name: "admin"}},
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
			[]iamsdk.Role{{ID: "rid-member", Name: "member"}},
			[]iamsdk.Role{{ID: "rid-admin", Name: "admin"}},
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
			return &iamsdk.User{Email: email, Roles: []string{"rid-admin"}}, nil
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
	names := map[string]string{"rid-admin": "admin", "rid-ops": "ops"}
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{"rid-admin", "rid-ops"}}, nil
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
			return &iamsdk.User{Email: email, Roles: []string{"rid-admin"}}, nil
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
			return &iamsdk.User{Email: email, Roles: []string{"rid-admin", "rid-member"}}, nil
		},
		getRoleFn: unroutedGetRole,
		listRolesFn: pagedRoles(
			[]iamsdk.Role{{ID: "rid-member", Name: "member"}},
			[]iamsdk.Role{{ID: "rid-admin", Name: "admin"}},
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
