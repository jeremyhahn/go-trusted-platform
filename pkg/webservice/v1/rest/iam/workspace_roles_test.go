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
	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// getByEmailUndispatched answers GetUserByEmail as the embedded transport
// does: it does not dispatch the method.
func getByEmailUndispatched(context.Context, string, string) (*iamsdk.User, error) {
	return nil, &embedded.UnknownMethodError{Service: "quicbaas.IAM.User", Method: "GetByEmail"}
}

// listNoRoles answers a tenant with no roles, so stored values stay as
// they are.
func listNoRoles(context.Context, string, *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
	return &iamsdk.ListRolesResponse{}, nil
}

func TestWorkspaceRoleResolverReadsTheRolesOfTheWorkspaceUser(t *testing.T) {
	t.Parallel()
	var gotTenant, gotEmail string
	client := &mockIAMClient{
		getByEmailFn: getByEmailUndispatched,
		listRolesFn:  listNoRoles,
		listUsersFn: func(_ context.Context, tenantID string, _ *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			gotTenant, gotEmail = tenantID, "operator@platform"
			return &iamsdk.ListUsersResponse{
				Users: []iamsdk.User{{Email: "operator@platform", Roles: []string{"member"}}},
			}, nil
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
		getByEmailFn: getByEmailUndispatched,
		listRolesFn:  listNoRoles,
		listUsersFn: func(context.Context, string, *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			return &iamsdk.ListUsersResponse{
				Users: []iamsdk.User{{Email: "operator@platform", Roles: []string{"admin"}}},
			}, nil
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
		getByEmailFn: getByEmailUndispatched,
		listRolesFn:  listNoRoles,
		listUsersFn: func(context.Context, string, *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
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

// TestWorkspaceRoleResolverFindsTheWorkspaceUserByListing pins that Roles
// finds the principal by paging ListUsers, which every IAM transport
// dispatches, and never by GetUserByEmail, which the embedded transport the
// real-server e2e config runs does not (#2150).
func TestWorkspaceRoleResolverFindsTheWorkspaceUserByListing(t *testing.T) {
	t.Parallel()
	var tenants []string
	client := &mockIAMClient{
		getByEmailFn: getByEmailUndispatched,
		listRolesFn:  listNoRoles,
		listUsersFn: func(_ context.Context, tenantID string, req *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			tenants = append(tenants, tenantID)
			if req.PageToken == "" {
				return &iamsdk.ListUsersResponse{
					Users:      []iamsdk.User{{Email: "other@example.com", Roles: []string{"member"}}},
					Pagination: iamsdk.PaginationInfo{HasMore: true, NextPageToken: "p2"},
				}, nil
			}
			return &iamsdk.ListUsersResponse{
				Users: []iamsdk.User{{Email: "Owner@Example.com", Roles: []string{"admin"}}},
			}, nil
		},
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "owner@example.com")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if !slices.Equal(roles, []string{"admin"}) {
		t.Fatalf("expected the workspace user's roles, got %v", roles)
	}
	if len(tenants) == 0 || tenants[0] != "workspace-a" {
		t.Fatalf("expected the workspace tenant to be listed, got %v", tenants)
	}
}

func TestWorkspaceRoleResolverReadsTheUserByEmailWhereDispatched(t *testing.T) {
	t.Parallel()
	var gotTenant, gotEmail string
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, tenantID, email string) (*iamsdk.User, error) {
			gotTenant, gotEmail = tenantID, email
			return &iamsdk.User{Email: email, Roles: []string{"admin"}}, nil
		},
		listUsersFn: func(context.Context, string, *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			t.Fatal("Roles must not list users when GetUserByEmail answers")
			return nil, nil
		},
		listRolesFn: listNoRoles,
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "owner@example.com")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if gotTenant != "workspace-a" || gotEmail != "owner@example.com" {
		t.Fatalf("expected the workspace user to be read by email, got tenant %q email %q", gotTenant, gotEmail)
	}
	if !slices.Equal(roles, []string{"admin"}) {
		t.Fatalf("expected [admin], got %v", roles)
	}
}

func TestWorkspaceRoleResolverAnswersNoRolesWhenGetUserByEmailFindsNoUser(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: func(context.Context, string, string) (*iamsdk.User, error) {
			return nil, status.Error(codes.NotFound, "user not found")
		},
		listUsersFn: func(context.Context, string, *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			t.Fatal("Roles must not list users when GetUserByEmail answers NotFound")
			return nil, nil
		},
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "invited@platform")
	if err != nil || roles != nil {
		t.Fatalf("expected nil, nil for a user the workspace does not hold, got %v, %v", roles, err)
	}
}

func TestWorkspaceRoleResolverReturnsAGetUserByEmailFailure(t *testing.T) {
	t.Parallel()
	cause := status.Error(codes.Unavailable, "iam unavailable")
	client := &mockIAMClient{
		getByEmailFn: func(context.Context, string, string) (*iamsdk.User, error) {
			return nil, cause
		},
		listUsersFn: func(context.Context, string, *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			t.Fatal("Roles must not fall back to listing on a GetUserByEmail failure")
			return nil, nil
		},
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "operator@platform")
	if !errors.Is(err, cause) {
		t.Fatalf("expected the GetUserByEmail failure to be returned, got %v", err)
	}
	if roles != nil {
		t.Fatalf("a failed lookup must grant no roles, got %v", roles)
	}
}

func TestWorkspaceRoleResolverMapsRoleIDsToNames(t *testing.T) {
	t.Parallel()
	var gotReq *iamsdk.ListRolesRequest
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{"role-id-admin", "legacy-name"}}, nil
		},
		listRolesFn: func(_ context.Context, _ string, req *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
			gotReq = req
			return &iamsdk.ListRolesResponse{Roles: []iamsdk.Role{
				{ID: "role-id-admin", Name: "admin"},
				{ID: "role-id-member", Name: "member"},
			}}, nil
		},
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "owner@example.com")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if !slices.Equal(roles, []string{"admin", "legacy-name"}) {
		t.Fatalf("expected the role ID mapped to its name and the unknown value kept, got %v", roles)
	}
	if gotReq == nil || !gotReq.IncludeSystem {
		t.Fatalf("expected the system roles to be listed, got %+v", gotReq)
	}
}

func TestWorkspaceRoleResolverReturnsARoleListFailure(t *testing.T) {
	t.Parallel()
	cause := errors.New("roles unavailable")
	client := &mockIAMClient{
		getByEmailFn: func(_ context.Context, _, email string) (*iamsdk.User, error) {
			return &iamsdk.User{Email: email, Roles: []string{"role-id-admin"}}, nil
		},
		listRolesFn: func(context.Context, string, *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
			return nil, cause
		},
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "owner@example.com")
	var listFailed ErrRoleListFailed
	if !errors.As(err, &listFailed) || !errors.Is(err, cause) {
		t.Fatalf("expected ErrRoleListFailed wrapping the cause, got %v", err)
	}
	if roles != nil {
		t.Fatalf("a failed role listing must grant no roles, got %v", roles)
	}
}

func TestWorkspaceRoleResolverRefusesAFullPageWithoutANextPage(t *testing.T) {
	t.Parallel()
	page := make([]iamsdk.User, mirroredEmailsPageSize)
	for i := range page {
		page[i] = iamsdk.User{Email: "someone-else@example.com", Roles: []string{"member"}}
	}
	client := &mockIAMClient{
		getByEmailFn: getByEmailUndispatched,
		listUsersFn: func(context.Context, string, *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			return &iamsdk.ListUsersResponse{Users: page}, nil
		},
		listRolesFn: listNoRoles,
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	roles, err := resolver.Roles(context.Background(), "workspace-a", "owner@example.com")
	var incomplete ErrWorkspaceUserListingIncomplete
	if !errors.As(err, &incomplete) {
		t.Fatalf("expected ErrWorkspaceUserListingIncomplete, got roles %v err %v", roles, err)
	}
	if incomplete.TenantID != "workspace-a" || incomplete.Listed != int(mirroredEmailsPageSize) {
		t.Fatalf("unexpected error fields %+v", incomplete)
	}
	if roles != nil {
		t.Fatalf("an incomplete listing must grant no roles, got %v", roles)
	}
}

func TestWorkspaceRoleResolverRefusesAListingShortOfItsTotal(t *testing.T) {
	t.Parallel()
	client := &mockIAMClient{
		getByEmailFn: getByEmailUndispatched,
		listUsersFn: func(context.Context, string, *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			return &iamsdk.ListUsersResponse{
				Users:      []iamsdk.User{{Email: "someone-else@example.com"}},
				Pagination: iamsdk.PaginationInfo{TotalCount: 2},
			}, nil
		},
	}
	resolver, err := NewWorkspaceRoleResolver(client)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}

	_, err = resolver.Roles(context.Background(), "workspace-a", "owner@example.com")
	if !errors.As(err, new(ErrWorkspaceUserListingIncomplete)) {
		t.Fatalf("expected ErrWorkspaceUserListingIncomplete, got %v", err)
	}
}
