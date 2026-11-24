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
)

func TestWorkspaceRoleResolverReadsTheRolesOfTheWorkspaceUser(t *testing.T) {
	t.Parallel()
	var gotTenant, gotEmail string
	client := &mockIAMClient{
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
		getByEmailFn: func(context.Context, string, string) (*iamsdk.User, error) {
			t.Fatal("Roles must not call GetUserByEmail: the embedded transport does not dispatch it")
			return nil, nil
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
