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
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errRoleListUnavailable is the failure the fake role client is told to return.
type errRoleListUnavailable struct{}

func (errRoleListUnavailable) Error() string { return "role store unavailable" }

// pagedRoleClient serves a tenant's roles one page per List call, the way the
// SDK pages them, and records every request it was given.
type pagedRoleClient struct {
	iamsdk.RoleClient
	pages    [][]iamsdk.Role
	err      error
	requests []iamsdk.ListRolesRequest
}

func (c *pagedRoleClient) List(_ context.Context, _ string, req *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
	c.requests = append(c.requests, *req)
	if c.err != nil {
		return nil, c.err
	}
	page := len(c.requests) - 1
	resp := &iamsdk.ListRolesResponse{Roles: c.pages[page]}
	if page+1 < len(c.pages) {
		resp.Pagination = iamsdk.PaginationInfo{HasMore: true, NextPageToken: string(rune('a' + page))}
	}
	return resp, nil
}

// tenantRoles is a tenant seeded with two built-in roles across two pages.
func tenantRoles() *pagedRoleClient {
	return &pagedRoleClient{pages: [][]iamsdk.Role{
		{{ID: "0b5e-admin", Name: "admin", IsSystem: true}},
		{{ID: "0b5e-operator", Name: "operator", IsSystem: true}},
	}}
}

func TestResolveRoleIDs_ResolvesNamesAndIDsAcrossPages(t *testing.T) {
	roles := tenantRoles()

	ids, err := ResolveRoleIDs(context.Background(), roles, "tenant-a", []string{"operator", "0b5e-admin"})

	require.NoError(t, err)
	assert.Equal(t, []string{"0b5e-operator", "0b5e-admin"}, ids)
	require.Len(t, roles.requests, 2, "every page must be read")
	assert.True(t, roles.requests[0].IncludeSystem, "built-in roles must be listed")
	assert.Equal(t, "a", roles.requests[1].PageToken)
}

func TestResolveRoleIDs_NoReferencesReadsNothing(t *testing.T) {
	roles := tenantRoles()

	ids, err := ResolveRoleIDs(context.Background(), roles, "tenant-a", nil)

	require.NoError(t, err)
	assert.Nil(t, ids)
	assert.Empty(t, roles.requests)
}

func TestResolveRoleIDs_UnknownRoleIsNotFound(t *testing.T) {
	_, err := ResolveRoleIDs(context.Background(), tenantRoles(), "tenant-a", []string{"admin", "owner"})

	var notFound ErrRoleNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, ErrRoleNotFound{TenantID: "tenant-a", RoleID: "owner"}, notFound)
}

func TestResolveRoleIDs_EmptyReferenceIsMissingRole(t *testing.T) {
	_, err := ResolveRoleIDs(context.Background(), tenantRoles(), "tenant-a", []string{""})

	assert.ErrorIs(t, err, ErrMissingRole{})
}

func TestResolveRoleIDs_ListFailureIsTyped(t *testing.T) {
	roles := &pagedRoleClient{err: errRoleListUnavailable{}}

	_, err := ResolveRoleIDs(context.Background(), roles, "tenant-a", []string{"admin"})

	var failed ErrRoleListFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "tenant-a", failed.TenantID)
	assert.ErrorIs(t, err, errRoleListUnavailable{})
}

func TestResolveRoleIDs_NilRoleClient(t *testing.T) {
	_, err := ResolveRoleIDs(context.Background(), nil, "tenant-a", []string{"admin"})

	assert.ErrorIs(t, err, ErrRoleClientMissing{})
}

// recordingUserClient records the create request the adapter sends.
type recordingUserClient struct {
	iamsdk.UserClient
	created *iamsdk.CreateUserRequest
}

func (c *recordingUserClient) Create(_ context.Context, tenantID string, req *iamsdk.CreateUserRequest) (*iamsdk.User, error) {
	c.created = req
	return &iamsdk.User{ID: "user-1", TenantID: tenantID, Email: req.Email, Roles: req.Roles}, nil
}

// adapterSDKClient is an SDK client with only the user and role clients.
type adapterSDKClient struct {
	iamsdk.Client
	users *recordingUserClient
	roles *pagedRoleClient
}

func (c *adapterSDKClient) User() iamsdk.UserClient { return c.users }
func (c *adapterSDKClient) Role() iamsdk.RoleClient { return c.roles }

func TestQuicBaaSIAMAdapter_CreateUser_SendsRoleIDs(t *testing.T) {
	client := &adapterSDKClient{users: &recordingUserClient{}, roles: tenantRoles()}
	req := &iamsdk.CreateUserRequest{Username: "owner", Email: "owner@example.com", Roles: []string{"admin"}}

	user, err := NewQuicBaaSIAMAdapter(client).CreateUser(context.Background(), "tenant-a", req)

	require.NoError(t, err)
	assert.Equal(t, []string{"0b5e-admin"}, client.users.created.Roles)
	assert.Equal(t, []string{"0b5e-admin"}, user.Roles)
	assert.Equal(t, []string{"admin"}, req.Roles, "the caller's request must not be modified")
}

func TestQuicBaaSIAMAdapter_CreateUser_RefusesUnknownRole(t *testing.T) {
	client := &adapterSDKClient{users: &recordingUserClient{}, roles: tenantRoles()}
	req := &iamsdk.CreateUserRequest{Username: "owner", Email: "owner@example.com", Roles: []string{"owner"}}

	_, err := NewQuicBaaSIAMAdapter(client).CreateUser(context.Background(), "tenant-a", req)

	var notFound ErrRoleNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Nil(t, client.users.created, "no user may be created with an unresolved role")
}

func TestQuicBaaSIAMAdapter_CreateUser_NilRequest(t *testing.T) {
	client := &adapterSDKClient{users: &recordingUserClient{}, roles: tenantRoles()}

	_, err := NewQuicBaaSIAMAdapter(client).CreateUser(context.Background(), "tenant-a", nil)

	var invalid ErrInvalidRequestBody
	require.ErrorAs(t, err, &invalid)
	assert.Nil(t, client.users.created)
}

func TestErrRoleListFailed_Unwrap(t *testing.T) {
	err := ErrRoleListFailed{TenantID: "tenant-a", Err: errRoleListUnavailable{}}

	assert.Equal(t, "rest/iam: listing the roles of tenant tenant-a: role store unavailable", err.Error())
	assert.True(t, errors.Is(err, errRoleListUnavailable{}))
	assert.NotEmpty(t, ErrRoleClientMissing{}.Error())
}
