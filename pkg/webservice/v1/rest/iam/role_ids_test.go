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
	"net/http"
	"net/http/httptest"
	"strings"
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
	page := 0
	if req.PageToken != "" {
		page = int(req.PageToken[0]-'a') + 1
	}
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
	t.Parallel()
	roles := tenantRoles()

	ids, err := ResolveRoleIDs(context.Background(), roles, "tenant-a", []string{"operator", "0b5e-admin"})

	require.NoError(t, err)
	assert.Equal(t, []string{"0b5e-operator", "0b5e-admin"}, ids)
	require.Len(t, roles.requests, 2, "every page must be read")
	assert.True(t, roles.requests[0].IncludeSystem, "built-in roles must be listed")
	assert.Equal(t, "a", roles.requests[1].PageToken)
}

func TestResolveRoleIDs_NoReferencesReadsNothing(t *testing.T) {
	t.Parallel()
	roles := tenantRoles()

	ids, err := ResolveRoleIDs(context.Background(), roles, "tenant-a", nil)

	require.NoError(t, err)
	assert.Nil(t, ids)
	assert.Empty(t, roles.requests)
}

func TestResolveRoleIDs_UnknownRoleIsNotFound(t *testing.T) {
	t.Parallel()
	_, err := ResolveRoleIDs(context.Background(), tenantRoles(), "tenant-a", []string{"admin", "owner"})

	var notFound ErrRoleNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, ErrRoleNotFound{TenantID: "tenant-a", RoleID: "owner"}, notFound)
}

func TestResolveRoleIDs_EmptyReferenceIsMissingRole(t *testing.T) {
	t.Parallel()
	_, err := ResolveRoleIDs(context.Background(), tenantRoles(), "tenant-a", []string{""})

	assert.ErrorIs(t, err, ErrMissingRole{})
}

func TestResolveRoleIDs_ListFailureIsTyped(t *testing.T) {
	t.Parallel()
	roles := &pagedRoleClient{err: errRoleListUnavailable{}}

	_, err := ResolveRoleIDs(context.Background(), roles, "tenant-a", []string{"admin"})

	var failed ErrRoleListFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "tenant-a", failed.TenantID)
	assert.ErrorIs(t, err, errRoleListUnavailable{})
}

func TestResolveRoleIDs_NilRoleClient(t *testing.T) {
	t.Parallel()
	_, err := ResolveRoleIDs(context.Background(), nil, "tenant-a", []string{"admin"})

	assert.ErrorIs(t, err, ErrRoleClientMissing{})
}

// recordingUserClient records the create request and the role assignments and
// revocations sent to it; user is what Get returns.
type recordingUserClient struct {
	iamsdk.UserClient
	created   *iamsdk.CreateUserRequest
	user      *iamsdk.User
	assigned  []string
	revoked   []string
	updated   *iamsdk.UpdateUserRequest
	assignErr error
}

func (c *recordingUserClient) Get(_ context.Context, _, _ string) (*iamsdk.User, error) {
	return c.user, nil
}

func (c *recordingUserClient) AssignRole(_ context.Context, _, _, roleID string) error {
	if c.assignErr != nil {
		return c.assignErr
	}
	c.assigned = append(c.assigned, roleID)
	return nil
}

func (c *recordingUserClient) RevokeRole(_ context.Context, _, _, roleID string) error {
	c.revoked = append(c.revoked, roleID)
	return nil
}

func (c *recordingUserClient) Update(_ context.Context, tenantID, userID string, req *iamsdk.UpdateUserRequest) (*iamsdk.User, error) {
	c.updated = req
	return &iamsdk.User{ID: userID, TenantID: tenantID, DisplayName: req.DisplayName}, nil
}

// recordingTenantClient records the tenant update it receives and answers it
// the way the pinned embedded handler does: only the display name applies.
type recordingTenantClient struct {
	iamsdk.TenantClient
	created *iamsdk.CreateTenantRequest
	updated *iamsdk.UpdateTenantRequest
}

func (c *recordingTenantClient) Create(_ context.Context, req *iamsdk.CreateTenantRequest) (*iamsdk.Tenant, error) {
	c.created = req
	return &iamsdk.Tenant{ID: req.ID, Name: req.Name}, nil
}

func (c *recordingTenantClient) Update(_ context.Context, tenantID string, req *iamsdk.UpdateTenantRequest) (*iamsdk.Tenant, error) {
	c.updated = req
	return &iamsdk.Tenant{ID: tenantID, Name: req.DisplayName}, nil
}

func (c *recordingUserClient) Create(_ context.Context, tenantID string, req *iamsdk.CreateUserRequest) (*iamsdk.User, error) {
	c.created = req
	return &iamsdk.User{ID: "user-1", TenantID: tenantID, Email: req.Email, Roles: req.Roles}, nil
}

// adapterSDKClient is an SDK client with only the user and role clients.
type adapterSDKClient struct {
	iamsdk.Client
	users   *recordingUserClient
	roles   *pagedRoleClient
	tenants *recordingTenantClient
}

func (c *adapterSDKClient) Tenant() iamsdk.TenantClient { return c.tenants }

// adapterHandlers serves the IAM handlers through the real SDK adapter over
// client, so a test sees exactly which SDK calls a request makes.
func adapterHandlers(client *adapterSDKClient) (*IAMHandlers, *mockHttpWriter) {
	writer := &mockHttpWriter{}
	return NewIAMHandlers(newTestLogger(), NewQuicBaaSIAMAdapter(client), &mockPEPClient{}, writer), writer
}

func (c *adapterSDKClient) User() iamsdk.UserClient { return c.users }
func (c *adapterSDKClient) Role() iamsdk.RoleClient { return c.roles }

func TestQuicBaaSIAMAdapter_CreateUser_SendsRoleIDs(t *testing.T) {
	t.Parallel()
	client := &adapterSDKClient{users: &recordingUserClient{}, roles: tenantRoles()}
	req := &iamsdk.CreateUserRequest{Username: "owner", Email: "owner@example.com", Roles: []string{"admin"}}

	user, err := NewQuicBaaSIAMAdapter(client).CreateUser(context.Background(), "tenant-a", req)

	require.NoError(t, err)
	assert.Equal(t, []string{"0b5e-admin"}, client.users.created.Roles)
	assert.Equal(t, []string{"0b5e-admin"}, user.Roles)
	assert.Equal(t, []string{"admin"}, req.Roles, "the caller's request must not be modified")
}

func TestQuicBaaSIAMAdapter_CreateUser_RefusesUnknownRole(t *testing.T) {
	t.Parallel()
	client := &adapterSDKClient{users: &recordingUserClient{}, roles: tenantRoles()}
	req := &iamsdk.CreateUserRequest{Username: "owner", Email: "owner@example.com", Roles: []string{"owner"}}

	_, err := NewQuicBaaSIAMAdapter(client).CreateUser(context.Background(), "tenant-a", req)

	var notFound ErrRoleNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Nil(t, client.users.created, "no user may be created with an unresolved role")
}

func TestQuicBaaSIAMAdapter_CreateUser_NilRequest(t *testing.T) {
	t.Parallel()
	client := &adapterSDKClient{users: &recordingUserClient{}, roles: tenantRoles()}

	_, err := NewQuicBaaSIAMAdapter(client).CreateUser(context.Background(), "tenant-a", nil)

	var invalid ErrInvalidRequestBody
	require.ErrorAs(t, err, &invalid)
	assert.Nil(t, client.users.created)
}

func TestErrRoleListFailed_Unwrap(t *testing.T) {
	t.Parallel()
	err := ErrRoleListFailed{TenantID: "tenant-a", Err: errRoleListUnavailable{}}

	assert.Equal(t, "rest/iam: listing the roles of tenant tenant-a: role store unavailable", err.Error())
	assert.True(t, errors.Is(err, errRoleListUnavailable{}))
	assert.NotEmpty(t, ErrRoleClientMissing{}.Error())
}

func TestErrUserRolesSyncFailed_Unwrap(t *testing.T) {
	t.Parallel()
	err := ErrUserRolesSyncFailed{TenantID: "tenant-a", UserID: "user-1", RoleID: "0b5e-admin", Err: errRoleListUnavailable{}}

	assert.Equal(t, "rest/iam: setting role 0b5e-admin on user user-1 in tenant tenant-a: role store unavailable", err.Error())
	assert.ErrorIs(t, err, errRoleListUnavailable{})
	assert.NotEmpty(t, ErrIAMClientMissing{}.Error())
}

func TestResolveRoleID_ResolvesName(t *testing.T) {
	t.Parallel()
	id, err := ResolveRoleID(context.Background(), tenantRoles(), "tenant-a", "operator")

	require.NoError(t, err)
	assert.Equal(t, "0b5e-operator", id)
}

func TestResolveRoleID_EmptyReferenceReadsNothing(t *testing.T) {
	t.Parallel()
	roles := tenantRoles()

	_, err := ResolveRoleID(context.Background(), roles, "tenant-a", "")

	assert.ErrorIs(t, err, ErrMissingRole{})
	assert.Empty(t, roles.requests)
}

// userHolding is an SDK client whose user holds the given role IDs.
func userHolding(roleIDs ...string) *adapterSDKClient {
	return &adapterSDKClient{
		users: &recordingUserClient{user: &iamsdk.User{ID: "user-1", Roles: roleIDs}},
		roles: tenantRoles(),
	}
}

func TestSetUserRoles_ReplacesTheRoleSet(t *testing.T) {
	t.Parallel()
	client := userHolding("0b5e-admin", "0b5e-custom")

	err := SetUserRoles(context.Background(), client, "tenant-a", "user-1", []string{"operator", "admin"})

	require.NoError(t, err)
	assert.Equal(t, []string{"0b5e-operator"}, client.users.assigned, "only the missing role is assigned")
	assert.Equal(t, []string{"0b5e-custom"}, client.users.revoked, "only the unwanted role is revoked")
}

func TestSetUserRoles_NoReferencesLeavesRolesAlone(t *testing.T) {
	t.Parallel()
	client := userHolding("0b5e-admin")

	require.NoError(t, SetUserRoles(context.Background(), client, "tenant-a", "user-1", nil))

	assert.Empty(t, client.roles.requests)
	assert.Empty(t, client.users.assigned)
	assert.Empty(t, client.users.revoked)
}

func TestSetUserRoles_UnknownRoleChangesNothing(t *testing.T) {
	t.Parallel()
	client := userHolding("0b5e-custom")

	err := SetUserRoles(context.Background(), client, "tenant-a", "user-1", []string{"admin", "owner"})

	var notFound ErrRoleNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "owner", notFound.RoleID)
	assert.Empty(t, client.users.assigned)
	assert.Empty(t, client.users.revoked)
}

func TestSetUserRoles_AssignFailureIsTypedAndRevokesNothing(t *testing.T) {
	t.Parallel()
	client := userHolding("0b5e-custom")
	client.users.assignErr = errRoleListUnavailable{}

	err := SetUserRoles(context.Background(), client, "tenant-a", "user-1", []string{"admin"})

	var failed ErrUserRolesSyncFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "0b5e-admin", failed.RoleID)
	assert.Empty(t, client.users.revoked, "no role is revoked before every wanted role is assigned")
}

func TestSetUserRoles_NilClient(t *testing.T) {
	t.Parallel()
	err := SetUserRoles(context.Background(), nil, "tenant-a", "user-1", []string{"admin"})

	assert.ErrorIs(t, err, ErrIAMClientMissing{})
}

func TestQuicBaaSIAMAdapter_AssignRole_SendsRoleID(t *testing.T) {
	t.Parallel()
	client := userHolding()

	require.NoError(t, NewQuicBaaSIAMAdapter(client).AssignRole(context.Background(), "tenant-a", "user-1", "admin"))

	assert.Equal(t, []string{"0b5e-admin"}, client.users.assigned)
}

func TestQuicBaaSIAMAdapter_AssignRole_RefusesUnknownRole(t *testing.T) {
	t.Parallel()
	client := userHolding()

	err := NewQuicBaaSIAMAdapter(client).AssignRole(context.Background(), "tenant-a", "user-1", "owner")

	var notFound ErrRoleNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Empty(t, client.users.assigned)
}

func TestQuicBaaSIAMAdapter_RevokeRole_SendsRoleID(t *testing.T) {
	t.Parallel()
	client := userHolding("0b5e-admin")

	require.NoError(t, NewQuicBaaSIAMAdapter(client).RevokeRole(context.Background(), "tenant-a", "user-1", "admin"))

	assert.Equal(t, []string{"0b5e-admin"}, client.users.revoked)
}

func TestQuicBaaSIAMAdapter_RevokeRole_RefusesUnknownRole(t *testing.T) {
	t.Parallel()
	client := userHolding("0b5e-admin")

	err := NewQuicBaaSIAMAdapter(client).RevokeRole(context.Background(), "tenant-a", "user-1", "owner")

	var notFound ErrRoleNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Empty(t, client.users.revoked)
}

func TestQuicBaaSIAMAdapter_RequireUnchangedUserRoles_PassesTheHeldRoles(t *testing.T) {
	t.Parallel()
	client := userHolding("0b5e-admin")

	require.NoError(t, NewQuicBaaSIAMAdapter(client).RequireUnchangedUserRoles(context.Background(), "tenant-a", "user-1", []string{"admin"}))

	assert.Empty(t, client.users.assigned)
	assert.Empty(t, client.users.revoked)
}

func TestQuicBaaSIAMAdapter_RequireUnchangedUserRoles_RefusesARoleChange(t *testing.T) {
	t.Parallel()
	client := userHolding()

	err := NewQuicBaaSIAMAdapter(client).RequireUnchangedUserRoles(context.Background(), "tenant-a", "user-1", []string{"admin"})

	require.ErrorIs(t, err, ErrRoleChangeUnsupported{})
	assert.Empty(t, client.users.assigned)
	assert.Empty(t, client.users.revoked)
}

func TestRequireUnchangedUserRoles_SameSetInAnyOrderPasses(t *testing.T) {
	client := userHolding("0b5e-admin", "0b5e-operator")

	err := RequireUnchangedUserRoles(context.Background(), client, "tenant-a", "user-1", []string{"operator", "admin", "admin"})

	require.NoError(t, err)
}

func TestRequireUnchangedUserRoles_DroppingARoleIsAChange(t *testing.T) {
	client := userHolding("0b5e-admin", "0b5e-operator")

	err := RequireUnchangedUserRoles(context.Background(), client, "tenant-a", "user-1", []string{"admin"})

	var unsupported ErrRoleChangeUnsupported
	require.ErrorAs(t, err, &unsupported)
	assert.Equal(t, ErrRoleChangeUnsupported{TenantID: "tenant-a", UserID: "user-1"}, unsupported)
	assert.Empty(t, client.users.revoked)
}

func TestRequireUnchangedUserRoles_NoReferencesReadsNothing(t *testing.T) {
	require.NoError(t, RequireUnchangedUserRoles(context.Background(), nil, "tenant-a", "user-1", nil))
}

func TestRequireUnchangedUserRoles_NilClient(t *testing.T) {
	err := RequireUnchangedUserRoles(context.Background(), nil, "tenant-a", "user-1", []string{"admin"})

	require.ErrorIs(t, err, ErrIAMClientMissing{})
}

func TestUpdateUser_RoleChangeIsRefusedBeforeAnyWrite(t *testing.T) {
	client := userHolding()
	handlers, writer := adapterHandlers(client)

	body := UpdateUserRequest{Name: "Renamed", Roles: []string{"admin"}}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-a/users/user-1", body, map[string]string{"tenant": "tenant-a", "id": "user-1"})
	handlers.UpdateUser(httptest.NewRecorder(), req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	assert.Empty(t, client.users.assigned)
	assert.Empty(t, client.users.revoked)
	assert.Nil(t, client.users.updated, "a refused role change must not update the user")
}

func TestUpdateUser_UnchangedRolesUpdateTheOtherFields(t *testing.T) {
	client := userHolding("0b5e-admin")
	handlers, writer := adapterHandlers(client)

	body := UpdateUserRequest{Name: "Renamed", Roles: []string{"admin"}}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-a/users/user-1", body, map[string]string{"tenant": "tenant-a", "id": "user-1"})
	handlers.UpdateUser(httptest.NewRecorder(), req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	require.NotNil(t, client.users.updated, "the update must reach the SDK")
	assert.Equal(t, "Renamed", client.users.updated.DisplayName)
	assert.Empty(t, client.users.assigned)
	assert.Empty(t, client.users.revoked)
}

func TestQuicBaaSIAMAdapter_UpdateTenant_SendsTheNameAsDisplayName(t *testing.T) {
	client := &adapterSDKClient{tenants: &recordingTenantClient{}}

	resp, err := NewQuicBaaSIAMAdapter(client).UpdateTenant(context.Background(), "acme", &UpdateTenantRequest{Name: "renamed"})

	require.NoError(t, err)
	require.NotNil(t, client.tenants.updated)
	assert.Equal(t, "renamed", client.tenants.updated.DisplayName)
	assert.Equal(t, "renamed", resp.Name)
}

func TestQuicBaaSIAMAdapter_UpdateTenant_RefusesSettings(t *testing.T) {
	client := &adapterSDKClient{tenants: &recordingTenantClient{}}

	_, err := NewQuicBaaSIAMAdapter(client).UpdateTenant(context.Background(), "acme", &UpdateTenantRequest{Name: "renamed", Settings: &TenantSettings{}})

	require.ErrorIs(t, err, ErrTenantSettingsUnsupported{})
	assert.Nil(t, client.tenants.updated, "refused settings must not reach the SDK")
}

func TestUpdateTenant_SettingsAreABadRequest(t *testing.T) {
	client := &adapterSDKClient{tenants: &recordingTenantClient{}}
	handlers, writer := adapterHandlers(client)

	body := UpdateTenantRequest{Settings: &TenantSettings{}}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/acme", body, map[string]string{"tenant": "acme"})
	handlers.UpdateTenant(httptest.NewRecorder(), req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	assert.Nil(t, client.tenants.updated)
}

func TestQuicBaaSIAMAdapter_CreateTenant_SendsIDAndName(t *testing.T) {
	client := &adapterSDKClient{tenants: &recordingTenantClient{}}

	resp, err := NewQuicBaaSIAMAdapter(client).CreateTenant(context.Background(), &CreateTenantRequest{ID: "acme", Name: "Acme"})

	require.NoError(t, err)
	require.NotNil(t, client.tenants.created)
	assert.Equal(t, "acme", client.tenants.created.ID)
	assert.Equal(t, "Acme", client.tenants.created.Name)
	assert.Equal(t, "acme", resp.ID)
}

func TestQuicBaaSIAMAdapter_CreateTenant_RefusesSettings(t *testing.T) {
	client := &adapterSDKClient{tenants: &recordingTenantClient{}}

	_, err := NewQuicBaaSIAMAdapter(client).CreateTenant(context.Background(), &CreateTenantRequest{ID: "acme", Settings: &TenantSettings{MaxUsers: 5}})

	require.ErrorIs(t, err, ErrTenantSettingsUnsupported{})
	assert.Nil(t, client.tenants.created, "refused settings must not create the tenant")
}

// TestCreateTenant_SettingsAreABadRequest drives the handler with the
// in-memory SDK client: the pinned SDK's embedded transport cannot be built
// in a unit test here.
func TestCreateTenant_SettingsAreABadRequest(t *testing.T) {
	for name, body := range map[string]string{
		"mfa_required": `{"id":"acme","settings":{"mfa_required":true}}`,
		"max_users":    `{"id":"acme","settings":{"max_users":5}}`,
	} {
		t.Run(name, func(t *testing.T) {
			client := &adapterSDKClient{tenants: &recordingTenantClient{}}
			handlers, writer := adapterHandlers(client)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tenants", strings.NewReader(body))
			handlers.CreateTenant(httptest.NewRecorder(), req)

			assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
			assert.Nil(t, client.tenants.created, "no tenant may be created with refused settings")
		})
	}
}

func TestCreateTenant_WithoutSettingsCreates(t *testing.T) {
	client := &adapterSDKClient{tenants: &recordingTenantClient{}}
	handlers, writer := adapterHandlers(client)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tenants", strings.NewReader(`{"id":"acme","name":"Acme"}`))
	handlers.CreateTenant(httptest.NewRecorder(), req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	require.NotNil(t, client.tenants.created)
	assert.Equal(t, "acme", client.tenants.created.ID)
}

func TestQuicBaaSIAMAdapter_RequireUnchangedUserRoles_RefusesUnknownRole(t *testing.T) {
	client := userHolding()

	err := NewQuicBaaSIAMAdapter(client).RequireUnchangedUserRoles(context.Background(), "tenant-a", "user-1", []string{"owner"})

	var notFound ErrRoleNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Empty(t, client.users.assigned)
}
