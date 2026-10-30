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
	"testing"
	"time"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cov964NotFound is the typed not-found error the fake SDK clients return
// for an unknown ID, the way the real SDK clients do.
type cov964NotFound struct {
	Kind string
	ID   string
}

func (e cov964NotFound) Error() string { return e.Kind + " not found: " + e.ID }

// cov964Unavailable is the error a fake returns when told the store is down.
type cov964Unavailable struct{}

func (cov964Unavailable) Error() string { return "iam store unavailable" }

// cov964Users is an in-memory UserClient keyed by user ID.
type cov964Users struct {
	iamsdk.UserClient
	users   map[string]*iamsdk.User
	updated *iamsdk.UpdateUserRequest
	listed  *iamsdk.ListUsersRequest
}

func (c *cov964Users) Get(_ context.Context, _, userID string) (*iamsdk.User, error) {
	if u, ok := c.users[userID]; ok {
		return u, nil
	}
	return nil, cov964NotFound{Kind: "user", ID: userID}
}

func (c *cov964Users) GetByEmail(_ context.Context, _, email string) (*iamsdk.User, error) {
	for _, u := range c.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, cov964NotFound{Kind: "user", ID: email}
}

func (c *cov964Users) List(_ context.Context, _ string, req *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
	c.listed = req
	resp := &iamsdk.ListUsersResponse{}
	for _, u := range c.users {
		resp.Users = append(resp.Users, *u)
	}
	return resp, nil
}

func (c *cov964Users) Update(ctx context.Context, tenantID, userID string, req *iamsdk.UpdateUserRequest) (*iamsdk.User, error) {
	c.updated = req
	return c.Get(ctx, tenantID, userID)
}

func (c *cov964Users) Delete(_ context.Context, _, userID string) error {
	if _, ok := c.users[userID]; !ok {
		return cov964NotFound{Kind: "user", ID: userID}
	}
	delete(c.users, userID)
	return nil
}

// cov964Groups is an in-memory GroupClient keyed by group ID; members maps a
// group ID to its member user IDs.
type cov964Groups struct {
	iamsdk.GroupClient
	groups  map[string]*iamsdk.Group
	members map[string][]string
}

func (c *cov964Groups) Create(_ context.Context, tenantID string, _ *iamsdk.CreateGroupRequest) (*iamsdk.Group, error) {
	g := &iamsdk.Group{ID: "group-new", TenantID: tenantID}
	c.groups[g.ID] = g
	return g, nil
}

func (c *cov964Groups) Get(_ context.Context, _, groupID string) (*iamsdk.Group, error) {
	if g, ok := c.groups[groupID]; ok {
		return g, nil
	}
	return nil, cov964NotFound{Kind: "group", ID: groupID}
}

func (c *cov964Groups) List(_ context.Context, _ string, _ *iamsdk.ListGroupsRequest) (*iamsdk.ListGroupsResponse, error) {
	resp := &iamsdk.ListGroupsResponse{}
	for _, g := range c.groups {
		resp.Groups = append(resp.Groups, *g)
	}
	return resp, nil
}

func (c *cov964Groups) Update(ctx context.Context, tenantID, groupID string, _ *iamsdk.UpdateGroupRequest) (*iamsdk.Group, error) {
	return c.Get(ctx, tenantID, groupID)
}

func (c *cov964Groups) Delete(_ context.Context, _, groupID string) error {
	if _, ok := c.groups[groupID]; !ok {
		return cov964NotFound{Kind: "group", ID: groupID}
	}
	delete(c.groups, groupID)
	return nil
}

func (c *cov964Groups) AddMember(_ context.Context, _, groupID, userID string) error {
	if _, ok := c.groups[groupID]; !ok {
		return cov964NotFound{Kind: "group", ID: groupID}
	}
	c.members[groupID] = append(c.members[groupID], userID)
	return nil
}

func (c *cov964Groups) RemoveMember(_ context.Context, _, groupID, userID string) error {
	kept := make([]string, 0, len(c.members[groupID]))
	found := false
	for _, m := range c.members[groupID] {
		if m == userID {
			found = true
			continue
		}
		kept = append(kept, m)
	}
	if !found {
		return cov964NotFound{Kind: "member", ID: userID}
	}
	c.members[groupID] = kept
	return nil
}

// cov964Roles is an in-memory RoleClient keyed by role ID.
type cov964Roles struct {
	iamsdk.RoleClient
	roles map[string]*iamsdk.Role
}

func (c *cov964Roles) Create(_ context.Context, tenantID string, _ *iamsdk.CreateRoleRequest) (*iamsdk.Role, error) {
	r := &iamsdk.Role{ID: "role-new", TenantID: tenantID}
	c.roles[r.ID] = r
	return r, nil
}

func (c *cov964Roles) Get(_ context.Context, _, roleID string) (*iamsdk.Role, error) {
	if r, ok := c.roles[roleID]; ok {
		return r, nil
	}
	return nil, cov964NotFound{Kind: "role", ID: roleID}
}

func (c *cov964Roles) List(_ context.Context, _ string, _ *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
	resp := &iamsdk.ListRolesResponse{}
	for _, r := range c.roles {
		resp.Roles = append(resp.Roles, *r)
	}
	return resp, nil
}

func (c *cov964Roles) Update(ctx context.Context, tenantID, roleID string, _ *iamsdk.UpdateRoleRequest) (*iamsdk.Role, error) {
	return c.Get(ctx, tenantID, roleID)
}

func (c *cov964Roles) Delete(_ context.Context, _, roleID string) error {
	if _, ok := c.roles[roleID]; !ok {
		return cov964NotFound{Kind: "role", ID: roleID}
	}
	delete(c.roles, roleID)
	return nil
}

// cov964Tenants is an in-memory TenantClient that records the requests it
// was sent; err, when set, fails every call.
type cov964Tenants struct {
	iamsdk.TenantClient
	tenants map[string]*iamsdk.Tenant
	created *iamsdk.CreateTenantRequest
	updated *iamsdk.UpdateTenantRequest
	listed  *iamsdk.ListTenantsRequest
	err     error
}

func (c *cov964Tenants) Create(_ context.Context, req *iamsdk.CreateTenantRequest) (*iamsdk.Tenant, error) {
	c.created = req
	if c.err != nil {
		return nil, c.err
	}
	t := &iamsdk.Tenant{ID: req.ID, Name: req.Name, Settings: req.Settings, CreatedAt: time.Unix(1700000000, 0).UTC()}
	c.tenants[t.ID] = t
	return t, nil
}

func (c *cov964Tenants) Get(_ context.Context, tenantID string) (*iamsdk.Tenant, error) {
	if c.err != nil {
		return nil, c.err
	}
	if t, ok := c.tenants[tenantID]; ok {
		return t, nil
	}
	return nil, cov964NotFound{Kind: "tenant", ID: tenantID}
}

func (c *cov964Tenants) Update(ctx context.Context, tenantID string, req *iamsdk.UpdateTenantRequest) (*iamsdk.Tenant, error) {
	c.updated = req
	t, err := c.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	t.Settings = req.Settings
	t.UpdatedAt = time.Unix(1700000100, 0).UTC()
	return t, nil
}

func (c *cov964Tenants) Delete(_ context.Context, tenantID string) error {
	if _, ok := c.tenants[tenantID]; !ok {
		return cov964NotFound{Kind: "tenant", ID: tenantID}
	}
	delete(c.tenants, tenantID)
	return nil
}

func (c *cov964Tenants) List(_ context.Context, req *iamsdk.ListTenantsRequest) (*iamsdk.ListTenantsResponse, error) {
	c.listed = req
	if c.err != nil {
		return nil, c.err
	}
	resp := &iamsdk.ListTenantsResponse{}
	for _, t := range c.tenants {
		resp.Tenants = append(resp.Tenants, *t)
	}
	return resp, nil
}

// cov964Policies is an in-memory PolicyClient keyed by policy name that
// records the requests it was sent; err, when set, fails every call.
type cov964Policies struct {
	iamsdk.PolicyClient
	policies  map[string]*iamsdk.Policy
	created   *iamsdk.CreatePolicyRequest
	updated   *iamsdk.UpdatePolicyRequest
	listed    *iamsdk.ListPoliciesRequest
	validated *iamsdk.Policy
	tested    *iamsdk.TestPolicyRequest
	validRes  *iamsdk.ValidationResult
	testRes   *iamsdk.TestPolicyResponse
	err       error
}

func (c *cov964Policies) Create(_ context.Context, tenantID string, req *iamsdk.CreatePolicyRequest) (*iamsdk.Policy, error) {
	c.created = req
	if c.err != nil {
		return nil, c.err
	}
	p := &iamsdk.Policy{
		Name:        req.Name,
		TenantID:    tenantID,
		Description: req.Description,
		Priority:    req.Priority,
		SpecYAML:    req.SpecYAML,
		CreatedAt:   time.Unix(1700000000, 0).UTC(),
	}
	c.policies[p.Name] = p
	return p, nil
}

func (c *cov964Policies) Get(_ context.Context, _, policyName string) (*iamsdk.Policy, error) {
	if c.err != nil {
		return nil, c.err
	}
	if p, ok := c.policies[policyName]; ok {
		return p, nil
	}
	return nil, cov964NotFound{Kind: "policy", ID: policyName}
}

func (c *cov964Policies) Update(ctx context.Context, tenantID, policyName string, req *iamsdk.UpdatePolicyRequest) (*iamsdk.Policy, error) {
	c.updated = req
	p, err := c.Get(ctx, tenantID, policyName)
	if err != nil {
		return nil, err
	}
	p.Description = *req.Description
	p.Priority = *req.Priority
	p.UpdatedAt = time.Unix(1700000100, 0).UTC()
	return p, nil
}

func (c *cov964Policies) Delete(_ context.Context, _, policyName string) error {
	if _, ok := c.policies[policyName]; !ok {
		return cov964NotFound{Kind: "policy", ID: policyName}
	}
	delete(c.policies, policyName)
	return nil
}

func (c *cov964Policies) List(_ context.Context, _ string, req *iamsdk.ListPoliciesRequest) (*iamsdk.ListPoliciesResponse, error) {
	c.listed = req
	if c.err != nil {
		return nil, c.err
	}
	resp := &iamsdk.ListPoliciesResponse{}
	for _, p := range c.policies {
		resp.Policies = append(resp.Policies, *p)
	}
	return resp, nil
}

func (c *cov964Policies) Validate(_ context.Context, _ string, policy *iamsdk.Policy) (*iamsdk.ValidationResult, error) {
	c.validated = policy
	if c.err != nil {
		return nil, c.err
	}
	return c.validRes, nil
}

func (c *cov964Policies) Test(_ context.Context, _ string, req *iamsdk.TestPolicyRequest) (*iamsdk.TestPolicyResponse, error) {
	c.tested = req
	if c.err != nil {
		return nil, c.err
	}
	return c.testRes, nil
}

// cov964Apps is an in-memory AppClient keyed by client ID; err, when set,
// fails List and RotateSecret.
type cov964Apps struct {
	iamsdk.AppClient
	apps map[string]*iamsdk.Application
	err  error
}

func (c *cov964Apps) Register(_ context.Context, tenantID string, req *iamsdk.RegisterAppRequest) (*iamsdk.Application, error) {
	app := &iamsdk.Application{ClientID: "client-new", TenantID: tenantID}
	c.apps[app.ClientID] = app
	return app, nil
}

func (c *cov964Apps) Get(_ context.Context, _, clientID string) (*iamsdk.Application, error) {
	if app, ok := c.apps[clientID]; ok {
		return app, nil
	}
	return nil, cov964NotFound{Kind: "app", ID: clientID}
}

func (c *cov964Apps) Update(ctx context.Context, tenantID, clientID string, _ *iamsdk.UpdateAppRequest) (*iamsdk.Application, error) {
	return c.Get(ctx, tenantID, clientID)
}

func (c *cov964Apps) Delete(_ context.Context, _, clientID string) error {
	if _, ok := c.apps[clientID]; !ok {
		return cov964NotFound{Kind: "app", ID: clientID}
	}
	delete(c.apps, clientID)
	return nil
}

func (c *cov964Apps) List(_ context.Context, _ string) (*iamsdk.ListAppsResponse, error) {
	if c.err != nil {
		return nil, c.err
	}
	resp := &iamsdk.ListAppsResponse{}
	for _, app := range c.apps {
		resp.Applications = append(resp.Applications, *app)
	}
	resp.TotalCount = len(resp.Applications)
	return resp, nil
}

func (c *cov964Apps) RotateSecret(_ context.Context, _, clientID string) (*iamsdk.RotateSecretResponse, error) {
	if c.err != nil {
		return nil, c.err
	}
	if _, ok := c.apps[clientID]; !ok {
		return nil, cov964NotFound{Kind: "app", ID: clientID}
	}
	return &iamsdk.RotateSecretResponse{ClientID: clientID, ClientSecret: "rotated-secret"}, nil
}

// cov964PEP records the check request and answers with resp.
type cov964PEP struct {
	iamsdk.PEPClient
	checked *iamsdk.CheckRequest
	resp    *iamsdk.CheckResponse
}

func (p *cov964PEP) Check(_ context.Context, req *iamsdk.CheckRequest) (*iamsdk.CheckResponse, error) {
	p.checked = req
	return p.resp, nil
}

// cov964Client is an SDK IAM client over the in-memory fakes above.
type cov964Client struct {
	iamsdk.Client
	users    *cov964Users
	groups   *cov964Groups
	roles    *cov964Roles
	tenants  *cov964Tenants
	policies *cov964Policies
	apps     *cov964Apps
}

func (c *cov964Client) User() iamsdk.UserClient     { return c.users }
func (c *cov964Client) Group() iamsdk.GroupClient   { return c.groups }
func (c *cov964Client) Role() iamsdk.RoleClient     { return c.roles }
func (c *cov964Client) Tenant() iamsdk.TenantClient { return c.tenants }
func (c *cov964Client) Policy() iamsdk.PolicyClient { return c.policies }
func (c *cov964Client) App() iamsdk.AppClient       { return c.apps }

// cov964NewClient seeds one of each resource in tenant-a.
func cov964NewClient() *cov964Client {
	return &cov964Client{
		users: &cov964Users{users: map[string]*iamsdk.User{
			"user-1": {ID: "user-1", TenantID: "tenant-a", Email: "ada@example.com"},
		}},
		groups: &cov964Groups{
			groups:  map[string]*iamsdk.Group{"group-1": {ID: "group-1", TenantID: "tenant-a", Name: "ops"}},
			members: map[string][]string{},
		},
		roles: &cov964Roles{roles: map[string]*iamsdk.Role{
			"role-1": {ID: "role-1", TenantID: "tenant-a", Name: "viewer"},
		}},
		tenants: &cov964Tenants{tenants: map[string]*iamsdk.Tenant{
			"tenant-a": {ID: "tenant-a", Name: "Tenant A"},
		}},
		policies: &cov964Policies{policies: map[string]*iamsdk.Policy{
			"read-only": {Name: "read-only", Description: "reads", Priority: 3, SpecYAML: []byte("rules: []")},
		}},
		apps: &cov964Apps{apps: map[string]*iamsdk.Application{
			"client-1": {
				ClientID:     "client-1",
				Name:         "portal",
				RedirectURIs: []string{"https://portal.example.com/cb"},
				GrantTypes:   []iamsdk.GrantType{iamsdk.ParseGrantType("client_credentials")},
				CreatedAt:    time.Unix(1700000000, 0).UTC(),
				UpdatedAt:    time.Unix(1700000100, 0).UTC(),
			},
		}},
	}
}

func cov964RequireNotFound(t *testing.T, err error, kind, id string) {
	t.Helper()
	var nf cov964NotFound
	require.ErrorAs(t, err, &nf)
	assert.Equal(t, cov964NotFound{Kind: kind, ID: id}, nf)
}

// TestCov964Adapter_DelegatesUserGroupRoleApp checks that every pass-through
// adapter call reaches the matching SDK client and returns its result, and
// that the SDK's typed not-found error reaches the caller unchanged.
func TestCov964Adapter_DelegatesUserGroupRoleApp(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		call   func(a *QuicBaaSIAMAdapter, c *cov964Client) (any, error)
		want   func(c *cov964Client) any
		kind   string
		absent func(a *QuicBaaSIAMAdapter) error
	}{
		{
			name: "GetUser",
			call: func(a *QuicBaaSIAMAdapter, _ *cov964Client) (any, error) { return a.GetUser(ctx, "tenant-a", "user-1") },
			want: func(c *cov964Client) any { return c.users.users["user-1"] },
			kind: "user",
			absent: func(a *QuicBaaSIAMAdapter) error {
				_, err := a.GetUser(ctx, "tenant-a", "missing")
				return err
			},
		},
		{
			name: "GetUserByEmail",
			call: func(a *QuicBaaSIAMAdapter, _ *cov964Client) (any, error) {
				return a.GetUserByEmail(ctx, "tenant-a", "ada@example.com")
			},
			want: func(c *cov964Client) any { return c.users.users["user-1"] },
			kind: "user",
			absent: func(a *QuicBaaSIAMAdapter) error {
				_, err := a.GetUserByEmail(ctx, "tenant-a", "missing")
				return err
			},
		},
		{
			name: "UpdateUser",
			call: func(a *QuicBaaSIAMAdapter, _ *cov964Client) (any, error) {
				return a.UpdateUser(ctx, "tenant-a", "user-1", &iamsdk.UpdateUserRequest{})
			},
			want: func(c *cov964Client) any { return c.users.users["user-1"] },
			kind: "user",
			absent: func(a *QuicBaaSIAMAdapter) error {
				_, err := a.UpdateUser(ctx, "tenant-a", "missing", &iamsdk.UpdateUserRequest{})
				return err
			},
		},
		{
			name: "GetGroup",
			call: func(a *QuicBaaSIAMAdapter, _ *cov964Client) (any, error) {
				return a.GetGroup(ctx, "tenant-a", "group-1")
			},
			want: func(c *cov964Client) any { return c.groups.groups["group-1"] },
			kind: "group",
			absent: func(a *QuicBaaSIAMAdapter) error {
				_, err := a.GetGroup(ctx, "tenant-a", "missing")
				return err
			},
		},
		{
			name: "UpdateGroup",
			call: func(a *QuicBaaSIAMAdapter, _ *cov964Client) (any, error) {
				return a.UpdateGroup(ctx, "tenant-a", "group-1", &iamsdk.UpdateGroupRequest{})
			},
			want: func(c *cov964Client) any { return c.groups.groups["group-1"] },
			kind: "group",
			absent: func(a *QuicBaaSIAMAdapter) error {
				_, err := a.UpdateGroup(ctx, "tenant-a", "missing", &iamsdk.UpdateGroupRequest{})
				return err
			},
		},
		{
			name: "GetRole",
			call: func(a *QuicBaaSIAMAdapter, _ *cov964Client) (any, error) { return a.GetRole(ctx, "tenant-a", "role-1") },
			want: func(c *cov964Client) any { return c.roles.roles["role-1"] },
			kind: "role",
			absent: func(a *QuicBaaSIAMAdapter) error {
				_, err := a.GetRole(ctx, "tenant-a", "missing")
				return err
			},
		},
		{
			name: "UpdateRole",
			call: func(a *QuicBaaSIAMAdapter, _ *cov964Client) (any, error) {
				return a.UpdateRole(ctx, "tenant-a", "role-1", &iamsdk.UpdateRoleRequest{})
			},
			want: func(c *cov964Client) any { return c.roles.roles["role-1"] },
			kind: "role",
			absent: func(a *QuicBaaSIAMAdapter) error {
				_, err := a.UpdateRole(ctx, "tenant-a", "missing", &iamsdk.UpdateRoleRequest{})
				return err
			},
		},
		{
			name: "GetApp",
			call: func(a *QuicBaaSIAMAdapter, _ *cov964Client) (any, error) {
				return a.GetApp(ctx, "tenant-a", "client-1")
			},
			want: func(c *cov964Client) any { return c.apps.apps["client-1"] },
			kind: "app",
			absent: func(a *QuicBaaSIAMAdapter) error {
				_, err := a.GetApp(ctx, "tenant-a", "missing")
				return err
			},
		},
		{
			name: "UpdateApp",
			call: func(a *QuicBaaSIAMAdapter, _ *cov964Client) (any, error) {
				return a.UpdateApp(ctx, "tenant-a", "client-1", &iamsdk.UpdateAppRequest{})
			},
			want: func(c *cov964Client) any { return c.apps.apps["client-1"] },
			kind: "app",
			absent: func(a *QuicBaaSIAMAdapter) error {
				_, err := a.UpdateApp(ctx, "tenant-a", "missing", &iamsdk.UpdateAppRequest{})
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := cov964NewClient()
			adapter := NewQuicBaaSIAMAdapter(client)

			got, err := tt.call(adapter, client)
			require.NoError(t, err)
			assert.Same(t, tt.want(client), got)

			cov964RequireNotFound(t, tt.absent(adapter), tt.kind, "missing")
		})
	}
}

// TestCov964Adapter_CreatesListsAndDeletes checks the create, list and
// delete pass-through calls change the SDK store and report what it holds.
func TestCov964Adapter_CreatesListsAndDeletes(t *testing.T) {
	ctx := context.Background()
	client := cov964NewClient()
	adapter := NewQuicBaaSIAMAdapter(client)

	listReq := &iamsdk.ListUsersRequest{}
	users, err := adapter.ListUsers(ctx, "tenant-a", listReq)
	require.NoError(t, err)
	assert.Same(t, listReq, client.users.listed)
	require.Len(t, users.Users, 1)
	assert.Equal(t, "user-1", users.Users[0].ID)
	require.NoError(t, adapter.DeleteUser(ctx, "tenant-a", "user-1"))
	cov964RequireNotFound(t, adapter.DeleteUser(ctx, "tenant-a", "user-1"), "user", "user-1")

	group, err := adapter.CreateGroup(ctx, "tenant-a", &iamsdk.CreateGroupRequest{})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", group.TenantID)
	groups, err := adapter.ListGroups(ctx, "tenant-a", &iamsdk.ListGroupsRequest{})
	require.NoError(t, err)
	assert.Len(t, groups.Groups, 2)
	require.NoError(t, adapter.AddGroupMember(ctx, "tenant-a", "group-1", "user-9"))
	assert.Equal(t, []string{"user-9"}, client.groups.members["group-1"])
	cov964RequireNotFound(t, adapter.AddGroupMember(ctx, "tenant-a", "missing", "user-9"), "group", "missing")
	require.NoError(t, adapter.RemoveGroupMember(ctx, "tenant-a", "group-1", "user-9"))
	assert.Empty(t, client.groups.members["group-1"])
	cov964RequireNotFound(t, adapter.RemoveGroupMember(ctx, "tenant-a", "group-1", "user-9"), "member", "user-9")
	require.NoError(t, adapter.DeleteGroup(ctx, "tenant-a", "group-1"))
	cov964RequireNotFound(t, adapter.DeleteGroup(ctx, "tenant-a", "group-1"), "group", "group-1")

	role, err := adapter.CreateRole(ctx, "tenant-a", &iamsdk.CreateRoleRequest{})
	require.NoError(t, err)
	assert.Equal(t, "role-new", role.ID)
	roles, err := adapter.ListRoles(ctx, "tenant-a", &iamsdk.ListRolesRequest{})
	require.NoError(t, err)
	assert.Len(t, roles.Roles, 2)
	require.NoError(t, adapter.DeleteRole(ctx, "tenant-a", "role-1"))
	cov964RequireNotFound(t, adapter.DeleteRole(ctx, "tenant-a", "role-1"), "role", "role-1")

	app, err := adapter.RegisterApp(ctx, "tenant-a", &iamsdk.RegisterAppRequest{})
	require.NoError(t, err)
	assert.Equal(t, "client-new", app.ClientID)
	require.NoError(t, adapter.DeleteApp(ctx, "tenant-a", "client-new"))
	cov964RequireNotFound(t, adapter.DeleteApp(ctx, "tenant-a", "client-new"), "app", "client-new")
}

func TestCov964Adapter_CreateTenantEncodesSettings(t *testing.T) {
	client := cov964NewClient()
	adapter := NewQuicBaaSIAMAdapter(client)

	resp, err := adapter.CreateTenant(context.Background(), &CreateTenantRequest{
		ID:       "tenant-b",
		Name:     "Tenant B",
		Settings: &TenantSettings{MaxUsers: 25, MFARequired: true},
	})

	require.NoError(t, err)
	assert.Equal(t, "tenant-b", client.tenants.created.ID)
	assert.Equal(t, "Tenant B", client.tenants.created.Name)
	assert.Equal(t, map[string]string{"max_users": "25", "mfa_required": "true"}, client.tenants.created.Settings)
	assert.Equal(t, "tenant-b", resp.ID)
	assert.Equal(t, &TenantSettings{MaxUsers: 25, MFARequired: true}, resp.Settings)
	require.NotNil(t, resp.CreatedAt)
	assert.Equal(t, time.Unix(1700000000, 0).UTC(), *resp.CreatedAt)
	assert.Nil(t, resp.UpdatedAt, "a zero UpdatedAt is omitted")
}

func TestCov964Adapter_CreateTenantErrors(t *testing.T) {
	_, err := NewQuicBaaSIAMAdapter(cov964NewClient()).CreateTenant(context.Background(), nil)
	require.Error(t, err)

	client := cov964NewClient()
	client.tenants.err = cov964Unavailable{}
	_, err = NewQuicBaaSIAMAdapter(client).CreateTenant(context.Background(), &CreateTenantRequest{ID: "tenant-b"})
	assert.ErrorIs(t, err, cov964Unavailable{})
	assert.Nil(t, client.tenants.created.Settings, "no settings are sent when none are given")
}

func TestCov964Adapter_GetAndDeleteTenant(t *testing.T) {
	ctx := context.Background()
	adapter := NewQuicBaaSIAMAdapter(cov964NewClient())

	resp, err := adapter.GetTenant(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Equal(t, &TenantResponse{ID: "tenant-a", Name: "Tenant A"}, resp)

	_, err = adapter.GetTenant(ctx, "missing")
	cov964RequireNotFound(t, err, "tenant", "missing")

	require.NoError(t, adapter.DeleteTenant(ctx, "tenant-a"))
	cov964RequireNotFound(t, adapter.DeleteTenant(ctx, "tenant-a"), "tenant", "tenant-a")
}

func TestCov964Adapter_ListTenantsPageSize(t *testing.T) {
	tests := []struct {
		name     string
		limit    int32
		wantSize int
	}{
		{name: "positive limit becomes page size", limit: 10, wantSize: 10},
		{name: "zero limit leaves the SDK default", limit: 0, wantSize: 0},
		{name: "negative limit leaves the SDK default", limit: -4, wantSize: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := cov964NewClient()

			resp, err := NewQuicBaaSIAMAdapter(client).ListTenants(context.Background(), tt.limit, 0)

			require.NoError(t, err)
			assert.Equal(t, tt.wantSize, client.tenants.listed.PageSize)
			require.Len(t, resp.Tenants, 1)
			assert.Equal(t, "tenant-a", resp.Tenants[0].ID)
		})
	}
}

func TestCov964Adapter_ListTenantsError(t *testing.T) {
	client := cov964NewClient()
	client.tenants.err = cov964Unavailable{}

	_, err := NewQuicBaaSIAMAdapter(client).ListTenants(context.Background(), 5, 0)

	assert.ErrorIs(t, err, cov964Unavailable{})
}

func TestCov964Adapter_UpdateTenant(t *testing.T) {
	ctx := context.Background()
	client := cov964NewClient()
	adapter := NewQuicBaaSIAMAdapter(client)

	resp, err := adapter.UpdateTenant(ctx, "tenant-a", &UpdateTenantRequest{Settings: &TenantSettings{MaxUsers: 7}})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"max_users": "7"}, client.tenants.updated.Settings)
	assert.Equal(t, &TenantSettings{MaxUsers: 7}, resp.Settings)
	require.NotNil(t, resp.UpdatedAt)

	_, err = adapter.UpdateTenant(ctx, "tenant-a", nil)
	require.Error(t, err)

	_, err = adapter.UpdateTenant(ctx, "missing", &UpdateTenantRequest{})
	cov964RequireNotFound(t, err, "tenant", "missing")
	assert.Nil(t, client.tenants.updated.Settings, "no settings are sent when none are given")
}

func TestCov964DecodeTenantSettings(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]string
		want *TenantSettings
	}{
		{name: "empty map is no settings", in: map[string]string{}, want: nil},
		{name: "both keys", in: map[string]string{"max_users": "12", "mfa_required": "true"}, want: &TenantSettings{MaxUsers: 12, MFARequired: true}},
		{name: "mfa only true when literally true", in: map[string]string{"mfa_required": "yes"}, want: &TenantSettings{}},
		{name: "unparseable max users is zero", in: map[string]string{"max_users": "many"}, want: &TenantSettings{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, decodeTenantSettings(tt.in))
		})
	}
	assert.Nil(t, encodeTenantSettings(nil))
	assert.Empty(t, encodeTenantSettings(&TenantSettings{}))
	assert.Nil(t, decodeTenant(nil))
	assert.Nil(t, decodePolicy("tenant-a", nil))
	assert.Nil(t, decodeApp("tenant-a", nil))
}

func TestCov964ParsePolicyRulesFromYAML(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []iamsdk.Rule
	}{
		{name: "empty document", yaml: "", want: nil},
		{name: "malformed document", yaml: "spec: [", want: nil},
		{name: "no rules", yaml: "spec:\n  description: none\n", want: nil},
		{
			name: "spec rules with deny effect",
			yaml: "spec:\n  rules:\n    - name: block\n      effect: deny\n      priority: 9\n      actions: [\"iam:delete\"]\n      resources: [\"tenant/*\"]\n",
			want: []iamsdk.Rule{{
				Name:      "block",
				Effect:    iamsdk.EffectDeny,
				Priority:  9,
				Actions:   []iamsdk.ActionMatcher{{Pattern: "iam:delete"}},
				Resources: []iamsdk.ResourceMatcher{{Pattern: "tenant/*"}},
			}},
		},
		{
			name: "top-level rules default to allow",
			yaml: "rules:\n  - name: read\n    actions: [\"iam:get\", \"iam:list\"]\n",
			want: []iamsdk.Rule{{
				Name:      "read",
				Effect:    iamsdk.EffectAllow,
				Actions:   []iamsdk.ActionMatcher{{Pattern: "iam:get"}, {Pattern: "iam:list"}},
				Resources: []iamsdk.ResourceMatcher{},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parsePolicyRulesFromYAML(tt.yaml))
		})
	}
}

func TestCov964Adapter_CreatePolicy(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		wantRules []iamsdk.Rule
	}{
		{
			name: "rules come from the spec",
			spec: "spec:\n  rules:\n    - name: read\n      actions: [\"iam:get\"]\n",
			wantRules: []iamsdk.Rule{{
				Name:      "read",
				Effect:    iamsdk.EffectAllow,
				Actions:   []iamsdk.ActionMatcher{{Pattern: "iam:get"}},
				Resources: []iamsdk.ResourceMatcher{},
			}},
		},
		{
			name: "a spec without rules gets the deny-all placeholder",
			spec: "",
			wantRules: []iamsdk.Rule{{
				Name:    "default",
				Effect:  iamsdk.EffectDeny,
				Actions: []iamsdk.ActionMatcher{{Pattern: "*"}},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := cov964NewClient()

			resp, err := NewQuicBaaSIAMAdapter(client).CreatePolicy(context.Background(), "tenant-a", &CreatePolicyRequest{
				Name:        "audit",
				Description: "audit access",
				Priority:    4,
				SpecYAML:    tt.spec,
				Labels:      map[string]string{"team": "sec"},
			})

			require.NoError(t, err)
			sent := client.policies.created
			assert.Equal(t, tt.wantRules, sent.Rules)
			assert.True(t, sent.Enabled)
			assert.Equal(t, 4, sent.Priority)
			assert.Equal(t, []byte(tt.spec), sent.SpecYAML)
			assert.Equal(t, map[string]string{"team": "sec"}, sent.Labels)
			assert.Equal(t, "audit", resp.Name)
			assert.Equal(t, "tenant-a", resp.TenantID)
			assert.Equal(t, int32(4), resp.Priority)
			require.NotNil(t, resp.CreatedAt)
			assert.Nil(t, resp.UpdatedAt)
		})
	}
}

func TestCov964Adapter_CreatePolicyErrors(t *testing.T) {
	_, err := NewQuicBaaSIAMAdapter(cov964NewClient()).CreatePolicy(context.Background(), "tenant-a", nil)
	require.Error(t, err)

	client := cov964NewClient()
	client.policies.err = cov964Unavailable{}
	_, err = NewQuicBaaSIAMAdapter(client).CreatePolicy(context.Background(), "tenant-a", &CreatePolicyRequest{Name: "audit"})
	assert.ErrorIs(t, err, cov964Unavailable{})
}

func TestCov964Adapter_GetListDeletePolicy(t *testing.T) {
	ctx := context.Background()
	client := cov964NewClient()
	adapter := NewQuicBaaSIAMAdapter(client)

	got, err := adapter.GetPolicy(ctx, "tenant-a", "read-only")
	require.NoError(t, err)
	assert.Equal(t, &PolicyResponse{Name: "read-only", TenantID: "tenant-a", Description: "reads", Priority: 3, SpecYAML: "rules: []"}, got)
	_, err = adapter.GetPolicy(ctx, "tenant-a", "missing")
	cov964RequireNotFound(t, err, "policy", "missing")

	list, err := adapter.ListPolicies(ctx, "tenant-a", 20, 0)
	require.NoError(t, err)
	assert.Equal(t, 20, client.policies.listed.Limit)
	require.Len(t, list.Policies, 1)
	assert.Equal(t, "tenant-a", list.Policies[0].TenantID)
	_, err = adapter.ListPolicies(ctx, "tenant-a", 0, 0)
	require.NoError(t, err)
	assert.Zero(t, client.policies.listed.Limit, "no limit leaves the SDK default")

	require.NoError(t, adapter.DeletePolicy(ctx, "tenant-a", "read-only"))
	cov964RequireNotFound(t, adapter.DeletePolicy(ctx, "tenant-a", "read-only"), "policy", "read-only")

	client.policies.err = cov964Unavailable{}
	_, err = adapter.ListPolicies(ctx, "tenant-a", 1, 0)
	assert.ErrorIs(t, err, cov964Unavailable{})
}

func TestCov964Adapter_UpdatePolicy(t *testing.T) {
	ctx := context.Background()
	client := cov964NewClient()
	adapter := NewQuicBaaSIAMAdapter(client)

	resp, err := adapter.UpdatePolicy(ctx, "tenant-a", "read-only", &UpdatePolicyRequest{
		Description: "reads only",
		Priority:    8,
		Labels:      map[string]string{"tier": "1"},
	})
	require.NoError(t, err)
	sent := client.policies.updated
	assert.Equal(t, "reads only", *sent.Description)
	assert.Equal(t, 8, *sent.Priority)
	assert.Equal(t, map[string]string{"tier": "1"}, sent.Labels)
	assert.Equal(t, "reads only", resp.Description)
	assert.Equal(t, int32(8), resp.Priority)
	require.NotNil(t, resp.UpdatedAt)

	_, err = adapter.UpdatePolicy(ctx, "tenant-a", "missing", &UpdatePolicyRequest{})
	cov964RequireNotFound(t, err, "policy", "missing")
}

func TestCov964Adapter_UpdatePolicyRefusesBeforeTheSDK(t *testing.T) {
	tests := []struct {
		name string
		req  *UpdatePolicyRequest
	}{
		{name: "nil request", req: nil},
		{name: "spec yaml cannot be updated in place", req: &UpdatePolicyRequest{SpecYAML: "rules: []"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := cov964NewClient()

			_, err := NewQuicBaaSIAMAdapter(client).UpdatePolicy(context.Background(), "tenant-a", "read-only", tt.req)

			require.Error(t, err)
			assert.Nil(t, client.policies.updated, "the SDK must not be called")
		})
	}
}

func TestCov964Adapter_ValidatePolicy(t *testing.T) {
	client := cov964NewClient()
	client.policies.validRes = &iamsdk.ValidationResult{
		Valid:  false,
		Errors: []iamsdk.ValidationError{{Field: "spec.rules", Message: "rules are required"}},
	}
	adapter := NewQuicBaaSIAMAdapter(client)

	resp, err := adapter.ValidatePolicy(context.Background(), "tenant-a", "spec: {}")

	require.NoError(t, err)
	assert.Equal(t, &ValidatePolicyResponse{Valid: false, Errors: []string{"rules are required"}}, resp)
	assert.Equal(t, "tenant-a", client.policies.validated.TenantID)
	assert.Equal(t, []byte("spec: {}"), client.policies.validated.SpecYAML)

	client.policies.err = cov964Unavailable{}
	_, err = adapter.ValidatePolicy(context.Background(), "tenant-a", "spec: {}")
	assert.ErrorIs(t, err, cov964Unavailable{})
}

func TestCov964Adapter_TestPolicySendsOneInlineCase(t *testing.T) {
	client := cov964NewClient()
	client.policies.testRes = &iamsdk.TestPolicyResponse{Passed: 1}

	resp, err := NewQuicBaaSIAMAdapter(client).TestPolicy(context.Background(), "tenant-a", &TestPolicyRequest{
		SubjectID: "user-1",
		Roles:     []string{"viewer"},
		Groups:    []string{"ops"},
		Action:    "iam:get",
		Resource:  "tenant/a",
		Context:   map[string]string{"ip": "10.0.0.1"},
	})

	require.NoError(t, err)
	require.Len(t, client.policies.tested.TestCases, 1)
	tc := client.policies.tested.TestCases[0]
	assert.Equal(t, "rest-inline", tc.Name)
	assert.Equal(t, iamsdk.Subject{ID: "user-1", TenantID: "tenant-a", Roles: []string{"viewer"}, Groups: []string{"ops"}}, tc.Subject)
	assert.Equal(t, "iam:get", tc.Action)
	assert.Equal(t, "tenant/a", tc.Resource)
	assert.Equal(t, map[string]interface{}{"ip": "10.0.0.1"}, tc.Context)
	assert.Equal(t, &TestPolicyResponse{Allowed: true}, resp, "a passing count with no results is allowed")
}

func TestCov964Adapter_TestPolicyResultDecides(t *testing.T) {
	tests := []struct {
		name string
		res  *iamsdk.TestPolicyResponse
		want *TestPolicyResponse
	}{
		{
			name: "first result denies despite a passing count",
			res:  &iamsdk.TestPolicyResponse{Passed: 1, Results: []iamsdk.TestCaseResult{{Passed: false, MatchedRule: "block"}}},
			want: &TestPolicyResponse{Allowed: false, MatchedRule: "block"},
		},
		{
			name: "first result allows",
			res:  &iamsdk.TestPolicyResponse{Results: []iamsdk.TestCaseResult{{Passed: true, MatchedRule: "read"}}},
			want: &TestPolicyResponse{Allowed: true, MatchedRule: "read"},
		},
		{
			name: "nothing passed",
			res:  &iamsdk.TestPolicyResponse{Failed: 1},
			want: &TestPolicyResponse{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := cov964NewClient()
			client.policies.testRes = tt.res

			resp, err := NewQuicBaaSIAMAdapter(client).TestPolicy(context.Background(), "tenant-a", &TestPolicyRequest{Action: "iam:get"})

			require.NoError(t, err)
			assert.Equal(t, tt.want, resp)
		})
	}
}

func TestCov964Adapter_TestPolicyErrors(t *testing.T) {
	client := cov964NewClient()
	_, err := NewQuicBaaSIAMAdapter(client).TestPolicy(context.Background(), "tenant-a", nil)
	require.Error(t, err)
	assert.Nil(t, client.policies.tested, "the SDK must not be called")

	client.policies.err = cov964Unavailable{}
	_, err = NewQuicBaaSIAMAdapter(client).TestPolicy(context.Background(), "tenant-a", &TestPolicyRequest{})
	assert.ErrorIs(t, err, cov964Unavailable{})
}

func TestCov964Adapter_ListApps(t *testing.T) {
	client := cov964NewClient()
	adapter := NewQuicBaaSIAMAdapter(client)

	resp, err := adapter.ListApps(context.Background(), "tenant-a", 0, 0)

	require.NoError(t, err)
	require.Len(t, resp.Apps, 1)
	app := resp.Apps[0]
	assert.Equal(t, "client-1", app.ClientID)
	assert.Equal(t, "tenant-a", app.TenantID)
	assert.Equal(t, "portal", app.Name)
	assert.Equal(t, []string{"https://portal.example.com/cb"}, app.RedirectURIs)
	assert.Equal(t, []string{"client_credentials"}, app.GrantTypes)
	require.NotNil(t, app.CreatedAt)
	require.NotNil(t, app.UpdatedAt)
	assert.Equal(t, time.Unix(1700000100, 0).UTC(), *app.UpdatedAt)

	client.apps.err = cov964Unavailable{}
	_, err = adapter.ListApps(context.Background(), "tenant-a", 0, 0)
	assert.ErrorIs(t, err, cov964Unavailable{})
}

func TestCov964Adapter_RotateAppSecret(t *testing.T) {
	ctx := context.Background()
	client := cov964NewClient()
	adapter := NewQuicBaaSIAMAdapter(client)

	resp, err := adapter.RotateAppSecret(ctx, "tenant-a", "client-1")
	require.NoError(t, err)
	assert.Equal(t, &RotateSecretResponse{ClientID: "client-1", ClientSecret: "rotated-secret"}, resp)

	_, err = adapter.RotateAppSecret(ctx, "tenant-a", "missing")
	cov964RequireNotFound(t, err, "app", "missing")
}

func TestCov964PEPAdapter_Check(t *testing.T) {
	pep := &cov964PEP{resp: &iamsdk.CheckResponse{Allowed: true, MatchedPolicy: "read-only"}}
	req := &iamsdk.CheckRequest{Action: "iam:get"}

	resp, err := NewQuicBaaSPEPAdapter(pep).Check(context.Background(), req)

	require.NoError(t, err)
	assert.Same(t, req, pep.checked)
	assert.Same(t, pep.resp, resp)
}
