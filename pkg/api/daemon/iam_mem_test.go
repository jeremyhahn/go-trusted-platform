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

package daemon

import (
	"context"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
)

// wiredIAMGRPCService is the gRPC IAM service on an in-memory IAM client.
func wiredIAMGRPCService(iam *memIAM) *IAMGRPCService {
	return NewIAMGRPCService(slog.Default(), iam, iam.PEP())
}

// memIAMCreated is the creation time of every record memIAM stores, so two
// runs of the same calls produce the same answers.
var memIAMCreated = time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)

// memIAM is an in-memory QuicBaaS IAM client: users, roles, groups and
// tenants in maps, and a PEP that allows an action when one of the subject's
// roles grants it. A missing record is the SDK's NotFound error, as QuicBaaS
// answers it.
type memIAM struct {
	quicbaassdk.IAMClient

	mu      sync.Mutex
	users   map[string]*sdkiam.User
	roles   map[string]*sdkiam.Role
	groups  map[string]*sdkiam.Group
	tenants map[string]*sdkiam.Tenant
}

func newMemIAM() *memIAM {
	return &memIAM{
		users:   map[string]*sdkiam.User{},
		roles:   map[string]*sdkiam.Role{},
		groups:  map[string]*sdkiam.Group{},
		tenants: map[string]*sdkiam.Tenant{},
	}
}

func (m *memIAM) User() sdkiam.UserClient     { return memUsers{m: m} }
func (m *memIAM) Role() sdkiam.RoleClient     { return memRoles{m: m} }
func (m *memIAM) Group() sdkiam.GroupClient   { return memGroups{m: m} }
func (m *memIAM) Tenant() sdkiam.TenantClient { return memTenants{m: m} }
func (m *memIAM) PEP() sdkiam.PEPClient       { return memPEP{m: m} }

func memKey(tenantID, id string) string { return tenantID + "/" + id }

// memFind returns the record under tenantID/id, or the SDK's NotFound error.
func memFind[T any](records map[string]*T, op, tenantID, id string) (*T, error) {
	record, ok := records[memKey(tenantID, id)]
	if !ok {
		return nil, sdkerrors.NewNotFound(op, id+" not found")
	}
	return record, nil
}

// memList returns the records of tenantID sorted by key; an empty tenantID
// lists every record.
func memList[T any](records map[string]*T, tenantID string) []T {
	keys := make([]string, 0, len(records))
	for key := range records {
		if tenantID == "" || strings.HasPrefix(key, tenantID+"/") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	list := make([]T, 0, len(keys))
	for _, key := range keys {
		list = append(list, *records[key])
	}
	return list
}

type memUsers struct {
	sdkiam.UserClient
	m *memIAM
}

func (u memUsers) Create(_ context.Context, tenantID string, req *sdkiam.CreateUserRequest) (*sdkiam.User, error) {
	// The real SDK refuses a create without a username
	// (INVALID_INPUT: iam.user.Create: username is required); so does the fake.
	if req.Username == "" {
		return nil, errMemUsernameRequired{}
	}
	u.m.mu.Lock()
	defer u.m.mu.Unlock()
	user := &sdkiam.User{
		ID: req.Email, TenantID: tenantID, Username: req.Username, Email: req.Email, DisplayName: req.DisplayName,
		Roles: req.Roles, Groups: req.Groups, Metadata: req.Metadata,
		CreatedAt: memIAMCreated, UpdatedAt: memIAMCreated,
	}
	u.m.users[memKey(tenantID, user.ID)] = user
	copied := *user
	return &copied, nil
}

// errMemUsernameRequired is the fake's refusal of a create with no username.
type errMemUsernameRequired struct{}

func (errMemUsernameRequired) Error() string { return "iam.user.Create: username is required" }

func (u memUsers) Get(_ context.Context, tenantID, userID string) (*sdkiam.User, error) {
	u.m.mu.Lock()
	defer u.m.mu.Unlock()
	user, err := memFind(u.m.users, "iam.user.get", tenantID, userID)
	if err != nil {
		return nil, err
	}
	copied := *user
	return &copied, nil
}

// Update applies the non-empty fields, as the SDK's partial update does.
func (u memUsers) Update(_ context.Context, tenantID, userID string, req *sdkiam.UpdateUserRequest) (*sdkiam.User, error) {
	u.m.mu.Lock()
	defer u.m.mu.Unlock()
	user, err := memFind(u.m.users, "iam.user.update", tenantID, userID)
	if err != nil {
		return nil, err
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	if req.Metadata != nil {
		user.Metadata = req.Metadata
	}
	copied := *user
	return &copied, nil
}

func (u memUsers) Delete(_ context.Context, tenantID, userID string) error {
	u.m.mu.Lock()
	defer u.m.mu.Unlock()
	if _, err := memFind(u.m.users, "iam.user.delete", tenantID, userID); err != nil {
		return err
	}
	delete(u.m.users, memKey(tenantID, userID))
	return nil
}

func (u memUsers) List(_ context.Context, tenantID string, _ *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
	u.m.mu.Lock()
	defer u.m.mu.Unlock()
	users := memList(u.m.users, tenantID)
	return &sdkiam.ListUsersResponse{Users: users, Pagination: sdkiam.PaginationInfo{TotalCount: len(users)}}, nil
}

func (u memUsers) AssignRole(_ context.Context, tenantID, userID, roleID string) error {
	u.m.mu.Lock()
	defer u.m.mu.Unlock()
	user, err := memFind(u.m.users, "iam.user.assign_role", tenantID, userID)
	if err != nil {
		return err
	}
	if _, err := memFind(u.m.roles, "iam.user.assign_role", tenantID, roleID); err != nil {
		return err
	}
	user.Roles = append(user.Roles, roleID)
	return nil
}

func (u memUsers) RevokeRole(_ context.Context, tenantID, userID, roleID string) error {
	u.m.mu.Lock()
	defer u.m.mu.Unlock()
	user, err := memFind(u.m.users, "iam.user.revoke_role", tenantID, userID)
	if err != nil {
		return err
	}
	user.Roles = slices.DeleteFunc(user.Roles, func(id string) bool { return id == roleID })
	return nil
}

type memRoles struct {
	sdkiam.RoleClient
	m *memIAM
}

func (r memRoles) Create(_ context.Context, tenantID string, req *sdkiam.CreateRoleRequest) (*sdkiam.Role, error) {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	role := &sdkiam.Role{
		ID: req.ID, TenantID: tenantID, Name: req.Name, Description: req.Description,
		Permissions: req.Permissions, CreatedAt: memIAMCreated, UpdatedAt: memIAMCreated,
	}
	r.m.roles[memKey(tenantID, role.ID)] = role
	copied := *role
	return &copied, nil
}

func (r memRoles) Get(_ context.Context, tenantID, roleID string) (*sdkiam.Role, error) {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	role, err := memFind(r.m.roles, "iam.role.get", tenantID, roleID)
	if err != nil {
		return nil, err
	}
	copied := *role
	return &copied, nil
}

// Update applies the non-empty fields, as the SDK's partial update does.
func (r memRoles) Update(_ context.Context, tenantID, roleID string, req *sdkiam.UpdateRoleRequest) (*sdkiam.Role, error) {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	role, err := memFind(r.m.roles, "iam.role.update", tenantID, roleID)
	if err != nil {
		return nil, err
	}
	if req.Name != "" {
		role.Name = req.Name
	}
	if req.Description != "" {
		role.Description = req.Description
	}
	if req.Permissions != nil {
		role.Permissions = req.Permissions
	}
	copied := *role
	return &copied, nil
}

func (r memRoles) Delete(_ context.Context, tenantID, roleID string) error {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	if _, err := memFind(r.m.roles, "iam.role.delete", tenantID, roleID); err != nil {
		return err
	}
	delete(r.m.roles, memKey(tenantID, roleID))
	return nil
}

func (r memRoles) List(_ context.Context, tenantID string, _ *sdkiam.ListRolesRequest) (*sdkiam.ListRolesResponse, error) {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	roles := memList(r.m.roles, tenantID)
	return &sdkiam.ListRolesResponse{Roles: roles, Pagination: sdkiam.PaginationInfo{TotalCount: len(roles)}}, nil
}

type memGroups struct {
	sdkiam.GroupClient
	m *memIAM
}

func (g memGroups) Create(_ context.Context, tenantID string, req *sdkiam.CreateGroupRequest) (*sdkiam.Group, error) {
	g.m.mu.Lock()
	defer g.m.mu.Unlock()
	group := &sdkiam.Group{
		ID: req.ID, TenantID: tenantID, Name: req.Name, Description: req.Description,
		CreatedAt: memIAMCreated, UpdatedAt: memIAMCreated,
	}
	g.m.groups[memKey(tenantID, group.ID)] = group
	copied := *group
	return &copied, nil
}

func (g memGroups) Get(_ context.Context, tenantID, groupID string) (*sdkiam.Group, error) {
	g.m.mu.Lock()
	defer g.m.mu.Unlock()
	group, err := memFind(g.m.groups, "iam.group.get", tenantID, groupID)
	if err != nil {
		return nil, err
	}
	copied := *group
	return &copied, nil
}

// Update applies the non-empty fields, as the SDK's partial update does.
func (g memGroups) Update(_ context.Context, tenantID, groupID string, req *sdkiam.UpdateGroupRequest) (*sdkiam.Group, error) {
	g.m.mu.Lock()
	defer g.m.mu.Unlock()
	group, err := memFind(g.m.groups, "iam.group.update", tenantID, groupID)
	if err != nil {
		return nil, err
	}
	if req.Name != "" {
		group.Name = req.Name
	}
	if req.Description != "" {
		group.Description = req.Description
	}
	copied := *group
	return &copied, nil
}

func (g memGroups) Delete(_ context.Context, tenantID, groupID string) error {
	g.m.mu.Lock()
	defer g.m.mu.Unlock()
	if _, err := memFind(g.m.groups, "iam.group.delete", tenantID, groupID); err != nil {
		return err
	}
	delete(g.m.groups, memKey(tenantID, groupID))
	return nil
}

func (g memGroups) List(_ context.Context, tenantID string, _ *sdkiam.ListGroupsRequest) (*sdkiam.ListGroupsResponse, error) {
	g.m.mu.Lock()
	defer g.m.mu.Unlock()
	groups := memList(g.m.groups, tenantID)
	return &sdkiam.ListGroupsResponse{Groups: groups, Pagination: sdkiam.PaginationInfo{TotalCount: len(groups)}}, nil
}

func (g memGroups) AddMember(_ context.Context, tenantID, groupID, userID string) error {
	g.m.mu.Lock()
	defer g.m.mu.Unlock()
	group, err := memFind(g.m.groups, "iam.group.add_member", tenantID, groupID)
	if err != nil {
		return err
	}
	user, err := memFind(g.m.users, "iam.group.add_member", tenantID, userID)
	if err != nil {
		return err
	}
	user.Groups = append(user.Groups, groupID)
	group.MemberCount++
	return nil
}

func (g memGroups) RemoveMember(_ context.Context, tenantID, groupID, userID string) error {
	g.m.mu.Lock()
	defer g.m.mu.Unlock()
	group, err := memFind(g.m.groups, "iam.group.remove_member", tenantID, groupID)
	if err != nil {
		return err
	}
	user, err := memFind(g.m.users, "iam.group.remove_member", tenantID, userID)
	if err != nil {
		return err
	}
	user.Groups = slices.DeleteFunc(user.Groups, func(id string) bool { return id == groupID })
	group.MemberCount--
	return nil
}

// memTenants keys tenants under an empty tenant prefix, so a tenant ID is
// its own key.
type memTenants struct {
	sdkiam.TenantClient
	m *memIAM
}

func (tc memTenants) Create(_ context.Context, req *sdkiam.CreateTenantRequest) (*sdkiam.Tenant, error) {
	tc.m.mu.Lock()
	defer tc.m.mu.Unlock()
	tenant := &sdkiam.Tenant{
		ID: req.ID, Name: req.Name, Settings: req.Settings,
		CreatedAt: memIAMCreated, UpdatedAt: memIAMCreated,
	}
	tc.m.tenants[memKey("", tenant.ID)] = tenant
	copied := *tenant
	return &copied, nil
}

func (tc memTenants) Get(_ context.Context, tenantID string) (*sdkiam.Tenant, error) {
	tc.m.mu.Lock()
	defer tc.m.mu.Unlock()
	tenant, err := memFind(tc.m.tenants, "iam.tenant.get", "", tenantID)
	if err != nil {
		return nil, err
	}
	copied := *tenant
	return &copied, nil
}

func (tc memTenants) Delete(_ context.Context, tenantID string) error {
	tc.m.mu.Lock()
	defer tc.m.mu.Unlock()
	if _, err := memFind(tc.m.tenants, "iam.tenant.delete", "", tenantID); err != nil {
		return err
	}
	delete(tc.m.tenants, memKey("", tenantID))
	return nil
}

func (tc memTenants) List(_ context.Context, _ *sdkiam.ListTenantsRequest) (*sdkiam.ListTenantsResponse, error) {
	tc.m.mu.Lock()
	defer tc.m.mu.Unlock()
	tenants := memList(tc.m.tenants, "")
	return &sdkiam.ListTenantsResponse{Tenants: tenants, Pagination: sdkiam.PaginationInfo{TotalCount: len(tenants)}}, nil
}

// memPEP allows an action when one of the subject's roles grants it, and
// rejects a resource that is not a type://path URI as invalid input.
type memPEP struct {
	m *memIAM
}

func (p memPEP) Check(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
	if !strings.Contains(req.Resource, "://") {
		return nil, sdkerrors.NewInvalidInput("iam.pep.check", "resource must be a type://path URI")
	}
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	for _, roleID := range req.Subject.Roles {
		role, ok := p.m.roles[memKey(req.Subject.TenantID, roleID)]
		if ok && slices.Contains(role.Permissions, req.Action) {
			return &sdkiam.CheckResponse{Allowed: true, MatchedPolicy: "role:" + roleID, MatchedRule: req.Action}, nil
		}
	}
	return &sdkiam.CheckResponse{Allowed: false}, nil
}

func (p memPEP) CheckBatch(_ context.Context, _ *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error) {
	return nil, sdkerrors.NewUnimplemented("iam.pep.check_batch", "not used by the IAM service")
}
