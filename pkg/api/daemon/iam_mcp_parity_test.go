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

//go:build iam && codec_msgpack

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	platformiam "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
	sdkmcp "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
)

// memIAMCreated is the creation time of every record memIAM stores, so two
// runs of the same calls produce the same answers.
var memIAMCreated = time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)

// memIAM is an in-memory QuicBaaS IAM client: users, roles and tenants in
// maps, and a PEP that allows an action when one of the subject's roles
// grants it. A missing record is the SDK's NotFound error, as QuicBaaS
// answers it.
type memIAM struct {
	quicbaassdk.IAMClient

	mu      sync.Mutex
	users   map[string]*sdkiam.User
	roles   map[string]*sdkiam.Role
	tenants map[string]*sdkiam.Tenant
}

func newMemIAM() *memIAM {
	return &memIAM{
		users:   map[string]*sdkiam.User{},
		roles:   map[string]*sdkiam.Role{},
		tenants: map[string]*sdkiam.Tenant{},
	}
}

func (m *memIAM) User() sdkiam.UserClient     { return memUsers{m: m} }
func (m *memIAM) Role() sdkiam.RoleClient     { return memRoles{m: m} }
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
	u.m.mu.Lock()
	defer u.m.mu.Unlock()
	user := &sdkiam.User{
		ID: req.Email, TenantID: tenantID, Email: req.Email, DisplayName: req.DisplayName,
		Roles: req.Roles, Metadata: req.Metadata,
		CreatedAt: memIAMCreated, UpdatedAt: memIAMCreated,
	}
	u.m.users[memKey(tenantID, user.ID)] = user
	copied := *user
	return &copied, nil
}

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

// wiredIAMGRPCService is the gRPC IAM service on an in-memory IAM client.
func wiredIAMGRPCService(iam *memIAM) *IAMGRPCService {
	return NewIAMGRPCService(slog.Default(), iam, iam.PEP())
}

// wiredIAMToolRegistry is the MCP tool registry on an in-memory IAM client,
// built the way createMCPServer builds it.
func wiredIAMToolRegistry(iam *memIAM) *mcp.ToolRegistry {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{IAMClient: iam, PEPClient: iam.PEP()})
	return mcp.NewToolRegistry(provider, logging.DefaultLogger())
}

// iamParityTransports opens the SDK IAM client over gRPC and over MCP, each
// on its own in-memory IAM client.
func iamParityTransports() map[string]func(t *testing.T, iam *memIAM) *platformiam.Client {
	return map[string]func(t *testing.T, iam *memIAM) *platformiam.Client{
		"gRPC": func(t *testing.T, iam *memIAM) *platformiam.Client {
			return iamTokenGRPCClient(t, wiredIAMGRPCService(iam), nil)
		},
		"MCP": func(t *testing.T, iam *memIAM) *platformiam.Client {
			srv := httptest.NewServer(mcpToolBridge(t, wiredIAMToolRegistry(iam)))
			t.Cleanup(srv.Close)
			adapter, err := sdkmcp.Connect(context.Background(), platform.NewOptions(platform.WithMCPAddr(srv.URL)))
			return iamClient(connection(t, adapter, err))
		},
	}
}

// iamScript runs one tool group's calls through an SDK IAM client and
// returns every answer in order.
type iamScript func(ctx context.Context, t *testing.T, c *platformiam.Client) []proto.Message

func iamUsersScript(ctx context.Context, t *testing.T, c *platformiam.Client) []proto.Message {
	alice, err := c.CreateUser(ctx, &platformv1.CreateIAMUserRequest{
		TenantId: "acme", Email: "alice@acme.test", Name: "Alice", Attributes: map[string]string{"dept": "ops"},
	})
	require.NoError(t, err)
	bob, err := c.CreateUser(ctx, &platformv1.CreateIAMUserRequest{TenantId: "acme", Email: "bob@acme.test"})
	require.NoError(t, err)
	got, err := c.GetUser(ctx, "acme", alice.GetId())
	require.NoError(t, err)
	listReq := &platformv1.ListIAMUsersRequest{TenantId: "acme", Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 10}}
	listed, total, err := c.ListUsers(ctx, listReq)
	require.NoError(t, err)
	require.NoError(t, c.DeleteUser(ctx, "acme", bob.GetId()))
	remaining, remainingTotal, err := c.ListUsers(ctx, listReq)
	require.NoError(t, err)

	answers := []proto.Message{alice, bob, got, wrapperspb.Int64(total)}
	for _, user := range listed {
		answers = append(answers, user)
	}
	answers = append(answers, wrapperspb.Int64(remainingTotal))
	for _, user := range remaining {
		answers = append(answers, user)
	}
	return answers
}

func iamRolesScript(ctx context.Context, t *testing.T, c *platformiam.Client) []proto.Message {
	admin, err := c.CreateRole(ctx, &platformv1.CreateIAMRoleRequest{
		TenantId: "acme", Id: "admin", Name: "Admin", Description: "all of it", Permissions: []string{"iam:read", "iam:write"},
	})
	require.NoError(t, err)
	got, err := c.GetRole(ctx, "acme", "admin")
	require.NoError(t, err)
	alice, err := c.CreateUser(ctx, &platformv1.CreateIAMUserRequest{TenantId: "acme", Email: "alice@acme.test"})
	require.NoError(t, err)
	require.NoError(t, c.AssignRole(ctx, "acme", alice.GetId(), "admin"))
	assigned, err := c.GetUser(ctx, "acme", alice.GetId())
	require.NoError(t, err)
	require.Equal(t, []string{"admin"}, assigned.GetRoles(), "the role reached the IAM client")
	require.NoError(t, c.RevokeRole(ctx, "acme", alice.GetId(), "admin"))
	revoked, err := c.GetUser(ctx, "acme", alice.GetId())
	require.NoError(t, err)
	listReq := &platformv1.ListIAMRolesRequest{TenantId: "acme"}
	listed, total, err := c.ListRoles(ctx, listReq)
	require.NoError(t, err)
	require.NoError(t, c.DeleteRole(ctx, "acme", "admin"))
	_, remainingTotal, err := c.ListRoles(ctx, listReq)
	require.NoError(t, err)

	answers := []proto.Message{admin, got, assigned, revoked, wrapperspb.Int64(total), wrapperspb.Int64(remainingTotal)}
	for _, role := range listed {
		answers = append(answers, role)
	}
	return answers
}

func iamTenantsScript(ctx context.Context, t *testing.T, c *platformiam.Client) []proto.Message {
	acme, err := c.CreateTenant(ctx, &platformv1.CreateIAMTenantRequest{
		Id: "acme", Name: "Acme", Settings: &platformv1.IAMTenantSettings{MfaRequired: true},
	})
	require.NoError(t, err)
	require.True(t, acme.GetSettings().GetMfaRequired(), "the settings reached the IAM client")
	globex, err := c.CreateTenant(ctx, &platformv1.CreateIAMTenantRequest{Id: "globex", Name: "Globex"})
	require.NoError(t, err)
	got, err := c.GetTenant(ctx, "acme")
	require.NoError(t, err)
	listed, total, err := c.ListTenants(ctx, &platformv1.ListIAMTenantsRequest{})
	require.NoError(t, err)
	require.NoError(t, c.DeleteTenant(ctx, "globex"))
	remaining, remainingTotal, err := c.ListTenants(ctx, &platformv1.ListIAMTenantsRequest{})
	require.NoError(t, err)

	answers := []proto.Message{acme, globex, got, wrapperspb.Int64(total), wrapperspb.Int64(remainingTotal)}
	for _, tenant := range append(listed, remaining...) {
		answers = append(answers, tenant)
	}
	return answers
}

func iamCheckPermissionScript(ctx context.Context, t *testing.T, c *platformiam.Client) []proto.Message {
	_, err := c.CreateRole(ctx, &platformv1.CreateIAMRoleRequest{
		TenantId: "acme", Id: "reader", Name: "Reader", Permissions: []string{"device:read"},
	})
	require.NoError(t, err)

	var answers []proto.Message
	for _, action := range []string{"device:read", "device:write"} {
		decision, err := c.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{
			TenantId: "acme", SubjectId: "alice", Roles: []string{"reader"},
			Action: action, Resource: "device://rack-1", Context: map[string]string{"source": "parity"},
		})
		require.NoError(t, err)
		decision.Timestamp = nil // the time of the answer, not part of it
		answers = append(answers, decision)
	}
	require.True(t, answers[0].(*platformv1.CheckIAMPermissionResponse).GetAllowed(), "the reader role grants device:read")
	require.False(t, answers[1].(*platformv1.CheckIAMPermissionResponse).GetAllowed(), "the reader role does not grant device:write")
	return answers
}

// TestIAMMCPParity: each IAM tool group gives the SDK the same answers over
// MCP as over gRPC, both transports on the same in-memory QuicBaaS IAM
// client.
func TestIAMMCPParity(t *testing.T) {
	scripts := map[string]iamScript{
		"users":            iamUsersScript,
		"roles":            iamRolesScript,
		"tenants":          iamTenantsScript,
		"check_permission": iamCheckPermissionScript,
	}
	ctx := context.Background()

	for group, script := range scripts {
		t.Run(group, func(t *testing.T) {
			answers := map[string][]proto.Message{}
			for name, open := range iamParityTransports() {
				answers[name] = script(ctx, t, open(t, newMemIAM()))
			}

			want, got := answers["gRPC"], answers["MCP"]
			require.NotEmpty(t, want)
			require.Len(t, got, len(want))
			for i := range want {
				assert.True(t, proto.Equal(want[i], got[i]),
					"answer %d differs:\ngRPC: %s\nMCP:  %s", i, protojson.Format(want[i]), protojson.Format(got[i]))
			}
		})
	}
}

// iamErrorCase is one failing IAM call made through the gRPC method and
// through its MCP tool.
type iamErrorCase struct {
	grpc func(ctx context.Context, svc *IAMGRPCService) error
	tool string
	args map[string]interface{}
	want codes.Code
}

func iamErrorCases() map[string]iamErrorCase {
	return map[string]iamErrorCase{
		"users/not found": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.GetUser(ctx, &platformv1.GetIAMUserRequest{TenantId: "acme", UserId: "nobody"})
				return err
			},
			tool: "iam_get_user", args: map[string]interface{}{"tenant_id": "acme", "user_id": "nobody"},
			want: codes.NotFound,
		},
		"users/delete not found": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.DeleteUser(ctx, &platformv1.DeleteIAMUserRequest{TenantId: "acme", UserId: "nobody"})
				return err
			},
			tool: "iam_delete_user", args: map[string]interface{}{"tenant_id": "acme", "user_id": "nobody"},
			want: codes.NotFound,
		},
		"users/no tenant": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.CreateUser(ctx, &platformv1.CreateIAMUserRequest{Email: "alice@acme.test"})
				return err
			},
			tool: "iam_create_user", args: map[string]interface{}{"email": "alice@acme.test"},
			want: codes.InvalidArgument,
		},
		"roles/not found": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.GetRole(ctx, &platformv1.GetIAMRoleRequest{TenantId: "acme", RoleId: "nobody"})
				return err
			},
			tool: "iam_get_role", args: map[string]interface{}{"tenant_id": "acme", "role_id": "nobody"},
			want: codes.NotFound,
		},
		"roles/assign to a missing user": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{TenantId: "acme", UserId: "nobody", RoleId: "admin"})
				return err
			},
			tool: "iam_assign_role", args: map[string]interface{}{"tenant_id": "acme", "user_id": "nobody", "role_id": "admin"},
			want: codes.NotFound,
		},
		"roles/no role id": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.RevokeRole(ctx, &platformv1.RevokeIAMRoleRequest{TenantId: "acme", UserId: "alice"})
				return err
			},
			tool: "iam_revoke_role", args: map[string]interface{}{"tenant_id": "acme", "user_id": "alice"},
			want: codes.InvalidArgument,
		},
		"tenants/not found": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.GetTenant(ctx, &platformv1.GetIAMTenantRequest{TenantId: "nobody"})
				return err
			},
			tool: "iam_get_tenant", args: map[string]interface{}{"tenant_id": "nobody"},
			want: codes.NotFound,
		},
		"tenants/no id": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.CreateTenant(ctx, &platformv1.CreateIAMTenantRequest{Name: "Acme"})
				return err
			},
			tool: "iam_create_tenant", args: map[string]interface{}{"name": "Acme"},
			want: codes.InvalidArgument,
		},
		"check_permission/no action": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{TenantId: "acme", SubjectId: "alice", Resource: "device://rack-1"})
				return err
			},
			tool: "iam_check_permission", args: map[string]interface{}{"tenant_id": "acme", "subject_id": "alice", "resource": "device://rack-1"},
			want: codes.InvalidArgument,
		},
		"check_permission/resource the PEP rejects": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{
					TenantId: "acme", SubjectId: "alice", Action: "device:read", Resource: "rack-1",
				})
				return err
			},
			tool: "iam_check_permission",
			args: map[string]interface{}{"tenant_id": "acme", "subject_id": "alice", "action": "device:read", "resource": "rack-1"},
			want: codes.InvalidArgument,
		},
	}
}

// TestIAMMCPErrorParity: a failing IAM call gets the same error class from
// its MCP tool as from its gRPC method, for a missing record and for invalid
// input. The SDK's MCP wire client retries every error one second apart, so
// the MCP side is asserted at the tool registry the MCP server runs.
func TestIAMMCPErrorParity(t *testing.T) {
	ctx := context.Background()
	svc := wiredIAMGRPCService(newMemIAM())
	registry := wiredIAMToolRegistry(newMemIAM())

	for name, tc := range iamErrorCases() {
		t.Run(name, func(t *testing.T) {
			grpcErr := tc.grpc(ctx, svc)
			assert.Equal(t, tc.want, status.Code(grpcErr), "gRPC: %v", grpcErr)

			got, mcpErr := registry.ExecuteTool(ctx, tc.tool, tc.args)
			assert.Nil(t, got)
			assert.Equal(t, tc.want, status.Code(mcpErr), "MCP: %v", mcpErr)
		})
	}
}

// TestIAMMCPUnavailableParity: without the QuicBaaS IAM clients every call
// above answers the typed unavailable error over both transports, before
// any input check.
func TestIAMMCPUnavailableParity(t *testing.T) {
	ctx := context.Background()
	svc := NewIAMGRPCService(slog.Default(), nil, nil)
	registry := mcp.NewToolRegistry(NewMCPServiceProvider(&MCPServiceProviderConfig{}), logging.DefaultLogger())

	for name, tc := range iamErrorCases() {
		t.Run(name, func(t *testing.T) {
			var unavailable ErrIAMServiceNotAvailable

			grpcErr := tc.grpc(ctx, svc)
			assert.True(t, errors.As(grpcErr, &unavailable), "gRPC: %v", grpcErr)
			assert.Equal(t, codes.FailedPrecondition, status.Code(grpcErr))

			_, mcpErr := registry.ExecuteTool(ctx, tc.tool, tc.args)
			assert.True(t, errors.As(mcpErr, &unavailable), "MCP: %v", mcpErr)
			assert.Equal(t, codes.FailedPrecondition, status.Code(mcpErr))
		})
	}
}

// TestIAMGRPCService_WrapError: a status error keeps its code, an SDK error
// gets the code of its category, and anything else is Internal.
func TestIAMGRPCService_WrapError(t *testing.T) {
	svc := NewIAMGRPCService(slog.Default(), nil, nil)
	cases := map[string]struct {
		err  error
		want codes.Code
	}{
		"status error":       {status.Error(codes.PermissionDenied, "denied"), codes.PermissionDenied},
		"SDK not found":      {sdkerrors.NewNotFound("op", "missing"), codes.NotFound},
		"SDK invalid input":  {sdkerrors.NewInvalidInput("op", "bad"), codes.InvalidArgument},
		"SDK already exists": {sdkerrors.NewAlreadyExists("op", "dup"), codes.AlreadyExists},
		"SDK forbidden":      {sdkerrors.NewForbidden("op", "no"), codes.PermissionDenied},
		"SDK unavailable":    {sdkerrors.NewUnavailable("op", "down"), codes.Unavailable},
		"SDK internal":       {sdkerrors.NewInternal("op", "boom"), codes.Internal},
		"plain error":        {errLivenessUnreachable{}, codes.Internal},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, status.Code(svc.wrapError(tc.err)))
		})
	}
}

// newMCPTestDaemon is a daemon whose MCP server is not yet created, built
// the way TestCreateMCPServer_SkipIAMValidationIsTheOnlyOptOut builds it.
func newMCPTestDaemon(t *testing.T, socketPath string) *Daemon {
	config := testConfig(socketPath)
	config.EnableMCP = false
	d, err := New(config)
	require.NoError(t, err)
	d.config.MCPConfig = &MCPConfig{Transport: "stdio"}
	return d
}

// TestCreateMCPServer_HandsTheIAMClientsToTheProvider: with QuicBaaS IAM the
// MCP IAM tools answer from the daemon's IAM client and its PEP.
func TestCreateMCPServer_HandsTheIAMClientsToTheProvider(t *testing.T) {
	ctx := context.Background()
	iam := newMemIAM()
	_, err := iam.User().Create(ctx, "acme", &sdkiam.CreateUserRequest{Email: "alice@acme.test"})
	require.NoError(t, err)
	_, err = iam.Role().Create(ctx, "acme", &sdkiam.CreateRoleRequest{ID: "reader", Permissions: []string{"device:read"}})
	require.NoError(t, err)

	d := newMCPTestDaemon(t, "/tmp/test-mcp-iam-wired.sock")
	d.iamService = &IAMService{iamClient: iam}
	_, err = d.createMCPServer()
	require.NoError(t, err)
	registry := mcp.NewToolRegistry(d.mcpProvider, logging.DefaultLogger())

	user, err := registry.ExecuteTool(ctx, "iam_get_user", map[string]interface{}{"tenant_id": "acme", "user_id": "alice@acme.test"})
	require.NoError(t, err, "the user tools answer from the IAM client")
	assert.Equal(t, "alice@acme.test", user.(map[string]interface{})["user"].(map[string]interface{})["email"])

	decision, err := registry.ExecuteTool(ctx, "iam_check_permission", map[string]interface{}{
		"tenant_id": "acme", "subject_id": "alice", "roles": []interface{}{"reader"},
		"action": "device:read", "resource": "device://rack-1",
	})
	require.NoError(t, err, "check_permission answers from the PEP")
	assert.Equal(t, true, decision.(map[string]interface{})["allowed"])
}

// TestCreateMCPServer_WithoutIAMTheToolsAreUnavailable: without QuicBaaS IAM
// the MCP IAM tools answer the typed unavailable error.
func TestCreateMCPServer_WithoutIAMTheToolsAreUnavailable(t *testing.T) {
	ctx := context.Background()
	d := newMCPTestDaemon(t, "/tmp/test-mcp-iam-absent.sock")
	d.iamService = nil
	_, err := d.createMCPServer()
	require.NoError(t, err)
	registry := mcp.NewToolRegistry(d.mcpProvider, logging.DefaultLogger())

	for tool, args := range map[string]map[string]interface{}{
		"iam_get_user": {"tenant_id": "acme", "user_id": "alice"},
		"iam_check_permission": {
			"tenant_id": "acme", "subject_id": "alice", "action": "device:read", "resource": "device://rack-1",
		},
	} {
		got, err := registry.ExecuteTool(ctx, tool, args)
		var unavailable ErrIAMServiceNotAvailable
		assert.True(t, errors.As(err, &unavailable), "%s: %v", tool, err)
		assert.Nil(t, got, tool)
	}
}
