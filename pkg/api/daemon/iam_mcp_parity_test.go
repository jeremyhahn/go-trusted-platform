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
	"testing"

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

// The create request carries only an email; the SDK refuses an empty
// username, so the service derives it from the email's local part.
func TestIAMGRPCService_CreateUserDerivesUsernameFromEmail(t *testing.T) {
	iam := newMemIAM()
	svc := wiredIAMGRPCService(iam)
	ctx := context.Background()

	_, err := svc.CreateUser(ctx, &platformv1.CreateIAMUserRequest{TenantId: "acme", Email: "alice@acme.test"})
	require.NoError(t, err)

	stored, err := iam.User().Get(ctx, "acme", "alice@acme.test")
	require.NoError(t, err)
	assert.Equal(t, "alice", stored.Username)
}

func TestIAMGRPCService_CreateUserWithoutEmailIsRefused(t *testing.T) {
	svc := wiredIAMGRPCService(newMemIAM())

	_, err := svc.CreateUser(context.Background(), &platformv1.CreateIAMUserRequest{TenantId: "acme"})
	require.Error(t, err)
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

func iamGroupsScript(ctx context.Context, t *testing.T, c *platformiam.Client) []proto.Message {
	ops, err := c.CreateGroup(ctx, &platformv1.CreateIAMGroupRequest{TenantId: "acme", Id: "ops", Name: "Ops", Description: "on call"})
	require.NoError(t, err)
	alice, err := c.CreateUser(ctx, &platformv1.CreateIAMUserRequest{TenantId: "acme", Email: "alice@acme.test"})
	require.NoError(t, err)
	require.NoError(t, c.AddGroupMember(ctx, "acme", "ops", alice.GetId()))
	member, err := c.GetUser(ctx, "acme", alice.GetId())
	require.NoError(t, err)
	require.Equal(t, []string{"ops"}, member.GetGroups(), "the membership reached the IAM client")
	withMember, err := c.GetGroup(ctx, "acme", "ops")
	require.NoError(t, err)
	require.NoError(t, c.RemoveGroupMember(ctx, "acme", "ops", alice.GetId()))
	removed, err := c.GetUser(ctx, "acme", alice.GetId())
	require.NoError(t, err)
	listReq := &platformv1.ListIAMGroupsRequest{TenantId: "acme"}
	listed, total, err := c.ListGroups(ctx, listReq)
	require.NoError(t, err)
	require.NoError(t, c.DeleteGroup(ctx, "acme", "ops"))
	_, remainingTotal, err := c.ListGroups(ctx, listReq)
	require.NoError(t, err)

	answers := []proto.Message{ops, member, withMember, removed, wrapperspb.Int64(total), wrapperspb.Int64(remainingTotal)}
	for _, group := range listed {
		answers = append(answers, group)
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
		"groups":           iamGroupsScript,
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
		"groups/not found": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.GetGroup(ctx, &platformv1.GetIAMGroupRequest{TenantId: "acme", GroupId: "nobody"})
				return err
			},
			tool: "iam_get_group", args: map[string]interface{}{"tenant_id": "acme", "group_id": "nobody"},
			want: codes.NotFound,
		},
		"groups/add to a missing group": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.AddGroupMember(ctx, &platformv1.AddGroupMemberRequest{TenantId: "acme", GroupId: "nobody", UserId: "alice"})
				return err
			},
			tool: "iam_add_group_member", args: map[string]interface{}{"tenant_id": "acme", "group_id": "nobody", "user_id": "alice"},
			want: codes.NotFound,
		},
		"groups/no user id": {
			grpc: func(ctx context.Context, svc *IAMGRPCService) error {
				_, err := svc.RemoveGroupMember(ctx, &platformv1.RemoveGroupMemberRequest{TenantId: "acme", GroupId: "ops"})
				return err
			},
			tool: "iam_remove_group_member", args: map[string]interface{}{"tenant_id": "acme", "group_id": "ops"},
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

// upstreamTestCode and upstreamTestError have the shape of the QuicBaaS
// server's structured error, which the embedded transport hands through
// untranslated and which the platform may not import.
type upstreamTestCode string

func (c upstreamTestCode) String() string { return string(c) }

type upstreamTestError struct {
	Code upstreamTestCode
	Op   string
	Err  error
}

func (e *upstreamTestError) Error() string { return e.Op + ": " + e.Code.String() }
func (e *upstreamTestError) Unwrap() error { return e.Err }

// An invalid role permission refused by the in-process server is the
// caller's fault: InvalidArgument, never Internal (#973 CreateRole).
func TestIAMGRPCService_WrapError_UpstreamServerError(t *testing.T) {
	svc := NewIAMGRPCService(slog.Default(), nil, nil)
	invalid := &upstreamTestError{Code: "invalid_input", Op: "iam.role.qrdb.create"}
	cases := map[string]struct {
		err  error
		want codes.Code
	}{
		"invalid input":         {&upstreamTestError{Code: "invalid_input", Op: "api.create role", Err: invalid}, codes.InvalidArgument},
		"wrapped invalid input": {&upstreamTestError{Code: "storage", Op: "api", Err: invalid}, codes.InvalidArgument},
		"not found":             {&upstreamTestError{Code: "not_found", Op: "api.get role"}, codes.NotFound},
		"already exists":        {&upstreamTestError{Code: "already_exists", Op: "api.create role"}, codes.AlreadyExists},
		"unclassified code":     {&upstreamTestError{Code: "split_brain", Op: "api"}, codes.Internal},
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
	_, err := iam.User().Create(ctx, "acme", &sdkiam.CreateUserRequest{Username: "alice", Email: "alice@acme.test"})
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
