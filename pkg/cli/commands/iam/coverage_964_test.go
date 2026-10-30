package iam

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	iamsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
)

// fakeIAMServer is an in-process PlatformIAMService. fail makes every RPC
// return Internal, empty makes lists and lookups return nothing, and
// rejected makes every status-bearing RPC report Success=false.
type fakeIAMServer struct {
	platformv1.UnimplementedPlatformIAMServiceServer
	fail     bool
	empty    bool
	rejected bool

	lastTenantUpdate atomic.Pointer[platformv1.UpdateIAMTenantRequest]
}

var errFakeIAM = status.Error(codes.Internal, "fake iam failure")

func (s *fakeIAMServer) opStatus() *platformv1.Status {
	return &platformv1.Status{Success: !s.rejected, Message: "done"}
}

func (s *fakeIAMServer) user() *platformv1.IAMUser {
	return &platformv1.IAMUser{
		Id: "u1", TenantId: "t1", Email: "u1@example.com", Name: "User One",
		Roles: []string{"admin"}, Groups: []string{"ops"},
		Attributes: map[string]string{"dept": "eng"}, MfaVerified: true,
		CreatedAt: timestamppb.Now(), UpdatedAt: timestamppb.Now(), LastAuth: timestamppb.Now(),
	}
}

func (s *fakeIAMServer) role() *platformv1.IAMRole {
	return &platformv1.IAMRole{
		Id: "r1", TenantId: "t1", Name: "Reader", Description: "read only",
		Permissions: []string{"vm:read", "vm:list"}, CreatedAt: timestamppb.Now(),
	}
}

func (s *fakeIAMServer) group() *platformv1.IAMGroup {
	return &platformv1.IAMGroup{
		Id: "g1", TenantId: "t1", Name: "Ops", Description: "operators",
		Members: []string{"u1"}, CreatedAt: timestamppb.Now(),
	}
}

func (s *fakeIAMServer) tenant() *platformv1.IAMTenant {
	if s.empty {
		return nil
	}
	return &platformv1.IAMTenant{
		Id: "t1", Name: "Acme",
		Settings:  &platformv1.IAMTenantSettings{MaxUsers: 25, MfaRequired: true},
		CreatedAt: timestamppb.Now(),
	}
}

func (s *fakeIAMServer) policy() *platformv1.IAMPolicy {
	return &platformv1.IAMPolicy{
		Name: "p1", TenantId: "t1", Description: "allow reads", Priority: 10,
		SpecYaml: []byte("rules: []"), Labels: map[string]string{"env": "dev"},
		CreatedAt: timestamppb.Now(),
	}
}

func (s *fakeIAMServer) app() *platformv1.IAMApp {
	return &platformv1.IAMApp{
		ClientId: "c1", ClientSecret: "s3cret", TenantId: "t1", Name: "portal",
		RedirectUris: []string{"https://portal/cb"}, GrantTypes: []string{"authorization_code"},
		ResponseTypes: []string{"code"}, ResourcePrefix: "/portal", CreatedAt: timestamppb.Now(),
	}
}

func (s *fakeIAMServer) CreateUser(context.Context, *platformv1.CreateIAMUserRequest) (*platformv1.IAMUserResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMUserResponse{User: s.user()}, nil
}

func (s *fakeIAMServer) GetUser(context.Context, *platformv1.GetIAMUserRequest) (*platformv1.IAMUserResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMUserResponse{User: s.user()}, nil
}

func (s *fakeIAMServer) ListUsers(context.Context, *platformv1.ListIAMUsersRequest) (*platformv1.ListIAMUsersResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	if s.empty {
		return &platformv1.ListIAMUsersResponse{}, nil
	}
	return &platformv1.ListIAMUsersResponse{Users: []*platformv1.IAMUser{s.user()}, Total: 1}, nil
}

func (s *fakeIAMServer) UpdateUser(context.Context, *platformv1.UpdateIAMUserRequest) (*platformv1.IAMUserResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMUserResponse{User: s.user()}, nil
}

func (s *fakeIAMServer) DeleteUser(context.Context, *platformv1.DeleteIAMUserRequest) (*platformv1.DeleteIAMUserResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.DeleteIAMUserResponse{Status: s.opStatus()}, nil
}

func (s *fakeIAMServer) AssignRole(context.Context, *platformv1.AssignIAMRoleRequest) (*platformv1.AssignIAMRoleResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.AssignIAMRoleResponse{Status: s.opStatus()}, nil
}

func (s *fakeIAMServer) RevokeRole(context.Context, *platformv1.RevokeIAMRoleRequest) (*platformv1.RevokeIAMRoleResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.RevokeIAMRoleResponse{Status: s.opStatus()}, nil
}

func (s *fakeIAMServer) CreateRole(context.Context, *platformv1.CreateIAMRoleRequest) (*platformv1.IAMRoleResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMRoleResponse{Role: s.role()}, nil
}

func (s *fakeIAMServer) GetRole(context.Context, *platformv1.GetIAMRoleRequest) (*platformv1.IAMRoleResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMRoleResponse{Role: s.role()}, nil
}

func (s *fakeIAMServer) ListRoles(context.Context, *platformv1.ListIAMRolesRequest) (*platformv1.ListIAMRolesResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	if s.empty {
		return &platformv1.ListIAMRolesResponse{}, nil
	}
	return &platformv1.ListIAMRolesResponse{Roles: []*platformv1.IAMRole{s.role()}, Total: 1}, nil
}

func (s *fakeIAMServer) UpdateRole(context.Context, *platformv1.UpdateIAMRoleRequest) (*platformv1.IAMRoleResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMRoleResponse{Role: s.role()}, nil
}

func (s *fakeIAMServer) DeleteRole(context.Context, *platformv1.DeleteIAMRoleRequest) (*platformv1.DeleteIAMRoleResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.DeleteIAMRoleResponse{Status: s.opStatus()}, nil
}

func (s *fakeIAMServer) CreateGroup(context.Context, *platformv1.CreateIAMGroupRequest) (*platformv1.IAMGroupResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMGroupResponse{Group: s.group()}, nil
}

func (s *fakeIAMServer) GetGroup(context.Context, *platformv1.GetIAMGroupRequest) (*platformv1.IAMGroupResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMGroupResponse{Group: s.group()}, nil
}

func (s *fakeIAMServer) ListGroups(context.Context, *platformv1.ListIAMGroupsRequest) (*platformv1.ListIAMGroupsResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	if s.empty {
		return &platformv1.ListIAMGroupsResponse{}, nil
	}
	return &platformv1.ListIAMGroupsResponse{Groups: []*platformv1.IAMGroup{s.group()}, Total: 1}, nil
}

func (s *fakeIAMServer) UpdateGroup(context.Context, *platformv1.UpdateIAMGroupRequest) (*platformv1.IAMGroupResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMGroupResponse{Group: s.group()}, nil
}

func (s *fakeIAMServer) DeleteGroup(context.Context, *platformv1.DeleteIAMGroupRequest) (*platformv1.DeleteIAMGroupResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.DeleteIAMGroupResponse{Status: s.opStatus()}, nil
}

func (s *fakeIAMServer) CreateTenant(context.Context, *platformv1.CreateIAMTenantRequest) (*platformv1.IAMTenantResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMTenantResponse{Tenant: s.tenant()}, nil
}

func (s *fakeIAMServer) GetTenant(context.Context, *platformv1.GetIAMTenantRequest) (*platformv1.IAMTenantResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMTenantResponse{Tenant: s.tenant()}, nil
}

func (s *fakeIAMServer) ListTenants(context.Context, *platformv1.ListIAMTenantsRequest) (*platformv1.ListIAMTenantsResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	if s.empty {
		return &platformv1.ListIAMTenantsResponse{}, nil
	}
	unlimited := &platformv1.IAMTenant{Id: "t2", Name: "Free"}
	return &platformv1.ListIAMTenantsResponse{Tenants: []*platformv1.IAMTenant{s.tenant(), unlimited}, Total: 2}, nil
}

func (s *fakeIAMServer) UpdateTenant(_ context.Context, req *platformv1.UpdateIAMTenantRequest) (*platformv1.IAMTenantResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	s.lastTenantUpdate.Store(req)
	return &platformv1.IAMTenantResponse{Tenant: s.tenant()}, nil
}

func (s *fakeIAMServer) DeleteTenant(context.Context, *platformv1.DeleteIAMTenantRequest) (*platformv1.DeleteIAMTenantResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.DeleteIAMTenantResponse{Status: s.opStatus()}, nil
}

func (s *fakeIAMServer) CreatePolicy(context.Context, *platformv1.CreateIAMPolicyRequest) (*platformv1.IAMPolicyResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMPolicyResponse{Policy: s.policy()}, nil
}

func (s *fakeIAMServer) GetPolicy(context.Context, *platformv1.GetIAMPolicyRequest) (*platformv1.IAMPolicyResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMPolicyResponse{Policy: s.policy()}, nil
}

func (s *fakeIAMServer) ListPolicies(context.Context, *platformv1.ListIAMPoliciesRequest) (*platformv1.ListIAMPoliciesResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	if s.empty {
		return &platformv1.ListIAMPoliciesResponse{}, nil
	}
	return &platformv1.ListIAMPoliciesResponse{Policies: []*platformv1.IAMPolicy{s.policy()}, Total: 1}, nil
}

func (s *fakeIAMServer) UpdatePolicy(context.Context, *platformv1.UpdateIAMPolicyRequest) (*platformv1.IAMPolicyResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMPolicyResponse{Policy: s.policy()}, nil
}

func (s *fakeIAMServer) DeletePolicy(context.Context, *platformv1.DeleteIAMPolicyRequest) (*platformv1.DeleteIAMPolicyResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.DeleteIAMPolicyResponse{Status: s.opStatus()}, nil
}

func (s *fakeIAMServer) ValidatePolicy(context.Context, *platformv1.ValidateIAMPolicyRequest) (*platformv1.ValidateIAMPolicyResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	if s.rejected {
		return &platformv1.ValidateIAMPolicyResponse{Valid: false, Errors: []string{"rules: required"}}, nil
	}
	return &platformv1.ValidateIAMPolicyResponse{Valid: true}, nil
}

func (s *fakeIAMServer) TestPolicy(context.Context, *platformv1.TestIAMPolicyRequest) (*platformv1.TestIAMPolicyResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	if s.rejected {
		return &platformv1.TestIAMPolicyResponse{Allowed: false, EvaluationTimeNs: 1200}, nil
	}
	return &platformv1.TestIAMPolicyResponse{
		Allowed: true, MatchedPolicy: "p1", MatchedRule: "allow-read", EvaluationTimeNs: 1200,
	}, nil
}

func (s *fakeIAMServer) RegisterApp(context.Context, *platformv1.RegisterIAMAppRequest) (*platformv1.IAMAppResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMAppResponse{App: s.app()}, nil
}

func (s *fakeIAMServer) GetApp(context.Context, *platformv1.GetIAMAppRequest) (*platformv1.IAMAppResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMAppResponse{App: s.app()}, nil
}

func (s *fakeIAMServer) ListApps(context.Context, *platformv1.ListIAMAppsRequest) (*platformv1.ListIAMAppsResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	if s.empty {
		return &platformv1.ListIAMAppsResponse{}, nil
	}
	return &platformv1.ListIAMAppsResponse{Apps: []*platformv1.IAMApp{s.app()}, Total: 1}, nil
}

func (s *fakeIAMServer) UpdateApp(context.Context, *platformv1.UpdateIAMAppRequest) (*platformv1.IAMAppResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.IAMAppResponse{App: s.app()}, nil
}

func (s *fakeIAMServer) DeleteApp(context.Context, *platformv1.DeleteIAMAppRequest) (*platformv1.DeleteIAMAppResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.DeleteIAMAppResponse{Status: s.opStatus()}, nil
}

func (s *fakeIAMServer) RotateAppSecret(context.Context, *platformv1.RotateIAMAppSecretRequest) (*platformv1.RotateIAMAppSecretResponse, error) {
	if s.fail {
		return nil, errFakeIAM
	}
	return &platformv1.RotateIAMAppSecretResponse{ClientId: "c1", Name: "portal", ClientSecret: "n3w"}, nil
}

// startFakeIAM serves srv on a unix socket in a temp dir and returns a flags
// factory whose local context dials it.
func startFakeIAM(t *testing.T, srv *fakeIAMServer) func(cli.OutputFormat) *cli.CommonFlags {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	gs := grpc.NewServer()
	platformv1.RegisterPlatformIAMServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	return func(format cli.OutputFormat) *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
			NoColor:      true,
			GetContext: func() (*cli.Context, error) {
				return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
			},
		}
	}
}

// iamRunCase is one CLI run function plus the WrappedError message it
// reports when the IAM service fails.
type iamRunCase struct {
	name    string
	failMsg string
	run     func(f *cli.CommonFlags) error
}

func iamRunCases(policyFile string) []iamRunCase {
	return []iamRunCase{
		{"UserCreate", "failed to create user", func(f *cli.CommonFlags) error {
			return runUserCreate(f, "t1", "u1@example.com", "User One", "admin", "ops", "dept=eng")
		}},
		{"UserGet", "failed to get user", func(f *cli.CommonFlags) error { return runUserGet(f, "t1", "u1") }},
		{"UserList", "failed to list users", func(f *cli.CommonFlags) error {
			return runUserList(f, "t1", 1, 10, iamsvc.UserListFilter{})
		}},
		{"UserUpdate", "failed to update user", func(f *cli.CommonFlags) error {
			return runUserUpdate(f, "t1", "u1", "new@example.com", "New", "admin", "ops", "dept=ops")
		}},
		{"UserDelete", "failed to delete user", func(f *cli.CommonFlags) error { return runUserDelete(f, "t1", "u1") }},
		{"UserAssignRole", "failed to assign role", func(f *cli.CommonFlags) error { return runUserAssignRole(f, "t1", "u1", "r1") }},
		{"UserRevokeRole", "failed to revoke role", func(f *cli.CommonFlags) error { return runUserRevokeRole(f, "t1", "u1", "r1") }},
		{"RoleCreate", "failed to create role", func(f *cli.CommonFlags) error {
			return runRoleCreate(f, "t1", "r1", "Reader", "read only", []string{"vm:read"})
		}},
		{"RoleGet", "failed to get role", func(f *cli.CommonFlags) error { return runRoleGet(f, "t1", "r1") }},
		{"RoleList", "failed to list roles", func(f *cli.CommonFlags) error { return runRoleList(f, "t1", 1, 10) }},
		{"RoleUpdate", "failed to update role", func(f *cli.CommonFlags) error {
			return runRoleUpdate(f, "t1", "r1", "Reader", "read only", []string{"vm:read"})
		}},
		{"RoleDelete", "failed to delete role", func(f *cli.CommonFlags) error { return runRoleDelete(f, "t1", "r1") }},
		{"GroupCreate", "failed to create group", func(f *cli.CommonFlags) error {
			return runGroupCreate(f, "t1", "g1", "Ops", "operators")
		}},
		{"GroupGet", "failed to get group", func(f *cli.CommonFlags) error { return runGroupGet(f, "t1", "g1") }},
		{"GroupList", "failed to list groups", func(f *cli.CommonFlags) error { return runGroupList(f, "t1", 1, 10) }},
		{"GroupUpdate", "failed to update group", func(f *cli.CommonFlags) error {
			return runGroupUpdate(f, "t1", "g1", "Ops", "operators")
		}},
		{"GroupDelete", "failed to delete group", func(f *cli.CommonFlags) error { return runGroupDelete(f, "t1", "g1") }},
		{"TenantCreate", "failed to create tenant", func(f *cli.CommonFlags) error {
			return runTenantCreate(f, "t1", "Acme", 25, true)
		}},
		{"TenantGet", "failed to get tenant", func(f *cli.CommonFlags) error { return runTenantGet(f, "t1") }},
		{"TenantList", "failed to list tenants", func(f *cli.CommonFlags) error { return runTenantList(f, 1, 10) }},
		{"TenantUpdate", "failed to get tenant for update", func(f *cli.CommonFlags) error {
			return runTenantUpdate(f, "t1", "Acme Corp", 50, false, true)
		}},
		{"TenantDelete", "failed to delete tenant", func(f *cli.CommonFlags) error { return runTenantDelete(f, "t1") }},
		{"PolicyCreate", "failed to create policy", func(f *cli.CommonFlags) error {
			return runPolicyCreate(f, "t1", "p1", "allow reads", 10, policyFile, "env=dev")
		}},
		{"PolicyGet", "failed to get policy", func(f *cli.CommonFlags) error { return runPolicyGet(f, "t1", "p1") }},
		{"PolicyList", "failed to list policies", func(f *cli.CommonFlags) error { return runPolicyList(f, "t1", 1, 10) }},
		{"PolicyUpdate", "failed to update policy", func(f *cli.CommonFlags) error {
			return runPolicyUpdate(f, "t1", "p1", "allow reads", 10, policyFile, "env=dev")
		}},
		{"PolicyDelete", "failed to delete policy", func(f *cli.CommonFlags) error { return runPolicyDelete(f, "t1", "p1") }},
		{"PolicyValidate", "failed to validate policy", func(f *cli.CommonFlags) error { return runPolicyValidate(f, "t1", policyFile) }},
		{"PolicyTest", "failed to test policy", func(f *cli.CommonFlags) error {
			return runPolicyTest(f, "t1", "u1", "admin", "ops", "read", "vm/1", "ip=10.0.0.1")
		}},
		{"AppRegister", "failed to register application", func(f *cli.CommonFlags) error {
			return runAppRegister(f, "t1", "portal", "https://portal/cb", "authorization_code", "code", "/portal")
		}},
		{"AppGet", "failed to get application", func(f *cli.CommonFlags) error { return runAppGet(f, "t1", "c1") }},
		{"AppList", "failed to list applications", func(f *cli.CommonFlags) error { return runAppList(f, "t1", 1, 10) }},
		{"AppUpdate", "failed to update application", func(f *cli.CommonFlags) error {
			return runAppUpdate(f, "t1", "c1", "portal", "https://portal/cb", "authorization_code", "code", "/portal")
		}},
		{"AppDelete", "failed to delete application", func(f *cli.CommonFlags) error { return runAppDelete(f, "t1", "c1") }},
		{"AppRotateSecret", "failed to rotate application secret", func(f *cli.CommonFlags) error {
			return runAppRotateSecret(f, "t1", "c1")
		}},
	}
}

func writePolicyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte("rules: []\n"), 0o600))
	return path
}

// TestRunCommands964_Success runs every command against a healthy service in
// every output format, and again with empty lists and rejected operations.
func TestRunCommands964_Success(t *testing.T) {
	policyFile := writePolicyFile(t)
	servers := map[string]*fakeIAMServer{
		"populated": {},
		"rejected":  {rejected: true},
	}
	formats := []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatJSON, cli.OutputFormatYAML}

	for srvName, srv := range servers {
		flags := startFakeIAM(t, srv)
		for _, format := range formats {
			for _, tc := range iamRunCases(policyFile) {
				t.Run(srvName+"/"+string(format)+"/"+tc.name, func(t *testing.T) {
					require.NoError(t, tc.run(flags(format)))
				})
			}
		}
	}
}

// TestRunCommands964_EmptyResults covers the "nothing found" table output of
// every list command.
func TestRunCommands964_EmptyResults(t *testing.T) {
	flags := startFakeIAM(t, &fakeIAMServer{empty: true})(cli.OutputFormatTable)

	lists := map[string]func() error{
		"users":    func() error { return runUserList(flags, "t1", 1, 10, iamsvc.UserListFilter{}) },
		"roles":    func() error { return runRoleList(flags, "t1", 1, 10) },
		"groups":   func() error { return runGroupList(flags, "t1", 1, 10) },
		"tenants":  func() error { return runTenantList(flags, 1, 10) },
		"policies": func() error { return runPolicyList(flags, "t1", 1, 10) },
		"apps":     func() error { return runAppList(flags, "t1", 1, 10) },
	}
	for name, run := range lists {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, run())
		})
	}
}

// TestRunCommands964_ServiceError asserts every command wraps a service
// failure in a WrappedError carrying its own message and the cause.
func TestRunCommands964_ServiceError(t *testing.T) {
	flags := startFakeIAM(t, &fakeIAMServer{fail: true})
	for _, tc := range iamRunCases(writePolicyFile(t)) {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(flags(cli.OutputFormatJSON))
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			require.Equal(t, tc.failMsg, wrapped.Msg)
			require.Equal(t, codes.Internal, status.Code(err))
			require.Contains(t, err.Error(), tc.failMsg)
		})
	}
}

// TestRunCommands964_InvalidOutputFormat asserts every command rejects an
// unknown output format after a successful call.
func TestRunCommands964_InvalidOutputFormat(t *testing.T) {
	flags := startFakeIAM(t, &fakeIAMServer{})
	for _, tc := range iamRunCases(writePolicyFile(t)) {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(flags(cli.OutputFormat("xml")))
			var invalid cli.ErrInvalidOutputFormat
			require.ErrorAs(t, err, &invalid)
			require.Equal(t, "xml", invalid.Format)
		})
	}
}

// TestRunTenantUpdate964_PreservesCurrentSettings asserts that fields left
// unset on the command line keep the tenant's current values.
func TestRunTenantUpdate964_PreservesCurrentSettings(t *testing.T) {
	srv := &fakeIAMServer{}
	flags := startFakeIAM(t, srv)

	require.NoError(t, runTenantUpdate(flags(cli.OutputFormatJSON), "t1", "", 0, false, false))
	req := srv.lastTenantUpdate.Load()
	require.NotNil(t, req)
	require.Equal(t, "Acme", req.GetName())
	require.Equal(t, int32(25), req.GetSettings().GetMaxUsers())
	require.True(t, req.GetSettings().GetMfaRequired())

	require.NoError(t, runTenantUpdate(flags(cli.OutputFormatJSON), "t1", "Acme Corp", 50, false, true))
	req = srv.lastTenantUpdate.Load()
	require.Equal(t, "Acme Corp", req.GetName())
	require.Equal(t, int32(50), req.GetSettings().GetMaxUsers())
	require.False(t, req.GetSettings().GetMfaRequired())
}

// TestRunTenantUpdate964_TenantNotFound asserts a missing tenant is reported
// as a MessageError and no update is sent.
func TestRunTenantUpdate964_TenantNotFound(t *testing.T) {
	srv := &fakeIAMServer{empty: true}
	flags := startFakeIAM(t, srv)

	err := runTenantUpdate(flags(cli.OutputFormatJSON), "t9", "x", 0, false, false)
	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	require.Equal(t, "tenant not found: t9", msgErr.Msg)
	require.Nil(t, srv.lastTenantUpdate.Load())
}

// TestRunPolicy964_UnreadableFile asserts the policy commands that take a
// spec file report a read failure before calling the service.
func TestRunPolicy964_UnreadableFile(t *testing.T) {
	flags := startFakeIAM(t, &fakeIAMServer{})(cli.OutputFormatJSON)
	missing := filepath.Join(t.TempDir(), "absent.yaml")

	runs := map[string]func() error{
		"create":   func() error { return runPolicyCreate(flags, "t1", "p1", "", 1, missing, "") },
		"update":   func() error { return runPolicyUpdate(flags, "t1", "p1", "", 1, missing, "") },
		"validate": func() error { return runPolicyValidate(flags, "t1", missing) },
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			err := run()
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			require.Equal(t, "failed to read policy file", wrapped.Msg)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}
