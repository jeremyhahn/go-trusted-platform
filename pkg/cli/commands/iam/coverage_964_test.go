package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"gopkg.in/yaml.v3"

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
	name     string
	failMsg  string
	run      func(f *cli.CommonFlags) error
	want     iamWant
	rejected *iamWant // the rejected server's outcome; nil when it prints the same as want
}

// iamWant is the outcome one response prints. fields holds top-level
// JSON/YAML fields, compared through fmt.Sprint so both decoders agree;
// table holds substrings of the table rendering.
type iamWant struct {
	fields map[string]string
	table  []string
}

// wantFor returns the outcome expected from the named fake server.
func (tc iamRunCase) wantFor(srvName string) iamWant {
	if srvName == "rejected" && tc.rejected != nil {
		return *tc.rejected
	}
	return tc.want
}

// statusWant is the outcome of a status-bearing command: the Status fields
// and the one table line its success or failure branch prints.
func statusWant(success bool, line string) iamWant {
	return iamWant{
		fields: map[string]string{"success": fmt.Sprint(success), "message": "done"},
		table:  []string{line},
	}
}

// rejectedStatus is the status outcome the rejected server produces.
func rejectedStatus(line string) *iamWant {
	want := statusWant(false, line)
	return &want
}

// iamDecoders decode the structured output formats into top-level fields.
var iamDecoders = map[cli.OutputFormat]func([]byte, any) error{
	cli.OutputFormatJSON: json.Unmarshal,
	cli.OutputFormatYAML: yaml.Unmarshal,
}

// assertIAMOutput checks the printed output against want: substrings for
// the table format, decoded fields for JSON and YAML.
func assertIAMOutput(t *testing.T, format cli.OutputFormat, out string, want iamWant) {
	t.Helper()
	decode, structured := iamDecoders[format]
	if !structured {
		for _, line := range want.table {
			require.Contains(t, out, line)
		}
		return
	}
	var got map[string]any
	require.NoError(t, decode([]byte(out), &got), out)
	for key, value := range want.fields {
		require.Contains(t, got, key, out)
		require.Equal(t, value, fmt.Sprint(got[key]), key)
	}
}

// captureStdout runs fn with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w

	var buf bytes.Buffer
	copied := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(&buf, r)
		copied <- copyErr
	}()

	runErr := fn()
	os.Stdout = orig
	require.NoError(t, w.Close())
	require.NoError(t, <-copied)
	require.NoError(t, r.Close())
	return buf.String(), runErr
}

func iamRunCases(policyFile string) []iamRunCase {
	user := map[string]string{"id": "u1", "email": "u1@example.com", "mfa_verified": "true"}
	role := map[string]string{"id": "r1", "name": "Reader"}
	group := map[string]string{"id": "g1", "name": "Ops"}
	tenant := map[string]string{"id": "t1", "name": "Acme"}
	policy := map[string]string{"name": "p1", "priority": "10"}
	app := map[string]string{"client_id": "c1", "name": "portal"}
	listed := map[string]string{"total": "1"}

	return []iamRunCase{
		{
			name: "UserCreate", failMsg: "failed to create user",
			run: func(f *cli.CommonFlags) error {
				return runUserCreate(f, "t1", "u1@example.com", "User One", "admin", "ops", "dept=eng")
			},
			want: iamWant{user, []string{"[SUCCESS] User created successfully: u1", "u1@example.com"}},
		},
		{
			name: "UserGet", failMsg: "failed to get user",
			run:  func(f *cli.CommonFlags) error { return runUserGet(f, "t1", "u1") },
			want: iamWant{user, []string{"u1@example.com"}},
		},
		{
			name: "UserList", failMsg: "failed to list users",
			run: func(f *cli.CommonFlags) error {
				return runUserList(f, "t1", 1, 10, iamsvc.UserListFilter{})
			},
			want: iamWant{listed, []string{"u1@example.com"}},
		},
		{
			name: "UserUpdate", failMsg: "failed to update user",
			run: func(f *cli.CommonFlags) error {
				return runUserUpdate(f, "t1", "u1", "new@example.com", "New", "admin", "ops", "dept=ops")
			},
			want: iamWant{user, []string{"[SUCCESS] User updated successfully: u1"}},
		},
		{
			name: "UserDelete", failMsg: "failed to delete user",
			run:      func(f *cli.CommonFlags) error { return runUserDelete(f, "t1", "u1") },
			want:     statusWant(true, "[SUCCESS] User u1 deleted successfully"),
			rejected: rejectedStatus("[ERROR] Failed to delete user u1"),
		},
		{
			name: "UserAssignRole", failMsg: "failed to assign role",
			run:      func(f *cli.CommonFlags) error { return runUserAssignRole(f, "t1", "u1", "r1") },
			want:     statusWant(true, "[SUCCESS] Role 'r1' assigned to user u1"),
			rejected: rejectedStatus("[ERROR] Failed to assign role 'r1' to user u1"),
		},
		{
			name: "UserRevokeRole", failMsg: "failed to revoke role",
			run:      func(f *cli.CommonFlags) error { return runUserRevokeRole(f, "t1", "u1", "r1") },
			want:     statusWant(true, "[SUCCESS] Role 'r1' revoked from user u1"),
			rejected: rejectedStatus("[ERROR] Failed to revoke role 'r1' from user u1"),
		},
		{
			name: "RoleCreate", failMsg: "failed to create role",
			run: func(f *cli.CommonFlags) error {
				return runRoleCreate(f, "t1", "r1", "Reader", "read only", []string{"vm:read"})
			},
			want: iamWant{role, []string{"[SUCCESS] Role created successfully: r1", "Reader"}},
		},
		{
			name: "RoleGet", failMsg: "failed to get role",
			run:  func(f *cli.CommonFlags) error { return runRoleGet(f, "t1", "r1") },
			want: iamWant{role, []string{"Reader", "vm:read"}},
		},
		{
			name: "RoleList", failMsg: "failed to list roles",
			run:  func(f *cli.CommonFlags) error { return runRoleList(f, "t1", 1, 10) },
			want: iamWant{listed, []string{"Reader"}},
		},
		{
			name: "RoleUpdate", failMsg: "failed to update role",
			run: func(f *cli.CommonFlags) error {
				return runRoleUpdate(f, "t1", "r1", "Reader", "read only", []string{"vm:read"})
			},
			want: iamWant{role, []string{"[SUCCESS] Role updated successfully: r1"}},
		},
		{
			name: "RoleDelete", failMsg: "failed to delete role",
			run:      func(f *cli.CommonFlags) error { return runRoleDelete(f, "t1", "r1") },
			want:     statusWant(true, "[SUCCESS] Role deleted successfully: r1"),
			rejected: rejectedStatus("[ERROR] Failed to delete role: r1"),
		},
		{
			name: "GroupCreate", failMsg: "failed to create group",
			run: func(f *cli.CommonFlags) error {
				return runGroupCreate(f, "t1", "g1", "Ops", "operators")
			},
			want: iamWant{group, []string{"[SUCCESS] Group created successfully: g1", "Ops"}},
		},
		{
			name: "GroupGet", failMsg: "failed to get group",
			run:  func(f *cli.CommonFlags) error { return runGroupGet(f, "t1", "g1") },
			want: iamWant{group, []string{"Ops", "operators"}},
		},
		{
			name: "GroupList", failMsg: "failed to list groups",
			run:  func(f *cli.CommonFlags) error { return runGroupList(f, "t1", 1, 10) },
			want: iamWant{listed, []string{"Ops"}},
		},
		{
			name: "GroupUpdate", failMsg: "failed to update group",
			run: func(f *cli.CommonFlags) error {
				return runGroupUpdate(f, "t1", "g1", "Ops", "operators")
			},
			want: iamWant{group, []string{"[SUCCESS] Group updated successfully: g1"}},
		},
		{
			name: "GroupDelete", failMsg: "failed to delete group",
			run:      func(f *cli.CommonFlags) error { return runGroupDelete(f, "t1", "g1") },
			want:     statusWant(true, "[SUCCESS] Group deleted successfully: g1"),
			rejected: rejectedStatus("[ERROR] Failed to delete group: g1"),
		},
		{
			name: "TenantCreate", failMsg: "failed to create tenant",
			run: func(f *cli.CommonFlags) error {
				return runTenantCreate(f, "t1", "Acme", 25, true)
			},
			want: iamWant{tenant, []string{"[SUCCESS] Tenant created successfully: t1", "Acme"}},
		},
		{
			name: "TenantGet", failMsg: "failed to get tenant",
			run:  func(f *cli.CommonFlags) error { return runTenantGet(f, "t1") },
			want: iamWant{tenant, []string{"Acme"}},
		},
		{
			name: "TenantList", failMsg: "failed to list tenants",
			run:  func(f *cli.CommonFlags) error { return runTenantList(f, 1, 10) },
			want: iamWant{map[string]string{"total": "2"}, []string{"Acme"}},
		},
		{
			name: "TenantUpdate", failMsg: "failed to get tenant for update",
			run: func(f *cli.CommonFlags) error {
				return runTenantUpdate(f, "t1", "Acme Corp", 50, false, true)
			},
			want: iamWant{tenant, []string{"[SUCCESS] Tenant updated successfully: t1"}},
		},
		{
			name: "TenantDelete", failMsg: "failed to delete tenant",
			run:      func(f *cli.CommonFlags) error { return runTenantDelete(f, "t1") },
			want:     statusWant(true, "[SUCCESS] Tenant t1 deleted successfully"),
			rejected: rejectedStatus("[ERROR] Failed to delete tenant t1"),
		},
		{
			name: "PolicyCreate", failMsg: "failed to create policy",
			run: func(f *cli.CommonFlags) error {
				return runPolicyCreate(f, "t1", "p1", "allow reads", 10, policyFile, "env=dev")
			},
			want: iamWant{policy, []string{"[SUCCESS] Policy created successfully: p1", "allow reads"}},
		},
		{
			name: "PolicyGet", failMsg: "failed to get policy",
			run:  func(f *cli.CommonFlags) error { return runPolicyGet(f, "t1", "p1") },
			want: iamWant{policy, []string{"allow reads", "Policy Spec: \nrules: []"}},
		},
		{
			name: "PolicyList", failMsg: "failed to list policies",
			run:  func(f *cli.CommonFlags) error { return runPolicyList(f, "t1", 1, 10) },
			want: iamWant{listed, []string{"p1", "Total Count: 1"}},
		},
		{
			name: "PolicyUpdate", failMsg: "failed to update policy",
			run: func(f *cli.CommonFlags) error {
				return runPolicyUpdate(f, "t1", "p1", "allow reads", 10, policyFile, "env=dev")
			},
			want: iamWant{policy, []string{"[SUCCESS] Policy updated successfully: p1"}},
		},
		{
			name: "PolicyDelete", failMsg: "failed to delete policy",
			run:      func(f *cli.CommonFlags) error { return runPolicyDelete(f, "t1", "p1") },
			want:     statusWant(true, "[SUCCESS] Policy p1 deleted successfully from tenant t1"),
			rejected: rejectedStatus("[ERROR] Failed to delete policy p1 from tenant t1"),
		},
		{
			name: "PolicyValidate", failMsg: "failed to validate policy",
			run:  func(f *cli.CommonFlags) error { return runPolicyValidate(f, "t1", policyFile) },
			want: iamWant{map[string]string{"valid": "true"}, []string{"[SUCCESS] Policy is valid"}},
			rejected: &iamWant{
				map[string]string{"valid": "false", "errors": "[rules: required]"},
				[]string{"[ERROR] Policy validation failed", "Errors: \n", "  1. rules: required\n"},
			},
		},
		{
			name: "PolicyTest", failMsg: "failed to test policy",
			run: func(f *cli.CommonFlags) error {
				return runPolicyTest(f, "t1", "u1", "admin", "ops", "read", "vm/1", "ip=10.0.0.1")
			},
			want: iamWant{
				map[string]string{
					"allowed": "true", "matched_policy": "p1", "matched_rule": "allow-read", "evaluation_time_ns": "1200",
				},
				[]string{
					"[SUCCESS] Access ALLOWED", "Subject: u1", "Action: read", "Resource: vm/1",
					"Matched Policy: p1", "Matched Rule: allow-read", "Evaluation Time: 1.2µs",
				},
			},
			rejected: &iamWant{
				map[string]string{"allowed": "false", "evaluation_time_ns": "1200"},
				[]string{"[ERROR] Access DENIED", "Subject: u1", "Resource: vm/1", "Evaluation Time: 1.2µs"},
			},
		},
		{
			name: "AppRegister", failMsg: "failed to register application",
			run: func(f *cli.CommonFlags) error {
				return runAppRegister(f, "t1", "portal", "https://portal/cb", "authorization_code", "code", "/portal")
			},
			want: iamWant{app, []string{"[SUCCESS] Application registered successfully: portal", "s3cret"}},
		},
		{
			name: "AppGet", failMsg: "failed to get application",
			run:  func(f *cli.CommonFlags) error { return runAppGet(f, "t1", "c1") },
			want: iamWant{app, []string{"portal", "https://portal/cb"}},
		},
		{
			name: "AppList", failMsg: "failed to list applications",
			run:  func(f *cli.CommonFlags) error { return runAppList(f, "t1", 1, 10) },
			want: iamWant{listed, []string{"portal"}},
		},
		{
			name: "AppUpdate", failMsg: "failed to update application",
			run: func(f *cli.CommonFlags) error {
				return runAppUpdate(f, "t1", "c1", "portal", "https://portal/cb", "authorization_code", "code", "/portal")
			},
			want: iamWant{app, []string{"[SUCCESS] Application updated successfully: portal"}},
		},
		{
			name: "AppDelete", failMsg: "failed to delete application",
			run:      func(f *cli.CommonFlags) error { return runAppDelete(f, "t1", "c1") },
			want:     statusWant(true, "[SUCCESS] Application deleted successfully: c1"),
			rejected: rejectedStatus("[WARNING] Application deletion may not have completed: c1"),
		},
		{
			name: "AppRotateSecret", failMsg: "failed to rotate application secret",
			run: func(f *cli.CommonFlags) error {
				return runAppRotateSecret(f, "t1", "c1")
			},
			want: iamWant{
				map[string]string{"client_id": "c1", "name": "portal", "client_secret": "n3w"},
				[]string{"[SUCCESS] Client secret rotated successfully for: portal", "n3w"},
			},
		},
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
					out, err := captureStdout(t, func() error { return tc.run(flags(format)) })
					require.NoError(t, err)
					assertIAMOutput(t, format, out, tc.wantFor(srvName))
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
