package daemon

import (
	"context"
	"log/slog"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tenantRecordingIAMClient answers User/Role/Group Get from the tenant it is
// asked for and records that tenant, so a test can prove which tenant a
// request was served from. Every other IAM method is left to the embedded nil
// interface: a call to one panics, which the tests below never make.
type tenantRecordingIAMClient struct {
	quicbaassdk.IAMClient
	servedTenant string
}

func (c *tenantRecordingIAMClient) User() sdkiam.UserClient {
	return tenantRecordingUsers{client: c}
}

func (c *tenantRecordingIAMClient) Role() sdkiam.RoleClient {
	return tenantRecordingRoles{client: c}
}

func (c *tenantRecordingIAMClient) Group() sdkiam.GroupClient {
	return tenantRecordingGroups{client: c}
}

type tenantRecordingUsers struct {
	sdkiam.UserClient
	client *tenantRecordingIAMClient
}

func (u tenantRecordingUsers) Get(_ context.Context, tenantID, userID string) (*sdkiam.User, error) {
	u.client.servedTenant = tenantID
	return &sdkiam.User{ID: userID, TenantID: tenantID}, nil
}

type tenantRecordingRoles struct {
	sdkiam.RoleClient
	client *tenantRecordingIAMClient
}

func (r tenantRecordingRoles) Get(_ context.Context, tenantID, roleID string) (*sdkiam.Role, error) {
	r.client.servedTenant = tenantID
	return &sdkiam.Role{ID: roleID, TenantID: tenantID}, nil
}

type tenantRecordingGroups struct {
	sdkiam.GroupClient
	client *tenantRecordingIAMClient
}

func (g tenantRecordingGroups) Get(_ context.Context, tenantID, groupID string) (*sdkiam.Group, error) {
	g.client.servedTenant = tenantID
	return &sdkiam.Group{ID: groupID, TenantID: tenantID}, nil
}

func tokenCallerContext(tenantID string) context.Context {
	return grpcapi.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: tenantID})
}

// unixOperatorContext is the context of the local operator: a Unix-socket
// caller with kernel-verified peer credentials and no tenant binding.
func unixOperatorContext() context.Context {
	return peercred.ContextWithUnixCredentials(context.Background(), peercred.UnixCredentials{PID: 1, UID: 0, GID: 0})
}

// tenantOnlySession is an IAM session that names only its tenant.
type tenantOnlySession struct {
	iammw.IAMSession
	tenant string
}

func (s tenantOnlySession) TenantID() string { return s.tenant }

// TestUnboundTenantCallers covers SPEC row 109: a caller with no identity
// at all is refused every tenant-scoped IAM and tenant call with
// PermissionDenied, and the Unix peer-credential operator is still admitted.
func TestUnboundTenantCallers(t *testing.T) {
	s := &TenantGRPCServer{}
	s.SetSystemTenant("system")

	checks := []struct {
		name string
		call func(ctx context.Context) error
	}{
		{"authorizeIAMTenant", func(ctx context.Context) error { return authorizeIAMTenant(ctx, "tenant-a") }},
		{"authorizeSystemCaller", func(ctx context.Context) error { return authorizeSystemCaller(ctx, "system", "ListTenants") }},
		{"authorizeTenant", func(ctx context.Context) error { return s.authorizeTenant(ctx, "tenant-a") }},
		{"authorizeSystemTenant", func(ctx context.Context) error { return s.authorizeSystemTenant(ctx, "CreateTenant") }},
		{"authorizeTenantName", func(ctx context.Context) error { return s.authorizeTenantName(ctx, "tenant-a") }},
	}

	for _, c := range checks {
		t.Run(c.name+" refuses a caller with no identity", func(t *testing.T) {
			err := c.call(context.Background())
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("code = %v, want PermissionDenied (err %v)", status.Code(err), err)
			}
		})
		t.Run(c.name+" admits the Unix peer-credential operator", func(t *testing.T) {
			if err := c.call(unixOperatorContext()); err != nil {
				t.Fatalf("%s() = %v, want nil", c.name, err)
			}
		})
	}
}

func TestCallerTenant(t *testing.T) {
	tests := []struct {
		name       string
		ctx        context.Context
		wantTenant string
		wantBound  bool
	}{
		{
			name:       "gRPC platform token",
			ctx:        tokenCallerContext("tenant-a"),
			wantTenant: "tenant-a",
			wantBound:  true,
		},
		{
			name:       "QUIC platform token",
			ctx:        quic.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: "tenant-q"}),
			wantTenant: "tenant-q",
			wantBound:  true,
		},
		{
			name:       "REST platform token (webservice PlatformTokenMiddleware)",
			ctx:        iammw.SetAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: "tenant-r"}),
			wantTenant: "tenant-r",
			wantBound:  true,
		},
		{
			name:       "REST IAM session (webservice JWT handler)",
			ctx:        iammw.SetSessionInContext(context.Background(), tenantOnlySession{tenant: "tenant-s"}),
			wantTenant: "tenant-s",
			wantBound:  true,
		},
		{
			name:       "mTLS client certificate",
			ctx:        context.WithValue(context.Background(), ContextKeyIdentity, &auth.Identity{TenantID: "tenant-m"}),
			wantTenant: "tenant-m",
			wantBound:  true,
		},
		{
			name:      "unbound caller (Unix peer credentials or SkipIAMValidation)",
			ctx:       context.Background(),
			wantBound: false,
		},
		{
			name:      "nil token context is not a binding",
			ctx:       grpcapi.ContextWithAuthorizedContext(context.Background(), nil),
			wantBound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant, bound := callerTenant(tt.ctx)
			if bound != tt.wantBound || tenant != tt.wantTenant {
				t.Fatalf("callerTenant() = (%q, %v), want (%q, %v)", tenant, bound, tt.wantTenant, tt.wantBound)
			}
		})
	}
}

func TestAuthorizeIAMTenant(t *testing.T) {
	t.Run("own tenant is allowed", func(t *testing.T) {
		if err := authorizeIAMTenant(tokenCallerContext("tenant-a"), "tenant-a"); err != nil {
			t.Fatalf("authorizeIAMTenant() = %v, want nil", err)
		}
	})

	t.Run("caller with no identity is refused", func(t *testing.T) {
		err := authorizeIAMTenant(context.Background(), "tenant-a")
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("code = %v, want PermissionDenied (err %v)", status.Code(err), err)
		}
	})

	t.Run("Unix peer-credential operator is allowed", func(t *testing.T) {
		if err := authorizeIAMTenant(unixOperatorContext(), "tenant-a"); err != nil {
			t.Fatalf("authorizeIAMTenant() = %v, want nil", err)
		}
	})

	t.Run("another tenant is refused", func(t *testing.T) {
		err := authorizeIAMTenant(tokenCallerContext("tenant-a"), "tenant-b")
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("code = %v, want PermissionDenied (err %v)", status.Code(err), err)
		}
		want := ErrIAMTenantForbidden{Requested: "tenant-b"}.Error()
		if got := status.Convert(err).Message(); got != want {
			t.Fatalf("message = %q, want %q", got, want)
		}
	})

	t.Run("tenant-less token does not match a named tenant", func(t *testing.T) {
		err := authorizeIAMTenant(tokenCallerContext(""), "tenant-b")
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("code = %v, want PermissionDenied (err %v)", status.Code(err), err)
		}
	})
}

// TestIAMGRPCService_TenantBinding is the gRPC half of #401: the same three
// cases the SDK REST adapter test asserts over HTTP. A tenant-bound caller is
// served from its own tenant, refused with PermissionDenied for another one,
// and refused with InvalidArgument when the tenant is missing.
func TestIAMGRPCService_TenantBinding(t *testing.T) {
	type getter func(s *IAMGRPCService, ctx context.Context, tenantID string) error

	getters := map[string]getter{
		"GetUser": func(s *IAMGRPCService, ctx context.Context, tenantID string) error {
			_, err := s.GetUser(ctx, &platformv1.GetIAMUserRequest{TenantId: tenantID, UserId: "u-1"})
			return err
		},
		"GetRole": func(s *IAMGRPCService, ctx context.Context, tenantID string) error {
			_, err := s.GetRole(ctx, &platformv1.GetIAMRoleRequest{TenantId: tenantID, RoleId: "r-1"})
			return err
		},
		"GetGroup": func(s *IAMGRPCService, ctx context.Context, tenantID string) error {
			_, err := s.GetGroup(ctx, &platformv1.GetIAMGroupRequest{TenantId: tenantID, GroupId: "g-1"})
			return err
		},
	}

	cases := []struct {
		name          string
		tenantID      string
		wantCode      codes.Code
		wantServedFor string
	}{
		{name: "matching tenant", tenantID: "tenant-a", wantCode: codes.OK, wantServedFor: "tenant-a"},
		{name: "mismatched tenant", tenantID: "tenant-b", wantCode: codes.PermissionDenied},
		{name: "missing tenant", tenantID: "", wantCode: codes.InvalidArgument},
	}

	for method, get := range getters {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				client := &tenantRecordingIAMClient{}
				svc := NewIAMGRPCService(slog.Default(), client, nil)

				err := get(svc, tokenCallerContext("tenant-a"), tc.tenantID)
				if status.Code(err) != tc.wantCode {
					t.Fatalf("code = %v, want %v (err %v)", status.Code(err), tc.wantCode, err)
				}
				if client.servedTenant != tc.wantServedFor {
					t.Fatalf("served from tenant %q, want %q", client.servedTenant, tc.wantServedFor)
				}
			})
		}
	}
}

// TestIAMGRPCService_CrossTenantRPCsAreSystemOnly pins the REST
// RequireSystemTenant rule on the shared IAM service every transport calls:
// only the system tenant creates or lists IAM tenants, and a refused create
// leaves no tenant behind.
func TestIAMGRPCService_CrossTenantRPCsAreSystemOnly(t *testing.T) {
	cases := []struct {
		name         string
		systemTenant string
		ctx          context.Context
		wantCode     codes.Code
	}{
		{name: "system tenant", systemTenant: "system", ctx: tokenCallerContext("system"), wantCode: codes.OK},
		{name: "local operator", systemTenant: "system", ctx: unixOperatorContext(), wantCode: codes.OK},
		{name: "anonymous caller", systemTenant: "system", ctx: context.Background(), wantCode: codes.PermissionDenied},
		{name: "other tenant", systemTenant: "system", ctx: tokenCallerContext("tenant-a"), wantCode: codes.PermissionDenied},
		{name: "unset system tenant", systemTenant: "", ctx: tokenCallerContext("system"), wantCode: codes.PermissionDenied},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewIAMGRPCService(slog.Default(), newMemIAM(), nil)
			svc.SetSystemTenant(tc.systemTenant)

			_, err := svc.CreateTenant(tc.ctx, &platformv1.CreateIAMTenantRequest{Id: "acme", Name: "Acme"})
			if status.Code(err) != tc.wantCode {
				t.Fatalf("CreateTenant code = %v, want %v (err %v)", status.Code(err), tc.wantCode, err)
			}
			_, err = svc.ListTenants(tc.ctx, &platformv1.ListIAMTenantsRequest{})
			if status.Code(err) != tc.wantCode {
				t.Fatalf("ListTenants code = %v, want %v (err %v)", status.Code(err), tc.wantCode, err)
			}

			listed, err := svc.ListTenants(unixOperatorContext(), &platformv1.ListIAMTenantsRequest{})
			if err != nil {
				t.Fatalf("ListTenants as the local caller: %v", err)
			}
			wantTenants := 0
			if tc.wantCode == codes.OK {
				wantTenants = 1
			}
			if len(listed.GetTenants()) != wantTenants {
				t.Fatalf("tenants after CreateTenant = %d, want %d", len(listed.GetTenants()), wantTenants)
			}
		})
	}
}
