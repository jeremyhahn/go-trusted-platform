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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tenantRecordingIAMClient answers User/Role Get from the tenant it is
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

func tokenCallerContext(tenantID string) context.Context {
	return grpcapi.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: tenantID})
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

	t.Run("unbound caller is allowed", func(t *testing.T) {
		if err := authorizeIAMTenant(context.Background(), "tenant-a"); err != nil {
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
