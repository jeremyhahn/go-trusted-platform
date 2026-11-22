package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// restTokenValidator is the platform-token validator the webservice's
// PlatformTokenMiddleware consults: each bearer names one tenant.
type restTokenValidator map[string]string

func (v restTokenValidator) Validate(_ context.Context, token, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	tenantID, ok := v[token]
	if !ok {
		return nil, errors.New("unknown token")
	}
	return &platformtoken.AuthorizedContext{Subject: token, TenantID: tenantID, Scopes: []string{"*:*"}}, nil
}

// restRefusalWriter records that the middleware refused the request.
type restRefusalWriter struct {
	response.HttpWriter
}

func (restRefusalWriter) Error401(w http.ResponseWriter, _ *http.Request, _ error) {
	w.WriteHeader(http.StatusUnauthorized)
}

// TestRESTPlatformTokenCallersStayBound drives a request through the real
// webservice PlatformTokenMiddleware into the TenantGRPCServer tenant checks
// its REST handlers reach with r.Context() (#2031 round 1 P1 1).
func TestRESTPlatformTokenCallersStayBound(t *testing.T) {
	validator := restTokenValidator{"tok-a": "tenant-a", "tok-system": "system"}
	mw, err := iammw.NewPlatformTokenMiddleware(logging.NewLogger(slog.LevelError, nil), restRefusalWriter{}, validator, iammw.PlatformTokenConfig{AllowBearer: true})
	if err != nil {
		t.Fatalf("NewPlatformTokenMiddleware: %v", err)
	}
	s := &TenantGRPCServer{}
	s.SetSystemTenant("system")

	cases := []struct {
		name  string
		token string
		check func(ctx context.Context) error
		want  codes.Code
	}{
		{"a tenant reads itself", "tok-a", func(ctx context.Context) error { return s.authorizeTenant(ctx, "tenant-a") }, codes.OK},
		{"a tenant reads another tenant", "tok-a", func(ctx context.Context) error { return s.authorizeTenant(ctx, "tenant-b") }, codes.PermissionDenied},
		{"the system tenant lists tenants", "tok-system", func(ctx context.Context) error { return s.authorizeSystemTenant(ctx, "ListTenants") }, codes.OK},
		{"a tenant lists tenants", "tok-a", func(ctx context.Context) error { return s.authorizeSystemTenant(ctx, "ListTenants") }, codes.PermissionDenied},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got error
			reached := false
			h := mw.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				reached = true
				got = c.check(r.Context())
			}))
			req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+c.token)
			h.ServeHTTP(httptest.NewRecorder(), req)
			if !reached {
				t.Fatal("middleware refused the request")
			}
			if status.Code(got) != c.want {
				t.Fatalf("code = %v, want %v (err %v)", status.Code(got), c.want, got)
			}
		})
	}
}

// legacyLocalJWTValidator is a local (non-claims) token validator: the bool
// ValidateToken path plus the principal the token names.
type legacyLocalJWTValidator map[string]string

func (v legacyLocalJWTValidator) ValidateToken(_ context.Context, token string) (bool, error) {
	_, ok := v[token]
	return ok, nil
}

func (v legacyLocalJWTValidator) TokenPrincipal(_ context.Context, token string) (*platformtoken.AuthorizedContext, error) {
	return &platformtoken.AuthorizedContext{Subject: token, TenantID: v[token]}, nil
}

type allowAllChecker struct{}

func (allowAllChecker) CheckPermission(context.Context, string, string, string) (bool, error) {
	return true, nil
}

// TestLegacyLocalJWTReachesOwnTenant sends a local JWT through the
// OIDCUnaryInterceptor legacy path into an IAM tenant-scoped RPC
// (#2031 round 1 P1 2).
func TestLegacyLocalJWTReachesOwnTenant(t *testing.T) {
	interceptor := grpcapi.OIDCUnaryInterceptor(
		grpcapi.WithTokenValidator(legacyLocalJWTValidator{"jwt-a": "tenant-a"}),
		grpcapi.WithAuthorizationChecker(allowAllChecker{}),
	)
	info := &grpc.UnaryServerInfo{FullMethod: platformv1.PlatformIAMService_GetUser_FullMethodName}

	for _, c := range []struct {
		name     string
		tenantID string
		want     codes.Code
	}{
		{"own tenant", "tenant-a", codes.OK},
		{"another tenant", "tenant-b", codes.PermissionDenied},
	} {
		t.Run(c.name, func(t *testing.T) {
			client := &tenantRecordingIAMClient{}
			svc := NewIAMGRPCService(slog.Default(), client, nil)
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer jwt-a"))
			req := &platformv1.GetIAMUserRequest{TenantId: c.tenantID, UserId: "u-1"}
			_, err := interceptor(ctx, req, info, func(ctx context.Context, req interface{}) (interface{}, error) {
				return svc.GetUser(ctx, req.(*platformv1.GetIAMUserRequest))
			})
			if status.Code(err) != c.want {
				t.Fatalf("code = %v, want %v (err %v)", status.Code(err), c.want, err)
			}
		})
	}
}
