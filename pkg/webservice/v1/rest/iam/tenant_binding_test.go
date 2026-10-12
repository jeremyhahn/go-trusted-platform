package iam

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// tenantBoundIAMServer serves the IAM tree with the production guards behind
// TLS, as a tenant-a administrator whose session the authenticator publishes
// for every request. servedTenant records the tenant each Get was answered
// from, so a test can prove no request is answered from another tenant.
func tenantBoundIAMServer(t *testing.T, servedTenant *string) *httptest.Server {
	t.Helper()
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	writer := response.NewResponseWriter(logger, nil)
	guard, err := iammw.NewSessionGuard(logger, writer)
	require.NoError(t, err)

	session := iammw.NewIAMSession(&iamsdk.User{ID: "admin-a", TenantID: "tenant-a", Roles: []string{"admin"}})
	authenticate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(iammw.SetSessionInContext(r.Context(), session)))
		})
	}

	client := &mockIAMClient{
		getUserFn: func(_ context.Context, tenantID, userID string) (*iamsdk.User, error) {
			*servedTenant = tenantID
			return &iamsdk.User{ID: userID, TenantID: tenantID}, nil
		},
		getRoleFn: func(_ context.Context, tenantID, roleID string) (*iamsdk.Role, error) {
			*servedTenant = tenantID
			return &iamsdk.Role{ID: roleID, TenantID: tenantID}, nil
		},
		getGroupFn: func(_ context.Context, tenantID, groupID string) (*iamsdk.Group, error) {
			*servedTenant = tenantID
			return &iamsdk.Group{ID: groupID, TenantID: tenantID}, nil
		},
	}

	iamRouter, err := NewIAMRouter(logger, client, &mockPEPClient{}, writer, Authorization{
		Authenticate:        authenticate,
		RequireAdmin:        guard.RequireRoles("admin"),
		RequireSystemTenant: guard.RequireTenant("system"),
		RequireOwnTenant: guard.RequireOwnTenant(func(r *http.Request) string {
			return mux.Vars(r)["tenant"]
		}),
	})
	require.NoError(t, err)

	root := mux.NewRouter()
	// The SDK probes /health on Connect; the daemon serves it unauthenticated.
	root.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	iamRouter.RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)
	return server
}

// TestIAMOverSDKREST_TenantBinding is the REST half of #401, driven through the
// SDK REST adapter so it asserts what an SDK caller sees: the same three cases
// pkg/api/daemon TestIAMGRPCService_TenantBinding asserts over gRPC, with the
// same status codes. A tenant-a caller is served from tenant-a, refused with
// PermissionDenied (HTTP 403) for tenant-b, and refused with InvalidArgument
// when the tenant is missing.
func TestIAMOverSDKREST_TenantBinding(t *testing.T) {
	type operation struct {
		grpcMethod string
		request    func(tenantID string) proto.Message
		response   func() proto.Message
	}

	operations := map[string]operation{
		"GetUser": {
			grpcMethod: "/platform.v1.PlatformIAMService/GetUser",
			request: func(tenantID string) proto.Message {
				return &platformv1.GetIAMUserRequest{TenantId: tenantID, UserId: "u-1"}
			},
			response: func() proto.Message { return &platformv1.IAMUserResponse{} },
		},
		"GetRole": {
			grpcMethod: "/platform.v1.PlatformIAMService/GetRole",
			request: func(tenantID string) proto.Message {
				return &platformv1.GetIAMRoleRequest{TenantId: tenantID, RoleId: "r-1"}
			},
			response: func() proto.Message { return &platformv1.IAMRoleResponse{} },
		},
		"GetGroup": {
			grpcMethod: "/platform.v1.PlatformIAMService/GetGroup",
			request: func(tenantID string) proto.Message {
				return &platformv1.GetIAMGroupRequest{TenantId: tenantID, GroupId: "g-1"}
			},
			response: func() proto.Message { return &platformv1.IAMGroupResponse{} },
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

	for method, op := range operations {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				var servedTenant string
				server := tenantBoundIAMServer(t, &servedTenant)

				tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				conn, err := sdkrest.Connect(context.Background(), platform.NewOptions(
					platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
				require.NoError(t, err)
				t.Cleanup(func() {
					if err := conn.Close(); err != nil {
						t.Errorf("Close: %v", err)
					}
				})
				adapter := conn.(*sdkrest.Adapter)

				err = adapter.Connection().Invoke(context.Background(), op.grpcMethod, op.request(tc.tenantID), op.response())
				if status.Code(err) != tc.wantCode {
					t.Fatalf("code = %v, want %v (err %v)", status.Code(err), tc.wantCode, err)
				}
				if servedTenant != tc.wantServedFor {
					t.Fatalf("served from tenant %q, want %q", servedTenant, tc.wantServedFor)
				}
			})
		}
	}
}
