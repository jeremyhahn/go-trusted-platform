package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
		createUserFn: func(_ context.Context, tenantID string, req *iamsdk.CreateUserRequest) (*iamsdk.User, error) {
			*servedTenant = tenantID
			return &iamsdk.User{ID: "u-new", TenantID: tenantID, Email: req.Email}, nil
		},
		listUsersFn: func(_ context.Context, tenantID string, _ *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			*servedTenant = tenantID
			return &iamsdk.ListUsersResponse{}, nil
		},
		updateUserFn: func(_ context.Context, tenantID, userID string, req *iamsdk.UpdateUserRequest) (*iamsdk.User, error) {
			*servedTenant = tenantID
			return &iamsdk.User{ID: userID, TenantID: tenantID, Email: req.Email}, nil
		},
		createRoleFn: func(_ context.Context, tenantID string, req *iamsdk.CreateRoleRequest) (*iamsdk.Role, error) {
			*servedTenant = tenantID
			return &iamsdk.Role{ID: "r-new", TenantID: tenantID, Name: req.Name}, nil
		},
		listRolesFn: func(_ context.Context, tenantID string, _ *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
			*servedTenant = tenantID
			return &iamsdk.ListRolesResponse{}, nil
		},
		updateRoleFn: func(_ context.Context, tenantID, roleID string, req *iamsdk.UpdateRoleRequest) (*iamsdk.Role, error) {
			*servedTenant = tenantID
			return &iamsdk.Role{ID: roleID, TenantID: tenantID, Description: req.Description}, nil
		},
		createGroupFn: func(_ context.Context, tenantID string, req *iamsdk.CreateGroupRequest) (*iamsdk.Group, error) {
			*servedTenant = tenantID
			return &iamsdk.Group{ID: "g-new", TenantID: tenantID, Name: req.Name}, nil
		},
		listGroupsFn: func(_ context.Context, tenantID string, _ *iamsdk.ListGroupsRequest) (*iamsdk.ListGroupsResponse, error) {
			*servedTenant = tenantID
			return &iamsdk.ListGroupsResponse{}, nil
		},
		updateGroupFn: func(_ context.Context, tenantID, groupID string, req *iamsdk.UpdateGroupRequest) (*iamsdk.Group, error) {
			*servedTenant = tenantID
			return &iamsdk.Group{ID: groupID, TenantID: tenantID, Description: req.Description}, nil
		},
	}

	return adminSessionIAMServer(t, client, &mockPEPClient{})
}

// adminSessionIAMServer serves the real IAM router over TLS, behind the real
// session guards, to a caller authenticated as admin-a of tenant-a, with the
// given IAM client and policy enforcement point behind the handlers.
func adminSessionIAMServer(t *testing.T, client IAMClient, pep PEPClient) *httptest.Server {
	t.Helper()
	return adminSessionIAMServerIn(t, "tenant-a", client, pep)
}

// adminSessionIAMServerIn is adminSessionIAMServer with the admin session
// bound to tenantID, so a test can reach the system-only tenant routes.
func adminSessionIAMServerIn(t *testing.T, tenantID string, client IAMClient, pep PEPClient) *httptest.Server {
	t.Helper()
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	writer := response.NewResponseWriter(logger, nil)
	guard, err := iammw.NewSessionGuard(logger, writer)
	require.NoError(t, err)

	session := iammw.NewIAMSession(&iamsdk.User{ID: "admin-a", TenantID: tenantID, Roles: []string{"admin"}})
	authenticate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(iammw.SetSessionInContext(r.Context(), session)))
		})
	}

	iamRouter, err := NewIAMRouter(logger, client, pep, writer, Authorization{
		Authenticate:        authenticate,
		RequireAdmin:        guard.RequireRoles("admin"),
		RequireSystemTenant: guard.RequireTenant("system"),
		RequireOwnTenant:    guard.RequireOwnTenant(RequestedTenant),
	})
	require.NoError(t, err)

	root := mux.NewRouter()
	// The SDK probes /health/live on Connect; the daemon serves it unauthenticated.
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
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
	t.Parallel()
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
		"UpdateUser": {
			grpcMethod: "/platform.v1.PlatformIAMService/UpdateUser",
			request: func(tenantID string) proto.Message {
				return &platformv1.UpdateIAMUserRequest{TenantId: tenantID, UserId: "u-1", Email: "u1@example.test"}
			},
			response: func() proto.Message { return &platformv1.IAMUserResponse{} },
		},
		"UpdateRole": {
			grpcMethod: "/platform.v1.PlatformIAMService/UpdateRole",
			request: func(tenantID string) proto.Message {
				return &platformv1.UpdateIAMRoleRequest{TenantId: tenantID, RoleId: "r-1", Description: "ops"}
			},
			response: func() proto.Message { return &platformv1.IAMRoleResponse{} },
		},
		"UpdateGroup": {
			grpcMethod: "/platform.v1.PlatformIAMService/UpdateGroup",
			request: func(tenantID string) proto.Message {
				return &platformv1.UpdateIAMGroupRequest{TenantId: tenantID, GroupId: "g-1", Description: "ops"}
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

// TestIAMOverSDKREST_Update drives the Go SDK's three IAM updates over its
// REST transport against the real router and handlers. They had no REST
// route and fell back to /api/v1/platformiam/update<item>, which the server
// does not serve (#401). Each must reach the tenant-scoped PUT route, carry
// its changed field in the body, and come back as the updated resource on
// the reply.
func TestIAMOverSDKREST_Update(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		grpcMethod string
		request    proto.Message
		response   proto.Message
		changed    func(reply proto.Message) string
		want       string
	}{
		{
			name:       "UpdateUser",
			grpcMethod: "/platform.v1.PlatformIAMService/UpdateUser",
			request:    &platformv1.UpdateIAMUserRequest{TenantId: "tenant-a", UserId: "u-1", Email: "u1@example.test"},
			response:   &platformv1.IAMUserResponse{},
			changed: func(reply proto.Message) string {
				return reply.(*platformv1.IAMUserResponse).GetUser().GetEmail()
			},
			want: "u1@example.test",
		},
		{
			name:       "UpdateRole",
			grpcMethod: "/platform.v1.PlatformIAMService/UpdateRole",
			request:    &platformv1.UpdateIAMRoleRequest{TenantId: "tenant-a", RoleId: "r-1", Description: "ops"},
			response:   &platformv1.IAMRoleResponse{},
			changed: func(reply proto.Message) string {
				return reply.(*platformv1.IAMRoleResponse).GetRole().GetDescription()
			},
			want: "ops",
		},
		{
			name:       "UpdateGroup",
			grpcMethod: "/platform.v1.PlatformIAMService/UpdateGroup",
			request:    &platformv1.UpdateIAMGroupRequest{TenantId: "tenant-a", GroupId: "g-1", Description: "ops"},
			response:   &platformv1.IAMGroupResponse{},
			changed: func(reply proto.Message) string {
				return reply.(*platformv1.IAMGroupResponse).GetGroup().GetDescription()
			},
			want: "ops",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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

			if err := adapter.Connection().Invoke(context.Background(), tc.grpcMethod, tc.request, tc.response); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if servedTenant != "tenant-a" {
				t.Fatalf("served from tenant %q, want %q", servedTenant, "tenant-a")
			}
			if got := tc.changed(tc.response); got != tc.want {
				t.Fatalf("reply carries %q, want the updated %q", got, tc.want)
			}
		})
	}
}

// TestIAMOverRawREST_FlatRouteTenantQuery pins #401 for a raw REST client
// on the flat routes: a tenant_id query naming another tenant is refused
// with 403, as gRPC refuses it with PermissionDenied, and never answered
// with the session tenant's object under the same id.
func TestIAMOverRawREST_FlatRouteTenantQuery(t *testing.T) {
	t.Parallel()
	items := map[string]string{
		"GetUser":  "/api/v1/iam/users/u-1",
		"GetRole":  "/api/v1/iam/roles/r-1",
		"GetGroup": "/api/v1/iam/groups/g-1",
	}
	cases := []struct {
		name          string
		query         string
		wantStatus    int
		wantServedFor string
	}{
		{name: "no tenant named", query: "", wantStatus: http.StatusOK, wantServedFor: "tenant-a"},
		{name: "matching tenant", query: "?tenant_id=tenant-a", wantStatus: http.StatusOK, wantServedFor: "tenant-a"},
		{name: "mismatched tenant", query: "?tenant_id=tenant-b", wantStatus: http.StatusForbidden},
	}

	for operation, path := range items {
		for _, tc := range cases {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				var servedTenant string
				server := tenantBoundIAMServer(t, &servedTenant)

				resp, err := server.Client().Get(server.URL + path + tc.query)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())

				if resp.StatusCode != tc.wantStatus {
					t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
				}
				if servedTenant != tc.wantServedFor {
					t.Fatalf("served from tenant %q, want %q", servedTenant, tc.wantServedFor)
				}
			})
		}
	}
}

// TestIAMOverRawREST_ScopedRouteTenantQuery: on a /tenants/{tenant}/ route a
// tenant_id query naming another tenant was ignored and the path's tenant
// served (#401). It is refused with 403 before the handler runs, whichever
// of the two is the caller's own; the same tenant in both, or no query, is
// served as before.
func TestIAMOverRawREST_ScopedRouteTenantQuery(t *testing.T) {
	t.Parallel()
	items := map[string]string{
		"GetUser":  "/users/u-1",
		"GetRole":  "/roles/r-1",
		"GetGroup": "/groups/g-1",
	}
	cases := []struct {
		name          string
		pathTenant    string
		query         string
		wantStatus    int
		wantServedFor string
	}{
		{name: "no query", pathTenant: "tenant-a", query: "", wantStatus: http.StatusOK, wantServedFor: "tenant-a"},
		{name: "query matches path", pathTenant: "tenant-a", query: "?tenant_id=tenant-a", wantStatus: http.StatusOK, wantServedFor: "tenant-a"},
		{name: "query names another tenant", pathTenant: "tenant-a", query: "?tenant_id=tenant-b", wantStatus: http.StatusForbidden},
		{name: "path names another tenant", pathTenant: "tenant-b", query: "?tenant_id=tenant-a", wantStatus: http.StatusForbidden},
	}

	for operation, item := range items {
		for _, tc := range cases {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				var servedTenant string
				server := tenantBoundIAMServer(t, &servedTenant)

				target := "/api/v1/iam/tenants/" + tc.pathTenant + item + tc.query
				resp, err := server.Client().Get(server.URL + target)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())

				if resp.StatusCode != tc.wantStatus {
					t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
				}
				if servedTenant != tc.wantServedFor {
					t.Fatalf("served from tenant %q, want %q", servedTenant, tc.wantServedFor)
				}
			})
		}
	}
}

func TestRequestedTenant(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		target  string
		urlVars map[string]string
		want    string
	}{
		{name: "path tenant", target: "/iam/tenants/acme/users/u-1",
			urlVars: map[string]string{"tenant": "acme", "id": "u-1"}, want: "acme"},
		{name: "path tenant takes precedence over the query", target: "/iam/tenants/acme/users/u-1?tenant_id=other",
			urlVars: map[string]string{"tenant": "acme", "id": "u-1"}, want: "acme"},
		{name: "query tenant on a flat route", target: "/iam/users/u-1?tenant_id=acme",
			urlVars: map[string]string{"id": "u-1"}, want: "acme"},
		{name: "no tenant named", target: "/iam/users/u-1",
			urlVars: map[string]string{"id": "u-1"}, want: ""},
		{name: "empty query value names no tenant", target: "/iam/users/u-1?tenant_id=",
			urlVars: map[string]string{"id": "u-1"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, tc.target, nil), tc.urlVars)
			if got := RequestedTenant(req); got != tc.want {
				t.Fatalf("RequestedTenant = %q, want %q", got, tc.want)
			}
		})
	}
}

// sendIAMJSON sends method path to server with fields marshalled as the JSON
// body, or with no body when fields is empty, and returns the status.
func sendIAMJSON(t *testing.T, server *httptest.Server, method, path string, fields map[string]any) int {
	t.Helper()
	var body io.Reader
	if len(fields) > 0 {
		encoded, err := json.Marshal(fields)
		require.NoError(t, err)
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, server.URL+path, body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return resp.StatusCode
}

// TestIAMOverRawREST_FlatRouteBodyTenant pins the body half of #401: a tenant
// named in the body of an unscoped Create, List or Update route, in either
// spelling a client sends, is held to the rule the tenant_id query is. A
// refused request reaches neither a write nor a lookup.
func TestIAMOverRawREST_FlatRouteBodyTenant(t *testing.T) {
	t.Parallel()
	routes := []struct {
		name   string
		method string
		path   string
		fields map[string]any
	}{
		{"CreateUser", http.MethodPost, "/api/v1/iam/users", map[string]any{"email": "u@example.test"}},
		{"ListUsers", http.MethodGet, "/api/v1/iam/users", nil},
		{"UpdateUser", http.MethodPut, "/api/v1/iam/users/u-1", map[string]any{"name": "U"}},
		{"CreateRole", http.MethodPost, "/api/v1/iam/roles", map[string]any{"id": "r-1", "name": "R"}},
		{"ListRoles", http.MethodGet, "/api/v1/iam/roles", nil},
		{"UpdateRole", http.MethodPut, "/api/v1/iam/roles/r-1", map[string]any{"name": "R"}},
		{"CreateGroup", http.MethodPost, "/api/v1/iam/groups", map[string]any{"id": "g-1", "name": "G"}},
		{"ListGroups", http.MethodGet, "/api/v1/iam/groups", nil},
		{"UpdateGroup", http.MethodPut, "/api/v1/iam/groups/g-1", map[string]any{"name": "G"}},
	}
	cases := []struct {
		name          string
		tenant        map[string]any
		wantStatus    int
		wantServedFor string
	}{
		{name: "no tenant named", wantStatus: http.StatusOK, wantServedFor: "tenant-a"},
		{name: "matching tenant_id", tenant: map[string]any{"tenant_id": "tenant-a"},
			wantStatus: http.StatusOK, wantServedFor: "tenant-a"},
		{name: "matching tenantId", tenant: map[string]any{"tenantId": "tenant-a"},
			wantStatus: http.StatusOK, wantServedFor: "tenant-a"},
		{name: "mismatched tenant_id", tenant: map[string]any{"tenant_id": "tenant-b"},
			wantStatus: http.StatusForbidden},
		{name: "mismatched tenantId", tenant: map[string]any{"tenantId": "tenant-b"},
			wantStatus: http.StatusForbidden},
		{name: "one spelling mismatched", tenant: map[string]any{"tenant_id": "tenant-a", "tenantId": "tenant-b"},
			wantStatus: http.StatusForbidden},
	}

	for _, route := range routes {
		for _, tc := range cases {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				fields := map[string]any{}
				maps.Copy(fields, route.fields)
				maps.Copy(fields, tc.tenant)

				var servedTenant string
				server := tenantBoundIAMServer(t, &servedTenant)

				if got := sendIAMJSON(t, server, route.method, route.path, fields); got != tc.wantStatus {
					t.Fatalf("status = %d, want %d", got, tc.wantStatus)
				}
				if servedTenant != tc.wantServedFor {
					t.Fatalf("served from tenant %q, want %q", servedTenant, tc.wantServedFor)
				}
			})
		}
	}
}

// TestIAMOverRawREST_ScopedRouteBodyTenant holds the tenant-scoped form to
// the same rule: a path naming the caller's own tenant does not carry a body
// naming another one through.
func TestIAMOverRawREST_ScopedRouteBodyTenant(t *testing.T) {
	t.Parallel()
	var servedTenant string
	server := tenantBoundIAMServer(t, &servedTenant)

	got := sendIAMJSON(t, server, http.MethodPost, "/api/v1/iam/tenants/tenant-a/users",
		map[string]any{"email": "u@example.test", "tenant_id": "tenant-b"})
	if got != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
	}
	if servedTenant != "" {
		t.Fatalf("served from tenant %q, want no write", servedTenant)
	}
}

// TestIAMOverRawREST_ListMalformedBody is the error half of reading a list
// route's body: a body that is not JSON is refused with 400, not skipped.
func TestIAMOverRawREST_ListMalformedBody(t *testing.T) {
	t.Parallel()
	var servedTenant string
	server := tenantBoundIAMServer(t, &servedTenant)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		server.URL+"/api/v1/iam/users", strings.NewReader("{not json"))
	require.NoError(t, err)
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if servedTenant != "" {
		t.Fatalf("served from tenant %q, want no lookup", servedTenant)
	}
}

// TestIAMOverSDKREST_BodyTenant drives the Go SDK's REST transport, which
// sends Create and List to the unscoped routes with the request's tenant_id in
// the body: a foreign tenant is PermissionDenied, as it is on gRPC (#401).
func TestIAMOverSDKREST_BodyTenant(t *testing.T) {
	t.Parallel()
	type operation struct {
		grpcMethod string
		request    func(tenantID string) proto.Message
		response   func() proto.Message
	}

	operations := map[string]operation{
		"CreateUser": {
			grpcMethod: "/platform.v1.PlatformIAMService/CreateUser",
			request: func(tenantID string) proto.Message {
				return &platformv1.CreateIAMUserRequest{TenantId: tenantID, Email: "u@example.test"}
			},
			response: func() proto.Message { return &platformv1.IAMUserResponse{} },
		},
		"ListUsers": {
			grpcMethod: "/platform.v1.PlatformIAMService/ListUsers",
			request: func(tenantID string) proto.Message {
				return &platformv1.ListIAMUsersRequest{TenantId: tenantID}
			},
			response: func() proto.Message { return &platformv1.ListIAMUsersResponse{} },
		},
		"ListRoles": {
			grpcMethod: "/platform.v1.PlatformIAMService/ListRoles",
			request: func(tenantID string) proto.Message {
				return &platformv1.ListIAMRolesRequest{TenantId: tenantID}
			},
			response: func() proto.Message { return &platformv1.ListIAMRolesResponse{} },
		},
		"ListGroups": {
			grpcMethod: "/platform.v1.PlatformIAMService/ListGroups",
			request: func(tenantID string) proto.Message {
				return &platformv1.ListIAMGroupsRequest{TenantId: tenantID}
			},
			response: func() proto.Message { return &platformv1.ListIAMGroupsResponse{} },
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
