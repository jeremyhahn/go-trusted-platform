package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// daemonRoundTripper serves each SDK request with the daemon's router in
// memory (no listener, no port) and keeps the last response so a test can
// tell a guard refusal from a handler answer.
type daemonRoundTripper struct {
	server *RESTServer
	last   *httptest.ResponseRecorder
}

func (rt *daemonRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.last = httptest.NewRecorder()
	rt.server.router.ServeHTTP(rt.last, r)
	return rt.last.Result(), nil
}

// iamSDKCollectionCalls are the SDK calls whose tenant once travelled only in
// the body, where the daemon's tenant guard never looks.
var iamSDKCollectionCalls = []struct {
	method string
	req    func(tenant string) proto.Message
	resp   proto.Message
}{
	{"CreateUser", func(t string) proto.Message {
		return &platformv1.CreateIAMUserRequest{TenantId: t}
	}, &platformv1.IAMUserResponse{}},
	{"ListUsers", func(t string) proto.Message {
		return &platformv1.ListIAMUsersRequest{TenantId: t}
	}, &platformv1.ListIAMUsersResponse{}},
	{"CreateGroup", func(t string) proto.Message {
		return &platformv1.CreateIAMGroupRequest{TenantId: t}
	}, &platformv1.IAMGroupResponse{}},
	{"ListGroups", func(t string) proto.Message {
		return &platformv1.ListIAMGroupsRequest{TenantId: t}
	}, &platformv1.ListIAMGroupsResponse{}},
	{"CreateRole", func(t string) proto.Message {
		return &platformv1.CreateIAMRoleRequest{TenantId: t}
	}, &platformv1.IAMRoleResponse{}},
	{"ListRoles", func(t string) proto.Message {
		return &platformv1.ListIAMRolesRequest{TenantId: t}
	}, &platformv1.ListIAMRolesResponse{}},
	{"CheckPermission", func(t string) proto.Message {
		return &platformv1.CheckIAMPermissionRequest{TenantId: t}
	}, &platformv1.CheckIAMPermissionResponse{}},
}

func invokeIAMThroughSDK(t *testing.T, method string, req, resp proto.Message) *httptest.ResponseRecorder {
	t.Helper()
	rt := &daemonRoundTripper{server: iamRESTServer(t)}
	adapter, err := sdkrest.NewWithRoundTripper("https://platformd.invalid", rt, "operator")
	require.NoError(t, err)
	// The handler's answer (success or a validation error) is the point;
	// what matters here is which status the daemon wrote.
	invokeErr := adapter.Connection().Invoke(context.Background(), "/platform.v1.PlatformIAMService/"+method, req, resp)
	require.NotNil(t, rt.last, "the SDK sent nothing: %v", invokeErr)
	return rt.last
}

func TestIAMREST_SDKCollectionCallsPassTheGuardForTheirOwnTenant(t *testing.T) {
	for _, call := range iamSDKCollectionCalls {
		t.Run(call.method, func(t *testing.T) {
			recorder := invokeIAMThroughSDK(t, call.method, call.req(iamRESTTenantA), proto.Clone(call.resp))
			assertReachedHandler(t, recorder, recorder.Body.String())
		})
	}
}

func TestIAMREST_SDKCollectionCallsRefuseAForeignTenant(t *testing.T) {
	for _, call := range iamSDKCollectionCalls {
		t.Run(call.method, func(t *testing.T) {
			recorder := invokeIAMThroughSDK(t, call.method, call.req(iamRESTTenantB), proto.Clone(call.resp))
			assert.Equal(t, http.StatusForbidden, recorder.Code, recorder.Body.String())
		})
	}
}
