package daemon

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

var registryRESTCallers = iamRESTTokens{
	"registry-reader":  {Subject: "registry-reader", TenantID: iamRESTTenantA, Scopes: []string{"registry:read"}},
	"registry-writer":  {Subject: "registry-writer", TenantID: iamRESTTenantA, Scopes: []string{"registry:write"}},
	"registry-deleter": {Subject: "registry-deleter", TenantID: iamRESTTenantA, Scopes: []string{"registry:delete"}},
	"dns-reader":       {Subject: "dns-reader", TenantID: iamRESTTenantA, Scopes: []string{"dns:read"}},
}

// newRESTRegistryService answers every read and delete with an empty,
// non-nil response so a request that passes the guard reaches a handler
// that can render it.
func newRESTRegistryService() *fakeRegistryService {
	return &fakeRegistryService{
		listResp:    &grpcapi.RegistryListResponse{},
		inspectResp: &grpcapi.RegistryInspectResponse{},
		deleteResp:  &grpcapi.RegistryDeleteResponse{},
		statusResp:  &grpcapi.RegistryStatusResponse{},
	}
}

func newRegistryRESTServer(t *testing.T, service grpcapi.RegistryService) *RESTServer {
	t.Helper()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	require.NoError(t, s.SetRegistryRouterHandlers(logging.DefaultLogger(), service, restapi.NewScopeGuard(registryRESTCallers, nil, nil)))
	return s
}

func TestSetRegistryRouterHandlers_RefusesAMissingDependency(t *testing.T) {
	guard := restapi.NewScopeGuard(registryRESTCallers, nil, nil)
	cases := []struct {
		name    string
		logger  *logging.Logger
		service grpcapi.RegistryService
		guard   *restapi.ScopeGuard
		reason  string
	}{
		{"no logger", nil, newRESTRegistryService(), guard, "no logger"},
		{"no service", logging.DefaultLogger(), nil, guard, "no registry service"},
		{"no guard", logging.DefaultLogger(), newRESTRegistryService(), nil, "no REST scope guard"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
			err := s.SetRegistryRouterHandlers(tc.logger, tc.service, tc.guard)
			var unavailable ErrRegistryRESTUnavailable
			require.ErrorAs(t, err, &unavailable)
			assert.Equal(t, tc.reason, unavailable.Reason)
			assert.Equal(t, http.StatusNotFound, serveIAM(s, http.MethodGet, "/api/v1/compute/images/status", "registry-reader").Code,
				"a refused mount serves no registry route")
		})
	}
}

func TestRegistryRouterREST_ScopePerRoute(t *testing.T) {
	service := newRESTRegistryService()
	s := newRegistryRESTServer(t, service)

	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/compute/images", "").Code)
	assert.Equal(t, http.StatusForbidden, serveIAM(s, http.MethodGet, "/api/v1/compute/images", "dns-reader").Code)
	assert.Nil(t, service.lastList)

	recorder := serveIAM(s, http.MethodGet, "/api/v1/compute/images", "registry-reader")
	assertReachedHandler(t, recorder, recorder.Body.String())
	assert.NotNil(t, service.lastList)

	recorder = serveIAM(s, http.MethodDelete, "/api/v1/compute/images/apps/web:v1", "registry-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "registry:delete")
	assert.Nil(t, service.lastDelete)

	recorder = serveIAM(s, http.MethodPost, "/api/v1/compute/images", "registry-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "registry:write")

	recorder = serveIAM(s, http.MethodDelete, "/api/v1/compute/images/apps/web:v1", "registry-deleter")
	assertReachedHandler(t, recorder, recorder.Body.String())
	assert.NotNil(t, service.lastDelete)
}

// TestRegistryRouterREST_ServesTheIntegrationLeaves holds one row per call
// the registry REST adapter (test/integration/registry/rest_adapter.go)
// makes: each must reach a served route, never a 404 or a 405.
func TestRegistryRouterREST_ServesTheIntegrationLeaves(t *testing.T) {
	s := newRegistryRESTServer(t, newRESTRegistryService())

	leaves := []struct {
		leaf, method, path, token string
	}{
		{"TestRegistryMultiProtocol/REST Push", http.MethodPost, "/api/v1/compute/images", "registry-writer"},
		{"TestRegistryMultiProtocol/REST Pull", http.MethodGet, "/api/v1/compute/images/apps/web:v1", "registry-reader"},
		{"TestRegistryMultiProtocol/REST List", http.MethodGet, "/api/v1/compute/images", "registry-reader"},
		{"TestRegistryMultiProtocol/REST Inspect", http.MethodGet, "/api/v1/compute/images/apps/web:v1", "registry-reader"},
		{"TestRegistryMultiProtocol/REST Delete", http.MethodDelete, "/api/v1/compute/images/apps/web:v1", "registry-deleter"},
		{"TestRegistryMultiProtocol/REST Status", http.MethodGet, "/api/v1/compute/images/status", "registry-reader"},
	}
	for _, leaf := range leaves {
		t.Run(leaf.leaf, func(t *testing.T) {
			code := serveIAM(s, leaf.method, leaf.path, leaf.token).Code
			assert.NotEqual(t, http.StatusNotFound, code)
			assert.NotEqual(t, http.StatusMethodNotAllowed, code)
		})
	}
}

func TestRegistryRouteScope(t *testing.T) {
	cases := []struct {
		method, scope string
	}{
		{http.MethodGet, "registry:read"},
		{http.MethodPost, "registry:write"},
		{http.MethodDelete, "registry:delete"},
	}
	for _, tc := range cases {
		scope, err := registryRouteScope(tc.method, "/api/v1/compute/images")
		require.NoError(t, err)
		assert.Equal(t, tc.scope, scope)
	}

	_, err := registryRouteScope(http.MethodOptions, "/api/v1/compute/images")
	var forbidden restapi.ErrRouteForbidden
	require.ErrorAs(t, err, &forbidden)
	assert.Equal(t, "registry:*", forbidden.Scope)
}
