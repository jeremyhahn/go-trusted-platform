package daemon

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// pxeRESTServer mounts the PXE routes on the PXE service platformd builds:
// one without a backend.
func pxeRESTServer(t *testing.T) *RESTServer {
	t.Helper()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	require.NoError(t, s.SetPXERouterHandlers(logging.DefaultLogger(), NewPXEGRPCService(logging.DefaultLogger(), nil),
		restapi.NewScopeGuard(dnsRESTCallers, nil, nil)))
	return s
}

func TestSetPXERouterHandlers_RefusesAMissingDependency(t *testing.T) {
	guard := restapi.NewScopeGuard(dnsRESTCallers, nil, nil)
	server := NewPXEGRPCService(logging.DefaultLogger(), nil)
	cases := []struct {
		name   string
		logger *logging.Logger
		server platformv1.PXEServiceServer
		guard  *restapi.ScopeGuard
		reason string
	}{
		{"no logger", nil, server, guard, "no logger"},
		{"no server", logging.DefaultLogger(), nil, guard, "no PXE service"},
		{"no guard", logging.DefaultLogger(), server, nil, "no REST scope guard"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
			err := s.SetPXERouterHandlers(tc.logger, tc.server, tc.guard)
			var unavailable ErrPXERESTUnavailable
			require.ErrorAs(t, err, &unavailable)
			assert.Equal(t, tc.reason, unavailable.Reason)
			assert.Equal(t, http.StatusNotFound, serveIAM(s, http.MethodGet, "/api/v1/pxe/status", "pxe-reader").Code,
				"a refused mount serves no PXE route")
		})
	}
}

func TestPXERouterREST_ScopePerRoute(t *testing.T) {
	s := pxeRESTServer(t)

	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/pxe/status", "").Code)

	recorder := serveIAM(s, http.MethodGet, "/api/v1/pxe/status", "dns-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "pxe:read")

	recorder = serveIAM(s, http.MethodPost, "/api/v1/pxe/start", "pxe-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "pxe:write")

	recorder = serveIAM(s, http.MethodDelete, "/api/v1/pxe/devices/7", "pxe-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "pxe:delete")
}

// TestPXERouterREST_ServesTheIntegrationLeaves pins every route the
// integration REST adapters call for PXE: each must be mounted, so the
// router answers with something other than 404 or 405.
func TestPXERouterREST_ServesTheIntegrationLeaves(t *testing.T) {
	s := pxeRESTServer(t)

	leaves := []struct {
		leaf, method, path, token string
	}{
		{"pxe/REST GetStatus", http.MethodGet, "/api/v1/pxe/status", "pxe-reader"},
		{"pxe/REST ListDevices", http.MethodGet, "/api/v1/pxe/devices", "pxe-reader"},
		{"pxe/REST RegisterDevice", http.MethodPost, "/api/v1/pxe/devices", "pxe-writer"},
		{"pxe/REST GetDevice", http.MethodGet, "/api/v1/pxe/devices/7", "pxe-reader"},
		{"pxe/REST RemoveDevice", http.MethodDelete, "/api/v1/pxe/devices/7", "pxe-deleter"},
	}
	for _, leaf := range leaves {
		t.Run(leaf.leaf, func(t *testing.T) {
			code := serveIAM(s, leaf.method, leaf.path, leaf.token).Code
			assert.NotEqual(t, http.StatusNotFound, code)
			assert.NotEqual(t, http.StatusMethodNotAllowed, code)
		})
	}
}

// TestPXERouterREST_AnswersNotConfigured: platformd sets no PXE backend, so
// REST answers what gRPC, QUIC, MCP and Unix answer.
func TestPXERouterREST_AnswersNotConfigured(t *testing.T) {
	recorder := serveIAM(pxeRESTServer(t), http.MethodGet, "/api/v1/pxe/status", "pxe-reader")
	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code, recorder.Body.String())
	assert.Contains(t, recorder.Body.String(), "PXE service is not configured on this node")
}

// TestSetPXERouterHandlers_LeavesTheWebhookUnmounted: the credential-less
// install webhook (#238) is the webservice's, never the daemon's.
func TestSetPXERouterHandlers_LeavesTheWebhookUnmounted(t *testing.T) {
	s := pxeRESTServer(t)
	assert.NotEmpty(t, restRouteTemplates(t, s, "/api/v1/pxe/devices"))
	assert.Empty(t, restRouteTemplates(t, s, "/api/v1/pxe/webhook"))
}
