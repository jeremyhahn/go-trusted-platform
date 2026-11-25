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
	// The PXE store is the system tenant's (#1896 Codex r10): the fixture
	// callers of tenant A are its system tenant.
	svc := NewPXEGRPCService(logging.DefaultLogger(), nil)
	svc.SetSystemTenant(iamRESTTenantA)
	require.NoError(t, s.SetPXERouterHandlers(logging.DefaultLogger(), svc,
		restapi.NewScopeGuard(dnsRESTCallers, nil, nil)))
	return s
}

// TestPXERouterREST_RefusesNonSystemTenant: on the daemon REST listener a
// bearer of another tenant holding pxe:read is refused by PXEService's
// system-tenant check, before the (absent) PXE backend is consulted.
func TestPXERouterREST_RefusesNonSystemTenant(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	svc := NewPXEGRPCService(logging.DefaultLogger(), nil)
	svc.SetSystemTenant(iamRESTTenantB)
	require.NoError(t, s.SetPXERouterHandlers(logging.DefaultLogger(), svc,
		restapi.NewScopeGuard(dnsRESTCallers, nil, nil)))

	recorder := serveIAM(s, http.MethodGet, "/api/v1/pxe/status", "pxe-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code, recorder.Body.String())
	assert.Contains(t, recorder.Body.String(), "only the system tenant")
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
