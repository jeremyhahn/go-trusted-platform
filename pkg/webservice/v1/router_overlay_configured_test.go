// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/require"
)

// fakeOverlayServer stands in for the daemon's OverlayService, which this
// package cannot import (pkg/api/daemon imports pkg/webservice/v1). Its
// Configured method reports whether an overlay controller is attached.
type fakeOverlayServer struct {
	platformv1.UnimplementedOverlayServiceServer
	configured bool
}

func (f *fakeOverlayServer) Configured() bool { return f.configured }

// fakeOverlayRegistry satisfies RestHandlerRegistry for the overlay
// accessor only; the embedded nil interface panics on any other accessor.
type fakeOverlayRegistry struct {
	RestHandlerRegistry
	server platformv1.OverlayServiceServer
	writer response.HttpWriter
}

func (f *fakeOverlayRegistry) ResponseWriter() response.HttpWriter {
	return f.writer
}

func (f *fakeOverlayRegistry) OverlayServiceServer() platformv1.OverlayServiceServer {
	return f.server
}

func (f *fakeOverlayRegistry) JSONWebTokenHandler() jwt.TokenHandler {
	return &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}
}

func (f *fakeOverlayRegistry) PlatformTokenMiddleware() middleware.AuthMiddleware {
	return nil
}

func newOverlayTestRouter(t *testing.T, server platformv1.OverlayServiceServer) *mux.Router {
	t.Helper()
	logger := testLogger()
	writer := response.NewResponseWriter(logger, nil)
	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	v1Router := &Router{
		logger:         logger,
		responseWriter: writer,
		router:         api,
		restHandlerRegistry: &fakeOverlayRegistry{
			server: server,
			writer: writer,
		},
		serviceRegistry: NewServiceRegistry(logger, writer),
	}
	v1Router.overlayRoutes()
	registerCapabilitiesEndpoint(api, v1Router.serviceRegistry, nil, writer, nil)
	return root
}

func requireOverlayDark(t *testing.T, root *mux.Router) {
	t.Helper()
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/overlay/status", nil))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "GET /api/v1/overlay/status")
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	svc, _ := body["service"].(string)
	require.Equal(t, "overlay", svc)

	caps := getCapabilities(t, root)
	c, ok := caps["overlay"]
	require.True(t, ok, "the overlay service is not listed")
	require.Equal(t, CapabilityKindService, c.Kind)
	require.False(t, c.Enabled, "the overlay service is listed enabled")
	require.True(t, strings.HasPrefix(c.Reason, CapabilityReasonNotConfigured+"overlay"),
		"overlay reason = %q", c.Reason)
	for _, op := range []string{"DELETE /api/v1/overlay/macs", "POST /api/v1/overlay/vnis"} {
		if c, ok := caps[op]; ok {
			require.Falsef(t, c.Enabled, "%s is listed enabled without a controller", op)
		}
	}
}

func TestOverlayRoutes_NoControllerAnswer503(t *testing.T) {
	requireOverlayDark(t, newOverlayTestRouter(t, &fakeOverlayServer{configured: false}))
}

func TestOverlayRoutes_NilServerAnswer503(t *testing.T) {
	requireOverlayDark(t, newOverlayTestRouter(t, nil))
}

func TestOverlayRoutes_ControllerListsOps(t *testing.T) {
	root := newOverlayTestRouter(t, &fakeOverlayServer{configured: true})

	caps := getCapabilities(t, root)
	c, ok := caps["DELETE /api/v1/overlay/macs"]
	require.True(t, ok, "DELETE /api/v1/overlay/macs is not listed")
	require.True(t, c.Enabled, "DELETE /api/v1/overlay/macs is listed disabled: %q", c.Reason)

	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/overlay/status", nil))
	if rec.Code == http.StatusServiceUnavailable {
		var body map[string]any
		_ = json.NewDecoder(rec.Body).Decode(&body)
		svc, _ := body["service"].(string)
		require.NotEqual(t, "overlay", svc, "a configured overlay answers the dark-service 503")
	}
}
