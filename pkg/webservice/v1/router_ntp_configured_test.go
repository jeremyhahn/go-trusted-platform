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

// fakeNTPServer stands in for the daemon's NTPGRPCService, which this
// package cannot import. Its Configured method reports whether the node has
// a time-synchronization backend (an `ntp:` section).
type fakeNTPServer struct {
	platformv1.UnimplementedNTPServiceServer
	configured bool
}

func (f *fakeNTPServer) Configured() bool { return f.configured }

// fakeNTPRegistry satisfies RestHandlerRegistry for the NTP accessor only;
// the embedded nil interface panics on any other accessor.
type fakeNTPRegistry struct {
	RestHandlerRegistry
	server platformv1.NTPServiceServer
	writer response.HttpWriter
}

func (f *fakeNTPRegistry) ResponseWriter() response.HttpWriter { return f.writer }

func (f *fakeNTPRegistry) NTPServiceServer() platformv1.NTPServiceServer { return f.server }

func (f *fakeNTPRegistry) JSONWebTokenHandler() jwt.TokenHandler {
	return &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}
}

func (f *fakeNTPRegistry) PlatformTokenMiddleware() middleware.AuthMiddleware { return nil }

func newNTPTestRouter(t *testing.T, server platformv1.NTPServiceServer) *mux.Router {
	t.Helper()
	logger := testLogger()
	writer := response.NewResponseWriter(logger, nil)
	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	v1Router := &Router{
		logger:              logger,
		responseWriter:      writer,
		router:              api,
		restHandlerRegistry: &fakeNTPRegistry{server: server, writer: writer},
		serviceRegistry:     NewServiceRegistry(logger, writer),
	}
	v1Router.ntpRoutes()
	registerCapabilitiesEndpoint(api, v1Router.serviceRegistry, nil, writer, nil, nil)
	return root
}

// requireNTPDark checks that a node without an NTP backend lists the ntp
// service and its routes as not configured, so the console shows the
// not-enabled card instead of reading routes that answer 503.
func requireNTPDark(t *testing.T, root *mux.Router) {
	t.Helper()
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ntp/status", nil))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "GET /api/v1/ntp/status")
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	svc, _ := body["service"].(string)
	require.Equal(t, "ntp", svc)

	caps := getCapabilities(t, root)
	c, ok := caps["ntp"]
	require.True(t, ok, "the ntp service is not listed")
	require.Equal(t, CapabilityKindService, c.Kind)
	require.False(t, c.Enabled, "the ntp service is listed enabled")
	require.True(t, strings.HasPrefix(c.Reason, CapabilityReasonNotConfigured+"ntp"),
		"ntp reason = %q", c.Reason)
	for _, op := range []string{"GET /api/v1/ntp/status", "GET /api/v1/ntp/sources", "POST /api/v1/ntp/step"} {
		if c, ok := caps[op]; ok {
			require.Falsef(t, c.Enabled, "%s is listed enabled without an NTP backend", op)
		}
	}
}

func TestNTPRoutes_NoBackendAnswer503(t *testing.T) {
	requireNTPDark(t, newNTPTestRouter(t, &fakeNTPServer{configured: false}))
}

func TestNTPRoutes_NilServerAnswer503(t *testing.T) {
	requireNTPDark(t, newNTPTestRouter(t, nil))
}

func TestNTPRoutes_BackendListsOps(t *testing.T) {
	root := newNTPTestRouter(t, &fakeNTPServer{configured: true})

	caps := getCapabilities(t, root)
	for _, op := range []string{"GET /api/v1/ntp/status", "GET /api/v1/ntp/sources", "POST /api/v1/ntp/step"} {
		c, ok := caps[op]
		require.Truef(t, ok, "%s is not listed", op)
		require.Truef(t, c.Enabled, "%s is listed disabled: %q", op, c.Reason)
	}
}
