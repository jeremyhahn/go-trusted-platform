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

package v1_test

import (
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// daemonRouteGoldenPath holds every "METHOD /template" the webservice
// listener mounts for the daemon-owned groups.
const daemonRouteGoldenPath = "testdata/daemon_routes.golden"

// pathVariable matches one gorilla/mux template variable, with or without
// a pattern ({slot}, {profileID:[0-9]+}).
var pathVariable = regexp.MustCompile(`\{[^}]+\}`)

// goldenBMC is a BMC handler whose methods are never called: the route table
// only takes their method values, and every request below stops at the gate.
type goldenBMC struct{ bmcwebsvc.RestHandler }

// ownedRoutes adapts the daemon REST server's owned groups to the
// v1.DaemonRESTRoutes table the webservice router mounts.
type ownedRoutes struct{ server *daemon.RESTServer }

// ClientCAs is an empty pool: these tests send no client certificate.
func (o ownedRoutes) ClientCAs() *x509.CertPool { return x509.NewCertPool() }

func (o ownedRoutes) MountRESTRoutes(api *mux.Router) error {
	return o.server.MountOwnedRoutes(api)
}

// daemonRoutesOnWebservice builds the daemon REST server with every
// daemon-owned group registered through its setters and mounts the groups
// the way the webservice router does: v1.MountDaemonRESTRoutes on /api/v1.
func daemonRoutesOnWebservice(t *testing.T) *mux.Router {
	t.Helper()

	config := daemon.DefaultConfig()
	config.RESTListenAddr = "127.0.0.1:0"
	service, err := daemon.NewService(config)
	require.NoError(t, err)
	server, err := daemon.NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)

	logger := logging.DefaultLogger()
	server.SetBMCHandler(goldenBMC{})
	server.SetCeremonyService(daemon.NewCeremonyService(logger, nil))
	server.SetPIVService(daemon.NewPIVService(logger, nil))
	server.SetLUKSService(daemon.NewLUKSService(logger, nil, nil))
	server.SetFIDO2Service(daemon.NewFIDO2Service(logger, nil))
	server.SetClusterService(platformv1.UnimplementedClusterServiceServer{})

	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	writer := response.NewResponseWriter(logger, nil)
	require.NoError(t, v1.MountDaemonRESTRoutes(api, ownedRoutes{server: server}, writer, passThrough))
	return root
}

// passThrough authorizes every privileged route, so these tests see the
// client-certificate gate alone.
func passThrough(string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

// TestMountDaemonRESTRoutes_EveryDaemonRouteStillExists compares the
// daemon-owned groups the webservice listener mounts against the checked-in
// golden. A setter that stops registering a group, or a group that moves out
// of the owned set, removes lines here, which the router's own walk cannot
// see (docs/daemon/architecture.md). Regenerate the golden by hand.
func TestMountDaemonRESTRoutes_EveryDaemonRouteStillExists(t *testing.T) {
	built := testutil.WalkRoutes(t, daemonRoutesOnWebservice(t))

	data, err := os.ReadFile(daemonRouteGoldenPath)
	require.NoError(t, err, "missing %s -- it is the assertion, not a cache", daemonRouteGoldenPath)
	assert.Equal(t, goldenLines(string(data)), built,
		"the daemon-owned routes mounted on the webservice listener differ from %s", daemonRouteGoldenPath)
}

// TestMountDaemonRESTRoutes_EveryDaemonRouteRequiresClientCert sends every
// daemon-owned endpoint a request with no TLS state: each must answer the
// gate's 401, so no daemon-owned route is reachable on the webservice
// listener without a verified client certificate. The golden also lists the
// group subrouter prefixes (GET /api/v1/fido2, ...), which carry no handler
// and answer 404; the sweep probes every route that does carry one.
func TestMountDaemonRESTRoutes_EveryDaemonRouteRequiresClientCert(t *testing.T) {
	root := daemonRoutesOnWebservice(t)

	data, err := os.ReadFile(daemonRouteGoldenPath)
	require.NoError(t, err)
	golden := goldenLines(string(data))

	endpoints := endpointRoutes(t, root)
	require.NotEmpty(t, endpoints, "the webservice router mounts no daemon-owned endpoint")

	for _, route := range endpoints {
		assert.Contains(t, golden, route, "endpoint missing from %s", daemonRouteGoldenPath)

		method, template, found := strings.Cut(route, " ")
		require.True(t, found, "route %q is not \"METHOD /template\"", route)
		path := pathVariable.ReplaceAllString(template, "1")

		rec := httptest.NewRecorder()
		root.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "%s %s without a client certificate", method, path)
	}
}

// endpointRoutes returns "METHOD /template" for every route on router that
// carries a handler, in the form testutil.WalkRoutes uses.
func endpointRoutes(t *testing.T, router *mux.Router) []string {
	t.Helper()

	endpoints := make([]string, 0)
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if route.GetHandler() == nil {
			return nil
		}
		template, err := route.GetPathTemplate()
		if err != nil {
			return err
		}
		methods, err := route.GetMethods()
		if err != nil {
			methods = []string{http.MethodGet}
		}
		for _, method := range methods {
			endpoints = append(endpoints, method+" "+template)
		}
		return nil
	})
	require.NoError(t, err)
	return endpoints
}

// goldenLines returns the non-blank lines of a golden file, trimmed.
func goldenLines(data string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(data, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
