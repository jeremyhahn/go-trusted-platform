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

package daemon

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// restRoutesTestConfig is a daemon config with no REST listener; routesOnly
// selects whether it still builds the REST route table.
func restRoutesTestConfig(t *testing.T, routesOnly bool) *Config {
	t.Helper()
	config := DefaultConfig()
	config.SocketPath = filepath.Join(t.TempDir(), "platformd.sock")
	config.SocketGroup = ""
	config.EnableGRPCTCP = false
	config.EnableREST = false
	config.RESTRoutesOnly = routesOnly
	config.SkipIAMValidation = true
	return config
}

// apiRouter is a router rooted at /api/v1, the shape the webservice hands
// to MountRESTRoutes.
func apiRouter() (*mux.Router, *mux.Router) {
	root := mux.NewRouter()
	return root, root.PathPrefix(restBasePath).Subrouter()
}

func serve(root *mux.Router, method, path string) int {
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code
}

func TestDaemon_MountRESTRoutes_RoutesOnlyServesOwnedGroups(t *testing.T) {
	d, err := New(restRoutesTestConfig(t, true))
	require.NoError(t, err)
	defer func() { _ = d.ForceStop() }()

	// A route table without a listener is not the daemon's REST server.
	assert.Nil(t, d.RESTServer())
	assert.False(t, d.IsRESTEnabled())
	assert.NotContains(t, d.HealthRegistry().List(), "rest",
		"a route table that never listens must not report REST health")

	root, api := apiRouter()
	require.NoError(t, d.MountRESTRoutes(api))

	assert.Equal(t, http.StatusOK, serve(root, http.MethodGet, "/api/v1/version"))
	assert.Equal(t, http.StatusOK, serve(root, http.MethodGet, "/api/v1/protocols"))
	// The webservice serves its own /api/v1/status; the daemon's stays off.
	assert.Equal(t, http.StatusNotFound, serve(root, http.MethodGet, "/api/v1/status"))
}

func TestDaemon_MountRESTRoutes_RefusesWithoutRouteTable(t *testing.T) {
	d, err := New(restRoutesTestConfig(t, false))
	require.NoError(t, err)
	defer func() { _ = d.ForceStop() }()

	_, api := apiRouter()
	err = d.MountRESTRoutes(api)
	require.ErrorIs(t, err, ErrRESTRoutesUnavailable{})
}

func TestDaemon_MountRESTRoutes_RefusesNilRouter(t *testing.T) {
	d, err := New(restRoutesTestConfig(t, true))
	require.NoError(t, err)
	defer func() { _ = d.ForceStop() }()

	require.ErrorIs(t, d.MountRESTRoutes(nil), ErrRESTRoutesUnavailable{})
}
