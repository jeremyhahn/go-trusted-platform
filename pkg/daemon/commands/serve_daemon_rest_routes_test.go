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

package commands

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// webserviceModeDaemonConfig is the daemon config platformd serve builds for
// a webservices: section, reduced to what a unit test can start.
func webserviceModeDaemonConfig(t *testing.T) *daemon.Config {
	t.Helper()
	cfg := daemon.DefaultConfig()
	cfg.SocketPath = filepath.Join(t.TempDir(), "platformd.sock")
	cfg.SocketGroup = ""
	cfg.EnableGRPCTCP = false
	cfg.SkipIAMValidation = true
	cfg.MTLSClientCAPool = x509.NewCertPool()
	leaveRESTToWebservice(cfg)
	return cfg
}

func TestLeaveRESTToWebservice_BuildsRouteTableWithoutListener(t *testing.T) {
	cfg := daemon.DefaultConfig()
	cfg.EnableREST = true

	leaveRESTToWebservice(cfg)

	assert.False(t, cfg.EnableREST, "the webservice owns the REST listener")
	assert.True(t, cfg.RESTRoutesOnly, "the daemon must still build its route table")
}

func TestDaemonRESTRoutes_NilDaemonIsNilInterface(t *testing.T) {
	// A typed nil would make the router try to mount a nil daemon.
	assert.Nil(t, daemonRESTRoutes(nil))
}

func TestDaemonRESTRoutes_WebserviceMountsDaemonGroups(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	callerOnly := testutil.GenerateTestTLSBundle(t)
	cfg := webserviceModeDaemonConfig(t)
	cfg.MTLSClientCAPool = platform.CAPool
	d, err := daemon.New(cfg)
	require.NoError(t, err)
	defer func() { _ = d.ForceStop() }()

	routes := daemonRESTRoutes(d)
	require.NotNil(t, routes)

	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	writer := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	require.NoError(t, v1.MountDaemonRESTRoutes(api, routes, writer))

	verified := func(bundle *testutil.TestTLSBundle) *tls.ConnectionState {
		leaf, parseErr := x509.ParseCertificate(bundle.ClientCert.Certificate[0])
		require.NoError(t, parseErr)
		return &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains:   [][]*x509.Certificate{{leaf, bundle.CACert}},
		}
	}
	tests := []struct {
		name  string
		state *tls.ConnectionState
		want  int
	}{
		{"client certificate from the daemon's client roots", verified(platform), http.StatusOK},
		{"client certificate from another anchor", verified(callerOnly), http.StatusForbidden},
		{"no client certificate", &tls.ConnectionState{}, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
			req.TLS = tt.state
			rec := httptest.NewRecorder()
			root.ServeHTTP(rec, req)
			assert.Equal(t, tt.want, rec.Code)
		})
	}
}

func TestDaemonRESTRoutes_DaemonWithoutClientRootsRefusesMount(t *testing.T) {
	cfg := webserviceModeDaemonConfig(t)
	cfg.MTLSClientCAPool = nil
	d, err := daemon.New(cfg)
	require.NoError(t, err)
	defer func() { _ = d.ForceStop() }()

	api := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
	writer := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	err = v1.MountDaemonRESTRoutes(api, daemonRESTRoutes(d), writer)
	require.ErrorIs(t, err, v1.ErrDaemonRouteNoClientRoots{})
}

func TestDaemonRESTRoutes_DaemonWithoutRouteTableRefusesMount(t *testing.T) {
	cfg := webserviceModeDaemonConfig(t)
	cfg.RESTRoutesOnly = false
	d, err := daemon.New(cfg)
	require.NoError(t, err)
	defer func() { _ = d.ForceStop() }()

	api := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
	writer := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	err = v1.MountDaemonRESTRoutes(api, daemonRESTRoutes(d), writer)
	require.ErrorIs(t, err, daemon.ErrRESTRoutesUnavailable{})
}
