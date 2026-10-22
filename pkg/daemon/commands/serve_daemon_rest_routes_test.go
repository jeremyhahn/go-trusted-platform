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

// refusedByGateHeader marks a 403 written by refusingAuthorizer, so a test
// can tell the webservice gate's refusal from the certificate gate's.
const refusedByGateHeader = "X-Webservice-Gate"

// refusingAuthorizer answers 403 on every privileged daemon route, standing
// in for the webservice admin gate the replay puts in front of them.
func refusingAuthorizer(string) func(http.Handler) http.Handler {
	return func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(refusedByGateHeader, "refused")
			w.WriteHeader(http.StatusForbidden)
		})
	}
}

// refusingCaller answers 401 on every caller-checked daemon route, standing
// in for the webservice login check the replay puts in front of them.
func refusingCaller(http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
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
	require.NoError(t, v1.MountDaemonRESTRoutes(api, routes, writer, refusingAuthorizer, refusingCaller))

	verified := func(bundle *testutil.TestTLSBundle) *tls.ConnectionState {
		leaf, parseErr := x509.ParseCertificate(bundle.ClientCert.Certificate[0])
		require.NoError(t, parseErr)
		return &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains:   [][]*x509.Certificate{{leaf, bundle.CACert}},
		}
	}
	// GET /version takes the webservice gate (#983): a certificate from the
	// daemon's roots gets past the certificate gate and stops there, any
	// other caller stops at the certificate gate.
	tests := []struct {
		name        string
		state       *tls.ConnectionState
		want        int
		reachedGate bool
	}{
		{"client certificate from the daemon's client roots", verified(platform), http.StatusForbidden, true},
		{"client certificate from another anchor", verified(callerOnly), http.StatusForbidden, false},
		{"no client certificate", &tls.ConnectionState{}, http.StatusUnauthorized, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
			req.TLS = tt.state
			rec := httptest.NewRecorder()
			root.ServeHTTP(rec, req)
			assert.Equal(t, tt.want, rec.Code)
			assert.Equal(t, tt.reachedGate, rec.Header().Get(refusedByGateHeader) != "", "reached the webservice gate")
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
	err = v1.MountDaemonRESTRoutes(api, daemonRESTRoutes(d), writer, refusingAuthorizer, refusingCaller)
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
	err = v1.MountDaemonRESTRoutes(api, daemonRESTRoutes(d), writer, refusingAuthorizer, refusingCaller)
	require.ErrorIs(t, err, daemon.ErrRESTRoutesUnavailable{})
}
