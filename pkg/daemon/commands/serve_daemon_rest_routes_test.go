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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
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

// replayCA is the daemon's platform CA in the issue-cert test: it really
// certifies the CSR and returns its root as the chain.
type replayCA struct{ *issuancetest.CA }

func (c replayCA) CABundle() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Root.Raw}), nil
}

// callerAs is the webservice login check for a session whose principal is
// caller: it publishes caller to the daemon handler, as the replay does.
func callerAs(caller *platformtoken.AuthorizedContext) v1.DaemonCallerAuthenticator {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(restapi.WithCaller(r.Context(), caller)))
		})
	}
}

// The daemon's own issue-cert route, replayed on the webservice, decides
// admin from the caller the login check publishes: without one it is
// refused, a user issues for themselves only, and an admin role, not an
// admin-named certificate, issues for anyone (#983).
func TestDaemonRESTRoutes_IssueCertTakesTheReplayedCaller(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	key := issuancetest.RSAKey(t)
	user := &platformtoken.AuthorizedContext{Subject: "alice", TenantID: "system", Roles: []string{"user"}}
	admin := &platformtoken.AuthorizedContext{Subject: "ops", TenantID: "system", Roles: []string{common.ROLE_ADMIN}}

	tests := []struct {
		name   string
		caller v1.DaemonCallerAuthenticator
		userID string
		want   int
	}{
		{"no caller", refusingCaller, "alice", http.StatusUnauthorized},
		{"own subject", callerAs(user), "alice", http.StatusCreated},
		{"other subject without admin", callerAs(user), "bob", http.StatusForbidden},
		{"admin role for another subject", callerAs(admin), "bob", http.StatusCreated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := replayCA{issuancetest.NewCA(t)}
			cfg := webserviceModeDaemonConfig(t)
			cfg.MTLSClientCAPool = platform.CAPool
			cfg.CAService = ca
			d, err := daemon.New(cfg)
			require.NoError(t, err)
			defer func() { _ = d.ForceStop() }()

			root := mux.NewRouter()
			api := root.PathPrefix("/api/v1").Subrouter()
			writer := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
			require.NoError(t, v1.MountDaemonRESTRoutes(api, daemonRESTRoutes(d), writer, refusingAuthorizer, tt.caller))

			body, err := json.Marshal(restapi.IssueMTLSCertRequest{CSRPEM: string(issuancetest.CSR(t, key, tt.userID))})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+tt.userID+"/factors/mtls/issue-cert", bytes.NewReader(body))
			leaf, err := x509.ParseCertificate(platform.ClientCert.Certificate[0])
			require.NoError(t, err)
			req.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{leaf},
				VerifiedChains:   [][]*x509.Certificate{{leaf, platform.CACert}},
			}
			rec := httptest.NewRecorder()
			root.ServeHTTP(rec, req)

			assert.Equal(t, tt.want, rec.Code, rec.Body.String())
			if tt.want == http.StatusCreated {
				require.NotNil(t, ca.Opts, "the CA signed the CSR")
				require.NotNil(t, ca.Opts.Subject)
				assert.Equal(t, tt.userID, ca.Opts.Subject.CommonName)
				assert.Equal(t, "system", ca.Opts.Subject.Organization, "the certificate is issued in the caller's tenant")
			} else {
				assert.Nil(t, ca.Opts, "a refused caller must not reach the CA")
			}
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
