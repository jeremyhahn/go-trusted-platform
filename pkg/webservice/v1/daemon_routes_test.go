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
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// fakeDaemonPath is a certificate-only daemon route, so the client
// certificate is the only gate these tests exercise; a template the
// guard does not classify would be denied before the handler.
const fakeDaemonPath = "/api/v1/ceremony/status"

// fakeDaemonRoutes stands in for the daemon's route table: one route, or
// the error MountRESTRoutes returns.
type fakeDaemonRoutes struct {
	err   error
	roots *x509.CertPool
}

func (f *fakeDaemonRoutes) ClientCAs() *x509.CertPool { return f.roots }

func (f *fakeDaemonRoutes) MountRESTRoutes(api *mux.Router) error {
	if f.err != nil {
		return f.err
	}
	api.HandleFunc("/ceremony/status", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)
	return nil
}

// errFakeMount is the failure fakeDaemonRoutes reports.
type errFakeMount struct{}

func (errFakeMount) Error() string { return "fake mount failure" }

func getWithTLS(root http.Handler, path string, state *tls.ConnectionState) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.TLS = state
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec.Code
}

func TestRegisterRoutes_DaemonRoutesRequireVerifiedClientCert(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	callerOnly := testutil.GenerateTestTLSBundle(t)
	root := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &anonymousAuth{},
		daemonRoutes: &fakeDaemonRoutes{roots: platform.CAPool},
	})
	unverified := verifiedClientState(t, platform)
	unverified.VerifiedChains = nil

	tests := []struct {
		name  string
		state *tls.ConnectionState
		want  int
	}{
		{"no TLS", nil, http.StatusUnauthorized},
		{"TLS without a client certificate", &tls.ConnectionState{}, http.StatusUnauthorized},
		{"unverified peer certificate", unverified, http.StatusUnauthorized},
		// The webservice handshake also verifies chains to the attestation
		// caller-admission anchors; such a chain is not a daemon client.
		{"verified chain to a caller-admission-only anchor", verifiedClientState(t, callerOnly), http.StatusForbidden},
		{"verified chain to the daemon's client roots", verifiedClientState(t, platform), http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, getWithTLS(root, fakeDaemonPath, tt.state))
		})
	}
}

// proxyDaemonRoutes mounts GET /proxy/routes behind the daemon's own scope
// guard, as the daemon does, so a replayed request must satisfy it.
type proxyDaemonRoutes struct {
	roots  *x509.CertPool
	guard  *restapi.ScopeGuard
	served *platformtoken.AuthorizedContext
}

func (d *proxyDaemonRoutes) ClientCAs() *x509.CertPool { return d.roots }

func (d *proxyDaemonRoutes) MountRESTRoutes(r *mux.Router) error {
	r.HandleFunc("/proxy/routes", d.guard.RequireCaller(proxyReadScope,
		func(w http.ResponseWriter, _ *http.Request, caller *platformtoken.AuthorizedContext) {
			d.served = caller
			w.WriteHeader(http.StatusOK)
		})).Methods(http.MethodGet)
	return nil
}

// A console admin session (the legacy JWT, which carries no platform token)
// passes the operator gate and must then pass the daemon's scope guard as
// that session, not by re-reading the bearer: the guard has no token
// authorizer, so a re-read bearer would be refused 401.
func TestMountDaemonRESTRoutes_OperatorRouteReplaysTheSessionCaller(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	daemon := &proxyDaemonRoutes{roots: platform.CAPool, guard: restapi.NewScopeGuard(nil, nil, slog.Default())}
	v1Router := newGatedV1Router(t, &testHandlerRegistry{tokenHandler: &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}})
	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	require.NoError(t, MountDaemonRESTRoutes(api, daemon, v1Router.responseWriter, v1Router.daemonRouteAuthorizer(), v1Router.daemonCallerAuthenticator()))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proxy/routes", nil)
	req.Header.Set("Authorization", "Bearer console-admin")
	req.TLS = verifiedClientState(t, platform)
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, daemon.served)
	assert.Equal(t, []string{proxyReadScope}, daemon.served.Scopes, "the caller holds only the scope the operator gate authorized")
	assert.Contains(t, daemon.served.Roles, common.ROLE_ADMIN)
}

// verifiedClientState is the connection state a webservice handshake
// yields for bundle's client certificate: the leaf, and the chain the TLS
// stack built to bundle's CA.
func verifiedClientState(t *testing.T, bundle *testutil.TestTLSBundle) *tls.ConnectionState {
	t.Helper()
	leaf, err := x509.ParseCertificate(bundle.ClientCert.Certificate[0])
	require.NoError(t, err)
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf, bundle.CACert}},
	}
}

func TestRegisterRoutes_NoDaemonRoutesMountsNone(t *testing.T) {
	root := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	verified := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}

	assert.Equal(t, http.StatusNotFound, getWithTLS(root, fakeDaemonPath, verified))
}

func TestMountDaemonRESTRoutes_ReturnsMountError(t *testing.T) {
	api := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
	writer := response.NewResponseWriter(testLogger(), nil)

	err := MountDaemonRESTRoutes(api, &fakeDaemonRoutes{err: errFakeMount{}, roots: x509.NewCertPool()}, writer, permitAll, permitCaller)
	require.ErrorIs(t, err, errFakeMount{})
}

func TestMountDaemonRESTRoutes_RefusesWithoutAuthorizer(t *testing.T) {
	api := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
	writer := response.NewResponseWriter(testLogger(), nil)

	err := MountDaemonRESTRoutes(api, &fakeDaemonRoutes{roots: x509.NewCertPool()}, writer, nil, permitCaller)
	require.ErrorIs(t, err, ErrDaemonRouteNoAuthorizer{})
	assert.Equal(t, http.StatusNotFound, getWithTLS(api, fakeDaemonPath, nil))
}

func TestMountDaemonRESTRoutes_RefusesWithoutCallerAuthenticator(t *testing.T) {
	api := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
	writer := response.NewResponseWriter(testLogger(), nil)

	err := MountDaemonRESTRoutes(api, &fakeDaemonRoutes{roots: x509.NewCertPool()}, writer, permitAll, nil)
	require.ErrorIs(t, err, ErrDaemonRouteNoCallerAuthenticator{})
	assert.Equal(t, http.StatusNotFound, getWithTLS(api, fakeDaemonPath, nil))
}

func TestRequireDaemonClientCert_RefusesWithTypedErrors(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	callerOnly := testutil.GenerateTestTLSBundle(t)
	writer := &recordingWriter{HttpWriter: response.NewResponseWriter(testLogger(), nil)}
	handler := requireDaemonClientCert(writer, platform.CAPool)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	assert.Equal(t, http.StatusUnauthorized, getWithTLS(handler, fakeDaemonPath, nil))
	require.ErrorIs(t, writer.err, ErrDaemonRouteClientCertRequired{})

	assert.Equal(t, http.StatusForbidden, getWithTLS(handler, fakeDaemonPath, verifiedClientState(t, callerOnly)))
	var untrusted ErrDaemonRouteClientCertUntrusted
	require.ErrorAs(t, writer.err, &untrusted)
	var unknownAuthority x509.UnknownAuthorityError
	require.ErrorAs(t, untrusted, &unknownAuthority)
}

func TestMountDaemonRESTRoutes_RefusesWithoutClientRoots(t *testing.T) {
	api := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
	writer := response.NewResponseWriter(testLogger(), nil)

	err := MountDaemonRESTRoutes(api, &fakeDaemonRoutes{}, writer, permitAll, permitCaller)
	require.ErrorIs(t, err, ErrDaemonRouteNoClientRoots{})
	assert.Equal(t, http.StatusNotFound, getWithTLS(api, fakeDaemonPath, nil))
}

// recordingWriter records the error handed to Error401.
type recordingWriter struct {
	response.HttpWriter
	err error
}

func (w *recordingWriter) Error401(rw http.ResponseWriter, r *http.Request, err error) {
	w.err = err
	w.HttpWriter.Error401(rw, r, err)
}

func (w *recordingWriter) Error403(rw http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	w.err = err
	w.HttpWriter.Error403(rw, r, err, payload)
}
