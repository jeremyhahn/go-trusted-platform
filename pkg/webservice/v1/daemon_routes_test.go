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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const fakeDaemonPath = "/api/v1/fake-daemon"

// fakeDaemonRoutes stands in for the daemon's route table: one route, or
// the error MountRESTRoutes returns.
type fakeDaemonRoutes struct{ err error }

func (f *fakeDaemonRoutes) MountRESTRoutes(api *mux.Router) error {
	if f.err != nil {
		return f.err
	}
	api.HandleFunc("/fake-daemon", func(w http.ResponseWriter, _ *http.Request) {
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
	root := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &anonymousAuth{},
		daemonRoutes: &fakeDaemonRoutes{},
	})
	cert := &x509.Certificate{}

	tests := []struct {
		name  string
		state *tls.ConnectionState
		want  int
	}{
		{"no TLS", nil, http.StatusUnauthorized},
		{"TLS without a client certificate", &tls.ConnectionState{}, http.StatusUnauthorized},
		{"unverified peer certificate", &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}, http.StatusUnauthorized},
		{"verified client certificate", &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
			VerifiedChains:   [][]*x509.Certificate{{cert}},
		}, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, getWithTLS(root, fakeDaemonPath, tt.state))
		})
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

	err := MountDaemonRESTRoutes(api, &fakeDaemonRoutes{err: errFakeMount{}}, writer)
	require.ErrorIs(t, err, errFakeMount{})
}

func TestRequireVerifiedClientCert_RefusesWithTypedError(t *testing.T) {
	writer := &recordingWriter{HttpWriter: response.NewResponseWriter(testLogger(), nil)}
	handler := requireVerifiedClientCert(writer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	assert.Equal(t, http.StatusUnauthorized, getWithTLS(handler, fakeDaemonPath, nil))
	require.ErrorIs(t, writer.err, ErrDaemonRouteClientCertRequired{})
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
