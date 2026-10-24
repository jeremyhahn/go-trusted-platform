package bootstrap

import (
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newServerNameChecker returns a health checker that trusts pki's CA and
// probes srv's port only.
func newServerNameChecker(t *testing.T, pki *testCPPKI, srv *httptest.Server) *httpHealthChecker {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(pki.caCert)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	return newHTTPHealthChecker(slog.New(slog.NewTextHandler(io.Discard, nil)), pool, []int{port})
}

func TestHTTPHealthChecker_CheckServerName_ProbesRegistrationIP(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, nil)

	var regPath atomic.Value
	pxeboot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		regPath.Store(r.URL.Path)
		_, _ = io.WriteString(w, `{"hostname":"node-01","ip":"127.0.0.1"}`)
	}))
	t.Cleanup(pxeboot.Close)

	hc := newServerNameChecker(t, pki, srv)
	hc.pxebootURL = pxeboot.URL

	// The FQDN does not resolve; the probe succeeds only because the
	// registration supplied the address, looked up by short hostname.
	err := hc.CheckServerName(t.Context(), "node-01.unresolvable.test", testCPTLSName)
	require.NoError(t, err)
	assert.Equal(t, "/installs/node-01/registration.json", regPath.Load())
}

func TestHTTPHealthChecker_CheckServerName_NonOKStatusFails(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusServiceUnavailable, nil)
	hc := newServerNameChecker(t, pki, srv)

	err := hc.CheckServerName(t.Context(), "127.0.0.1", testCPTLSName)

	var healthErr ErrHealthCheckFailed
	require.ErrorAs(t, err, &healthErr)
	assert.Equal(t, "127.0.0.1", healthErr.Address)
	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, msgErr.Msg, "returned HTTP 503")
}

func TestHTTPHealthChecker_CheckServerName_IgnoresUnusableRegistration(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, nil)

	for name, handler := range map[string]http.HandlerFunc{
		"not found":    func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) },
		"invalid JSON": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{") },
		"empty ip":     func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"ip":""}`) },
	} {
		t.Run(name, func(t *testing.T) {
			pxeboot := httptest.NewServer(handler)
			t.Cleanup(pxeboot.Close)
			hc := newServerNameChecker(t, pki, srv)
			hc.pxebootURL = pxeboot.URL

			// The address passed in is kept and probed directly.
			require.NoError(t, hc.CheckServerName(t.Context(), "127.0.0.1", testCPTLSName))
		})
	}
}

func TestHTTPHealthChecker_CheckServerName_NoPortsFailsWithoutCause(t *testing.T) {
	hc := newHTTPHealthChecker(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)

	err := hc.CheckServerName(t.Context(), "127.0.0.1", testCPTLSName)

	var healthErr ErrHealthCheckFailed
	require.ErrorAs(t, err, &healthErr)
	assert.Equal(t, "127.0.0.1", healthErr.Address)
	assert.Nil(t, healthErr.Cause)
	assert.Nil(t, errors.Unwrap(err))
}
