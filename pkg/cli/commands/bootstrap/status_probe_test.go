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

package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The regressions in #235. Each asserts a way this probe used to report a
// verdict it had not measured.

// TestHealthEndpointPath_IsAPathTheWebserviceServes is the first defect. The
// probe targeted /api/v1/health, which the webservice does not serve — its
// only /health is /api/v1/platform/health, and the daemon listener that does
// serve /api/v1/health is a different server (#232). So the probe never
// reached a handler on the port it dials.
func TestHealthEndpointPath_IsAPathTheWebserviceServes(t *testing.T) {
	assert.Equal(t, "/api/v1/status", healthEndpointPath,
		"the probe must target a path the webservice actually serves on the port it dials")
	assert.NotEqual(t, "/api/v1/health", healthEndpointPath)
}

// TestHealthPorts_CoverEveryRolesWebservicePort is the second defect, and the
// one that made the command useless on a dedicated deployment: the probe
// dialled a fixed 8443, but only control-plane and single-node serve there.
// Compute serves 9443 and gateway 443
// (configs/platform/templates/**), so those nodes reported "unreachable"
// however healthy they were.
func TestHealthPorts_CoverEveryRolesWebservicePort(t *testing.T) {
	for _, port := range []string{
		"8443", // control-plane, single-node
		"9443", // compute
		"443",  // gateway
	} {
		assert.Contains(t, healthPorts, port,
			"a role's webservice port is missing from the probe's candidates")
	}
}

// newProbeServer starts a TLS listener answering the probe's path with the
// supplied status and body, and returns a client that trusts it.
func newProbeServer(t *testing.T, status int, body string) (host string, client *http.Client) {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != healthEndpointPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(srv.Close)

	certPool := x509.NewCertPool()
	certPool.AddCert(srv.Certificate())

	h, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)

	prev := healthPorts
	healthPorts = []string{port}
	t.Cleanup(func() { healthPorts = prev })

	return h, &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: certPool},
		},
	}
}

// TestProbe_RejectsAnEmpty200 is the third defect. A status code alone cannot
// distinguish platformd from anything else answering 200 on that port — and
// that is not hypothetical: until #251 the platform's own SPA fallback
// answered this probe with a 200 and the command reported every node healthy.
func TestProbe_RejectsAnEmpty200(t *testing.T) {
	host, client := newProbeServer(t, http.StatusOK, "")

	assert.Equal(t, "unhealthy", checkNodeHealth(t.Context(), client, host),
		"an empty 200 was accepted as a platform answer")
}

// TestProbe_RejectsAnHTMLPage is the same defect in the shape it actually
// took: a 200 carrying the SPA shell.
func TestProbe_RejectsAnHTMLPage(t *testing.T) {
	host, client := newProbeServer(t, http.StatusOK,
		"<!DOCTYPE html><html><head><title>Trusted Platform</title></head><body></body></html>")

	assert.Equal(t, "unhealthy", checkNodeHealth(t.Context(), client, host),
		"an HTML page was accepted as a platform answer — this is the exact pre-#251 behaviour")
}

// TestProbe_AcceptsAPlatformAnswer is the positive case, without which the
// two rejections above would pass against a probe that rejects everything.
func TestProbe_AcceptsAPlatformAnswer(t *testing.T) {
	host, client := newProbeServer(t, http.StatusOK,
		`{"payload":{"os":{"hostname":"node-1"},"runtime":{"version":"test"}}}`)

	assert.Equal(t, "healthy", checkNodeHealth(t.Context(), client, host))
}

// TestProbe_AcceptsATruncatedPlatformAnswer covers the bounded read: the
// probe reads at most 512 bytes, so a real /api/v1/status response — which
// carries SMBIOS, OS, network and TPM blocks — arrives cut mid-object. The
// check must not mistake truncation for malformed output.
func TestProbe_AcceptsATruncatedPlatformAnswer(t *testing.T) {
	long := `{"payload":{"os":{"hostname":"node-1","kernel":"` +
		string(make([]byte, 0, 600)) + repeatByte('x', 600) + `"}}}`
	host, client := newProbeServer(t, http.StatusOK, long)

	assert.Equal(t, "healthy", checkNodeHealth(t.Context(), client, host),
		"a valid but truncated platform response was rejected")
}

// TestProbe_ReportsUnhealthyForANonOKStatus keeps the original contract: a
// node that answers but is not OK is unhealthy, not unreachable.
func TestProbe_ReportsUnhealthyForANonOKStatus(t *testing.T) {
	host, client := newProbeServer(t, http.StatusServiceUnavailable, `{"error":"down"}`)

	assert.Equal(t, "unhealthy", checkNodeHealth(t.Context(), client, host))
}

// TestCheckNodeHealth_TriesEveryCandidatePort proves the port search reaches a
// node that serves on the last candidate rather than the first — the compute
// and gateway case.
func TestCheckNodeHealth_TriesEveryCandidatePort(t *testing.T) {
	host, client := newProbeServer(t, http.StatusOK, `{"payload":{}}`)

	// Put two dead ports ahead of the live one.
	live := healthPorts[0]
	healthPorts = []string{"1", "2", live}

	assert.Equal(t, "healthy", checkNodeHealth(t.Context(), client, host),
		"the probe stopped at the first unreachable port instead of trying the rest")
}

// TestCheckNodeHealth_AnsweredPortEndsTheSearch is the converse: a node that
// answers "unhealthy" on an early port must not be re-probed on later ones and
// reported healthy by a different service that happens to listen there.
func TestCheckNodeHealth_AnsweredPortEndsTheSearch(t *testing.T) {
	host, client := newProbeServer(t, http.StatusServiceUnavailable, `{"error":"down"}`)

	live := healthPorts[0]
	healthPorts = []string{live, "8443", "9443"}

	assert.Equal(t, "unhealthy", checkNodeHealth(t.Context(), client, host))
}

// repeatByte builds a run of one byte without pulling in strings.Repeat's
// allocation for a test fixture.
func repeatByte(b byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return string(out)
}
