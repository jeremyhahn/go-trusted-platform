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

package attestation_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
)

// quotingTPM stands in for the node's TPM: it quotes whatever qualifying
// data the attestation server hands it and records it.
type quotingTPM struct {
	daemon.AttestationService
	quoted [][]byte
}

func (q *quotingTPM) CollectHostAttestation(_ context.Context, _ *daemon.QuoteConfig, nonce []byte) (*manifest.HostAttestation, error) {
	q.quoted = append(q.quoted, nonce)
	return &manifest.HostAttestation{
		QuoteData: []byte("tpms-attest"),
		Signature: []byte("ak-signature"),
		PCRs:      []manifest.PCRValue{{Index: 7, Value: []byte("pcr-7")}},
		Nonce:     nonce,
	}, nil
}

// localhostResolver points the collector at one address, expecting the
// test bundle's "localhost" server certificate there.
type localhostResolver struct{ address string }

func (r localhostResolver) Endpoints(context.Context, string) ([]reporting.Endpoint, error) {
	return []reporting.Endpoint{{Address: r.address, ServerName: "localhost"}}, nil
}

// newAttestor is a real attesting node's REST surface: the production
// attestation server behind the production collect-host route, over mTLS.
func newAttestor(t *testing.T, bundle *testutil.TestTLSBundle, tpm *quotingTPM) *httptest.Server {
	t.Helper()
	return startTLS(t, bundle, attestorRouter(tpm))
}

// attestorRouter serves the node's quote routes over the production
// attestation server.
func attestorRouter(tpm *quotingTPM) http.Handler {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	server := daemon.NewAttestationServiceServer(tpm, slog.New(slog.NewTextHandler(io.Discard, nil)))
	router := attestation.NewAttestationServerRouter(logger, server, response.NewResponseWriter(logger, nil))
	parent := mux.NewRouter()
	// The SDK REST transport probes /health/live before its first call.
	parent.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	router.RegisterQuoteRoutes(parent.PathPrefix("/api/v1").Subrouter(), nil, nil)
	return parent
}

// newRelay holds a valid certificate and passes each request on to
// upstream over a TLS connection of its own, returning the answer verbatim.
func newRelay(t *testing.T, bundle *testutil.TestTLSBundle, upstream *httptest.Server) *httptest.Server {
	t.Helper()
	clientTLS := bundle.ClientTLSConfig()
	clientTLS.ServerName = "localhost"
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	t.Cleanup(client.CloseIdleConnections)
	return startTLS(t, bundle, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forward, err := http.NewRequestWithContext(r.Context(), r.Method, upstream.URL+r.URL.Path, r.Body)
		require.NoError(t, err)
		forward.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		resp, err := client.Do(forward)
		require.NoError(t, err)
		defer func() { require.NoError(t, resp.Body.Close()) }()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, err = io.Copy(w, resp.Body)
		require.NoError(t, err)
	}))
}

func startTLS(t *testing.T, bundle *testutil.TestTLSBundle, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = bundle.ServerTLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// newCollector is the production collector, dialing address with the
// bundle's client certificate.
func newCollector(t *testing.T, bundle *testutil.TestTLSBundle, address string) *reporting.NodeQuoteSource {
	t.Helper()
	src, err := reporting.NewNodeQuoteSource(reporting.NodeQuoteSourceConfig{
		Addresses: localhostResolver{address: address},
		TLS: func(_ context.Context, ep reporting.Endpoint) (*tls.Config, error) {
			cfg := bundle.ClientTLSConfig()
			cfg.ServerName = ep.ServerName
			return cfg, nil
		},
	})
	require.NoError(t, err)
	return src
}

// TestCollectHost_DirectConnectionIsAccepted: the collector reaches the
// node itself, the node binds the nonce to that one connection, and the
// collector's own derivation agrees.
func TestCollectHost_DirectConnectionIsAccepted(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	tpm := &quotingTPM{}
	node := newAttestor(t, bundle, tpm)
	nonce := []byte("0123456789abcdef0123456789abcdef")

	raw, err := newCollector(t, bundle, node.Listener.Addr().String()).Collect(context.Background(), "42", nonce)
	require.NoError(t, err)

	var evidence reporting.Evidence
	require.NoError(t, json.Unmarshal(raw, &evidence))
	assert.Equal(t, nonce, evidence.Nonce)
	assert.NotEmpty(t, evidence.ChannelBinding)
	require.Len(t, tpm.quoted, 1)
	assert.NotEqual(t, nonce, tpm.quoted[0], "the node quoted the connection-bound value, not the bare nonce")
}

// TestCollectHost_RelayedQuoteIsRejected is #482: an authenticated endpoint
// that relays the collector's request (connection A) to a healthy node over
// a connection of its own (connection B) gets a quote bound to B. The
// collector, holding A, rejects it with a typed error, so the relay cannot
// pass off the node's attested state as its own.
func TestCollectHost_RelayedQuoteIsRejected(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	tpm := &quotingTPM{}
	node := newAttestor(t, bundle, tpm)
	relay := newRelay(t, bundle, node)

	_, err := newCollector(t, bundle, relay.Listener.Addr().String()).Collect(context.Background(), "42", []byte("0123456789abcdef0123456789abcdef"))

	var notBound reporting.ErrQuoteNotBound
	require.ErrorAs(t, err, &notBound)
	assert.Equal(t, relay.Listener.Addr().String(), notBound.Endpoint)
	assert.Len(t, tpm.quoted, 1, "the healthy node was reached through the relay and did quote")
}
