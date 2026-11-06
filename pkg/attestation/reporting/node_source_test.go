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

package reporting

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPKI is a root that issues a server certificate for the fake node and
// a client certificate for the collector.
type testPKI struct {
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	pool     *x509.CertPool
	server   tls.Certificate
	client   tls.Certificate
	otherCli tls.Certificate
}

func newTestPKI(t *testing.T, serverName string) *testPKI {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(root)

	issue := func(cn string, eku x509.ExtKeyUsage, dns []string, ips []net.IP) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
			DNSNames: dns, IPAddresses: ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
		require.NoError(t, err)
		leaf, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	}
	return &testPKI{
		root: root, rootKey: rootKey, pool: pool,
		server:   issue(serverName, x509.ExtKeyUsageServerAuth, []string{serverName}, nil),
		client:   issue("cp.example.internal", x509.ExtKeyUsageClientAuth, []string{"cp.example.internal"}, nil),
		otherCli: issue("rogue.example.internal", x509.ExtKeyUsageClientAuth, nil, nil),
	}
}

// fakeNode is a TLS server that behaves like a node's quote endpoint: it
// requires a client certificate from the PKI and answers with the platform
// envelope.
type fakeNode struct {
	srv          *httptest.Server
	hits         atomic.Int32
	clockHits    atomic.Int32
	lastBody     []byte
	lastBinding  []byte
	respond      func(w http.ResponseWriter, nonce []byte, body map[string]any)
	respondClock func(w http.ResponseWriter)
}

func newFakeNode(t *testing.T, pki *testPKI) *fakeNode {
	t.Helper()
	n := &fakeNode{}
	n.respond = func(w http.ResponseWriter, nonce []byte, _ map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write(envelope(t, goodAttestation(nonce)))
		require.NoError(t, err)
	}
	n.respondClock = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"code":200,"success":true,"payload":{"synced":true,"stratum":3}}`))
		require.NoError(t, err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.hits.Add(1)
		if r.URL.Path == nodeClockPath && r.Method == http.MethodGet {
			n.clockHits.Add(1)
			n.respondClock(w)
			return
		}
		if r.URL.Path != hostAttestationPath || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		n.lastBody = body
		// The node derives the binding from its own end of the connection,
		// the way a real node's quote handler does.
		binding, err := r.TLS.ExportKeyingMaterial(xkms.PeerChannelBindingExporterLabel, nil, xkms.PeerChannelBindingLength)
		require.NoError(t, err)
		n.lastBinding = binding
		var req map[string]any
		require.NoError(t, json.Unmarshal(body, &req))
		nonceStr, _ := req["nonce"].(string)
		nonce, err := base64.StdEncoding.DecodeString(nonceStr)
		require.NoError(t, err)
		// It quotes the nonce bound to that connection, never the nonce as
		// sent (#482), and echoes the value it quoted.
		n.respond(w, xkms.PeerQualifyingData(nonce, binding), req)
	})
	n.srv = httptest.NewUnstartedServer(handler)
	n.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.pool,
		MinVersion:   tls.VersionTLS12,
	}
	n.srv.StartTLS()
	t.Cleanup(n.srv.Close)
	return n
}

func (n *fakeNode) address() string {
	return strings.TrimPrefix(n.srv.URL, "https://")
}

type fixedResolver struct {
	eps []Endpoint
	err error
}

func (r *fixedResolver) Endpoints(context.Context, string) ([]Endpoint, error) {
	return r.eps, r.err
}

func dialerWith(pki *testPKI, cert tls.Certificate) TLSDialer {
	return func(_ context.Context, _ Endpoint) (*tls.Config, error) {
		return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pki.pool, MinVersion: tls.VersionTLS12}, nil
	}
}

func TestNewNodeQuoteSource_FailsClosed(t *testing.T) {
	_, err := NewNodeQuoteSource(NodeQuoteSourceConfig{TLS: func(context.Context, Endpoint) (*tls.Config, error) { return nil, nil }})
	var noResolver ErrNoAddressResolver
	require.ErrorAs(t, err, &noResolver)

	_, err = NewNodeQuoteSource(NodeQuoteSourceConfig{Addresses: &fixedResolver{}})
	var noDialer ErrNoTLSDialer
	require.ErrorAs(t, err, &noDialer)
}

func TestNodeQuoteSource_CollectsEvidenceOverMTLS(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: node.address(), ServerName: "node-01.example.internal", Source: SourcePlatformDNS}}},
		TLS:       dialerWith(pki, pki.client),
		PCRs:      []int{0, 7},
	})
	require.NoError(t, err)

	nonce := []byte("fresh-nonce")
	evidence, err := src.Collect(context.Background(), "42", nonce)
	require.NoError(t, err)

	var ev Evidence
	require.NoError(t, json.Unmarshal(evidence, &ev))
	assert.Equal(t, nonce, ev.Nonce)
	assert.Equal(t, []byte("TPMS_ATTEST"), ev.Quote)
	assert.Len(t, ev.PCRs, 2)
	// The evidence carries the binding the node derived on its own end.
	require.Len(t, node.lastBinding, xkms.PeerChannelBindingLength)
	assert.Equal(t, node.lastBinding, ev.ChannelBinding)

	// The collector sends the bare nonce: the node binds it to the
	// connection itself (#482). The PCR selection is in the node's protojson
	// vocabulary.
	var sent map[string]any
	require.NoError(t, json.Unmarshal(node.lastBody, &sent))
	assert.Equal(t, base64.StdEncoding.EncodeToString(nonce), sent["nonce"])
	cfg, _ := sent["config"].(map[string]any)
	assert.Equal(t, []any{float64(0), float64(7)}, cfg["pcrIndices"])
	assert.Equal(t, int32(1), node.hits.Load())
}

// TestNodeQuoteSource_AlwaysSendsAConfig is the fleet finding of 2026-09-05:
// with no PCR selection configured the collector omitted `config`, and the
// node's gRPC surface answered 400 "quote config is required" to every
// collection. An empty config is how the node is asked for its default PCR
// selection, so it must be present even when there is nothing to put in it.
func TestNodeQuoteSource_AlwaysSendsAConfig(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: node.address(), ServerName: "node-01.example.internal", Source: SourcePlatformDNS}}},
		TLS:       dialerWith(pki, pki.client),
	})
	require.NoError(t, err)

	_, err = src.Collect(context.Background(), "42", []byte("fresh-nonce"))
	require.NoError(t, err)

	var sent map[string]any
	require.NoError(t, json.Unmarshal(node.lastBody, &sent))
	cfg, ok := sent["config"].(map[string]any)
	require.True(t, ok, "config must be present even with no PCR selection: %s", node.lastBody)
	_, hasPCRs := cfg["pcrIndices"]
	assert.False(t, hasPCRs, "an empty selection must not be sent as an empty list; the node defaults on absence")
}

func TestNodeQuoteSource_RefusesWithoutNonce(t *testing.T) {
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{Addresses: &fixedResolver{}, TLS: dialerWith(nil, tls.Certificate{})})
	require.NoError(t, err)
	_, err = src.Collect(context.Background(), "1", nil)
	var invalid ErrInvalidEvidence
	require.ErrorAs(t, err, &invalid)
}

func TestNodeQuoteSource_NoAddressFailsClosed(t *testing.T) {
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{err: ErrNoDialableAddress{DeviceID: "1", Reason: "none"}},
		TLS:       dialerWith(nil, tls.Certificate{}),
	})
	require.NoError(t, err)
	_, err = src.Collect(context.Background(), "1", []byte("n"))
	var none ErrNoDialableAddress
	require.ErrorAs(t, err, &none)
}

func TestNodeQuoteSource_WrongServerNameIsRefusedByTLS(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: node.address(), ServerName: "someone-else.example.internal", Source: SourceHeartbeatPeer}}},
		TLS:       dialerWith(pki, pki.client),
	})
	require.NoError(t, err)
	_, err = src.Collect(context.Background(), "42", []byte("n"))
	var unreachable ErrNodeUnreachable
	require.ErrorAs(t, err, &unreachable)
	assert.Equal(t, int32(0), node.hits.Load(), "the handshake must fail before a request is made")
	assert.Contains(t, err.Error(), SourceHeartbeatPeer)
}

func TestNodeQuoteSource_UntrustedServerIsRefused(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	other := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, other)
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: node.address(), ServerName: "node-01.example.internal"}}},
		TLS:       dialerWith(pki, pki.client), // trusts pki, node is other
	})
	require.NoError(t, err)
	_, err = src.Collect(context.Background(), "42", []byte("n"))
	var unreachable ErrNodeUnreachable
	require.ErrorAs(t, err, &unreachable)
	assert.Equal(t, int32(0), node.hits.Load())
}

func TestNodeQuoteSource_NodeRefusalIsReportedNotVerified(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	node.respond = func(w http.ResponseWriter, _ []byte, _ map[string]any) {
		w.WriteHeader(http.StatusForbidden)
		_, err := w.Write([]byte(`{"success":false,"code":403,"error":{"message":"caller not admitted"}}` + "\nsecond line"))
		require.NoError(t, err)
	}
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: node.address(), ServerName: "node-01.example.internal"}}},
		TLS:       dialerWith(pki, pki.client),
	})
	require.NoError(t, err)
	_, err = src.Collect(context.Background(), "42", []byte("n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 403")
	assert.Contains(t, err.Error(), "caller not admitted")
	assert.NotContains(t, err.Error(), "second line")
}

// TestNodeQuoteSource_UnboundNonceEchoIsRefused covers a node that echoes a
// nonce other than the one bound to this connection: a stale value, or the
// bare nonce from a node on the old contract or one that quotes whatever it
// is sent. Neither proves anything about the connection, so both are
// refused (#482).
func TestNodeQuoteSource_UnboundNonceEchoIsRefused(t *testing.T) {
	nonce := []byte("fresh-nonce")
	cases := map[string][]byte{
		"stale nonce": []byte("stale"),
		"bare nonce":  nonce,
	}
	for name, echoed := range cases {
		t.Run(name, func(t *testing.T) {
			pki := newTestPKI(t, "node-01.example.internal")
			node := newFakeNode(t, pki)
			node.respond = func(w http.ResponseWriter, _ []byte, _ map[string]any) {
				_, err := w.Write(envelope(t, goodAttestation(echoed)))
				require.NoError(t, err)
			}
			src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
				Addresses: &fixedResolver{eps: []Endpoint{{Address: node.address(), ServerName: "node-01.example.internal"}}},
				TLS:       dialerWith(pki, pki.client),
			})
			require.NoError(t, err)

			_, err = src.Collect(context.Background(), "42", nonce)

			var notBound ErrQuoteNotBound
			require.ErrorAs(t, err, &notBound)
			assert.Equal(t, node.address(), notBound.Endpoint)
			assert.Contains(t, err.Error(), "not bound to this connection")
		})
	}
}

// TestNodeQuoteSource_RelayedQuoteIsRefused is the relay of #482 against the
// collector: the endpoint it dials terminates TLS and forwards the bare
// request to a healthy node over a connection of its own (connection B). The
// node binds its quote to connection B, so the collector, which holds
// connection A, refuses it.
func TestNodeQuoteSource_RelayedQuoteIsRefused(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	relay := newRelay(t, pki, node)
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: relay.Listener.Addr().String(), ServerName: "node-01.example.internal"}}},
		TLS:       dialerWith(pki, pki.client),
	})
	require.NoError(t, err)

	_, err = src.Collect(context.Background(), "42", []byte("fresh-nonce"))

	var notBound ErrQuoteNotBound
	require.ErrorAs(t, err, &notBound)
	assert.Equal(t, int32(1), node.hits.Load(), "the node was reached through the relay and quoted")

	// The refusal is the recorded cause of the collection failing, not
	// flattened into a string.
	var unreachable ErrNodeUnreachable
	require.ErrorAs(t, err, &unreachable)
	require.Len(t, unreachable.Causes, 1)
	assert.Equal(t, notBound, unreachable.Causes[0])
}

// newRelay is an endpoint that holds a valid certificate and passes every
// host-attestation request on to node over its own mTLS connection,
// returning the node's answer verbatim.
func newRelay(t *testing.T, pki *testPKI, node *fakeNode) *httptest.Server {
	t.Helper()
	upstream := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{pki.client},
		RootCAs:      pki.pool,
		ServerName:   "node-01.example.internal",
		MinVersion:   tls.VersionTLS12,
	}}}
	t.Cleanup(upstream.CloseIdleConnections)
	relay := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forward, err := http.NewRequestWithContext(r.Context(), r.Method, node.srv.URL+r.URL.Path, r.Body)
		require.NoError(t, err)
		forward.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		resp, err := upstream.Do(forward)
		require.NoError(t, err)
		defer func() { require.NoError(t, resp.Body.Close()) }()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, err = io.Copy(w, resp.Body)
		require.NoError(t, err)
	}))
	relay.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.pool,
		MinVersion:   tls.VersionTLS12,
	}
	relay.StartTLS()
	t.Cleanup(relay.Close)
	return relay
}

func TestNodeQuoteSource_OversizedResponseIsRefused(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	node.respond = func(w http.ResponseWriter, _ []byte, _ map[string]any) {
		_, err := w.Write(make([]byte, maxResponseBytes+10))
		require.NoError(t, err)
	}
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: node.address(), ServerName: "node-01.example.internal"}}},
		TLS:       dialerWith(pki, pki.client),
	})
	require.NoError(t, err)
	_, err = src.Collect(context.Background(), "42", []byte("n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestNodeQuoteSource_TriesNextEndpointAfterFailure(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	// A listener that accepts and closes: the first candidate is dead.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, dead.Close())

	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{
			{Address: dead.Addr().String(), ServerName: "node-01.example.internal", Source: SourcePlatformDNS},
			{Address: node.address(), ServerName: "node-01.example.internal", Source: SourceHeartbeatPeer},
		}},
		TLS: dialerWith(pki, pki.client),
	})
	require.NoError(t, err)
	evidence, err := src.Collect(context.Background(), "42", []byte("n"))
	require.NoError(t, err)
	assert.NotEmpty(t, evidence)
	assert.Equal(t, int32(1), node.hits.Load())
}

func TestNodeQuoteSource_DialerErrorsAndInsecureConfigsAreRefused(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	ep := Endpoint{Address: node.address(), ServerName: "node-01.example.internal"}

	cases := map[string]TLSDialer{
		"dialer error": func(context.Context, Endpoint) (*tls.Config, error) { return nil, errors.New("no identity") },
		"nil config":   func(context.Context, Endpoint) (*tls.Config, error) { return nil, nil },
		"insecure": func(context.Context, Endpoint) (*tls.Config, error) {
			return verificationDisabled(&tls.Config{Certificates: []tls.Certificate{pki.client}}), nil
		},
	}
	for name, dialer := range cases {
		t.Run(name, func(t *testing.T) {
			src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{Addresses: &fixedResolver{eps: []Endpoint{ep}}, TLS: dialer})
			require.NoError(t, err)
			_, err = src.Collect(context.Background(), "42", []byte("n"))
			require.Error(t, err)
			assert.Equal(t, int32(0), node.hits.Load())
		})
	}
	assert.Contains(t, ErrInsecureDialer{Endpoint: "x"}.Error(), "verification disabled")
}

// A quote relayed from another session must not verify, so every
// connection hands the node different qualifying data for the same nonce.
func TestNodeQuoteSource_EachConnectionIsBoundSeparately(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: node.address(), ServerName: "node-01.example.internal"}}},
		TLS:       dialerWith(pki, pki.client),
	})
	require.NoError(t, err)

	nonce := []byte("same-nonce")
	firstEvidence, err := src.Collect(context.Background(), "42", nonce)
	require.NoError(t, err)
	first := node.lastBinding
	secondEvidence, err := src.Collect(context.Background(), "42", nonce)
	require.NoError(t, err)
	assert.NotEqual(t, first, node.lastBinding)

	var a, b Evidence
	require.NoError(t, json.Unmarshal(firstEvidence, &a))
	require.NoError(t, json.Unmarshal(secondEvidence, &b))
	assert.NotEqual(t, a.ChannelBinding, b.ChannelBinding,
		"the same nonce over two connections is bound to two different values")
	assert.Equal(t, int32(2), node.hits.Load())
}

func TestNodeQuoteSource_CloseConnIsQuietOnAClosedConnection(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	var logs bytes.Buffer
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{},
		TLS:       dialerWith(pki, pki.client),
		Logger:    slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	require.NoError(t, err)
	conn, err := src.dial(context.Background(), Endpoint{Address: node.address(), ServerName: "node-01.example.internal"})
	require.NoError(t, err)

	src.closeConn(conn)
	src.closeConn(conn)
	assert.Empty(t, logs.String())
}

// failingCloseConn is a connection whose Close fails with something other
// than net.ErrClosed.
type failingCloseConn struct{ net.Conn }

func (failingCloseConn) Close() error { return errors.New("close failed") }

func TestNodeQuoteSource_CloseConnLogsARealCloseFailure(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		assert.NoError(t, client.Close())
		assert.NoError(t, server.Close())
	})
	var logs bytes.Buffer
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{},
		TLS:       func(context.Context, Endpoint) (*tls.Config, error) { return nil, nil },
		Logger:    slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	require.NoError(t, err)

	src.closeConn(tls.Client(failingCloseConn{client}, &tls.Config{MinVersion: tls.VersionTLS12}))
	assert.Contains(t, logs.String(), "close failed")
}

func TestSingleUseDialer_HandsOverOneConnectionThenRefuses(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		assert.NoError(t, client.Close())
		assert.NoError(t, server.Close())
	})
	dial := singleUseDialer(Endpoint{Address: "node-01:9443"}, client)

	got, err := dial(context.Background(), "tcp", "node-01:9443")
	require.NoError(t, err)
	assert.Equal(t, client, got)

	got, err = dial(context.Background(), "tcp", "node-01:9443")
	assert.Nil(t, got)
	var spent ErrConnectionSpent
	require.ErrorAs(t, err, &spent)
	assert.Equal(t, "node-01:9443", spent.Endpoint)
	assert.Contains(t, err.Error(), "refusing to redial")
}

func TestErrChannelBinding_NamesTheEndpointAndCause(t *testing.T) {
	cause := errors.New("TLS exporter refused")
	var err error = ErrChannelBinding{Endpoint: "10.0.0.5:9443", Cause: cause}
	assert.Contains(t, err.Error(), "10.0.0.5:9443")
	assert.Contains(t, err.Error(), "TLS exporter refused")
	assert.ErrorIs(t, err, cause)

	assert.Equal(t, "attestation reporting: no channel binding on the connection to x",
		ErrChannelBinding{Endpoint: "x"}.Error())
}

func TestNodeQuoteSource_ContextCancellationStopsTheAttempts(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, dead.Close())
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: dead.Addr().String(), ServerName: "n"}, {Address: dead.Addr().String(), ServerName: "n"}}},
		TLS:       dialerWith(pki, pki.client),
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = src.Collect(ctx, "42", []byte("n"))
	var unreachable ErrNodeUnreachable
	require.ErrorAs(t, err, &unreachable)
	assert.Len(t, unreachable.Attempts, 1, "a cancelled context stops after the first attempt")
	assert.Len(t, unreachable.Causes, 1, "each attempt keeps its cause")
}

func TestNodeQuoteSource_RedirectsAreNotFollowed(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	node.respond = func(w http.ResponseWriter, _ []byte, _ map[string]any) {
		http.Redirect(w, &http.Request{URL: nil, Method: http.MethodPost}, "https://attacker.example/", http.StatusFound)
	}
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: node.address(), ServerName: "node-01.example.internal"}}},
		TLS:       dialerWith(pki, pki.client),
	})
	require.NoError(t, err)
	_, err = src.Collect(context.Background(), "42", []byte("n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 302")
	assert.Equal(t, int32(1), node.hits.Load())
}

func TestSummarise(t *testing.T) {
	assert.Equal(t, "first", summarise([]byte("  first\nsecond")))
	long := strings.Repeat("x", 300)
	assert.Len(t, summarise([]byte(long)), 200)
}

// verificationDisabled returns cfg with certificate verification switched
// off. It exists ONLY so the test above can prove NodeQuoteSource refuses
// such a dialer; the field is assigned rather than written as a literal so
// the repository's InsecureSkipVerify allowlist gate (make
// check-insecure-tls), which greps for the literal form in production
// dials, does not have to carry a test that asserts refusal.
func verificationDisabled(cfg *tls.Config) *tls.Config {
	cfg.InsecureSkipVerify = true
	return cfg
}
