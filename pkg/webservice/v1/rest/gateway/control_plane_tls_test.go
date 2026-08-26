// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// testCA issues the client and server certificates for the handshake
// tests below. Everything stays in memory: no files, no host changes.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "control-plane-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issue mints a leaf certificate with the given Common Name, valid for
// both client and server authentication. ips populates the IP SANs the
// httptest listener needs to be verifiable as 127.0.0.1.
func (ca *testCA) issue(t *testing.T, commonName string, ips ...net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("sign leaf %s: %v", commonName, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf %s: %v", commonName, err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// startControlPlaneTLS serves the control-plane routes over a real TLS
// listener configured the way the platform webservice configures its
// own: ClientCAs populated and tls.VerifyClientCertIfGiven, so a client
// certificate is requested but not required. This is what
// requestOptionalClientCert produces in pkg/webservice/webserver_v1.go.
func startControlPlaneTLS(t *testing.T, ca *testCA, cp *ControlPlane) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(controlPlaneRouter(cp))
	// Registered before any certificate generation that can t.Fatalf, so
	// the listener is closed even on that early-failure path.
	t.Cleanup(srv.Close)
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{ca.issue(t, "control-plane", net.ParseIP("127.0.0.1"), net.ParseIP("::1"))},
		ClientCAs:    ca.pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	srv.StartTLS()
	return srv
}

// clientFor builds an HTTPS client presenting the given certificate, or
// none when clientCert is nil.
func clientFor(ca *testCA, clientCert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func postSnapshot(t *testing.T, client *http.Client, baseURL, gatewayID string) *http.Response {
	t.Helper()
	body, err := json.Marshal(&gwstate.Snapshot{GatewayID: gatewayID})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := client.Post(baseURL+"/api/v1/gateway/telemetry", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST telemetry: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestControlPlaneOverRealTLS_BindsToPresentedCertificate exercises the
// binding across an actual TLS handshake rather than a fabricated
// ConnectionState. It is the end-to-end proof that the pieces fit: the
// listener asks for a certificate, the TLS stack verifies it against
// ClientCAs and populates VerifiedChains, and the handler binds the
// reported gateway_id to the CN it finds there.
func TestControlPlaneOverRealTLS_BindsToPresentedCertificate(t *testing.T) {
	ca := newTestCA(t)
	store := newMemStore()
	srv := startControlPlaneTLS(t, ca, newControlPlane(store, nil))

	mini01 := ca.issue(t, "lab-node-1")
	mini02 := ca.issue(t, "lab-node-2")

	t.Run("own gateway_id is accepted", func(t *testing.T) {
		resp := postSnapshot(t, clientFor(ca, &mini01), srv.URL, "lab-node-1")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if _, ok := store.snaps["lab-node-1"]; !ok {
			t.Fatal("lab-node-1's snapshot was not persisted")
		}
	})

	t.Run("another gateway_id is refused", func(t *testing.T) {
		before := store.puts
		resp := postSnapshot(t, clientFor(ca, &mini01), srv.URL, "lab-node-2")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
		}
		if store.puts != before {
			t.Fatalf("store.puts moved from %d to %d — a refused request persisted state", before, store.puts)
		}
		if _, ok := store.snaps["lab-node-2"]; ok {
			t.Fatal("lab-node-1's certificate wrote lab-node-2's snapshot over a real handshake")
		}
	})

	t.Run("each certificate reaches its own record", func(t *testing.T) {
		resp := postSnapshot(t, clientFor(ca, &mini02), srv.URL, "lab-node-2")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("no client certificate is refused", func(t *testing.T) {
		before := store.puts
		resp := postSnapshot(t, clientFor(ca, nil), srv.URL, "lab-node-1")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
		if store.puts != before {
			t.Fatalf("store.puts moved from %d to %d", before, store.puts)
		}
	})
}

// TestControlPlaneOverRealTLS_ForeignCAIsRejected proves the client CA
// pool is doing real work: a certificate with a perfectly good CN, from
// a CA the listener does not trust, must not become an identity. Under
// tls.VerifyClientCertIfGiven the TLS stack refuses it at handshake, so
// the request never reaches a handler at all.
func TestControlPlaneOverRealTLS_ForeignCAIsRejected(t *testing.T) {
	ca := newTestCA(t)
	foreign := newTestCA(t)
	store := newMemStore()
	srv := startControlPlaneTLS(t, ca, newControlPlane(store, nil))

	impostor := foreign.issue(t, "lab-node-1")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      ca.pool, // trust the server; the server must not trust us
		Certificates: []tls.Certificate{impostor},
		MinVersion:   tls.VersionTLS12,
	}}}

	body, err := json.Marshal(&gwstate.Snapshot{GatewayID: "lab-node-1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := client.Post(srv.URL+"/api/v1/gateway/telemetry", "application/json", strings.NewReader(string(body)))
	// The rejection must happen in the handshake, not in a handler. A
	// status-code assertion would still pass if the TLS layer started
	// admitting the foreign certificate and only the handler refused it,
	// which is a materially weaker property than the one being claimed.
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("request succeeded with status %d; a certificate from an untrusted CA must be rejected at the TLS handshake", resp.StatusCode)
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0 — an untrusted certificate wrote state", store.puts)
	}
}

// TestControlPlaneOverRealTLS_DesiredConfigBinding covers the pull side
// over a real handshake.
func TestControlPlaneOverRealTLS_DesiredConfigBinding(t *testing.T) {
	ca := newTestCA(t)
	src := &recordingConfigSource{payload: map[string]interface{}{"bgp_asn": float64(65001)}}
	srv := startControlPlaneTLS(t, ca, newControlPlane(nil, src))
	mini01 := ca.issue(t, "lab-node-1")
	client := clientFor(ca, &mini01)

	resp, err := client.Get(srv.URL + "/api/v1/gateway/desired-config/lab-node-1")
	if err != nil {
		t.Fatalf("GET own desired-config: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("own desired-config status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	resp, err = client.Get(srv.URL + "/api/v1/gateway/desired-config/lab-node-2")
	if err != nil {
		t.Fatalf("GET foreign desired-config: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign desired-config status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if src.calls != 1 {
		t.Fatalf("DesiredConfig calls = %d, want 1 — the refused fetch must not read fleet intent", src.calls)
	}
}
