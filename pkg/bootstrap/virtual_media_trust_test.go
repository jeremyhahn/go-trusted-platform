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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// testCPTLSName is the DNS name the test control plane's leaf is issued
// for. Like the real control plane's certificate it carries no IP SAN, so
// a client dialing 127.0.0.1 verifies only by asking for this name.
const testCPTLSName = "cp.example.test"

// testCPPKI holds an in-memory CA + leaf issued for testCPTLSName, used to
// stand up a fake control-plane webservice for capture-then-verify tests.
type testCPPKI struct {
	caPEM    []byte
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	tlsCert  tls.Certificate
	spkiPinB string // base64-std SHA-256 of the CA's SPKI
}

// newTestCPPKI mints an ECDSA P-256 CA and a server leaf whose only
// SAN is the DNS name testCPTLSName. The returned tls.Certificate
// presents the full leaf+CA chain so SPKI pin capture can locate the CA
// anchor.
func newTestCPPKI(t *testing.T) *testCPPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-cp-root-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-cp-webservice"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{testCPTLSName},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(&caKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal CA SPKI: %v", err)
	}
	sum := sha256.Sum256(spkiDER)

	return &testCPPKI{
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		caCert: caCert,
		caKey:  caKey,
		tlsCert: tls.Certificate{
			Certificate: [][]byte{leafDER, caDER},
			PrivateKey:  leafKey,
		},
		spkiPinB: base64.StdEncoding.EncodeToString(sum[:]),
	}
}

// startTestCPServer serves body at every path over TLS using the PKI's
// leaf+CA chain on an ephemeral port; pointControlPlaneAt aims an
// orchestrator at it.
func startTestCPServer(t *testing.T, pki *testCPPKI, status int, body []byte) *httptest.Server {
	t.Helper()
	return startTestCPServerHandler(t, pki, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if _, err := w.Write(body); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
}

// startTestCPServerHandler is startTestCPServer with a caller-supplied
// handler, for tests that must answer the bundle and status paths
// differently.
func startTestCPServerHandler(t *testing.T, pki *testCPPKI, handler http.Handler) *httptest.Server {
	t.Helper()

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pki.tlsCert},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// serverPort is the port srv listens on.
func serverPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split server addr: %v", err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return p
}

// pointControlPlaneAt configures o's control-plane webservice port to srv's
// ephemeral port, the way an operator sets platform.control_plane_port.
func pointControlPlaneAt(t *testing.T, o *Orchestrator, srv *httptest.Server) {
	t.Helper()
	o.config.Platform.ControlPlanePort = serverPort(t, srv)
}

// newTrustTestOrchestrator builds a minimal orchestrator whose discovered
// list contains one control-plane node with a 127.0.0.1 static interface
// and no templates, so the control-plane TLS name falls back to the cp
// role alias under the platform domain: testCPTLSName.
func newTrustTestOrchestrator() *Orchestrator {
	return &Orchestrator{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: &BootstrapConfig{Platform: PlatformGlobalConfig{Domain: "example.test"}},
		discovered: []DiscoveredNode{
			{
				NodeConfig: NodeConfig{
					Hostname: "cp-01",
					Role:     RoleControlPlane,
					Interfaces: []installer.InterfaceConfig{
						{
							Name:        "eth0",
							Type:        installer.InterfaceTypeStatic,
							IPv4Address: "127.0.0.1",
						},
					},
				},
			},
		},
	}
}

func TestFetchControlPlaneCABundle_CaptureThenVerify(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)

	o := newTrustTestOrchestrator()
	pointControlPlaneAt(t, o, srv)
	bundle, err := o.fetchControlPlaneCABundle(context.Background())
	if err != nil {
		t.Fatalf("fetchControlPlaneCABundle: %v", err)
	}
	if bundle != string(pki.caPEM) {
		t.Error("returned bundle does not match served PEM")
	}
	if o.cpCAPool == nil {
		t.Fatal("cpCAPool not stored after successful capture-then-verify")
	}
}

func TestFetchControlPlaneCABundle_RejectsMismatchedBundle(t *testing.T) {
	serving := newTestCPPKI(t)
	other := newTestCPPKI(t)
	// The server's TLS chain is signed by `serving`, but the bundle it
	// returns belongs to `other` — capture-then-verify must reject it.
	srv := startTestCPServer(t, serving, http.StatusOK, other.caPEM)

	o := newTrustTestOrchestrator()
	pointControlPlaneAt(t, o, srv)
	_, err := o.fetchControlPlaneCABundle(context.Background())
	var verifyErr ErrCABundleVerifyFailed
	if !errors.As(err, &verifyErr) {
		t.Fatalf("expected ErrCABundleVerifyFailed, got %v", err)
	}
	if o.cpCAPool != nil {
		t.Error("cpCAPool must not be stored when verification fails")
	}
}

func TestFetchControlPlaneCABundle_AcceptsMixedBundle(t *testing.T) {
	// Under the capture-then-verify policy (x509.Verify with VerifyOptions)
	// a bundle containing the genuine CA plus additional CAs is accepted:
	// the peer chain (signed by genuine CA) verifies against the pool
	// (genuine CA is present). Subsequent connections use RootCAs: cpCAPool
	// so any extra CA in the pool cannot be leveraged to forge a cert that
	// passes TLS verification against the serving endpoint.
	serving := newTestCPPKI(t)
	extra := newTestCPPKI(t)
	mixed := append(append([]byte{}, serving.caPEM...), extra.caPEM...)
	srv := startTestCPServer(t, serving, http.StatusOK, mixed)

	o := newTrustTestOrchestrator()
	pointControlPlaneAt(t, o, srv)
	bundle, err := o.fetchControlPlaneCABundle(context.Background())
	if err != nil {
		t.Fatalf("fetchControlPlaneCABundle rejected a valid mixed bundle: %v", err)
	}
	if bundle != string(mixed) {
		t.Error("returned bundle does not match served PEM")
	}
	if o.cpCAPool == nil {
		t.Fatal("cpCAPool must be stored after successful capture-then-verify")
	}
}

func TestFetchControlPlaneCABundle_RejectsInvalidPEM(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, []byte("this is not a PEM bundle"))

	o := newTrustTestOrchestrator()
	pointControlPlaneAt(t, o, srv)
	_, err := o.fetchControlPlaneCABundle(context.Background())
	var invalidErr ErrCABundleInvalid
	if !errors.As(err, &invalidErr) {
		t.Fatalf("expected ErrCABundleInvalid, got %v", err)
	}
	if o.cpCAPool != nil {
		t.Error("cpCAPool must not be stored for an invalid bundle")
	}
}

func TestFetchControlPlaneCABundle_NoControlPlane(t *testing.T) {
	o := &Orchestrator{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		discovered: []DiscoveredNode{{NodeConfig: NodeConfig{Hostname: "w1", Role: RoleWorker}}},
	}
	if _, err := o.fetchControlPlaneCABundle(context.Background()); err == nil {
		t.Fatal("expected error when no control-plane node is discovered")
	}
}

func TestFetchControlPlaneSPKIPin_RequiresCAPool(t *testing.T) {
	o := newTrustTestOrchestrator()
	// o.cpCAPool is nil: pin capture must refuse to dial unverified.
	_, err := o.fetchControlPlaneSPKIPin(context.Background())
	var required ErrCABundleRequired
	if !errors.As(err, &required) {
		t.Fatalf("expected ErrCABundleRequired, got %v", err)
	}
}

func TestFetchControlPlaneSPKIPin_RejectsUnverifiedChain(t *testing.T) {
	serving := newTestCPPKI(t)
	other := newTestCPPKI(t)
	srv := startTestCPServer(t, serving, http.StatusOK, serving.caPEM)

	// cpCAPool holds an unrelated CA: tls.DialWithDialer rejects the
	// server certificate because it is not signed by any root in the pool.
	// The error is a native TLS x509 verification failure, not a wrapped
	// ErrCABundleVerifyFailed, because the TLS library returns before any
	// application-layer verification can run.
	o := newTrustTestOrchestrator()
	pointControlPlaneAt(t, o, srv)
	pool := x509.NewCertPool()
	pool.AddCert(other.caCert)
	o.cpCAPool = pool

	_, err := o.fetchControlPlaneSPKIPin(context.Background())
	if err == nil {
		t.Fatal("expected an error when cpCAPool does not trust the serving CA")
	}
	// The error comes from the TLS stack (x509: certificate signed by unknown
	// authority), not from application code.  Only assert that an error occurs.
}

func TestFetchControlPlaneSPKIPin_VerifiedCapture(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)

	o := newTrustTestOrchestrator()
	pointControlPlaneAt(t, o, srv)
	if _, err := o.fetchControlPlaneCABundle(context.Background()); err != nil {
		t.Fatalf("prerequisite bundle fetch: %v", err)
	}

	pin, err := o.fetchControlPlaneSPKIPin(context.Background())
	if err != nil {
		t.Fatalf("fetchControlPlaneSPKIPin: %v", err)
	}
	if pin != pki.spkiPinB {
		t.Errorf("pin = %s, want CA anchor pin %s", pin, pki.spkiPinB)
	}
}

func TestControlPlaneCAPool_FetchesAndCaches(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)

	o := newTrustTestOrchestrator()
	pointControlPlaneAt(t, o, srv)
	pool, err := o.ControlPlaneCAPool(context.Background())
	if err != nil {
		t.Fatalf("ControlPlaneCAPool: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}

	cached, err := o.ControlPlaneCAPool(context.Background())
	if err != nil {
		t.Fatalf("cached ControlPlaneCAPool: %v", err)
	}
	if cached != pool {
		t.Error("expected cached pool to be returned on second call")
	}
}

func TestControlPlaneCAPool_PropagatesFetchError(t *testing.T) {
	o := &Orchestrator{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		discovered: []DiscoveredNode{{NodeConfig: NodeConfig{Hostname: "w1", Role: RoleWorker}}},
	}
	if _, err := o.ControlPlaneCAPool(context.Background()); err == nil {
		t.Fatal("expected error when bundle fetch cannot run")
	}
}
