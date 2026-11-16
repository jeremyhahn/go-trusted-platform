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

package quicagent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
)

// testServerName is the DNS SAN on the agent's test certificate and the
// ServerName the client verifies against.
const testServerName = "deploy-agent"

// testCA is an in-memory certificate authority for the tests: the agent's
// server certificate and the deployer's client certificate are both issued
// from it. Certificate issuance from the platform CA is out of scope.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

func (ca *testCA) issue(t *testing.T, cn string, usage x509.ExtKeyUsage, dnsNames ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startAgent runs a Server on a loopback UDP socket, trusting clientCA for
// client certificates, and returns its address.
func startAgent(t *testing.T, serverCA, clientCA *testCA) string {
	t.Helper()
	srv, err := NewServer(&tls.Config{
		Certificates: []tls.Certificate{serverCA.issue(t, testServerName, x509.ExtKeyUsageServerAuth, testServerName)},
		ClientCAs:    clientCA.pool,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, pc) }()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		<-done
		_ = pc.Close()
	})
	return pc.LocalAddr().String()
}

// newTestClient returns a Client for addr holding a client certificate
// issued by clientCA and trusting serverCA for the agent.
func newTestClient(t *testing.T, addr string, serverCA, clientCA *testCA) *Client {
	t.Helper()
	c, err := NewClient(addr, &tls.Config{
		Certificates: []tls.Certificate{clientCA.issue(t, "deployer", x509.ExtKeyUsageClientAuth)},
		RootCAs:      serverCA.pool,
		ServerName:   testServerName,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// connectedPair starts an agent and returns a connected client.
func connectedPair(t *testing.T) *Client {
	t.Helper()
	ca := newTestCA(t, "test-ca")
	addr := startAgent(t, ca, ca)
	c := newTestClient(t, addr, ca, ca)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !c.IsConnected() {
		t.Fatalf("IsConnected() = false after Connect")
	}
	return c
}

// idleAddr is a loopback UDP address nothing is expected to listen on; the
// tests that use it never dial.
func idleAddr() string {
	return (&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}).String()
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestClientImplementsRemoteHost(t *testing.T) {
	var _ deployer.RemoteHost = (*Client)(nil)
}

func TestRunReturnsOutput(t *testing.T) {
	c := connectedPair(t)
	out, err := c.Run(testCtx(t), "printf 'hello from the agent'")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out != "hello from the agent" {
		t.Fatalf("Run output = %q, want %q", out, "hello from the agent")
	}
}

func TestRunReportsExitStatus(t *testing.T) {
	c := connectedPair(t)
	out, err := c.Run(testCtx(t), "echo broken >&2; exit 3")
	var cmdErr ErrCommand
	if !errors.As(err, &cmdErr) {
		t.Fatalf("Run error = %v, want ErrCommand", err)
	}
	if cmdErr.ExitCode != 3 {
		t.Fatalf("ExitCode = %d, want 3", cmdErr.ExitCode)
	}
	if out != "broken\n" || cmdErr.Output != "broken\n" {
		t.Fatalf("output = %q (error output %q), want the stderr text", out, cmdErr.Output)
	}
}

func TestCopyFileStreamDigestMatches(t *testing.T) {
	c := connectedPair(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "image.iso")
	payload := make([]byte, 3<<20+17)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	dst := filepath.Join(dir, "remote", "staged.iso")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := c.CopyFileStream(testCtx(t), src, dst); err != nil {
		t.Fatalf("CopyFileStream: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read copy: %v", err)
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatalf("sha256 of the copy does not match the source")
	}
}

func TestCopyFileStreamMissingSource(t *testing.T) {
	c := connectedPair(t)
	err := c.CopyFileStream(testCtx(t), filepath.Join(t.TempDir(), "absent"), filepath.Join(t.TempDir(), "dst"))
	var readErr deployer.ErrFileRead
	if !errors.As(err, &readErr) {
		t.Fatalf("CopyFileStream error = %v, want deployer.ErrFileRead", err)
	}
}

func TestStatRemote(t *testing.T) {
	c := connectedPair(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	if err := os.WriteFile(p, []byte("twelve bytes"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	mtime := time.Unix(1700000000, 0)
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	size, gotMtime, err := c.StatRemote(testCtx(t), p)
	if err != nil {
		t.Fatalf("StatRemote: %v", err)
	}
	if size != 12 || gotMtime != mtime.Unix() {
		t.Fatalf("StatRemote = (%d, %d), want (12, %d)", size, gotMtime, mtime.Unix())
	}

	_, _, err = c.StatRemote(testCtx(t), filepath.Join(dir, "absent"))
	var notFound deployer.ErrRemoteFileNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("StatRemote(absent) error = %v, want deployer.ErrRemoteFileNotFound", err)
	}
}

func TestOperationsBeforeConnect(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	c := newTestClient(t, idleAddr(), ca, ca)
	_, err := c.Run(testCtx(t), "true")
	var notConnected ErrNotConnected
	if !errors.As(err, &notConnected) {
		t.Fatalf("Run before Connect error = %v, want ErrNotConnected", err)
	}
}

func TestRefusedClientCertificate(t *testing.T) {
	serverCA := newTestCA(t, "agent-ca")
	trustedClientCA := newTestCA(t, "deployer-ca")
	rogueCA := newTestCA(t, "rogue-ca")
	addr := startAgent(t, serverCA, trustedClientCA)

	c := newTestClient(t, addr, serverCA, rogueCA)
	marker := filepath.Join(t.TempDir(), "ran")
	ctx := testCtx(t)
	err := c.Connect(ctx)
	if err == nil {
		// TLS 1.3 lets the client finish its handshake before the server
		// has checked the client certificate; the refusal then arrives on
		// the first operation.
		_, err = c.Run(ctx, "touch '"+marker+"'")
	}
	if err == nil {
		t.Fatalf("a client certificate from an untrusted CA was accepted")
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the agent ran a command for a refused client (stat: %v)", statErr)
	}
}

func TestNewClientRequiresClientCertificate(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	_, err := NewClient(idleAddr(), &tls.Config{RootCAs: ca.pool, ServerName: testServerName})
	var cfgErr ErrInvalidTLSConfig
	if !errors.As(err, &cfgErr) {
		t.Fatalf("NewClient without a certificate error = %v, want ErrInvalidTLSConfig", err)
	}
}

func TestNewServerRequiresClientCAs(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	_, err := NewServer(&tls.Config{
		Certificates: []tls.Certificate{ca.issue(t, testServerName, x509.ExtKeyUsageServerAuth, testServerName)},
	}, nil)
	var cfgErr ErrInvalidTLSConfig
	if !errors.As(err, &cfgErr) {
		t.Fatalf("NewServer without ClientCAs error = %v, want ErrInvalidTLSConfig", err)
	}
}
