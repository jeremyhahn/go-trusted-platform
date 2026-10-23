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

// fail_closed_test.go asserts the fail-closed transport contract (#32): a
// network transport whose TLS material is absent refuses to start with a
// typed error and binds no listener. The Unix-domain-socket transport is the
// single sanctioned non-TLS carve-out — it is filesystem-permission-scoped,
// not network-exposed.

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// sharedTestTLSCertificate generates one ephemeral self-signed server
// certificate per test binary (127.0.0.1 / localhost) for tests that need a
// transport to actually start under the fail-closed contract. The generation
// panic is acceptable in test-only code: it means crypto/rand is broken and
// nothing else in the binary would work either.
var sharedTestTLSCertificate = sync.OnceValue(func() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("test TLS certificate: key generation: " + err.Error())
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fail-closed-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic("test TLS certificate: create certificate: " + err.Error())
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
})

// testServerTLSCertificate returns the shared in-memory test certificate,
// suitable for Config.TLSCertificate.
func testServerTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	return sharedTestTLSCertificate()
}

// reservePort binds an ephemeral loopback port, records its address, and
// releases it so the test can assert nothing else binds it afterwards.
func reservePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

// assertNothingListening dials the address and requires the connection to be
// refused — the fail-closed contract's "no listener is bound" half.
func assertNothingListening(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("expected no listener on %s, but a connection succeeded", addr)
	}
}

func TestRESTServer_FailsClosedWithoutTLS(t *testing.T) {
	config := DefaultConfig()
	config.SkipIAMValidation = true // lifecycle test: the REST auth gate (#550) is not under test here
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = false
	config.RESTListenAddr = reservePort(t)
	// No TLSCertificate, no cert/key files: TLS material is absent.

	service, err := NewService(config)
	require.NoError(t, err)

	server, err := NewRESTServer(config, service, nil)
	require.NoError(t, err)

	err = server.Start()
	require.Error(t, err)
	var startFailed ErrRESTServerStartFailed
	assert.ErrorAs(t, err, &startFailed)
	assert.False(t, server.IsRunning())
	assertNothingListening(t, config.RESTListenAddr)
}

func TestRESTServer_StartsWithInMemoryTLS(t *testing.T) {
	cert := testServerTLSCertificate(t)

	config := DefaultConfig()
	config.SkipIAMValidation = true // lifecycle test: the REST auth gate (#550) is not under test here
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = false
	config.RESTListenAddr = "127.0.0.1:0"
	config.TLSCertificate = &cert

	service, err := NewService(config)
	require.NoError(t, err)

	server, err := NewRESTServer(config, service, nil)
	require.NoError(t, err)

	require.NoError(t, server.Start())
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(ctx)
	}()
	assert.True(t, server.IsRunning())
}

func TestDaemon_GRPCTCPFailsClosedWithoutTLS(t *testing.T) {
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCUDS = false
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = reservePort(t)
	// No TLSCertificate, no cert/key files: TLS material is absent.

	d, err := New(config)
	require.NoError(t, err)

	err = d.Start(context.Background())
	require.Error(t, err)
	var tlsFailed ErrTLSConfigFailed
	assert.ErrorAs(t, err, &tlsFailed)
	assertNothingListening(t, config.GRPCListenAddr)
}

func TestDaemon_GRPCTCPStartsWithInMemoryTLS(t *testing.T) {
	cert := testServerTLSCertificate(t)

	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCUDS = false
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"
	config.TLSCertificate = &cert

	d, err := New(config)
	require.NoError(t, err)

	require.NoError(t, d.Start(context.Background()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, d.Stop(ctx))
}

func TestDaemon_QUICFailsClosedWithoutTLS(t *testing.T) {
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = false
	config.EnableQUIC = true
	config.QUICConfig = nil // no TLS material of any kind
	config.QUICListenAddr = "127.0.0.1:0"

	// quic.NewServer refuses a config without TLS, and an enabled transport
	// that cannot be constructed fails New itself (#444): there is no daemon
	// to start without QUIC.
	d, err := New(config)
	require.Error(t, err)
	assert.Nil(t, d)
	var constructFailed ErrTransportConstructionFailed
	require.ErrorAs(t, err, &constructFailed)
	assert.Equal(t, transportQUIC, constructFailed.Transport)
	var invalidConfig quicwire.ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidConfig, "the cause must be the QUIC server's own refusal")
}

// TestDaemon_RESTStartFailureIsFatal asserts Daemon.Start propagates a REST
// transport start failure instead of degrading to a daemon without its
// advertised TLS surface.
func TestDaemon_RESTStartFailureIsFatal(t *testing.T) {
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = false
	config.EnableREST = true
	config.RESTListenAddr = reservePort(t)
	// TLS material absent: REST refuses to start, and that refusal must
	// fail Daemon.Start, not be logged and ignored.

	d, err := New(config)
	require.NoError(t, err)

	err = d.Start(context.Background())
	require.Error(t, err)
	var startFailed ErrRESTServerStartFailed
	assert.ErrorAs(t, err, &startFailed)
	assertNothingListening(t, config.RESTListenAddr)
}

// TestDaemon_UDSCarveOutStillStarts asserts the sanctioned carve-out: the
// gRPC Unix-domain-socket transport starts without TLS material.
func TestDaemon_UDSCarveOutStillStarts(t *testing.T) {
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = true
	config.GRPCSocketPath = t.TempDir() + "/platformd-test.sock"
	config.SocketPath = config.GRPCSocketPath

	d, err := New(config)
	require.NoError(t, err)

	require.NoError(t, d.Start(context.Background()))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.Stop(ctx)
	}()

	conn, err := net.DialTimeout("unix", config.GRPCSocketPath, time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}

// TestDaemon_GRPCTCPConfigMutationCannotRetrofitTLS asserts the credential
// decision is immutable at construction: adding TLS material to the config
// AFTER New cannot make a server that was built plaintext bindable.
func TestDaemon_GRPCTCPConfigMutationCannotRetrofitTLS(t *testing.T) {
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCUDS = false
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = reservePort(t)
	// TLS material absent at construction: New builds a plaintext server.

	d, err := New(config)
	require.NoError(t, err)

	// Mutating the shared config after construction must not help.
	cert := sharedTestTLSCertificate()
	config.TLSCertificate = &cert

	err = d.Start(context.Background())
	require.Error(t, err)
	var tlsFailed ErrTLSConfigFailed
	assert.ErrorAs(t, err, &tlsFailed)
	assertNothingListening(t, config.GRPCListenAddr)
}

// TestRESTServer_BindFailureIsSynchronous asserts a listener bind failure
// (address in use) surfaces as the typed startup error from Start itself,
// not as a log line from a goroutine after Start reported success.
func TestRESTServer_BindFailureIsSynchronous(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer blocker.Close()

	cert := sharedTestTLSCertificate()
	config := DefaultConfig()
	config.SkipIAMValidation = true // lifecycle test: the REST auth gate (#550) is not under test here
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = false
	config.RESTListenAddr = blocker.Addr().String()
	config.TLSCertificate = &cert

	service, err := NewService(config)
	require.NoError(t, err)

	server, err := NewRESTServer(config, service, nil)
	require.NoError(t, err)

	err = server.Start()
	require.Error(t, err)
	var startFailed ErrRESTServerStartFailed
	assert.ErrorAs(t, err, &startFailed)
	assert.False(t, server.IsRunning())
}

// stubGRPCServer is a minimal GRPCServerInterface double for the
// server-replacement test. Defined here rather than reusing the build-tagged
// coverage mocks so this file stays free of build constraints.
type stubGRPCServer struct{}

func (*stubGRPCServer) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {}
func (*stubGRPCServer) Serve(lis net.Listener) error                             { return nil }
func (*stubGRPCServer) GracefulStop()                                            {}
func (*stubGRPCServer) Stop()                                                    {}

// TestDaemon_GRPCTCPServerReplacementClearsTLSClaim asserts the second TOCTOU
// door is shut: TLS material present at New sets the credentials flag for the
// server New BUILT, and WithGRPCServer swapping in a server of unknown TLS
// state must clear that claim so Start refuses to bind it.
func TestDaemon_GRPCTCPServerReplacementClearsTLSClaim(t *testing.T) {
	cert := sharedTestTLSCertificate()

	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCUDS = false
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = reservePort(t)
	config.TLSCertificate = &cert // material present: New attaches creds

	d, err := New(config, WithGRPCServer(&stubGRPCServer{}))
	require.NoError(t, err)
	assert.False(t, d.grpcTLSCredsAttached)

	err = d.Start(context.Background())
	require.Error(t, err)
	var tlsFailed ErrTLSConfigFailed
	assert.ErrorAs(t, err, &tlsFailed)
	assertNothingListening(t, config.GRPCListenAddr)
}

// TestDaemon_QUICGetConfigForClientIsTLSMaterial asserts the preflight
// recognizes crypto/tls's third certificate-supplying mechanism: a config
// whose only material arrives through GetConfigForClient must pass the
// material check rather than being refused at startup.
func TestDaemon_QUICGetConfigForClientIsTLSMaterial(t *testing.T) {
	cert := sharedTestTLSCertificate()

	config := DefaultConfig()
	config.QUICConfig = &quic.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return &tls.Config{
					MinVersion:   tls.VersionTLS13,
					Certificates: []tls.Certificate{cert},
				}, nil
			},
		},
	}

	assert.True(t, config.quicTLSMaterialPresent(),
		"a GetConfigForClient-only tls.Config is valid dynamic material and must not be refused")

	// And the other two mechanisms plus the absent case stay correct.
	config.QUICConfig.TLSConfig = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &cert, nil
	}}
	assert.True(t, config.quicTLSMaterialPresent())
	config.QUICConfig.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	assert.True(t, config.quicTLSMaterialPresent())
	config.QUICConfig.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	assert.False(t, config.quicTLSMaterialPresent())
}

// stubRESTServer is a minimal RESTServerInterface double whose TLS
// attestation is controlled by the test.
type stubRESTServer struct {
	servesTLS bool
	running   bool
}

func (s *stubRESTServer) Start() error                   { s.running = true; return nil }
func (s *stubRESTServer) Stop(ctx context.Context) error { s.running = false; return nil }
func (s *stubRESTServer) ForceStop() error               { s.running = false; return nil }
func (s *stubRESTServer) IsRunning() bool                { return s.running }
func (s *stubRESTServer) ServesTLS() bool                { return s.servesTLS }

// TestDaemon_ReplacementRESTServerMustAttestTLS asserts the WithRESTServer
// door is shut: an injected server of unknown TLS state is refused, and one
// that attests TLS via TLSAttestor starts.
func TestDaemon_ReplacementRESTServerMustAttestTLS(t *testing.T) {
	newDaemon := func(t *testing.T, server RESTServerInterface) *Daemon {
		t.Helper()
		cert := sharedTestTLSCertificate()
		config := DefaultConfig()
		config.SkipIAMValidation = true
		config.EnableGRPCTCP = false
		config.EnableGRPCUDS = false
		config.EnableREST = true
		config.RESTListenAddr = "127.0.0.1:0"
		config.TLSCertificate = &cert // material present — must not matter

		d, err := New(config, WithRESTServer(server))
		require.NoError(t, err)
		return d
	}

	t.Run("unattested replacement is refused", func(t *testing.T) {
		d := newDaemon(t, &stubRESTServer{servesTLS: false})
		err := d.Start(context.Background())
		require.Error(t, err)
		var startFailed ErrRESTServerStartFailed
		assert.ErrorAs(t, err, &startFailed)
	})

	t.Run("attested replacement starts", func(t *testing.T) {
		d := newDaemon(t, &stubRESTServer{servesTLS: true})
		require.NoError(t, d.Start(context.Background()))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.Stop(ctx)
	})
}

// tlsAttestingGRPCServer is stubGRPCServer plus a positive TLS attestation.
type tlsAttestingGRPCServer struct{ stubGRPCServer }

func (*tlsAttestingGRPCServer) ServesTLS() bool { return true }

// TestDaemon_ReplacementGRPCServerMayAttestTLS asserts the gRPC replacement
// contract: an attesting replacement binds, a non-attesting one stays
// refused (the latter is asserted by
// TestDaemon_GRPCTCPServerReplacementClearsTLSClaim).
func TestDaemon_ReplacementGRPCServerMayAttestTLS(t *testing.T) {
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCUDS = false
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"

	d, err := New(config, WithGRPCServer(&tlsAttestingGRPCServer{}))
	require.NoError(t, err)

	require.NoError(t, d.Start(context.Background()))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = d.Stop(ctx)
}

// stickyRESTServer attests TLS but records Start calls and refuses to stop —
// the hazard case for refusal-after-start: if the daemon started it before a
// later TLS refusal, it would remain serving behind a startup error.
type stickyRESTServer struct {
	startCalls int
	running    bool
}

func (s *stickyRESTServer) Start() error { s.startCalls++; s.running = true; return nil }
func (s *stickyRESTServer) Stop(ctx context.Context) error {
	return ErrRESTServerStopFailed{Reason: "sticky"}
}
func (s *stickyRESTServer) ForceStop() error { return ErrRESTServerStopFailed{Reason: "sticky"} }
func (s *stickyRESTServer) IsRunning() bool  { return s.running }
func (s *stickyRESTServer) ServesTLS() bool  { return true }

// TestDaemon_TLSRefusalStartsNothing asserts the preflight ordering contract
// (#32): a TLS refusal is decided before any transport starts, so a refusal
// never depends on rolling back a live listener — not even one whose stop
// operation fails.
func TestDaemon_TLSRefusalStartsNothing(t *testing.T) {
	rest := &stickyRESTServer{}

	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableGRPCUDS = false
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = reservePort(t)
	// No TLS material: the gRPC preflight must refuse startup.

	d, err := New(config, WithRESTServer(rest))
	require.NoError(t, err)

	err = d.Start(context.Background())
	require.Error(t, err)
	var tlsFailed ErrTLSConfigFailed
	assert.ErrorAs(t, err, &tlsFailed)

	assert.Zero(t, rest.startCalls,
		"the REST server must never start when a later transport's TLS preflight refuses")
	assert.False(t, rest.IsRunning())
	assertNothingListening(t, config.GRPCListenAddr)
}

// TestDaemon_NilReplacementServersAreRefused asserts a nil replacement for an
// enabled transport fails startup rather than silently omitting it.
func TestDaemon_NilReplacementServersAreRefused(t *testing.T) {
	cert := sharedTestTLSCertificate()

	t.Run("nil REST replacement with EnableREST", func(t *testing.T) {
		config := DefaultConfig()
		config.SkipIAMValidation = true
		config.EnableGRPCTCP = false
		config.EnableGRPCUDS = false
		config.EnableREST = true
		config.RESTListenAddr = "127.0.0.1:0"
		config.TLSCertificate = &cert

		d, err := New(config, WithRESTServer(nil))
		require.NoError(t, err)

		err = d.Start(context.Background())
		require.Error(t, err)
		var restFailed ErrRESTServerStartFailed
		assert.ErrorAs(t, err, &restFailed)
	})

	t.Run("nil gRPC replacement with EnableGRPCTCP", func(t *testing.T) {
		config := DefaultConfig()
		config.SkipIAMValidation = true
		config.EnableREST = false
		config.EnableGRPCUDS = false
		config.EnableGRPCTCP = true
		config.GRPCListenAddr = reservePort(t)
		config.TLSCertificate = &cert

		d, err := New(config, WithGRPCServer(nil))
		require.NoError(t, err)

		err = d.Start(context.Background())
		require.Error(t, err)
		var tlsFailed ErrTLSConfigFailed
		assert.ErrorAs(t, err, &tlsFailed)
		assertNothingListening(t, config.GRPCListenAddr)
	})
}

// TestDaemon_StartFailureRollsBackStartedComponents asserts a fatal startup
// failure AFTER earlier components started rolls them back even though
// d.running is still false (Stop/ForceStop are unusable then): an attested
// replacement REST server starts, the gRPC TCP bind fails on an occupied
// port, and the rollback must force-stop the REST server.
func TestDaemon_StartFailureRollsBackStartedComponents(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer blocker.Close()

	cert := sharedTestTLSCertificate()
	rest := &stubRESTServer{servesTLS: true}

	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableGRPCUDS = false
	config.EnableREST = true
	config.RESTListenAddr = "127.0.0.1:0"
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = blocker.Addr().String() // bind will fail
	config.TLSCertificate = &cert

	d, err := New(config, WithRESTServer(rest))
	require.NoError(t, err)

	err = d.Start(context.Background())
	require.Error(t, err)
	assert.False(t, rest.IsRunning(),
		"the REST server started before the gRPC bind failure must be rolled back")
}

// TestDaemon_TransientFailureRetrySucceeds asserts the rollback does not
// poison unstarted gRPC servers: after a transient gRPC TCP bind failure
// (port occupied) is cleared, a retry on the same Daemon starts fully and
// the gRPC listener genuinely serves.
func TestDaemon_TransientFailureRetrySucceeds(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := blocker.Addr().String()

	cert := sharedTestTLSCertificate()
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCUDS = false
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = addr
	config.TLSCertificate = &cert

	d, err := New(config)
	require.NoError(t, err)

	// First attempt fails on the occupied port; the rollback must NOT stop
	// the never-served gRPC server.
	require.Error(t, d.Start(context.Background()))

	require.NoError(t, blocker.Close())
	require.NoError(t, d.Start(context.Background()),
		"retry after a transient bind failure must succeed with an unpoisoned gRPC server")

	// The listener must genuinely accept connections.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = d.Stop(ctx)
}

// TestDaemon_RetryAfterServedGRPCIsRefused asserts the other half of the
// contract: when the rollback had to stop a gRPC server that HAD served
// (UDS bind failure after the TCP listener was up), a retry on the same
// Daemon is refused with the typed error instead of reporting success with
// a permanently stopped transport.
func TestDaemon_RetryAfterServedGRPCIsRefused(t *testing.T) {
	cert := sharedTestTLSCertificate()
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"
	config.EnableGRPCUDS = true
	config.GRPCSocketPath = t.TempDir() + "/missing-dir/uds.sock" // bind fails
	config.SocketPath = config.GRPCSocketPath
	config.TLSCertificate = &cert

	d, err := New(config)
	require.NoError(t, err)

	// gRPC TCP serves, then the UDS bind fails and rollback stops it.
	require.Error(t, d.Start(context.Background()))

	err = d.Start(context.Background())
	require.Error(t, err)
	var retryUnsafe ErrDaemonRetryUnsafe
	assert.ErrorAs(t, err, &retryUnsafe)
}

// partialQUICServer attests TLS and simulates a QUIC Start that acquires
// resources (reports running) before returning an error.
type partialQUICServer struct {
	running    bool
	stopCalled bool
}

func (s *partialQUICServer) Start() error {
	s.running = true
	return ErrQUICServerStartFailed{Cause: ErrTLSConfigFailed{Reason: "simulated partial start"}}
}
func (s *partialQUICServer) Stop() error                        { s.stopCalled = true; s.running = false; return nil }
func (s *partialQUICServer) IsRunning() bool                    { return s.running }
func (s *partialQUICServer) ListenAddr() string                 { return "127.0.0.1:0" }
func (s *partialQUICServer) GetMetrics() map[string]interface{} { return nil }
func (s *partialQUICServer) Stats() *quic.ServerStats           { return nil }
func (s *partialQUICServer) ServesTLS() bool                    { return true }

// TestDaemon_PartiallyStartedQUICIsRolledBack asserts a QUIC Start that
// acquired resources before failing is stopped by the rollback rather than
// left reachable behind a startup error.
func TestDaemon_PartiallyStartedQUICIsRolledBack(t *testing.T) {
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = false
	config.EnableQUIC = true
	config.QUICListenAddr = "127.0.0.1:0"

	quicStub := &partialQUICServer{}
	d, err := New(config, WithQUICServer(quicStub))
	require.NoError(t, err)

	err = d.Start(context.Background())
	require.Error(t, err)
	var quicFailed ErrQUICServerStartFailed
	assert.ErrorAs(t, err, &quicFailed)

	assert.True(t, quicStub.stopCalled, "rollback must stop the partially started QUIC server")
	assert.False(t, quicStub.IsRunning())
}

// TestDaemon_EmptyInMemoryCertificateIsNotMaterial asserts a structurally
// unusable &tls.Certificate{} — no chain, no key — is treated as absent
// material: the daemon must refuse startup rather than bind listeners whose
// every TLS handshake would fail.
func TestDaemon_EmptyInMemoryCertificateIsNotMaterial(t *testing.T) {
	t.Run("gRPC refuses at preflight", func(t *testing.T) {
		config := DefaultConfig()
		config.SkipIAMValidation = true // lifecycle test: the REST auth gate (#550) is not under test here
		config.SkipIAMValidation = true
		config.EnableREST = false
		config.EnableGRPCUDS = false
		config.EnableGRPCTCP = true
		config.GRPCListenAddr = reservePort(t)
		config.TLSCertificate = &tls.Certificate{} // structurally unusable

		d, err := New(config)
		require.NoError(t, err)

		err = d.Start(context.Background())
		require.Error(t, err)
		var tlsFailed ErrTLSConfigFailed
		assert.ErrorAs(t, err, &tlsFailed)
		assertNothingListening(t, config.GRPCListenAddr)
	})

	t.Run("REST refuses at bind time", func(t *testing.T) {
		config := DefaultConfig()
		config.SkipIAMValidation = true // lifecycle test: the REST auth gate (#550) is not under test here
		config.EnableGRPCTCP = false
		config.EnableGRPCUDS = false
		config.RESTListenAddr = reservePort(t)
		config.TLSCertificate = &tls.Certificate{}

		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, nil)
		require.NoError(t, err)

		err = server.Start()
		require.Error(t, err)
		var startFailed ErrRESTServerStartFailed
		assert.ErrorAs(t, err, &startFailed)
		assertNothingListening(t, config.RESTListenAddr)
	})
}

// TestDaemon_QUICEmptyCertificateIsNotMaterial extends the empty-certificate
// boundary to QUIC: a Certificates slice holding only a structurally empty
// entry is not material, and startup must refuse with the typed error.
func TestDaemon_QUICEmptyCertificateIsNotMaterial(t *testing.T) {
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = false
	config.EnableQUIC = true
	config.QUICListenAddr = "127.0.0.1:0"
	config.QUICConfig = &quic.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{{}}, // structurally unusable
		},
	}

	d, err := New(config)
	require.NoError(t, err)

	err = d.Start(context.Background())
	require.Error(t, err)
	var quicFailed ErrQUICServerStartFailed
	assert.ErrorAs(t, err, &quicFailed)
}

// TestDaemon_UnusableInMemoryCertFallsBackToFiles asserts the selection
// preference matches the material predicate: with a structurally empty
// in-memory certificate AND a valid cert/key file pair, the file pair is
// loaded and a real gRPC TLS handshake succeeds.
func TestDaemon_UnusableInMemoryCertFallsBackToFiles(t *testing.T) {
	cert := sharedTestTLSCertificate()

	dir := t.TempDir()
	certPath := dir + "/server.pem"
	keyPath := dir + "/server.key"
	require.NoError(t, os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600))
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600))

	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCUDS = false
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = reservePort(t)
	config.TLSCertificate = &tls.Certificate{} // unusable — must NOT be selected
	config.GRPCTLSCertFile = certPath
	config.GRPCTLSKeyFile = keyPath

	d, err := New(config)
	require.NoError(t, err)

	require.NoError(t, d.Start(context.Background()))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.Stop(ctx)
	}()

	// A real, VERIFIED TLS handshake must complete against the file-pair
	// identity (the self-signed test certificate is its own trust root).
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp",
		config.GRPCListenAddr, &tls.Config{RootCAs: roots, NextProtos: []string{"h2"}})
	require.NoError(t, err, "TLS handshake must succeed against the file-pair certificate")
	require.NoError(t, conn.Close())
}
