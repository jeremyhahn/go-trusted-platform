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

package nbd

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// serveInBackground runs Serve on a loopback listener and returns its
// address and the channel Serve's result arrives on.
func serveInBackground(t *testing.T, ctx context.Context, server *Server) (string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, ln) }()
	return ln.Addr().String(), result
}

func TestServe_CloseEndsOpenSessions(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	server := newTestServer(t, testConfig(t, bundle))
	addr, result := serveInBackground(t, t.Context(), server)

	c := attach(t, addr, bundle)
	c.request(cmdFlush, 0, 1, 0, 0, nil)
	if code := c.simpleReply(1); code != errNone {
		t.Fatalf("FLUSH error = %d", code)
	}

	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("Serve = %v, want nil on Close", err)
	}
	c.expectClosed()
	if err := server.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestServe_ContextCancelStopsTheServer(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	server := newTestServer(t, testConfig(t, bundle))
	ctx, cancel := context.WithCancel(t.Context())
	addr, result := serveInBackground(t, ctx, server)

	c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
	cancel()
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("Serve = %v, want nil on cancel", err)
	}
	c.expectClosed()
	if _, err := net.Dial("tcp", addr); err == nil {
		t.Fatal("the listener still accepts after shutdown")
	}
}

func TestServe_ListenerFailureIsReported(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	server := newTestServer(t, testConfig(t, bundle))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	var failed ErrServeFailed
	if err := server.Serve(t.Context(), ln); !errors.As(err, &failed) || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve = %v, want ErrServeFailed wrapping net.ErrClosed", err)
	}
}

func TestClose_WaitsForTheListenerAndTheAcceptLoop(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	server := newTestServer(t, testConfig(t, bundle))
	ln := newGatedListener()
	result := make(chan error, 1)
	go func() { result <- server.Serve(t.Context(), ln) }()
	awaitSignal(t, ln.accepting, "Serve never reached its accept loop")

	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	awaitSignal(t, ln.closing, "Close never closed the listener")
	awaitSignal(t, ln.acceptDone, "the accept loop never saw the listener close")
	select {
	case err := <-closed:
		t.Fatalf("Close returned (%v) while the listener was still closing", err)
	default:
	}

	close(ln.release)
	if err := awaitResult(t, closed); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("Serve = %v, want nil on Close", err)
	}
}

func TestServe_AfterCloseClosesTheListenerWithoutAccepting(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	server := newTestServer(t, testConfig(t, bundle))
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ln := newGatedListener()
	close(ln.release)

	if err := server.Serve(t.Context(), ln); err != nil {
		t.Fatalf("Serve after Close = %v, want nil", err)
	}
	select {
	case <-ln.closing:
	default:
		t.Fatal("Serve after Close left the listener open")
	}
	select {
	case <-ln.accepting:
		t.Fatal("Serve after Close accepted connections")
	default:
	}
}

// gatedListener is an in-memory net.Listener whose Close blocks until
// release is closed, so a test can hold the listener mid-close and see
// what its owner does meanwhile.
type gatedListener struct {
	accepting  chan struct{} // closed when Accept is first entered
	acceptDone chan struct{} // closed when Accept returns
	closing    chan struct{} // closed when Close is entered
	release    chan struct{} // Close returns once this is closed
	acceptOnce sync.Once
	closeOnce  sync.Once
}

func newGatedListener() *gatedListener {
	return &gatedListener{
		accepting:  make(chan struct{}),
		acceptDone: make(chan struct{}),
		closing:    make(chan struct{}),
		release:    make(chan struct{}),
	}
}

func (l *gatedListener) Accept() (net.Conn, error) {
	l.acceptOnce.Do(func() { close(l.accepting) })
	<-l.closing
	close(l.acceptDone)
	return nil, net.ErrClosed
}

func (l *gatedListener) Close() error {
	l.closeOnce.Do(func() { close(l.closing) })
	<-l.release
	return nil
}

func (l *gatedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func awaitSignal(t *testing.T, signal <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-signal:
	case <-untilDeadline(t):
		t.Fatal(failure)
	}
}

func TestNewServer_RejectsInvalidConfig(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	cfg := testConfig(t, bundle)
	cfg.Anchor = nil

	var invalid ErrInvalidConfig
	if _, err := NewServer(cfg); !errors.As(err, &invalid) || invalid.Field != "Anchor" {
		t.Fatalf("NewServer = %v, want ErrInvalidConfig for Anchor", err)
	}
}

func TestNewServer_AppliesDefaultsAndFoldsIdentities(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	cfg := testConfig(t, bundle)
	cfg.Identities = []string{"Node-01"}
	cfg.Logger = nil

	server := newTestServer(t, cfg)
	if server.handshakeTimeout != DefaultHandshakeTimeout {
		t.Fatalf("handshake timeout = %v", server.handshakeTimeout)
	}
	if server.logger == nil {
		t.Fatal("no default logger")
	}
	if _, ok := server.identities["node-01"]; !ok {
		t.Fatalf("identities = %v, want the lowercased hostname", server.identities)
	}
}
