package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// TestStopShutdownErrorForcesClose verifies that Stop with an expired
// context reports the shutdown error and force-closes the server instead of
// leaking it.
func TestStopShutdownErrorForcesClose(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		if _, err := w.Write([]byte("late")); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
			// The proxy connection may already be force-closed; that error
			// is expected here.
			t.Logf("backend write after force-close: %v", err)
		}
	}))
	t.Cleanup(backend.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	e, _ := newPublicEngine(t, backend.URL)
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := e.Status().Listeners[0].BoundAddress
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := http.Get("http://" + addr + "/slow")
		if err != nil {
			// The force-close may sever the client connection; that is the
			// expected outcome of an expired-shutdown Stop.
			return
		}
		closeBody(t, resp)
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := e.Stop(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop err = %v, want wrapped context.Canceled", err)
	}
	var lerr *ListenerError
	if !errors.As(err, &lerr) {
		t.Fatalf("Stop err %T, want *ListenerError", err)
	}
	close(release)
	wg.Wait()
	// A second Stop must be a clean no-op.
	if err := e.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// TestServeLogsUnexpectedListenerError exercises the serve goroutine's
// non-graceful exit branch by closing the bound listener out from under the
// server.
func TestServeLogsUnexpectedListenerError(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	e.mu.Lock()
	ln := e.listeners[0].ln
	e.mu.Unlock()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	// Stop waits for the serve goroutine, which exits through the
	// unexpected-error branch because Accept fails on the closed listener.
	// Depending on whether Serve has already deregistered the listener,
	// Shutdown may legitimately report the already-closed listener.
	if err := e.Stop(context.Background()); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Stop: %v", err)
	}
}

// TestCloseListenersLogsCloseError exercises the cleanup path when a
// listener is already closed.
func TestCloseListenersLogsCloseError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	closeListeners([]*listenerRuntime{{cfg: ListenerConfig{ID: "x"}, ln: ln}}, testLogger())
}

// TestNewCompileError covers the compile failure branch of New: validation
// and fail-closed checks pass, but the trust resolver fails during
// transport construction.
func TestNewCompileError(t *testing.T) {
	resolveErr := errors.New("trust store sealed")
	cfg := publicConfig("https://10.0.0.1:8443")
	cfg.Pools[0].TLS.TrustClass = "internal"
	_, err := New(cfg, Deps{Trust: &fakeTrust{err: resolveErr}, Logger: testLogger()})
	if !errors.Is(err, resolveErr) {
		t.Fatalf("New err = %v, want wrapped %v", err, resolveErr)
	}
}

// TestReloadCompileErrorKeepsOldState covers the compile failure branch of
// Reload: the new config is valid and fail-closed checks pass, but pool
// compilation fails, leaving the running state untouched.
func TestReloadCompileErrorKeepsOldState(t *testing.T) {
	backend := okBackend(t)
	trust := &fakeTrust{cfg: &tls.Config{MinVersion: tls.VersionTLS13}}
	e, err := New(publicConfig(backend.URL), Deps{Trust: trust, Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	trust.err = errors.New("resolver now failing")
	next := publicConfig(backend.URL)
	next.Pools[0].TLS.TrustClass = "internal"
	if err := e.Reload(next); !errors.Is(err, trust.err) {
		t.Fatalf("Reload err = %v, want wrapped resolver error", err)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status after failed reload = %d, want 200", rec.Code)
	}
	if got := e.Status().ReloadCount; got != 0 {
		t.Fatalf("ReloadCount = %d, want 0", got)
	}
}

// TestCountingResponseWriterUnwrap pins the ResponseController integration
// point.
func TestCountingResponseWriterUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	var n atomic.Uint64
	cw := &countingResponseWriter{ResponseWriter: rec, bytes: &n}
	if cw.Unwrap() != http.ResponseWriter(rec) {
		t.Fatal("Unwrap must return the underlying writer")
	}
	written, err := cw.Write([]byte("abcd"))
	if err != nil || written != 4 {
		t.Fatalf("Write = %d, %v", written, err)
	}
	if n.Load() != 4 {
		t.Fatalf("counted bytes = %d, want 4", n.Load())
	}
}
