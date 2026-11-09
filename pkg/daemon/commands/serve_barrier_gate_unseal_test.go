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

package commands

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	apidaemon "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// lockedGateBarrier is a fakeGateBarrier that the gate's HTTP handlers
// and waitForUnseal can share: every method the two goroutines call takes
// the lock, and WaitReady blocks until Unseal (or an external unseal seen
// by SyncStatus) releases it.
type lockedGateBarrier struct {
	*fakeGateBarrier

	mu sync.Mutex
	// waiting is closed on the first WaitReady call. waitForUnseal calls
	// WaitReady only after the gate's listeners are bound.
	waiting     chan struct{}
	waitingOnce sync.Once
	// ready is closed when the barrier unseals.
	ready     chan struct{}
	readyOnce sync.Once
	// unsealOnSync makes SyncStatus report an unseal made on another node.
	unsealOnSync bool
}

func newLockedGateBarrier(initialized, sealed bool) *lockedGateBarrier {
	return &lockedGateBarrier{
		fakeGateBarrier: &fakeGateBarrier{initialized: initialized, sealed: sealed},
		waiting:         make(chan struct{}),
		ready:           make(chan struct{}),
	}
}

func (l *lockedGateBarrier) IsInitialized() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fakeGateBarrier.IsInitialized()
}

func (l *lockedGateBarrier) IsSealed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fakeGateBarrier.IsSealed()
}

func (l *lockedGateBarrier) IsUnsealing() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fakeGateBarrier.IsUnsealing()
}

func (l *lockedGateBarrier) Status(ctx context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fakeGateBarrier.Status(ctx)
}

func (l *lockedGateBarrier) Unseal(ctx context.Context, secret string) error {
	l.mu.Lock()
	err := l.fakeGateBarrier.Unseal(ctx, secret)
	l.mu.Unlock()
	if err == nil {
		l.readyOnce.Do(func() { close(l.ready) })
	}
	return err
}

func (l *lockedGateBarrier) SyncStatus(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.fakeGateBarrier.SyncStatus(ctx); err != nil {
		return err
	}
	if l.unsealOnSync {
		l.sealed = false
	}
	return nil
}

func (l *lockedGateBarrier) WaitReady(ctx context.Context) error {
	l.waitingOnce.Do(func() { close(l.waiting) })
	select {
	case <-l.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// unixHTTPClient sends HTTP requests over the gate's Unix socket.
func unixHTTPClient(socket string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
}

func unixRequest(t *testing.T, client *http.Client, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://gate"+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest %s %s: %v", method, path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s body: %v", method, path, err)
	}
	return resp.StatusCode, string(data)
}

// startGate runs serveUntilUnsealed in a goroutine on a Unix socket in a
// temp dir and an ephemeral loopback port. The returned channel carries
// its result.
func startGate(t *testing.T, ctx context.Context, gate *lockedGateBarrier, pollEvery time.Duration) (string, <-chan error) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "platformd.sock")
	cfg := barrierGateConfig{socketPath: socket, httpAddr: "127.0.0.1:0", pollEvery: pollEvery}
	state := &barrierStateProvider{barrier: gate}
	done := make(chan error, 1)
	go func() {
		done <- serveUntilUnsealed(ctx, logging.NewLogger(0, nil), cfg, gate, state, nil, gate)
	}()
	return socket, done
}

// waitGate returns serveUntilUnsealed's result, failing the test when it
// does not return within the deadline.
func waitGate(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilUnsealed did not return within 10s")
		return nil
	}
}

// waitBound blocks until waitForUnseal has started waiting, which happens
// only after the gate's listeners are bound.
func waitBound(t *testing.T, gate *lockedGateBarrier, done <-chan error) {
	t.Helper()
	select {
	case <-gate.waiting:
	case err := <-done:
		t.Fatalf("serveUntilUnsealed returned before waiting: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilUnsealed did not start waiting within 10s")
	}
}

func assertSocketRefuses(t *testing.T, socket string) {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err == nil {
		conn.Close()
		t.Fatalf("gate socket %s still accepts connections after release", socket)
	}
}

// The gate serves a sealed barrier until POST /unseal unseals it, then
// stops its listener and returns nil so the production transports bind.
func TestServeUntilUnsealed_ServesUntilUnsealThenReleases(t *testing.T) {
	gate := newLockedGateBarrier(true, true)
	// A poll interval far beyond the test keeps the release on the
	// manager's ready signal, not on SyncStatus.
	socket, done := startGate(t, context.Background(), gate, time.Hour)
	waitBound(t, gate, done)

	client := unixHTTPClient(socket)
	code, body := unixRequest(t, client, http.MethodGet, "/healthz", "")
	if code != http.StatusOK || !strings.Contains(body, `"state":"sealed"`) || !strings.Contains(body, `"ready":false`) {
		t.Fatalf("GET /healthz = %d %s, want 200 with state sealed and ready false", code, body)
	}
	// The daemon binds its production transports only after the gate
	// returns, so a sealed barrier must keep the gate holding.
	select {
	case err := <-done:
		t.Fatalf("serveUntilUnsealed returned while sealed: %v", err)
	default:
	}

	code, body = unixRequest(t, client, http.MethodPost, "/unseal", `{"secret":"unseal-key"}`)
	if code != http.StatusOK || !strings.Contains(body, `"sealed":false`) {
		t.Fatalf("POST /unseal = %d %s, want 200 with sealed false", code, body)
	}
	if gate.unsealSecret != "unseal-key" {
		t.Errorf("barrier unsealed with %q, want %q", gate.unsealSecret, "unseal-key")
	}

	if err := waitGate(t, done); err != nil {
		t.Fatalf("serveUntilUnsealed = %v, want nil after unseal", err)
	}
	assertSocketRefuses(t, socket)
}

// An uninitialized barrier is reported as such and keeps the gate up.
func TestServeUntilUnsealed_ReportsUninitialized(t *testing.T) {
	gate := newLockedGateBarrier(false, true)
	ctx, cancel := context.WithCancel(context.Background())
	socket, done := startGate(t, ctx, gate, time.Hour)
	waitBound(t, gate, done)

	code, body := unixRequest(t, unixHTTPClient(socket), http.MethodGet, "/healthz", "")
	if code != http.StatusOK || !strings.Contains(body, `"state":"uninitialized"`) || !strings.Contains(body, `"ready":false`) {
		t.Fatalf("GET /healthz = %d %s, want 200 with state uninitialized and ready false", code, body)
	}

	cancel()
	if err := waitGate(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("serveUntilUnsealed = %v, want context.Canceled", err)
	}
	assertSocketRefuses(t, socket)
}

// An unseal made on another node is seen through SyncStatus, after a
// failed sync is retried.
func TestServeUntilUnsealed_ReleasesOnExternalUnseal(t *testing.T) {
	gate := newLockedGateBarrier(true, true)
	gate.syncErr = errors.New("peer unreachable")
	socket, done := startGate(t, context.Background(), gate, 5*time.Millisecond)
	waitBound(t, gate, done)

	gate.mu.Lock()
	gate.syncErr = nil
	gate.unsealOnSync = true
	gate.mu.Unlock()

	if err := waitGate(t, done); err != nil {
		t.Fatalf("serveUntilUnsealed = %v, want nil after external unseal", err)
	}
	if gate.syncCalls < 1 {
		t.Errorf("SyncStatus called %d times, want at least 1", gate.syncCalls)
	}
	assertSocketRefuses(t, socket)
}

// An already unsealed barrier releases the gate at once, without waiting.
func TestServeUntilUnsealed_AlreadyUnsealedReturnsAtOnce(t *testing.T) {
	gate := newLockedGateBarrier(true, false)
	socket, done := startGate(t, context.Background(), gate, time.Hour)

	if err := waitGate(t, done); err != nil {
		t.Fatalf("serveUntilUnsealed = %v, want nil", err)
	}
	select {
	case <-gate.waiting:
		t.Error("WaitReady was called for an already unsealed barrier")
	default:
	}
	assertSocketRefuses(t, socket)
}

// A gate that cannot be built returns the server's error.
func TestServeUntilUnsealed_MissingLogger(t *testing.T) {
	gate := newLockedGateBarrier(true, true)
	cfg := barrierGateConfig{socketPath: filepath.Join(t.TempDir(), "platformd.sock"), httpAddr: "127.0.0.1:0"}
	err := serveUntilUnsealed(context.Background(), nil, cfg, gate, &barrierStateProvider{barrier: gate}, nil, gate)
	var want apidaemon.ErrInitOnlyMissingLogger
	if !errors.As(err, &want) {
		t.Fatalf("serveUntilUnsealed = %v, want ErrInitOnlyMissingLogger", err)
	}
}

// A gate whose socket cannot be bound returns the bind error.
func TestServeUntilUnsealed_BindFails(t *testing.T) {
	gate := newLockedGateBarrier(true, true)
	cfg := barrierGateConfig{socketPath: filepath.Join(t.TempDir(), "missing", "platformd.sock"), httpAddr: "127.0.0.1:0"}
	err := serveUntilUnsealed(context.Background(), logging.NewLogger(0, nil), cfg, gate, &barrierStateProvider{barrier: gate}, nil, gate)
	if err == nil {
		t.Fatal("serveUntilUnsealed = nil, want a bind error for a socket in a missing directory")
	}
}
