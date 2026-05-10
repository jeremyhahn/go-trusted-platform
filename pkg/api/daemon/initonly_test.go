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

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// =============================================================================
// Fakes
// =============================================================================

type fakeStateProvider struct {
	state atomic.Value
}

func newFakeStateProvider(s rest.PlatformState) *fakeStateProvider {
	p := &fakeStateProvider{}
	p.state.Store(s)
	return p
}

func (p *fakeStateProvider) State(_ context.Context) rest.PlatformState {
	v, _ := p.state.Load().(rest.PlatformState)
	return v
}

type fakeInit struct {
	called atomic.Int32
	resp   *rest.BarrierInitResponse
	err    error
}

func (s *fakeInit) Initialize(_ context.Context, _ *rest.BarrierInitRequest) (*rest.BarrierInitResponse, error) {
	s.called.Add(1)
	return s.resp, s.err
}

type fakeUnseal struct {
	called atomic.Int32
	resp   *rest.BarrierUnsealResponse
	err    error
}

func (s *fakeUnseal) Unseal(_ context.Context, _ *rest.BarrierUnsealRequest) (*rest.BarrierUnsealResponse, error) {
	s.called.Add(1)
	return s.resp, s.err
}

// =============================================================================
// Helpers
// =============================================================================

func newTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	return logging.DefaultLogger()
}

// freeLoopbackAddr returns a "127.0.0.1:N" address with N currently free.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func startInitOnly(t *testing.T, cfg InitOnlyConfig) *InitOnlyServer {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = newTestLogger(t)
	}
	if cfg.HTTPListenAddr == "" {
		cfg.HTTPListenAddr = freeLoopbackAddr(t)
	}
	srv, err := NewInitOnlyServer(cfg)
	if err != nil {
		t.Fatalf("NewInitOnlyServer: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Stop(context.Background())
	})
	return srv
}

func httpGet(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func httpPost(t *testing.T, url, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// =============================================================================
// Tests
// =============================================================================

func TestInitOnlyServer_RequiresState(t *testing.T) {
	_, err := NewInitOnlyServer(InitOnlyConfig{Logger: newTestLogger(t)})
	if err == nil {
		t.Fatal("expected error when State is nil")
	}
	if _, ok := err.(ErrInitOnlyMissingState); !ok {
		t.Errorf("expected ErrInitOnlyMissingState, got %T", err)
	}
}

func TestInitOnlyServer_RequiresLogger(t *testing.T) {
	_, err := NewInitOnlyServer(InitOnlyConfig{State: newFakeStateProvider(rest.PlatformStateUninitialized)})
	if err == nil {
		t.Fatal("expected error when Logger is nil")
	}
}

func TestInitOnlyServer_HealthzReachableOnHTTP(t *testing.T) {
	state := newFakeStateProvider(rest.PlatformStateUninitialized)
	socket := filepath.Join(t.TempDir(), "platformd.sock")
	srv := startInitOnly(t, InitOnlyConfig{
		SocketPath: socket,
		State:      state,
	})
	code, body := httpGet(t, "http://"+srv.HTTPListenAddr()+"/healthz")
	if code != http.StatusOK {
		t.Fatalf("/healthz: expected 200, got %d", code)
	}
	var hb rest.BarrierHealthResponse
	if err := json.Unmarshal(body, &hb); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hb.State != rest.PlatformStateUninitialized {
		t.Errorf("state: got %q want uninitialized", hb.State)
	}
	if hb.Ready {
		t.Error("expected not ready")
	}
}

func TestInitOnlyServer_InitDelegatesToBackend(t *testing.T) {
	state := newFakeStateProvider(rest.PlatformStateUninitialized)
	init := &fakeInit{resp: &rest.BarrierInitResponse{CeremonyID: "c-1"}}
	socket := filepath.Join(t.TempDir(), "platformd.sock")
	srv := startInitOnly(t, InitOnlyConfig{
		SocketPath: socket,
		State:      state,
		Init:       init,
	})
	code, body := httpPost(t, "http://"+srv.HTTPListenAddr()+"/init", `{"so_pin":"X","user_pin":"Y"}`)
	if code != http.StatusOK {
		t.Fatalf("/init: expected 200, got %d (body=%s)", code, body)
	}
	if init.called.Load() != 1 {
		t.Fatalf("init not called")
	}
}

func TestInitOnlyServer_UnsealRejectedWhenUninitialized(t *testing.T) {
	state := newFakeStateProvider(rest.PlatformStateUninitialized)
	socket := filepath.Join(t.TempDir(), "platformd.sock")
	srv := startInitOnly(t, InitOnlyConfig{
		SocketPath: socket,
		State:      state,
		Unseal:     &fakeUnseal{},
	})
	code, _ := httpPost(t, "http://"+srv.HTTPListenAddr()+"/unseal", `{"secret":"k"}`)
	if code != http.StatusConflict {
		t.Fatalf("/unseal: expected 409, got %d", code)
	}
}

func TestInitOnlyServer_OnlyMinimalRoutesBound(t *testing.T) {
	state := newFakeStateProvider(rest.PlatformStateUninitialized)
	socket := filepath.Join(t.TempDir(), "platformd.sock")
	srv := startInitOnly(t, InitOnlyConfig{
		SocketPath: socket,
		State:      state,
	})
	// Only /healthz, /init, /unseal are registered. Anything else
	// returns 404 because we use a plain ServeMux.
	cases := []string{"/grpc", "/api/v1/dns", "/cluster", "/random"}
	for _, p := range cases {
		code, _ := httpGet(t, "http://"+srv.HTTPListenAddr()+p)
		if code != http.StatusNotFound {
			t.Errorf("%s: expected 404, got %d", p, code)
		}
	}
}

func TestInitOnlyServer_ServesUnixSocket(t *testing.T) {
	state := newFakeStateProvider(rest.PlatformStateSealed)
	socket := filepath.Join(t.TempDir(), "platformd.sock")
	srv := startInitOnly(t, InitOnlyConfig{
		SocketPath: socket,
		State:      state,
	})
	if srv.SocketPath() != socket {
		t.Errorf("socket path: got %q want %q", srv.SocketPath(), socket)
	}

	// Direct dial of the Unix socket and issue an HTTP/1.1 GET on /healthz.
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatalf("dial unix %s: %v", socket, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	req := "GET /healthz HTTP/1.1\r\nHost: platformd\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	text := string(out)
	if !strings.Contains(text, "200 OK") {
		t.Errorf("unix /healthz response missing 200 OK: %q", text)
	}
	if !strings.Contains(text, "\"sealed\"") {
		t.Errorf("unix /healthz response missing state: %q", text)
	}
}

func TestInitOnlyServer_DoubleStartReturnsError(t *testing.T) {
	state := newFakeStateProvider(rest.PlatformStateUninitialized)
	socket := filepath.Join(t.TempDir(), "platformd.sock")
	srv := startInitOnly(t, InitOnlyConfig{
		SocketPath: socket,
		State:      state,
	})
	if err := srv.Start(context.Background()); err == nil {
		t.Fatal("expected error on double Start")
	} else if _, ok := err.(ErrInitOnlyAlreadyRunning); !ok {
		t.Errorf("expected ErrInitOnlyAlreadyRunning, got %T", err)
	}
}

func TestInitOnlyServer_StopWithoutStart(t *testing.T) {
	srv, err := NewInitOnlyServer(InitOnlyConfig{
		State:      newFakeStateProvider(rest.PlatformStateUninitialized),
		SocketPath: filepath.Join(t.TempDir(), "platformd.sock"),
		Logger:     newTestLogger(t),
	})
	if err != nil {
		t.Fatalf("NewInitOnlyServer: %v", err)
	}
	if err := srv.Stop(context.Background()); err == nil {
		t.Fatal("expected error stopping non-running server")
	} else if _, ok := err.(ErrInitOnlyNotRunning); !ok {
		t.Errorf("expected ErrInitOnlyNotRunning, got %T", err)
	}
}

func TestInitOnlyServer_StopAfterStart(t *testing.T) {
	state := newFakeStateProvider(rest.PlatformStateUninitialized)
	socket := filepath.Join(t.TempDir(), "platformd.sock")
	srv, err := NewInitOnlyServer(InitOnlyConfig{
		State:      state,
		SocketPath: socket,
		Logger:     newTestLogger(t),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !srv.IsRunning() {
		t.Error("expected IsRunning=true after Start")
	}
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if srv.IsRunning() {
		t.Error("expected IsRunning=false after Stop")
	}
}

func TestErrInitOnlyListenerFailed_Error(t *testing.T) {
	e := &ErrInitOnlyListenerFailed{Address: "127.0.0.1:1", Cause: errors.New("nope")}
	if !strings.Contains(e.Error(), "127.0.0.1:1") {
		t.Errorf("error should include address: %q", e.Error())
	}
	if !errors.Is(e, e.Cause) {
		// Unwrap should yield the cause.
		if got := e.Unwrap(); got == nil || got.Error() != "nope" {
			t.Errorf("Unwrap should return cause, got %v", got)
		}
	}
}

func TestInitOnlyConfig_Defaults(t *testing.T) {
	srv, err := NewInitOnlyServer(InitOnlyConfig{
		State:  newFakeStateProvider(rest.PlatformStateUninitialized),
		Logger: newTestLogger(t),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if srv.cfg.SocketPath == "" {
		t.Error("SocketPath default must be non-empty")
	}
	if srv.cfg.HTTPListenAddr == "" {
		t.Error("HTTPListenAddr default must be non-empty")
	}
	if srv.cfg.SocketMode == 0 {
		t.Error("SocketMode default must be non-zero")
	}
	if srv.cfg.ShutdownTimeout <= 0 {
		t.Error("ShutdownTimeout default must be positive")
	}
}
