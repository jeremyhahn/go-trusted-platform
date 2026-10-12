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

// initonly.go implements the platformd "init-only" listener mode used when
// the barrier is uninitialized or sealed. Per docs/08-bootstrap-auth-architecture.md
// §7 and §8 #6, the daemon must NOT bind remote transports (gRPC TCP, full
// REST, QUIC, MCP) before the barrier is unsealed. Only the Unix socket
// (for local platformctl) and a minimal loopback HTTP endpoint (for
// /healthz, /init, /unseal) are exposed.

package daemon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// =============================================================================
// Typed errors
// =============================================================================

// ErrInitOnlyAlreadyRunning is returned when Start is called on an already
// running InitOnlyServer.
type ErrInitOnlyAlreadyRunning struct{}

// Error returns a human-readable description of the error.
func (ErrInitOnlyAlreadyRunning) Error() string {
	return "init-only server already running"
}

// ErrInitOnlyNotRunning is returned when Stop is called on a server that
// has not been started.
type ErrInitOnlyNotRunning struct{}

// Error returns a human-readable description of the error.
func (ErrInitOnlyNotRunning) Error() string {
	return "init-only server not running"
}

// ErrInitOnlyMissingState is returned when InitOnlyConfig.State is nil.
type ErrInitOnlyMissingState struct{}

// Error returns a human-readable description of the error.
func (ErrInitOnlyMissingState) Error() string {
	return "init-only server requires a StateProvider"
}

// ErrInitOnlyMissingLogger is returned when InitOnlyConfig.Logger is nil.
type ErrInitOnlyMissingLogger struct{}

// Error returns a human-readable description of the error.
func (ErrInitOnlyMissingLogger) Error() string {
	return "init-only server requires a logger"
}

// ErrInitOnlyListenerFailed wraps a listener bind failure.
type ErrInitOnlyListenerFailed struct {
	Address string
	Cause   error
}

// Error returns a human-readable description of the error.
func (e *ErrInitOnlyListenerFailed) Error() string {
	if e.Cause == nil {
		return "init-only listener bind failed: " + e.Address
	}
	return "init-only listener bind failed: " + e.Address + ": " + e.Cause.Error()
}

// Unwrap returns the underlying listener error.
func (e *ErrInitOnlyListenerFailed) Unwrap() error { return e.Cause }

// =============================================================================
// Configuration
// =============================================================================

// DefaultInitOnlyHTTPAddr is the loopback address of the pre-unseal HTTP
// listener. Port 9446 is reserved for the barrier gate: it collides with
// none of the production transports (REST 8443, gRPC 10443, QUIC 9444,
// MCP 9445).
const DefaultInitOnlyHTTPAddr = "127.0.0.1:9446"

// InitOnlyConfig configures the minimal pre-unseal listener set.
type InitOnlyConfig struct {
	// SocketPath is the Unix domain socket bound for local platformctl.
	// Defaults to /run/platformd.sock when empty.
	SocketPath string

	// SocketMode is the chmod applied to the Unix socket. Defaults to 0660.
	SocketMode os.FileMode

	// HTTPListenAddr is the loopback address bound for the minimal HTTP
	// surface. Defaults to DefaultInitOnlyHTTPAddr when empty.
	HTTPListenAddr string

	// State reports the current platform state. Required.
	State rest.PlatformStateProvider

	// Init delegates POST /init. Optional; when nil /init returns 503.
	Init rest.BarrierInitService

	// Unseal delegates POST /unseal. Optional; when nil /unseal returns 503.
	Unseal rest.BarrierUnsealService

	// Logger is used for lifecycle messages. Required.
	Logger *logging.Logger

	// ShutdownTimeout caps graceful shutdown of the HTTP server. Defaults
	// to 10 seconds.
	ShutdownTimeout time.Duration

	// UnixHandler is an optional HTTP handler bound to the Unix socket. When
	// nil the same minimal /healthz + /init + /unseal mux is reused on the
	// Unix socket so local CLIs can target it without TLS.
	UnixHandler http.Handler
}

// =============================================================================
// InitOnlyServer
// =============================================================================

// InitOnlyServer binds the minimal pre-unseal listener set: a Unix socket
// for local platformctl and a loopback HTTP endpoint for /healthz, /init,
// and /unseal. All other transports remain unbound until the barrier is
// unsealed.
type InitOnlyServer struct {
	cfg     InitOnlyConfig
	logger  *logging.Logger
	mu      sync.Mutex
	running atomic.Bool

	httpListener net.Listener
	unixListener net.Listener
	httpServer   *http.Server
	unixServer   *http.Server
	handlers     *rest.InitHandlers
}

// NewInitOnlyServer constructs an InitOnlyServer from the given config.
// Defaults are applied for any unset fields. The State provider is required
// because /healthz must always have a definitive answer.
func NewInitOnlyServer(cfg InitOnlyConfig) (*InitOnlyServer, error) {
	if cfg.State == nil {
		return nil, ErrInitOnlyMissingState{}
	}
	if cfg.Logger == nil {
		return nil, ErrInitOnlyMissingLogger{}
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = "/run/platformd.sock"
	}
	if cfg.SocketMode == 0 {
		cfg.SocketMode = 0660
	}
	if cfg.HTTPListenAddr == "" {
		cfg.HTTPListenAddr = DefaultInitOnlyHTTPAddr
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 10 * time.Second
	}

	handlers := rest.NewInitHandlers(rest.InitHandlersConfig{
		State:  cfg.State,
		Init:   cfg.Init,
		Unseal: cfg.Unseal,
	})

	return &InitOnlyServer{
		cfg:      cfg,
		logger:   cfg.Logger,
		handlers: handlers,
	}, nil
}

// HTTPListenAddr returns the loopback HTTP address actually bound (after
// resolving "host:0" port assignments). Empty before Start.
func (s *InitOnlyServer) HTTPListenAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpListener == nil {
		return ""
	}
	return s.httpListener.Addr().String()
}

// SocketPath returns the configured Unix socket path.
func (s *InitOnlyServer) SocketPath() string { return s.cfg.SocketPath }

// IsRunning reports whether the server is currently listening.
func (s *InitOnlyServer) IsRunning() bool { return s.running.Load() }

// Start binds the Unix socket and loopback HTTP listeners and serves the
// minimal pre-unseal mux on both. It is idempotent only in that it returns
// ErrInitOnlyAlreadyRunning when called on a running server; it does not
// silently no-op.
func (s *InitOnlyServer) Start(_ context.Context) error {
	if s.running.Load() {
		return ErrInitOnlyAlreadyRunning{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	mux := http.NewServeMux()
	s.handlers.Register(mux)

	// Bind the loopback HTTP listener first; any failure here is fatal
	// because the orchestrator can't probe /healthz without it.
	httpListener, err := net.Listen("tcp", s.cfg.HTTPListenAddr)
	if err != nil {
		return &ErrInitOnlyListenerFailed{Address: s.cfg.HTTPListenAddr, Cause: err}
	}
	s.httpListener = httpListener
	s.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Unix socket: clean any stale path then bind. A bind failure here is
	// fatal too; we do not want to silently fall back to "HTTP only".
	if rmErr := os.RemoveAll(s.cfg.SocketPath); rmErr != nil {
		_ = httpListener.Close()
		return &ErrInitOnlyListenerFailed{Address: s.cfg.SocketPath, Cause: rmErr}
	}
	unixListener, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		_ = httpListener.Close()
		return &ErrInitOnlyListenerFailed{Address: s.cfg.SocketPath, Cause: err}
	}
	if chmodErr := os.Chmod(s.cfg.SocketPath, s.cfg.SocketMode); chmodErr != nil {
		// Non-fatal: log and keep going. Tightening permissions is
		// preferred but a working socket beats a missing one.
		s.logger.Warn("init-only: failed to chmod unix socket",
			"path", s.cfg.SocketPath, "error", chmodErr)
	}
	s.unixListener = unixListener

	unixHandler := s.cfg.UnixHandler
	if unixHandler == nil {
		unixHandler = mux
	}
	s.unixServer = &http.Server{
		Handler:           unixHandler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	s.running.Store(true)

	// Capture local references so the goroutines do not race with Stop()
	// nilling out the server's pointers during shutdown.
	httpAddr := httpListener.Addr().String()
	socketPath := s.cfg.SocketPath
	logger := s.logger
	httpServer := s.httpServer
	unixServer := s.unixServer

	go func() {
		logger.Info("init-only HTTP serving",
			"addr", httpAddr,
			"endpoints", "/healthz,/init,/unseal")
		if err := httpServer.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error(err, "component", "init_only_http")
		}
	}()
	go func() {
		logger.Info("init-only Unix socket serving",
			"path", socketPath)
		if err := unixServer.Serve(unixListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error(err, "component", "init_only_unix")
		}
	}()

	return nil
}

// Stop gracefully shuts down both listeners. Safe to call multiple times;
// subsequent calls return ErrInitOnlyNotRunning.
func (s *InitOnlyServer) Stop(ctx context.Context) error {
	if !s.running.Load() {
		return ErrInitOnlyNotRunning{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	shutdownCtx, cancel := context.WithTimeout(ctx, s.cfg.ShutdownTimeout)
	defer cancel()

	var firstErr error
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.unixServer != nil {
		if err := s.unixServer.Shutdown(shutdownCtx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.httpListener != nil {
		_ = s.httpListener.Close()
		s.httpListener = nil
	}
	if s.unixListener != nil {
		_ = s.unixListener.Close()
		s.unixListener = nil
	}
	// Best-effort socket file cleanup; failures here are not fatal.
	_ = os.RemoveAll(s.cfg.SocketPath)
	s.running.Store(false)
	return firstErr
}
