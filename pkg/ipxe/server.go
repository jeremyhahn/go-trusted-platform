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

package ipxe

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const (
	// readyCheckInterval is the interval for checking service readiness.
	readyCheckInterval = 100 * time.Millisecond

	// defaultReadyTimeout is the default timeout for waiting for services to be ready.
	defaultReadyTimeout = 10 * time.Second
)

// Server represents the complete PXE server with DHCP, TFTP, and HTTP services.
type Server struct {
	config   *ServerConfig
	logger   *logging.Logger
	serverIP net.IP

	httpServer *HTTPServer
	tftpServer *TFTPServer
	dhcpServer *DHCPServer

	mu      sync.Mutex
	running atomic.Bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	errChan chan error

	// readyCh closes once every enabled listener has bound. startErr
	// holds the first failure so Start can report it instead of nil.
	//
	// readyCh is created once, in NewServer, and never replaced:
	// callers hold the channel Ready() handed them, so swapping it in
	// Start would leave them waiting on one nobody ever closes. A
	// Server is started once.
	readyCh   chan struct{}
	readyOnce sync.Once
	started   atomic.Bool
	startErr  atomic.Pointer[error]
}

// signalBound reports that a listener has bound. Non-blocking: the
// channel is buffered per listener, and a nil channel (a sub-server
// started outside Server.Start) is simply ignored.
func signalBound(bound chan<- struct{}) {
	if bound == nil {
		return
	}
	select {
	case bound <- struct{}{}:
	default:
	}
}

// NewServer creates a new PXE server instance.
func NewServer(cfg *ServerConfig, logger *logging.Logger) (*Server, error) {
	if cfg == nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "server config is nil"}}
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, &WrappedError{Msg: "invalid server configuration", Err: err}
	}

	// Determine server IP
	serverIPStr, err := cfg.GetServerIP()
	if err != nil {
		return nil, &WrappedError{Msg: "failed to determine server IP", Err: err}
	}

	serverIP := net.ParseIP(serverIPStr)
	if serverIP == nil {
		return nil, &SentinelCauseError{Sentinel: ErrNoServerIP, Cause: &MessageError{Msg: fmt.Sprintf("invalid server IP %s", serverIPStr)}}
	}

	// Auto-detect external URL if not set
	if cfg.ExternalURL == "" {
		cfg.ExternalURL = fmt.Sprintf("http://%s:%d", serverIP.String(), cfg.HTTPPort)
		logger.Info("Auto-detected external URL", "url", cfg.ExternalURL)
	}

	// Auto-detect iPXE script URL if not set
	if cfg.IPXEScript == "" {
		cfg.IPXEScript = fmt.Sprintf("%s/boot.ipxe", cfg.ExternalURL)
		logger.Info("Auto-detected iPXE script URL", "url", cfg.IPXEScript)
	}

	server := &Server{
		config:   cfg,
		logger:   logger,
		serverIP: serverIP,
		errChan:  make(chan error, 3), // Buffer for HTTP, TFTP, DHCP errors
		readyCh:  make(chan struct{}),
	}

	// Create HTTP server
	server.httpServer = NewHTTPServer(cfg, logger)

	// Create TFTP server
	server.tftpServer = NewTFTPServer(cfg, serverIP, logger)

	// Create DHCP server if enabled
	if cfg.EnableDHCP {
		dhcpConfig, err := server.buildDHCPConfig()
		if err != nil {
			return nil, &WrappedError{Msg: "failed to build DHCP configuration", Err: err}
		}

		server.dhcpServer, err = NewDHCPServer(dhcpConfig, logger)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to create DHCP server", Err: err}
		}
	}

	return server, nil
}

// Start starts all PXE server services concurrently.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running.Load() {
		s.mu.Unlock()
		return &MessageError{Msg: "server is already running"}
	}
	// readyCh and startErr are one-shot, so a Server is single-use.
	// Re-running one would report the previous run's readiness and its
	// first error; refusing is honest where silently reusing stale
	// state is not.
	if s.started.Swap(true) {
		s.mu.Unlock()
		return &MessageError{Msg: "server has already been started; construct a new Server"}
	}

	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.running.Store(true)
	s.mu.Unlock()

	s.logger.Info("Starting PXE server",
		"server_ip", s.serverIP.String(),
		"http_port", s.config.HTTPPort,
		"tftp_port", s.config.TFTPPort,
		"dhcp_enabled", s.config.EnableDHCP,
	)

	// One buffered slot per listener. A bind signal is what Ready waits
	// on, so every listener must report exactly once.
	listeners := 2
	if s.dhcpServer != nil {
		listeners = 3
	}
	bound := make(chan struct{}, listeners)

	run := func(name string, start func(context.Context, chan<- struct{}) error) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := start(ctx, bound); err != nil && ctx.Err() == nil {
				wrapped := &WrappedError{Msg: name + " server failed", Err: err}
				s.logger.Error(wrapped)
				s.recordStartErr(wrapped)
				s.errChan <- wrapped
			}
		}()
	}

	run("HTTP", s.httpServer.Start)
	run("TFTP", s.tftpServer.Start)
	if s.dhcpServer != nil {
		run("DHCP", s.dhcpServer.Start)
	}

	// Ready only once EVERY listener has bound. A caller that treats
	// "the HTTP port answers" as "the server is up" would otherwise miss
	// a TFTP or DHCP bind failure that lands microseconds later — the
	// node then PXE-boots into nothing.
	go func() {
		for i := 0; i < listeners; i++ {
			select {
			case <-bound:
			case <-ctx.Done():
				return
			}
		}
		s.readyOnce.Do(func() { close(s.readyCh) })
	}()

	// Monitor for errors or context cancellation
	go func() {
		select {
		case err := <-s.errChan:
			s.logger.Error(&WrappedError{Msg: "server error", Err: err})
			s.Stop()
		case <-ctx.Done():
			return
		}
	}()

	// Wait for all services to complete
	s.wg.Wait()

	s.mu.Lock()
	s.running.Store(false)
	s.mu.Unlock()

	s.logger.Info("PXE server stopped")
	if err := s.startErr.Load(); err != nil {
		// Returning nil here is how a bind failure used to be masked
		// from the caller: the monitor stopped the server, wg.Wait
		// returned, and Start reported success.
		return *err
	}
	return nil
}

// Ready returns a channel closed once every enabled listener has bound.
// It never closes when a listener fails; callers select on it alongside
// their own context.
func (s *Server) Ready() <-chan struct{} { return s.readyCh }

// recordStartErr keeps the FIRST listener failure, which is the one that
// explains the others.
func (s *Server) recordStartErr(err error) {
	s.startErr.CompareAndSwap(nil, &err)
}

// Stop gracefully stops all PXE server services.
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running.Load() {
		s.mu.Unlock()
		return nil
	}

	s.logger.Info("Stopping PXE server")

	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()

	// Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("All services stopped gracefully")
	case <-time.After(10 * time.Second):
		s.logger.Warn("Timeout waiting for services to stop")
	}

	return nil
}

// ServerIP returns the server IP address.
func (s *Server) ServerIP() net.IP {
	return s.serverIP
}

// HTTPServer returns the underlying HTTP server for additional configuration.
func (s *Server) HTTPServer() *HTTPServer {
	return s.httpServer
}

// IsRunning returns whether the server is currently running.
func (s *Server) IsRunning() bool {
	return s.running.Load()
}

// WaitForReady waits for all services to be ready or timeout.
func (s *Server) WaitForReady(timeout time.Duration) error {
	if timeout == 0 {
		timeout = defaultReadyTimeout
	}

	deadline := time.Now().Add(timeout)

	s.logger.Info("Waiting for services to be ready", "timeout", timeout)

	// Check HTTP server
	httpReady := s.waitForHTTPReady(deadline)
	if !httpReady {
		return &MessageError{Msg: "HTTP server not ready within timeout"}
	}

	// TFTP and DHCP servers don't have direct readiness checks
	// They're considered ready when they start listening
	// The firmware loading in TFTP happens during Start()

	s.logger.Info("All services are ready")
	return nil
}

// waitForHTTPReady waits for the HTTP server to be ready.
func (s *Server) waitForHTTPReady(deadline time.Time) bool {
	addr := net.JoinHostPort(s.serverIP.String(), fmt.Sprintf("%d", s.config.HTTPPort))

	// A ticker rather than a sleep: the poll must stay interruptible by the
	// deadline, and a sleep holds the goroutine for its full interval no
	// matter how little time is left (go-style.md No time.Sleep, #260).
	ticker := time.NewTicker(readyCheckInterval)
	defer ticker.Stop()

	timeout := time.NewTimer(time.Until(deadline))
	defer timeout.Stop()

	for {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			s.logger.Debug("HTTP server is ready", "address", addr)
			return true
		}

		select {
		case <-ticker.C:
		case <-timeout.C:
			return false
		}
	}
}

// RunWithSignals starts the server and waits for interrupt signals.
// This is a convenience method for running the server as a standalone service.
func (s *Server) RunWithSignals(ctx context.Context) error {
	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- s.Start(ctx)
	}()

	// Wait for either signal or error
	select {
	case sig := <-sigChan:
		s.logger.Info("Received signal, shutting down", "signal", sig.String())
		cancel()
		return s.Stop()
	case err := <-errChan:
		if err != nil {
			return &WrappedError{Msg: "server error", Err: err}
		}
		return nil
	}
}

// buildDHCPConfig converts the ServerConfig to a DHCPConfig.
func (s *Server) buildDHCPConfig() (*DHCPConfig, error) {
	// Determine interface
	dhcpInterface := s.config.DHCPInterface
	if dhcpInterface == "" {
		dhcpInterface = s.config.Interface
	}

	// Parse IPs
	rangeStart := net.ParseIP(s.config.DHCPRangeStart)
	if rangeStart == nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidIPRange, Cause: &MessageError{Msg: fmt.Sprintf("invalid range start IP %s", s.config.DHCPRangeStart)}}
	}

	rangeEnd := net.ParseIP(s.config.DHCPRangeEnd)
	if rangeEnd == nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidIPRange, Cause: &MessageError{Msg: fmt.Sprintf("invalid range end IP %s", s.config.DHCPRangeEnd)}}
	}

	subnetMask := net.ParseIP(s.config.DHCPSubnetMask)
	if subnetMask == nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: fmt.Sprintf("invalid subnet mask %s", s.config.DHCPSubnetMask)}}
	}

	// Calculate broadcast IP
	broadcastIP := calculateBroadcastIP(s.serverIP, subnetMask)

	// Resolve arch-aware boot filename map. nil (the zero value)
	// means "use the standard defaults"; callers can opt out by
	// passing an explicit empty map, which falls through to
	// BootFilename uniformly.
	archMap := s.config.BootFilenameByArch
	if archMap == nil {
		archMap = DefaultBootFilenameByArch()
	}
	dhcpConfig := &DHCPConfig{
		Interface:          dhcpInterface,
		ServerIP:           s.serverIP,
		BroadcastIP:        broadcastIP,
		SubnetMask:         subnetMask.To4(),
		RangeStart:         rangeStart.To4(),
		RangeEnd:           rangeEnd.To4(),
		LeaseTime:          s.config.DHCPLeaseTime,
		TFTPServerName:     s.config.TFTPServerName,
		TFTPServerIP:       s.serverIP, // Use same IP for TFTP
		BootFilename:       s.config.BootFilename,
		BootFilenameByArch: archMap,
		IPXEScript:         s.config.IPXEScript,
		UseRawSocket:       false,
		RespondToAll:       s.config.DHCPRespondToAll,
		Port:               s.config.DHCPPort,
	}

	// Optional fields
	if s.config.DHCPGateway != "" {
		dhcpConfig.Router = net.ParseIP(s.config.DHCPGateway).To4()
	}

	if s.config.DHCPDNS != "" {
		dhcpConfig.DNSServers = []net.IP{net.ParseIP(s.config.DHCPDNS).To4()}
	}

	return dhcpConfig, nil
}
