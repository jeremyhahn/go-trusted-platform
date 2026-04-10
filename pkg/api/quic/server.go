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

package quic

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Handler processes incoming QUIC requests
type Handler interface {
	// HandleRequest processes a request and returns a response
	HandleRequest(ctx context.Context, req *Request) *Response
}

// ServerStats holds statistics about the QUIC server
type ServerStats struct {
	ActiveConnections int64
	TotalConnections  uint64
	ActiveStreams     int64
	RequestsHandled   uint64
	Errors            uint64
}

// Server implements a QUIC transport layer for the Trusted Platform
type Server struct {
	config   *ServerConfig
	handler  Handler
	listener *quicgo.Listener
	logger   *logging.Logger

	// Server state
	running atomic.Bool
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc

	// Metrics
	activeStreams    atomic.Int64
	totalRequests    atomic.Uint64
	totalErrors      atomic.Uint64
	activeConns      atomic.Int64
	totalConnections atomic.Uint64
}

// ServerOption is a functional option for configuring the Server
type ServerOption func(*Server)

// WithHandler sets the request handler
func WithHandler(h Handler) ServerOption {
	return func(s *Server) {
		s.handler = h
	}
}

// WithLogger sets the server logger
func WithLogger(l *logging.Logger) ServerOption {
	return func(s *Server) {
		s.logger = l
	}
}

// NewServer creates a new QUIC server
func NewServer(config *ServerConfig, opts ...ServerOption) (*Server, error) {
	if config == nil {
		config = DefaultServerConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.logger == nil {
		s.logger = logging.DefaultLogger()
	}

	return s, nil
}

// Start starts the QUIC server
func (s *Server) Start() error {
	if s.running.Load() {
		return ErrServerRunning
	}

	// Create UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", s.config.ListenAddr)
	if err != nil {
		return err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	// Configure QUIC transport
	quicConfig := &quicgo.Config{
		MaxIdleTimeout:                 s.config.MaxIdleTimeout,
		MaxIncomingStreams:             s.config.MaxIncomingStreams,
		MaxIncomingUniStreams:          s.config.MaxIncomingUniStreams,
		KeepAlivePeriod:                s.config.KeepAlivePeriod,
		HandshakeIdleTimeout:           s.config.HandshakeIdleTimeout,
		InitialStreamReceiveWindow:     s.config.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         s.config.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: s.config.MaxReceiveBufferSize,
		MaxConnectionReceiveWindow:     s.config.MaxReceiveBufferSize * 2,
		EnableDatagrams:                false,
	}

	listener, err := quicgo.Listen(udpConn, s.config.TLSConfig, quicConfig)
	if err != nil {
		_ = udpConn.Close()
		return err
	}

	s.listener = listener
	s.running.Store(true)

	s.logger.Info("QUIC server started on %s", s.config.ListenAddr)

	s.wg.Add(1)
	go s.acceptConnections()

	return nil
}

// Stop gracefully stops the QUIC server
func (s *Server) Stop() error {
	if !s.running.Load() {
		return ErrServerNotRunning
	}

	s.logger.Info("Stopping QUIC server")

	s.running.Store(false)
	s.cancel()

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.logger.Warn("Error closing QUIC listener: %v", err)
		}
	}

	// Wait for connections with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("QUIC server stopped gracefully")
	case <-time.After(30 * time.Second):
		s.logger.Warn("QUIC server stop timeout, forcing shutdown")
	}

	return nil
}

// acceptConnections accepts incoming QUIC connections
func (s *Server) acceptConnections() {
	defer s.wg.Done()

	for s.running.Load() {
		conn, err := s.listener.Accept(s.ctx)
		if err != nil {
			if !s.running.Load() {
				return
			}
			s.logger.Errorf("Failed to accept QUIC connection: %v", err)
			continue
		}

		s.activeConns.Add(1)
		s.totalConnections.Add(1)
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single QUIC connection
func (s *Server) handleConnection(conn *quicgo.Conn) {
	defer s.wg.Done()
	defer s.activeConns.Add(-1)

	s.logger.Debug("New QUIC connection from %s", conn.RemoteAddr())

	for s.running.Load() {
		stream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			if !s.running.Load() {
				return
			}
			s.logger.Debug("Connection closed: %v", err)
			return
		}

		if s.activeStreams.Load() >= int64(s.config.MaxStreams) {
			s.logger.Warn("Maximum concurrent streams reached")
			_ = stream.Close()
			continue
		}

		s.activeStreams.Add(1)
		s.wg.Add(1)
		go s.handleStream(stream)
	}
}

// handleStream handles a single QUIC stream
func (s *Server) handleStream(stream *quicgo.Stream) {
	defer s.wg.Done()
	defer s.activeStreams.Add(-1)
	defer stream.Close()

	startTime := time.Now()

	req, err := ReadRequest(stream)
	if err != nil {
		s.totalErrors.Add(1)
		s.logger.Errorf("Failed to read request: %v", err)
		resp := &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte(err.Error()),
		}
		_ = WriteResponse(stream, resp)
		return
	}

	s.totalRequests.Add(1)

	s.logger.Debug("Processing request: %s", OpcodeToString(req.Opcode))

	var resp *Response
	if s.handler != nil {
		resp = s.handler.HandleRequest(s.ctx, req)
	} else {
		resp = &Response{
			Status:  StatusNotImplemented,
			Payload: []byte("no handler configured"),
		}
	}

	if err := WriteResponse(stream, resp); err != nil {
		s.totalErrors.Add(1)
		s.logger.Errorf("Failed to write response: %v", err)
		return
	}

	s.logger.Debug("Request completed in %v", time.Since(startTime))
}

// GetMetrics returns current server metrics
func (s *Server) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"active_connections": s.activeConns.Load(),
		"total_connections":  s.totalConnections.Load(),
		"active_streams":     s.activeStreams.Load(),
		"total_requests":     s.totalRequests.Load(),
		"total_errors":       s.totalErrors.Load(),
		"running":            s.running.Load(),
	}
}

// Stats returns current server statistics
func (s *Server) Stats() *ServerStats {
	return &ServerStats{
		ActiveConnections: s.activeConns.Load(),
		TotalConnections:  s.totalConnections.Load(),
		ActiveStreams:     s.activeStreams.Load(),
		RequestsHandled:   s.totalRequests.Load(),
		Errors:            s.totalErrors.Load(),
	}
}

// IsRunning returns true if the server is running
func (s *Server) IsRunning() bool {
	return s.running.Load()
}

// ListenAddr returns the configured listen address
func (s *Server) ListenAddr() string {
	return s.config.ListenAddr
}
