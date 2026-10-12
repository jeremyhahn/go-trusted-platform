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
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Handler processes incoming QUIC requests
type Handler interface {
	// HandleRequest processes a request and returns a response
	HandleRequest(ctx context.Context, req *quicwire.Request) *quicwire.Response
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

	s.logger.Infof("QUIC server started on %s", s.config.ListenAddr)

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
			s.logger.Warnf("Error closing QUIC listener: %v", err)
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

	remoteAddr := conn.RemoteAddr().String()
	slog.Debug("QUIC connection accepted",
		slog.String("remote_addr", remoteAddr),
		slog.Int64("active_conns", s.activeConns.Load()),
	)

	for s.running.Load() {
		stream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			if !s.running.Load() {
				return
			}
			// Log connection close at DEBUG: normal EOF on peer close is not an error.
			slog.Debug("QUIC connection closed",
				slog.String("remote_addr", remoteAddr),
				slog.String("error", err.Error()),
				slog.String("conn_ctx_err", ctxErrString(conn.Context())),
			)
			return
		}

		if s.activeStreams.Load() >= int64(s.config.MaxStreams) {
			s.logger.Warn("Maximum concurrent streams reached")
			if err := stream.Close(); err != nil {
				slog.Debug("QUIC stream close failed (max-streams reject)",
					slog.Int64("stream_id", int64(stream.StreamID())),
					slog.String("error", err.Error()),
				)
			}
			continue
		}

		s.activeStreams.Add(1)
		s.wg.Add(1)
		go s.handleStream(stream, remoteAddr)
	}
}

// handleStream handles a single QUIC stream.
// A deferred recover guard catches any panic that escapes the Handler
// (defense-in-depth: the Handler itself should recover, but this goroutine-level
// guard ensures the stream goroutine is never silently killed). A panicking
// handler produces a StatusInternalError response so the client always receives
// a valid response frame rather than an EOF.
func (s *Server) handleStream(stream *quicgo.Stream, remoteAddr string) {
	defer s.wg.Done()
	defer s.activeStreams.Add(-1)

	streamID := int64(stream.StreamID())

	slog.Debug("QUIC stream accepted",
		slog.String("remote_addr", remoteAddr),
		slog.Int64("stream_id", streamID),
		slog.Int64("active_streams", s.activeStreams.Load()),
	)

	// Goroutine-level panic guard: write an error response before the stream
	// closes so the client never sees a bare EOF from a panicking handler.
	var panicResp *quicwire.Response
	defer func() {
		if r := recover(); r != nil {
			s.totalErrors.Add(1)
			s.logger.Errorf("QUIC stream handler panic: %v\n%s", r, debug.Stack())
			panicResp = &quicwire.Response{
				Status:  quicwire.StatusInternalError,
				Payload: []byte(fmt.Sprintf("internal server error: %v", r)),
			}
			if werr := quicwire.WriteResponse(stream, panicResp); werr != nil {
				slog.Debug("QUIC WriteResponse failed after panic recovery",
					slog.Int64("stream_id", streamID),
					slog.String("error", werr.Error()),
				)
			}
		}
	}()
	defer func() {
		if cerr := stream.Close(); cerr != nil {
			slog.Debug("QUIC stream close error",
				slog.String("remote_addr", remoteAddr),
				slog.Int64("stream_id", streamID),
				slog.String("error", cerr.Error()),
			)
		}
	}()

	startTime := time.Now()

	req, err := quicwire.ReadRequest(stream)
	if err != nil {
		s.totalErrors.Add(1)
		slog.Debug("QUIC stream read request failed",
			slog.String("remote_addr", remoteAddr),
			slog.Int64("stream_id", streamID),
			slog.String("error", err.Error()),
		)
		resp := &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte(err.Error()),
		}
		if werr := quicwire.WriteResponse(stream, resp); werr != nil {
			slog.Debug("QUIC WriteResponse failed after read error",
				slog.String("remote_addr", remoteAddr),
				slog.Int64("stream_id", streamID),
				slog.String("error", werr.Error()),
			)
		}
		return
	}

	s.totalRequests.Add(1)

	slog.Debug("QUIC stream request read",
		slog.String("remote_addr", remoteAddr),
		slog.Int64("stream_id", streamID),
		slog.String("opcode", quicwire.OpcodeToString(req.Opcode)),
		slog.String("opcode_hex", fmt.Sprintf("0x%02X", req.Opcode)),
		slog.Int("payload_len", len(req.Payload)),
	)

	var resp *quicwire.Response
	if s.handler != nil {
		resp = s.handler.HandleRequest(s.ctx, req)
	} else {
		resp = &quicwire.Response{
			Status:  quicwire.StatusNotImplemented,
			Payload: []byte("no handler configured"),
		}
	}

	respPayloadLen := 0
	if resp != nil {
		respPayloadLen = len(resp.Payload)
	}

	slog.Debug("QUIC stream response ready",
		slog.String("remote_addr", remoteAddr),
		slog.Int64("stream_id", streamID),
		slog.String("opcode", quicwire.OpcodeToString(req.Opcode)),
		slog.String("status", quicwire.StatusToString(resp.Status)),
		slog.Int("payload_len", respPayloadLen),
	)

	if werr := quicwire.WriteResponse(stream, resp); werr != nil {
		s.totalErrors.Add(1)
		slog.Error("QUIC stream WriteResponse failed",
			slog.String("remote_addr", remoteAddr),
			slog.Int64("stream_id", streamID),
			slog.String("opcode", quicwire.OpcodeToString(req.Opcode)),
			slog.String("error", werr.Error()),
		)
		return
	}

	elapsed := time.Since(startTime)
	slog.Debug("QUIC stream request completed",
		slog.String("remote_addr", remoteAddr),
		slog.Int64("stream_id", streamID),
		slog.String("opcode", quicwire.OpcodeToString(req.Opcode)),
		slog.String("status", quicwire.StatusToString(resp.Status)),
		slog.Int64("elapsed_us", elapsed.Microseconds()),
	)
}

// ctxErrString returns the context error string, or "nil" if the context has
// no error. Used to include connection-level cancellation state in log lines.
func ctxErrString(ctx context.Context) string {
	if err := ctx.Err(); err != nil {
		return err.Error()
	}
	return "nil"
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
