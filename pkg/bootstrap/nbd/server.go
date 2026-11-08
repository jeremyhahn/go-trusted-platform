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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// Server is the NBD-over-TLS export server.
type Server struct {
	tlsConfig        *tls.Config
	anchor           *trust.Anchor
	identities       map[string]struct{}
	volumes          *volumeStore
	handshakeTimeout time.Duration
	logger           *slog.Logger

	// mu guards conns and stopping: Serve's watcher closes every tracked
	// connection on shutdown, and a connection accepted after that is
	// refused rather than tracked.
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	stopping bool

	// closeOnce and closed are guarded by mu as well, so a Serve call
	// either registers in serving before Close starts waiting or sees
	// closed and never registers.
	closeOnce sync.Once
	closed    chan struct{}

	// serving counts the running Serve calls, so Close can wait until
	// each one has closed its listener and left its accept loop.
	serving sync.WaitGroup
}

// NewServer validates cfg and returns a server ready to Serve.
func NewServer(cfg Config) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	identities := make(map[string]struct{}, len(cfg.Identities))
	for _, identity := range cfg.Identities {
		identities[strings.ToLower(identity)] = struct{}{}
	}

	timeout := cfg.HandshakeTimeout
	if timeout == 0 {
		timeout = DefaultHandshakeTimeout
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Server{
		tlsConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cfg.Certificate},
			// The certificate is requested, not required, so that its
			// absence reaches VerifyConnection and is refused with
			// ErrClientCertificateRequired rather than a generic alert.
			ClientAuth: tls.RequestClientCert,
		},
		anchor:           cfg.Anchor,
		identities:       identities,
		volumes:          newVolumeStore(cfg.Volumes, cfg.VolumeSize),
		handshakeTimeout: timeout,
		logger:           logger,
		conns:            make(map[net.Conn]struct{}),
		closed:           make(chan struct{}),
	}, nil
}

// Serve accepts connections on ln until ctx is cancelled or Close is
// called, then closes the listener and every open connection and waits
// for their goroutines. It returns nil on shutdown and ErrServeFailed if
// the listener fails first.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if !s.beginServe() {
		s.shutdown(ln)
		return nil
	}
	defer s.serving.Done()

	ctx, cancel := context.WithCancel(ctx)
	var sessions sync.WaitGroup
	defer func() {
		cancel()
		sessions.Wait()
	}()

	sessions.Go(func() {
		select {
		case <-ctx.Done():
		case <-s.closed:
			cancel()
		}
		s.shutdown(ln)
	})

	s.logger.Info("nbd export server listening", slog.String("addr", ln.Addr().String()))
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrServeFailed{Cause: err}
		}
		if !s.track(conn) {
			s.closeConn(conn)
			continue
		}
		sessions.Go(func() {
			defer s.untrack(conn)
			s.logOutcome(ctx, conn, s.serveConn(ctx, conn))
		})
	}
}

// Close stops every running Serve and returns once each has closed its
// listener and its accept loop has exited, so the port no longer
// accepts when Close returns. A Serve called after Close closes its
// listener and returns nil at once. It is safe to call more than once.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closeOnce.Do(func() { close(s.closed) })
	s.mu.Unlock()
	s.serving.Wait()
	return nil
}

// beginServe registers a Serve call with serving. It reports false once
// Close has begun: that Serve must not run, and Close does not wait for it.
func (s *Server) beginServe() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
		return false
	default:
	}
	s.serving.Add(1)
	return true
}

func (s *Server) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) untrack(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
	s.closeConn(conn)
}

// shutdown closes the listener and every tracked connection, so each
// session's blocked read returns and its goroutine ends.
func (s *Server) shutdown(ln net.Listener) {
	if err := ln.Close(); err != nil && !isClosedError(err) {
		s.logger.Warn("nbd listener close failed", slog.Any("error", err))
	}
	s.mu.Lock()
	s.stopping = true
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	for _, conn := range conns {
		s.closeConn(conn)
	}
}

func (s *Server) closeConn(conn net.Conn) {
	if err := conn.Close(); err != nil && !isClosedError(err) {
		s.logger.Warn("nbd connection close failed", slog.Any("error", err))
	}
}

func (s *Server) logOutcome(ctx context.Context, conn net.Conn, err error) {
	remote := slog.String("remote", conn.RemoteAddr().String())
	switch {
	case err == nil:
		s.logger.Info("nbd session ended", remote)
	case ctx.Err() != nil:
		s.logger.Debug("nbd session closed by shutdown", remote, slog.Any("error", err))
	default:
		s.logger.Warn("nbd session refused or failed", remote, slog.Any("error", err))
	}
}

// isClosedError reports the error a second close of a connection returns.
func isClosedError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

// serveConn runs one connection: negotiation, then transmission. Its
// error is the reason the session ended; nil means the client aborted
// negotiation or disconnected cleanly with NBD_CMD_DISC.
func (s *Server) serveConn(ctx context.Context, conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(s.handshakeTimeout)); err != nil {
		return ErrProtocol{Reason: "set handshake deadline", Cause: err}
	}

	neg := &negotiation{server: s, conn: conn}
	vol, err := neg.run(ctx)
	if err != nil || vol == nil {
		return err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return closeVolume(neg.identity, vol, ErrProtocol{Reason: "clear handshake deadline", Cause: err})
	}
	t := &transmission{
		conn:     neg.conn,
		identity: neg.identity,
		vol:      vol,
		logger:   s.logger,
	}
	return closeVolume(neg.identity, vol, t.run())
}

// tlsConfigFor returns the TLS configuration for one connection. Its
// VerifyConnection hook records the verified identity in *identity.
func (s *Server) tlsConfigFor(ctx context.Context, identity *string) *tls.Config {
	cfg := s.tlsConfig.Clone()
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		verified, err := s.verifyClient(ctx, state.PeerCertificates)
		if err != nil {
			return err
		}
		*identity = verified
		return nil
	}
	return cfg
}

// verifyClient checks the client chain against the platform anchor, read
// for this handshake so a rotated CA applies without a restart, and
// returns the identity it carries. This is the chain check attestation
// caller admission makes; there is no second trust store.
func (s *Server) verifyClient(ctx context.Context, chain []*x509.Certificate) (string, error) {
	if len(chain) == 0 {
		return "", ErrClientCertificateRequired{}
	}
	roots, err := s.anchor.CAPool(ctx)
	if err != nil {
		return "", ErrTrustAnchor{Cause: err}
	}

	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return "", ErrClientCertificateUntrusted{Subject: leaf.Subject.String(), Cause: err}
	}

	// The IDevID's subject CN is the node's enrollment hostname.
	identity := strings.ToLower(leaf.Subject.CommonName)
	if _, ok := s.identities[identity]; !ok {
		return "", ErrUnknownIdentity{Identity: leaf.Subject.CommonName}
	}
	return identity, nil
}

// closeVolume closes vol and returns err, joined with the close failure if
// there was one.
func closeVolume(identity string, vol *volume, err error) error {
	if closeErr := vol.file.Close(); closeErr != nil {
		return errors.Join(err, ErrVolume{Identity: identity, Op: "close", Cause: closeErr})
	}
	return err
}
