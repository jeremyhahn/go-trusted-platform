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

package quicagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

// shellPath is the shell the agent runs commands with, as SSH does.
const shellPath = "/bin/sh"

// runWaitDelay bounds how long a cancelled command may keep its output
// pipes open before run gives up on them and returns.
const runWaitDelay = 3 * time.Second

// streamRefused is the stream error code the agent sends when it stops
// reading a body it will not write.
const streamRefused quic.StreamErrorCode = 2

// Server is the deploy-target side of the QUIC deploy agent. It accepts
// only clients whose certificate verifies against the configured ClientCAs.
type Server struct {
	tlsConf *tls.Config
	logger  *slog.Logger
	// outputLimit is the Run output budget in bytes; zero means
	// maxOutputSize.
	outputLimit int

	mu       sync.Mutex
	listener *quic.Listener
	conns    map[*quic.Conn]struct{}
	closed   bool
	wg       sync.WaitGroup
}

// NewServer returns an agent for tlsConf, which must carry the agent's
// certificate and the CAs that issue deployer client certificates. The
// agent forces TLS 1.3, a verified client certificate, its ALPN and the
// FIPS curves.
func NewServer(tlsConf *tls.Config, logger *slog.Logger) (*Server, error) {
	if tlsConf == nil {
		return nil, ErrInvalidTLSConfig{Reason: "no TLS configuration"}
	}
	if len(tlsConf.Certificates) == 0 && tlsConf.GetCertificate == nil {
		return nil, ErrInvalidTLSConfig{Reason: "no agent certificate"}
	}
	if tlsConf.ClientCAs == nil {
		return nil, ErrInvalidTLSConfig{Reason: "no client CAs to verify the deployer"}
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	conf := tlsConf.Clone()
	conf.GetConfigForClient = nil
	hardenServerConfig(conf, tlsConf.ClientCAs)
	if perClient := tlsConf.GetConfigForClient; perClient != nil {
		base := conf.Clone()
		conf.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			c, err := perClient(hello)
			if err != nil {
				return nil, err
			}
			if c == nil {
				return base, nil
			}
			c = c.Clone()
			c.GetConfigForClient = nil
			if len(c.Certificates) == 0 && c.GetCertificate == nil {
				c.Certificates = base.Certificates
				c.GetCertificate = base.GetCertificate
			}
			hardenServerConfig(c, base.ClientCAs)
			return c, nil
		}
	}
	return &Server{tlsConf: conf, logger: logger}, nil
}

// hardenServerConfig forces the agent's TLS policy on conf: TLS 1.3 only,
// a client certificate verified against clientCAs, the agent ALPN and the
// FIPS curves. A per-client configuration gets the same policy.
func hardenServerConfig(conf *tls.Config, clientCAs *x509.CertPool) {
	conf.MinVersion = tls.VersionTLS13
	conf.MaxVersion = tls.VersionTLS13
	conf.ClientAuth = tls.RequireAndVerifyClientCert
	conf.ClientCAs = clientCAs
	conf.NextProtos = []string{ALPN}
	conf.CurvePreferences = fipsCurves
}

// Serve accepts deployer connections on pc until ctx ends or Close is
// called, then waits for the operations in flight. It does not close pc.
func (s *Server) Serve(ctx context.Context, pc net.PacketConn) error {
	ln, err := quic.Listen(pc, s.tlsConf, &quic.Config{KeepAlivePeriod: keepAlivePeriod})
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ln.Close()
	}
	s.listener = ln
	s.mu.Unlock()

	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	defer s.wg.Wait()

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			return err
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// Close stops the listener and closes the deployer connections; Serve
// returns once their operations end.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for conn := range s.conns {
		_ = conn.CloseWithError(0, "agent closing")
	}
	if s.listener == nil {
		return nil
	}
	err := s.listener.Close()
	s.listener = nil
	return err
}

func (s *Server) handleConn(conn *quic.Conn) {
	defer s.wg.Done()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.CloseWithError(0, "agent closing")
		return
	}
	if s.conns == nil {
		s.conns = make(map[*quic.Conn]struct{})
	}
	s.conns[conn] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()
	peer := conn.RemoteAddr().String()
	if certs := conn.ConnectionState().TLS.PeerCertificates; len(certs) > 0 {
		s.logger.Info("deploy agent: client connected", "peer", peer, "subject", certs[0].Subject.String())
	}
	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.handleStream(stream, peer)
	}
}

func (s *Server) handleStream(stream *quic.Stream, peer string) {
	defer s.wg.Done()
	defer func() { _ = stream.Close() }()

	var req request
	if err := readFrame(stream, &req); err != nil {
		s.logger.Warn("deploy agent: bad request frame", "peer", peer, "error", err)
		stream.CancelRead(streamRefused)
		return
	}
	var resp response
	switch req.Op {
	case opRun:
		resp = s.run(stream.Context(), req.Command)
	case opCopy:
		resp = s.copy(stream, req)
	case opStat:
		resp = s.stat(req.Path)
	default:
		resp = response{Error: "unknown operation " + req.Op}
	}
	if resp.Error != "" {
		s.logger.Warn("deploy agent: operation failed", "peer", peer, "op", req.Op, "error", resp.Error)
		stream.CancelRead(streamRefused)
	}
	if err := writeFrame(stream, resp); err != nil {
		s.logger.Warn("deploy agent: write response", "peer", peer, "op", req.Op, "error", err)
	}
}

func (s *Server) run(ctx context.Context, command string) response {
	limit := s.outputLimit
	if limit <= 0 {
		limit = maxOutputSize
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// stdout and stderr share one budget, enforced while the command
	// runs: the write that passes it kills the process group, so a
	// verbose or endless command cannot grow the agent's memory.
	budget := &outputBudget{limit: limit, exceeded: cancel}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(runCtx, shellPath, "-c", command)
	cmd.Stdout = budget.writer(&stdout)
	cmd.Stderr = budget.writer(&stderr)
	// Cancellation kills the command's whole process group, and the wait
	// for output pipes a stray descendant still holds is bounded, so a
	// cancelled operation cannot hold up Serve's shutdown.
	killProcessGroupOnCancel(cmd)
	cmd.WaitDelay = runWaitDelay
	err := cmd.Run()
	if budget.over() {
		return response{Error: ErrOutputTooLarge{Limit: limit}.Error()}
	}
	resp := response{Stdout: stdout.String(), Stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		resp.ExitCode = exitErr.ExitCode()
	default:
		resp.Error = err.Error()
	}
	return resp
}

// outputBudget bounds the bytes a command's stdout and stderr together
// may hold. The write that would pass the limit is refused, marks the
// budget exceeded and calls exceeded (which cancels the command).
type outputBudget struct {
	limit    int
	exceeded func()

	mu   sync.Mutex
	used int
	hit  bool
}

func (b *outputBudget) writer(buf *bytes.Buffer) io.Writer {
	return budgetWriter{b: b, buf: buf}
}

func (b *outputBudget) over() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hit
}

type budgetWriter struct {
	b   *outputBudget
	buf *bytes.Buffer
}

func (w budgetWriter) Write(p []byte) (int, error) {
	w.b.mu.Lock()
	if w.b.hit || w.b.used+len(p) > w.b.limit {
		first := !w.b.hit
		w.b.hit = true
		w.b.mu.Unlock()
		if first {
			w.b.exceeded()
		}
		return 0, ErrOutputTooLarge{Limit: w.b.limit}
	}
	w.b.used += len(p)
	n, err := w.buf.Write(p)
	w.b.mu.Unlock()
	return n, err
}

// copy writes exactly req.Size body bytes to a temporary file beside
// req.Path, then renames it into place and reports its sha256.
func (s *Server) copy(body io.Reader, req request) response {
	if req.Size < 0 {
		return response{Error: "negative size"}
	}
	dir := filepath.Dir(req.Path)
	tmp, err := os.CreateTemp(dir, ".quicagent-*")
	if err != nil {
		return response{Error: err.Error()}
	}
	tmpName := tmp.Name()
	fail := func(err error) response {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return response{Error: err.Error()}
	}
	h := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(tmp, h), body, req.Size); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(copyFileMode); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmpName, req.Path); err != nil {
		_ = os.Remove(tmpName)
		return response{Error: err.Error()}
	}
	return response{Size: req.Size, SHA256: hex.EncodeToString(h.Sum(nil))}
}

func (s *Server) stat(path string) response {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return response{NotFound: true}
	}
	if err != nil {
		return response{Error: err.Error()}
	}
	return response{Size: info.Size(), MTime: info.ModTime().Unix()}
}
