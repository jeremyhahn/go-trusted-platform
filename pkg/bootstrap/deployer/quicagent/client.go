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
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
)

// streamCancelled is the QUIC stream error code the client sends when the
// caller's context ends mid-operation.
const streamCancelled quic.StreamErrorCode = 1

// keepAlivePeriod keeps an idle deploy session open between operations.
const keepAlivePeriod = 15 * time.Second

var _ deployer.RemoteHost = (*Client)(nil)

// Client is the deployer side of the QUIC deploy agent. It implements
// deployer.RemoteHost.
type Client struct {
	addr    string
	tlsConf *tls.Config

	mu   sync.Mutex
	conn *quic.Conn
}

// NewClient returns a client for the agent at addr. tlsConf must carry the
// deployer's client certificate and the roots that verify the agent; the
// client forces TLS 1.3, the agent's ALPN and the FIPS curves.
func NewClient(addr string, tlsConf *tls.Config) (*Client, error) {
	if tlsConf == nil {
		return nil, ErrInvalidTLSConfig{Reason: "no TLS configuration"}
	}
	if len(tlsConf.Certificates) == 0 && tlsConf.GetClientCertificate == nil {
		return nil, ErrInvalidTLSConfig{Reason: "no client certificate"}
	}
	if tlsConf.RootCAs == nil {
		return nil, ErrInvalidTLSConfig{Reason: "no root CAs to verify the agent"}
	}
	if tlsConf.InsecureSkipVerify {
		return nil, ErrInvalidTLSConfig{Reason: "InsecureSkipVerify would accept any agent certificate"}
	}
	conf := tlsConf.Clone()
	conf.MinVersion = tls.VersionTLS13
	conf.MaxVersion = tls.VersionTLS13
	conf.NextProtos = []string{ALPN}
	conf.CurvePreferences = fipsCurves
	return &Client{addr: addr, tlsConf: conf}, nil
}

// Connect dials the agent and completes the mutually authenticated
// handshake. Connecting an already connected client is a no-op.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil && c.conn.Context().Err() == nil {
		return nil
	}
	conn, err := quic.DialAddr(ctx, c.addr, c.tlsConf, &quic.Config{KeepAlivePeriod: keepAlivePeriod})
	if err != nil {
		return ErrConnect{Addr: c.addr, Cause: err}
	}
	c.conn = conn
	return nil
}

// Close closes the connection to the agent.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.CloseWithError(0, "")
	c.conn = nil
	return err
}

// IsConnected reports whether the client holds an open connection.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil && c.conn.Context().Err() == nil
}

// Run runs command through the agent's shell. On a non-zero exit it returns
// the command's stderr (else its stdout) and an ErrCommand with the status.
func (c *Client) Run(ctx context.Context, command string) (string, error) {
	resp, err := c.roundTrip(ctx, request{Op: opRun, Command: command}, nil)
	if err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", ErrCommand{Command: command, ExitCode: -1, Cause: ErrRemote{Op: opRun, Message: resp.Error}}
	}
	if resp.ExitCode != 0 {
		output := resp.Stderr
		if output == "" {
			output = resp.Stdout
		}
		return output, ErrCommand{Command: command, Output: output, ExitCode: resp.ExitCode}
	}
	return resp.Stdout, nil
}

// CopyFileStream streams localPath to remotePath. The agent writes a
// temporary file next to remotePath and renames it into place once the
// sha256 of what it wrote is known; the client compares it with its own.
func (c *Client) CopyFileStream(ctx context.Context, localPath, remotePath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return deployer.ErrFileRead{Path: localPath, Cause: err}
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return deployer.ErrFileRead{Path: localPath, Cause: err}
	}
	return c.copyFrom(ctx, f, info.Size(), localPath, remotePath)
}

// copyFrom uploads exactly size bytes of src to remotePath and checks the
// agent's digest against the digest of those same bytes. A source that
// grows after size was taken is cut at size, so the body never overruns
// the request (the agent stops reading at Size, and the surplus would
// exhaust QUIC flow control); one that shrinks fails with
// ErrSourceChanged before the agent can commit the destination.
func (c *Client) copyFrom(ctx context.Context, src io.Reader, size int64, localPath, remotePath string) error {
	h := sha256.New()
	body := func(w io.Writer) error {
		n, err := io.CopyN(w, io.TeeReader(src, h), size)
		if errors.Is(err, io.EOF) {
			return ErrSourceChanged{Path: localPath, Announced: size, Sent: n}
		}
		return err
	}
	resp, err := c.roundTrip(ctx, request{Op: opCopy, Path: remotePath, Size: size}, body)
	if err != nil {
		return deployer.ErrFileCopy{Local: localPath, Remote: remotePath, Cause: err}
	}
	if resp.Error != "" {
		return deployer.ErrFileCopy{Local: localPath, Remote: remotePath, Cause: ErrRemote{Op: opCopy, Message: resp.Error}}
	}
	if local := hex.EncodeToString(h.Sum(nil)); local != resp.SHA256 {
		return ErrDigestMismatch{Path: remotePath, Local: local, Remote: resp.SHA256}
	}
	return nil
}

// StatRemote returns the size and modification time (Unix seconds) of
// remotePath on the agent, or deployer.ErrRemoteFileNotFound.
func (c *Client) StatRemote(ctx context.Context, remotePath string) (int64, int64, error) {
	resp, err := c.roundTrip(ctx, request{Op: opStat, Path: remotePath}, nil)
	if err != nil {
		return 0, 0, err
	}
	if resp.NotFound {
		return 0, 0, deployer.ErrRemoteFileNotFound{Path: remotePath}
	}
	if resp.Error != "" {
		return 0, 0, ErrRemote{Op: opStat, Message: resp.Error}
	}
	return resp.Size, resp.MTime, nil
}

// roundTrip runs one operation on its own stream: the request frame, the
// body (when body is not nil), the end of the send side, then the response
// frame.
func (c *Client) roundTrip(ctx context.Context, req request, body func(io.Writer) error) (resp response, err error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return response{}, ErrNotConnected{Addr: c.addr}
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return response{}, ErrStream{Op: req.Op, Cause: err}
	}
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(streamCancelled)
		stream.CancelWrite(streamCancelled)
	})
	defer stop()
	// Release both sides of the stream on every failed exit, so neither
	// peer waits on it.
	defer func() {
		if err != nil {
			stream.CancelWrite(streamCancelled)
			stream.CancelRead(streamCancelled)
		}
	}()

	sw := &streamWriter{w: stream}
	sendErr := writeFrame(sw, req)
	if sendErr == nil && body != nil {
		sendErr = body(sw)
	}
	if sendErr != nil && sw.err == nil {
		// The failure is local (an oversized frame, a failing body
		// source): the agent has nothing to answer, so do not wait.
		return response{}, ErrStream{Op: req.Op, Cause: sendErr}
	}
	if sendErr == nil {
		sendErr = stream.Close()
	}

	if rerr := readFrame(stream, &resp); rerr != nil {
		if sendErr != nil {
			rerr = sendErr
		}
		if ctx.Err() != nil {
			rerr = ctx.Err()
		}
		return response{}, ErrStream{Op: req.Op, Cause: rerr}
	}
	// The agent can answer (with an error) before it has read the whole
	// body; its answer explains the failed send.
	if sendErr != nil && resp.Error == "" {
		return response{}, ErrStream{Op: req.Op, Cause: sendErr}
	}
	return resp, nil
}

// streamWriter records the first error the stream itself returned, so
// roundTrip can tell a transport failure (the agent may still answer) from
// a local one.
type streamWriter struct {
	w   io.Writer
	err error
}

func (s *streamWriter) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if err != nil && s.err == nil {
		s.err = err
	}
	return n, err
}
