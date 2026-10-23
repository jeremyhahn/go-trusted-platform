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
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// remoteAlertOp is the net.OpError operation crypto/tls reports for an alert
// the peer sent. Under TLS 1.3 a server that rejects the client certificate
// sends its alert after the client's handshake has returned, so the node
// sees the rejection on its first read.
const remoteAlertOp = "remote error"

// ClientConfig is a diskless-nbd node's side of the attach.
type ClientConfig struct {
	// Certificate is the node's IDevID certificate. Its PrivateKey is the
	// TPM-resident signer, so the key never leaves the TPM.
	Certificate tls.Certificate
	// RootCAs verifies the boot server's certificate: the platform CA the
	// image carries.
	RootCAs *x509.CertPool
	// ServerName is the name the boot server's certificate must carry.
	ServerName string
	// HandshakeTimeout bounds negotiation; zero means DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
}

// Validate reports the first field the node cannot attach with.
func (c *ClientConfig) Validate() error {
	if len(c.Certificate.Certificate) == 0 || c.Certificate.PrivateKey == nil {
		return ErrInvalidConfig{Field: "Certificate", Reason: "the IDevID certificate and its key are required"}
	}
	if c.RootCAs == nil {
		return ErrInvalidConfig{Field: "RootCAs", Reason: "the platform CA pool is required"}
	}
	if c.ServerName == "" {
		return ErrInvalidConfig{Field: "ServerName", Reason: "the boot server's certificate name is required"}
	}
	if c.HandshakeTimeout < 0 {
		return ErrInvalidConfig{Field: "HandshakeTimeout", Reason: "must not be negative"}
	}
	return nil
}

// NewClientConfig builds a diskless-nbd node's ClientConfig from the server
// address on its signed command line, the platform anchor the image carries
// and its IDevID certificate. The server's certificate must carry the
// address's host; the handshake timeout is the default.
func NewClientConfig(ctx context.Context, server ServerAddr, anchor *trust.Anchor, idevid tls.Certificate) (ClientConfig, error) {
	if err := server.Validate(); err != nil {
		return ClientConfig{}, err
	}
	if anchor == nil {
		return ClientConfig{}, ErrInvalidConfig{Field: "RootCAs", Reason: "the platform anchor is required"}
	}
	roots, err := anchor.CAPool(ctx)
	if err != nil {
		return ClientConfig{}, ErrTrustAnchor{Cause: err}
	}
	cfg := ClientConfig{
		Certificate:      idevid,
		RootCAs:          roots,
		ServerName:       server.Host,
		HandshakeTimeout: DefaultHandshakeTimeout,
	}
	if err := cfg.Validate(); err != nil {
		return ClientConfig{}, err
	}
	return cfg, nil
}

// tlsConfig is TLS 1.3 only, presenting the IDevID and verifying the server
// against the platform CA.
func (c *ClientConfig) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{c.Certificate},
		RootCAs:      c.RootCAs,
		ServerName:   c.ServerName,
	}
}

// Export is an attached export in the transmission phase.
type Export struct {
	// Conn is the TLS connection transmission requests travel on.
	Conn net.Conn
	// Size is the export's size in bytes.
	Size uint64
	// Flags are the export's transmission flags.
	Flags uint16
	// MinBlockSize, PreferredBlockSize and MaxBlockSize are the server's
	// NBD_INFO_BLOCK_SIZE constraints; zero when it sent none.
	MinBlockSize       uint32
	PreferredBlockSize uint32
	MaxBlockSize       uint32
}

// serverReply is one option reply as the client reads it.
type serverReply struct {
	replyType uint32
	data      []byte
}

// Attach negotiates the node's export over conn: fixed newstyle,
// NBD_OPT_STARTTLS first, a TLS 1.3 handshake presenting the IDevID, then
// NBD_OPT_GO with an empty export name, which the server resolves to the
// node's own volume. On success the export is in transmission.
//
// Attach owns conn. On any error it closes conn and returns, because a
// refusal is final: the node never retries in plaintext and never asks for
// another export. A server refusal is ErrServerRefused; a failed or
// rejected handshake is ErrTLSHandshake; anything else on the wire,
// including a closed connection, a timeout or a cancelled ctx, is
// ErrProtocol.
func Attach(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Export, error) {
	if err := cfg.Validate(); err != nil {
		return nil, closeAfterFailure(conn, err)
	}
	timeout := cfg.HandshakeTimeout
	if timeout == 0 {
		timeout = DefaultHandshakeTimeout
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, closeAfterFailure(conn, ErrProtocol{Reason: "set negotiation deadline", Cause: err})
	}

	// Cancelling ctx closes conn, which unblocks whatever read or write the
	// negotiation is in.
	interrupted := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() {
		interrupted <- conn.Close()
	})
	export, err := negotiate(ctx, conn, &cfg)
	if !stop() {
		return nil, cancelled(ctx, <-interrupted)
	}
	if err != nil {
		return nil, closeAfterFailure(conn, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, closeAfterFailure(conn, ErrProtocol{Reason: "clear negotiation deadline", Cause: err})
	}
	return export, nil
}

func negotiate(ctx context.Context, conn net.Conn, cfg *ClientConfig) (*Export, error) {
	serverFlags, err := readGreeting(conn)
	if err != nil {
		return nil, err
	}
	clientFlags := clientFlagFixedNewstyle
	if serverFlags&flagNoZeroes != 0 {
		clientFlags |= clientFlagNoZeroes
	}
	if _, err := conn.Write(binary.BigEndian.AppendUint32(nil, clientFlags)); err != nil {
		return nil, wireError("write client flags", err)
	}

	reply, err := exchange(conn, optStartTLS, nil)
	if err != nil {
		return nil, err
	}
	if reply.replyType != repAck {
		return nil, unexpectedReply(optStartTLS, reply.replyType)
	}
	tlsConn := tls.Client(conn, cfg.tlsConfig())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, ErrTLSHandshake{Cause: err}
	}
	return goExport(tlsConn)
}

// readGreeting reads the server greeting and returns its handshake flags.
func readGreeting(r io.Reader) (uint16, error) {
	var greeting [18]byte
	if _, err := io.ReadFull(r, greeting[:]); err != nil {
		return 0, wireError("read greeting", err)
	}
	if binary.BigEndian.Uint64(greeting[0:8]) != nbdMagic || binary.BigEndian.Uint64(greeting[8:16]) != optionMagic {
		return 0, ErrProtocol{Reason: "bad greeting magic"}
	}
	flags := binary.BigEndian.Uint16(greeting[16:18])
	if flags&flagFixedNewstyle == 0 {
		return 0, ErrProtocol{Reason: "server does not offer fixed newstyle"}
	}
	return flags, nil
}

// exchange sends one option and reads the first reply to it.
func exchange(rw io.ReadWriter, option uint32, data []byte) (serverReply, error) {
	msg := binary.BigEndian.AppendUint64(nil, optionMagic)
	msg = binary.BigEndian.AppendUint32(msg, option)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(data)))
	if _, err := rw.Write(append(msg, data...)); err != nil {
		return serverReply{}, wireError("write option", err)
	}
	return readOptionReply(rw, option)
}

// readOptionReply reads one reply and checks it answers option.
func readOptionReply(r io.Reader, option uint32) (serverReply, error) {
	var header [20]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return serverReply{}, wireError("read option reply", err)
	}
	if binary.BigEndian.Uint64(header[0:8]) != optionReplyMagic {
		return serverReply{}, ErrProtocol{Reason: "bad option reply magic"}
	}
	if got := binary.BigEndian.Uint32(header[8:12]); got != option {
		return serverReply{}, ErrProtocol{Reason: "reply to " + optionName(got) + " while awaiting " + optionName(option)}
	}
	length := binary.BigEndian.Uint32(header[16:20])
	if length > maxOptionLength {
		return serverReply{}, ErrProtocol{Reason: "oversized option reply"}
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return serverReply{}, wireError("read option reply data", err)
	}
	return serverReply{replyType: binary.BigEndian.Uint32(header[12:16]), data: data}, nil
}

// goExport sends NBD_OPT_GO for the empty export name, asking for the block
// size constraints, and collects the information up to the final ACK.
func goExport(conn net.Conn) (*Export, error) {
	request := binary.BigEndian.AppendUint32(nil, 0) // empty export name
	request = binary.BigEndian.AppendUint16(request, 1)
	request = binary.BigEndian.AppendUint16(request, infoBlockSize)

	export := &Export{Conn: conn}
	haveExport := false
	reply, err := exchange(conn, optGo, request)
	for {
		if err != nil {
			return nil, err
		}
		switch reply.replyType {
		case repAck:
			if !haveExport {
				return nil, ErrProtocol{Reason: "NBD_OPT_GO acknowledged without NBD_INFO_EXPORT"}
			}
			return export, nil
		case repInfo:
			isExport, infoErr := export.applyInfo(reply.data)
			if infoErr != nil {
				return nil, infoErr
			}
			haveExport = haveExport || isExport
		default:
			return nil, unexpectedReply(optGo, reply.replyType)
		}
		reply, err = readOptionReply(conn, optGo)
	}
}

// applyInfo records one NBD_REP_INFO payload and reports whether it was
// NBD_INFO_EXPORT. Information types the client did not ask for are
// ignored, as the protocol requires.
func (e *Export) applyInfo(data []byte) (bool, error) {
	if len(data) < 2 {
		return false, ErrProtocol{Reason: "truncated NBD_REP_INFO"}
	}
	switch binary.BigEndian.Uint16(data[0:2]) {
	case infoExport:
		if len(data) != 12 {
			return false, ErrProtocol{Reason: "malformed NBD_INFO_EXPORT"}
		}
		e.Size = binary.BigEndian.Uint64(data[2:10])
		e.Flags = binary.BigEndian.Uint16(data[10:12])
		return true, nil
	case infoBlockSize:
		if len(data) != 14 {
			return false, ErrProtocol{Reason: "malformed NBD_INFO_BLOCK_SIZE"}
		}
		e.MinBlockSize = binary.BigEndian.Uint32(data[2:6])
		e.PreferredBlockSize = binary.BigEndian.Uint32(data[6:10])
		e.MaxBlockSize = binary.BigEndian.Uint32(data[10:14])
	}
	return false, nil
}

// unexpectedReply is a refusal for an error reply, and a protocol error for
// any other reply type the client did not expect.
func unexpectedReply(option, replyType uint32) error {
	if replyType&repFlagError != 0 {
		return ErrServerRefused{Option: option, Reply: replyType}
	}
	return ErrProtocol{Reason: "unexpected " + replyName(replyType) + " to " + optionName(option)}
}

// wireError classifies a read or write failure: a TLS alert from the server
// rejects the handshake, anything else breaks the protocol.
func wireError(step string, err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == remoteAlertOp {
		return ErrTLSHandshake{Cause: err}
	}
	return ErrProtocol{Reason: step, Cause: err}
}

// cancelled is the error for a negotiation ctx ended. closeErr is the result
// of the close that interrupted it.
func cancelled(ctx context.Context, closeErr error) error {
	cause := context.Cause(ctx)
	if closeErr != nil && !isClosedError(closeErr) {
		cause = errors.Join(cause, closeErr)
	}
	return ErrProtocol{Reason: "negotiation cancelled", Cause: cause}
}

// closeAfterFailure closes conn after err ended the attach, keeping err the
// error the caller sees.
func closeAfterFailure(conn net.Conn, err error) error {
	if closeErr := conn.Close(); closeErr != nil && !isClosedError(closeErr) {
		return errors.Join(err, ErrProtocol{Reason: "close connection", Cause: closeErr})
	}
	return err
}
