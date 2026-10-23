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
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

const (
	testIdentity   = "test-client"
	testVolumeSize = 1 << 20

	// deadlineGrace is how long before the test binary's -timeout a wait
	// gives up, so the test fails with its own message rather than the
	// binary's timeout panic.
	deadlineGrace = 5 * time.Second
)

// staticAnchor returns a platform anchor that always yields ca.
func staticAnchor(t *testing.T, ca *x509.Certificate) *trust.Anchor {
	t.Helper()
	anchor, err := trust.NewAnchor(trust.AnchorSourceFunc(func(context.Context) ([]*x509.Certificate, error) {
		return []*x509.Certificate{ca}, nil
	}))
	if err != nil {
		t.Fatalf("NewAnchor: %v", err)
	}
	return anchor
}

// testConfig returns a valid server configuration for bundle's CA that
// exports one volume to the bundle's client identity.
func testConfig(t *testing.T, bundle *testutil.TestTLSBundle) Config {
	t.Helper()
	return Config{
		Certificate: bundle.ServerCert,
		Anchor:      staticAnchor(t, bundle.CACert),
		Identities:  []string{testIdentity},
		VolumeDir:   t.TempDir(),
		VolumeSize:  testVolumeSize,
		Logger:      slog.New(slog.DiscardHandler),
	}
}

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server
}

// startSession serves exactly one connection on a loopback listener and
// delivers serveConn's result on the returned channel.
func startSession(t *testing.T, server *Server) (string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			result <- err
			return
		}
		result <- server.serveConn(t.Context(), conn)
		server.closeConn(conn)
	}()
	t.Cleanup(func() {
		if err := ln.Close(); err != nil && !isClosedError(err) {
			t.Errorf("listener close: %v", err)
		}
		<-done
	})
	return ln.Addr().String(), result
}

// awaitResult waits for the session's outcome.
func awaitResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-untilDeadline(t):
		t.Fatal("session did not end before the test deadline")
		return nil
	}
}

// untilDeadline fires shortly before the test binary's deadline. A session
// ends in milliseconds, but under -race on a loaded runner its fsync and TLS
// close can take longer than any fixed budget, so only the binary's own
// -timeout bounds the wait. Without a deadline (-timeout 0) it never fires.
func untilDeadline(t *testing.T) <-chan time.Time {
	t.Helper()
	deadline, ok := t.Deadline()
	if !ok {
		return nil
	}
	return time.After(time.Until(deadline) - deadlineGrace)
}

// clientTLS is the configuration of a node presenting cert and verifying
// the server against roots.
func clientTLS(roots *x509.CertPool, cert *tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: "localhost",
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
}

// testClient is a minimal NBD client driving the server over the wire.
type testClient struct {
	t    *testing.T
	conn net.Conn
}

type optionReply struct {
	option    uint32
	replyType uint32
	data      []byte
}

// dialClient connects, checks the greeting and sends clientFlags.
func dialClient(t *testing.T, addr string, clientFlags uint32) *testClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := &testClient{t: t, conn: conn}
	t.Cleanup(func() {
		if err := c.conn.Close(); err != nil && !isClosedError(err) {
			t.Logf("client close: %v", err)
		}
	})

	greeting := c.readFull(18)
	if binary.BigEndian.Uint64(greeting[0:8]) != nbdMagic || binary.BigEndian.Uint64(greeting[8:16]) != optionMagic {
		t.Fatalf("bad greeting % x", greeting)
	}
	if flags := binary.BigEndian.Uint16(greeting[16:18]); flags != flagFixedNewstyle|flagNoZeroes {
		t.Fatalf("greeting flags = %#x", flags)
	}
	c.write(binary.BigEndian.AppendUint32(nil, clientFlags))
	return c
}

func (c *testClient) write(data []byte) {
	c.t.Helper()
	if _, err := c.conn.Write(data); err != nil {
		c.t.Fatalf("client write: %v", err)
	}
}

func (c *testClient) readFull(n int) []byte {
	c.t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		c.t.Fatalf("client read: %v", err)
	}
	return buf
}

func (c *testClient) sendOption(option uint32, data []byte) {
	c.t.Helper()
	msg := binary.BigEndian.AppendUint64(nil, optionMagic)
	msg = binary.BigEndian.AppendUint32(msg, option)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(data)))
	c.write(append(msg, data...))
}

func (c *testClient) readReply() optionReply {
	c.t.Helper()
	header := c.readFull(20)
	if binary.BigEndian.Uint64(header[0:8]) != optionReplyMagic {
		c.t.Fatalf("bad option reply magic % x", header[0:8])
	}
	return optionReply{
		option:    binary.BigEndian.Uint32(header[8:12]),
		replyType: binary.BigEndian.Uint32(header[12:16]),
		data:      c.readFull(int(binary.BigEndian.Uint32(header[16:20]))),
	}
}

// startTLS negotiates STARTTLS and runs the client handshake.
func (c *testClient) startTLS(cfg *tls.Config) {
	c.t.Helper()
	c.sendOption(optStartTLS, nil)
	if reply := c.readReply(); reply.replyType != repAck {
		c.t.Fatalf("STARTTLS reply type = %#x", reply.replyType)
	}
	tlsConn := tls.Client(c.conn, cfg)
	if err := tlsConn.HandshakeContext(c.t.Context()); err != nil {
		c.t.Fatalf("client handshake: %v", err)
	}
	c.conn = tlsConn
}

// infoRequest encodes the data of NBD_OPT_INFO and NBD_OPT_GO.
func infoRequest(name string, requests ...uint16) []byte {
	data := binary.BigEndian.AppendUint32(nil, uint32(len(name)))
	data = append(data, name...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(requests)))
	for _, request := range requests {
		data = binary.BigEndian.AppendUint16(data, request)
	}
	return data
}

// describe sends INFO or GO and collects replies up to the final ACK or
// error reply.
func (c *testClient) describe(option uint32, name string, requests ...uint16) []optionReply {
	c.t.Helper()
	c.sendOption(option, infoRequest(name, requests...))
	var replies []optionReply
	for {
		reply := c.readReply()
		replies = append(replies, reply)
		if reply.replyType == repAck || reply.replyType&repFlagError != 0 {
			return replies
		}
	}
}

// attach runs STARTTLS with the bundle's client certificate and GO for the
// default export, leaving the client in transmission.
func attach(t *testing.T, addr string, bundle *testutil.TestTLSBundle) *testClient {
	t.Helper()
	c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
	c.startTLS(clientTLS(bundle.CAPool, &bundle.ClientCert))
	replies := c.describe(optGo, "")
	if last := replies[len(replies)-1]; last.replyType != repAck {
		t.Fatalf("GO reply type = %#x", last.replyType)
	}
	return c
}

// request sends one transmission request.
func (c *testClient) request(command, flags uint16, handle, offset uint64, length uint32, payload []byte) {
	c.t.Helper()
	msg := binary.BigEndian.AppendUint32(nil, requestMagic)
	msg = binary.BigEndian.AppendUint16(msg, flags)
	msg = binary.BigEndian.AppendUint16(msg, command)
	msg = binary.BigEndian.AppendUint64(msg, handle)
	msg = binary.BigEndian.AppendUint64(msg, offset)
	msg = binary.BigEndian.AppendUint32(msg, length)
	c.write(append(msg, payload...))
}

// simpleReply reads one reply header and checks its handle.
func (c *testClient) simpleReply(handle uint64) uint32 {
	c.t.Helper()
	header := c.readFull(16)
	if magic := binary.BigEndian.Uint32(header[0:4]); magic != simpleReplyMagic {
		c.t.Fatalf("reply magic = %#x", magic)
	}
	if got := binary.BigEndian.Uint64(header[8:16]); got != handle {
		c.t.Fatalf("reply handle = %d, want %d", got, handle)
	}
	return binary.BigEndian.Uint32(header[4:8])
}

// expectClosed asserts that the server ended the connection.
func (c *testClient) expectClosed() {
	c.t.Helper()
	var buf [1]byte
	if n, err := c.conn.Read(buf[:]); err == nil {
		c.t.Fatalf("read %d bytes from a connection the server should have closed", n)
	}
}
