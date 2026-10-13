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
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// nodeConfig is the attach configuration of the bundle's client: its
// certificate stands in for the IDevID.
func nodeConfig(bundle *testutil.TestTLSBundle) ClientConfig {
	return ClientConfig{
		Certificate: bundle.ClientCert,
		RootCAs:     bundle.CAPool,
		ServerName:  "localhost",
	}
}

// attachTo dials addr and attaches with cfg.
func attachTo(t *testing.T, addr string, cfg ClientConfig) (*Export, error) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return Attach(t.Context(), conn, cfg)
}

// TestAttach_ServerExport attaches to the real export server and checks the
// session is in transmission on the node's own volume.
func TestAttach_ServerExport(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))

	export, err := attachTo(t, addr, nodeConfig(bundle))
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if export.Size != testVolumeSize || export.Flags != exportFlags {
		t.Fatalf("export size %d flags %#x, want %d %#x", export.Size, export.Flags, testVolumeSize, exportFlags)
	}
	if export.MinBlockSize != 1 || export.PreferredBlockSize != preferredBlockSize || export.MaxBlockSize != maxPayload {
		t.Fatalf("block sizes %d/%d/%d", export.MinBlockSize, export.PreferredBlockSize, export.MaxBlockSize)
	}
	if _, ok := export.Conn.(*tls.Conn); !ok {
		t.Fatalf("export connection is %T, want *tls.Conn", export.Conn)
	}

	c := &testClient{t: t, conn: export.Conn}
	c.request(cmdFlush, 0, 1, 0, 0, nil)
	if code := c.simpleReply(1); code != errNone {
		t.Fatalf("FLUSH error code = %d", code)
	}
	c.request(cmdDisc, 0, 2, 0, 0, nil)
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("session ended with %v", err)
	}
}

// TestAttach_ServerRefusals drives each refusal the real server can give a
// node that negotiates correctly, and checks the node gets the typed error
// and the connection is closed.
func TestAttach_ServerRefusals(t *testing.T) {
	tests := []struct {
		name      string
		configure func(t *testing.T, server *Config, node *ClientConfig)
		check     func(t *testing.T, err error)
	}{
		{
			name: "client certificate from another CA",
			configure: func(t *testing.T, _ *Config, node *ClientConfig) {
				node.Certificate = testutil.GenerateTestTLSBundle(t).ClientCert
			},
			check: wantHandshakeError,
		},
		{
			name: "identity not a diskless-nbd node",
			configure: func(_ *testing.T, server *Config, _ *ClientConfig) {
				server.Identities = []string{"other-node"}
			},
			check: wantHandshakeError,
		},
		{
			name: "server certificate from another CA",
			configure: func(t *testing.T, _ *Config, node *ClientConfig) {
				node.RootCAs = testutil.GenerateTestTLSBundle(t).CAPool
			},
			check: wantHandshakeError,
		},
		{
			name: "server certificate for another name",
			configure: func(_ *testing.T, _ *Config, node *ClientConfig) {
				node.ServerName = "boot.example"
			},
			check: wantHandshakeError,
		},
		{
			name: "volume cannot be created",
			configure: func(t *testing.T, server *Config, _ *ClientConfig) {
				blocker := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(blocker, nil, 0o600); err != nil {
					t.Fatalf("write blocker: %v", err)
				}
				server.VolumeDir = filepath.Join(blocker, "nbd")
			},
			check: func(t *testing.T, err error) {
				wantRefusal(t, err, ErrServerRefused{Option: optGo, Reply: repErrPlatform})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := testutil.GenerateTestTLSBundle(t)
			serverCfg := testConfig(t, bundle)
			node := nodeConfig(bundle)
			tc.configure(t, &serverCfg, &node)
			addr, result := startSession(t, newTestServer(t, serverCfg))

			export, err := attachTo(t, addr, node)
			if export != nil {
				t.Fatal("Attach returned an export on a refusal")
			}
			tc.check(t, err)
			if awaitResult(t, result) == nil {
				t.Fatal("server session ended without an error")
			}
		})
	}
}

func wantHandshakeError(t *testing.T, err error) {
	t.Helper()
	var handshake ErrTLSHandshake
	if !errors.As(err, &handshake) {
		t.Fatalf("err = %v, want ErrTLSHandshake", err)
	}
}

func wantRefusal(t *testing.T, err error, want ErrServerRefused) {
	t.Helper()
	var refused ErrServerRefused
	if !errors.As(err, &refused) || refused != want {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func wantProtocolError(t *testing.T, err error) {
	t.Helper()
	var protocol ErrProtocol
	if !errors.As(err, &protocol) {
		t.Fatalf("err = %v, want ErrProtocol", err)
	}
}

// TestAttach_MissingCertificate refuses to attach without the IDevID and
// closes the connection without writing to it.
func TestAttach_MissingCertificate(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	node, server := net.Pipe()
	cfg := nodeConfig(bundle)
	cfg.Certificate = tls.Certificate{}

	_, err := Attach(t.Context(), node, cfg)
	var invalid ErrInvalidConfig
	if !errors.As(err, &invalid) || invalid.Field != "Certificate" {
		t.Fatalf("err = %v, want ErrInvalidConfig on Certificate", err)
	}
	if n, readErr := server.Read(make([]byte, 1)); !errors.Is(readErr, io.EOF) {
		t.Fatalf("peer read %d bytes, err %v; want EOF from a closed connection", n, readErr)
	}
}

func TestClientConfig_Validate(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	valid := nodeConfig(bundle)
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(valid) = %v", err)
	}
	tests := []struct {
		field  string
		mutate func(*ClientConfig)
	}{
		{"Certificate", func(c *ClientConfig) { c.Certificate.PrivateKey = nil }},
		{"RootCAs", func(c *ClientConfig) { c.RootCAs = nil }},
		{"ServerName", func(c *ClientConfig) { c.ServerName = "" }},
		{"HandshakeTimeout", func(c *ClientConfig) { c.HandshakeTimeout = -time.Second }},
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			cfg := nodeConfig(bundle)
			tc.mutate(&cfg)
			var invalid ErrInvalidConfig
			if err := cfg.Validate(); !errors.As(err, &invalid) || invalid.Field != tc.field {
				t.Fatalf("Validate = %v, want ErrInvalidConfig on %s", err, tc.field)
			}
		})
	}
}

func TestClientConfig_TLSConfig(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	cfg := nodeConfig(bundle)
	got := cfg.tlsConfig()
	if got.MinVersion != tls.VersionTLS13 || got.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS versions %#x-%#x, want TLS 1.3 only", got.MinVersion, got.MaxVersion)
	}
	if len(got.Certificates) != 1 || got.RootCAs != bundle.CAPool || got.ServerName != "localhost" {
		t.Fatalf("tls.Config does not carry the node's certificate, roots and server name")
	}
}

// scriptedPeer plays a server that misbehaves in a chosen way. Its helpers
// return errors because they run off the test goroutine.
type scriptedPeer struct {
	conn net.Conn
}

// greet sends a greeting with flags and reads the client flags.
func (p *scriptedPeer) greet(flags uint16) error {
	msg := binary.BigEndian.AppendUint64(nil, nbdMagic)
	msg = binary.BigEndian.AppendUint64(msg, optionMagic)
	msg = binary.BigEndian.AppendUint16(msg, flags)
	if _, err := p.conn.Write(msg); err != nil {
		return err
	}
	_, err := io.ReadFull(p.conn, make([]byte, 4))
	return err
}

// readOption reads one option and returns its number.
func (p *scriptedPeer) readOption() (uint32, error) {
	var header [16]byte
	if _, err := io.ReadFull(p.conn, header[:]); err != nil {
		return 0, err
	}
	_, err := io.ReadFull(p.conn, make([]byte, binary.BigEndian.Uint32(header[12:16])))
	return binary.BigEndian.Uint32(header[8:12]), err
}

func (p *scriptedPeer) reply(option, replyType uint32, data []byte) error {
	msg := binary.BigEndian.AppendUint64(nil, optionReplyMagic)
	msg = binary.BigEndian.AppendUint32(msg, option)
	msg = binary.BigEndian.AppendUint32(msg, replyType)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(data)))
	_, err := p.conn.Write(append(msg, data...))
	return err
}

// startTLS acknowledges STARTTLS and runs the server handshake.
func (p *scriptedPeer) startTLS(bundle *testutil.TestTLSBundle) error {
	if _, err := p.readOption(); err != nil {
		return err
	}
	if err := p.reply(optStartTLS, repAck, nil); err != nil {
		return err
	}
	tlsConn := tls.Server(p.conn, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{bundle.ServerCert},
	})
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	p.conn = tlsConn
	return nil
}

// answerGo completes STARTTLS and answers NBD_OPT_GO with replies.
func answerGo(bundle *testutil.TestTLSBundle, replies ...serverReply) func(*scriptedPeer) error {
	return func(p *scriptedPeer) error {
		if err := p.greet(flagFixedNewstyle | flagNoZeroes); err != nil {
			return err
		}
		if err := p.startTLS(bundle); err != nil {
			return err
		}
		if _, err := p.readOption(); err != nil {
			return err
		}
		for _, r := range replies {
			if err := p.reply(optGo, r.replyType, r.data); err != nil {
				return err
			}
		}
		return nil
	}
}

func exportInfo(size uint64) []byte {
	data := binary.BigEndian.AppendUint16(nil, infoExport)
	data = binary.BigEndian.AppendUint64(data, size)
	return binary.BigEndian.AppendUint16(data, exportFlags)
}

// runScripted attaches against script over an in-memory pipe and returns
// Attach's result once the peer has finished.
func runScripted(t *testing.T, ctx context.Context, cfg ClientConfig, script func(*scriptedPeer) error) (*Export, error) {
	t.Helper()
	node, server := net.Pipe()
	t.Cleanup(func() {
		if err := server.Close(); err != nil && !isClosedError(err) {
			t.Errorf("peer close: %v", err)
		}
	})
	peerDone := make(chan error, 1)
	go func() {
		peerDone <- script(&scriptedPeer{conn: server})
	}()
	export, err := Attach(ctx, node, cfg)
	select {
	case <-peerDone:
	case <-time.After(sessionTimeout):
		t.Fatal("scripted peer did not finish")
	}
	return export, err
}

// TestAttach_ScriptedRefusals covers the refusals and protocol breaks the
// in-repo server never produces, so a peer scripts them.
func TestAttach_ScriptedRefusals(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	answerStartTLS := func(replyType uint32) func(*scriptedPeer) error {
		return func(p *scriptedPeer) error {
			if err := p.greet(flagFixedNewstyle | flagNoZeroes); err != nil {
				return err
			}
			if _, err := p.readOption(); err != nil {
				return err
			}
			return p.reply(optStartTLS, replyType, nil)
		}
	}
	tests := []struct {
		name   string
		script func(*scriptedPeer) error
		check  func(t *testing.T, err error)
	}{
		{
			name:   "STARTTLS unsupported",
			script: answerStartTLS(repErrUnsup),
			check: func(t *testing.T, err error) {
				wantRefusal(t, err, ErrServerRefused{Option: optStartTLS, Reply: repErrUnsup})
			},
		},
		{
			name:   "STARTTLS refused by policy",
			script: answerStartTLS(repErrPolicy),
			check: func(t *testing.T, err error) {
				wantRefusal(t, err, ErrServerRefused{Option: optStartTLS, Reply: repErrPolicy})
			},
		},
		{
			name:   "GO refused by policy",
			script: answerGo(bundle, serverReply{replyType: repErrPolicy}),
			check: func(t *testing.T, err error) {
				wantRefusal(t, err, ErrServerRefused{Option: optGo, Reply: repErrPolicy})
			},
		},
		{
			name:   "GO for an unknown export",
			script: answerGo(bundle, serverReply{replyType: repErrUnknown}),
			check: func(t *testing.T, err error) {
				wantRefusal(t, err, ErrServerRefused{Option: optGo, Reply: repErrUnknown})
			},
		},
		{
			name:   "TLS required after TLS",
			script: answerGo(bundle, serverReply{replyType: repErrTLSReqd}),
			check: func(t *testing.T, err error) {
				wantRefusal(t, err, ErrServerRefused{Option: optGo, Reply: repErrTLSReqd})
			},
		},
		{
			name:   "GO acknowledged without export information",
			script: answerGo(bundle, serverReply{replyType: repAck}),
			check:  wantProtocolError,
		},
		{
			name:   "malformed export information",
			script: answerGo(bundle, serverReply{replyType: repInfo, data: exportInfo(testVolumeSize)[:11]}),
			check:  wantProtocolError,
		},
		{
			name: "connection closed after STARTTLS",
			script: func(p *scriptedPeer) error {
				if err := p.greet(flagFixedNewstyle); err != nil {
					return err
				}
				if _, err := p.readOption(); err != nil {
					return err
				}
				return p.conn.Close()
			},
			check: func(t *testing.T, err error) {
				wantProtocolError(t, err)
				if !errors.Is(err, io.EOF) {
					t.Fatalf("err = %v, want it to wrap io.EOF", err)
				}
			},
		},
		{
			name: "server without fixed newstyle",
			script: func(p *scriptedPeer) error {
				msg := binary.BigEndian.AppendUint64(nil, nbdMagic)
				msg = binary.BigEndian.AppendUint64(msg, optionMagic)
				_, err := p.conn.Write(binary.BigEndian.AppendUint16(msg, 0))
				return err
			},
			check: wantProtocolError,
		},
		{
			name: "oldstyle greeting",
			script: func(p *scriptedPeer) error {
				_, err := p.conn.Write(make([]byte, 18))
				return err
			},
			check: wantProtocolError,
		},
		{
			name:   "STARTTLS answered with information",
			script: answerStartTLS(repInfo),
			check:  wantProtocolError,
		},
		{
			name: "bad option reply magic",
			script: func(p *scriptedPeer) error {
				if err := p.greet(flagFixedNewstyle); err != nil {
					return err
				}
				if _, err := p.readOption(); err != nil {
					return err
				}
				_, err := p.conn.Write(make([]byte, 20))
				return err
			},
			check: wantProtocolError,
		},
		{
			name: "oversized option reply",
			script: func(p *scriptedPeer) error {
				if err := p.greet(flagFixedNewstyle); err != nil {
					return err
				}
				if _, err := p.readOption(); err != nil {
					return err
				}
				msg := binary.BigEndian.AppendUint64(nil, optionReplyMagic)
				msg = binary.BigEndian.AppendUint32(msg, optStartTLS)
				msg = binary.BigEndian.AppendUint32(msg, repAck)
				_, err := p.conn.Write(binary.BigEndian.AppendUint32(msg, maxOptionLength+1))
				return err
			},
			check: wantProtocolError,
		},
		{
			name: "reply to another option",
			script: func(p *scriptedPeer) error {
				if err := p.greet(flagFixedNewstyle | flagNoZeroes); err != nil {
					return err
				}
				if _, err := p.readOption(); err != nil {
					return err
				}
				return p.reply(optGo, repAck, nil)
			},
			check: wantProtocolError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			export, err := runScripted(t, t.Context(), nodeConfig(bundle), tc.script)
			if export != nil {
				t.Fatal("Attach returned an export")
			}
			tc.check(t, err)
		})
	}
}

// TestAttach_IgnoresUnrequestedInformation accepts information types the
// node did not ask for, as the protocol requires.
func TestAttach_IgnoresUnrequestedInformation(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	name := binary.BigEndian.AppendUint16(nil, infoName)
	name = append(name, "node"...)
	script := answerGo(bundle,
		serverReply{replyType: repInfo, data: name},
		serverReply{replyType: repInfo, data: exportInfo(4096)},
		serverReply{replyType: repAck},
	)
	export, err := runScripted(t, t.Context(), nodeConfig(bundle), script)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if export.Size != 4096 || export.MaxBlockSize != 0 {
		t.Fatalf("export size %d max block %d, want 4096 and no block-size information", export.Size, export.MaxBlockSize)
	}
}

// TestAttach_Cancelled ends a negotiation the server never answers when the
// context is cancelled.
func TestAttach_Cancelled(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	ctx, cancel := context.WithCancel(t.Context())
	silent := func(p *scriptedPeer) error {
		cancel()
		_, err := p.conn.Read(make([]byte, 1))
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	_, err := runScripted(t, ctx, nodeConfig(bundle), silent)
	wantProtocolError(t, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want it to wrap context.Canceled", err)
	}
}

// TestAttach_Timeout ends a negotiation the server never answers when
// HandshakeTimeout passes.
func TestAttach_Timeout(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	cfg := nodeConfig(bundle)
	cfg.HandshakeTimeout = 50 * time.Millisecond
	silent := func(p *scriptedPeer) error {
		_, err := p.conn.Read(make([]byte, 1))
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	_, err := runScripted(t, t.Context(), cfg, silent)
	wantProtocolError(t, err)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want it to wrap os.ErrDeadlineExceeded", err)
	}
}

func TestExport_ApplyInfo(t *testing.T) {
	blockSize := binary.BigEndian.AppendUint16(nil, infoBlockSize)
	blockSize = binary.BigEndian.AppendUint32(blockSize, 512)
	blockSize = binary.BigEndian.AppendUint32(blockSize, 4096)
	blockSize = binary.BigEndian.AppendUint32(blockSize, 1<<20)

	var export Export
	if isExport, err := export.applyInfo(exportInfo(8192)); err != nil || !isExport {
		t.Fatalf("applyInfo(export) = %v, %v", isExport, err)
	}
	if isExport, err := export.applyInfo(blockSize); err != nil || isExport {
		t.Fatalf("applyInfo(block size) = %v, %v", isExport, err)
	}
	if export.Size != 8192 || export.MinBlockSize != 512 || export.PreferredBlockSize != 4096 || export.MaxBlockSize != 1<<20 {
		t.Fatalf("export = %+v", export)
	}

	for name, data := range map[string][]byte{
		"truncated":            {0},
		"short export":         exportInfo(1)[:10],
		"long block size info": append(blockSize, 0),
	} {
		if _, err := export.applyInfo(data); err == nil {
			t.Errorf("%s: applyInfo accepted %x", name, data)
		}
	}
}
