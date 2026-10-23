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
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

func TestTransmission_WriteReadFlushTrimDisconnect(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))
	c := attach(t, addr, bundle)

	const offset, length = 8192, 4096
	written := bytes.Repeat([]byte{0xa5}, length)
	c.request(cmdWrite, cmdFlagFUA, 1, offset, length, written)
	if code := c.simpleReply(1); code != errNone {
		t.Fatalf("WRITE error = %d", code)
	}

	c.request(cmdRead, 0, 2, offset, length, nil)
	if code := c.simpleReply(2); code != errNone {
		t.Fatalf("READ error = %d", code)
	}
	if got := c.readFull(length); !bytes.Equal(got, written) {
		t.Fatal("READ did not return what was written")
	}

	c.request(cmdFlush, 0, 3, 0, 0, nil)
	if code := c.simpleReply(3); code != errNone {
		t.Fatalf("FLUSH error = %d", code)
	}

	c.request(cmdTrim, 0, 4, offset, length, nil)
	if code := c.simpleReply(4); code != errNone {
		t.Fatalf("TRIM error = %d", code)
	}
	c.request(cmdRead, 0, 5, offset, length, nil)
	if code := c.simpleReply(5); code != errNone {
		t.Fatalf("READ after TRIM error = %d", code)
	}
	if got := c.readFull(length); !bytes.Equal(got, make([]byte, length)) {
		t.Fatal("trimmed range does not read back as zeros")
	}

	c.request(cmdDisc, 0, 6, 0, 0, nil)
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("session error = %v", err)
	}
	// DISC gets no reply; the server sends close_notify and the client
	// sees a clean end of stream.
	if _, err := c.conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read after DISC = %v, want io.EOF", err)
	}
}

func TestTransmission_DataPersistsAcrossAttaches(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	server := newTestServer(t, testConfig(t, bundle))
	written := []byte("persisted block")

	addr, result := startSession(t, server)
	first := attach(t, addr, bundle)
	first.request(cmdWrite, 0, 1, 0, uint32(len(written)), written)
	if code := first.simpleReply(1); code != errNone {
		t.Fatalf("WRITE error = %d", code)
	}
	first.request(cmdDisc, 0, 2, 0, 0, nil)
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("first session error = %v", err)
	}

	addr, result = startSession(t, server)
	second := attach(t, addr, bundle)
	second.request(cmdRead, 0, 1, 0, uint32(len(written)), nil)
	if code := second.simpleReply(1); code != errNone {
		t.Fatalf("READ error = %d", code)
	}
	if got := second.readFull(len(written)); !bytes.Equal(got, written) {
		t.Fatalf("second attach read %q, want %q", got, written)
	}
	second.request(cmdDisc, 0, 2, 0, 0, nil)
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("second session error = %v", err)
	}
}

func TestTransmission_RefusedRequestsGetErrorCodes(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))
	c := attach(t, addr, bundle)

	tests := []struct {
		name    string
		command uint16
		flags   uint16
		offset  uint64
		length  uint32
		payload []byte
		want    uint32
	}{
		{name: "read past the end", command: cmdRead, offset: testVolumeSize - 1, length: 2, want: errInval},
		{name: "read over the payload limit", command: cmdRead, length: maxPayload + 1, want: errInval},
		{name: "read with unknown flags", command: cmdRead, flags: 0x8000, length: 1, want: errInval},
		{name: "write past the end", command: cmdWrite, offset: testVolumeSize, length: 1, payload: []byte{1}, want: errNoSpc},
		{name: "write with unknown flags", command: cmdWrite, flags: 0x8000, length: 1, payload: []byte{1}, want: errInval},
		{name: "write over the payload limit", command: cmdWrite, length: maxPayload + 1, payload: make([]byte, maxPayload+1), want: errInval},
		{name: "trim past the end", command: cmdTrim, offset: testVolumeSize, length: 1, want: errInval},
		{name: "trim with offset overflow", command: cmdTrim, offset: ^uint64(0), length: 2, want: errInval},
		{name: "flush with unknown flags", command: cmdFlush, flags: 0x8000, want: errInval},
		{name: "unknown command", command: 42, want: errInval},
	}
	for i, tc := range tests {
		handle := uint64(i + 1)
		c.request(tc.command, tc.flags, handle, tc.offset, tc.length, tc.payload)
		if code := c.simpleReply(handle); code != tc.want {
			t.Errorf("%s: error = %d, want %d", tc.name, code, tc.want)
		}
	}

	// The session survives every refusal.
	c.request(cmdTrim, 0, 99, 0, 0, nil)
	if code := c.simpleReply(99); code != errNone {
		t.Fatalf("empty TRIM error = %d", code)
	}
	c.request(cmdDisc, 0, 100, 0, 0, nil)
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("session error = %v", err)
	}
}

func TestTransmission_BadRequestMagicEndsTheSession(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))
	c := attach(t, addr, bundle)

	c.write(make([]byte, requestHeaderLength))
	if err := awaitResult(t, result); !errors.As(err, new(ErrProtocol)) {
		t.Fatalf("session error = %v, want ErrProtocol", err)
	}
	c.expectClosed()
}

func TestTransmission_TruncatedWritePayloadEndsTheSession(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))
	c := attach(t, addr, bundle)

	c.request(cmdWrite, 0, 1, 0, 16, []byte("short"))
	if err := c.conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := awaitResult(t, result); !errors.As(err, new(ErrProtocol)) {
		t.Fatalf("session error = %v, want ErrProtocol", err)
	}
}

func TestTransmission_VolumeFailuresAreEIO(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "node-01"+volumeSuffix))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	tr := &transmission{
		conn:     serverConn,
		identity: "node-01",
		vol:      &volume{file: file, size: 4096},
		logger:   slog.New(slog.DiscardHandler),
	}
	result := make(chan error, 1)
	go func() { result <- tr.run() }()
	c := &testClient{t: t, conn: clientConn}
	t.Cleanup(func() {
		if err := clientConn.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	requests := []struct {
		name    string
		command uint16
		flags   uint16
		length  uint32
		payload []byte
	}{
		{name: "read", command: cmdRead, length: 512},
		{name: "write", command: cmdWrite, length: 1, payload: []byte{1}},
		{name: "flush", command: cmdFlush},
		{name: "trim", command: cmdTrim, length: 512},
	}
	for i, req := range requests {
		handle := uint64(i + 1)
		c.request(req.command, req.flags, handle, 0, req.length, req.payload)
		if code := c.simpleReply(handle); code != errIO {
			t.Errorf("%s on a failed volume: error = %d, want EIO", req.name, code)
		}
	}

	// DISC cannot make the volume durable, so the session ends with the
	// volume error rather than a clean disconnect.
	c.request(cmdDisc, 0, 9, 0, 0, nil)
	var failed ErrVolume
	if err := awaitResult(t, result); !errors.As(err, &failed) || failed.Op != "sync" {
		t.Fatalf("session error = %v, want ErrVolume sync", err)
	}
}
