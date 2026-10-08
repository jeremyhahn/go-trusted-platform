// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package vici

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeCharon plays charon's side of a VICI session from a script.
type fakeCharon struct {
	t  *testing.T
	nc net.Conn
}

// expect reads the next packet and checks its type and name; on a mismatch
// it fails the test and closes the pipe so the client side unblocks.
func (f *fakeCharon) expect(kind byte, name string) *Message {
	f.t.Helper()
	p, err := readPacket(f.nc)
	if err != nil {
		f.t.Errorf("fake charon: read: %v", err)
		f.close()
		return nil
	}
	if p.kind != kind || p.name != name {
		f.t.Errorf("fake charon: got packet %d %q, want %d %q", p.kind, p.name, kind, name)
		f.close()
		return nil
	}
	return p.message
}

func (f *fakeCharon) send(kind byte, name string, msg *Message) {
	f.t.Helper()
	if err := writePacket(f.nc, kind, name, msg); err != nil {
		f.t.Errorf("fake charon: write: %v", err)
	}
}

func (f *fakeCharon) event(name string, kv ...string) {
	m := NewMessage()
	for i := 0; i+1 < len(kv); i += 2 {
		m.SetValue(kv[i], kv[i+1])
	}
	f.send(pktEvent, name, m)
}

func (f *fakeCharon) close() {
	if err := f.nc.Close(); err != nil {
		f.t.Errorf("fake charon: close: %v", err)
	}
}

// startCharon connects a client Conn to a fake charon running script and
// returns a channel closed when the script finishes.
func startCharon(t *testing.T, script func(f *fakeCharon)) (*Conn, <-chan struct{}) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		script(&fakeCharon{t: t, nc: server})
	}()
	c := NewConn(client)
	t.Cleanup(func() {
		if !c.Closed() {
			if err := c.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}
		if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close server pipe: %v", err)
		}
		<-done
	})
	return c, done
}

func response(kv ...string) *Message {
	m := NewMessage()
	for i := 0; i+1 < len(kv); i += 2 {
		m.SetValue(kv[i], kv[i+1])
	}
	return m
}

func TestCallReturnsResponse(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		req := f.expect(pktCmdRequest, "load-conn")
		if req == nil {
			return
		}
		if _, ok := req.Section("vtep-10.0.0.2"); !ok {
			f.t.Errorf("load-conn request lost its connection section: %v", req.Keys())
		}
		f.send(pktCmdResponse, "", response("success", "yes"))
	})
	req := NewMessage()
	req.SetSection("vtep-10.0.0.2", NewMessage())

	resp, err := c.Call(context.Background(), "load-conn", req)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if v, _ := resp.Value("success"); v != "yes" {
		t.Fatalf("success = %q", v)
	}
	<-done
}

func TestCallWithoutSuccessKeySucceeds(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktCmdRequest, "version") == nil {
			return
		}
		f.send(pktCmdResponse, "", response("daemon", "charon", "version", "6.0.1"))
	})
	resp, err := c.Call(context.Background(), "version", nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if v, _ := resp.Value("version"); v != "6.0.1" {
		t.Fatalf("version = %q", v)
	}
	<-done
}

func TestCallRefusedReturnsCommandErrorAndStaysUsable(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktCmdRequest, "load-cert") == nil {
			return
		}
		f.send(pktCmdResponse, "", response("success", "no", "errmsg", "parsing X509 certificate failed"))
		if f.expect(pktCmdRequest, "version") == nil {
			return
		}
		f.send(pktCmdResponse, "", response("version", "6.0.1"))
	})

	resp, err := c.Call(context.Background(), "load-cert", nil)
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("err = %v, want *CommandError", err)
	}
	if cmdErr.Command != "load-cert" || cmdErr.Message != "parsing X509 certificate failed" {
		t.Fatalf("CommandError = %+v", cmdErr)
	}
	if resp == nil {
		t.Fatal("a refused command must still return its response")
	}
	if _, err := c.Call(context.Background(), "version", nil); err != nil {
		t.Fatalf("connection unusable after a refused command: %v", err)
	}
	<-done
}

func TestCallUnknownCommandStaysUsable(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktCmdRequest, "no-such-command") == nil {
			return
		}
		f.send(pktCmdUnknown, "", nil)
		if f.expect(pktCmdRequest, "version") == nil {
			return
		}
		f.send(pktCmdResponse, "", response())
	})

	if _, err := c.Call(context.Background(), "no-such-command", nil); !errors.Is(err, ErrUnknownCommand) {
		t.Fatalf("err = %v, want ErrUnknownCommand", err)
	}
	if _, err := c.Call(context.Background(), "version", nil); err != nil {
		t.Fatalf("connection unusable after CMD_UNKNOWN: %v", err)
	}
	<-done
}

func TestCallRejectsInvalidRequestsWithoutClosing(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktCmdRequest, "version") == nil {
			return
		}
		f.send(pktCmdResponse, "", response())
	})

	if _, err := c.Call(context.Background(), "", nil); !errors.Is(err, ErrEmptyName) {
		t.Fatalf("empty command: err = %v, want ErrEmptyName", err)
	}
	bad := NewMessage()
	bad.SetBytes("blob", make([]byte, 70000))
	var encErr *EncodeError
	if _, err := c.Call(context.Background(), "load-cert", bad); !errors.As(err, &encErr) {
		t.Fatalf("oversized value: err = %v, want *EncodeError", err)
	}
	if _, err := c.Call(context.Background(), "version", nil); err != nil {
		t.Fatalf("connection unusable after a request that never left: %v", err)
	}
	<-done
}

func TestCallStreamingDeliversEventsAndQueuesOthers(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktEventRegister, "list-sa") == nil {
			return
		}
		f.send(pktEventConfirm, "", nil)
		if f.expect(pktCmdRequest, "list-sas") == nil {
			return
		}
		f.event("list-sa", "uniqueid", "1")
		f.event("ike-updown", "up", "yes")
		f.event("list-sa", "uniqueid", "2")
		f.send(pktCmdResponse, "", response())
		if f.expect(pktEventUnregister, "list-sa") == nil {
			return
		}
		f.send(pktEventConfirm, "", nil)
	})

	var ids []string
	_, err := c.CallStreaming(context.Background(), "list-sas", "list-sa", nil, func(m *Message) error {
		id, _ := m.Value("uniqueid")
		ids = append(ids, id)
		return nil
	})
	if err != nil {
		t.Fatalf("CallStreaming: %v", err)
	}
	if strings.Join(ids, ",") != "1,2" {
		t.Fatalf("streamed ids = %v, want [1 2]", ids)
	}
	<-done

	// The interleaved ike-updown was queued, not dropped.
	ev, err := c.NextEvent(context.Background())
	if err != nil {
		t.Fatalf("NextEvent: %v", err)
	}
	if ev.Name != "ike-updown" {
		t.Fatalf("queued event = %q, want ike-updown", ev.Name)
	}
}

func TestCallStreamingCallbackErrorDrainsStream(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktEventRegister, "list-sa") == nil {
			return
		}
		f.send(pktEventConfirm, "", nil)
		if f.expect(pktCmdRequest, "list-sas") == nil {
			return
		}
		f.event("list-sa", "uniqueid", "1")
		f.event("list-sa", "uniqueid", "2")
		f.send(pktCmdResponse, "", response())
		if f.expect(pktEventUnregister, "list-sa") == nil {
			return
		}
		f.send(pktEventConfirm, "", nil)
		if f.expect(pktCmdRequest, "version") == nil {
			return
		}
		f.send(pktCmdResponse, "", response())
	})

	stop := errors.New("stop")
	calls := 0
	_, err := c.CallStreaming(context.Background(), "list-sas", "list-sa", nil, func(*Message) error {
		calls++
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("err = %v, want the callback's error", err)
	}
	if calls != 1 {
		t.Fatalf("callback ran %d times after failing, want 1", calls)
	}
	if _, err := c.Call(context.Background(), "version", nil); err != nil {
		t.Fatalf("connection out of step after a callback error: %v", err)
	}
	<-done
}

func TestCallStreamingUnknownCommandUnregisters(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktEventRegister, "list-sa") == nil {
			return
		}
		f.send(pktEventConfirm, "", nil)
		if f.expect(pktCmdRequest, "list-sas") == nil {
			return
		}
		f.send(pktCmdUnknown, "", nil)
		if f.expect(pktEventUnregister, "list-sa") == nil {
			return
		}
		f.send(pktEventConfirm, "", nil)
	})

	_, err := c.CallStreaming(context.Background(), "list-sas", "list-sa", nil, func(*Message) error { return nil })
	if !errors.Is(err, ErrUnknownCommand) {
		t.Fatalf("err = %v, want ErrUnknownCommand", err)
	}
	<-done
}

func TestSubscribeAndNextEvent(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktEventRegister, "ike-updown") == nil {
			return
		}
		f.send(pktEventConfirm, "", nil)
		// An event for the first name arrives before the second
		// registration is confirmed.
		if f.expect(pktEventRegister, "child-updown") == nil {
			return
		}
		f.event("ike-updown", "up", "yes")
		f.send(pktEventConfirm, "", nil)
		f.event("child-updown", "up", "yes")
	})

	if err := c.Subscribe(context.Background(), "ike-updown", "child-updown"); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	for _, want := range []string{"ike-updown", "child-updown"} {
		ev, err := c.NextEvent(context.Background())
		if err != nil {
			t.Fatalf("NextEvent: %v", err)
		}
		if ev.Name != want {
			t.Fatalf("event = %q, want %q", ev.Name, want)
		}
		if up, _ := ev.Message.Value("up"); up != "yes" {
			t.Fatalf("event payload lost: %v", ev.Message.Keys())
		}
	}
	<-done
}

func TestSubscribeUnknownEvent(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktEventRegister, "no-such-event") == nil {
			return
		}
		f.send(pktEventUnknown, "", nil)
	})
	if err := c.Subscribe(context.Background(), "no-such-event"); !errors.Is(err, ErrUnknownEvent) {
		t.Fatalf("err = %v, want ErrUnknownEvent", err)
	}
	if c.Closed() {
		t.Fatal("an unknown event closed the connection")
	}
	if err := c.Subscribe(context.Background(), ""); !errors.Is(err, ErrEmptyName) {
		t.Fatalf("empty event: err = %v, want ErrEmptyName", err)
	}
	<-done
}

func TestUnsubscribe(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktEventUnregister, "ike-updown") == nil {
			return
		}
		f.send(pktEventConfirm, "", nil)
	})
	if err := c.Unsubscribe(context.Background(), "ike-updown"); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
	<-done
}

func TestCancelMidExchangeClosesConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c, _ := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktCmdRequest, "version") == nil {
			return
		}
		// The client is now waiting for the response; charon stays
		// silent and the client gives up.
		cancel()
		var buf [1]byte
		if _, err := f.nc.Read(buf[:]); err == nil {
			f.t.Error("fake charon: client wrote after cancelling")
		}
	})
	_, err := c.Call(ctx, "version", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if !c.Closed() {
		t.Fatal("a cancelled read left the connection open")
	}
	if _, err := c.Call(context.Background(), "version", nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Call after cancel: err = %v, want ErrClosed", err)
	}
}

func TestAcquireHonoursContext(t *testing.T) {
	c, _ := startCharon(t, func(f *fakeCharon) {
		var buf [1]byte
		if _, err := f.nc.Read(buf[:]); err == nil {
			f.t.Error("fake charon: unexpected client write")
		}
	})

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Call(cancelled, "version", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Call with an ended context: err = %v, want context.Canceled", err)
	}
	if c.Closed() {
		t.Fatal("a context that ended before the exchange closed the connection")
	}

	// Another exchange owns the slot: the wait ends with the context.
	c.sem <- struct{}{}
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if _, err := c.Call(ctx, "version", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Call while busy: err = %v, want context.DeadlineExceeded", err)
	}
	<-c.sem
	if c.Closed() {
		t.Fatal("waiting for the slot closed the connection")
	}
}

func TestUnexpectedPacketClosesConn(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktCmdRequest, "version") == nil {
			return
		}
		f.send(pktEventConfirm, "", nil)
	})
	if _, err := c.Call(context.Background(), "version", nil); !errors.Is(err, ErrUnexpectedPacket) {
		t.Fatalf("err = %v, want ErrUnexpectedPacket", err)
	}
	if !c.Closed() {
		t.Fatal("a protocol violation left the connection open")
	}
	<-done
}

func TestMalformedResponseClosesConn(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktCmdRequest, "version") == nil {
			return
		}
		// A response whose message has an unknown element type.
		if _, err := f.nc.Write([]byte{0, 0, 0, 2, pktCmdResponse, 9}); err != nil {
			f.t.Errorf("fake charon: write: %v", err)
		}
	})
	var decErr *DecodeError
	if _, err := c.Call(context.Background(), "version", nil); !errors.As(err, &decErr) {
		t.Fatalf("err = %v, want *DecodeError", err)
	}
	if !c.Closed() {
		t.Fatal("a malformed response left the connection open")
	}
	<-done
}

func TestPeerHangupIsTransportError(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktCmdRequest, "version") == nil {
			return
		}
		f.close()
	})
	var opErr *OpError
	if _, err := c.Call(context.Background(), "version", nil); !errors.As(err, &opErr) || opErr.Op != "version" {
		t.Fatalf("err = %v, want *OpError for version", err)
	}
	if !c.Closed() {
		t.Fatal("a hangup left the connection open")
	}
	<-done
}

func TestEventBacklogBounded(t *testing.T) {
	c, done := startCharon(t, func(f *fakeCharon) {
		if f.expect(pktCmdRequest, "version") == nil {
			return
		}
		for range maxPendingEvents + 1 {
			f.event("ike-updown")
		}
	})
	if _, err := c.Call(context.Background(), "version", nil); !errors.Is(err, ErrEventBacklog) {
		t.Fatalf("err = %v, want ErrEventBacklog", err)
	}
	<-done
}

func TestCloseTwice(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close server pipe: %v", err)
		}
	})
	c := NewConn(client)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("second Close: err = %v, want ErrClosed", err)
	}
	if err := c.Subscribe(context.Background(), "ike-updown"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Subscribe after Close: err = %v, want ErrClosed", err)
	}
}

func TestDialUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "charon.vici")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
	})
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		nc, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		f := &fakeCharon{t: t, nc: nc}
		if f.expect(pktCmdRequest, "version") != nil {
			f.send(pktCmdResponse, "", response("version", "6.0.1"))
		}
		f.close()
	}()

	c, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	if _, err := c.Call(context.Background(), "version", nil); err != nil {
		t.Fatalf("Call over the socket: %v", err)
	}
	<-accepted
}

func TestDialMissingSocket(t *testing.T) {
	var opErr *OpError
	_, err := Dial(context.Background(), filepath.Join(t.TempDir(), "absent.vici"))
	if !errors.As(err, &opErr) || opErr.Op != "dial" {
		t.Fatalf("err = %v, want *OpError for dial", err)
	}
}

func TestPacketFraming(t *testing.T) {
	var buf bytes.Buffer
	if err := writePacket(&buf, pktCmdRequest, "version", nil); err != nil {
		t.Fatalf("writePacket: %v", err)
	}
	want := append([]byte{0, 0, 0, 9, pktCmdRequest, 7}, "version"...)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("frame = %v, want %v", buf.Bytes(), want)
	}
	if err := writePacket(&buf, pktCmdRequest, strings.Repeat("c", 256), nil); err == nil {
		t.Fatal("a 256-byte command name was framed")
	}
}

func TestPacketSizeLimits(t *testing.T) {
	big := NewMessage()
	for i := range 9 {
		big.SetBytes(string(rune('a'+i)), make([]byte, 65535))
	}
	if err := writePacket(&bytes.Buffer{}, pktCmdRequest, "load-cert", big); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("write of %d+ bytes: err = %v, want ErrMessageTooLarge", 9*65535, err)
	}

	header := binary.BigEndian.AppendUint32(nil, MaxPacketSize+1)
	if _, err := readPacket(bytes.NewReader(header)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("read of an oversized header: err = %v, want ErrMessageTooLarge", err)
	}
}

func TestReadPacketRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty packet", []byte{0, 0, 0, 0}},
		{"unknown packet type", []byte{0, 0, 0, 1, 8}},
		{"named packet without a name", []byte{0, 0, 0, 1, pktEvent}},
		{"name longer than the packet", []byte{0, 0, 0, 3, pktEvent, 5, 'a'}},
		{"zero-length name", []byte{0, 0, 0, 2, pktEvent, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var decErr *DecodeError
			if _, err := readPacket(bytes.NewReader(tt.data)); !errors.As(err, &decErr) {
				t.Fatalf("err = %v, want *DecodeError", err)
			}
		})
	}
}
