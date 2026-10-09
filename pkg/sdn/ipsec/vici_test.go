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

package ipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"iter"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
	"unsafe"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
	govici "github.com/strongswan/govici/vici"
)

// fakeCaller records the requests a viciSession sends.
type fakeCaller struct {
	cmds   []string
	reqs   []*govici.Message
	resp   *govici.Message
	stream []*govici.Message
	err    error
	// onCall runs inside Call, while the request is in flight.
	onCall   func(req *govici.Message)
	notified chan<- govici.Event
	closeErr error
}

func (f *fakeCaller) Call(_ context.Context, cmd string, in *govici.Message) (*govici.Message, error) {
	f.cmds = append(f.cmds, cmd)
	f.reqs = append(f.reqs, in)
	if f.onCall != nil {
		f.onCall(in)
	}
	if f.err != nil {
		return nil, f.err
	}
	if f.resp == nil {
		return govici.NewMessage(), nil
	}
	return f.resp, nil
}

func (f *fakeCaller) CallStreaming(_ context.Context, cmd, _ string, in *govici.Message) iter.Seq2[*govici.Message, error] {
	f.cmds = append(f.cmds, cmd)
	f.reqs = append(f.reqs, in)
	return func(yield func(*govici.Message, error) bool) {
		for _, m := range f.stream {
			if !yield(m, nil) {
				return
			}
		}
		if f.err != nil {
			yield(nil, f.err)
		}
	}
}

func (f *fakeCaller) NotifyEvents(c chan<- govici.Event) { f.notified = c }

func (f *fakeCaller) Close() error { return f.closeErr }

// end closes the notify channel, as govici does when the connection ends.
func (f *fakeCaller) end() { close(f.notified) }

func newFakeVICISession(t *testing.T) (*viciSession, *fakeCaller) {
	t.Helper()
	c := &fakeCaller{}
	s := newVICISession(c)
	t.Cleanup(func() {
		if c.notified != nil {
			c.end()
		}
	})
	return s, c
}

func message(t *testing.T, kv ...any) *govici.Message {
	t.Helper()
	m := govici.NewMessage()
	for i := 0; i < len(kv); i += 2 {
		if err := m.Set(kv[i].(string), kv[i+1]); err != nil {
			t.Fatalf("Set(%v): %v", kv[i], err)
		}
	}
	return m
}

// recv receives from ch, failing the test if nothing arrives.
func recv[T any](t *testing.T, ch <-chan T) (T, bool) {
	t.Helper()
	select {
	case v, ok := <-ch:
		return v, ok
	case <-time.After(5 * time.Second):
		t.Fatal("nothing received")
		var zero T
		return zero, false
	}
}

func TestVICISessionRequests(t *testing.T) {
	ctx := context.Background()
	s, c := newFakeVICISession(t)

	if err := s.LoadConn(ctx, "vtep-10.20.0.30", &Connection{Version: "2", RemoteAddrs: []string{"10.20.0.30"}}); err != nil {
		t.Fatalf("LoadConn: %v", err)
	}
	body := section(t, c.reqs[0], "vtep-10.20.0.30")
	if body.Get("version") != "2" || body.Get("local_addrs") != nil {
		t.Fatalf("load-conn body = %v", body)
	}

	if err := s.UnloadConn(ctx, "vtep-10.20.0.30"); err != nil {
		t.Fatalf("UnloadConn: %v", err)
	}
	if got := c.reqs[1].Get("name"); got != "vtep-10.20.0.30" {
		t.Fatalf("unload-conn name = %v", got)
	}

	if err := s.TerminateIKE(ctx, "7"); err != nil {
		t.Fatalf("TerminateIKE: %v", err)
	}
	if c.reqs[2].Get("ike-id") != "7" || c.reqs[2].Get("force") != "yes" {
		t.Fatalf("terminate request = %v", c.reqs[2])
	}

	if want := []string{"load-conn", "unload-conn", "terminate"}; !slices.Equal(c.cmds, want) {
		t.Fatalf("commands = %v, want %v", c.cmds, want)
	}
}

func TestVICISessionConns(t *testing.T) {
	ctx := context.Background()
	s, c := newFakeVICISession(t)
	c.resp = message(t, "conns", []string{"vtep-10.20.0.1", "operator-test"})
	names, err := s.Conns(ctx)
	if err != nil || !slices.Equal(names, []string{"vtep-10.20.0.1", "operator-test"}) {
		t.Fatalf("Conns = %v, %v", names, err)
	}

	c.resp = govici.NewMessage()
	if names, err := s.Conns(ctx); err != nil || names != nil {
		t.Fatalf("Conns of an empty charon = %v, %v", names, err)
	}

	c.err = errInjected
	var cmdErr *CommandError
	if _, err := s.Conns(ctx); !errors.As(err, &cmdErr) || cmdErr.Command != "get-conns" || !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want a get-conns CommandError", err)
	}
}

func TestVICISessionIKESAs(t *testing.T) {
	ctx := context.Background()
	s, c := newFakeVICISession(t)
	c.stream = []*govici.Message{
		message(t, "vtep-10.20.0.2", message(t, "uniqueid", "7", "state", "ESTABLISHED")),
		message(t, "vtep-10.20.0.2", message(t, "uniqueid", "9")),
		message(t, "noise", "not a section"),
	}
	ids, err := s.IKESAs(ctx, "vtep-10.20.0.2")
	if err != nil || !slices.Equal(ids, []string{"7", "9"}) {
		t.Fatalf("IKESAs = %v, %v", ids, err)
	}
	if c.reqs[0].Get("ike") != "vtep-10.20.0.2" || c.reqs[0].Get("noblock") != "yes" {
		t.Fatalf("list-sas request = %v", c.reqs[0])
	}

	c.err = errInjected
	var cmdErr *CommandError
	if _, err := s.IKESAs(ctx, "vtep-10.20.0.2"); !errors.As(err, &cmdErr) || cmdErr.Command != "list-sas" {
		t.Fatalf("err = %v, want a list-sas CommandError", err)
	}
}

func TestVICISessionLoadCert(t *testing.T) {
	ctx := context.Background()
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	tests := []struct {
		kind       CredentialKind
		typ, flag  string
		flagAbsent bool
	}{
		{CredentialEndEntity, "X509", "NONE", false},
		{CredentialAuthority, "X509", "CA", false},
		{CredentialCRL, "X509_CRL", "", true},
	}
	for _, tt := range tests {
		s, c := newFakeVICISession(t)
		if err := s.LoadCert(ctx, Credential{Kind: tt.kind, DER: der}); err != nil {
			t.Fatalf("LoadCert(%v): %v", tt.kind, err)
		}
		req := c.reqs[0]
		if req.Get("type") != tt.typ || req.Get("data") != string(der) {
			t.Fatalf("kind %v: request = %v", tt.kind, req)
		}
		if flag := req.Get("flag"); (flag == nil) != tt.flagAbsent || (!tt.flagAbsent && flag != tt.flag) {
			t.Fatalf("kind %v: flag = %v, want %q", tt.kind, flag, tt.flag)
		}
	}

	s, c := newFakeVICISession(t)
	for _, cred := range []Credential{{Kind: CredentialKind(9), DER: der}, {Kind: CredentialCRL}} {
		if err := s.LoadCert(ctx, cred); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("LoadCert(%+v): err = %v, want ErrInvalidMessage", cred, err)
		}
	}
	c.err = errInjected
	var cmdErr *CommandError
	if err := s.LoadCert(ctx, Credential{Kind: CredentialCRL, DER: der}); !errors.As(err, &cmdErr) || cmdErr.Command != "load-cert" {
		t.Fatalf("err = %v, want a load-cert CommandError", err)
	}
}

// TestVICISessionLoadTokenPIN checks the PIN reaches charon from the locked
// buffer and leaves the request once the call returns: platformd never
// holds it in a string of its own.
func TestVICISessionLoadTokenPIN(t *testing.T) {
	ctx := context.Background()
	s, c := newFakeVICISession(t)
	var sent bool
	c.onCall = func(req *govici.Message) {
		pin, ok := req.Get("pin").(string)
		// Compared in place, without copying it out of the message.
		sent = ok && pin == "1234"
	}
	key := TokenKey{Module: "xkms", Slot: 2, KeyID: []byte("ipsec")}
	if err := s.LoadToken(ctx, key, newSecret(t, "1234")); err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if !sent {
		t.Fatal("load-token did not carry the PIN")
	}
	req := c.reqs[0]
	if req.Get("pin") != nil {
		t.Fatal("the request kept a view of the PIN after the call")
	}
	if req.Get("handle") != "6970736563" || req.Get("slot") != "2" || req.Get("module") != "xkms" {
		t.Fatalf("load-token request = %v", req)
	}

	// The PIN is wiped from the request when the call fails too.
	c.err = errInjected
	var cmdErr *CommandError
	if err := s.LoadToken(ctx, key, newSecret(t, "1234")); !errors.As(err, &cmdErr) || cmdErr.Command != "load-token" {
		t.Fatalf("err = %v, want a load-token CommandError", err)
	}
	if c.reqs[1].Get("pin") != nil {
		t.Fatal("a failed call left the PIN in the request")
	}
}

func TestVICISessionLoadTokenWithoutPIN(t *testing.T) {
	ctx := context.Background()
	s, c := newFakeVICISession(t)
	if err := s.LoadToken(ctx, TokenKey{KeyID: []byte{0x01}}, nil); err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	req := c.reqs[0]
	if req.Get("pin") != nil || req.Get("module") != nil || req.Get("handle") != "01" || req.Get("slot") != "0" {
		t.Fatalf("load-token request = %v", req)
	}
}

func TestVICISessionLoadTokenRejects(t *testing.T) {
	ctx := context.Background()
	s, c := newFakeVICISession(t)
	if err := s.LoadToken(ctx, TokenKey{}, nil); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("no key ID: err = %v, want ErrInvalidMessage", err)
	}
	destroyed := newSecret(t, "1234")
	destroyed.Destroy()
	var nilSecret *secure.NilSecretError
	if err := s.LoadToken(ctx, TokenKey{KeyID: []byte{0x01}}, destroyed); !errors.As(err, &nilSecret) {
		t.Fatalf("destroyed PIN: err = %v, want a NilSecretError", err)
	}
	if len(c.cmds) != 0 {
		t.Fatalf("sent %v for a request that cannot be made", c.cmds)
	}
}

func TestLockedStringAliases(t *testing.T) {
	b := []byte("1234")
	s := lockedString(b)
	if unsafe.StringData(s) != &b[0] || len(s) != len(b) {
		t.Fatal("lockedString copied its input")
	}
	b[0] = '9'
	if s != "9234" {
		t.Fatal("the view does not follow the buffer")
	}
	if lockedString(nil) != "" {
		t.Fatal("an empty buffer is not an empty string")
	}
}

func TestVICISessionDoneAndClose(t *testing.T) {
	c := &fakeCaller{}
	s := newVICISession(c)
	select {
	case <-s.Done():
		t.Fatal("done before the connection ended")
	default:
	}
	c.end()
	recv(t, s.Done())

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	c.closeErr = errInjected
	if err := s.Close(); !errors.Is(err, errInjected) {
		t.Fatalf("Close: err = %v, want the close failure", err)
	}
}

func TestParseUpdown(t *testing.T) {
	m := message(t,
		"up", "yes",
		"vtep-10.20.0.1", message(t, "uniqueid", "4", "remote-host", "10.20.0.1", "remote-id", "10.20.0.1", "state", "ESTABLISHED"),
		"vtep-10.20.0.2", message(t, "uniqueid", "5", "remote-id", []string{"not", "a value"}),
	)
	ev := parseUpdown(m)
	if !ev.Up {
		t.Fatal("up=yes not read")
	}
	if got := ev.SAs["vtep-10.20.0.1"]; got != (IKESA{UniqueID: "4", RemoteHost: "10.20.0.1", RemoteID: "10.20.0.1"}) {
		t.Fatalf("SA = %+v", got)
	}
	if got, ok := ev.SAs["vtep-10.20.0.2"]; !ok || got.RemoteID != "" {
		t.Fatalf("an unreadable SA = %+v, %v; want it kept with no identity", got, ok)
	}
	if len(ev.SAs) != 2 {
		t.Fatalf("SAs = %v, want the sections only", ev.SAs)
	}

	if down := parseUpdown(message(t, "vtep-10.20.0.1", message(t, "uniqueid", "4"))); down.Up {
		t.Fatal("an event without up=yes read as up")
	}
}

// fakeSource is an eventSource.
type fakeSource struct {
	in       chan<- govici.Event
	closed   int
	closeErr error
}

func (f *fakeSource) NotifyEvents(c chan<- govici.Event) { f.in = c }
func (f *fakeSource) Close() error                       { f.closed++; return f.closeErr }

func TestVICIEventsForward(t *testing.T) {
	src := &fakeSource{}
	e := newVICIEvents(src)
	src.in <- govici.Event{Name: "child-updown", Message: message(t, "up", "yes")}
	src.in <- govici.Event{Name: updownEvent}
	src.in <- govici.Event{Name: updownEvent, Message: message(t, "up", "yes", "vtep-10.20.0.1", message(t, "uniqueid", "4"))}
	ev, ok := recv(t, e.Events())
	if !ok || !ev.Up || ev.SAs["vtep-10.20.0.1"].UniqueID != "4" {
		t.Fatalf("event = %+v, %v; want only the ike-updown with a message", ev, ok)
	}
	close(src.in)
	if _, ok := recv(t, e.Events()); ok {
		t.Fatal("the stream outlived the connection")
	}
}

func TestVICIEventsClose(t *testing.T) {
	src := &fakeSource{closeErr: errInjected}
	e := newVICIEvents(src)
	// An event nobody reads must not hold the forwarder after Close.
	src.in <- govici.Event{Name: updownEvent, Message: message(t, "up", "yes")}
	if err := e.Close(); !errors.Is(err, errInjected) {
		t.Fatalf("Close: err = %v, want the close failure", err)
	}
	if err := e.Close(); err != nil || src.closed != 1 {
		t.Fatalf("second Close: err = %v, closed %d times", err, src.closed)
	}
	for range e.Events() {
	}
}

// listenSocket listens on a unix socket in a fresh directory, with mode.
func listenSocket(t *testing.T, mode fs.FileMode) (string, *net.UnixListener) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "charon.vici")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close listener: %v", err)
		}
	})
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return path, ln
}

func TestCheckSocket(t *testing.T) {
	owner := os.Geteuid()
	good, _ := listenSocket(t, 0o600)
	open, _ := listenSocket(t, 0o660)
	file := filepath.Join(t.TempDir(), "charon.vici")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(t.TempDir(), "charon.vici")
	if err := os.Symlink(good, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := checkSocket(good, owner); err != nil {
		t.Fatalf("checkSocket: %v", err)
	}
	tests := []struct {
		name  string
		path  string
		owner int
		want  error
	}{
		{"missing", filepath.Join(t.TempDir(), "absent"), owner, fs.ErrNotExist},
		{"regular file", file, owner, ErrNotSocket},
		{"symlink to the socket", link, owner, ErrNotSocket},
		{"group-accessible socket", open, owner, ErrSocketMode},
		{"socket of another user", good, owner + 1, ErrSocketOwner},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSocket(tt.path, tt.owner)
			var sockErr *SocketError
			if !errors.As(err, &sockErr) || sockErr.Path != tt.path || !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want a SocketError for %v", err, tt.want)
			}
		})
	}
}

func TestVICIDialerRefusesBeforeConnecting(t *testing.T) {
	path, ln := listenSocket(t, 0o666)
	accepted := make(chan struct{})
	go func() {
		if c, err := ln.Accept(); err == nil {
			close(accepted)
			if err := c.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		}
	}()
	d := NewVICIDialer(path)
	if _, err := d.Dial(context.Background()); !errors.Is(err, ErrSocketMode) {
		t.Fatalf("Dial: err = %v, want ErrSocketMode", err)
	}
	if _, err := d.Subscribe(context.Background()); !errors.Is(err, ErrSocketMode) {
		t.Fatalf("Subscribe: err = %v, want ErrSocketMode", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	select {
	case <-accepted:
		t.Fatal("the dialer connected to a socket it refused")
	default:
	}
}

func TestVICIDialerConnectionRefused(t *testing.T) {
	path, ln := listenSocket(t, 0o600)
	ln.SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	var sockErr *SocketError
	if _, err := NewVICIDialer(path).Dial(context.Background()); !errors.As(err, &sockErr) || errors.Is(err, ErrSocketMode) {
		t.Fatalf("err = %v, want the dial failure as a SocketError", err)
	}
}

// VICI packet and element types, from charon's vici README.
const (
	pktCmdRequest    = 0
	pktCmdResponse   = 1
	pktEventRegister = 3
	pktEventConfirm  = 5
	pktEventUnknown  = 6
	pktEvent         = 7

	elemSectionStart = 1
	elemSectionEnd   = 2
	elemKeyValue     = 3
)

// viciServer answers VICI on a unix socket the way charon does, closely
// enough for govici: every command succeeds with an empty response, and
// event registration is confirmed, or refused when unknownEvents is set.
type viciServer struct {
	path          string
	conns         chan net.Conn
	unknownEvents bool
}

func newVICIServer(t *testing.T, unknownEvents bool) *viciServer {
	t.Helper()
	path, ln := listenSocket(t, 0o600)
	s := &viciServer{path: path, conns: make(chan net.Conn, 4), unknownEvents: unknownEvents}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() {
				if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Errorf("close: %v", err)
				}
			})
			s.conns <- c
			go s.serve(c)
		}
	}()
	return s
}

func (s *viciServer) serve(c net.Conn) {
	for {
		var size [4]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return
		}
		pkt := make([]byte, binary.BigEndian.Uint32(size[:]))
		if _, err := io.ReadFull(c, pkt); err != nil {
			return
		}
		reply := byte(pktCmdResponse)
		switch {
		case pkt[0] == pktEventRegister && s.unknownEvents:
			reply = pktEventUnknown
		case pkt[0] == pktEventRegister:
			reply = pktEventConfirm
		case pkt[0] != pktCmdRequest:
			continue
		}
		if _, err := c.Write(viciPacket(reply, "")); err != nil {
			return
		}
	}
}

func viciPacket(ptype byte, name string, elems ...[]byte) []byte {
	p := []byte{ptype}
	if name != "" {
		p = append(append(p, byte(len(name))), name...)
	}
	for _, e := range elems {
		p = append(p, e...)
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(p))), p...)
}

func keyValue(k, v string) []byte {
	b := append([]byte{elemKeyValue, byte(len(k))}, k...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	return append(b, v...)
}

func sectionOf(k string, elems ...[]byte) []byte {
	b := append([]byte{elemSectionStart, byte(len(k))}, k...)
	for _, e := range elems {
		b = append(b, e...)
	}
	return append(b, elemSectionEnd)
}

// TestVICIDialerOverASocket drives both connections through govici: the
// event stream delivers an ike-updown charon sends, and each connection
// signals its end when charon closes it.
func TestVICIDialerOverASocket(t *testing.T) {
	ctx := context.Background()
	srv := newVICIServer(t, false)
	d := NewVICIDialer(srv.path)

	events, err := d.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	evConn, _ := recv(t, srv.conns)
	sess, err := d.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	cmdConn, _ := recv(t, srv.conns)
	if names, err := sess.Conns(ctx); err != nil || names != nil {
		t.Fatalf("Conns = %v, %v", names, err)
	}

	updown := viciPacket(pktEvent, updownEvent, keyValue("up", "yes"), sectionOf("vtep-10.20.0.1",
		keyValue("uniqueid", "4"), keyValue("remote-host", "10.20.0.1"), keyValue("remote-id", "10.20.0.1")))
	if _, err := evConn.Write(updown); err != nil {
		t.Fatalf("write event: %v", err)
	}
	ev, ok := recv(t, events.Events())
	if !ok || !ev.Up || ev.SAs["vtep-10.20.0.1"].RemoteID != "10.20.0.1" {
		t.Fatalf("event = %+v, %v", ev, ok)
	}

	if err := cmdConn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	recv(t, sess.Done())
	if err := evConn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, ok := recv(t, events.Events()); ok {
		t.Fatal("the stream outlived charon's end of it")
	}
	if err := sess.Close(); err != nil {
		t.Errorf("Close session: %v", err)
	}
	if err := events.Close(); err != nil {
		t.Errorf("Close stream: %v", err)
	}
}

func TestVICIDialerSubscribeRefused(t *testing.T) {
	srv := newVICIServer(t, true)
	var cmdErr *CommandError
	if _, err := NewVICIDialer(srv.path).Subscribe(context.Background()); !errors.As(err, &cmdErr) || cmdErr.Command != "subscribe ike-updown" {
		t.Fatalf("err = %v, want a subscribe CommandError", err)
	}
}
