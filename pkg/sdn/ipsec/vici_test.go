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
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
	"unsafe"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	govici "github.com/strongswan/govici/vici"
	"golang.org/x/sys/unix"
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

// TestVICISessionRejectsRefusals hands every command a success=no reply with
// no transport error: the session itself must fail it as ErrCommandRefused
// with charon's errmsg, whatever govici makes of the reply.
func TestVICISessionRejectsRefusals(t *testing.T) {
	ctx := context.Background()
	key := TokenKey{KeyID: []byte("ipsec")}
	commands := []struct {
		cmd string
		run func(s *viciSession) error
	}{
		{"load-conn", func(s *viciSession) error { return s.LoadConn(ctx, "vtep-10.20.0.30", &Connection{Version: "2"}) }},
		{"unload-conn", func(s *viciSession) error { return s.UnloadConn(ctx, "vtep-10.20.0.30") }},
		{"get-conns", func(s *viciSession) error {
			names, err := s.Conns(ctx)
			if names != nil {
				t.Errorf("get-conns returned %v from a refusal", names)
			}
			return err
		}},
		{"list-sas", func(s *viciSession) error {
			held, err := s.IKESAs(ctx, "vtep-10.20.0.30")
			if held != nil {
				t.Errorf("list-sas returned %v from a refusal", held)
			}
			return err
		}},
		{"terminate", func(s *viciSession) error { return s.TerminateIKE(ctx, "7") }},
		{"load-cert", func(s *viciSession) error {
			return s.LoadCert(ctx, Credential{Kind: CredentialAuthority, DER: []byte{0x30}})
		}},
		{"load-token", func(s *viciSession) error { return s.LoadToken(ctx, key, newSecret(t, "1234")) }},
		{"load-token", func(s *viciSession) error { return s.LoadToken(ctx, key, nil) }},
	}
	replies := []struct {
		name   string
		reply  *govici.Message
		reason string
	}{
		{"with errmsg", message(t, "success", "no", "errmsg", "loading private key failed"), "loading private key failed"},
		{"without errmsg", message(t, "success", "no"), "no errmsg"},
	}
	for _, r := range replies {
		for _, c := range commands {
			s, fake := newFakeVICISession(t)
			fake.resp, fake.stream = r.reply, []*govici.Message{r.reply}
			err := c.run(s)
			var cmdErr *CommandError
			if !errors.As(err, &cmdErr) || cmdErr.Command != c.cmd || cmdErr.Reason != r.reason || !errors.Is(err, ErrCommandRefused) {
				t.Errorf("%s %s: err = %v, want a refused CommandError carrying %q", r.name, c.cmd, err, r.reason)
			}
		}
	}
}

// TestVICISessionAcceptsReplies checks what is not a refusal: success=yes,
// a reply without a success field, as get-conns sends, and a list-sa event
// with a connection that happens to be named success.
func TestVICISessionAcceptsReplies(t *testing.T) {
	ctx := context.Background()
	s, fake := newFakeVICISession(t)
	fake.resp = message(t, "success", "yes")
	if err := s.UnloadConn(ctx, "vtep-10.20.0.30"); err != nil {
		t.Fatalf("success=yes: %v", err)
	}
	fake.resp = message(t, "conns", []string{"vtep-10.20.0.30"})
	if names, err := s.Conns(ctx); err != nil || !slices.Equal(names, []string{"vtep-10.20.0.30"}) {
		t.Fatalf("get-conns = %v, %v", names, err)
	}
	fake.stream = []*govici.Message{message(t, "success", message(t, "uniqueid", "3"))}
	if held, err := s.IKESAs(ctx, ""); err != nil || len(held) != 1 || held[0].Conn != "success" {
		t.Fatalf("list-sas = %v, %v", held, err)
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
		message(t, "vtep-10.20.0.2", message(t, "uniqueid", "7", "state", "ESTABLISHED",
			"remote-host", "10.20.0.2", "remote-id", "10.20.0.2")),
		message(t, "operator-test", message(t, "uniqueid", "9")),
		message(t, "noise", "not a section"),
	}
	held, err := s.IKESAs(ctx, "")
	want := []HeldSA{
		{Conn: "vtep-10.20.0.2", SA: IKESA{UniqueID: "7", RemoteHost: "10.20.0.2", RemoteID: "10.20.0.2"}},
		{Conn: "operator-test", SA: IKESA{UniqueID: "9"}},
	}
	if err != nil || !slices.Equal(held, want) {
		t.Fatalf("IKESAs = %+v, %v", held, err)
	}
	if c.reqs[0].Get("ike") != nil || c.reqs[0].Get("noblock") != "yes" {
		t.Fatalf("list-sas request for every SA = %v", c.reqs[0])
	}
	if _, err := s.IKESAs(ctx, "vtep-10.20.0.2"); err != nil || c.reqs[1].Get("ike") != "vtep-10.20.0.2" {
		t.Fatalf("list-sas request for one connection = %v, %v", c.reqs[1], err)
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

func TestVICIEventsForwardMarksLostEvents(t *testing.T) {
	up := func(id string) govici.Event {
		return govici.Event{Name: updownEvent, Message: message(t, "up", "yes", "vtep-10.20.0.1", message(t, "uniqueid", id))}
	}
	tests := []struct {
		name  string
		queue []govici.Event
		first IKEUpdown
	}{
		{"an ike-updown read from a full queue", []govici.Event{up("1"), up("2"), up("3"), up("4")},
			IKEUpdown{Up: true, SAs: map[string]IKESA{"vtep-10.20.0.1": {UniqueID: "1"}}, Lost: true}},
		{"another event read from a full queue", []govici.Event{{Name: "child-updown"}, up("2"), up("3"), up("4")},
			IKEUpdown{Lost: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A queue govici found full: the forwarder starts behind it.
			in := make(chan govici.Event, len(tt.queue))
			for _, ev := range tt.queue {
				in <- ev
			}
			close(in)
			e := &viciEvents{out: make(chan IKEUpdown), done: make(chan struct{})}
			go e.forward(in)

			ev, ok := recv(t, e.Events())
			if !ok || ev.Lost != tt.first.Lost || ev.Up != tt.first.Up || !maps.Equal(ev.SAs, tt.first.SAs) {
				t.Fatalf("first event = %+v, want %+v", ev, tt.first)
			}
			// Once the queue has room again, events are whole.
			ev, ok = recv(t, e.Events())
			if !ok || ev.Lost || ev.SAs["vtep-10.20.0.1"].UniqueID != "2" {
				t.Fatalf("second event = %+v, want the next ike-updown, not lost", ev)
			}
			for range e.Events() {
			}
		})
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

func TestOpenSocket(t *testing.T) {
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

	fd, err := openSocket(good, owner)
	if err != nil {
		t.Fatalf("openSocket: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("close: %v", err)
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
			fd, err := openSocket(tt.path, tt.owner)
			var sockErr *SocketError
			if fd != -1 || !errors.As(err, &sockErr) || sockErr.Path != tt.path || !errors.Is(err, tt.want) {
				t.Fatalf("fd = %d, err = %v, want a SocketError for %v", fd, err, tt.want)
			}
		})
	}
}

func TestCheckSocketBadDescriptor(t *testing.T) {
	if err := checkSocket(-1, os.Geteuid()); !errors.Is(err, unix.EBADF) {
		t.Fatalf("err = %v, want EBADF", err)
	}
}

// A socket swapped in under the path after the checks is never reached:
// the connect goes through the descriptor the checks read.
func TestOpenSocketSurvivesASwap(t *testing.T) {
	path, checked := listenSocket(t, 0o600)
	checked.SetUnlinkOnClose(false)
	fd, err := openSocket(path, os.Geteuid())
	if err != nil {
		t.Fatalf("openSocket: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Close(fd); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	impostor, _ := listenSocket(t, 0o600)
	if err := os.Rename(impostor, path); err != nil {
		t.Fatalf("swap: %v", err)
	}

	conn, err := net.Dial("unix", fdPath(fd))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close conn: %v", err)
		}
	})
	if err := checked.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	accepted, err := checked.Accept()
	if err != nil {
		t.Fatalf("the checked socket was not the one reached: %v", err)
	}
	if err := accepted.Close(); err != nil {
		t.Fatalf("close accepted: %v", err)
	}
}

func TestCheckPeer(t *testing.T) {
	path, ln := listenSocket(t, 0o600)
	go func() {
		if c, err := ln.Accept(); err == nil {
			if err := c.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		}
	}()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close conn: %v", err)
		}
	})

	if err := checkPeer(conn, os.Geteuid()); err != nil {
		t.Fatalf("checkPeer: %v", err)
	}
	if err := checkPeer(conn, os.Geteuid()+1); !errors.Is(err, ErrSocketPeer) {
		t.Fatalf("another uid: err = %v, want ErrSocketPeer", err)
	}
	pipe, other := net.Pipe()
	defer func() {
		if err := errors.Join(pipe.Close(), other.Close()); err != nil {
			t.Errorf("close pipe: %v", err)
		}
	}()
	var notUnix peercred.ErrNotUnixConnection
	if err := checkPeer(pipe, os.Geteuid()); !errors.As(err, &notUnix) {
		t.Fatalf("not a unix socket: err = %v, want ErrNotUnixConnection", err)
	}
}

func TestVICIDialerRefusesAnotherServer(t *testing.T) {
	srv := newVICIServer(t, false)
	d := NewVICIDialer(srv.path, os.Geteuid()+1)
	var sockErr *SocketError
	if _, err := d.Dial(context.Background()); !errors.As(err, &sockErr) || !errors.Is(err, ErrSocketPeer) {
		t.Fatalf("Dial: err = %v, want ErrSocketPeer", err)
	}
	if _, err := d.Subscribe(context.Background()); !errors.Is(err, ErrSocketPeer) {
		t.Fatalf("Subscribe: err = %v, want ErrSocketPeer", err)
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
	d := NewVICIDialer(path, os.Geteuid())
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
	if _, err := NewVICIDialer(path, os.Geteuid()).Dial(context.Background()); !errors.As(err, &sockErr) || errors.Is(err, ErrSocketMode) {
		t.Fatalf("err = %v, want the dial failure as a SocketError", err)
	}
}

// VICI packet and element types, from charon's vici README.
const (
	pktCmdRequest      = 0
	pktCmdResponse     = 1
	pktEventRegister   = 3
	pktEventUnregister = 4
	pktEventConfirm    = 5
	pktEventUnknown    = 6
	pktEvent           = 7

	elemSectionStart = 1
	elemSectionEnd   = 2
	elemKeyValue     = 3
)

// viciServer answers VICI on a unix socket the way charon does, closely
// enough for govici: every command succeeds with an empty response, or is
// refused with success=no and refuse as its errmsg when refuse is set (only
// the commands in refused, when that is set), and event registration and
// unregistration are confirmed, or refused when unknownEvents is set.
type viciServer struct {
	path          string
	conns         chan net.Conn
	unknownEvents bool
	refuse        string
	refused       []string
}

// refuses reports whether s refuses the command request pkt.
func (s *viciServer) refuses(pkt []byte) bool {
	if s.refuse == "" {
		return false
	}
	if len(s.refused) == 0 {
		return true
	}
	if len(pkt) < 2 || len(pkt) < 2+int(pkt[1]) {
		return false
	}
	return slices.Contains(s.refused, string(pkt[2:2+int(pkt[1])]))
}

func newVICIServer(t *testing.T, unknownEvents bool) *viciServer {
	t.Helper()
	return startVICIServer(t, &viciServer{unknownEvents: unknownEvents})
}

// startVICIServer serves s, whose options are set before any connection.
func startVICIServer(t *testing.T, s *viciServer) *viciServer {
	t.Helper()
	path, ln := listenSocket(t, 0o600)
	s.path, s.conns = path, make(chan net.Conn, 4)
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
		var body [][]byte
		switch {
		case pkt[0] == pktEventRegister && s.unknownEvents:
			reply = pktEventUnknown
		case pkt[0] == pktEventRegister || pkt[0] == pktEventUnregister:
			reply = pktEventConfirm
		case pkt[0] != pktCmdRequest:
			continue
		case s.refuses(pkt):
			body = [][]byte{keyValue("success", "no"), keyValue("errmsg", s.refuse)}
		}
		if _, err := c.Write(viciPacket(reply, "", body...)); err != nil {
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
	d := NewVICIDialer(srv.path, os.Geteuid())

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

// TestVICISessionRefusedOverASocket drives every command through govici
// against a charon that refuses each one with success=no: none may pass for
// done, and each must fail as a CommandError carrying charon's errmsg.
func TestVICISessionRefusedOverASocket(t *testing.T) {
	// A command left waiting on a reply fails the test instead of hanging it.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const reason = "loading private key failed"
	srv := startVICIServer(t, &viciServer{refuse: reason})
	sess, err := NewVICIDialer(srv.path, os.Geteuid()).Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	recv(t, srv.conns)
	t.Cleanup(func() {
		if err := sess.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	key := TokenKey{KeyID: []byte("ipsec"), Module: "xkms"}
	commands := []struct {
		cmd string
		run func() error
	}{
		{"load-conn", func() error {
			return sess.LoadConn(ctx, "vtep-10.20.0.30", &Connection{Version: "2", RemoteAddrs: []string{"10.20.0.30"}})
		}},
		{"unload-conn", func() error { return sess.UnloadConn(ctx, "vtep-10.20.0.30") }},
		{"get-conns", func() error {
			names, err := sess.Conns(ctx)
			if names != nil {
				t.Errorf("get-conns returned %v from a refusal", names)
			}
			return err
		}},
		{"list-sas", func() error {
			held, err := sess.IKESAs(ctx, "vtep-10.20.0.30")
			if held != nil {
				t.Errorf("list-sas returned %v from a refusal", held)
			}
			return err
		}},
		{"terminate", func() error { return sess.TerminateIKE(ctx, "7") }},
		{"load-cert", func() error { return sess.LoadCert(ctx, Credential{Kind: CredentialEndEntity, DER: []byte{0x30}}) }},
		{"load-token", func() error { return sess.LoadToken(ctx, key, newSecret(t, "1234")) }},
		{"load-token", func() error { return sess.LoadToken(ctx, key, nil) }},
	}
	for _, c := range commands {
		err := c.run()
		var cmdErr *CommandError
		if !errors.As(err, &cmdErr) || cmdErr.Command != c.cmd || cmdErr.Reason != reason || !errors.Is(err, ErrCommandRefused) {
			t.Errorf("%s: err = %v, want a CommandError carrying %q", c.cmd, err, reason)
		}
	}
}

// TestAttachOverARefusingSocket joins the controller to a govici session
// whose charon refuses commands: a refused credential leaves the controller
// detached, and a refused connection is not marked loaded but left for the
// retry, so the controller keeps converging.
func TestAttachOverARefusingSocket(t *testing.T) {
	tests := []struct {
		name     string
		refused  []string
		op       string
		attached bool
	}{
		{"load-cert refused", []string{"load-cert"}, "load-cert", false},
		{"load-token refused", []string{"load-token"}, "load-token", false},
		{"load-conn refused", []string{"load-conn"}, "load-conn", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			srv := startVICIServer(t, &viciServer{refuse: "no such key", refused: tt.refused})
			sess, err := NewVICIDialer(srv.path, os.Geteuid()).Dial(ctx)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			recv(t, srv.conns)
			t.Cleanup(func() {
				if err := sess.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			})
			h := newDetachedHarness(t)

			err = h.ctl.Attach(ctx, sess)
			var opErr *OpError
			var peerErr *PeerError
			failedOp := (errors.As(err, &opErr) && opErr.Op == tt.op) || (errors.As(err, &peerErr) && peerErr.Op == tt.op)
			if !failedOp || !errors.Is(err, ErrCommandRefused) {
				t.Fatalf("Attach: err = %v, want the %s refusal", err, tt.op)
			}
			if h.ctl.attached() != tt.attached || len(h.ctl.loaded) != 0 {
				t.Fatalf("attached=%v with %d connections marked loaded, want attached=%v and none", h.ctl.attached(), len(h.ctl.loaded), tt.attached)
			}
			if tt.attached {
				if s := h.ctl.Status(); len(s.Unsynced) != 2 {
					t.Fatalf("unsynced = %v, want both static peers left for the retry", s.Unsynced)
				}
				select {
				case <-h.ctl.retry:
				default:
					t.Fatal("a refused connection did not signal a retry")
				}
			}
		})
	}
}

func TestVICIDialerSubscribeRefused(t *testing.T) {
	srv := newVICIServer(t, true)
	var cmdErr *CommandError
	if _, err := NewVICIDialer(srv.path, os.Geteuid()).Subscribe(context.Background()); !errors.As(err, &cmdErr) || cmdErr.Command != "subscribe ike-updown" {
		t.Fatalf("err = %v, want a subscribe CommandError", err)
	}
}
