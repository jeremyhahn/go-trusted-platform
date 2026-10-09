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
	"encoding/hex"
	"io/fs"
	"iter"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
	govici "github.com/strongswan/govici/vici"
)

const (
	// DefaultVICISocket is charon's control socket.
	DefaultVICISocket = "/var/run/charon.vici"

	// socketMode is the only mode the VICI socket may have: VICI carries
	// no authentication, so whoever can open the socket commands charon.
	socketMode fs.FileMode = 0o600

	// eventBuffer is how many events govici queues for the stream. govici
	// drops an event rather than block when the queue is full.
	eventBuffer = 256

	// updownEvent is the event the stream subscribes to.
	updownEvent = "ike-updown"
)

// credentialTypes maps a CredentialKind to load-cert's type and flag.
var credentialTypes = map[CredentialKind][2]string{
	CredentialEndEntity: {"X509", "NONE"},
	CredentialAuthority: {"X509", "CA"},
	CredentialCRL:       {"X509_CRL", ""},
}

// VICIDialer opens govici sessions on charon's VICI socket, after checking
// that the socket is mode 0600 and owned by Owner.
type VICIDialer struct {
	// Socket is the socket path.
	Socket string
	// Owner is the uid that must own the socket: platformd's.
	Owner int
}

// NewVICIDialer returns a dialer for socket, which this process's
// effective user must own.
func NewVICIDialer(socket string) *VICIDialer {
	return &VICIDialer{Socket: socket, Owner: os.Geteuid()}
}

// Dial opens a command session.
func (d *VICIDialer) Dial(ctx context.Context) (Session, error) {
	s, err := d.open(ctx)
	if err != nil {
		return nil, err
	}
	return newVICISession(s), nil
}

// Subscribe opens an event connection subscribed to ike-updown.
func (d *VICIDialer) Subscribe(ctx context.Context) (EventStream, error) {
	s, err := d.open(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.Subscribe(updownEvent); err != nil {
		return nil, closeAfter(s, &CommandError{Command: "subscribe " + updownEvent, Err: err})
	}
	return newVICIEvents(s), nil
}

func (d *VICIDialer) open(ctx context.Context) (*govici.Session, error) {
	if err := checkSocket(d.Socket, d.Owner); err != nil {
		return nil, err
	}
	// govici dials with a background context; this one honours ctx.
	dial := func(_ context.Context, network, addr string) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, network, addr)
	}
	s, err := govici.NewSession(govici.WithSocketPath(d.Socket), govici.WithDialContext(dial))
	if err != nil {
		return nil, &SocketError{Path: d.Socket, Err: err}
	}
	return s, nil
}

// checkSocket refuses a path that is not a socket, not mode 0600, or not
// owned by owner.
func checkSocket(path string, owner int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return &SocketError{Path: path, Err: err}
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return &SocketError{Path: path, Err: ErrNotSocket}
	}
	if fi.Mode().Perm() != socketMode {
		return &SocketError{Path: path, Err: ErrSocketMode}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != owner {
		return &SocketError{Path: path, Err: ErrSocketOwner}
	}
	return nil
}

// closeAfter closes c after cause, and returns cause with any close error.
func closeAfter(c interface{ Close() error }, cause error) error {
	if err := c.Close(); err != nil {
		return &CloseError{Cause: cause, Err: err}
	}
	return cause
}

// caller is the part of *govici.Session a command session uses.
type caller interface {
	Call(ctx context.Context, cmd string, in *govici.Message) (*govici.Message, error)
	CallStreaming(ctx context.Context, cmd, event string, in *govici.Message) iter.Seq2[*govici.Message, error]
	NotifyEvents(c chan<- govici.Event)
	Close() error
}

// viciSession is a Session over govici.
type viciSession struct {
	c    caller
	done chan struct{}
}

// newVICISession wraps c. govici closes a notify channel when its
// connection's reader stops, so draining one marks the connection's end.
func newVICISession(c caller) *viciSession {
	s := &viciSession{c: c, done: make(chan struct{})}
	ch := make(chan govici.Event, 1)
	c.NotifyEvents(ch)
	go func() {
		for range ch {
		}
		close(s.done)
	}()
	return s
}

func (s *viciSession) Done() <-chan struct{} { return s.done }

func (s *viciSession) Close() error {
	if err := s.c.Close(); err != nil {
		return &CommandError{Command: "close", Err: err}
	}
	return nil
}

func (s *viciSession) call(ctx context.Context, cmd string, req *govici.Message) (*govici.Message, error) {
	resp, err := s.c.Call(ctx, cmd, req)
	if err != nil {
		return nil, &CommandError{Command: cmd, Err: err}
	}
	return resp, nil
}

// Requests, marshalled by govici. Empty fields are left out.
type (
	unloadConnRequest struct {
		Name string `vici:"name"`
	}
	listSAsRequest struct {
		IKE     string `vici:"ike"`
		NoBlock bool   `vici:"noblock"`
	}
	terminateRequest struct {
		IKEID string `vici:"ike-id"`
		Force bool   `vici:"force"`
	}
	loadCertRequest struct {
		Type string `vici:"type"`
		Flag string `vici:"flag"`
		Data string `vici:"data"`
	}
	loadTokenRequest struct {
		Handle string `vici:"handle"`
		Slot   uint32 `vici:"slot"`
		Module string `vici:"module"`
	}
)

// request marshals a cmd request.
func request(cmd string, v any) (*govici.Message, error) {
	m, err := govici.MarshalMessage(v)
	if err != nil {
		return nil, &CommandError{Command: cmd, Err: err}
	}
	return m, nil
}

func (s *viciSession) LoadConn(ctx context.Context, name string, conn *Connection) error {
	body, err := request("load-conn", conn)
	if err != nil {
		return err
	}
	req := govici.NewMessage()
	if err := req.Set(name, body); err != nil {
		return &CommandError{Command: "load-conn", Err: err}
	}
	_, err = s.call(ctx, "load-conn", req)
	return err
}

func (s *viciSession) UnloadConn(ctx context.Context, name string) error {
	req, err := request("unload-conn", unloadConnRequest{Name: name})
	if err != nil {
		return err
	}
	_, err = s.call(ctx, "unload-conn", req)
	return err
}

func (s *viciSession) Conns(ctx context.Context) ([]string, error) {
	resp, err := s.call(ctx, "get-conns", nil)
	if err != nil {
		return nil, err
	}
	names, ok := resp.Get("conns").([]string)
	if !ok {
		return nil, nil
	}
	return names, nil
}

func (s *viciSession) IKESAs(ctx context.Context, conn string) ([]string, error) {
	req, err := request("list-sas", listSAsRequest{IKE: conn, NoBlock: true})
	if err != nil {
		return nil, err
	}
	var ids []string
	for ev, err := range s.c.CallStreaming(ctx, "list-sas", "list-sa", req) {
		if err != nil {
			return nil, &CommandError{Command: "list-sas", Err: err}
		}
		for _, name := range ev.Keys() {
			sa, ok := ev.Get(name).(*govici.Message)
			if !ok {
				continue
			}
			if id, ok := sa.Get("uniqueid").(string); ok {
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

func (s *viciSession) TerminateIKE(ctx context.Context, uniqueID string) error {
	req, err := request("terminate", terminateRequest{IKEID: uniqueID, Force: true})
	if err != nil {
		return err
	}
	_, err = s.call(ctx, "terminate", req)
	return err
}

func (s *viciSession) LoadCert(ctx context.Context, cred Credential) error {
	kind, ok := credentialTypes[cred.Kind]
	if !ok || len(cred.DER) == 0 {
		return &CommandError{Command: "load-cert", Err: ErrInvalidMessage}
	}
	// Certificates and CRLs are public: the string copy is harmless.
	req, err := request("load-cert", loadCertRequest{Type: kind[0], Flag: kind[1], Data: string(cred.DER)})
	if err != nil {
		return err
	}
	_, err = s.call(ctx, "load-cert", req)
	return err
}

func (s *viciSession) LoadToken(ctx context.Context, key TokenKey, pin *secure.Secret) error {
	if len(key.KeyID) == 0 {
		return &CommandError{Command: "load-token", Err: ErrInvalidMessage}
	}
	req, err := request("load-token", loadTokenRequest{
		Handle: hex.EncodeToString(key.KeyID),
		Slot:   key.Slot,
		Module: key.Module,
	})
	if err != nil {
		return err
	}
	if pin == nil {
		_, err = s.call(ctx, "load-token", req)
		return err
	}
	buf, err := pin.Open()
	if err != nil {
		return &CommandError{Command: "load-token", Err: err}
	}
	defer buf.Destroy()
	if err := req.Set("pin", lockedString(buf.Bytes())); err != nil {
		return &CommandError{Command: "load-token", Err: err}
	}
	// Runs before Destroy: the message must not keep a view of memory
	// that is about to be wiped and unmapped.
	defer req.Unset("pin")
	_, err = s.call(ctx, "load-token", req)
	return err
}

// lockedString views b, a locked buffer, as a string without copying it.
// govici's messages hold strings only, and converting would leave a heap
// copy of the PIN that nothing wipes. The view must not outlive the buffer.
// govici's encoder still copies the value into the packet it writes; that
// copy is govici's, and is not wiped.
func lockedString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b)) // #nosec G103 -- aliases a locked buffer for the length of one call
}

// eventSource is the part of *govici.Session an event stream uses.
type eventSource interface {
	NotifyEvents(c chan<- govici.Event)
	Close() error
}

// viciEvents is an EventStream over govici.
type viciEvents struct {
	src       eventSource
	out       chan IKEUpdown
	done      chan struct{}
	closeOnce sync.Once
}

func newVICIEvents(src eventSource) *viciEvents {
	e := &viciEvents{src: src, out: make(chan IKEUpdown), done: make(chan struct{})}
	in := make(chan govici.Event, eventBuffer)
	src.NotifyEvents(in)
	go e.forward(in)
	return e
}

// forward hands each ike-updown event on until govici closes in, which it
// does when the connection ends, or the stream is closed.
func (e *viciEvents) forward(in <-chan govici.Event) {
	defer close(e.out)
	for {
		var ev govici.Event
		select {
		case <-e.done:
			return
		case next, ok := <-in:
			if !ok {
				return
			}
			ev = next
		}
		if ev.Name != updownEvent || ev.Message == nil {
			continue
		}
		select {
		case e.out <- parseUpdown(ev.Message):
		case <-e.done:
			return
		}
	}
}

func (e *viciEvents) Events() <-chan IKEUpdown { return e.out }

func (e *viciEvents) Close() error {
	var err error
	e.closeOnce.Do(func() {
		close(e.done)
		if cerr := e.src.Close(); cerr != nil {
			err = &CommandError{Command: "close", Err: cerr}
		}
	})
	return err
}

// parseUpdown reads an ike-updown message: up=yes when the SAs came up,
// and one section per IKE_SA, named after its connection.
func parseUpdown(m *govici.Message) IKEUpdown {
	up, _ := m.Get("up").(string)
	ev := IKEUpdown{Up: up == "yes", SAs: make(map[string]IKESA)}
	for _, name := range m.Keys() {
		section, ok := m.Get(name).(*govici.Message)
		if !ok {
			continue
		}
		var sa IKESA
		if err := govici.UnmarshalMessage(section, &sa); err != nil {
			// An SA that does not parse cannot prove its identity: an
			// empty remote-id fails the check, which ends the SA.
			sa.RemoteID = ""
		}
		ev.SAs[name] = sa
	}
	return ev
}
