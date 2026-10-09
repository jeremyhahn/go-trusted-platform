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
	"strconv"
	"sync"
	"unsafe"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	govici "github.com/strongswan/govici/vici"
	"golang.org/x/sys/unix"
)

const (
	// DefaultVICISocket is charon's control socket, as the shipped
	// strongswan.d/trusted-platform.conf sets it.
	DefaultVICISocket = "/run/charon.vici"

	// socketMode is the only mode the VICI socket may have: VICI carries
	// no authentication, so whoever can open the socket commands charon.
	socketMode fs.FileMode = 0o600

	// eventBuffer is how many events govici queues for the stream. govici
	// drops an event rather than block when the queue is full; the stream
	// then marks the next event Lost.
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

// VICIDialer opens govici sessions on charon's VICI socket. VICI carries no
// authentication, so the dialer checks both ends of every connection: the
// socket must be mode 0600 and owned by Owner, and the process serving it
// must have listened as Charon.
type VICIDialer struct {
	// Socket is the socket path.
	Socket string
	// Owner is the uid that must own the socket: platformd's.
	Owner int
	// Charon is the uid the serving process listened as. SO_PEERCRED
	// reports the credentials of the listen call, and charon creates the
	// socket before it drops root, so for the shipped package this is 0.
	Charon int
}

// NewVICIDialer returns a dialer for socket, which this process's
// effective user must own and a process that listened as uid charon must
// serve.
func NewVICIDialer(socket string, charon int) *VICIDialer {
	return &VICIDialer{Socket: socket, Owner: os.Geteuid(), Charon: charon}
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

// open starts a govici session over d.dial. govici dials with a background
// context; the dial honours ctx instead. govici returns the dial's error
// as it is, a *SocketError.
func (d *VICIDialer) open(ctx context.Context) (*govici.Session, error) {
	dial := func(context.Context, string, string) (net.Conn, error) { return d.dial(ctx) }
	return govici.NewSession(govici.WithDialContext(dial))
}

// dial connects through a descriptor opened on the socket path rather than
// through the path, so the checks and the connect see the same inode: a
// socket swapped in under the path after the checks is never reached. The
// serving process is checked once connected.
func (d *VICIDialer) dial(ctx context.Context) (net.Conn, error) {
	fd, err := openSocket(d.Socket, d.Owner)
	if err != nil {
		return nil, err
	}
	var nd net.Dialer
	conn, dialErr := nd.DialContext(ctx, "unix", fdPath(fd))
	closeErr := unix.Close(fd)
	if dialErr != nil {
		if closeErr != nil {
			dialErr = &CloseError{Cause: dialErr, Err: closeErr}
		}
		return nil, &SocketError{Path: d.Socket, Err: dialErr}
	}
	if closeErr != nil {
		return nil, closeAfter(conn, &SocketError{Path: d.Socket, Err: closeErr})
	}
	if err := checkPeer(conn, d.Charon); err != nil {
		return nil, closeAfter(conn, &SocketError{Path: d.Socket, Err: err})
	}
	return conn, nil
}

// fdPath names the file behind this process's descriptor fd. Connecting
// to it reaches the socket fd was opened on, whatever its path names now.
func fdPath(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

// openSocket opens path itself, never a symlink's target, as an O_PATH
// descriptor, and refuses it unless it is a socket of mode 0600 owned by
// owner. The caller closes the descriptor.
func openSocket(path string, owner int) (int, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, &SocketError{Path: path, Err: err}
	}
	if err := checkSocket(fd, owner); err != nil {
		var cause error = &SocketError{Path: path, Err: err}
		if closeErr := unix.Close(fd); closeErr != nil {
			cause = &CloseError{Cause: cause, Err: closeErr}
		}
		return -1, cause
	}
	return fd, nil
}

// checkSocket refuses a descriptor that is not a socket, not mode 0600, or
// not owned by owner.
func checkSocket(fd, owner int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return ErrNotSocket
	}
	if fs.FileMode(st.Mode&0o7777) != socketMode {
		return ErrSocketMode
	}
	if int(st.Uid) != owner {
		return ErrSocketOwner
	}
	return nil
}

// checkPeer refuses a connection whose serving process did not listen as
// uid.
func checkPeer(conn net.Conn, uid int) error {
	cred, err := peercred.ExtractUnixCredentials(conn)
	if err != nil {
		return err
	}
	if int(cred.UID) != uid {
		return ErrSocketPeer
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

func (s *viciSession) IKESAs(ctx context.Context, conn string) ([]HeldSA, error) {
	req, err := request("list-sas", listSAsRequest{IKE: conn, NoBlock: true})
	if err != nil {
		return nil, err
	}
	var held []HeldSA
	for ev, err := range s.c.CallStreaming(ctx, "list-sas", "list-sa", req) {
		if err != nil {
			return nil, &CommandError{Command: "list-sas", Err: err}
		}
		for _, name := range ev.Keys() {
			if section, ok := ev.Get(name).(*govici.Message); ok {
				held = append(held, HeldSA{Conn: name, SA: parseSA(section)})
			}
		}
	}
	return held, nil
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
//
// govici queues events in in and drops one it cannot queue. A queue found
// full, or one short of full, after a receive may have dropped events, so
// the next event handed on is marked Lost; when no ike-updown comes next,
// a Lost event without SAs is handed on in place of whatever was read.
func (e *viciEvents) forward(in <-chan govici.Event) {
	defer close(e.out)
	lost := false
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
		if len(in) >= cap(in)-1 {
			lost = true
		}
		var up IKEUpdown
		switch {
		case ev.Name == updownEvent && ev.Message != nil:
			up = parseUpdown(ev.Message)
		case !lost:
			continue
		}
		up.Lost = lost
		select {
		case e.out <- up:
			lost = false
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
		ev.SAs[name] = parseSA(section)
	}
	return ev
}

// parseSA reads one IKE_SA section of an ike-updown event or a list-sas
// reply.
func parseSA(section *govici.Message) IKESA {
	var sa IKESA
	if err := govici.UnmarshalMessage(section, &sa); err != nil {
		// An SA that does not parse cannot prove its identity: an empty
		// remote-id fails the check, which ends the SA.
		sa.RemoteID = ""
	}
	return sa
}
