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
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// DefaultSocket is where charon's vici plugin listens by default.
const DefaultSocket = "/var/run/charon.vici"

// maxPendingEvents bounds the events a Conn queues while an exchange is in
// progress, so a subscriber that stops reading cannot grow memory without
// limit; the connection fails instead.
const maxPendingEvents = 1024

// ErrEventBacklog is returned when more than maxPendingEvents events queue
// up unread.
var ErrEventBacklog = errors.New("vici: event backlog exceeded")

// Event is an event charon raised.
type Event struct {
	// Name is the event name, e.g. "ike-updown".
	Name string
	// Message is the event payload.
	Message *Message
}

// Conn is one VICI session. Exchanges on it are serialised: a command,
// a registration and a wait for an event each own the socket until they
// finish. Events for subscribed names that arrive during another exchange
// are queued for NextEvent.
//
// A transport failure, a protocol violation or a cancelled context closes
// the Conn, because the position in the packet stream is then unknown.
// A refused command (CommandError) or an unknown command or event leaves
// it usable.
type Conn struct {
	nc      net.Conn
	sem     chan struct{}
	closed  atomic.Bool
	pending []Event // guarded by sem
}

// Dial connects to charon's VICI socket.
func Dial(ctx context.Context, path string) (*Conn, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, &OpError{Op: "dial", Err: err}
	}
	return NewConn(nc), nil
}

// NewConn wraps an established stream connection.
func NewConn(nc net.Conn) *Conn {
	return &Conn{nc: nc, sem: make(chan struct{}, 1)}
}

// Close closes the connection. Closing twice returns ErrClosed.
func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return ErrClosed
	}
	if err := c.nc.Close(); err != nil {
		return &OpError{Op: "close", Err: err}
	}
	return nil
}

// Closed reports whether the connection has been closed, by Close or by a
// failure.
func (c *Conn) Closed() bool { return c.closed.Load() }

// acquire takes the exchange slot and arms ctx cancellation on the socket.
// The returned release must be called when the exchange ends.
func (c *Conn) acquire(ctx context.Context) (func(), error) {
	if c.closed.Load() {
		return nil, ErrClosed
	}
	// select picks at random among ready cases, so an already-ended
	// context must be caught before it races a free slot.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if c.closed.Load() {
		<-c.sem
		return nil, ErrClosed
	}
	stop := context.AfterFunc(ctx, c.interrupt)
	return func() {
		stop()
		<-c.sem
	}, nil
}

// interrupt unblocks the read or write in flight when an exchange's
// context ends; the exchange then fails and closes the connection.
func (c *Conn) interrupt() {
	// SetDeadline fails only on a closed connection, which has nothing
	// left to interrupt.
	if err := c.nc.SetDeadline(time.Unix(1, 0)); err != nil {
		return
	}
}

// fail closes the connection after cause left the stream position
// unknown, and returns cause together with any error from the close.
func (c *Conn) fail(cause error) error {
	if !c.closed.CompareAndSwap(false, true) {
		return cause
	}
	if err := c.nc.Close(); err != nil {
		return errors.Join(cause, &OpError{Op: "close", Err: err})
	}
	return cause
}

// transportError fails the connection and wraps err, preferring the
// context's error when the context ended the exchange.
func (c *Conn) transportError(ctx context.Context, op string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	}
	return c.fail(&OpError{Op: op, Err: err})
}

// send writes one packet. An encoding error leaves the connection usable,
// because nothing reached the socket.
func (c *Conn) send(ctx context.Context, op string, kind byte, name string, msg *Message) error {
	if err := writePacket(c.nc, kind, name, msg); err != nil {
		var encodeErr *EncodeError
		if errors.As(err, &encodeErr) || errors.Is(err, ErrEmptyName) || errors.Is(err, ErrMessageTooLarge) {
			return err
		}
		return c.transportError(ctx, op, err)
	}
	return nil
}

// receive reads one packet. Any failure closes the connection.
func (c *Conn) receive(ctx context.Context, op string) (packet, error) {
	p, err := readPacket(c.nc)
	if err != nil {
		var decodeErr *DecodeError
		if errors.As(err, &decodeErr) || errors.Is(err, ErrMessageTooLarge) {
			return packet{}, c.fail(err)
		}
		return packet{}, c.transportError(ctx, op, err)
	}
	return p, nil
}

// queue holds an event for NextEvent. The caller holds the exchange slot.
func (c *Conn) queue(p packet) error {
	if len(c.pending) >= maxPendingEvents {
		return c.fail(ErrEventBacklog)
	}
	c.pending = append(c.pending, Event{Name: p.name, Message: p.message})
	return nil
}

// unexpected fails the connection on a packet the exchange does not allow.
func (c *Conn) unexpected(op string) error {
	return c.fail(&OpError{Op: op, Err: ErrUnexpectedPacket})
}

// Call sends a command and returns its response. A nil req sends an empty
// message. When the response carries success=no, Call returns the response
// together with a *CommandError holding charon's errmsg.
func (c *Conn) Call(ctx context.Context, command string, req *Message) (*Message, error) {
	return c.CallStreaming(ctx, command, "", req, nil)
}

// CallStreaming sends a command whose results charon streams as events
// (list-sas streams "list-sa", list-conns streams "list-conn", ...). It
// registers for event, issues the command, hands each streamed event to fn
// and returns the final response. An error from fn stops further calls to
// fn; the stream is still drained so the connection stays in step, and
// the first fn error is returned with the response. An empty event
// behaves like Call.
func (c *Conn) CallStreaming(ctx context.Context, command, event string, req *Message, fn func(*Message) error) (*Message, error) {
	if command == "" {
		return nil, ErrEmptyName
	}
	release, err := c.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	if event == "" {
		return c.exchange(ctx, command, "", req, nil)
	}
	if err := c.register(ctx, pktEventRegister, event); err != nil {
		return nil, err
	}
	var fnErr error
	deliver := func(m *Message) {
		if fn != nil && fnErr == nil {
			fnErr = fn(m)
		}
	}
	resp, err := c.exchange(ctx, command, event, req, deliver)
	if c.closed.Load() {
		return nil, err
	}
	// The command ran (or charon refused it as unknown) with the stream
	// intact: drop the registration so later events do not pile up.
	if unregErr := c.register(ctx, pktEventUnregister, event); unregErr != nil {
		return nil, errors.Join(err, unregErr)
	}
	if fnErr != nil {
		return resp, fnErr
	}
	return resp, err
}

// exchange sends a command and reads up to its response, handing events
// named event to deliver and queueing any other. The caller holds the
// exchange slot.
func (c *Conn) exchange(ctx context.Context, command, event string, req *Message, deliver func(*Message)) (*Message, error) {
	if err := c.send(ctx, command, pktCmdRequest, command, req); err != nil {
		return nil, err
	}
	for {
		p, err := c.receive(ctx, command)
		if err != nil {
			return nil, err
		}
		switch {
		case p.kind == pktCmdResponse:
			return p.message, commandStatus(command, p.message)
		case p.kind == pktCmdUnknown:
			return nil, &OpError{Op: command, Err: ErrUnknownCommand}
		case p.kind == pktEvent && event != "" && p.name == event:
			deliver(p.message)
		case p.kind == pktEvent:
			if err := c.queue(p); err != nil {
				return nil, err
			}
		default:
			return nil, c.unexpected(command)
		}
	}
}

// commandStatus turns a response's success=no into a CommandError.
// Responses without a success key (version, stats, list commands) succeed.
func commandStatus(command string, resp *Message) error {
	status, ok := resp.Value("success")
	if !ok || status == "yes" {
		return nil
	}
	// An absent errmsg reads as "", which CommandError renders without one.
	reason, _ := resp.Value("errmsg")
	return &CommandError{Command: command, Message: reason}
}

// register sends an event (un)registration and waits for its confirmation.
// The caller holds the exchange slot.
func (c *Conn) register(ctx context.Context, kind byte, event string) error {
	if err := c.send(ctx, event, kind, event, nil); err != nil {
		return err
	}
	for {
		p, err := c.receive(ctx, event)
		if err != nil {
			return err
		}
		switch p.kind {
		case pktEventConfirm:
			return nil
		case pktEventUnknown:
			return &OpError{Op: event, Err: ErrUnknownEvent}
		case pktEvent:
			if err := c.queue(p); err != nil {
				return err
			}
		default:
			return c.unexpected(event)
		}
	}
}

// Subscribe registers for events; NextEvent then returns them. Events for
// one name may arrive before the next name's registration is confirmed;
// they are queued, not lost.
func (c *Conn) Subscribe(ctx context.Context, events ...string) error {
	return c.registerAll(ctx, pktEventRegister, events)
}

// Unsubscribe cancels registrations made by Subscribe.
func (c *Conn) Unsubscribe(ctx context.Context, events ...string) error {
	return c.registerAll(ctx, pktEventUnregister, events)
}

func (c *Conn) registerAll(ctx context.Context, kind byte, events []string) error {
	for _, e := range events {
		if e == "" {
			return ErrEmptyName
		}
	}
	release, err := c.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	for _, e := range events {
		if err := c.register(ctx, kind, e); err != nil {
			return err
		}
	}
	return nil
}

// NextEvent returns the next event for a subscribed name, waiting until
// one arrives or ctx ends. A cancelled wait closes the connection, so an
// event subscription belongs on a Conn of its own.
func (c *Conn) NextEvent(ctx context.Context) (Event, error) {
	release, err := c.acquire(ctx)
	if err != nil {
		return Event{}, err
	}
	defer release()
	if len(c.pending) > 0 {
		e := c.pending[0]
		c.pending[0] = Event{}
		c.pending = c.pending[1:]
		return e, nil
	}
	p, err := c.receive(ctx, "event")
	if err != nil {
		return Event{}, err
	}
	if p.kind != pktEvent {
		return Event{}, c.unexpected("event")
	}
	return Event{Name: p.name, Message: p.message}, nil
}
