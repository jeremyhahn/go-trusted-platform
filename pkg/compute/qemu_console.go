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

package compute

import (
	"context"
	"net"
	"path/filepath"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// consoleReadBuffer is the read chunk size for the upstream QEMU console
// connection.
const consoleReadBuffer = 4096

// consoleSubscriberBuffer bounds each attached viewer's output channel. When a
// viewer cannot keep up, output is dropped for that viewer only (its stream
// lags) so a single slow viewer cannot stall the broker or other viewers.
const consoleSubscriberBuffer = 512

// dialConsoleSocket dials a VM's console unix socket. It is a seam so tests can
// substitute an in-memory endpoint.
var dialConsoleSocket = func(path string) (net.Conn, error) {
	return net.Dial("unix", path)
}

// consoleBrokerRegistry holds the live console brokers keyed by instance ID.
// Instance IDs are globally unique, so a single process-wide registry is safe;
// brokers self-close when their upstream connection ends, and the orchestrator
// closes them explicitly on VM stop/delete.
var consoleBrokerRegistry = &consoleRegistry{brokers: make(map[string]*consoleBroker)}

// consoleSocketPath returns the console unix socket path for an instance. It
// must match the console chardev socket configured on the QEMU VM at boot.
func consoleSocketPath(inst *qemuInstance) string {
	if inst == nil || inst.instance == nil || inst.instance.Config == nil {
		return ""
	}
	return filepath.Join(inst.instance.Config.WorkDir, "console.sock")
}

// consoleRegistry maps instance IDs to their console broker.
type consoleRegistry struct {
	mu      sync.Mutex
	brokers map[string]*consoleBroker
}

// getOrCreate returns the broker for id, creating it (and dialing the upstream
// console connection) on first use.
func (r *consoleRegistry) getOrCreate(id string, dial func() (net.Conn, error), logger *logging.Logger) (*consoleBroker, error) {
	r.mu.Lock()
	if b, ok := r.brokers[id]; ok && !b.isClosed() {
		r.mu.Unlock()
		return b, nil
	}
	conn, err := dial()
	if err != nil {
		r.mu.Unlock()
		return nil, &SentinelCauseError{Sentinel: ErrConsoleUnavailable, Cause: err}
	}
	b := &consoleBroker{
		id:      id,
		conn:    conn,
		logger:  logger,
		subs:    make(map[uint64]chan []byte),
		onClose: func() { r.remove(id) },
	}
	r.brokers[id] = b
	r.mu.Unlock()

	go b.readLoop()
	return b, nil
}

// remove drops a broker from the registry.
func (r *consoleRegistry) remove(id string) {
	r.mu.Lock()
	delete(r.brokers, id)
	r.mu.Unlock()
}

// close closes the broker for id, if present.
func (r *consoleRegistry) close(id string) {
	r.mu.Lock()
	b, ok := r.brokers[id]
	r.mu.Unlock()
	if ok {
		_ = b.Close()
	}
}

// consoleBroker owns the single upstream connection to a VM's console socket
// and fans its output out to any number of attached viewers while serializing
// their input writes onto the one connection.
type consoleBroker struct {
	id      string
	conn    net.Conn
	logger  *logging.Logger
	onClose func()

	mu      sync.Mutex
	subs    map[uint64]chan []byte
	nextSub uint64
	closed  bool
}

// readLoop reads console output from the upstream connection and fans it out
// to every attached viewer until the connection ends.
func (b *consoleBroker) readLoop() {
	buf := make([]byte, consoleReadBuffer)
	for {
		n, err := b.conn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			b.fanout(chunk)
		}
		if err != nil {
			_ = b.Close()
			return
		}
	}
}

// fanout delivers a chunk to every subscriber, dropping for any viewer whose
// buffer is full (that viewer's stream lags; others are unaffected).
func (b *consoleBroker) fanout(chunk []byte) {
	b.mu.Lock()
	for _, ch := range b.subs {
		select {
		case ch <- chunk:
		default:
			if b.logger != nil {
				b.logger.Warnf("console broker %s: dropping output for a slow viewer", b.id)
			}
		}
	}
	b.mu.Unlock()
}

// subscribe registers a new viewer and returns its session.
func (b *consoleBroker) subscribe() (*consoleSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, &SentinelCauseError{Sentinel: ErrConsoleUnavailable, Cause: &MessageError{Msg: "console broker closed"}}
	}
	id := b.nextSub
	b.nextSub++
	ch := make(chan []byte, consoleSubscriberBuffer)
	b.subs[id] = ch
	return &consoleSession{broker: b, id: id, out: ch}, nil
}

// unsubscribe detaches a viewer and closes its output channel.
func (b *consoleBroker) unsubscribe(id uint64) {
	b.mu.Lock()
	if ch, ok := b.subs[id]; ok {
		delete(b.subs, id)
		close(ch)
	}
	b.mu.Unlock()
}

// write serializes input onto the single upstream connection.
func (b *consoleBroker) write(p []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return &SentinelCauseError{Sentinel: ErrConsoleUnavailable, Cause: &MessageError{Msg: "console broker closed"}}
	}
	_, err := b.conn.Write(p)
	if err != nil {
		return &WrappedError{Msg: "console write failed", Err: err}
	}
	return nil
}

// isClosed reports whether the broker has been closed.
func (b *consoleBroker) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// Close tears down the broker: it closes every viewer channel, the upstream
// connection, and removes itself from the registry. It is idempotent.
func (b *consoleBroker) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	for id, ch := range b.subs {
		delete(b.subs, id)
		close(ch)
	}
	conn := b.conn
	onClose := b.onClose
	b.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
	if onClose != nil {
		onClose()
	}
	return nil
}

// consoleSession is one attached viewer of a broker.
type consoleSession struct {
	broker *consoleBroker
	id     uint64
	out    chan []byte
	once   sync.Once
}

// Output returns the viewer's output channel.
func (s *consoleSession) Output() <-chan []byte { return s.out }

// Write forwards input to the shared broker connection.
func (s *consoleSession) Write(p []byte) error { return s.broker.write(p) }

// Close detaches the viewer. It is safe to call more than once.
func (s *consoleSession) Close() error {
	s.once.Do(func() { s.broker.unsubscribe(s.id) })
	return nil
}

// consoleBrokerFor resolves the console broker for a running instance, creating
// it on first use.
func (o *QEMUOrchestrator) consoleBrokerFor(ctx context.Context, instanceID string) (*consoleBroker, error) {
	o.mu.RLock()
	inst, exists := o.instances[instanceID]
	o.mu.RUnlock()
	if !exists {
		return nil, ErrInstanceNotFound
	}

	state, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return nil, err
	}
	if state != StateRunning {
		return nil, &SentinelCauseError{Sentinel: ErrConsoleUnavailable, Cause: &MessageError{Msg: "VM console requires a running VM"}}
	}

	sockPath := consoleSocketPath(inst)
	if sockPath == "" {
		return nil, &SentinelCauseError{Sentinel: ErrConsoleUnavailable, Cause: &MessageError{Msg: "instance has no console socket"}}
	}

	return consoleBrokerRegistry.getOrCreate(instanceID, func() (net.Conn, error) {
		return dialConsoleSocket(sockPath)
	}, o.logger)
}

// AttachConsole attaches a new multiplexed viewer to the VM console.
func (o *QEMUOrchestrator) AttachConsole(ctx context.Context, instanceID string) (VMConsoleSession, error) {
	if instanceID == "" {
		return nil, ErrInvalidInstanceID
	}
	broker, err := o.consoleBrokerFor(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	return broker.subscribe()
}

// SendConsoleInput writes input to the VM console without attaching a viewer.
func (o *QEMUOrchestrator) SendConsoleInput(ctx context.Context, instanceID string, data []byte) error {
	if instanceID == "" {
		return ErrInvalidInstanceID
	}
	if len(data) == 0 {
		return nil
	}
	broker, err := o.consoleBrokerFor(ctx, instanceID)
	if err != nil {
		return err
	}
	return broker.write(data)
}

// closeConsole tears down any console broker for the instance. It is invoked
// from the orchestrator's Stop/Delete/Close paths so console resources do not
// outlive the VM.
func (o *QEMUOrchestrator) closeConsole(instanceID string) {
	consoleBrokerRegistry.close(instanceID)
}
