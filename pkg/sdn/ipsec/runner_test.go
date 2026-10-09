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
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// fakeStream is an EventStream the test feeds.
type fakeStream struct {
	events chan IKEUpdown
	// watching is signalled each time the runner waits on the stream,
	// which it does only once attached.
	watching chan struct{}
	closed   bool
	closeErr error
}

func newFakeStream() *fakeStream {
	return &fakeStream{events: make(chan IKEUpdown), watching: make(chan struct{}, 1)}
}

func (s *fakeStream) Events() <-chan IKEUpdown {
	select {
	case s.watching <- struct{}{}:
	default:
	}
	return s.events
}

func (s *fakeStream) Close() error {
	s.closed = true
	return s.closeErr
}

// attempt is what one connection attempt of the fake dialer yields.
type attempt struct {
	subErr, dialErr error
	stream          *fakeStream
	sess            *fakeSession
}

// fakeDialer hands out queued attempts, and once they are used up fails
// every subscription.
type fakeDialer struct {
	attempts []attempt
	cur      attempt
}

func (d *fakeDialer) Subscribe(context.Context) (EventStream, error) {
	d.cur = attempt{subErr: errInjected}
	if len(d.attempts) > 0 {
		d.cur, d.attempts = d.attempts[0], d.attempts[1:]
	}
	if d.cur.subErr != nil {
		return nil, d.cur.subErr
	}
	if d.cur.stream == nil {
		d.cur.stream = newFakeStream()
	}
	return d.cur.stream, nil
}

func (d *fakeDialer) Dial(context.Context) (Session, error) {
	if d.cur.dialErr != nil {
		return nil, d.cur.dialErr
	}
	return d.cur.sess, nil
}

type runnerHarness struct {
	*harness
	waits   chan time.Duration // each backoff the runner waits
	fire    chan time.Time     // ends the wait
	cancel  context.CancelFunc
	stopped chan struct{}
}

// startRunner runs a runner for a detached harness over attempts.
func startRunner(t *testing.T, attempts ...attempt) *runnerHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	rh := &runnerHarness{
		harness: newDetachedHarness(t),
		waits:   make(chan time.Duration),
		fire:    make(chan time.Time),
		cancel:  cancel,
		stopped: make(chan struct{}),
	}
	r, err := NewRunner(rh.ctl, &fakeDialer{attempts: attempts}, nil)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	r.after = func(d time.Duration) <-chan time.Time {
		select {
		case rh.waits <- d:
		case <-ctx.Done():
		}
		return rh.fire
	}
	go func() {
		defer close(rh.stopped)
		r.Run(ctx)
	}()
	t.Cleanup(func() { rh.stop(t) })
	return rh
}

// wait returns the backoff the runner waits next.
func (rh *runnerHarness) wait(t *testing.T) time.Duration {
	t.Helper()
	d, _ := recv(t, rh.waits)
	return d
}

// next ends the runner's wait.
func (rh *runnerHarness) next(t *testing.T) {
	t.Helper()
	select {
	case rh.fire <- time.Time{}:
	case <-time.After(5 * time.Second):
		t.Fatal("the runner is not waiting")
	}
}

func (rh *runnerHarness) stop(t *testing.T) {
	t.Helper()
	rh.cancel()
	recv(t, rh.stopped)
}

func TestNewRunnerRejects(t *testing.T) {
	h := newDetachedHarness(t)
	if _, err := NewRunner(nil, &fakeDialer{}, nil); !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("no controller: err = %v", err)
	}
	if _, err := NewRunner(h.ctl, nil, nil); !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("no dialer: err = %v", err)
	}
}

func TestRunnerReconnectRePushes(t *testing.T) {
	first, second := newFakeSession(), newFakeSession()
	firstStream, orphan, secondStream := newFakeStream(), newFakeStream(), newFakeStream()
	rh := startRunner(t,
		attempt{sess: first, stream: firstStream},
		attempt{dialErr: errInjected, stream: orphan},
		attempt{subErr: errInjected},
		attempt{sess: second, stream: secondStream},
	)
	ctx := context.Background()

	recv(t, firstStream.watching)
	if !rh.ctl.Status().Attached {
		t.Fatal("not attached to the first charon")
	}
	close(first.done) // charon stops
	if d := rh.wait(t); d != MinBackoff {
		t.Fatalf("first wait %v, want %v", d, MinBackoff)
	}
	if !first.closed || !firstStream.closed || rh.ctl.Status().Attached {
		t.Fatal("the ended session was not closed and detached")
	}
	if got := first.loaded(); !slices.Equal(got, []string{"vtep-10.20.0.1", "vtep-10.20.0.2"}) {
		t.Fatalf("first charon holds %v", got)
	}

	// While charon is away a CRL arrives and a route names a new peer.
	crl := rh.pki.crl(t, 1, rh.pki.issued)
	if err := rh.ctl.PushCRL(ctx, crl); err != nil {
		t.Fatalf("PushCRL: %v", err)
	}
	if err := rh.ctl.HandleEVPNRoute(ctx, imet(100, "10.20.0.30", false)); err != nil {
		t.Fatalf("route: %v", err)
	}

	rh.next(t) // the dial fails
	if d := rh.wait(t); d != 2*MinBackoff {
		t.Fatalf("wait after a failed dial %v, want %v", d, 2*MinBackoff)
	}
	if !orphan.closed {
		t.Fatal("the event stream of a failed dial was left open")
	}
	rh.next(t) // the subscription fails
	if d := rh.wait(t); d != 4*MinBackoff {
		t.Fatalf("wait after a failed subscription %v, want %v", d, 4*MinBackoff)
	}
	rh.next(t) // charon is back

	recv(t, secondStream.watching)
	if got := second.loaded(); !slices.Equal(got, []string{"vtep-10.20.0.1", "vtep-10.20.0.2", "vtep-10.20.0.30"}) {
		t.Fatalf("restarted charon holds %v", got)
	}
	if got := second.crls(); len(got) != 1 || !bytes.Equal(got[0], crl) {
		t.Fatal("the CRL was not re-pushed")
	}
	if len(second.tokens) != 1 || len(second.certs) != 3 {
		t.Fatalf("restarted charon has %d tokens and %d credentials", len(second.tokens), len(second.certs))
	}
	order := []int{
		slices.Index(second.commands, "load-token"),
		slices.Index(second.commands, "load-crl"),
		slices.Index(second.commands, "load-conn"),
	}
	if !slices.IsSorted(order) || order[0] < 0 {
		t.Fatalf("commands %v: want the identity, then the CRL, then the connections", second.commands)
	}

	// An SA that authenticated as another node is torn down.
	secondStream.events <- updown(true, "vtep-10.20.0.1", IKESA{UniqueID: "4", RemoteHost: "10.20.0.1", RemoteID: "10.20.0.2"})
	close(secondStream.events) // the event connection drops
	if d := rh.wait(t); d != MinBackoff {
		t.Fatalf("wait after an attached session %v, want the backoff reset to %v", d, MinBackoff)
	}
	if !slices.Equal(second.killed, []string{"4"}) {
		t.Fatalf("terminated %v, want the mismatched SA", second.killed)
	}
	if !second.closed || !secondStream.closed {
		t.Fatal("the command session outlived its event stream")
	}
}

func TestRunnerKeepsSessionThroughPeerFailures(t *testing.T) {
	sess, stream := newFakeSession(), newFakeStream()
	sess.fail["load-conn"] = errInjected
	sess.fail["close"] = errInjected
	stream.closeErr = errInjected
	rh := startRunner(t, attempt{sess: sess, stream: stream})

	recv(t, stream.watching)
	if !rh.ctl.Status().Attached {
		t.Fatal("peer failures ended the session")
	}
	rh.stop(t)
	if !sess.closed || !stream.closed || rh.ctl.Status().Attached {
		t.Fatal("stopping left the session open or attached")
	}
}

func TestRunnerBackoff(t *testing.T) {
	refused := newFakeSession()
	refused.fail["load-token"] = errInjected
	rh := startRunner(t, attempt{sess: refused})

	want := []time.Duration{
		MinBackoff, 2 * MinBackoff, 4 * MinBackoff, 8 * MinBackoff,
		16 * MinBackoff, 32 * MinBackoff, MaxBackoff, MaxBackoff,
	}
	for i, w := range want {
		if i > 0 {
			rh.next(t)
		}
		if d := rh.wait(t); d != w {
			t.Fatalf("wait %d = %v, want %v", i, d, w)
		}
	}
	if !refused.closed || len(refused.conns) != 0 || rh.ctl.Status().Attached {
		t.Fatal("a session whose identity failed to load was used")
	}
}
