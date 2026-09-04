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

package daemon

import (
	"sync"
	"testing"
	"time"
)

// streamDeadline bounds how long a test waits for something that must
// eventually happen — a stream registering its subscription, or a published
// message reaching the mock. It is a liveness backstop, not a timing
// assumption: these tests advance on the event itself, so a loaded machine only
// makes them slower, and the deadline is reached only when the stream has
// genuinely stopped making progress.
const streamDeadline = 10 * time.Second

// signal is the counter-plus-wakeup pair these tests synchronise on. The count
// is authoritative and the channel only nudges a waiter, so a wakeup dropped
// while nobody was waiting can never lose an event.
//
// It replaces the two sleeps every streaming subtest used to carry — "give
// stream time to initialize" and "give X time to be sent" — both of which
// stated the condition in a comment and then guessed a duration for it. Under
// CI load 50ms was not enough for the stream goroutine to reach its subscribe
// call, so publishes fanned out to nobody and the assertion saw 0 of 2 (#255).
type signal struct {
	mu    sync.Mutex
	count int
	wake  chan struct{}
}

func newSignal() *signal {
	return &signal{wake: make(chan struct{}, 1)}
}

// fire records one occurrence. It runs on the stream's own goroutine, so it
// must never block.
func (s *signal) fire() {
	s.mu.Lock()
	s.count++
	s.mu.Unlock()

	select {
	case s.wake <- struct{}{}:
	default: // a wakeup is already pending and unconsumed; one is enough
	}
}

// n returns the number of occurrences so far.
func (s *signal) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// await blocks until at least want occurrences have been recorded, failing the
// test with what it was waiting for if progress stops.
func (s *signal) await(t *testing.T, want int, what string) {
	t.Helper()

	deadline := time.After(streamDeadline)
	for {
		if s.n() >= want {
			return
		}
		select {
		case <-s.wake:
		case <-deadline:
			t.Fatalf("%s: got %d of %d within %s", what, s.n(), want, streamDeadline)
		}
	}
}

// observeSubscriptions wires the service's subscribe hook to a signal, so a
// test can wait for a stream to be able to receive before it publishes.
func observeSubscriptions(svc *Service) *signal {
	s := newSignal()
	svc.onSubscribe = s.fire
	return s
}

// awaitSubscribed blocks until want streams have registered.
func awaitSubscribed(t *testing.T, s *signal, want int) {
	t.Helper()
	s.await(t, want, "streams registered")
}
