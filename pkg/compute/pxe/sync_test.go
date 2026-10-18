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

package pxe

import (
	"sync"
	"testing"
	"time"
)

// pxeDeadline bounds how long a test waits for an event that must eventually
// arrive. It is a liveness backstop, not a timing assumption: these tests
// advance on the event itself, so a loaded machine only makes them slower.
const pxeDeadline = 10 * time.Second

// eventSignal is the counter-plus-wakeup pair the event tests synchronise on.
// The count is authoritative and the channel only nudges a waiter, so a wakeup
// dropped while nobody was waiting cannot lose an event.
//
// emitEvent dispatches each handler on its own goroutine (state.go), so an
// assertion made straight after Transition races the dispatch. Every one of
// these tests bridged that with a 100ms sleep (#262).
type eventSignal struct {
	mu    sync.Mutex
	count int
	wake  chan struct{}
}

func newEventSignal() *eventSignal {
	return &eventSignal{wake: make(chan struct{}, 1)}
}

// fire records one delivered event. It runs on the dispatch goroutine, so it
// must never block.
func (s *eventSignal) fire() {
	s.mu.Lock()
	s.count++
	s.mu.Unlock()

	select {
	case s.wake <- struct{}{}:
	default: // a wakeup is already pending and unconsumed; one is enough
	}
}

func (s *eventSignal) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// await blocks until at least want events have been delivered.
func (s *eventSignal) await(t *testing.T, want int) {
	t.Helper()

	deadline := time.After(pxeDeadline)
	for {
		if s.n() >= want {
			return
		}
		select {
		case <-s.wake:
		case <-deadline:
			t.Fatalf("handler received %d of %d events within %s", s.n(), want, pxeDeadline)
		}
	}
}
