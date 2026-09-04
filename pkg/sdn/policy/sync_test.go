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

package policy

import (
	"sync"
	"testing"
	"time"
)

// policyDeadline bounds how long a test waits for a monitor sweep or callback
// that must eventually happen. It is a liveness backstop, not a timing
// assumption: these tests advance on the event itself, so a loaded machine only
// makes them slower.
const policyDeadline = 10 * time.Second

// signal is the counter-plus-wakeup pair the monitor tests synchronise on. The
// count is authoritative and the channel only nudges a waiter, so a wakeup
// dropped while nobody is waiting cannot lose an occurrence.
type signal struct {
	mu    sync.Mutex
	count int
	wake  chan struct{}
}

func newSignal() *signal {
	return &signal{wake: make(chan struct{}, 1)}
}

// fire records one occurrence. It runs on the monitor's goroutine, so it must
// never block.
func (s *signal) fire() {
	s.mu.Lock()
	s.count++
	s.mu.Unlock()

	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *signal) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func (s *signal) await(t *testing.T, want int, what string) {
	t.Helper()

	deadline := time.After(policyDeadline)
	for {
		if s.n() >= want {
			return
		}
		select {
		case <-s.wake:
		case <-deadline:
			t.Fatalf("%s: got %d of %d within %s", what, s.n(), want, policyDeadline)
		}
	}
}

// observeChecks wires the monitor's sweep hook to a signal. Call it BEFORE
// Start: onCheck is read by the monitor goroutine without synchronisation, on
// the understanding that it is fixed before the goroutine exists.
func observeChecks(m *CertificateMonitor) *signal {
	s := newSignal()
	m.onCheck = s.fire
	return s
}

// awaitChecks blocks until the monitor has completed want sweeps. This is what
// makes a negative assertion meaningful: "the callback did not fire" is worth
// nothing until a sweep has provably run.
func awaitChecks(t *testing.T, s *signal, want int) {
	t.Helper()
	s.await(t, want, "monitor completed sweeps")
}
