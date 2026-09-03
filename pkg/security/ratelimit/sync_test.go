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

package ratelimit

import (
	"testing"
	"time"
)

// testDeadline bounds how long a test waits for something that must eventually happen —
// a cleanup sweep, or a Wait call that is only blocked on token or window decay. It is a
// liveness backstop, not a timing assumption: these tests advance on the event itself,
// so a slow or loaded machine only takes longer, and the deadline is reached only by a
// limiter that has genuinely stopped making progress.
const testDeadline = 10 * time.Second

// sweepObserver records completed cleanup sweeps so a test can wait for one instead of
// sleeping and hoping the background goroutine got there first. It is handed to the
// limiter constructors that accept an observer.
type sweepObserver struct {
	// sweeps carries one pending sweep notification; sends are non-blocking, so a
	// test that is not currently waiting never stalls the cleanup goroutine.
	sweeps chan struct{}
}

func newSweepObserver() *sweepObserver {
	return &sweepObserver{sweeps: make(chan struct{}, 1)}
}

// notify records a completed sweep. It is the func passed to the limiter, and runs on
// the cleanup goroutine, so it must never block.
func (o *sweepObserver) notify() {
	select {
	case o.sweeps <- struct{}{}:
	default: // a sweep is already recorded and unconsumed; one pending is enough
	}
}

// awaitSweepAfterNow blocks until a cleanup sweep that began after this call has
// completed, so the caller can assert on state it wrote beforehand.
//
// The first notification may come from a sweep already in flight, which need not have
// observed that state, so two are consumed. The cleanup loop is a single goroutine and
// the channel is FIFO, so the second notification comes from a strictly later sweep —
// one that started after the first finished, hence after this call began.
func (o *sweepObserver) awaitSweepAfterNow(t *testing.T) {
	t.Helper()

	select {
	case <-o.sweeps: // discard a notification that may predate the caller's writes
	default:
	}

	for i := 0; i < 2; i++ {
		select {
		case <-o.sweeps:
		case <-time.After(testDeadline):
			t.Fatalf("cleanup sweep did not complete within %s", testDeadline)
		}
	}
}

// awaitSweepUntil consumes completed sweeps until cond reports true. It lets a test
// assert on an outcome the sweep produces without assuming how many sweeps that takes
// or how fast the machine is; what is being waited for names the failure.
func (o *sweepObserver) awaitSweepUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.After(testDeadline)
	for {
		if cond() {
			return
		}
		select {
		case <-o.sweeps:
		case <-deadline:
			t.Fatalf("cleanup sweeps did not %s within %s", what, testDeadline)
		}
	}
}
