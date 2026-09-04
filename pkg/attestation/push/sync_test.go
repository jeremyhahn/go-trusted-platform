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

package push

import (
	"sync/atomic"
	"testing"
	"time"
)

// testDeadline bounds how long a test waits for a push that must eventually
// happen. It is a liveness backstop, not a timing assumption: these tests
// advance on completed pushes, so a slow or loaded machine only takes longer,
// and the deadline is reached only by a scheduler that has stopped making
// progress.
const testDeadline = 10 * time.Second

// pushObserver records completed push batches so a test can wait for the pushes
// it needs instead of asserting how many fit inside a wall-clock window. That
// window was what failed on a loaded host: TestSchedulerPeriodicPush asserted
// two pushes inside 150ms and got one (issue #207).
//
// handle is the scheduler's result handler, so the count and the wakeup are the
// scheduler's own notion of a completed push, not the test's guess at one.
type pushObserver struct {
	// count is authoritative. wake only nudges a waiter, so a wakeup dropped
	// while nobody was waiting can never lose a push.
	count atomic.Int32
	wake  chan struct{}
}

func newPushObserver() *pushObserver {
	return &pushObserver{wake: make(chan struct{}, 1)}
}

// handle records a completed push. It is passed to WithHandler and runs on the
// scheduler's result goroutine, so it must never block.
func (o *pushObserver) handle(*PushBatchResult) {
	o.count.Add(1)
	select {
	case o.wake <- struct{}{}:
	default: // a wakeup is already pending and unconsumed; one is enough
	}
}

// Count returns the number of pushes completed so far.
func (o *pushObserver) Count() int32 {
	return o.count.Load()
}

// awaitPushes blocks until the scheduler has completed at least n pushes,
// failing the test if it stops making progress.
func (o *pushObserver) awaitPushes(t *testing.T, n int32) {
	t.Helper()

	deadline := time.After(testDeadline)
	for {
		if o.count.Load() >= n {
			return
		}
		select {
		case <-o.wake:
		case <-deadline:
			t.Fatalf("scheduler completed %d of %d pushes within %s", o.count.Load(), n, testDeadline)
		}
	}
}
