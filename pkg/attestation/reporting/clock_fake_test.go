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

package reporting

import (
	"sync"
	"time"
)

// fakeClock drives the collector without sleeping.
//
// It implements both halves of the seam for the reason the seam has two: the
// collector reads Now to age reports and blocks on After between cycles. A
// fake that advanced only Now would leave Run waiting on a real interval that
// never elapses in fake time, and the test would either sleep or hang.
//
// advance() releases every waiter whose deadline has passed, so a test drives
// the loop by moving time rather than by waiting for it.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []fakeWaiter
}

type fakeWaiter struct {
	at time.Time
	ch chan time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.waiters = append(c.waiters, fakeWaiter{at: c.now.Add(d), ch: ch})
	return ch
}

// advance moves fake time forward and fires every waiter now due.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	var due, pending []fakeWaiter
	for _, w := range c.waiters {
		if !w.at.After(now) {
			due = append(due, w)
		} else {
			pending = append(pending, w)
		}
	}
	c.waiters = pending
	c.mu.Unlock()

	for _, w := range due {
		w.ch <- now
	}
}

// waiters reports how many timers are outstanding, so a test can establish
// the loop has reached its wait before advancing — rather than racing it.
func (c *fakeClock) waiters_() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}
