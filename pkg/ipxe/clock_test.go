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

package ipxe

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// manualClock is a hand-advanced clock. Lease-expiry tests used to spend real
// time to reach an expiry; they now move this instead, which is both instant
// and exact — a sleep only guarantees AT LEAST the duration, so the old tests
// asserted against an unknown amount of elapsed time (#284).
//
// Named to distinguish it from media_watch_test.go's fakeClock, which AUTO-
// advances one second per call and is wired through a func() time.Time rather
// than this interface. Two seams, two shapes, one package: the watcher wants
// time to move on its own, the lease tables must not.
//
// Safe for concurrent use: the allocators and DHCPServer read the clock under
// their own locks, and a test may advance it from another goroutine.
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

// newManualClock starts at a fixed instant rather than time.Now(), so a test that
// accidentally depends on the wall clock fails consistently instead of rarely.
func newManualClock() *manualClock {
	return &manualClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// Now returns the current fake instant.
func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the fake clock forward.
func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TestManualClock_Advance pins the test double itself: a fake that did not move,
// or moved by the wrong amount, would make every expiry test vacuous.
func TestManualClock_Advance(t *testing.T) {
	t.Run("advances by exactly the requested duration", func(t *testing.T) {
		c := newManualClock()
		start := c.Now()
		c.Advance(90 * time.Second)
		assert.Equal(t, 90*time.Second, c.Now().Sub(start))
	})

	t.Run("does not move on its own", func(t *testing.T) {
		c := newManualClock()
		first := c.Now()
		assert.Equal(t, first, c.Now(), "the fake clock must only move when advanced")
	})
}

// TestRealClock_Now confirms the production clock is the standard library and
// actually moves, which is what the fake is standing in for.
func TestRealClock_Now(t *testing.T) {
	t.Run("returns a plausible wall-clock time", func(t *testing.T) {
		got := realClock{}.Now()
		assert.WithinDuration(t, time.Now(), got, time.Second)
	})

	t.Run("satisfies the clock interface", func(t *testing.T) {
		var c clock = realClock{}
		assert.False(t, c.Now().IsZero())
	})
}
