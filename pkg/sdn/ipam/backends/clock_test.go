package backends

import (
	"sync"
	"time"
)

// manualClock is a time source the test advances by hand, passed to the
// backend as MemoryBackendConfig.Clock. Expiry tests move it across the
// inactivity boundary instead of sleeping past it (#284).
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func newManualClock() *manualClock {
	return &manualClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// Now returns the clock's current time.
func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newClockedMemoryBackend returns a memory backend reading time from clock.
func newClockedMemoryBackend(clock *manualClock) *MemoryBackend {
	return NewMemoryBackendWithConfig(&MemoryBackendConfig{Clock: clock.Now})
}
