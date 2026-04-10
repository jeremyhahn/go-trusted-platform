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
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// slidingWindowEntry represents a per-key sliding window state
type slidingWindowEntry struct {
	// currentCount is the count in the current window
	currentCount atomic.Int64

	// previousCount is the count from the previous window
	previousCount atomic.Int64

	// windowStart is the start time of the current window (Unix nano)
	windowStart atomic.Int64

	// lastAccess is the last access time for cleanup purposes
	lastAccess atomic.Int64

	// mu protects window rotation
	mu sync.Mutex
}

// SlidingWindowLimiter implements a sliding window rate limiter with per-key limiting
type SlidingWindowLimiter struct {
	config SlidingWindowConfig

	// windows stores per-key sliding window state using sync.Map for lock-free reads
	windows sync.Map // map[string]*slidingWindowEntry

	// windowSizeNano is the window size in nanoseconds
	windowSizeNano int64

	// closed indicates if the limiter has been closed
	closed atomic.Bool

	// stopCleanup signals the cleanup goroutine to stop
	stopCleanup chan struct{}

	// cleanupWg waits for cleanup goroutine to finish
	cleanupWg sync.WaitGroup
}

// NewSlidingWindowLimiter creates a new sliding window rate limiter
func NewSlidingWindowLimiter(config SlidingWindowConfig) (*SlidingWindowLimiter, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	swl := &SlidingWindowLimiter{
		config:         config,
		windowSizeNano: int64(config.WindowSize),
		stopCleanup:    make(chan struct{}),
	}

	// Start cleanup goroutine
	swl.cleanupWg.Add(1)
	go swl.cleanupLoop()

	return swl, nil
}

// Allow checks if a single request is allowed for the given key
func (swl *SlidingWindowLimiter) Allow(key string) bool {
	return swl.AllowN(key, 1)
}

// AllowN checks if n requests are allowed for the given key
func (swl *SlidingWindowLimiter) AllowN(key string, n int) bool {
	if swl.closed.Load() {
		return false
	}

	if n <= 0 {
		return true
	}

	entry := swl.getOrCreateEntry(key)
	now := time.Now().UnixNano()

	// Update last access time
	entry.lastAccess.Store(now)

	// Ensure window is current
	swl.rotateWindow(entry, now)

	// Calculate the weighted count using sliding window algorithm
	windowStart := entry.windowStart.Load()
	elapsed := now - windowStart
	if elapsed < 0 {
		elapsed = 0
	}

	// Calculate weight for previous window (how much of current window has elapsed)
	weight := float64(elapsed) / float64(swl.windowSizeNano)
	if weight > 1.0 {
		weight = 1.0
	}

	previousCount := entry.previousCount.Load()
	currentCount := entry.currentCount.Load()

	// Weighted count: previous * (1 - weight) + current
	weightedCount := float64(previousCount)*(1.0-weight) + float64(currentCount)

	// Check if adding n requests would exceed the limit
	if int64(weightedCount)+int64(n) > swl.config.MaxRequests {
		return false
	}

	// Increment counter
	entry.currentCount.Add(int64(n))

	return true
}

// Wait blocks until a request is allowed for the given key or context is canceled
func (swl *SlidingWindowLimiter) Wait(ctx context.Context, key string) error {
	return swl.WaitN(ctx, key, 1)
}

// WaitN blocks until n requests are allowed for the given key or context is canceled
func (swl *SlidingWindowLimiter) WaitN(ctx context.Context, key string, n int) error {
	if swl.closed.Load() {
		return ErrLimiterClosed{}
	}

	if n <= 0 {
		return nil
	}

	// Fast path - try to allow immediately
	if swl.AllowN(key, n) {
		return nil
	}

	entry := swl.getOrCreateEntry(key)

	for {
		select {
		case <-ctx.Done():
			return ErrContextCanceled{Key: key}
		default:
		}

		now := time.Now().UnixNano()

		// Rotate window if needed
		swl.rotateWindow(entry, now)

		windowStart := entry.windowStart.Load()
		elapsed := now - windowStart

		// Calculate time until window rotates
		timeUntilRotate := swl.windowSizeNano - elapsed
		if timeUntilRotate < 0 {
			timeUntilRotate = 0
		}

		// Calculate current weighted count
		weight := float64(elapsed) / float64(swl.windowSizeNano)
		if weight > 1.0 {
			weight = 1.0
		}

		previousCount := entry.previousCount.Load()
		currentCount := entry.currentCount.Load()
		weightedCount := float64(previousCount)*(1.0-weight) + float64(currentCount)

		// If we can allow now, do it
		if int64(weightedCount)+int64(n) <= swl.config.MaxRequests {
			if swl.AllowN(key, n) {
				return nil
			}
			continue // Race condition, retry
		}

		// Calculate approximate wait time
		// We need the weighted count to drop by: weightedCount + n - maxRequests
		excess := weightedCount + float64(n) - float64(swl.config.MaxRequests)

		// The weight increases over time, reducing previousCount's contribution
		// Wait time estimation: when does (previousCount * (1 - newWeight)) drop enough?
		var waitTime time.Duration
		if previousCount > 0 && excess > 0 {
			// Estimate: wait for window to rotate or partial decay
			neededWeightIncrease := excess / float64(previousCount)
			waitNanos := int64(neededWeightIncrease * float64(swl.windowSizeNano))
			if waitNanos < int64(time.Millisecond) {
				waitNanos = int64(time.Millisecond)
			}
			waitTime = time.Duration(waitNanos)
		} else {
			// Wait for next window rotation
			waitTime = time.Duration(timeUntilRotate)
			if waitTime < time.Millisecond {
				waitTime = time.Millisecond
			}
		}

		// Cap wait time to remaining window time
		if waitTime > time.Duration(swl.windowSizeNano) {
			waitTime = time.Duration(swl.windowSizeNano)
		}

		select {
		case <-ctx.Done():
			return ErrContextCanceled{Key: key}
		case <-time.After(waitTime):
			// Try again after waiting
		}
	}
}

// Reset clears the rate limit state for the given key
func (swl *SlidingWindowLimiter) Reset(key string) {
	swl.windows.Delete(key)
}

// ResetAll clears all rate limit state
func (swl *SlidingWindowLimiter) ResetAll() {
	swl.windows.Range(func(key, value any) bool {
		swl.windows.Delete(key)
		return true
	})
}

// Close releases resources held by the limiter
func (swl *SlidingWindowLimiter) Close() error {
	if swl.closed.Swap(true) {
		return ErrLimiterClosed{}
	}

	close(swl.stopCleanup)
	swl.cleanupWg.Wait()
	swl.ResetAll()

	return nil
}

// getOrCreateEntry gets or creates a sliding window entry for the given key
func (swl *SlidingWindowLimiter) getOrCreateEntry(key string) *slidingWindowEntry {
	if entry, ok := swl.windows.Load(key); ok {
		return entry.(*slidingWindowEntry)
	}

	now := time.Now().UnixNano()
	newEntry := &slidingWindowEntry{}
	newEntry.currentCount.Store(0)
	newEntry.previousCount.Store(0)
	newEntry.windowStart.Store(now)
	newEntry.lastAccess.Store(now)

	actual, _ := swl.windows.LoadOrStore(key, newEntry)
	return actual.(*slidingWindowEntry)
}

// rotateWindow rotates the window if necessary
func (swl *SlidingWindowLimiter) rotateWindow(entry *slidingWindowEntry, now int64) {
	windowStart := entry.windowStart.Load()
	elapsed := now - windowStart

	// Check if we need to rotate
	if elapsed < swl.windowSizeNano {
		return
	}

	// Use mutex for window rotation to prevent double rotation
	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Double-check after acquiring lock
	windowStart = entry.windowStart.Load()
	elapsed = now - windowStart

	if elapsed < swl.windowSizeNano {
		return
	}

	// Calculate how many windows have passed
	windowsPassed := elapsed / swl.windowSizeNano

	if windowsPassed == 1 {
		// Normal rotation: current becomes previous
		entry.previousCount.Store(entry.currentCount.Load())
		entry.currentCount.Store(0)
		entry.windowStart.Store(windowStart + swl.windowSizeNano)
	} else {
		// Multiple windows passed: reset everything
		entry.previousCount.Store(0)
		entry.currentCount.Store(0)
		entry.windowStart.Store(now)
	}
}

// cleanupLoop periodically removes stale entries
func (swl *SlidingWindowLimiter) cleanupLoop() {
	defer swl.cleanupWg.Done()

	ticker := time.NewTicker(swl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-swl.stopCleanup:
			return
		case <-ticker.C:
			swl.cleanup()
		}
	}
}

// cleanup removes entries that haven't been accessed recently
func (swl *SlidingWindowLimiter) cleanup() {
	now := time.Now().UnixNano()
	maxIdle := int64(swl.config.MaxIdleTime)

	swl.windows.Range(func(key, value any) bool {
		entry := value.(*slidingWindowEntry)
		lastAccess := entry.lastAccess.Load()

		if now-lastAccess > maxIdle {
			swl.windows.Delete(key)
		}
		return true
	})
}

// Stats returns statistics about the limiter
func (swl *SlidingWindowLimiter) Stats() SlidingWindowStats {
	var count int64
	swl.windows.Range(func(key, value any) bool {
		count++
		return true
	})

	return SlidingWindowStats{
		ActiveKeys:  count,
		WindowSize:  swl.config.WindowSize,
		MaxRequests: swl.config.MaxRequests,
		Closed:      swl.closed.Load(),
	}
}

// SlidingWindowStats holds statistics about the sliding window limiter
type SlidingWindowStats struct {
	ActiveKeys  int64
	WindowSize  time.Duration
	MaxRequests int64
	Closed      bool
}

// GetKeyStats returns statistics for a specific key
func (swl *SlidingWindowLimiter) GetKeyStats(key string) (KeyStats, bool) {
	entry, ok := swl.windows.Load(key)
	if !ok {
		return KeyStats{}, false
	}

	e := entry.(*slidingWindowEntry)
	now := time.Now().UnixNano()
	windowStart := e.windowStart.Load()
	elapsed := now - windowStart

	weight := float64(elapsed) / float64(swl.windowSizeNano)
	if weight > 1.0 {
		weight = 1.0
	}

	previousCount := e.previousCount.Load()
	currentCount := e.currentCount.Load()
	weightedCount := float64(previousCount)*(1.0-weight) + float64(currentCount)

	return KeyStats{
		Key:           key,
		CurrentCount:  currentCount,
		PreviousCount: previousCount,
		WeightedCount: int64(weightedCount),
		WindowStart:   time.Unix(0, windowStart),
		LastAccess:    time.Unix(0, e.lastAccess.Load()),
	}, true
}

// KeyStats holds statistics for a specific key
type KeyStats struct {
	Key           string
	CurrentCount  int64
	PreviousCount int64
	WeightedCount int64
	WindowStart   time.Time
	LastAccess    time.Time
}
