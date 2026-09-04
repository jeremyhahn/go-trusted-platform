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

// tokenBucketEntry represents a per-key token bucket state
type tokenBucketEntry struct {
	tokens     atomic.Int64 // tokens available (scaled by tokenScale for precision)
	lastUpdate atomic.Int64 // Unix nano timestamp of last token update
	lastAccess atomic.Int64 // Unix nano timestamp of last access (for cleanup)
}

// TokenBucketLimiter implements a token bucket rate limiter with per-key limiting
type TokenBucketLimiter struct {
	config LimitConfig

	// buckets stores per-key token bucket state using sync.Map for lock-free reads
	buckets sync.Map // map[string]*tokenBucketEntry

	// tokenScale is used to provide sub-token precision
	tokenScale int64

	// tokensPerNano is the rate of token replenishment per nanosecond (scaled)
	tokensPerNano int64

	// maxTokens is the maximum number of tokens (burst size, scaled)
	maxTokens int64

	// closed indicates if the limiter has been closed
	closed atomic.Bool

	// stopCleanup signals the cleanup goroutine to stop
	stopCleanup chan struct{}

	// cleanupWg waits for cleanup goroutine to finish
	cleanupWg sync.WaitGroup

	// onSweep, when non-nil, is invoked by the cleanup goroutine after every
	// completed sweep. It turns the sweep — otherwise an invisible background
	// event — into a synchronisation point the package's own tests can wait on
	// instead of racing it with wall-clock sleeps. It is fixed at construction
	// and never mutated afterwards, so the cleanup loop reads it without
	// synchronisation, and it is nil on every production construction path.
	onSweep func()

	// clk is the limiter's view of time. Token replenishment is computed purely
	// from the interval since a bucket was last drawn from, so advancing this
	// clock is the whole of "let the bucket refill". Like onSweep it is fixed at
	// construction and never mutated, so concurrent readers need no
	// synchronisation; production always gets realClock.
	clk clock
}

const tokenScale = 1000000000 // Scale factor for token precision (uses nanosecond precision)

// NewTokenBucketLimiter creates a new token bucket rate limiter
func NewTokenBucketLimiter(config LimitConfig) (*TokenBucketLimiter, error) {
	return newTokenBucketLimiterWithSweepObserver(config, nil)
}

// newTokenBucketLimiterWithSweepObserver creates a token bucket rate limiter whose
// cleanup goroutine calls onSweep after each completed sweep. onSweep runs on the
// cleanup goroutine, so it must not block; a nil observer disables the notification
// entirely and yields exactly the limiter NewTokenBucketLimiter returns.
func newTokenBucketLimiterWithSweepObserver(config LimitConfig, onSweep func()) (*TokenBucketLimiter, error) {
	return newTokenBucketLimiterWithSeams(config, onSweep, realClock{})
}

// newTokenBucketLimiterWithSeams is the single construction path, taking both test
// seams explicitly. See newSlidingWindowLimiterWithSeams; the two limiters follow
// the same shape deliberately, so neither is a special case to remember. clk must
// be non-nil.
func newTokenBucketLimiterWithSeams(config LimitConfig, onSweep func(), clk clock) (*TokenBucketLimiter, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	tokensPerNano := int64(config.Rate * float64(tokenScale) / float64(time.Second))
	if tokensPerNano == 0 {
		tokensPerNano = 1 // Minimum of 1 to avoid divide by zero
	}

	tbl := &TokenBucketLimiter{
		config:        config,
		tokenScale:    tokenScale,
		tokensPerNano: tokensPerNano,
		maxTokens:     int64(config.Burst) * tokenScale,
		stopCleanup:   make(chan struct{}),
		onSweep:       onSweep,
		clk:           clk,
	}

	// Start cleanup goroutine
	tbl.cleanupWg.Add(1)
	go tbl.cleanupLoop()

	return tbl, nil
}

// Allow checks if a single request is allowed for the given key
func (tbl *TokenBucketLimiter) Allow(key string) bool {
	return tbl.AllowN(key, 1)
}

// AllowN checks if n requests are allowed for the given key
func (tbl *TokenBucketLimiter) AllowN(key string, n int) bool {
	if tbl.closed.Load() {
		return false
	}

	if n <= 0 {
		return true
	}

	tokensNeeded := int64(n) * tokenScale
	entry := tbl.getOrCreateEntry(key)
	now := tbl.clk.NowNano()

	// Update last access time
	entry.lastAccess.Store(now)

	// Try to consume tokens using CAS loop
	for {
		lastUpdate := entry.lastUpdate.Load()
		oldTokens := entry.tokens.Load()

		// Calculate tokens to add based on elapsed time
		elapsed := now - lastUpdate
		if elapsed < 0 {
			elapsed = 0
		}
		tokensToAdd := elapsed * tbl.tokensPerNano / int64(time.Nanosecond)
		newTokens := oldTokens + tokensToAdd
		if newTokens > tbl.maxTokens {
			newTokens = tbl.maxTokens
		}

		// Check if we have enough tokens
		if newTokens < tokensNeeded {
			return false
		}

		// Try to atomically update
		newTokenCount := newTokens - tokensNeeded
		if entry.tokens.CompareAndSwap(oldTokens, newTokenCount) {
			entry.lastUpdate.CompareAndSwap(lastUpdate, now)
			return true
		}
		// CAS failed, retry
	}
}

// Wait blocks until a request is allowed for the given key or context is canceled
func (tbl *TokenBucketLimiter) Wait(ctx context.Context, key string) error {
	return tbl.WaitN(ctx, key, 1)
}

// WaitN blocks until n requests are allowed for the given key or context is canceled
func (tbl *TokenBucketLimiter) WaitN(ctx context.Context, key string, n int) error {
	if tbl.closed.Load() {
		return ErrLimiterClosed{}
	}

	if n <= 0 {
		return nil
	}

	// Fast path - try to allow immediately
	if tbl.AllowN(key, n) {
		return nil
	}

	// Calculate how long we need to wait
	tokensNeeded := int64(n) * tokenScale
	entry := tbl.getOrCreateEntry(key)

	for {
		select {
		case <-ctx.Done():
			return ErrContextCanceled{Key: key}
		default:
		}

		now := tbl.clk.NowNano()
		lastUpdate := entry.lastUpdate.Load()
		currentTokens := entry.tokens.Load()

		// Calculate current token count
		elapsed := now - lastUpdate
		if elapsed < 0 {
			elapsed = 0
		}
		tokensToAdd := elapsed * tbl.tokensPerNano / int64(time.Nanosecond)
		availableTokens := currentTokens + tokensToAdd
		if availableTokens > tbl.maxTokens {
			availableTokens = tbl.maxTokens
		}

		// Check if we have enough tokens now
		if availableTokens >= tokensNeeded {
			if tbl.AllowN(key, n) {
				return nil
			}
			continue // Race condition, retry
		}

		// Calculate wait time
		tokensDeficit := tokensNeeded - availableTokens
		waitNanos := tokensDeficit * int64(time.Nanosecond) / tbl.tokensPerNano
		if waitNanos < int64(time.Millisecond) {
			waitNanos = int64(time.Millisecond) // Minimum wait of 1ms
		}

		select {
		case <-ctx.Done():
			return ErrContextCanceled{Key: key}
		case <-tbl.clk.After(time.Duration(waitNanos)):
			// Try again after waiting
		}
	}
}

// Reset clears the rate limit state for the given key
func (tbl *TokenBucketLimiter) Reset(key string) {
	tbl.buckets.Delete(key)
}

// ResetAll clears all rate limit state
func (tbl *TokenBucketLimiter) ResetAll() {
	tbl.buckets.Range(func(key, value any) bool {
		tbl.buckets.Delete(key)
		return true
	})
}

// Close releases resources held by the limiter
func (tbl *TokenBucketLimiter) Close() error {
	if tbl.closed.Swap(true) {
		return ErrLimiterClosed{}
	}

	close(tbl.stopCleanup)
	tbl.cleanupWg.Wait()
	tbl.ResetAll()

	return nil
}

// getOrCreateEntry gets or creates a token bucket entry for the given key
func (tbl *TokenBucketLimiter) getOrCreateEntry(key string) *tokenBucketEntry {
	if entry, ok := tbl.buckets.Load(key); ok {
		return entry.(*tokenBucketEntry)
	}

	now := tbl.clk.NowNano()
	newEntry := &tokenBucketEntry{}
	newEntry.tokens.Store(tbl.maxTokens) // Start with full bucket
	newEntry.lastUpdate.Store(now)
	newEntry.lastAccess.Store(now)

	actual, _ := tbl.buckets.LoadOrStore(key, newEntry)
	return actual.(*tokenBucketEntry)
}

// cleanupLoop periodically removes stale entries
func (tbl *TokenBucketLimiter) cleanupLoop() {
	defer tbl.cleanupWg.Done()

	ticker := time.NewTicker(tbl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tbl.stopCleanup:
			return
		case <-ticker.C:
			tbl.cleanup()
			if tbl.onSweep != nil {
				tbl.onSweep()
			}
		}
	}
}

// cleanup removes entries that haven't been accessed recently
func (tbl *TokenBucketLimiter) cleanup() {
	now := tbl.clk.NowNano()
	maxIdle := int64(tbl.config.MaxIdleTime)

	tbl.buckets.Range(func(key, value any) bool {
		entry := value.(*tokenBucketEntry)
		lastAccess := entry.lastAccess.Load()

		if now-lastAccess > maxIdle {
			tbl.buckets.Delete(key)
		}
		return true
	})
}

// Stats returns statistics about the limiter
func (tbl *TokenBucketLimiter) Stats() TokenBucketStats {
	var count int64
	tbl.buckets.Range(func(key, value any) bool {
		count++
		return true
	})

	return TokenBucketStats{
		ActiveKeys: count,
		Rate:       tbl.config.Rate,
		Burst:      tbl.config.Burst,
		Closed:     tbl.closed.Load(),
	}
}

// TokenBucketStats holds statistics about the token bucket limiter
type TokenBucketStats struct {
	ActiveKeys int64
	Rate       float64
	Burst      int
	Closed     bool
}
