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
	"testing"
	"time"
)

func TestNewSlidingWindowLimiter(t *testing.T) {
	tests := []struct {
		name        string
		config      SlidingWindowConfig
		expectError bool
	}{
		{
			name:        "valid config",
			config:      DefaultSlidingWindowConfig(),
			expectError: false,
		},
		{
			name: "invalid window size",
			config: SlidingWindowConfig{
				WindowSize:      0,
				MaxRequests:     100,
				CleanupInterval: time.Minute,
			},
			expectError: true,
		},
		{
			name: "invalid max requests",
			config: SlidingWindowConfig{
				WindowSize:      time.Minute,
				MaxRequests:     0,
				CleanupInterval: time.Minute,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter, err := NewSlidingWindowLimiter(tt.config)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer func() { _ = limiter.Close() }()

			if limiter == nil {
				t.Error("limiter is nil")
			}
		})
	}
}

func TestSlidingWindowLimiter_Allow(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     5,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Should allow max requests
	for i := 0; i < 5; i++ {
		if !limiter.Allow(key) {
			t.Errorf("request %d should be allowed", i)
		}
	}

	// Should deny after max requests
	if limiter.Allow(key) {
		t.Error("request after max should be denied")
	}
}

func TestSlidingWindowLimiter_AllowN(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Should allow 5 requests
	if !limiter.AllowN(key, 5) {
		t.Error("5 requests should be allowed")
	}

	// Should allow 5 more requests
	if !limiter.AllowN(key, 5) {
		t.Error("5 more requests should be allowed")
	}

	// Should deny 1 more request
	if limiter.AllowN(key, 1) {
		t.Error("11th request should be denied")
	}

	// Zero n should always be allowed
	if !limiter.AllowN(key, 0) {
		t.Error("zero requests should be allowed")
	}

	// Negative n should always be allowed
	if !limiter.AllowN(key, -1) {
		t.Error("negative requests should be allowed")
	}
}

func TestSlidingWindowLimiter_AllowN_AfterClose(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}

	// Close the limiter
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close should succeed: %v", err)
	}

	// AllowN should return false after close
	if limiter.AllowN("key", 1) {
		t.Error("AllowN should return false after close")
	}
}

func TestSlidingWindowLimiter_PerKeyLimiting(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     5,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key1 := "key1"
	key2 := "key2"

	// Exhaust key1's limit
	for i := 0; i < 5; i++ {
		limiter.Allow(key1)
	}

	// key1 should be denied
	if limiter.Allow(key1) {
		t.Error("key1 should be denied")
	}

	// key2 should still be allowed
	if !limiter.Allow(key2) {
		t.Error("key2 should be allowed")
	}
}

func TestSlidingWindowLimiter_WindowRotation(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      50 * time.Millisecond,
		MaxRequests:     5,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	clk := newFakeClock()
	limiter, err := newSlidingWindowLimiterWithSeams(config, nil, clk)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Exhaust limit
	for i := 0; i < 5; i++ {
		limiter.Allow(key)
	}

	// Should be denied
	if limiter.Allow(key) {
		t.Error("should be denied after exhausting limit")
	}

	// Just short of the window nothing has rotated yet: the five requests are
	// still the CURRENT count, and the previous window is still empty. Without
	// this probe the test cannot see a limiter that rotates early, because an
	// early rotation lands the same five requests in the previous window and
	// Allow refuses either way.
	clk.Advance(config.WindowSize - config.WindowSize/20)

	if limiter.Allow(key) {
		t.Error("should be denied before the window has elapsed")
	}

	stats, found := limiter.GetKeyStats(key)
	if !found {
		t.Fatal("key should be found")
	}
	if stats.PreviousCount != 0 || stats.CurrentCount != 5 {
		t.Errorf("before the boundary: CurrentCount=%d PreviousCount=%d, expected 5 and 0 — the window rotated early",
			stats.CurrentCount, stats.PreviousCount)
	}

	// Rotation alone does not admit anything. At exactly one window the counts
	// shift — the five requests become the previous window — but no time has
	// elapsed INTO the new window, so their weight is still a full 1.0 and the
	// effective count is still five.
	clk.Advance(config.WindowSize / 20)

	if limiter.Allow(key) {
		t.Error("should still be denied at exactly one window: rotation has happened but nothing has decayed yet")
	}

	// One nanosecond into the new window the previous count is weighted by
	// slightly less than 1.0, which drops the effective count below five and
	// admits a request. This is the boundary the old 60ms sleep stepped over
	// without measuring: it proved the limiter recovers at SOME point within
	// 60ms, not that it recovers exactly when the window advances.
	clk.Advance(time.Nanosecond)

	if !limiter.Allow(key) {
		t.Error("should be allowed one nanosecond past the rotation boundary")
	}
}

func TestSlidingWindowLimiter_MultipleWindowsPassed(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      20 * time.Millisecond,
		MaxRequests:     5,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	clk := newFakeClock()
	limiter, err := newSlidingWindowLimiterWithSeams(config, nil, clk)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Exhaust limit
	for i := 0; i < 5; i++ {
		limiter.Allow(key)
	}

	// Verify stats before advancing
	stats, found := limiter.GetKeyStats(key)
	if !found {
		t.Fatal("key should be found")
	}
	if stats.CurrentCount != 5 {
		t.Errorf("CurrentCount = %d, expected 5", stats.CurrentCount)
	}

	// Exactly two windows is the boundary between the two rotation branches:
	// one window shifts current into previous, two or more discards both. The
	// old 50ms sleep against a 20ms window landed at 2.5 windows, comfortably
	// inside the reset branch but unable to say where it began.
	clk.Advance(2 * config.WindowSize)

	// Should be allowed again (multiple windows passed resets everything)
	if !limiter.Allow(key) {
		t.Error("should be allowed after multiple windows passed")
	}

	// Verify counts are reset
	stats, found = limiter.GetKeyStats(key)
	if !found {
		t.Fatal("key should be found after access")
	}
	// Previous count should be 0 when multiple windows pass
	if stats.PreviousCount != 0 {
		t.Errorf("PreviousCount = %d, expected 0 after multiple windows passed", stats.PreviousCount)
	}
}

func TestSlidingWindowLimiter_Wait(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      50 * time.Millisecond,
		MaxRequests:     1,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Use the request
	if !limiter.Allow(key) {
		t.Error("first request should be allowed")
	}

	// Wait is blocked only on window decay, so the deadline is a liveness backstop
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()

	err = limiter.Wait(ctx, key)
	if err != nil {
		t.Errorf("Wait should succeed: %v", err)
	}
}

func TestSlidingWindowLimiter_Wait_ContextCanceled(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      time.Minute, // Long window
		MaxRequests:     1,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Use the request
	limiter.Allow(key)

	// Wait with short timeout should fail
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err = limiter.Wait(ctx, key)
	if err == nil {
		t.Error("Wait should fail with context timeout")
	}

	_, ok := err.(ErrContextCanceled)
	if !ok {
		t.Errorf("expected ErrContextCanceled, got %T", err)
	}
}

func TestSlidingWindowLimiter_WaitN_ZeroRequests(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	ctx := context.Background()

	// WaitN with n=0 should return nil immediately
	err = limiter.WaitN(ctx, "key", 0)
	if err != nil {
		t.Errorf("WaitN(0) should return nil, got %v", err)
	}

	// WaitN with n<0 should return nil immediately
	err = limiter.WaitN(ctx, "key", -1)
	if err != nil {
		t.Errorf("WaitN(-1) should return nil, got %v", err)
	}
}

func TestSlidingWindowLimiter_WaitN_AfterClose(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}

	// Close the limiter
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close should succeed: %v", err)
	}

	ctx := context.Background()

	// WaitN should return ErrLimiterClosed after close
	err = limiter.WaitN(ctx, "key", 1)
	if err == nil {
		t.Error("WaitN should return error after close")
	}

	_, ok := err.(ErrLimiterClosed)
	if !ok {
		t.Errorf("expected ErrLimiterClosed, got %T: %v", err, err)
	}
}

func TestSlidingWindowLimiter_Wait_AfterClose(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}

	// Close the limiter
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close should succeed: %v", err)
	}

	ctx := context.Background()

	// Wait should return ErrLimiterClosed after close
	err = limiter.Wait(ctx, "key")
	if err == nil {
		t.Error("Wait should return error after close")
	}

	_, ok := err.(ErrLimiterClosed)
	if !ok {
		t.Errorf("expected ErrLimiterClosed, got %T: %v", err, err)
	}
}

func TestSlidingWindowLimiter_Reset(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     5,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Exhaust requests
	for i := 0; i < 5; i++ {
		limiter.Allow(key)
	}

	// Should be denied
	if limiter.Allow(key) {
		t.Error("should be denied after exhausting requests")
	}

	// Reset
	limiter.Reset(key)

	// Should be allowed again
	if !limiter.Allow(key) {
		t.Error("should be allowed after reset")
	}
}

func TestSlidingWindowLimiter_ResetAll(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     1,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	// Exhaust requests for multiple keys
	limiter.Allow("key1")
	limiter.Allow("key2")
	limiter.Allow("key3")

	// All should be denied
	if limiter.Allow("key1") || limiter.Allow("key2") || limiter.Allow("key3") {
		t.Error("all keys should be denied")
	}

	// Reset all
	limiter.ResetAll()

	// All should be allowed
	if !limiter.Allow("key1") || !limiter.Allow("key2") || !limiter.Allow("key3") {
		t.Error("all keys should be allowed after reset")
	}
}

func TestSlidingWindowLimiter_Close(t *testing.T) {
	config := DefaultSlidingWindowConfig()

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}

	// Close should succeed
	err = limiter.Close()
	if err != nil {
		t.Errorf("Close should succeed: %v", err)
	}

	// Second close should return error
	err = limiter.Close()
	if err == nil {
		t.Error("second Close should return error")
	}

	_, ok := err.(ErrLimiterClosed)
	if !ok {
		t.Errorf("expected ErrLimiterClosed, got %T", err)
	}

	// Allow should fail after close
	if limiter.Allow("key") {
		t.Error("Allow should fail after close")
	}
}

func TestSlidingWindowLimiter_Stats(t *testing.T) {
	config := DefaultSlidingWindowConfig()

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	// Initial stats
	stats := limiter.Stats()
	if stats.ActiveKeys != 0 {
		t.Errorf("ActiveKeys = %d, expected 0", stats.ActiveKeys)
	}
	if stats.WindowSize != config.WindowSize {
		t.Errorf("WindowSize = %v, expected %v", stats.WindowSize, config.WindowSize)
	}
	if stats.MaxRequests != config.MaxRequests {
		t.Errorf("MaxRequests = %d, expected %d", stats.MaxRequests, config.MaxRequests)
	}
	if stats.Closed {
		t.Error("Closed should be false")
	}

	// Add some keys
	limiter.Allow("key1")
	limiter.Allow("key2")

	stats = limiter.Stats()
	if stats.ActiveKeys != 2 {
		t.Errorf("ActiveKeys = %d, expected 2", stats.ActiveKeys)
	}
}

func TestSlidingWindowLimiter_Stats_AfterClose(t *testing.T) {
	config := DefaultSlidingWindowConfig()

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}

	// Add some keys before close
	limiter.Allow("key1")
	limiter.Allow("key2")

	// Close the limiter
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close should succeed: %v", err)
	}

	// Stats should show closed state
	stats := limiter.Stats()
	if !stats.Closed {
		t.Error("Stats.Closed should be true after close")
	}

	// ActiveKeys should be 0 after close (ResetAll is called in Close)
	if stats.ActiveKeys != 0 {
		t.Errorf("ActiveKeys = %d, expected 0 after close", stats.ActiveKeys)
	}
}

func TestSlidingWindowLimiter_GetKeyStats(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Non-existent key
	_, found := limiter.GetKeyStats("non-existent")
	if found {
		t.Error("non-existent key should not be found")
	}

	// Add some requests
	for i := 0; i < 5; i++ {
		limiter.Allow(key)
	}

	stats, found := limiter.GetKeyStats(key)
	if !found {
		t.Error("key should be found")
	}
	if stats.CurrentCount != 5 {
		t.Errorf("CurrentCount = %d, expected 5", stats.CurrentCount)
	}
	if stats.Key != key {
		t.Errorf("Key = %s, expected %s", stats.Key, key)
	}
}

func TestSlidingWindowLimiter_GetKeyStats_WeightCapping(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      10 * time.Millisecond,
		MaxRequests:     10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	clk := newFakeClock()
	limiter, err := newSlidingWindowLimiterWithSeams(config, nil, clk)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// The cap is only observable once the PREVIOUS window is non-empty. With a
	// previous count of zero the weight multiplies nothing, so an uncapped
	// weight of 2.0 and a capped weight of 1.0 give the same answer — which is
	// why the old version of this test could not have failed. Build a non-empty
	// previous window first: four requests, then one window, then a request
	// that rotates them into place.
	for i := 0; i < 4; i++ {
		limiter.Allow(key)
	}
	clk.Advance(config.WindowSize)
	limiter.Allow(key)

	// Now go well past the window, so the raw weight would be 2.0.
	clk.Advance(2 * config.WindowSize)

	stats, found := limiter.GetKeyStats(key)
	if !found {
		t.Fatal("key should be found")
	}

	// previous=4, current=1. Capped at 1.0 the previous window contributes
	// nothing and the answer is the current count: 4*(1-1.0) + 1 = 1.
	// Uncapped it would be 4*(1-2.0) + 1 = -3, a negative rate-limit count.
	if stats.WeightedCount != 1 {
		t.Errorf("WeightedCount = %d, expected 1 (weight capped at 1.0; uncapped this would be -3)", stats.WeightedCount)
	}
	if stats.PreviousCount != 4 {
		t.Fatalf("PreviousCount = %d, expected 4 — the fixture did not build the previous window it needs", stats.PreviousCount)
	}
}

func TestSlidingWindowLimiter_Concurrent(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     1000,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	var wg sync.WaitGroup
	goroutines := 10
	requestsPerGoroutine := 100

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := "shared-key"
			for j := 0; j < requestsPerGoroutine; j++ {
				limiter.Allow(key)
			}
		}(i)
	}

	wg.Wait()

	// Should complete without race conditions
	stats := limiter.Stats()
	if stats.ActiveKeys != 1 {
		t.Errorf("ActiveKeys = %d, expected 1", stats.ActiveKeys)
	}
}

func TestSlidingWindowLimiter_SlidingBehavior(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	clk := newFakeClock()
	limiter, err := newSlidingWindowLimiterWithSeams(config, nil, clk)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Use 8 requests
	for i := 0; i < 8; i++ {
		if !limiter.Allow(key) {
			t.Errorf("request %d should be allowed", i)
		}
	}

	// Advance half a window. Note what does NOT happen here: this is still the
	// first window, so the previous count is zero and nothing decays. The
	// comment this test used to carry — "previous count should be weighted at
	// ~50%, so effective count is ~4" — described a decay that cannot occur
	// yet, and the assertion under it ("allowed != 0") passed for an unrelated
	// reason: the eight requests simply left two of the ten free.
	clk.Advance(config.WindowSize / 2)

	allowed := 0
	for i := 0; i < 10; i++ {
		if limiter.Allow(key) {
			allowed++
		}
	}

	// Exactly the two the first window has left. A deterministic clock can say
	// "two", where a real sleep could only say "more than none".
	if allowed != 2 {
		t.Errorf("allowed = %d, expected exactly 2 — the remainder of the first window's budget, with no decay yet", allowed)
	}
}

func TestSlidingWindowLimiter_Cleanup(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     10,
		CleanupInterval: 10 * time.Millisecond,
		// Every sweep after the accesses below sees both keys as idle, so the
		// eviction depends on a sweep running, never on how soon it runs.
		MaxIdleTime: time.Millisecond,
	}

	observer := newSweepObserver()
	limiter, err := newSlidingWindowLimiterWithSweepObserver(config, observer.notify)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	// Add some keys
	limiter.Allow("key1")
	limiter.Allow("key2")

	stats := limiter.Stats()
	if stats.ActiveKeys != 2 {
		t.Errorf("ActiveKeys = %d, expected 2", stats.ActiveKeys)
	}

	// Idle entries are evicted by the background sweep, which the observer makes
	// visible; nothing here depends on a wall-clock budget.
	observer.awaitSweepUntil(t, "evict the idle keys", func() bool {
		return limiter.Stats().ActiveKeys == 0
	})
}

func TestSlidingWindowLimiter_Cleanup_KeepsActiveEntries(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     10,
		CleanupInterval: 10 * time.Millisecond,
		// The idle window outlasts any scheduling delay, so the entry is still
		// active whenever the sweep examines it, however late that is.
		MaxIdleTime: time.Hour,
	}

	observer := newSweepObserver()
	limiter, err := newSlidingWindowLimiterWithSweepObserver(config, observer.notify)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	// Add a key
	limiter.Allow("active-key")

	// Wait for a sweep that provably examined the entry
	observer.awaitSweepAfterNow(t)

	// Entry should still exist because it's actively used
	stats := limiter.Stats()
	if stats.ActiveKeys != 1 {
		t.Errorf("ActiveKeys = %d, expected 1 (active entry should not be cleaned up)", stats.ActiveKeys)
	}
}

// TestSlidingWindowLimiter_Cleanup_AccessRefreshesIdleness drives cleanup directly so
// the idle predicate itself is tested without any background goroutine: an entry left
// untouched past MaxIdleTime is evicted, and the same entry rescued by an access is not.
func TestSlidingWindowLimiter_Cleanup_AccessRefreshesIdleness(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     10,
		CleanupInterval: time.Hour, // the background loop must not interfere
		MaxIdleTime:     20 * time.Millisecond,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	const key = "test-key"

	limiter.Allow(key)
	idleSlidingWindowEntry(t, limiter, key, config.MaxIdleTime)

	// An access resets lastAccess, so the entry survives the sweep
	limiter.Allow(key)
	limiter.cleanup()

	if stats := limiter.Stats(); stats.ActiveKeys != 1 {
		t.Fatalf("ActiveKeys = %d, expected 1 (access should refresh the entry)", stats.ActiveKeys)
	}

	// Left idle again, the same entry is evicted
	idleSlidingWindowEntry(t, limiter, key, config.MaxIdleTime)
	limiter.cleanup()

	if stats := limiter.Stats(); stats.ActiveKeys != 0 {
		t.Errorf("ActiveKeys = %d, expected 0 (idle entry should be evicted)", stats.ActiveKeys)
	}
}

// idleSlidingWindowEntry backdates a key's last access past idle so a sweep sees it as
// stale, without waiting for wall-clock time to pass.
func idleSlidingWindowEntry(t *testing.T, limiter *SlidingWindowLimiter, key string, idle time.Duration) {
	t.Helper()

	value, ok := limiter.windows.Load(key)
	if !ok {
		t.Fatalf("key %q should be present", key)
	}
	entry := value.(*slidingWindowEntry)
	entry.lastAccess.Store(time.Now().Add(-2 * idle).UnixNano())
}

func TestSlidingWindowLimiter_WaitN_RaceRetry(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      50 * time.Millisecond,
		MaxRequests:     2,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Exhaust most requests
	limiter.Allow(key)

	// Run concurrent waits to trigger race condition retries
	var wg sync.WaitGroup
	errors := make(chan error, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if err := limiter.WaitN(ctx, key, 1); err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Some waits may have timed out, but no panics or deadlocks should occur
	// This test mainly ensures concurrent WaitN doesn't cause issues
}

func TestSlidingWindowLimiter_GetOrCreateEntry_Concurrent(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     1000,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	var wg sync.WaitGroup
	goroutines := 100

	// Create the same key from multiple goroutines concurrently
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limiter.Allow("same-key")
		}()
	}

	wg.Wait()

	// Should only have one entry
	stats := limiter.Stats()
	if stats.ActiveKeys != 1 {
		t.Errorf("ActiveKeys = %d, expected 1", stats.ActiveKeys)
	}
}

func TestSlidingWindowLimiter_WaitN_WaitTimeCalculation(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      50 * time.Millisecond,
		MaxRequests:     2,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	clk := newFakeClock()
	limiter, err := newSlidingWindowLimiterWithSeams(config, nil, clk)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Exhaust all requests, then rotate them into the previous window.
	limiter.AllowN(key, 2)
	clk.Advance(config.WindowSize)

	// Rotation only; at zero elapsed into the new window the two previous
	// requests still weigh 2.0, so this is refused and the window stays empty.
	if limiter.AllowN(key, 2) {
		t.Fatal("AllowN should be refused at exactly the rotation boundary; the fixture depends on it")
	}

	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()

	before := clk.NowNano()
	err = limiter.WaitN(ctx, key, 1)
	waited := time.Duration(clk.NowNano() - before)

	if err != nil {
		t.Errorf("Wait should succeed: %v", err)
	}

	// This is the calculation the test is named for, and it is now asserted
	// rather than logged. WaitN needs the effective count to fall from 2 to 1
	// so that one more request fits under the limit of 2. The previous window
	// holds 2, so it needs the weight to rise by (2 + 1 - 2) / 2 = 0.5, which
	// is half a window. The old version measured this with time.Since and then
	// only t.Logf'd the result, so no value of the wait could fail it.
	if want := config.WindowSize / 2; waited != want {
		t.Errorf("WaitN advanced the clock by %v, expected exactly %v", waited, want)
	}
}

func TestSlidingWindowLimiter_WaitN_ZeroPreviousCount(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      100 * time.Millisecond,
		MaxRequests:     1,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Exhaust current window (previousCount is 0)
	limiter.Allow(key)

	// Should be denied
	if limiter.Allow(key) {
		t.Error("should be denied after exhausting current window")
	}

	// Wait for request - this tests the branch where previousCount is 0
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()

	err = limiter.Wait(ctx, key)
	if err != nil {
		t.Errorf("Wait should succeed: %v", err)
	}
}
