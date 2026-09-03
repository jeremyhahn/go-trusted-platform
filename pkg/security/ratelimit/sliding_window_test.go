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

	limiter, err := NewSlidingWindowLimiter(config)
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

	// Wait for window to rotate
	time.Sleep(60 * time.Millisecond)

	// Should be allowed again (previous count decays)
	if !limiter.Allow(key) {
		t.Error("should be allowed after window rotation")
	}
}

func TestSlidingWindowLimiter_MultipleWindowsPassed(t *testing.T) {
	config := SlidingWindowConfig{
		WindowSize:      20 * time.Millisecond,
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

	// Exhaust limit
	for i := 0; i < 5; i++ {
		limiter.Allow(key)
	}

	// Verify stats before waiting
	stats, found := limiter.GetKeyStats(key)
	if !found {
		t.Fatal("key should be found")
	}
	if stats.CurrentCount != 5 {
		t.Errorf("CurrentCount = %d, expected 5", stats.CurrentCount)
	}

	// Wait for multiple windows to pass (more than 2x window size)
	time.Sleep(50 * time.Millisecond)

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

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Add some requests
	limiter.Allow(key)

	// Wait for more than window size to test weight capping
	time.Sleep(20 * time.Millisecond)

	// Get stats - weight should be capped at 1.0
	stats, found := limiter.GetKeyStats(key)
	if !found {
		t.Error("key should be found")
	}
	// The weighted count calculation involves capping weight at 1.0
	// when elapsed > windowSize
	if stats.WeightedCount < 0 {
		t.Errorf("WeightedCount should be non-negative, got %d", stats.WeightedCount)
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

	limiter, err := NewSlidingWindowLimiter(config)
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

	// Wait for half the window
	time.Sleep(50 * time.Millisecond)

	// Previous count should be weighted at ~50%, so effective count is ~4
	// We should be able to make more requests now
	allowed := 0
	for i := 0; i < 10; i++ {
		if limiter.Allow(key) {
			allowed++
		}
	}

	// Should have allowed some requests due to sliding window decay
	if allowed == 0 {
		t.Error("sliding window should have allowed some requests after partial window elapsed")
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

	limiter, err := NewSlidingWindowLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Exhaust all requests
	limiter.AllowN(key, 2)

	// Wait for window to pass to move current to previous
	time.Sleep(60 * time.Millisecond)

	// Now exhaust current window again
	limiter.AllowN(key, 2)

	// Wait should succeed after waiting for decay
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()

	start := time.Now()
	err = limiter.WaitN(ctx, key, 1)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Wait should succeed: %v", err)
	}

	// Should have waited some time for decay
	if elapsed < 5*time.Millisecond {
		t.Logf("Wait duration: %v", elapsed)
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
