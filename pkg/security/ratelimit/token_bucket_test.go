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

func TestNewTokenBucketLimiter(t *testing.T) {
	tests := []struct {
		name        string
		config      LimitConfig
		expectError bool
	}{
		{
			name:        "valid config",
			config:      DefaultLimitConfig(),
			expectError: false,
		},
		{
			name: "invalid rate",
			config: LimitConfig{
				Rate:            0,
				Burst:           10,
				CleanupInterval: time.Minute,
			},
			expectError: true,
		},
		{
			name: "invalid burst",
			config: LimitConfig{
				Rate:            10.0,
				Burst:           0,
				CleanupInterval: time.Minute,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter, err := NewTokenBucketLimiter(tt.config)
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

func TestNewTokenBucketLimiter_VeryLowRate(t *testing.T) {
	// Test the edge case where rate is so low that tokensPerNano would be 0
	// The implementation should set it to minimum of 1
	config := LimitConfig{
		Rate:            0.000000001, // Extremely low rate
		Burst:           1,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	// Should still work with minimum tokensPerNano
	if limiter.tokensPerNano < 1 {
		t.Error("tokensPerNano should be at least 1")
	}
}

func TestTokenBucketLimiter_Allow(t *testing.T) {
	config := LimitConfig{
		Rate:            10.0,
		Burst:           5,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Should allow burst requests
	for i := 0; i < 5; i++ {
		if !limiter.Allow(key) {
			t.Errorf("request %d should be allowed", i)
		}
	}

	// Should deny after burst is exhausted
	if limiter.Allow(key) {
		t.Error("request after burst should be denied")
	}
}

func TestTokenBucketLimiter_AllowN(t *testing.T) {
	config := LimitConfig{
		Rate:            10.0,
		Burst:           10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
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

func TestTokenBucketLimiter_AllowN_AfterClose(t *testing.T) {
	config := LimitConfig{
		Rate:            10.0,
		Burst:           10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
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

func TestTokenBucketLimiter_PerKeyLimiting(t *testing.T) {
	config := LimitConfig{
		Rate:            10.0,
		Burst:           5,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key1 := "key1"
	key2 := "key2"

	// Exhaust key1's burst
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

func TestTokenBucketLimiter_Wait(t *testing.T) {
	config := LimitConfig{
		Rate:            100.0, // 100 per second = 10ms per token
		Burst:           1,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Use the token
	if !limiter.Allow(key) {
		t.Error("first request should be allowed")
	}

	// Wait should succeed with sufficient timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = limiter.Wait(ctx, key)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Wait should succeed: %v", err)
	}

	// Should have waited approximately 10ms
	if elapsed < 5*time.Millisecond {
		t.Logf("Wait duration: %v (expected ~10ms)", elapsed)
	}
}

func TestTokenBucketLimiter_Wait_ContextCanceled(t *testing.T) {
	config := LimitConfig{
		Rate:            1.0, // 1 token per second
		Burst:           1,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Use the token
	if !limiter.Allow(key) {
		t.Fatal("first Allow should succeed")
	}

	// Verify the token is exhausted
	if limiter.Allow(key) {
		t.Fatal("second Allow should fail (token exhausted)")
	}

	// Wait with very short timeout should fail (need to wait ~1 second for token)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	err = limiter.Wait(ctx, key)
	if err == nil {
		t.Error("Wait should fail with context timeout")
	}

	_, ok := err.(ErrContextCanceled)
	if !ok {
		t.Errorf("expected ErrContextCanceled, got %T: %v", err, err)
	}
}

func TestTokenBucketLimiter_WaitN_ZeroRequests(t *testing.T) {
	config := LimitConfig{
		Rate:            10.0,
		Burst:           10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
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

func TestTokenBucketLimiter_WaitN_AfterClose(t *testing.T) {
	config := LimitConfig{
		Rate:            10.0,
		Burst:           10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
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

func TestTokenBucketLimiter_Wait_AfterClose(t *testing.T) {
	config := LimitConfig{
		Rate:            10.0,
		Burst:           10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
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

func TestTokenBucketLimiter_Reset(t *testing.T) {
	config := LimitConfig{
		Rate:            10.0,
		Burst:           5,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Exhaust tokens
	for i := 0; i < 5; i++ {
		limiter.Allow(key)
	}

	// Should be denied
	if limiter.Allow(key) {
		t.Error("should be denied after exhausting tokens")
	}

	// Reset
	limiter.Reset(key)

	// Should be allowed again
	if !limiter.Allow(key) {
		t.Error("should be allowed after reset")
	}
}

func TestTokenBucketLimiter_ResetAll(t *testing.T) {
	config := LimitConfig{
		Rate:            10.0,
		Burst:           1,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	// Exhaust tokens for multiple keys
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

func TestTokenBucketLimiter_Close(t *testing.T) {
	config := DefaultLimitConfig()

	limiter, err := NewTokenBucketLimiter(config)
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

func TestTokenBucketLimiter_Stats(t *testing.T) {
	config := DefaultLimitConfig()

	limiter, err := NewTokenBucketLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	// Initial stats
	stats := limiter.Stats()
	if stats.ActiveKeys != 0 {
		t.Errorf("ActiveKeys = %d, expected 0", stats.ActiveKeys)
	}
	if stats.Rate != config.Rate {
		t.Errorf("Rate = %f, expected %f", stats.Rate, config.Rate)
	}
	if stats.Burst != config.Burst {
		t.Errorf("Burst = %d, expected %d", stats.Burst, config.Burst)
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

func TestTokenBucketLimiter_Stats_AfterClose(t *testing.T) {
	config := DefaultLimitConfig()

	limiter, err := NewTokenBucketLimiter(config)
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

func TestTokenBucketLimiter_Concurrent(t *testing.T) {
	config := LimitConfig{
		Rate:            1000.0,
		Burst:           100,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
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

func TestTokenBucketLimiter_TokenReplenishment(t *testing.T) {
	config := LimitConfig{
		Rate:            100.0, // 100 per second
		Burst:           1,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Use the token
	if !limiter.Allow(key) {
		t.Error("first request should be allowed")
	}

	// Should be denied immediately
	if limiter.Allow(key) {
		t.Error("second request should be denied")
	}

	// Wait for token to replenish
	time.Sleep(15 * time.Millisecond)

	// Should be allowed again
	if !limiter.Allow(key) {
		t.Error("request after replenishment should be allowed")
	}
}

func TestTokenBucketLimiter_Cleanup(t *testing.T) {
	config := LimitConfig{
		Rate:            10.0,
		Burst:           10,
		CleanupInterval: 10 * time.Millisecond, // Short cleanup interval for testing
		MaxIdleTime:     20 * time.Millisecond, // Short idle time for testing
	}

	limiter, err := NewTokenBucketLimiter(config)
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

	// Wait for cleanup to run and entries to become idle
	time.Sleep(50 * time.Millisecond)

	// Entries should be cleaned up
	stats = limiter.Stats()
	if stats.ActiveKeys != 0 {
		t.Errorf("ActiveKeys = %d, expected 0 after cleanup", stats.ActiveKeys)
	}
}

func TestTokenBucketLimiter_Cleanup_KeepsActiveEntries(t *testing.T) {
	config := LimitConfig{
		Rate:            10.0,
		Burst:           10,
		CleanupInterval: 10 * time.Millisecond,  // Short cleanup interval for testing
		MaxIdleTime:     100 * time.Millisecond, // Longer idle time
	}

	limiter, err := NewTokenBucketLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	// Add a key
	limiter.Allow("active-key")

	// Wait for cleanup to run, but keep the key active
	for i := 0; i < 5; i++ {
		time.Sleep(15 * time.Millisecond)
		limiter.Allow("active-key") // Keep accessing to reset lastAccess
	}

	// Entry should still exist because it's actively used
	stats := limiter.Stats()
	if stats.ActiveKeys != 1 {
		t.Errorf("ActiveKeys = %d, expected 1 (active entry should not be cleaned up)", stats.ActiveKeys)
	}
}

func TestTokenBucketLimiter_WaitN_RaceRetry(t *testing.T) {
	config := LimitConfig{
		Rate:            1000.0, // High rate
		Burst:           2,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
	if err != nil {
		t.Fatalf("failed to create limiter: %v", err)
	}
	defer func() { _ = limiter.Close() }()

	key := "test-key"

	// Exhaust most tokens
	limiter.Allow(key)

	// Run concurrent waits to trigger race condition retries
	var wg sync.WaitGroup
	errors := make(chan error, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
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

func TestTokenBucketLimiter_GetOrCreateEntry_Concurrent(t *testing.T) {
	config := LimitConfig{
		Rate:            10.0,
		Burst:           10,
		CleanupInterval: time.Minute,
		MaxIdleTime:     time.Minute,
	}

	limiter, err := NewTokenBucketLimiter(config)
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
