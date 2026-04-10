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

package util

import (
	"testing"
	"time"
)

func TestNewLeakyBucket(t *testing.T) {
	capacity := 10
	window := 1 * time.Second

	bucket := NewLeakyBucket(capacity, window)

	if bucket == nil {
		t.Fatal("Expected non-nil bucket")
	}

	if bucket.capacity != capacity {
		t.Errorf("Expected capacity %d, got %d", capacity, bucket.capacity)
	}

	if bucket.tokens != capacity {
		t.Errorf("Expected initial tokens %d, got %d", capacity, bucket.tokens)
	}

	expectedLeakInterval := window / time.Duration(capacity)
	if bucket.leakInterval != expectedLeakInterval {
		t.Errorf("Expected leak interval %v, got %v", expectedLeakInterval, bucket.leakInterval)
	}
}

func TestLeakyBucket_AllowRequest_InitiallyFull(t *testing.T) {
	capacity := 5
	window := 1 * time.Second
	bucket := NewLeakyBucket(capacity, window)

	// Bucket starts full, so first request should be denied
	if bucket.AllowRequest() {
		t.Error("Expected first request to be denied when bucket is initially full")
	}
}

func TestLeakyBucket_AllowRequest_AfterLeak(t *testing.T) {
	capacity := 5
	window := 100 * time.Millisecond
	bucket := NewLeakyBucket(capacity, window)

	// Wait for at least one token to leak
	time.Sleep(window/time.Duration(capacity) + 10*time.Millisecond)

	// After leak, request should be allowed
	if !bucket.AllowRequest() {
		t.Error("Expected request to be allowed after token leak")
	}
}

func TestLeakyBucket_AllowRequest_MultipleAfterLeak(t *testing.T) {
	capacity := 5
	window := 100 * time.Millisecond
	bucket := NewLeakyBucket(capacity, window)

	// Wait for multiple tokens to leak
	time.Sleep(window/time.Duration(capacity)*3 + 10*time.Millisecond)

	// Multiple requests should be allowed
	for i := 0; i < 3; i++ {
		if !bucket.AllowRequest() {
			t.Errorf("Expected request %d to be allowed after leak", i+1)
		}
	}
}

func TestLeakyBucket_AllowRequest_ExceedsCapacity(t *testing.T) {
	capacity := 3
	window := 100 * time.Millisecond
	bucket := NewLeakyBucket(capacity, window)

	// Wait for all tokens to leak
	time.Sleep(window + 10*time.Millisecond)

	// Fill the bucket to capacity
	for i := 0; i < capacity; i++ {
		if !bucket.AllowRequest() {
			t.Fatalf("Expected request %d to be allowed", i+1)
		}
	}

	// Next request should be denied (bucket is full again)
	if bucket.AllowRequest() {
		t.Error("Expected request to be denied when bucket is full")
	}
}

func TestLeakyBucket_AllowRequest_Refill(t *testing.T) {
	capacity := 5
	window := 100 * time.Millisecond
	bucket := NewLeakyBucket(capacity, window)

	// Wait for all tokens to leak
	time.Sleep(window + 10*time.Millisecond)

	// Fill the bucket
	for i := 0; i < capacity; i++ {
		if !bucket.AllowRequest() {
			t.Fatalf("Expected request %d to be allowed", i+1)
		}
	}

	// Bucket is full, request should be denied
	if bucket.AllowRequest() {
		t.Error("Expected request to be denied when bucket is full")
	}

	// Wait for tokens to leak again
	time.Sleep(window/time.Duration(capacity) + 10*time.Millisecond)

	// Request should be allowed again
	if !bucket.AllowRequest() {
		t.Error("Expected request to be allowed after token leak")
	}
}

func TestLeakyBucket_AllowRequest_GradualLeak(t *testing.T) {
	capacity := 10
	window := 200 * time.Millisecond
	bucket := NewLeakyBucket(capacity, window)

	// Wait for half the tokens to leak
	halfLeakTime := (window / time.Duration(capacity)) * time.Duration(capacity/2)
	time.Sleep(halfLeakTime + 10*time.Millisecond)

	// Should be able to make approximately half capacity requests
	allowed := 0
	for i := 0; i < capacity; i++ {
		if bucket.AllowRequest() {
			allowed++
		}
	}

	// Should allow at least capacity/2 requests
	if allowed < capacity/2 {
		t.Errorf("Expected at least %d requests allowed, got %d", capacity/2, allowed)
	}
}

func TestLeakyBucket_Concurrent(t *testing.T) {
	capacity := 100
	window := 1 * time.Second
	bucket := NewLeakyBucket(capacity, window)

	// Test concurrent access - this verifies thread safety
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 20; j++ {
				bucket.AllowRequest()
				time.Sleep(1 * time.Millisecond)
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Test passed if no race condition occurred
}
