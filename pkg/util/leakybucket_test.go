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
	bucket, clock := newTestBucket(capacity, window)

	// Let exactly one token leak
	clock.Advance(window / time.Duration(capacity))

	// After leak, request should be allowed
	if !bucket.AllowRequest() {
		t.Error("Expected request to be allowed after token leak")
	}
}

func TestLeakyBucket_AllowRequest_BeforeLeakInterval(t *testing.T) {
	capacity := 5
	window := 100 * time.Millisecond
	bucket, clock := newTestBucket(capacity, window)

	// One nanosecond short of the leak interval, no token has leaked
	clock.Advance(window/time.Duration(capacity) - time.Nanosecond)

	if bucket.AllowRequest() {
		t.Error("Expected request to be denied before a full leak interval elapsed")
	}
}

func TestLeakyBucket_AllowRequest_ClockStepsBack(t *testing.T) {
	capacity := 5
	window := 100 * time.Millisecond
	bucket, clock := newTestBucket(capacity, window)

	// A clock that steps backwards must not leak tokens or overfill the bucket
	clock.Advance(-window)

	if bucket.AllowRequest() {
		t.Error("Expected request to be denied when the clock stepped backwards")
	}
	if bucket.tokens != capacity {
		t.Errorf("Expected tokens to stay at %d, got %d", capacity, bucket.tokens)
	}
}

func TestLeakyBucket_AllowRequest_MultipleAfterLeak(t *testing.T) {
	capacity := 5
	window := 100 * time.Millisecond
	bucket, clock := newTestBucket(capacity, window)

	// Let three tokens leak
	clock.Advance(window / time.Duration(capacity) * 3)

	// Three requests should be allowed, the fourth denied
	for i := 0; i < 3; i++ {
		if !bucket.AllowRequest() {
			t.Errorf("Expected request %d to be allowed after leak", i+1)
		}
	}
	if bucket.AllowRequest() {
		t.Error("Expected request 4 to be denied once the leaked tokens are used")
	}
}

func TestLeakyBucket_AllowRequest_ExceedsCapacity(t *testing.T) {
	capacity := 3
	window := 100 * time.Millisecond
	bucket, clock := newTestBucket(capacity, window)

	// Let all tokens leak
	clock.Advance(window)

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
	bucket, clock := newTestBucket(capacity, window)

	// Let all tokens leak
	clock.Advance(window)

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

	// Let one token leak again
	clock.Advance(window / time.Duration(capacity))

	// Request should be allowed again
	if !bucket.AllowRequest() {
		t.Error("Expected request to be allowed after token leak")
	}
}

func TestLeakyBucket_AllowRequest_GradualLeak(t *testing.T) {
	capacity := 10
	window := 200 * time.Millisecond
	bucket, clock := newTestBucket(capacity, window)

	// Let half the tokens leak
	halfLeakTime := (window / time.Duration(capacity)) * time.Duration(capacity/2)
	clock.Advance(halfLeakTime)

	// Exactly half capacity requests fit before the bucket is full again
	allowed := 0
	for i := 0; i < capacity; i++ {
		if bucket.AllowRequest() {
			allowed++
		}
	}

	if allowed != capacity/2 {
		t.Errorf("Expected %d requests allowed, got %d", capacity/2, allowed)
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

// testClock is a clock the test advances by hand, so leak timing does not
// depend on the wall clock.
type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time {
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

// newTestBucket returns a leaky bucket driven by a testClock.
func newTestBucket(capacity int, window time.Duration) (*LeakyBucket, *testClock) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	return newLeakyBucket(capacity, window, clock.Now), clock
}
