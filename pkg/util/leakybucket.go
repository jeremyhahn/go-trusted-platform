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
	"sync"
	"time"
)

type LeakyBucket struct {
	capacity     int
	leakInterval time.Duration
	tokens       int
	lastLeakTime time.Time
	mu           sync.Mutex
}

// Creates a new rate limiter using the leaky bucket algorithm
func NewLeakyBucket(capacity int, window time.Duration) *LeakyBucket {
	leakInterval := window / time.Duration(capacity)
	return &LeakyBucket{
		capacity:     capacity,
		leakInterval: leakInterval,
		tokens:       capacity,
		lastLeakTime: time.Now(),
	}
}

func (b *LeakyBucket) AllowRequest() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastLeakTime)
	leakedTokens := int(elapsed / b.leakInterval)
	if leakedTokens > 0 {
		b.tokens -= leakedTokens
		if b.tokens < 0 {
			b.tokens = 0
		}
		b.lastLeakTime = now
	}

	if b.tokens < b.capacity {
		b.tokens++
		return true
	}

	return false
}
