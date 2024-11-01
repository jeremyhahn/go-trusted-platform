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
