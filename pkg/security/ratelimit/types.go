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
	"time"
)

// Limiter defines the interface for rate limiting implementations
type Limiter interface {
	// Allow checks if a single request is allowed for the given key
	// Returns true if the request is allowed, false otherwise
	Allow(key string) bool

	// AllowN checks if n requests are allowed for the given key
	// Returns true if all n requests are allowed, false otherwise
	AllowN(key string, n int) bool

	// Wait blocks until a request is allowed for the given key or context is canceled
	// Returns an error if the context is canceled or deadline exceeded
	Wait(ctx context.Context, key string) error

	// WaitN blocks until n requests are allowed for the given key or context is canceled
	// Returns an error if the context is canceled or deadline exceeded
	WaitN(ctx context.Context, key string, n int) error

	// Reset clears the rate limit state for the given key
	Reset(key string)

	// ResetAll clears all rate limit state
	ResetAll()

	// Close releases any resources held by the limiter
	Close() error
}

// LimitConfig holds the configuration for rate limiters
type LimitConfig struct {
	// Rate is the number of requests allowed per second
	Rate float64

	// Burst is the maximum number of requests that can be made in a single burst
	Burst int

	// CleanupInterval is the interval at which stale entries are cleaned up
	CleanupInterval time.Duration

	// MaxIdleTime is the maximum time a key can be idle before cleanup
	MaxIdleTime time.Duration
}

// DefaultLimitConfig returns a sensible default configuration
func DefaultLimitConfig() LimitConfig {
	return LimitConfig{
		Rate:            10.0,             // 10 requests per second
		Burst:           20,               // burst of 20 requests
		CleanupInterval: 5 * time.Minute,  // cleanup every 5 minutes
		MaxIdleTime:     10 * time.Minute, // remove idle entries after 10 minutes
	}
}

// Validate checks if the configuration is valid
func (c LimitConfig) Validate() error {
	if c.Rate <= 0 {
		return ErrInvalidRate{Rate: c.Rate}
	}
	if c.Burst <= 0 {
		return ErrInvalidBurst{Burst: c.Burst}
	}
	if c.CleanupInterval <= 0 {
		return ErrInvalidCleanupInterval{Interval: int64(c.CleanupInterval)}
	}
	return nil
}

// SlidingWindowConfig holds configuration specific to sliding window limiters
type SlidingWindowConfig struct {
	// WindowSize is the size of the sliding window
	WindowSize time.Duration

	// MaxRequests is the maximum number of requests allowed within the window
	MaxRequests int64

	// CleanupInterval is the interval at which stale entries are cleaned up
	CleanupInterval time.Duration

	// MaxIdleTime is the maximum time a key can be idle before cleanup
	MaxIdleTime time.Duration
}

// DefaultSlidingWindowConfig returns a sensible default configuration
func DefaultSlidingWindowConfig() SlidingWindowConfig {
	return SlidingWindowConfig{
		WindowSize:      time.Minute,      // 1 minute window
		MaxRequests:     100,              // 100 requests per minute
		CleanupInterval: 5 * time.Minute,  // cleanup every 5 minutes
		MaxIdleTime:     10 * time.Minute, // remove idle entries after 10 minutes
	}
}

// Validate checks if the configuration is valid
func (c SlidingWindowConfig) Validate() error {
	if c.WindowSize <= 0 {
		return ErrInvalidWindowSize{Size: int64(c.WindowSize)}
	}
	if c.MaxRequests <= 0 {
		return ErrInvalidBurst{Burst: int(c.MaxRequests)}
	}
	if c.CleanupInterval <= 0 {
		return ErrInvalidCleanupInterval{Interval: int64(c.CleanupInterval)}
	}
	return nil
}
