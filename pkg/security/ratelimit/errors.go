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

import "fmt"

// ErrRateLimitExceeded is returned when the rate limit has been exceeded for a key
type ErrRateLimitExceeded struct {
	Key string
}

func (e ErrRateLimitExceeded) Error() string {
	return fmt.Sprintf("rate limit exceeded for key: %s", e.Key)
}

// ErrInvalidRate is returned when the rate configuration is invalid
type ErrInvalidRate struct {
	Rate float64
}

func (e ErrInvalidRate) Error() string {
	return fmt.Sprintf("invalid rate: %f, must be positive", e.Rate)
}

// ErrInvalidBurst is returned when the burst configuration is invalid
type ErrInvalidBurst struct {
	Burst int
}

func (e ErrInvalidBurst) Error() string {
	return fmt.Sprintf("invalid burst size: %d, must be positive", e.Burst)
}

// ErrKeyNotFound is returned when a rate limiter key is not found
type ErrKeyNotFound struct {
	Key string
}

func (e ErrKeyNotFound) Error() string {
	return fmt.Sprintf("rate limiter key not found: %s", e.Key)
}

// ErrContextCanceled is returned when a wait operation is canceled via context
type ErrContextCanceled struct {
	Key string
}

func (e ErrContextCanceled) Error() string {
	return fmt.Sprintf("rate limit wait canceled for key: %s", e.Key)
}

// ErrInvalidWindowSize is returned when the sliding window size is invalid
type ErrInvalidWindowSize struct {
	Size int64
}

func (e ErrInvalidWindowSize) Error() string {
	return fmt.Sprintf("invalid window size: %d nanoseconds, must be positive", e.Size)
}

// ErrInvalidCleanupInterval is returned when the cleanup interval is invalid
type ErrInvalidCleanupInterval struct {
	Interval int64
}

func (e ErrInvalidCleanupInterval) Error() string {
	return fmt.Sprintf("invalid cleanup interval: %d nanoseconds, must be positive", e.Interval)
}

// ErrLimiterClosed is returned when operations are attempted on a closed limiter
type ErrLimiterClosed struct{}

func (e ErrLimiterClosed) Error() string {
	return "rate limiter has been closed"
}
