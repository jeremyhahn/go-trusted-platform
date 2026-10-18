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

//go:build integration

package helpers

import (
	"context"
	"fmt"
	"time"
)

// GenerateUniqueID generates a unique identifier with a prefix
func GenerateUniqueID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// GenerateTestData generates test data of a specified size
func GenerateTestData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}
	return data
}

// RetryConfig configures retry behavior for operations
type RetryConfig struct {
	MaxAttempts int
	InitialWait time.Duration
	MaxWait     time.Duration
	Multiplier  float64
}

// DefaultRetryConfig returns sensible defaults for retry operations
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 10,
		InitialWait: 500 * time.Millisecond,
		MaxWait:     5 * time.Second,
		Multiplier:  1.5,
	}
}

// Retry executes an operation with exponential backoff retry
func Retry(ctx context.Context, cfg RetryConfig, operation func() error) error {
	var lastErr error
	wait := cfg.InitialWait

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		lastErr = operation()
		if lastErr == nil {
			return nil
		}

		// Check context cancellation
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Don't wait after last attempt
		if attempt < cfg.MaxAttempts {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}

			// Exponential backoff
			wait = time.Duration(float64(wait) * cfg.Multiplier)
			if wait > cfg.MaxWait {
				wait = cfg.MaxWait
			}
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", cfg.MaxAttempts, lastErr)
}

// WaitForReady waits for a service to be ready
func WaitForReady(ctx context.Context, check func() error) error {
	cfg := DefaultRetryConfig()
	return Retry(ctx, cfg, check)
}

// TestDataSizes returns common test data sizes for testing
func TestDataSizes() []int {
	return []int{1, 100, 1024, 10 * 1024, 100 * 1024}
}

// Must panics if err is not nil
func Must[T any](val T, err error) T {
	if err != nil {
		panic(err)
	}
	return val
}

// MustOK panics if err is not nil
func MustOK(err error) {
	if err != nil {
		panic(err)
	}
}
