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
	"testing"
)

func TestErrRateLimitExceeded_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrRateLimitExceeded
		expected string
	}{
		{
			name:     "with key",
			err:      ErrRateLimitExceeded{Key: "user:123"},
			expected: "rate limit exceeded for key: user:123",
		},
		{
			name:     "with ip key",
			err:      ErrRateLimitExceeded{Key: "192.168.1.1"},
			expected: "rate limit exceeded for key: 192.168.1.1",
		},
		{
			name:     "empty key",
			err:      ErrRateLimitExceeded{Key: ""},
			expected: "rate limit exceeded for key: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidRate_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidRate
		expected string
	}{
		{
			name:     "negative rate",
			err:      ErrInvalidRate{Rate: -1.0},
			expected: "invalid rate: -1.000000, must be positive",
		},
		{
			name:     "zero rate",
			err:      ErrInvalidRate{Rate: 0.0},
			expected: "invalid rate: 0.000000, must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidBurst_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidBurst
		expected string
	}{
		{
			name:     "negative burst",
			err:      ErrInvalidBurst{Burst: -1},
			expected: "invalid burst size: -1, must be positive",
		},
		{
			name:     "zero burst",
			err:      ErrInvalidBurst{Burst: 0},
			expected: "invalid burst size: 0, must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestErrKeyNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrKeyNotFound
		expected string
	}{
		{
			name:     "with key",
			err:      ErrKeyNotFound{Key: "user:456"},
			expected: "rate limiter key not found: user:456",
		},
		{
			name:     "empty key",
			err:      ErrKeyNotFound{Key: ""},
			expected: "rate limiter key not found: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestErrContextCanceled_Error(t *testing.T) {
	err := ErrContextCanceled{Key: "test-key"}
	expected := "rate limit wait canceled for key: test-key"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrInvalidWindowSize_Error(t *testing.T) {
	err := ErrInvalidWindowSize{Size: -1000}
	expected := "invalid window size: -1000 nanoseconds, must be positive"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrInvalidCleanupInterval_Error(t *testing.T) {
	err := ErrInvalidCleanupInterval{Interval: 0}
	expected := "invalid cleanup interval: 0 nanoseconds, must be positive"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrLimiterClosed_Error(t *testing.T) {
	err := ErrLimiterClosed{}
	expected := "rate limiter has been closed"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}
