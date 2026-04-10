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
	"time"
)

func TestDefaultLimitConfig(t *testing.T) {
	config := DefaultLimitConfig()

	if config.Rate != 10.0 {
		t.Errorf("Rate = %f, expected 10.0", config.Rate)
	}
	if config.Burst != 20 {
		t.Errorf("Burst = %d, expected 20", config.Burst)
	}
	if config.CleanupInterval != 5*time.Minute {
		t.Errorf("CleanupInterval = %v, expected 5m", config.CleanupInterval)
	}
	if config.MaxIdleTime != 10*time.Minute {
		t.Errorf("MaxIdleTime = %v, expected 10m", config.MaxIdleTime)
	}
}

func TestLimitConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      LimitConfig
		expectError bool
		errorType   interface{}
	}{
		{
			name:        "valid config",
			config:      DefaultLimitConfig(),
			expectError: false,
		},
		{
			name: "negative rate",
			config: LimitConfig{
				Rate:            -1.0,
				Burst:           10,
				CleanupInterval: time.Minute,
			},
			expectError: true,
			errorType:   ErrInvalidRate{},
		},
		{
			name: "zero rate",
			config: LimitConfig{
				Rate:            0,
				Burst:           10,
				CleanupInterval: time.Minute,
			},
			expectError: true,
			errorType:   ErrInvalidRate{},
		},
		{
			name: "negative burst",
			config: LimitConfig{
				Rate:            10.0,
				Burst:           -1,
				CleanupInterval: time.Minute,
			},
			expectError: true,
			errorType:   ErrInvalidBurst{},
		},
		{
			name: "zero burst",
			config: LimitConfig{
				Rate:            10.0,
				Burst:           0,
				CleanupInterval: time.Minute,
			},
			expectError: true,
			errorType:   ErrInvalidBurst{},
		},
		{
			name: "negative cleanup interval",
			config: LimitConfig{
				Rate:            10.0,
				Burst:           10,
				CleanupInterval: -time.Minute,
			},
			expectError: true,
			errorType:   ErrInvalidCleanupInterval{},
		},
		{
			name: "zero cleanup interval",
			config: LimitConfig{
				Rate:            10.0,
				Burst:           10,
				CleanupInterval: 0,
			},
			expectError: true,
			errorType:   ErrInvalidCleanupInterval{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestDefaultSlidingWindowConfig(t *testing.T) {
	config := DefaultSlidingWindowConfig()

	if config.WindowSize != time.Minute {
		t.Errorf("WindowSize = %v, expected 1m", config.WindowSize)
	}
	if config.MaxRequests != 100 {
		t.Errorf("MaxRequests = %d, expected 100", config.MaxRequests)
	}
	if config.CleanupInterval != 5*time.Minute {
		t.Errorf("CleanupInterval = %v, expected 5m", config.CleanupInterval)
	}
	if config.MaxIdleTime != 10*time.Minute {
		t.Errorf("MaxIdleTime = %v, expected 10m", config.MaxIdleTime)
	}
}

func TestSlidingWindowConfig_Validate(t *testing.T) {
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
			name: "negative window size",
			config: SlidingWindowConfig{
				WindowSize:      -time.Minute,
				MaxRequests:     100,
				CleanupInterval: time.Minute,
			},
			expectError: true,
		},
		{
			name: "zero window size",
			config: SlidingWindowConfig{
				WindowSize:      0,
				MaxRequests:     100,
				CleanupInterval: time.Minute,
			},
			expectError: true,
		},
		{
			name: "negative max requests",
			config: SlidingWindowConfig{
				WindowSize:      time.Minute,
				MaxRequests:     -1,
				CleanupInterval: time.Minute,
			},
			expectError: true,
		},
		{
			name: "zero max requests",
			config: SlidingWindowConfig{
				WindowSize:      time.Minute,
				MaxRequests:     0,
				CleanupInterval: time.Minute,
			},
			expectError: true,
		},
		{
			name: "negative cleanup interval",
			config: SlidingWindowConfig{
				WindowSize:      time.Minute,
				MaxRequests:     100,
				CleanupInterval: -time.Minute,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
