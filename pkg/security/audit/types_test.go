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

package audit

import (
	"log/slog"
	"testing"
	"time"
)

func TestAuditEvent_Validate(t *testing.T) {
	validEvent := AuditEvent{
		ID:        "test-id",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "login",
		Outcome:   OutcomeSuccess,
	}

	tests := []struct {
		name        string
		event       AuditEvent
		expectError bool
		errorField  string
	}{
		{
			name:        "valid event",
			event:       validEvent,
			expectError: false,
		},
		{
			name: "empty ID",
			event: AuditEvent{
				ID:        "",
				Timestamp: time.Now(),
				Actor:     "user",
				Action:    "login",
				Outcome:   OutcomeSuccess,
			},
			expectError: true,
			errorField:  "ID",
		},
		{
			name: "zero timestamp",
			event: AuditEvent{
				ID:        "test-id",
				Timestamp: time.Time{},
				Actor:     "user",
				Action:    "login",
				Outcome:   OutcomeSuccess,
			},
			expectError: true,
			errorField:  "Timestamp",
		},
		{
			name: "empty actor",
			event: AuditEvent{
				ID:        "test-id",
				Timestamp: time.Now(),
				Actor:     "",
				Action:    "login",
				Outcome:   OutcomeSuccess,
			},
			expectError: true,
			errorField:  "Actor",
		},
		{
			name: "empty action",
			event: AuditEvent{
				ID:        "test-id",
				Timestamp: time.Now(),
				Actor:     "user",
				Action:    "",
				Outcome:   OutcomeSuccess,
			},
			expectError: true,
			errorField:  "Action",
		},
		{
			name: "empty outcome",
			event: AuditEvent{
				ID:        "test-id",
				Timestamp: time.Now(),
				Actor:     "user",
				Action:    "login",
				Outcome:   "",
			},
			expectError: true,
			errorField:  "Outcome",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if tt.expectError {
				invalidErr, ok := err.(ErrInvalidEvent)
				if !ok {
					t.Errorf("expected ErrInvalidEvent, got %T", err)
				} else if invalidErr.Field != tt.errorField {
					t.Errorf("Field = %s, expected %s", invalidErr.Field, tt.errorField)
				}
			}
		})
	}
}

func TestAuditFilter_Validate(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		filter      AuditFilter
		expectError bool
	}{
		{
			name:        "empty filter",
			filter:      AuditFilter{},
			expectError: false,
		},
		{
			name: "valid time range",
			filter: AuditFilter{
				StartTime: now.Add(-time.Hour),
				EndTime:   now,
			},
			expectError: false,
		},
		{
			name: "start after end",
			filter: AuditFilter{
				StartTime: now,
				EndTime:   now.Add(-time.Hour),
			},
			expectError: true,
		},
		{
			name: "negative limit",
			filter: AuditFilter{
				Limit: -1,
			},
			expectError: true,
		},
		{
			name: "negative offset",
			filter: AuditFilter{
				Offset: -1,
			},
			expectError: true,
		},
		{
			name: "valid pagination",
			filter: AuditFilter{
				Limit:  100,
				Offset: 50,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.filter.Validate()
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestDefaultLoggerConfig(t *testing.T) {
	config := DefaultLoggerConfig()

	if config.Logger == nil {
		t.Error("Logger should not be nil")
	}
	if config.BufferSize != 1000 {
		t.Errorf("BufferSize = %d, expected 1000", config.BufferSize)
	}
	if config.FlushInterval != 5*time.Second {
		t.Errorf("FlushInterval = %v, expected 5s", config.FlushInterval)
	}
	if !config.EnableAsync {
		t.Error("EnableAsync should be true")
	}
	if config.DropOnFull {
		t.Error("DropOnFull should be false")
	}
	if !config.ValidateEvents {
		t.Error("ValidateEvents should be true")
	}
}

func TestLoggerConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      LoggerConfig
		expectError bool
	}{
		{
			name:        "valid default config",
			config:      DefaultLoggerConfig(),
			expectError: false,
		},
		{
			name: "nil logger",
			config: LoggerConfig{
				Logger:     nil,
				BufferSize: 1000,
			},
			expectError: true,
		},
		{
			name: "async with zero buffer",
			config: LoggerConfig{
				Logger:      slog.Default(),
				EnableAsync: true,
				BufferSize:  0,
			},
			expectError: true,
		},
		{
			name: "async with negative buffer",
			config: LoggerConfig{
				Logger:      slog.Default(),
				EnableAsync: true,
				BufferSize:  -1,
			},
			expectError: true,
		},
		{
			name: "async with zero flush interval",
			config: LoggerConfig{
				Logger:        slog.Default(),
				EnableAsync:   true,
				BufferSize:    1000,
				FlushInterval: 0,
			},
			expectError: true,
		},
		{
			name: "sync mode with zero buffer allowed",
			config: LoggerConfig{
				Logger:      slog.Default(),
				EnableAsync: false,
				BufferSize:  0,
			},
			expectError: false,
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

func TestQueryResult(t *testing.T) {
	result := QueryResult{
		Events: []AuditEvent{
			{ID: "1", Actor: "user1"},
			{ID: "2", Actor: "user2"},
		},
		Total:   100,
		HasMore: true,
	}

	if len(result.Events) != 2 {
		t.Errorf("Events length = %d, expected 2", len(result.Events))
	}
	if result.Total != 100 {
		t.Errorf("Total = %d, expected 100", result.Total)
	}
	if !result.HasMore {
		t.Error("HasMore should be true")
	}
}

func TestOutcomeConstants(t *testing.T) {
	tests := []struct {
		outcome  Outcome
		expected string
	}{
		{OutcomeSuccess, "success"},
		{OutcomeFailure, "failure"},
		{OutcomeDenied, "denied"},
		{OutcomeError, "error"},
	}

	for _, tt := range tests {
		t.Run(string(tt.outcome), func(t *testing.T) {
			if string(tt.outcome) != tt.expected {
				t.Errorf("Outcome = %s, expected %s", tt.outcome, tt.expected)
			}
		})
	}
}
