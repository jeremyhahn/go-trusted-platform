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

package cluster

import (
	"testing"
	"time"
)

func TestFormatTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Time
		expected string
	}{
		{
			name:     "zero time",
			input:    time.Time{},
			expected: "N/A",
		},
		{
			name:     "valid time",
			input:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			expected: "2025-01-15T10:30:00Z",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatTimestamp(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected string
	}{
		{
			name:     "zero duration",
			input:    0,
			expected: "N/A",
		},
		{
			name:     "seconds only",
			input:    45 * time.Second,
			expected: "45s",
		},
		{
			name:     "minutes and seconds",
			input:    5*time.Minute + 30*time.Second,
			expected: "5m30s",
		},
		{
			name:     "hours minutes seconds",
			input:    2*time.Hour + 15*time.Minute + 10*time.Second,
			expected: "2h15m10s",
		},
		{
			name:     "days hours minutes",
			input:    3*24*time.Hour + 5*time.Hour + 30*time.Minute,
			expected: "3d5h30m",
		},
		{
			name:     "one day",
			input:    24 * time.Hour,
			expected: "1d",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatDuration(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestFormatBool(t *testing.T) {
	tests := []struct {
		name     string
		input    bool
		expected string
	}{
		{
			name:     "true",
			input:    true,
			expected: "Yes",
		},
		{
			name:     "false",
			input:    false,
			expected: "No",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatBool(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestFormatRaftState(t *testing.T) {
	tests := []struct {
		name     string
		input    RaftState
		expected string
	}{
		{
			name:     "leader",
			input:    RaftStateLeader,
			expected: "LEADER",
		},
		{
			name:     "follower",
			input:    RaftStateFollower,
			expected: "FOLLOWER",
		},
		{
			name:     "candidate",
			input:    RaftStateCandidate,
			expected: "CANDIDATE",
		},
		{
			name:     "shutdown",
			input:    RaftStateShutdown,
			expected: "SHUTDOWN",
		},
		{
			name:     "unknown",
			input:    RaftStateUnknown,
			expected: "UNKNOWN",
		},
		{
			name:     "invalid",
			input:    RaftState("invalid"),
			expected: "UNKNOWN",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatRaftState(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestFormatNodeState(t *testing.T) {
	tests := []struct {
		name     string
		input    NodeState
		expected string
	}{
		{
			name:     "alive",
			input:    NodeStateAlive,
			expected: "ALIVE",
		},
		{
			name:     "suspect",
			input:    NodeStateSuspect,
			expected: "SUSPECT",
		},
		{
			name:     "dead",
			input:    NodeStateDead,
			expected: "DEAD",
		},
		{
			name:     "left",
			input:    NodeStateLeft,
			expected: "LEFT",
		},
		{
			name:     "unknown",
			input:    NodeStateUnknown,
			expected: "UNKNOWN",
		},
		{
			name:     "invalid",
			input:    NodeState("invalid"),
			expected: "UNKNOWN",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatNodeState(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestFormatTerm(t *testing.T) {
	tests := []struct {
		name     string
		input    uint64
		expected string
	}{
		{
			name:     "zero",
			input:    0,
			expected: "0",
		},
		{
			name:     "small",
			input:    42,
			expected: "42",
		},
		{
			name:     "large",
			input:    1234567890,
			expected: "1234567890",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatTerm(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestFormatCommitIndex(t *testing.T) {
	tests := []struct {
		name     string
		input    uint64
		expected string
	}{
		{
			name:     "zero",
			input:    0,
			expected: "0",
		},
		{
			name:     "small",
			input:    100,
			expected: "100",
		},
		{
			name:     "large",
			input:    9876543210,
			expected: "9876543210",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatCommitIndex(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestParseAddressList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single address",
			input:    "10.0.0.1:7946",
			expected: []string{"10.0.0.1:7946"},
		},
		{
			name:     "multiple addresses",
			input:    "10.0.0.1:7946,10.0.0.2:7946,10.0.0.3:7946",
			expected: []string{"10.0.0.1:7946", "10.0.0.2:7946", "10.0.0.3:7946"},
		},
		{
			name:     "with spaces",
			input:    "10.0.0.1:7946, 10.0.0.2:7946 , 10.0.0.3:7946",
			expected: []string{"10.0.0.1:7946", "10.0.0.2:7946", "10.0.0.3:7946"},
		},
		{
			name:     "with empty entries",
			input:    "10.0.0.1:7946,,10.0.0.2:7946,",
			expected: []string{"10.0.0.1:7946", "10.0.0.2:7946"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseAddressList(tc.input)
			if len(result) != len(tc.expected) {
				t.Errorf("expected length %d, got %d", len(tc.expected), len(result))
				return
			}
			for i, addr := range result {
				if addr != tc.expected[i] {
					t.Errorf("at index %d: expected %q, got %q", i, tc.expected[i], addr)
				}
			}
		})
	}
}

func TestValidateAddress(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid IPv4 with port",
			input:   "10.0.0.1:7946",
			wantErr: false,
		},
		{
			name:    "valid hostname with port",
			input:   "node1.example.com:7946",
			wantErr: false,
		},
		{
			name:    "valid localhost with port",
			input:   "localhost:7946",
			wantErr: false,
		},
		{
			name:    "valid IPv6 with port",
			input:   "[::1]:7946",
			wantErr: false,
		},
		{
			name:    "missing port",
			input:   "10.0.0.1",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "port only",
			input:   ":7946",
			wantErr: true,
		},
		{
			name:    "host only with colon",
			input:   "10.0.0.1:",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAddress(tc.input)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestValidateAddressList(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{
			name:    "all valid",
			input:   []string{"10.0.0.1:7946", "10.0.0.2:7946"},
			wantErr: false,
		},
		{
			name:    "one invalid",
			input:   []string{"10.0.0.1:7946", "invalid"},
			wantErr: true,
		},
		{
			name:    "empty list",
			input:   []string{},
			wantErr: false,
		},
		{
			name:    "nil list",
			input:   nil,
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAddressList(tc.input)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "shorter than max",
			input:    "hello",
			maxLen:   10,
			expected: "hello",
		},
		{
			name:     "exact length",
			input:    "hello",
			maxLen:   5,
			expected: "hello",
		},
		{
			name:     "longer than max",
			input:    "hello world",
			maxLen:   8,
			expected: "hello...",
		},
		{
			name:     "very short max",
			input:    "hello",
			maxLen:   3,
			expected: "hel",
		},
		{
			name:     "zero max",
			input:    "hello",
			maxLen:   0,
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := truncateString(tc.input, tc.maxLen)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestTruncateID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "short ID",
			input:    "node-1",
			expected: "node-1",
		},
		{
			name:     "exactly 12 chars",
			input:    "123456789012",
			expected: "123456789012",
		},
		{
			name:     "longer than 12 chars",
			input:    "node-long-identifier",
			expected: "node-long-id...",
		},
		{
			name:     "UUID format",
			input:    "550e8400-e29b-41d4-a716-446655440000",
			expected: "550e8400-e29...",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := truncateID(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Time
		checkNot string
	}{
		{
			name:     "zero time returns N/A",
			input:    time.Time{},
			checkNot: "",
		},
		{
			name:     "recent time returns non-empty",
			input:    time.Now().Add(-1 * time.Hour),
			checkNot: "N/A",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatUptime(tc.input)
			if tc.checkNot != "" && result == tc.checkNot {
				t.Errorf("expected result different from %q, got %q", tc.checkNot, result)
			}
			if tc.checkNot == "" && tc.input.IsZero() && result != "N/A" {
				t.Errorf("expected N/A for zero time, got %q", result)
			}
		})
	}
}
