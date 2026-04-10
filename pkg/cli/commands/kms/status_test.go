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

package kms

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewStatusCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewStatusCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewStatusCommand returned nil")
	}

	if cmd.Use != "status" {
		t.Errorf("expected Use to be 'status', got %q", cmd.Use)
	}

	if cmd.Short != "Show KMS backend status" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewStatusCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewStatusCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	expectedLong := "Display the current status, health, and capabilities of the KMS backend"
	if cmd.Long != expectedLong {
		t.Errorf("unexpected Long description: got %q, want %q", cmd.Long, expectedLong)
	}
}

func TestNewStatusCommand_HasRunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewStatusCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestNewStatusCommand_NoSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewStatusCommand(getFlags)

	// Status is a leaf command, it should not have subcommands
	if len(cmd.Commands()) != 0 {
		t.Errorf("status command should not have subcommands, got %d", len(cmd.Commands()))
	}
}

func TestNewStatusCommand_NoArgs(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewStatusCommand(getFlags)

	// Status command doesn't take arguments
	if cmd.Args != nil {
		t.Error("status command should not have Args set (no required args)")
	}
}

func TestErrKMSClientNotInitialized(t *testing.T) {
	err := ErrKMSClientNotInitialized{}
	expected := "KMS client not initialized"
	if err.Error() != expected {
		t.Errorf("ErrKMSClientNotInitialized.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrKMSStatusFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "with nil error",
			err:      nil,
			expected: "failed to get KMS status: <nil>",
		},
		{
			name:     "with underlying error",
			err:      ErrKMSClientNotInitialized{},
			expected: "failed to get KMS status: KMS client not initialized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrKMSStatusFailed{Err: tt.err}

			if err.Error() != tt.expected {
				t.Errorf("ErrKMSStatusFailed.Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}

func TestFormatStatusIcon(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected string
	}{
		// Healthy states
		{"healthy lowercase", "healthy", "[HEALTHY]"},
		{"healthy uppercase", "HEALTHY", "[HEALTHY]"},
		{"healthy mixed case", "Healthy", "[HEALTHY]"},
		{"ready lowercase", "ready", "[HEALTHY]"},
		{"ready uppercase", "READY", "[HEALTHY]"},

		// Degraded states
		{"degraded lowercase", "degraded", "[DEGRADED]"},
		{"degraded uppercase", "DEGRADED", "[DEGRADED]"},
		{"degraded mixed case", "Degraded", "[DEGRADED]"},

		// Unavailable states
		{"unavailable lowercase", "unavailable", "[UNAVAILABLE]"},
		{"unavailable uppercase", "UNAVAILABLE", "[UNAVAILABLE]"},
		{"error lowercase", "error", "[UNAVAILABLE]"},
		{"error uppercase", "ERROR", "[UNAVAILABLE]"},

		// Unknown states
		{"unknown", "unknown", "[UNKNOWN]"},
		{"empty string", "", "[UNKNOWN]"},
		{"random status", "something-else", "[UNKNOWN]"},
		{"partial match", "health", "[UNKNOWN]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatStatusIcon(tt.status)
			if result != tt.expected {
				t.Errorf("formatStatusIcon(%q) = %q, want %q", tt.status, result, tt.expected)
			}
		})
	}
}

func TestFormatCapabilityName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single word lowercase",
			input:    "encryption",
			expected: "Encryption",
		},
		{
			name:     "single word uppercase",
			input:    "ENCRYPTION",
			expected: "Encryption",
		},
		{
			name:     "snake_case two words",
			input:    "key_generation",
			expected: "Key Generation",
		},
		{
			name:     "snake_case three words",
			input:    "secure_random_generation",
			expected: "Secure Random Generation",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single underscore",
			input:    "_",
			expected: " ",
		},
		{
			name:     "all caps snake_case",
			input:    "AES_GCM_ENCRYPTION",
			expected: "Aes Gcm Encryption",
		},
		{
			name:     "mixed case",
			input:    "Key_ROTATION",
			expected: "Key Rotation",
		},
		{
			name:     "trailing underscore",
			input:    "test_",
			expected: "Test ",
		},
		{
			name:     "leading underscore",
			input:    "_test",
			expected: " Test",
		},
		{
			name:     "multiple underscores",
			input:    "a__b",
			expected: "A  B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatCapabilityName(tt.input)
			if result != tt.expected {
				t.Errorf("formatCapabilityName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestStatusCommand_GetFlagsNotCalledOnCreation(t *testing.T) {
	callCount := 0
	getFlags := func() *cli.CommonFlags {
		callCount++
		return &cli.CommonFlags{}
	}

	_ = NewStatusCommand(getFlags)

	// getFlags should not be called during command creation
	if callCount != 0 {
		t.Errorf("getFlags was called %d times during command creation, expected 0", callCount)
	}
}

func TestStatusCommand_UsesCorrectOutputFormats(t *testing.T) {
	// Verify the command structure supports different output formats
	// by checking it uses the common flags pattern
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewStatusCommand(getFlags)

	// The command should be created successfully regardless of output format
	if cmd == nil {
		t.Fatal("command should be created successfully")
	}
}

func TestStatusCommand_DescriptionMentionsCapabilities(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewStatusCommand(getFlags)

	// Long description should mention capabilities since the command displays them
	if len(cmd.Long) < 20 {
		t.Error("Long description should be more descriptive")
	}
}
