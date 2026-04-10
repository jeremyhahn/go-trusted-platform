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

package container

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewAttestCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newAttestCommand(getFlags)

	if cmd == nil {
		t.Fatal("newAttestCommand returned nil")
	}

	if cmd.Use != "attest <container-id>" {
		t.Errorf("expected Use to be 'attest <container-id>', got %q", cmd.Use)
	}

	if cmd.Short != "Attest container integrity" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewAttestCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newAttestCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(cmd.Long) < 100 {
		t.Error("Long description should be descriptive")
	}
}

func TestNewAttestCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newAttestCommand(getFlags)

	tests := []struct {
		name     string
		defValue string
	}{
		{"nonce", ""},
		{"pcrs", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.name)
			if flag == nil {
				t.Errorf("--%s flag not found", tt.name)
				return
			}

			if flag.DefValue != tt.defValue {
				t.Errorf("--%s flag default: got %q, want %q", tt.name, flag.DefValue, tt.defValue)
			}
		})
	}
}

func TestNewAttestCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newAttestCommand(getFlags)

	if cmd.Args == nil {
		t.Error("Args should not be nil")
	}

	err := cmd.Args(cmd, []string{})
	if err == nil {
		t.Error("expected error when no args provided")
	}

	err = cmd.Args(cmd, []string{"container-id"})
	if err != nil {
		t.Errorf("unexpected error with one arg: %v", err)
	}
}

func TestRunAttest_EmptyContainerID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	opts := &attestOptions{nonce: "", pcrs: ""}

	err := runAttest(flags, "", opts)
	if err == nil {
		t.Error("expected error for empty container ID")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}

func TestParsePCRIndices(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    []uint32
		expectError bool
	}{
		{
			name:        "empty string",
			input:       "",
			expected:    nil,
			expectError: false,
		},
		{
			name:        "single PCR",
			input:       "0",
			expected:    []uint32{0},
			expectError: false,
		},
		{
			name:        "multiple PCRs",
			input:       "0,1,7,14",
			expected:    []uint32{0, 1, 7, 14},
			expectError: false,
		},
		{
			name:        "PCRs with spaces",
			input:       "0, 1, 7",
			expected:    []uint32{0, 1, 7},
			expectError: false,
		},
		{
			name:        "trailing comma",
			input:       "0,1,7,",
			expected:    []uint32{0, 1, 7},
			expectError: false,
		},
		{
			name:        "leading comma",
			input:       ",0,1,7",
			expected:    []uint32{0, 1, 7},
			expectError: false,
		},
		{
			name:        "multiple commas",
			input:       "0,,1,,7",
			expected:    []uint32{0, 1, 7},
			expectError: false,
		},
		{
			name:        "invalid PCR (not a number)",
			input:       "abc",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid PCR (out of range)",
			input:       "24",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "mixed valid and invalid",
			input:       "0,abc,7",
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePCRIndices(tt.input)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(result) != len(tt.expected) {
				t.Errorf("expected %d PCRs, got %d", len(tt.expected), len(result))
				return
			}

			for i, v := range tt.expected {
				if result[i] != v {
					t.Errorf("PCR at index %d: expected %d, got %d", i, v, result[i])
				}
			}
		})
	}
}

func TestFormatPCRIndices(t *testing.T) {
	tests := []struct {
		name     string
		indices  []uint32
		expected string
	}{
		{
			name:     "empty",
			indices:  nil,
			expected: "none",
		},
		{
			name:     "empty slice",
			indices:  []uint32{},
			expected: "none",
		},
		{
			name:     "single",
			indices:  []uint32{0},
			expected: "0",
		},
		{
			name:     "multiple",
			indices:  []uint32{0, 1, 7, 14},
			expected: "0, 1, 7, 14",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatPCRIndices(tt.indices)
			if result != tt.expected {
				t.Errorf("formatPCRIndices() = %q, want %q", result, tt.expected)
			}
		})
	}
}
