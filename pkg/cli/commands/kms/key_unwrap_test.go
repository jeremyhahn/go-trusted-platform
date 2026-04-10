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
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewKeyUnwrapCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyUnwrapCommand(getFlags)

	if cmd.Use != "unwrap" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Import a wrapped key (not yet implemented)" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewKeyUnwrapCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyUnwrapCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"key-id", "", ""},
		{"wrapping-key", "", ""},
		{"wrapping-algorithm", "", "aes-kw"},
		{"algorithm", "a", ""},
		{"name", "n", ""},
		{"description", "d", ""},
		{"input-file", "f", ""},
		{"material", "m", ""},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				t.Errorf("flag %q not found", tt.flagName)
				return
			}
			if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
				t.Errorf("flag %q shorthand: got %q, want %q", tt.flagName, flag.Shorthand, tt.shorthand)
			}
			if flag.DefValue != tt.defaultValue {
				t.Errorf("flag %q default: got %q, want %q", tt.flagName, flag.DefValue, tt.defaultValue)
			}
		})
	}
}

func TestErrKeyUnwrapFailed_Error(t *testing.T) {
	err := ErrKeyUnwrapFailed{Err: ErrInvalidKeyAlgorithm{Algorithm: "test"}}
	errStr := err.Error()

	if !strings.Contains(errStr, "failed to unwrap key") {
		t.Errorf("error message %q should contain 'failed to unwrap key'", errStr)
	}
}

func TestErrWrappedMaterialRequired_Error(t *testing.T) {
	err := ErrWrappedMaterialRequired{}
	errStr := err.Error()

	if !strings.Contains(errStr, "wrapped key material is required") {
		t.Errorf("error message %q should contain 'wrapped key material is required'", errStr)
	}
	if !strings.Contains(errStr, "--input-file") || !strings.Contains(errStr, "--material") {
		t.Errorf("error message %q should mention flag options", errStr)
	}
}

func TestErrReadWrappedMaterialFailed_Error(t *testing.T) {
	err := ErrReadWrappedMaterialFailed{Path: "/tmp/wrapped.bin", Err: os.ErrNotExist}
	errStr := err.Error()

	if !strings.Contains(errStr, "failed to read wrapped material") {
		t.Errorf("error message %q should contain 'failed to read wrapped material'", errStr)
	}
	if !strings.Contains(errStr, "/tmp/wrapped.bin") {
		t.Errorf("error message %q should contain path", errStr)
	}
}

func TestKeyUnwrapCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyUnwrapCommand(getFlags)

	// Should explain unwrapping
	if !strings.Contains(cmd.Long, "unwrap") {
		t.Error("Long description should mention unwrap")
	}

	// Should mention base64
	if !strings.Contains(cmd.Long, "base64") {
		t.Error("Long description should mention base64 encoding")
	}

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}

	// Should mention file option
	if !strings.Contains(cmd.Long, "file") {
		t.Error("Long description should mention file option")
	}
}

func TestKeyUnwrapCommand_InParentCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	parentCmd := NewKeyCommand(getFlags)

	var found bool
	for _, subcmd := range parentCmd.Commands() {
		if subcmd.Name() == "unwrap" {
			found = true
			break
		}
	}

	if !found {
		t.Error("unwrap subcommand not found in key command")
	}
}

func TestKeyUnwrapCommand_RequiredFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyUnwrapCommand(getFlags)

	requiredFlags := []string{"key-id", "wrapping-key", "algorithm"}
	for _, flagName := range requiredFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("required flag %q not found", flagName)
			continue
		}
		// Required flags should have empty defaults
		if flagName != "wrapping-algorithm" && flag.DefValue != "" {
			t.Errorf("required flag %q should have empty default, got %q", flagName, flag.DefValue)
		}
	}
}
