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

func TestNewKeyImportCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyImportCommand(getFlags)

	if cmd.Use != "import <key-id>" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Import an external key (not yet implemented)" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.Args == nil {
		t.Error("Args should be set")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewKeyImportCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyImportCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"algorithm", "a", "aes-256-gcm"},
		{"purpose", "p", "encrypt"},
		{"exportable", "e", "false"},
		{"deletion-protection", "", "false"},
		{"name", "n", ""},
		{"description", "d", ""},
		{"wrapping-key", "", ""},
		{"key-file", "f", ""},
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

func TestErrKeyImportFailed_Error(t *testing.T) {
	err := ErrKeyImportFailed{Err: ErrInvalidKeyAlgorithm{Algorithm: "test"}}
	errStr := err.Error()

	if !strings.Contains(errStr, "failed to import key") {
		t.Errorf("error message %q should contain 'failed to import key'", errStr)
	}
}

func TestErrInvalidKeyMaterial_Error(t *testing.T) {
	tests := []struct {
		reason   string
		contains string
	}{
		{"empty key", "empty key"},
		{"invalid format", "invalid format"},
		{"base64 decode failed", "base64 decode failed"},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			err := ErrInvalidKeyMaterial{Reason: tt.reason}
			errStr := err.Error()

			if !strings.Contains(errStr, "invalid key material") {
				t.Errorf("error message %q should contain 'invalid key material'", errStr)
			}
			if !strings.Contains(errStr, tt.contains) {
				t.Errorf("error message %q should contain %q", errStr, tt.contains)
			}
		})
	}
}

func TestErrKeyMaterialReadFailed_Error(t *testing.T) {
	err := ErrKeyMaterialReadFailed{Path: "/tmp/key.pem", Err: os.ErrNotExist}
	errStr := err.Error()

	if !strings.Contains(errStr, "failed to read key material") {
		t.Errorf("error message %q should contain 'failed to read key material'", errStr)
	}
	if !strings.Contains(errStr, "/tmp/key.pem") {
		t.Errorf("error message %q should contain path", errStr)
	}
}

func TestKeyImportCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyImportCommand(getFlags)

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}

	// Should mention base64
	if !strings.Contains(cmd.Long, "base64") {
		t.Error("Long description should mention base64 encoding")
	}

	// Should mention file
	if !strings.Contains(cmd.Long, "file") {
		t.Error("Long description should mention file option")
	}

	// Should mention wrapping key
	if !strings.Contains(cmd.Long, "wrapping") {
		t.Error("Long description should mention wrapping key")
	}
}

func TestKeyImportCommand_InParentCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	parentCmd := NewKeyCommand(getFlags)

	var found bool
	for _, subcmd := range parentCmd.Commands() {
		if subcmd.Name() == "import" {
			found = true
			break
		}
	}

	if !found {
		t.Error("import subcommand not found in key command")
	}
}
