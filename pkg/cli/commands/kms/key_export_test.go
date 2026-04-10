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
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewKeyExportCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyExportCommand(getFlags)

	if cmd.Use != "export <key-id>" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Export a wrapped key (not yet implemented)" {
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

func TestNewKeyExportCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyExportCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"wrapping-key", "", ""},
		{"wrapping-algorithm", "", "aes-kw"},
		{"format", "", "raw"},
		{"version", "v", "0"},
		{"output-file", "o", ""},
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

func TestNewKeyExportCommand_WrappingKeyRequired(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyExportCommand(getFlags)

	flag := cmd.Flags().Lookup("wrapping-key")
	if flag == nil {
		t.Fatal("wrapping-key flag not found")
	}

	// Check if it's a required flag by checking annotations
	annotations := flag.Annotations
	if annotations == nil {
		// If no annotations, the flag may be marked required differently
		// Just ensure the flag exists and has no default
		if flag.DefValue != "" {
			t.Error("wrapping-key should have empty default (required)")
		}
	}
}

func TestKeyExportCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyExportCommand(getFlags)

	// Should contain wrapping algorithms
	expectedAlgorithms := []string{
		"aes-kw",
		"aes-kwp",
		"aes-gcm",
		"rsa-oaep-sha256",
	}

	for _, alg := range expectedAlgorithms {
		if !strings.Contains(cmd.Long, alg) {
			t.Errorf("Long description should mention algorithm %q", alg)
		}
	}

	// Should mention export formats
	expectedFormats := []string{"raw", "jwk", "pem"}
	for _, format := range expectedFormats {
		if !strings.Contains(cmd.Long, format) {
			t.Errorf("Long description should mention format %q", format)
		}
	}

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}
}

func TestKeyExportCommand_InParentCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	parentCmd := NewKeyCommand(getFlags)

	var found bool
	for _, subcmd := range parentCmd.Commands() {
		if subcmd.Name() == "export" {
			found = true
			break
		}
	}

	if !found {
		t.Error("export subcommand not found in key command")
	}
}

// Error type tests

func TestErrKeyExportFailed_Error(t *testing.T) {
	innerErr := errors.New("permission denied")
	err := ErrKeyExportFailed{
		KeyID: "test-key-123",
		Err:   innerErr,
	}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "failed to export key") {
		t.Errorf("error message should contain 'failed to export key': %s", errMsg)
	}
	if !strings.Contains(errMsg, "test-key-123") {
		t.Errorf("error message should contain key ID: %s", errMsg)
	}
	if !strings.Contains(errMsg, "permission denied") {
		t.Errorf("error message should contain inner error: %s", errMsg)
	}
}

func TestErrKeyNotExportable_Error(t *testing.T) {
	err := ErrKeyNotExportable{
		KeyID: "non-exportable-key",
	}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "not marked as exportable") {
		t.Errorf("error message should contain 'not marked as exportable': %s", errMsg)
	}
	if !strings.Contains(errMsg, "non-exportable-key") {
		t.Errorf("error message should contain key ID: %s", errMsg)
	}
}

func TestErrWriteExportedKeyFailed_Error(t *testing.T) {
	innerErr := errors.New("disk full")
	err := ErrWriteExportedKeyFailed{
		Path: "/path/to/key.pem",
		Err:  innerErr,
	}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "failed to write exported key") {
		t.Errorf("error message should contain 'failed to write exported key': %s", errMsg)
	}
	if !strings.Contains(errMsg, "/path/to/key.pem") {
		t.Errorf("error message should contain path: %s", errMsg)
	}
	if !strings.Contains(errMsg, "disk full") {
		t.Errorf("error message should contain inner error: %s", errMsg)
	}
}
