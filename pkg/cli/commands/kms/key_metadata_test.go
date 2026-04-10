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

func TestNewKeyMetadataCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyMetadataCommand(getFlags)

	if cmd.Use != "metadata" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Manage key metadata (not yet implemented)" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewKeyMetadataCommand_Subcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyMetadataCommand(getFlags)

	expectedSubcommands := []string{"get", "update"}
	actualSubcommands := make(map[string]bool)

	for _, subcmd := range cmd.Commands() {
		actualSubcommands[subcmd.Name()] = true
	}

	for _, expected := range expectedSubcommands {
		if !actualSubcommands[expected] {
			t.Errorf("missing subcommand: %s", expected)
		}
	}
}

func TestNewKeyMetadataGetCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyMetadataGetCommand(getFlags)

	if cmd.Use != "get <key-id>" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Get key metadata (not yet implemented)" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Args == nil {
		t.Error("Args should be set")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewKeyMetadataUpdateCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyMetadataUpdateCommand(getFlags)

	if cmd.Use != "update <key-id>" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Update key metadata (not yet implemented)" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Args == nil {
		t.Error("Args should be set")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewKeyMetadataUpdateCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyMetadataUpdateCommand(getFlags)

	tests := []struct {
		flagName  string
		shorthand string
	}{
		{"name", "n"},
		{"description", "d"},
		{"tag", "t"},
		{"remove-tag", ""},
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
		})
	}
}

func TestKeyMetadataCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyMetadataCommand(getFlags)

	// Should mention metadata
	if !strings.Contains(cmd.Long, "metadata") {
		t.Error("Long description should mention metadata")
	}

	// Should mention what metadata includes
	if !strings.Contains(cmd.Long, "name") || !strings.Contains(cmd.Long, "description") {
		t.Error("Long description should mention name and description")
	}

	// Should mention tags
	if !strings.Contains(cmd.Long, "tags") {
		t.Error("Long description should mention tags")
	}
}

func TestKeyMetadataGetCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyMetadataGetCommand(getFlags)

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}

	// Should mention key material not exposed
	if !strings.Contains(cmd.Long, "key material") {
		t.Error("Long description should mention key material safety")
	}
}

func TestKeyMetadataUpdateCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyMetadataUpdateCommand(getFlags)

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}

	// Should mention tags format
	if !strings.Contains(cmd.Long, "key=value") {
		t.Error("Long description should mention tag format")
	}

	// Should mention remove tags
	if !strings.Contains(cmd.Long, "remove") {
		t.Error("Long description should mention removing tags")
	}
}

func TestKeyMetadataCommand_InParentCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	parentCmd := NewKeyCommand(getFlags)

	var found bool
	for _, subcmd := range parentCmd.Commands() {
		if subcmd.Name() == "metadata" {
			found = true
			break
		}
	}

	if !found {
		t.Error("metadata subcommand not found in key command")
	}
}

// Error type tests

func TestErrGetKeyMetadataFailed_Error(t *testing.T) {
	innerErr := errors.New("key not found")
	err := ErrGetKeyMetadataFailed{
		KeyID: "missing-key-123",
		Err:   innerErr,
	}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "failed to get metadata") {
		t.Errorf("error message should contain 'failed to get metadata': %s", errMsg)
	}
	if !strings.Contains(errMsg, "missing-key-123") {
		t.Errorf("error message should contain key ID: %s", errMsg)
	}
	if !strings.Contains(errMsg, "key not found") {
		t.Errorf("error message should contain inner error: %s", errMsg)
	}
}

func TestErrUpdateKeyMetadataFailed_Error(t *testing.T) {
	innerErr := errors.New("concurrent modification")
	err := ErrUpdateKeyMetadataFailed{
		KeyID: "locked-key-456",
		Err:   innerErr,
	}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "failed to update metadata") {
		t.Errorf("error message should contain 'failed to update metadata': %s", errMsg)
	}
	if !strings.Contains(errMsg, "locked-key-456") {
		t.Errorf("error message should contain key ID: %s", errMsg)
	}
	if !strings.Contains(errMsg, "concurrent modification") {
		t.Errorf("error message should contain inner error: %s", errMsg)
	}
}

func TestErrInvalidTagFormat_Error(t *testing.T) {
	err := ErrInvalidTagFormat{
		Tag: "invalid-tag-without-equals",
	}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "invalid tag format") {
		t.Errorf("error message should contain 'invalid tag format': %s", errMsg)
	}
	if !strings.Contains(errMsg, "invalid-tag-without-equals") {
		t.Errorf("error message should contain the invalid tag: %s", errMsg)
	}
	if !strings.Contains(errMsg, "key=value") {
		t.Errorf("error message should contain expected format hint: %s", errMsg)
	}
}
