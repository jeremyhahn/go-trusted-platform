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

func TestNewCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewCommand returned nil")
	}

	if cmd.Use != "kms" {
		t.Errorf("expected Use to be 'kms', got %q", cmd.Use)
	}

	if cmd.Short != "Key Management System operations" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	// Verify it contains key information about KMS functionality
	if len(cmd.Long) < 100 {
		t.Error("Long description should be descriptive (at least 100 chars)")
	}
}

func TestNewCommand_HasAllSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	expectedSubcommands := []string{
		"key",
		"dek",
		"secrets",
		"status",
		"crypto",
	}

	subcommands := cmd.Commands()

	// Verify we have at least the expected number of subcommands
	if len(subcommands) < len(expectedSubcommands) {
		t.Errorf("expected at least %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
	}

	// Verify each expected subcommand exists
	for _, expected := range expectedSubcommands {
		found := false
		for _, subcmd := range subcommands {
			if subcmd.Name() == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand %q not found", expected)
		}
	}
}

func TestNewCommand_SubcommandCount(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)
	subcommands := cmd.Commands()

	// We expect exactly 5 subcommands: key, dek, secrets, status, crypto
	expectedCount := 5
	if len(subcommands) != expectedCount {
		t.Errorf("expected exactly %d subcommands, got %d", expectedCount, len(subcommands))
		for _, subcmd := range subcommands {
			t.Logf("  found subcommand: %s", subcmd.Name())
		}
	}
}

func TestNewCommand_SubcommandDetails(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	tests := []struct {
		name          string
		expectedShort string
	}{
		{
			name:          "key",
			expectedShort: "Manage cryptographic keys",
		},
		{
			name:          "dek",
			expectedShort: "Data Encryption Key operations (not yet implemented)",
		},
		{
			name:          "secrets",
			expectedShort: "Secrets management operations",
		},
		{
			name:          "status",
			expectedShort: "Show KMS backend status",
		},
		{
			name:          "crypto",
			expectedShort: "Cryptographic operations",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var foundCmd *struct {
				Short string
			}

			for _, subcmd := range cmd.Commands() {
				if subcmd.Name() == tt.name {
					foundCmd = &struct{ Short string }{Short: subcmd.Short}
					break
				}
			}

			if foundCmd == nil {
				t.Fatalf("subcommand %q not found", tt.name)
			}

			if foundCmd.Short != tt.expectedShort {
				t.Errorf("subcommand %q: expected Short %q, got %q",
					tt.name, tt.expectedShort, foundCmd.Short)
			}
		})
	}
}

func TestNewCommand_NilGetFlagsHandling(t *testing.T) {
	// The command should be created even with a getFlags that returns nil
	// (the RunE functions may fail later, but creation should succeed)
	getFlags := func() *cli.CommonFlags {
		return nil
	}

	cmd := NewCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewCommand should create command even with nil-returning getFlags")
	}

	// Verify subcommands are still attached (key, dek, secrets, status, crypto)
	if len(cmd.Commands()) != 5 {
		t.Errorf("expected 5 subcommands, got %d", len(cmd.Commands()))
	}
}

func TestNewCommand_CommandConfiguration(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	// The kms command should not have its own RunE
	// It's a parent command that groups subcommands
	if cmd.RunE != nil {
		t.Error("kms root command should not have RunE set (it's a grouping command)")
	}

	// Verify the command can be used as a parent
	if !cmd.HasSubCommands() {
		t.Error("kms command should have subcommands")
	}
}

func TestNewCommand_FlagsFunction(t *testing.T) {
	callCount := 0
	getFlags := func() *cli.CommonFlags {
		callCount++
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
			Verbose:      true,
		}
	}

	cmd := NewCommand(getFlags)

	// Creating the command should not call getFlags
	// getFlags should only be called when RunE is executed
	if callCount != 0 {
		t.Errorf("getFlags should not be called during command creation, but was called %d times", callCount)
	}

	// The command should store the getFlags function for later use
	if cmd == nil {
		t.Fatal("command should be created successfully")
	}
}
