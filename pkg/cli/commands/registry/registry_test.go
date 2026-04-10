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

package registry

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

	if cmd.Use != "registry" {
		t.Errorf("expected Use to be 'registry', got %q", cmd.Use)
	}

	if cmd.Short != "Trusted Registry operations" {
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
		"push",
		"pull",
		"list",
		"delete",
		"inspect",
		"status",
	}

	subcommands := cmd.Commands()

	if len(subcommands) < len(expectedSubcommands) {
		t.Errorf("expected at least %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
	}

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

	expectedCount := 6
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
			name:          "push",
			expectedShort: "Push an image to the registry",
		},
		{
			name:          "pull",
			expectedShort: "Pull an image from the registry",
		},
		{
			name:          "list",
			expectedShort: "List images in the registry",
		},
		{
			name:          "delete",
			expectedShort: "Delete an image from the registry",
		},
		{
			name:          "inspect",
			expectedShort: "Inspect an image manifest",
		},
		{
			name:          "status",
			expectedShort: "Show registry status",
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
	getFlags := func() *cli.CommonFlags {
		return nil
	}

	cmd := NewCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewCommand should create command even with nil-returning getFlags")
	}

	if len(cmd.Commands()) != 6 {
		t.Errorf("expected 6 subcommands, got %d", len(cmd.Commands()))
	}
}

func TestNewCommand_CommandConfiguration(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	if cmd.RunE != nil {
		t.Error("registry root command should not have RunE set (it's a grouping command)")
	}

	if !cmd.HasSubCommands() {
		t.Error("registry command should have subcommands")
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

	if callCount != 0 {
		t.Errorf("getFlags should not be called during command creation, but was called %d times", callCount)
	}

	if cmd == nil {
		t.Fatal("command should be created successfully")
	}
}

func TestNewCommand_SubcommandAliases(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	aliasTests := []struct {
		name            string
		expectedAliases []string
	}{
		{name: "delete", expectedAliases: []string{"rm", "remove"}},
		{name: "inspect", expectedAliases: []string{"describe", "show"}},
		{name: "status", expectedAliases: []string{"health", "info"}},
	}

	for _, tt := range aliasTests {
		t.Run(tt.name, func(t *testing.T) {
			for _, subcmd := range cmd.Commands() {
				if subcmd.Name() == tt.name {
					if len(subcmd.Aliases) != len(tt.expectedAliases) {
						t.Errorf("expected %d aliases for %s, got %d",
							len(tt.expectedAliases), tt.name, len(subcmd.Aliases))
						return
					}
					for i, alias := range tt.expectedAliases {
						if subcmd.Aliases[i] != alias {
							t.Errorf("expected alias %q at index %d for %s, got %q",
								alias, i, tt.name, subcmd.Aliases[i])
						}
					}
					return
				}
			}
			t.Errorf("subcommand %q not found", tt.name)
		})
	}
}
