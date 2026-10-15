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

package compute

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

	if cmd.Use != "compute" {
		t.Errorf("expected Use to be 'compute', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Short description should not be empty")
	}
}

func TestNewCommand_Subcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	expectedSubcommands := []string{
		"create",
		"start",
		"stop",
		"reboot",
		"suspend",
		"resume",
		"delete",
		"get",
		"list",
		"migrate",
	}

	subcommands := cmd.Commands()

	if len(subcommands) != len(expectedSubcommands) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
		for _, subcmd := range subcommands {
			t.Logf("  found subcommand: %s", subcmd.Name())
		}
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

func TestNewCommand_IsGroupingCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	if cmd.RunE != nil {
		t.Error("compute root command should not have RunE set (it's a grouping command)")
	}

	if !cmd.HasSubCommands() {
		t.Error("compute command should have subcommands")
	}
}

func TestNewCommand_GetFlagsNotCalledDuringCreation(t *testing.T) {
	callCount := 0
	getFlags := func() *cli.CommonFlags {
		callCount++
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
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

func TestNewCommand_SubcommandDetails(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	tests := []struct {
		name          string
		expectedShort string
	}{
		{name: "create", expectedShort: "Create a new virtual machine"},
		{name: "start", expectedShort: "Start a virtual machine"},
		{name: "stop", expectedShort: "Stop a running virtual machine"},
		{name: "reboot", expectedShort: "Reboot a virtual machine"},
		{name: "suspend", expectedShort: "Suspend a running virtual machine"},
		{name: "resume", expectedShort: "Resume a suspended virtual machine"},
		{name: "delete", expectedShort: "Delete a virtual machine"},
		{name: "get", expectedShort: "Get virtual machine details"},
		{name: "list", expectedShort: "List virtual machines"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var found bool
			for _, subcmd := range cmd.Commands() {
				if subcmd.Name() == tt.name {
					found = true
					if subcmd.Short != tt.expectedShort {
						t.Errorf("subcommand %q: expected Short %q, got %q",
							tt.name, tt.expectedShort, subcmd.Short)
					}
					break
				}
			}
			if !found {
				t.Fatalf("subcommand %q not found", tt.name)
			}
		})
	}
}
