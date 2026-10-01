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

package tenant

import (
	"testing"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// testGetFlags returns test flags for testing
func testGetFlags() *cli.CommonFlags {
	return &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}
}

func TestNewCommand(t *testing.T) {
	cmd := NewCommand(testGetFlags)

	if cmd == nil {
		t.Fatal("NewCommand returned nil")
	}

	if cmd.Use != "tenant" {
		t.Errorf("expected Use 'tenant', got %s", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("command should have a short description")
	}

	if cmd.Long == "" {
		t.Error("command should have a long description")
	}

	// Check that all subcommands are added
	expectedSubcommands := []string{
		"list", "show", "create", "delete",
		"suspend", "resume", "quotas", "usage",
	}

	for _, expected := range expectedSubcommands {
		found := false
		for _, sub := range cmd.Commands() {
			if sub.Use == expected || (len(sub.Use) > len(expected) && sub.Use[:len(expected)+1] == expected+" ") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand %s not found", expected)
		}
	}

	// The vlan and bridge subcommands were retired with the per-tenant VLAN
	// range and OVS bridge (#708).
	for _, sub := range cmd.Commands() {
		if name := sub.Name(); name == "vlan" || name == "bridge" {
			t.Errorf("retired subcommand %q is still registered", name)
		}
	}
}

func TestNewListCommand(t *testing.T) {
	cmd := NewListCommand(testGetFlags)

	if cmd == nil {
		t.Fatal("NewListCommand returned nil")
	}

	if cmd.Use != "list" {
		t.Errorf("expected Use 'list', got %s", cmd.Use)
	}

	// Check flags
	limit := cmd.Flag("limit")
	if limit == nil {
		t.Error("expected limit flag")
	}

	offset := cmd.Flag("offset")
	if offset == nil {
		t.Error("expected offset flag")
	}
}

func TestNewShowCommand(t *testing.T) {
	cmd := NewShowCommand(testGetFlags)

	if cmd == nil {
		t.Fatal("NewShowCommand returned nil")
	}

	if cmd.Use != "show <tenant-name>" {
		t.Errorf("expected Use 'show <tenant-name>', got %s", cmd.Use)
	}

	// Check args validation
	if cmd.Args == nil {
		t.Error("expected Args validation function")
	}
}

func TestNewCreateCommand(t *testing.T) {
	cmd := NewCreateCommand(testGetFlags)

	if cmd == nil {
		t.Fatal("NewCreateCommand returned nil")
	}

	if cmd.Use != "create" {
		t.Errorf("expected Use 'create', got %s", cmd.Use)
	}

	// Check required flags
	expectedFlags := []string{
		"name", "display-name",
		"max-vms", "max-containers", "max-vcpus", "max-memory-gb",
		"max-bridges", "max-ports", "max-bandwidth-mbps",
		"max-volumes-gb", "max-snapshots",
	}

	for _, flagName := range expectedFlags {
		if cmd.Flag(flagName) == nil {
			t.Errorf("expected flag %s not found", flagName)
		}
	}

	// The VLAN range flags were retired (#708).
	for _, flagName := range []string{"vlan-start", "vlan-end"} {
		if cmd.Flag(flagName) != nil {
			t.Errorf("retired flag %s is still defined", flagName)
		}
	}
}

func TestNewDeleteCommand(t *testing.T) {
	cmd := NewDeleteCommand(testGetFlags)

	if cmd == nil {
		t.Fatal("NewDeleteCommand returned nil")
	}

	if cmd.Use != "delete <tenant-name>" {
		t.Errorf("expected Use 'delete <tenant-name>', got %s", cmd.Use)
	}

	// Check force flag
	force := cmd.Flag("force")
	if force == nil {
		t.Error("expected force flag")
	}
}

func TestNewSuspendCommand(t *testing.T) {
	cmd := NewSuspendCommand(testGetFlags)

	if cmd == nil {
		t.Fatal("NewSuspendCommand returned nil")
	}

	if cmd.Use != "suspend <tenant-name>" {
		t.Errorf("expected Use 'suspend <tenant-name>', got %s", cmd.Use)
	}
}

func TestNewResumeCommand(t *testing.T) {
	cmd := NewResumeCommand(testGetFlags)

	if cmd == nil {
		t.Fatal("NewResumeCommand returned nil")
	}

	if cmd.Use != "resume <tenant-name>" {
		t.Errorf("expected Use 'resume <tenant-name>', got %s", cmd.Use)
	}
}

func TestNewQuotasCommand(t *testing.T) {
	cmd := NewQuotasCommand(testGetFlags)

	if cmd == nil {
		t.Fatal("NewQuotasCommand returned nil")
	}

	if cmd.Use != "quotas" {
		t.Errorf("expected Use 'quotas', got %s", cmd.Use)
	}

	// Check subcommands
	hasGet := false
	hasSet := false
	for _, sub := range cmd.Commands() {
		if sub.Use == "get <tenant-name>" {
			hasGet = true
		}
		if sub.Use == "set <tenant-name>" {
			hasSet = true
		}
	}

	if !hasGet {
		t.Error("expected 'get' subcommand")
	}
	if !hasSet {
		t.Error("expected 'set' subcommand")
	}
}

func TestNewUsageCommand(t *testing.T) {
	cmd := NewUsageCommand(testGetFlags)

	if cmd == nil {
		t.Fatal("NewUsageCommand returned nil")
	}

	if cmd.Use != "usage <tenant-name>" {
		t.Errorf("expected Use 'usage <tenant-name>', got %s", cmd.Use)
	}
}

// TestCommandHierarchy validates the command structure
func TestCommandHierarchy(t *testing.T) {
	root := NewCommand(testGetFlags)

	// Test that root command has no RunE (should only be container)
	if root.RunE != nil {
		t.Error("root command should not have RunE, only subcommands")
	}

	// Test each subcommand has proper configuration
	for _, sub := range root.Commands() {
		if sub.Use == "" {
			t.Error("subcommand has empty Use")
		}
		if sub.Short == "" {
			t.Errorf("subcommand %s has empty Short description", sub.Use)
		}

		// Subcommand containers (quotas + barrier) bundle further subcommands
		// instead of running their own RunE.
		if sub.Use == "quotas" || sub.Use == "barrier" {
			if len(sub.Commands()) == 0 {
				t.Errorf("%s command should have subcommands", sub.Use)
			}
		} else {
			// Other subcommands should have RunE
			if sub.RunE == nil {
				t.Errorf("subcommand %s should have RunE", sub.Use)
			}
		}
	}
}

// TestSubcommandAliases verifies no unintended command collisions
func TestSubcommandAliases(t *testing.T) {
	root := NewCommand(testGetFlags)

	seen := make(map[string]bool)
	for _, sub := range root.Commands() {
		name := sub.Name()
		if seen[name] {
			t.Errorf("duplicate command name: %s", name)
		}
		seen[name] = true
	}
}

// validateCommandHasHelp checks that a command and its subcommands have help
func validateCommandHasHelp(t *testing.T, cmd *cobra.Command) {
	// Check command has help text
	if cmd.Long == "" && cmd.Short == "" {
		t.Errorf("command %s has no help text", cmd.Use)
	}

	// Recursively check subcommands
	for _, sub := range cmd.Commands() {
		validateCommandHasHelp(t, sub)
	}
}

func TestAllCommandsHaveHelp(t *testing.T) {
	root := NewCommand(testGetFlags)
	validateCommandHasHelp(t, root)
}

// TestTruncateID tests the truncateID helper function
