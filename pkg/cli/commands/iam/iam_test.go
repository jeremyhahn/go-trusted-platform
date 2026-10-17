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

package iam

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

	if cmd.Use != "iam" {
		t.Errorf("expected Use to be 'iam', got %q", cmd.Use)
	}

	if cmd.Short != "Identity and Access Management operations" {
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

	// Verify it contains key information about IAM functionality
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
		"user",
		"group",
		"role",
		"tenant",
		"policy",
		"permission",
		"app",
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

	// We expect exactly 7 subcommands: user, group, role, tenant, policy, permission, app
	expectedCount := 7
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
			name:          "user",
			expectedShort: "Manage users",
		},
		{
			name:          "group",
			expectedShort: "Manage groups",
		},
		{
			name:          "role",
			expectedShort: "Manage roles",
		},
		{
			name:          "tenant",
			expectedShort: "Manage tenants",
		},
		{
			name:          "policy",
			expectedShort: "Manage authorization policies",
		},
		{
			name:          "permission",
			expectedShort: "Check IAM permissions",
		},
		{
			name:          "app",
			expectedShort: "Manage OAuth applications",
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

	// Verify subcommands are still attached
	if len(cmd.Commands()) != 7 {
		t.Errorf("expected 7 subcommands, got %d", len(cmd.Commands()))
	}
}

func TestNewCommand_CommandConfiguration(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	// The iam command should not have its own RunE
	// It's a parent command that groups subcommands
	if cmd.RunE != nil {
		t.Error("iam root command should not have RunE set (it's a grouping command)")
	}

	// Verify the command can be used as a parent
	if !cmd.HasSubCommands() {
		t.Error("iam command should have subcommands")
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

// User Command Tests

func TestNewUserCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewUserCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewUserCommand returned nil")
	}

	if cmd.Use != "user" {
		t.Errorf("expected Use to be 'user', got %q", cmd.Use)
	}

	if cmd.Short != "Manage users" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewUserCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewUserCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewUserCommand_HasSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewUserCommand(getFlags)

	expectedSubcommands := []string{
		"create",
		"get",
		"list",
		"update",
		"delete",
		"assign-role",
		"revoke-role",
	}

	subcommands := cmd.Commands()

	if len(subcommands) != len(expectedSubcommands) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
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

func TestUserCreateCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewUserCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "create" {
			// Check required flags
			tenantFlag := subcmd.Flags().Lookup("tenant")
			if tenantFlag == nil {
				t.Error("--tenant flag not found")
			}

			emailFlag := subcmd.Flags().Lookup("email")
			if emailFlag == nil {
				t.Error("--email flag not found")
			}

			nameFlag := subcmd.Flags().Lookup("name")
			if nameFlag == nil {
				t.Error("--name flag not found")
			}

			rolesFlag := subcmd.Flags().Lookup("roles")
			if rolesFlag == nil {
				t.Error("--roles flag not found")
			}

			groupsFlag := subcmd.Flags().Lookup("groups")
			if groupsFlag == nil {
				t.Error("--groups flag not found")
			}

			attributesFlag := subcmd.Flags().Lookup("attributes")
			if attributesFlag == nil {
				t.Error("--attributes flag not found")
			}
			return
		}
	}

	t.Fatal("create subcommand not found")
}

func TestUserListCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewUserCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "list" {
			tenantFlag := subcmd.Flags().Lookup("tenant")
			if tenantFlag == nil {
				t.Error("--tenant flag not found")
			}

			pageFlag := subcmd.Flags().Lookup("page")
			if pageFlag == nil {
				t.Error("--page flag not found")
			} else if pageFlag.DefValue != "1" {
				t.Errorf("page default value: got %q, want %q", pageFlag.DefValue, "1")
			}

			pageSizeFlag := subcmd.Flags().Lookup("page-size")
			if pageSizeFlag == nil {
				t.Error("--page-size flag not found")
			} else if pageSizeFlag.DefValue != "50" {
				t.Errorf("page-size default value: got %q, want %q", pageSizeFlag.DefValue, "50")
			}
			return
		}
	}

	t.Fatal("list subcommand not found")
}

func TestUserUpdateCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewUserCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "update" {
			tenantFlag := subcmd.Flags().Lookup("tenant")
			if tenantFlag == nil {
				t.Error("--tenant flag not found")
			}

			userIDFlag := subcmd.Flags().Lookup("user-id")
			if userIDFlag == nil {
				t.Error("--user-id flag not found")
			}

			emailFlag := subcmd.Flags().Lookup("email")
			if emailFlag == nil {
				t.Error("--email flag not found")
			}

			nameFlag := subcmd.Flags().Lookup("name")
			if nameFlag == nil {
				t.Error("--name flag not found")
			}
			return
		}
	}

	t.Fatal("update subcommand not found")
}

func TestUserSubcommands_HaveRunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewUserCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		t.Run(subcmd.Name(), func(t *testing.T) {
			if subcmd.RunE == nil {
				t.Errorf("subcommand %q should have RunE set", subcmd.Name())
			}
		})
	}
}

// Group Command Tests

func TestNewGroupCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewGroupCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewGroupCommand returned nil")
	}

	if cmd.Use != "group" {
		t.Errorf("expected Use to be 'group', got %q", cmd.Use)
	}

	if cmd.Short != "Manage groups" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewGroupCommand_HasSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewGroupCommand(getFlags)

	expectedSubcommands := []string{
		"create",
		"get",
		"list",
		"update",
		"delete",
		"add-member",
		"remove-member",
	}

	subcommands := cmd.Commands()

	if len(subcommands) != len(expectedSubcommands) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
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

func TestGroupCreateCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewGroupCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "create" {
			tenantFlag := subcmd.Flags().Lookup("tenant")
			if tenantFlag == nil {
				t.Error("--tenant flag not found")
			} else if tenantFlag.Shorthand != "t" {
				t.Errorf("tenant flag shorthand: got %q, want %q", tenantFlag.Shorthand, "t")
			}

			nameFlag := subcmd.Flags().Lookup("name")
			if nameFlag == nil {
				t.Error("--name flag not found")
			} else if nameFlag.Shorthand != "n" {
				t.Errorf("name flag shorthand: got %q, want %q", nameFlag.Shorthand, "n")
			}

			descFlag := subcmd.Flags().Lookup("description")
			if descFlag == nil {
				t.Error("--description flag not found")
			} else if descFlag.Shorthand != "d" {
				t.Errorf("description flag shorthand: got %q, want %q", descFlag.Shorthand, "d")
			}
			return
		}
	}

	t.Fatal("create subcommand not found")
}

func TestGroupListCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewGroupCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "list" {
			tenantFlag := subcmd.Flags().Lookup("tenant")
			if tenantFlag == nil {
				t.Error("--tenant flag not found")
			} else if tenantFlag.Shorthand != "t" {
				t.Errorf("tenant flag shorthand: got %q, want %q", tenantFlag.Shorthand, "t")
			}

			pageFlag := subcmd.Flags().Lookup("page")
			if pageFlag == nil {
				t.Error("--page flag not found")
			} else {
				if pageFlag.Shorthand != "p" {
					t.Errorf("page flag shorthand: got %q, want %q", pageFlag.Shorthand, "p")
				}
				if pageFlag.DefValue != "1" {
					t.Errorf("page default value: got %q, want %q", pageFlag.DefValue, "1")
				}
			}

			pageSizeFlag := subcmd.Flags().Lookup("page-size")
			if pageSizeFlag == nil {
				t.Error("--page-size flag not found")
			} else {
				if pageSizeFlag.Shorthand != "s" {
					t.Errorf("page-size flag shorthand: got %q, want %q", pageSizeFlag.Shorthand, "s")
				}
				if pageSizeFlag.DefValue != "50" {
					t.Errorf("page-size default value: got %q, want %q", pageSizeFlag.DefValue, "50")
				}
			}
			return
		}
	}

	t.Fatal("list subcommand not found")
}

func TestGroupSubcommands_HaveRunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewGroupCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		t.Run(subcmd.Name(), func(t *testing.T) {
			if subcmd.RunE == nil {
				t.Errorf("subcommand %q should have RunE set", subcmd.Name())
			}
		})
	}
}

// Role Command Tests

func TestNewRoleCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewRoleCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewRoleCommand returned nil")
	}

	if cmd.Use != "role" {
		t.Errorf("expected Use to be 'role', got %q", cmd.Use)
	}

	if cmd.Short != "Manage roles" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewRoleCommand_HasSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewRoleCommand(getFlags)

	expectedSubcommands := []string{
		"create",
		"get",
		"list",
		"update",
		"delete",
	}

	subcommands := cmd.Commands()

	if len(subcommands) != len(expectedSubcommands) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
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

func TestRoleCreateCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewRoleCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "create" {
			tenantFlag := subcmd.Flags().Lookup("tenant")
			if tenantFlag == nil {
				t.Error("--tenant flag not found")
			} else if tenantFlag.Shorthand != "t" {
				t.Errorf("tenant flag shorthand: got %q, want %q", tenantFlag.Shorthand, "t")
			}

			nameFlag := subcmd.Flags().Lookup("name")
			if nameFlag == nil {
				t.Error("--name flag not found")
			} else if nameFlag.Shorthand != "n" {
				t.Errorf("name flag shorthand: got %q, want %q", nameFlag.Shorthand, "n")
			}

			descFlag := subcmd.Flags().Lookup("description")
			if descFlag == nil {
				t.Error("--description flag not found")
			} else if descFlag.Shorthand != "d" {
				t.Errorf("description flag shorthand: got %q, want %q", descFlag.Shorthand, "d")
			}

			permsFlag := subcmd.Flags().Lookup("permissions")
			if permsFlag == nil {
				t.Error("--permissions flag not found")
			} else if permsFlag.Shorthand != "p" {
				t.Errorf("permissions flag shorthand: got %q, want %q", permsFlag.Shorthand, "p")
			}
			return
		}
	}

	t.Fatal("create subcommand not found")
}

func TestRoleSubcommands_HaveRunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewRoleCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		t.Run(subcmd.Name(), func(t *testing.T) {
			if subcmd.RunE == nil {
				t.Errorf("subcommand %q should have RunE set", subcmd.Name())
			}
		})
	}
}

// Tenant Command Tests

func TestNewTenantCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewTenantCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewTenantCommand returned nil")
	}

	if cmd.Use != "tenant" {
		t.Errorf("expected Use to be 'tenant', got %q", cmd.Use)
	}

	if cmd.Short != "Manage tenants" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewTenantCommand_HasSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewTenantCommand(getFlags)

	expectedSubcommands := []string{
		"create",
		"get",
		"list",
		"update",
		"delete",
	}

	subcommands := cmd.Commands()

	if len(subcommands) != len(expectedSubcommands) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
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

func TestTenantCreateCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewTenantCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "create" {
			idFlag := subcmd.Flags().Lookup("id")
			if idFlag == nil {
				t.Error("--id flag not found")
			}

			nameFlag := subcmd.Flags().Lookup("name")
			if nameFlag == nil {
				t.Error("--name flag not found")
			}

			maxUsersFlag := subcmd.Flags().Lookup("max-users")
			if maxUsersFlag == nil {
				t.Error("--max-users flag not found")
			} else if maxUsersFlag.DefValue != "0" {
				t.Errorf("max-users default value: got %q, want %q", maxUsersFlag.DefValue, "0")
			}

			mfaFlag := subcmd.Flags().Lookup("mfa-required")
			if mfaFlag == nil {
				t.Error("--mfa-required flag not found")
			} else if mfaFlag.DefValue != "false" {
				t.Errorf("mfa-required default value: got %q, want %q", mfaFlag.DefValue, "false")
			}
			return
		}
	}

	t.Fatal("create subcommand not found")
}

func TestTenantListCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewTenantCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "list" {
			pageFlag := subcmd.Flags().Lookup("page")
			if pageFlag == nil {
				t.Error("--page flag not found")
			} else {
				if pageFlag.Shorthand != "p" {
					t.Errorf("page flag shorthand: got %q, want %q", pageFlag.Shorthand, "p")
				}
				if pageFlag.DefValue != "1" {
					t.Errorf("page default value: got %q, want %q", pageFlag.DefValue, "1")
				}
			}

			pageSizeFlag := subcmd.Flags().Lookup("page-size")
			if pageSizeFlag == nil {
				t.Error("--page-size flag not found")
			} else {
				if pageSizeFlag.Shorthand != "s" {
					t.Errorf("page-size flag shorthand: got %q, want %q", pageSizeFlag.Shorthand, "s")
				}
				if pageSizeFlag.DefValue != "50" {
					t.Errorf("page-size default value: got %q, want %q", pageSizeFlag.DefValue, "50")
				}
			}
			return
		}
	}

	t.Fatal("list subcommand not found")
}

func TestTenantSubcommands_HaveRunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewTenantCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		t.Run(subcmd.Name(), func(t *testing.T) {
			if subcmd.RunE == nil {
				t.Errorf("subcommand %q should have RunE set", subcmd.Name())
			}
		})
	}
}

// Policy Command Tests

func TestNewPolicyCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewPolicyCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewPolicyCommand returned nil")
	}

	if cmd.Use != "policy" {
		t.Errorf("expected Use to be 'policy', got %q", cmd.Use)
	}

	if cmd.Short != "Manage authorization policies" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewPolicyCommand_HasSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPolicyCommand(getFlags)

	expectedSubcommands := []string{
		"create",
		"get",
		"list",
		"update",
		"delete",
		"validate",
		"test",
	}

	subcommands := cmd.Commands()

	if len(subcommands) != len(expectedSubcommands) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
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

func TestPolicyCreateCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPolicyCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "create" {
			tenantFlag := subcmd.Flags().Lookup("tenant")
			if tenantFlag == nil {
				t.Error("--tenant flag not found")
			}

			nameFlag := subcmd.Flags().Lookup("name")
			if nameFlag == nil {
				t.Error("--name flag not found")
			}

			descFlag := subcmd.Flags().Lookup("description")
			if descFlag == nil {
				t.Error("--description flag not found")
			}

			priorityFlag := subcmd.Flags().Lookup("priority")
			if priorityFlag == nil {
				t.Error("--priority flag not found")
			} else if priorityFlag.DefValue != "0" {
				t.Errorf("priority default value: got %q, want %q", priorityFlag.DefValue, "0")
			}

			fileFlag := subcmd.Flags().Lookup("file")
			if fileFlag == nil {
				t.Error("--file flag not found")
			}

			labelsFlag := subcmd.Flags().Lookup("labels")
			if labelsFlag == nil {
				t.Error("--labels flag not found")
			}
			return
		}
	}

	t.Fatal("create subcommand not found")
}

func TestPolicyTestCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPolicyCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "test" {
			tenantFlag := subcmd.Flags().Lookup("tenant")
			if tenantFlag == nil {
				t.Error("--tenant flag not found")
			}

			subjectFlag := subcmd.Flags().Lookup("subject")
			if subjectFlag == nil {
				t.Error("--subject flag not found")
			}

			rolesFlag := subcmd.Flags().Lookup("roles")
			if rolesFlag == nil {
				t.Error("--roles flag not found")
			}

			groupsFlag := subcmd.Flags().Lookup("groups")
			if groupsFlag == nil {
				t.Error("--groups flag not found")
			}

			actionFlag := subcmd.Flags().Lookup("action")
			if actionFlag == nil {
				t.Error("--action flag not found")
			}

			resourceFlag := subcmd.Flags().Lookup("resource")
			if resourceFlag == nil {
				t.Error("--resource flag not found")
			}

			contextFlag := subcmd.Flags().Lookup("context")
			if contextFlag == nil {
				t.Error("--context flag not found")
			}
			return
		}
	}

	t.Fatal("test subcommand not found")
}

func TestPolicySubcommands_HaveRunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewPolicyCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		t.Run(subcmd.Name(), func(t *testing.T) {
			if subcmd.RunE == nil {
				t.Errorf("subcommand %q should have RunE set", subcmd.Name())
			}
		})
	}
}

// App Command Tests

func TestNewAppCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewAppCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewAppCommand returned nil")
	}

	if cmd.Use != "app" {
		t.Errorf("expected Use to be 'app', got %q", cmd.Use)
	}

	if cmd.Short != "Manage OAuth applications" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewAppCommand_HasSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewAppCommand(getFlags)

	expectedSubcommands := []string{
		"register",
		"get",
		"list",
		"update",
		"delete",
		"rotate-secret",
	}

	subcommands := cmd.Commands()

	if len(subcommands) != len(expectedSubcommands) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
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

func TestAppRegisterCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewAppCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "register" {
			tenantFlag := subcmd.Flags().Lookup("tenant")
			if tenantFlag == nil {
				t.Error("--tenant flag not found")
			}

			nameFlag := subcmd.Flags().Lookup("name")
			if nameFlag == nil {
				t.Error("--name flag not found")
			}

			redirectFlag := subcmd.Flags().Lookup("redirect-uris")
			if redirectFlag == nil {
				t.Error("--redirect-uris flag not found")
			}

			grantFlag := subcmd.Flags().Lookup("grant-types")
			if grantFlag == nil {
				t.Error("--grant-types flag not found")
			} else if grantFlag.DefValue != "authorization_code" {
				t.Errorf("grant-types default value: got %q, want %q", grantFlag.DefValue, "authorization_code")
			}

			responseFlag := subcmd.Flags().Lookup("response-types")
			if responseFlag == nil {
				t.Error("--response-types flag not found")
			} else if responseFlag.DefValue != "code" {
				t.Errorf("response-types default value: got %q, want %q", responseFlag.DefValue, "code")
			}

			prefixFlag := subcmd.Flags().Lookup("resource-prefix")
			if prefixFlag == nil {
				t.Error("--resource-prefix flag not found")
			}
			return
		}
	}

	t.Fatal("register subcommand not found")
}

func TestAppListCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewAppCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "list" {
			tenantFlag := subcmd.Flags().Lookup("tenant")
			if tenantFlag == nil {
				t.Error("--tenant flag not found")
			}

			pageFlag := subcmd.Flags().Lookup("page")
			if pageFlag == nil {
				t.Error("--page flag not found")
			} else if pageFlag.DefValue != "1" {
				t.Errorf("page default value: got %q, want %q", pageFlag.DefValue, "1")
			}

			pageSizeFlag := subcmd.Flags().Lookup("page-size")
			if pageSizeFlag == nil {
				t.Error("--page-size flag not found")
			} else if pageSizeFlag.DefValue != "50" {
				t.Errorf("page-size default value: got %q, want %q", pageSizeFlag.DefValue, "50")
			}
			return
		}
	}

	t.Fatal("list subcommand not found")
}

func TestAppUpdateCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewAppCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "update" {
			tenantFlag := subcmd.Flags().Lookup("tenant")
			if tenantFlag == nil {
				t.Error("--tenant flag not found")
			}

			clientIDFlag := subcmd.Flags().Lookup("client-id")
			if clientIDFlag == nil {
				t.Error("--client-id flag not found")
			}

			nameFlag := subcmd.Flags().Lookup("name")
			if nameFlag == nil {
				t.Error("--name flag not found")
			}

			redirectFlag := subcmd.Flags().Lookup("redirect-uris")
			if redirectFlag == nil {
				t.Error("--redirect-uris flag not found")
			}

			grantFlag := subcmd.Flags().Lookup("grant-types")
			if grantFlag == nil {
				t.Error("--grant-types flag not found")
			}

			responseFlag := subcmd.Flags().Lookup("response-types")
			if responseFlag == nil {
				t.Error("--response-types flag not found")
			}

			prefixFlag := subcmd.Flags().Lookup("resource-prefix")
			if prefixFlag == nil {
				t.Error("--resource-prefix flag not found")
			}
			return
		}
	}

	t.Fatal("update subcommand not found")
}

func TestAppSubcommands_HaveRunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewAppCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		t.Run(subcmd.Name(), func(t *testing.T) {
			if subcmd.RunE == nil {
				t.Errorf("subcommand %q should have RunE set", subcmd.Name())
			}
		})
	}
}

// All Subcommands Have Long Descriptions Tests

func TestAllSubcommands_HaveLongDescriptions(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	// Test top-level commands (user, group, role, etc.)
	cmd := NewCommand(getFlags)
	for _, subcmd := range cmd.Commands() {
		t.Run(subcmd.Name(), func(t *testing.T) {
			if subcmd.Long == "" {
				t.Errorf("command %q should have a Long description", subcmd.Name())
			}
		})
	}
}
