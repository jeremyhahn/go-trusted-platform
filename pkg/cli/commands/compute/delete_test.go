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

func TestNewDeleteCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newDeleteCommand(getFlags)

	if cmd == nil {
		t.Fatal("newDeleteCommand returned nil")
	}

	if cmd.Use != "delete <vm-id>" {
		t.Errorf("expected Use to be 'delete <vm-id>', got %q", cmd.Use)
	}

	if cmd.Short != "Delete a virtual machine" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}

	// Verify aliases
	expectedAliases := []string{"rm", "remove"}
	if len(cmd.Aliases) != len(expectedAliases) {
		t.Fatalf("expected %d aliases, got %d", len(expectedAliases), len(cmd.Aliases))
	}
	for i, alias := range expectedAliases {
		if cmd.Aliases[i] != alias {
			t.Errorf("expected alias[%d] to be %q, got %q", i, alias, cmd.Aliases[i])
		}
	}
}

func TestNewDeleteCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newDeleteCommand(getFlags)

	tests := []struct {
		name      string
		args      []string
		expectErr bool
	}{
		{name: "zero_args", args: []string{}, expectErr: true},
		{name: "one_arg", args: []string{"my-vm"}, expectErr: false},
		{name: "two_args", args: []string{"my-vm", "extra"}, expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmd.Args(cmd, tt.args)
			if tt.expectErr && err == nil {
				t.Error("expected error for invalid args count")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewDeleteCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newDeleteCommand(getFlags)

	// force flag with shorthand
	forceFlag := cmd.Flags().Lookup("force")
	if forceFlag == nil {
		t.Fatal("force flag not found")
	}
	if forceFlag.Shorthand != "f" {
		t.Errorf("force flag shorthand: expected 'f', got %q", forceFlag.Shorthand)
	}
	if forceFlag.DefValue != "false" {
		t.Errorf("force flag default: expected 'false', got %q", forceFlag.DefValue)
	}

	// delete-disks flag
	deleteDisksFlag := cmd.Flags().Lookup("delete-disks")
	if deleteDisksFlag == nil {
		t.Fatal("delete-disks flag not found")
	}
	if deleteDisksFlag.DefValue != "false" {
		t.Errorf("delete-disks flag default: expected 'false', got %q", deleteDisksFlag.DefValue)
	}
}

func TestRunDelete_EmptyVMID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &deleteOptions{}

	err := runDelete(flags, "", opts)
	if err == nil {
		t.Fatal("expected error for empty VM ID")
	}

	if _, ok := err.(ErrInvalidVMConfig); !ok {
		t.Errorf("expected ErrInvalidVMConfig, got %T: %v", err, err)
	}
}
