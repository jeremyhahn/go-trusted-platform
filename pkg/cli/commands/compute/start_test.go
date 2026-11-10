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

func TestNewStartCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStartCommand(getFlags)

	if cmd == nil {
		t.Fatal("newStartCommand returned nil")
	}

	if cmd.Use != "start <vm-id>" {
		t.Errorf("expected Use to be 'start <vm-id>', got %q", cmd.Use)
	}

	if cmd.Short != "Start a virtual machine" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewStartCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newStartCommand(getFlags)

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

func TestNewStartCommand_NoLocalFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStartCommand(getFlags)

	// Start command has no local flags (only inherits persistent flags)
	if cmd.HasLocalFlags() {
		t.Error("start command should not have local flags")
	}
}

func TestRunStart_EmptyVMID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	err := runStart(flags, "")
	if err == nil {
		t.Fatal("expected error for empty VM ID")
	}

	if _, ok := err.(ErrInvalidVMConfig); !ok {
		t.Errorf("expected ErrInvalidVMConfig, got %T: %v", err, err)
	}
}
