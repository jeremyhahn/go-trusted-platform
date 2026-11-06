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

func TestNewStopCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStopCommand(getFlags)

	if cmd == nil {
		t.Fatal("newStopCommand returned nil")
	}

	if cmd.Use != "stop <vm-id>" {
		t.Errorf("expected Use to be 'stop <vm-id>', got %q", cmd.Use)
	}

	if cmd.Short != "Stop a running virtual machine" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewStopCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStopCommand(getFlags)

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

func TestNewStopCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStopCommand(getFlags)

	// force flag
	forceFlag := cmd.Flags().Lookup("force")
	if forceFlag == nil {
		t.Fatal("force flag not found")
	}
	if forceFlag.DefValue != "false" {
		t.Errorf("force flag default: expected 'false', got %q", forceFlag.DefValue)
	}

	// timeout flag with shorthand
	timeoutFlag := cmd.Flags().Lookup("timeout")
	if timeoutFlag == nil {
		t.Fatal("timeout flag not found")
	}
	if timeoutFlag.Shorthand != "t" {
		t.Errorf("timeout flag shorthand: expected 't', got %q", timeoutFlag.Shorthand)
	}
	// 0 leaves the timeout to the daemon, so a bare --force is not refused
	// as a forced stop with a timeout.
	if timeoutFlag.DefValue != "0" {
		t.Errorf("timeout flag default: expected '0', got %q", timeoutFlag.DefValue)
	}
}

func TestRunStop_EmptyVMID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &stopOptions{}

	err := runStop(flags, "", opts)
	if err == nil {
		t.Fatal("expected error for empty VM ID")
	}

	if _, ok := err.(ErrInvalidVMConfig); !ok {
		t.Errorf("expected ErrInvalidVMConfig, got %T: %v", err, err)
	}
}
