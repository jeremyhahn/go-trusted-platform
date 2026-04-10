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

package container

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewStopCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newStopCommand(getFlags)

	if cmd == nil {
		t.Fatal("newStopCommand returned nil")
	}

	if cmd.Use != "stop <container-id>" {
		t.Errorf("expected Use to be 'stop <container-id>', got %q", cmd.Use)
	}

	if cmd.Short != "Stop a running container" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewStopCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStopCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewStopCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStopCommand(getFlags)

	// Check timeout flag
	timeoutFlag := cmd.Flags().Lookup("timeout")
	if timeoutFlag == nil {
		t.Error("--timeout flag not found")
	} else {
		if timeoutFlag.Shorthand != "t" {
			t.Errorf("timeout flag shorthand: got %q, want %q", timeoutFlag.Shorthand, "t")
		}
		if timeoutFlag.DefValue != "10" {
			t.Errorf("timeout flag default: got %q, want %q", timeoutFlag.DefValue, "10")
		}
	}
}

func TestNewStopCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStopCommand(getFlags)

	if cmd.Args == nil {
		t.Error("Args should not be nil")
	}

	// Test with no args
	err := cmd.Args(cmd, []string{})
	if err == nil {
		t.Error("expected error when no args provided")
	}

	// Test with one arg
	err = cmd.Args(cmd, []string{"container-id"})
	if err != nil {
		t.Errorf("unexpected error with one arg: %v", err)
	}
}

func TestRunStop_EmptyContainerID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	opts := &stopOptions{timeout: 10}

	err := runStop(flags, "", opts)
	if err == nil {
		t.Error("expected error for empty container ID")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}

func TestStopOptions_Defaults(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStopCommand(getFlags)

	// Get default value
	timeout, err := cmd.Flags().GetUint32("timeout")
	if err != nil {
		t.Fatalf("error getting timeout flag: %v", err)
	}

	if timeout != 10 {
		t.Errorf("expected default timeout 10, got %d", timeout)
	}
}
