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

func TestNewStartCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newStartCommand(getFlags)

	if cmd == nil {
		t.Fatal("newStartCommand returned nil")
	}

	if cmd.Use != "start <container-id>" {
		t.Errorf("expected Use to be 'start <container-id>', got %q", cmd.Use)
	}

	if cmd.Short != "Start a container" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewStartCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStartCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(cmd.Long) < 50 {
		t.Error("Long description should be descriptive")
	}
}

func TestNewStartCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStartCommand(getFlags)

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

	// Test with multiple args
	err = cmd.Args(cmd, []string{"arg1", "arg2"})
	if err == nil {
		t.Error("expected error when multiple args provided")
	}
}

func TestNewStartCommand_NoFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStartCommand(getFlags)

	// Start command should have minimal flags (only common flags)
	flags := cmd.Flags()
	if flags.NFlag() != 0 {
		t.Errorf("expected 0 local flags, got %d", flags.NFlag())
	}
}

func TestRunStart_EmptyContainerID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	err := runStart(flags, "")
	if err == nil {
		t.Error("expected error for empty container ID")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}
