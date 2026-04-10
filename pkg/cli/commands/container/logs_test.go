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

func TestNewLogsCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newLogsCommand(getFlags)

	if cmd == nil {
		t.Fatal("newLogsCommand returned nil")
	}

	if cmd.Use != "logs <container-id>" {
		t.Errorf("expected Use to be 'logs <container-id>', got %q", cmd.Use)
	}

	if cmd.Short != "Get container logs" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewLogsCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newLogsCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewLogsCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newLogsCommand(getFlags)

	tests := []struct {
		name      string
		shorthand string
		defValue  string
	}{
		{"follow", "f", "false"},
		{"tail", "n", "0"},
		{"timestamps", "t", "false"},
		{"stdout", "", "true"},
		{"stderr", "", "true"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.name)
			if flag == nil {
				t.Errorf("--%s flag not found", tt.name)
				return
			}

			if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
				t.Errorf("--%s flag shorthand: got %q, want %q", tt.name, flag.Shorthand, tt.shorthand)
			}

			if flag.DefValue != tt.defValue {
				t.Errorf("--%s flag default: got %q, want %q", tt.name, flag.DefValue, tt.defValue)
			}
		})
	}
}

func TestNewLogsCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newLogsCommand(getFlags)

	if cmd.Args == nil {
		t.Error("Args should not be nil")
	}

	err := cmd.Args(cmd, []string{})
	if err == nil {
		t.Error("expected error when no args provided")
	}

	err = cmd.Args(cmd, []string{"container-id"})
	if err != nil {
		t.Errorf("unexpected error with one arg: %v", err)
	}
}

func TestRunLogs_EmptyContainerID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	opts := &logsOptions{follow: false, tail: 0, timestamps: false, stdout: true, stderr: true}

	err := runLogs(flags, "", opts)
	if err == nil {
		t.Error("expected error for empty container ID")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}

func TestLogsOptions_Defaults(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newLogsCommand(getFlags)

	follow, err := cmd.Flags().GetBool("follow")
	if err != nil {
		t.Fatalf("error getting follow flag: %v", err)
	}
	if follow {
		t.Error("expected default follow to be false")
	}

	tail, err := cmd.Flags().GetUint32("tail")
	if err != nil {
		t.Fatalf("error getting tail flag: %v", err)
	}
	if tail != 0 {
		t.Errorf("expected default tail to be 0, got %d", tail)
	}

	timestamps, err := cmd.Flags().GetBool("timestamps")
	if err != nil {
		t.Fatalf("error getting timestamps flag: %v", err)
	}
	if timestamps {
		t.Error("expected default timestamps to be false")
	}

	stdout, err := cmd.Flags().GetBool("stdout")
	if err != nil {
		t.Fatalf("error getting stdout flag: %v", err)
	}
	if !stdout {
		t.Error("expected default stdout to be true")
	}

	stderr, err := cmd.Flags().GetBool("stderr")
	if err != nil {
		t.Fatalf("error getting stderr flag: %v", err)
	}
	if !stderr {
		t.Error("expected default stderr to be true")
	}
}
