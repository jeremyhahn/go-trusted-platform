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

package kms

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewSecretsVersionsCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newSecretsVersionsCommand(getFlags)

	if cmd == nil {
		t.Fatal("newSecretsVersionsCommand returned nil")
	}

	if cmd.Use != "versions <name>" {
		t.Errorf("expected Use to be 'versions <name>', got %q", cmd.Use)
	}

	if cmd.Short != "List the versions of a secret" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestSecretsVersionsCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newSecretsVersionsCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestSecretsVersionsCommand_HasRunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newSecretsVersionsCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestSecretsVersionsCommand_RequiresExactArgs(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newSecretsVersionsCommand(getFlags)

	if cmd.Args == nil {
		t.Error("Args validation should be set")
	}
}

func TestSecretsVersionsCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newSecretsVersionsCommand(getFlags)

	limitFlag := cmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Error("--limit flag not found")
	} else if limitFlag.DefValue != "100" {
		t.Errorf("limit flag default: got %q, want %q", limitFlag.DefValue, "100")
	}

	// The SDK returns every version at once, so there is no cursor.
	if cmd.Flags().Lookup("cursor") != nil {
		t.Error("--cursor flag should not exist")
	}
}

func TestSecretsVersionsCommand_InSecretsCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewSecretsCommand(getFlags)

	found := false
	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "versions" {
			found = true
			break
		}
	}

	if !found {
		t.Error("versions subcommand not found in secrets command")
	}
}
