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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewKeyRevokeCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyRevokeCommand(getFlags)

	if cmd.Use != "revoke <key-id>" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Revoke a key" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.Args == nil {
		t.Error("Args should be set")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewKeyRevokeCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyRevokeCommand(getFlags)

	flag := cmd.Flags().Lookup("reason")
	if flag == nil {
		t.Fatal("--reason flag not found")
	}

	if flag.Shorthand != "r" {
		t.Errorf("reason flag shorthand: got %q, want %q", flag.Shorthand, "r")
	}

	if flag.DefValue != "" {
		t.Errorf("reason flag default: got %q, want empty", flag.DefValue)
	}
}

func TestKeyRevokeCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyRevokeCommand(getFlags)

	// Should mention revocation
	if !strings.Contains(cmd.Long, "Revoke") {
		t.Error("Long description should mention revoke")
	}

	// Should mention compromised
	if !strings.Contains(cmd.Long, "compromised") {
		t.Error("Long description should mention compromised")
	}

	// Should mention reason required
	if !strings.Contains(cmd.Long, "reason") {
		t.Error("Long description should mention reason")
	}

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}
}

func TestKeyRevokeCommand_InParentCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	parentCmd := NewKeyCommand(getFlags)

	var found bool
	for _, subcmd := range parentCmd.Commands() {
		if subcmd.Name() == "revoke" {
			found = true
			break
		}
	}

	if !found {
		t.Error("revoke subcommand not found in key command")
	}
}

func TestKeyRevokeCommand_ReasonRequired(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyRevokeCommand(getFlags)

	flag := cmd.Flags().Lookup("reason")
	if flag == nil {
		t.Fatal("reason flag not found")
	}

	// Reason should have empty default (required)
	if flag.DefValue != "" {
		t.Error("reason flag should have empty default (required)")
	}
}
