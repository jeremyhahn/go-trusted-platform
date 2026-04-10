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

func TestNewKeyBackendTestCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyBackendTestCommand(getFlags)

	if cmd.Use != "backend-test" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Test KMS backend functionality (not yet implemented)" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestErrBackendTestFailed_Error(t *testing.T) {
	err := ErrBackendTestFailed{Err: ErrInvalidKeyAlgorithm{Algorithm: "test"}}
	errStr := err.Error()

	if !strings.Contains(errStr, "backend test failed") {
		t.Errorf("error message %q should contain 'backend test failed'", errStr)
	}
}

func TestKeyBackendTestCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyBackendTestCommand(getFlags)

	// Should mention seal/unseal test
	if !strings.Contains(cmd.Long, "seal") && !strings.Contains(cmd.Long, "unseal") {
		t.Error("Long description should mention seal/unseal test")
	}

	// Should mention backend
	if !strings.Contains(cmd.Long, "backend") {
		t.Error("Long description should mention backend")
	}

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}

	// Should mention configuration changes or diagnostics
	if !strings.Contains(cmd.Long, "configuration") && !strings.Contains(cmd.Long, "diagnose") {
		t.Error("Long description should mention use cases")
	}
}

func TestKeyBackendTestCommand_InParentCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	parentCmd := NewKeyCommand(getFlags)

	var found bool
	for _, subcmd := range parentCmd.Commands() {
		if subcmd.Name() == "backend-test" {
			found = true
			break
		}
	}

	if !found {
		t.Error("backend-test subcommand not found in key command")
	}
}

func TestKeyBackendTestCommand_NoArgs(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyBackendTestCommand(getFlags)

	// backend-test should not require any arguments
	if cmd.Args != nil {
		t.Error("backend-test should not require positional arguments")
	}
}
