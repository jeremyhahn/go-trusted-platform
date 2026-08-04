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
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewKeyPolicyCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyPolicyCommand(getFlags)

	if cmd.Use != "policy" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Manage key access policies" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewKeyPolicyCommand_Subcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyPolicyCommand(getFlags)

	expectedSubcommands := []string{"get", "set"}
	actualSubcommands := make(map[string]bool)

	for _, subcmd := range cmd.Commands() {
		actualSubcommands[subcmd.Name()] = true
	}

	for _, expected := range expectedSubcommands {
		if !actualSubcommands[expected] {
			t.Errorf("missing subcommand: %s", expected)
		}
	}
}

func TestNewKeyPolicyGetCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyPolicyGetCommand(getFlags)

	if cmd.Use != "get <key-id>" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Get key access policy" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Args == nil {
		t.Error("Args should be set")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewKeyPolicySetCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyPolicySetCommand(getFlags)

	if cmd.Use != "set <key-id>" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Set key access policy" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Args == nil {
		t.Error("Args should be set")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewKeyPolicySetCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyPolicySetCommand(getFlags)

	expectedFlags := []string{
		"operation",
		"allow-principal",
		"deny-principal",
		"expires-in",
		"rotation-required",
		"max-usage",
		"require-mfa",
	}

	for _, flagName := range expectedFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %q not found", flagName)
		}
	}
}

func TestParseDuration_NegativeDurations(t *testing.T) {
	negativeDurations := []string{
		"-1d",
		"-1h",
		"-30m",
	}

	for _, input := range negativeDurations {
		t.Run(input, func(t *testing.T) {
			_, err := parseDuration(input)
			if err == nil {
				t.Errorf("expected error for negative duration %q", input)
			}
		})
	}
}

func TestParseDuration_ZeroDuration(t *testing.T) {
	zeroDurations := []string{
		"0d",
		"0h",
		"0m",
		"0s",
	}

	for _, input := range zeroDurations {
		t.Run(input, func(t *testing.T) {
			result, err := parseDuration(input)
			if err != nil {
				t.Errorf("unexpected error for zero duration %q: %v", input, err)
			}
			if result != 0 {
				t.Errorf("expected 0 for %q, got %v", input, result)
			}
		})
	}
}

func TestParseDuration_UnsupportedUnits(t *testing.T) {
	unsupportedDurations := []string{
		"1w",  // weeks not supported
		"2w",  // weeks not supported
		"1y",  // years not supported
		"1mo", // months not supported
	}

	for _, input := range unsupportedDurations {
		t.Run(input, func(t *testing.T) {
			_, err := parseDuration(input)
			if err == nil {
				t.Errorf("expected error for unsupported duration %q", input)
			}
		})
	}
}

func TestKeyPolicyCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyPolicyCommand(getFlags)

	// Should mention access control
	if !strings.Contains(cmd.Long, "access") {
		t.Error("Long description should mention access control")
	}

	// Should mention principals
	if !strings.Contains(cmd.Long, "principal") {
		t.Error("Long description should mention principals")
	}
}

func TestKeyPolicyGetCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyPolicyGetCommand(getFlags)

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}
}

func TestKeyPolicySetCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyPolicySetCommand(getFlags)

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}

	// Should mention operations
	if !strings.Contains(cmd.Long, "operation") {
		t.Error("Long description should mention operations")
	}

	// Should mention principals
	if !strings.Contains(cmd.Long, "principal") {
		t.Error("Long description should mention principals")
	}

	// Should mention MFA
	if !strings.Contains(cmd.Long, "MFA") {
		t.Error("Long description should mention MFA")
	}
}

func TestKeyPolicyCommand_InParentCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	parentCmd := NewKeyCommand(getFlags)

	var found bool
	for _, subcmd := range parentCmd.Commands() {
		if subcmd.Name() == "policy" {
			found = true
			break
		}
	}

	if !found {
		t.Error("policy subcommand not found in key command")
	}
}

// Error type tests

func TestErrGetKeyPolicyFailed_Error(t *testing.T) {
	innerErr := errors.New("access denied")
	err := ErrGetKeyPolicyFailed{
		KeyID: "restricted-key-789",
		Err:   innerErr,
	}

	errMsg := err.Error()

	if !strings.Contains(errMsg, "failed to get policy") {
		t.Errorf("error message should contain 'failed to get policy': %s", errMsg)
	}
	if !strings.Contains(errMsg, "restricted-key-789") {
		t.Errorf("error message should contain key ID: %s", errMsg)
	}
	if !strings.Contains(errMsg, "access denied") {
		t.Errorf("error message should contain inner error: %s", errMsg)
	}
}
