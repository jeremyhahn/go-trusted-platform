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

//go:build key_safety

// NOTE: This file requires go-quicbaas API features that are not yet released.
// Enable with: go test -tags key_safety

package kms

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewKeySafetyCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetyCommand(getFlags)

	if cmd.Use != "safety" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Manage AEAD safety limits" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewKeySafetyCommand_Subcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetyCommand(getFlags)

	expectedSubcommands := []string{"set", "clear", "check", "report"}
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

func TestNewKeySafetySetCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetySetCommand(getFlags)

	if cmd.Use != "set <key-id>" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Set AEAD safety limits for a key" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Args == nil {
		t.Error("Args should be set")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewKeySafetySetCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetySetCommand(getFlags)

	tests := []struct {
		flagName     string
		defaultValue string
	}{
		{"max-operations", "0"},
		{"max-bytes", "0"},
		{"warning-percent", "80"},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				t.Errorf("flag %q not found", tt.flagName)
				return
			}
			if flag.DefValue != tt.defaultValue {
				t.Errorf("flag %q default: got %q, want %q", tt.flagName, flag.DefValue, tt.defaultValue)
			}
		})
	}
}

func TestNewKeySafetyClearCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetyClearCommand(getFlags)

	if cmd.Use != "clear <key-id>" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Clear custom AEAD safety limits" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Args == nil {
		t.Error("Args should be set")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewKeySafetyCheckCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetyCheckCommand(getFlags)

	if cmd.Use != "check" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Check for keys approaching safety limits" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewKeySafetyReportCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetyReportCommand(getFlags)

	if cmd.Use != "report" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "Generate comprehensive safety report" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestKeySafetyCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetyCommand(getFlags)

	// Should mention AEAD
	if !strings.Contains(cmd.Long, "AEAD") {
		t.Error("Long description should mention AEAD")
	}

	// Should mention safety limits
	if !strings.Contains(cmd.Long, "limit") {
		t.Error("Long description should mention limits")
	}

	// Should mention AES-GCM
	if !strings.Contains(cmd.Long, "AES-GCM") {
		t.Error("Long description should mention AES-GCM")
	}
}

func TestKeySafetySetCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetySetCommand(getFlags)

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}

	// Should mention operations
	if !strings.Contains(cmd.Long, "operations") {
		t.Error("Long description should mention operations")
	}

	// Should mention warning threshold
	if !strings.Contains(cmd.Long, "warning") {
		t.Error("Long description should mention warning threshold")
	}
}

func TestKeySafetyClearCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetyClearCommand(getFlags)

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}

	// Should mention defaults
	if !strings.Contains(cmd.Long, "default") {
		t.Error("Long description should mention reverting to defaults")
	}
}

func TestKeySafetyCheckCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetyCheckCommand(getFlags)

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}

	// Should mention warning
	if !strings.Contains(cmd.Long, "warning") {
		t.Error("Long description should mention warnings")
	}

	// Should mention critical
	if !strings.Contains(cmd.Long, "critical") {
		t.Error("Long description should mention critical level")
	}
}

func TestKeySafetyReportCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetyReportCommand(getFlags)

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}

	// Should mention detailed report
	if !strings.Contains(cmd.Long, "detailed") {
		t.Error("Long description should mention detailed report")
	}
}

func TestKeySafetyCommand_InParentCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	parentCmd := NewKeyCommand(getFlags)

	var found bool
	for _, subcmd := range parentCmd.Commands() {
		if subcmd.Name() == "safety" {
			found = true
			break
		}
	}

	if !found {
		t.Error("safety subcommand not found in key command")
	}
}

func TestFormatSafetyStatus_CaseSensitivity(t *testing.T) {
	// Test that status matching is case-sensitive (lowercase expected)
	tests := []struct {
		input    string
		expected string
	}{
		{"WARNING", "WARNING"}, // uppercase should pass through
		{"Warning", "Warning"}, // mixed case should pass through
		{"warning", "[WARNING] Warning"},
		{"CRITICAL", "CRITICAL"},
		{"critical", "[CRITICAL] Critical"},
		{"OK", "OK"},
		{"ok", "[OK] OK"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := formatSafetyStatus(tt.input)
			if result != tt.expected {
				t.Errorf("formatSafetyStatus(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
