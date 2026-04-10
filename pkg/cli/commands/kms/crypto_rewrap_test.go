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

func TestNewCryptoRewrapCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoRewrapCommand(getFlags)

	if cmd.Use != "rewrap" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "rewrap")
	}

	if cmd.Short != "Re-encrypt data with latest key version" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewCryptoRewrapCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoRewrapCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"key-id", "", ""},
		{"input", "i", ""},
		{"output", "o", ""},
		{"context", "", ""},
		{"nonce", "", ""},
		{"source-version", "", "0"},
		{"base64-input", "", "true"},
		{"base64", "", "true"},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				t.Errorf("flag %q not found", tt.flagName)
				return
			}
			if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
				t.Errorf("flag %q shorthand: got %q, want %q", tt.flagName, flag.Shorthand, tt.shorthand)
			}
			if flag.DefValue != tt.defaultValue {
				t.Errorf("flag %q default: got %q, want %q", tt.flagName, flag.DefValue, tt.defaultValue)
			}
		})
	}
}

func TestNewCryptoRewrapCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoRewrapCommand(getFlags)

	expectedContent := []string{
		"Re-encrypt ciphertext",
		"latest version",
		"key rotation",
		"server-side",
		"plaintext is never exposed",
		"--input",
		"stdin",
		"base64",
		"Examples:",
	}

	for _, content := range expectedContent {
		if !strings.Contains(cmd.Long, content) {
			t.Errorf("Long description should contain %q", content)
		}
	}
}

func TestCryptoRewrapCommand_InCryptoCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCryptoCommand(getFlags)

	var found bool
	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "rewrap" {
			found = true
			break
		}
	}

	if !found {
		t.Error("rewrap subcommand not found in crypto command")
	}
}

func TestCryptoRewrapCommand_RequiredKeyID(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoRewrapCommand(getFlags)

	flag := cmd.Flags().Lookup("key-id")
	if flag == nil {
		t.Fatal("key-id flag not found")
	}

	if flag.DefValue != "" {
		t.Error("key-id should have empty default (required flag)")
	}
}

// rewrapFlags struct tests

func TestRewrapFlags_Fields(t *testing.T) {
	flags := rewrapFlags{
		keyID:         "my-key",
		inputPath:     "/path/to/input.enc",
		outputPath:    "/path/to/output.enc",
		context:       "encryption-context",
		nonce:         "base64nonce==",
		sourceVersion: 2,
		base64In:      true,
		base64Out:     true,
	}

	if flags.keyID != "my-key" {
		t.Errorf("keyID = %q, want %q", flags.keyID, "my-key")
	}
	if flags.inputPath != "/path/to/input.enc" {
		t.Errorf("inputPath = %q, want %q", flags.inputPath, "/path/to/input.enc")
	}
	if flags.outputPath != "/path/to/output.enc" {
		t.Errorf("outputPath = %q, want %q", flags.outputPath, "/path/to/output.enc")
	}
	if flags.context != "encryption-context" {
		t.Errorf("context = %q, want %q", flags.context, "encryption-context")
	}
	if flags.nonce != "base64nonce==" {
		t.Errorf("nonce = %q, want %q", flags.nonce, "base64nonce==")
	}
	if flags.sourceVersion != 2 {
		t.Errorf("sourceVersion = %d, want %d", flags.sourceVersion, 2)
	}
	if !flags.base64In {
		t.Error("base64In should be true")
	}
	if !flags.base64Out {
		t.Error("base64Out should be true")
	}
}

func TestRewrapFlags_DefaultValues(t *testing.T) {
	flags := rewrapFlags{}

	if flags.keyID != "" {
		t.Errorf("keyID default should be empty, got %q", flags.keyID)
	}
	if flags.inputPath != "" {
		t.Errorf("inputPath default should be empty, got %q", flags.inputPath)
	}
	if flags.outputPath != "" {
		t.Errorf("outputPath default should be empty, got %q", flags.outputPath)
	}
	if flags.context != "" {
		t.Errorf("context default should be empty, got %q", flags.context)
	}
	if flags.nonce != "" {
		t.Errorf("nonce default should be empty, got %q", flags.nonce)
	}
	if flags.sourceVersion != 0 {
		t.Errorf("sourceVersion default should be 0, got %d", flags.sourceVersion)
	}
	if flags.base64In {
		t.Error("base64In default should be false (zero value)")
	}
	if flags.base64Out {
		t.Error("base64Out default should be false (zero value)")
	}
}

func TestCryptoRewrapCommand_GetFlagsNotCalledOnCreation(t *testing.T) {
	callCount := 0
	getFlags := func() *cli.CommonFlags {
		callCount++
		return &cli.CommonFlags{}
	}

	_ = newCryptoRewrapCommand(getFlags)

	if callCount != 0 {
		t.Errorf("getFlags was called %d times during command creation, expected 0", callCount)
	}
}

func TestCryptoRewrapCommand_FlagUsageDescriptions(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoRewrapCommand(getFlags)

	flagsWithUsage := []struct {
		name        string
		shouldExist bool
	}{
		{"key-id", true},
		{"input", true},
		{"output", true},
		{"context", true},
		{"nonce", true},
		{"source-version", true},
		{"base64-input", true},
		{"base64", true},
	}

	for _, f := range flagsWithUsage {
		flag := cmd.Flags().Lookup(f.name)
		if f.shouldExist {
			if flag == nil {
				t.Errorf("flag %q should exist", f.name)
				continue
			}
			if flag.Usage == "" {
				t.Errorf("flag %q should have a usage description", f.name)
			}
		}
	}
}

func TestCryptoRewrapCommand_SupportsAllOutputFormats(t *testing.T) {
	tests := []struct {
		name   string
		format cli.OutputFormat
	}{
		{"table format", cli.OutputFormatTable},
		{"json format", cli.OutputFormatJSON},
		{"yaml format", cli.OutputFormatYAML},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getFlags := func() *cli.CommonFlags {
				return &cli.CommonFlags{
					OutputFormat: tt.format,
				}
			}

			cmd := newCryptoRewrapCommand(getFlags)
			if cmd == nil {
				t.Errorf("command should be created for format %v", tt.format)
			}
		})
	}
}

func TestCryptoRewrapCommand_NoSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoRewrapCommand(getFlags)

	if len(cmd.Commands()) != 0 {
		t.Errorf("rewrap command should not have subcommands, got %d", len(cmd.Commands()))
	}
}

func TestCryptoRewrapCommand_NoPositionalArgs(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoRewrapCommand(getFlags)

	if cmd.Args != nil {
		t.Error("rewrap command should not require positional arguments")
	}
}
