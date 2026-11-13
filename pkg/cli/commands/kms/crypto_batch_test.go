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

func TestNewCryptoBatchCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoBatchCommand(getFlags)

	if cmd.Use != "batch" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "batch")
	}

	if cmd.Short != "Batch cryptographic operations" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewCryptoBatchCommand_HasSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoBatchCommand(getFlags)

	expectedSubcommands := []string{"encrypt", "decrypt"}
	subcommands := cmd.Commands()

	if len(subcommands) != len(expectedSubcommands) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
	}

	for _, expected := range expectedSubcommands {
		found := false
		for _, subcmd := range subcommands {
			if subcmd.Name() == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("subcommand %q not found", expected)
		}
	}
}

func TestNewCryptoBatchCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoBatchCommand(getFlags)

	expectedContent := []string{
		"multiple encrypt or decrypt operations",
		"single request",
		"JSON array",
		"plaintext",
		"ciphertext",
	}

	for _, content := range expectedContent {
		if !strings.Contains(cmd.Long, content) {
			t.Errorf("Long description should contain %q", content)
		}
	}
}

func TestNewBatchEncryptCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newBatchEncryptCommand(getFlags)

	if cmd.Use != "encrypt" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "encrypt")
	}

	if cmd.Short != "Batch encrypt multiple items" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewBatchEncryptCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newBatchEncryptCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"key-id", "", ""},
		{"input", "i", ""},
		{"json", "", "true"},
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

func TestNewBatchEncryptCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newBatchEncryptCommand(getFlags)

	expectedContent := []string{
		"JSON array",
		"plaintext",
		"item_id",
		"context",
		"nonce",
		"Examples:",
	}

	for _, content := range expectedContent {
		if !strings.Contains(cmd.Long, content) {
			t.Errorf("Long description should contain %q", content)
		}
	}
}

func TestNewBatchDecryptCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newBatchDecryptCommand(getFlags)

	if cmd.Use != "decrypt" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "decrypt")
	}

	if cmd.Short != "Batch decrypt multiple items" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewBatchDecryptCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newBatchDecryptCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"key-id", "", ""},
		{"input", "i", ""},
		{"json", "", "true"},
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

func TestNewBatchDecryptCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newBatchDecryptCommand(getFlags)

	expectedContent := []string{
		"JSON array",
		"ciphertext",
		"item_id",
		"context",
		"nonce",
		"key_version",
		"Examples:",
	}

	for _, content := range expectedContent {
		if !strings.Contains(cmd.Long, content) {
			t.Errorf("Long description should contain %q", content)
		}
	}
}

func TestBatchCommand_InCryptoCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCryptoCommand(getFlags)

	var found bool
	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "batch" {
			found = true
			break
		}
	}

	if !found {
		t.Error("batch subcommand not found in crypto command")
	}
}

// Error type tests

func TestErrBatchInputRequired_Error(t *testing.T) {
	err := ErrBatchInputRequired{}
	errStr := err.Error()

	if !strings.Contains(errStr, "batch operation requires input") {
		t.Errorf("error message should contain 'batch operation requires input': %s", errStr)
	}
	if !strings.Contains(errStr, "--input") {
		t.Errorf("error message should mention --input flag: %s", errStr)
	}
	if !strings.Contains(errStr, "stdin") {
		t.Errorf("error message should mention stdin: %s", errStr)
	}
}

func TestErrInvalidBatchFormat_Error(t *testing.T) {
	tests := []struct {
		name   string
		reason string
	}{
		{
			name:   "parsing error",
			reason: "invalid character 'x' looking for beginning of value",
		},
		{
			name:   "empty array",
			reason: "empty input array",
		},
		{
			name:   "missing field",
			reason: "missing ciphertext for item item-0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidBatchFormat{Reason: tt.reason}
			errStr := err.Error()

			if !strings.Contains(errStr, "invalid batch input format") {
				t.Errorf("error message should contain 'invalid batch input format': %s", errStr)
			}
			if !strings.Contains(errStr, tt.reason) {
				t.Errorf("error message should contain reason %q: %s", tt.reason, errStr)
			}
		})
	}
}

func TestErrBatchOperationFailed_Error(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		err       error
		expected  string
	}{
		{
			name:      "encrypt operation failed",
			operation: "encrypt",
			err:       errors.New("key not found"),
			expected:  "batch encrypt operation failed: key not found",
		},
		{
			name:      "decrypt operation failed",
			operation: "decrypt",
			err:       errors.New("decryption error"),
			expected:  "batch decrypt operation failed: decryption error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrBatchOperationFailed{Operation: tt.operation, Err: tt.err}
			errStr := err.Error()

			if errStr != tt.expected {
				t.Errorf("error message: got %q, want %q", errStr, tt.expected)
			}
		})
	}
}

func TestErrBatchOperationFailed_Unwrap(t *testing.T) {
	innerErr := errors.New("inner error")
	err := ErrBatchOperationFailed{Operation: "encrypt", Err: innerErr}

	unwrapped := err.Unwrap()
	if unwrapped != innerErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, innerErr)
	}
}

// Flag struct tests

func TestBatchCommand_GetFlagsNotCalledOnCreation(t *testing.T) {
	callCount := 0
	getFlags := func() *cli.CommonFlags {
		callCount++
		return &cli.CommonFlags{}
	}

	_ = newCryptoBatchCommand(getFlags)

	if callCount != 0 {
		t.Errorf("getFlags was called %d times during command creation, expected 0", callCount)
	}
}

func TestBatchEncryptCommand_GetFlagsNotCalledOnCreation(t *testing.T) {
	callCount := 0
	getFlags := func() *cli.CommonFlags {
		callCount++
		return &cli.CommonFlags{}
	}

	_ = newBatchEncryptCommand(getFlags)

	if callCount != 0 {
		t.Errorf("getFlags was called %d times during command creation, expected 0", callCount)
	}
}

func TestBatchDecryptCommand_GetFlagsNotCalledOnCreation(t *testing.T) {
	callCount := 0
	getFlags := func() *cli.CommonFlags {
		callCount++
		return &cli.CommonFlags{}
	}

	_ = newBatchDecryptCommand(getFlags)

	if callCount != 0 {
		t.Errorf("getFlags was called %d times during command creation, expected 0", callCount)
	}
}
