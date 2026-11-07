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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
)

func TestNewCryptoCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCryptoCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewCryptoCommand returned nil")
	}

	if cmd.Use != "crypto" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "crypto")
	}

	if cmd.Short != "Cryptographic operations" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewCryptoCommand_HasAllSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCryptoCommand(getFlags)

	expectedSubcommands := []string{
		"encrypt",
		"decrypt",
		"rewrap",
		"batch",
		"datakey",
		"sign",
		"verify",
		"hmac",
		"random",
		"hash",
	}

	subcommands := cmd.Commands()

	if len(subcommands) != len(expectedSubcommands) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
		for _, subcmd := range subcommands {
			t.Logf("  found subcommand: %s", subcmd.Name())
		}
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

func TestNewCryptoCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCryptoCommand(getFlags)

	expectedContent := []string{
		"encrypt/decrypt",
		"sign/verify",
		"hmac",
		"hash",
		"random",
		"rewrap",
		"datakey",
		"batch",
		"Examples:",
	}

	for _, content := range expectedContent {
		if !strings.Contains(cmd.Long, content) {
			t.Errorf("Long description should contain %q", content)
		}
	}
}

func TestNewCryptoCommand_NoRunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCryptoCommand(getFlags)

	if cmd.RunE != nil {
		t.Error("crypto root command should not have RunE (it's a grouping command)")
	}
}

// Error type tests

func TestCryptoErrors_Error(t *testing.T) {
	tests := []struct {
		err      error
		expected string
	}{
		{ErrCryptoClientNotInitialized{}, "crypto client not initialized"},
		{ErrInvalidHashAlgorithm{Algorithm: "md5"}, "invalid hash algorithm: md5"},
		{ErrInvalidAlgorithm{Algorithm: "invalid-alg"}, "invalid algorithm: invalid-alg"},
		{ErrHMACRequired{}, "HMAC is required (use --hmac flag)"},
		{ErrSignatureRequired{}, "signature is required (use --signature flag)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("Error() = %q, want %q", tt.err.Error(), tt.expected)
			}
		})
	}
}

func TestErrCryptoOperationFailed_Error(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		err       error
		expected  string
	}{
		{
			name:      "encrypt operation",
			operation: "encrypt",
			err:       errors.New("key not found"),
			expected:  "crypto encrypt operation failed: key not found",
		},
		{
			name:      "decrypt operation",
			operation: "decrypt",
			err:       errors.New("invalid ciphertext"),
			expected:  "crypto decrypt operation failed: invalid ciphertext",
		},
		{
			name:      "sign operation",
			operation: "sign",
			err:       errors.New("key not asymmetric"),
			expected:  "crypto sign operation failed: key not asymmetric",
		},
		{
			name:      "rewrap operation",
			operation: "rewrap",
			err:       errors.New("version mismatch"),
			expected:  "crypto rewrap operation failed: version mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrCryptoOperationFailed{Operation: tt.operation, Err: tt.err}

			if err.Error() != tt.expected {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}

func TestErrInputRequired_Error(t *testing.T) {
	tests := []struct {
		operation string
		expected  string
	}{
		{"encrypt", "encrypt requires input data (use --input flag or pipe via stdin)"},
		{"decrypt", "decrypt requires input data (use --input flag or pipe via stdin)"},
		{"sign", "sign requires input data (use --input flag or pipe via stdin)"},
		{"read", "read requires input data (use --input flag or pipe via stdin)"},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			err := ErrInputRequired{Operation: tt.operation}

			if err.Error() != tt.expected {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}

func TestErrInvalidInputFile_Error(t *testing.T) {
	innerErr := errors.New("file not found")
	err := ErrInvalidInputFile{Path: "/path/to/input.txt", Err: innerErr}

	errStr := err.Error()

	if !strings.Contains(errStr, "failed to read input file") {
		t.Errorf("error should contain 'failed to read input file': %s", errStr)
	}
	if !strings.Contains(errStr, "/path/to/input.txt") {
		t.Errorf("error should contain path: %s", errStr)
	}
	if !strings.Contains(errStr, "file not found") {
		t.Errorf("error should contain inner error: %s", errStr)
	}
}

func TestErrInvalidOutputFile_Error(t *testing.T) {
	innerErr := errors.New("permission denied")
	err := ErrInvalidOutputFile{Path: "/path/to/output.enc", Err: innerErr}

	errStr := err.Error()

	if !strings.Contains(errStr, "failed to write output file") {
		t.Errorf("error should contain 'failed to write output file': %s", errStr)
	}
	if !strings.Contains(errStr, "/path/to/output.enc") {
		t.Errorf("error should contain path: %s", errStr)
	}
	if !strings.Contains(errStr, "permission denied") {
		t.Errorf("error should contain inner error: %s", errStr)
	}
}

func TestErrKeyIDRequired_Error(t *testing.T) {
	tests := []struct {
		operation string
		expected  string
	}{
		{"encrypt", "encrypt requires a key ID"},
		{"decrypt", "decrypt requires a key ID"},
		{"sign", "sign requires a key ID"},
		{"rewrap", "rewrap requires a key ID"},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			err := ErrKeyIDRequired{Operation: tt.operation}

			if err.Error() != tt.expected {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}

func TestErrInvalidBase64_Error(t *testing.T) {
	innerErr := errors.New("illegal base64 data at input byte 0")
	err := ErrInvalidBase64{Field: "nonce", Err: innerErr}

	errStr := err.Error()

	if !strings.Contains(errStr, "invalid base64 encoding for nonce") {
		t.Errorf("error should contain field name: %s", errStr)
	}
	if !strings.Contains(errStr, "illegal base64 data") {
		t.Errorf("error should contain inner error: %s", errStr)
	}
}

func TestErrInvalidByteCount_Error(t *testing.T) {
	tests := []struct {
		count    int32
		expected string
	}{
		{-1, "invalid byte count: -1 (must be positive)"},
		{0, "invalid byte count: 0 (must be positive)"},
		{-100, "invalid byte count: -100 (must be positive)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			err := ErrInvalidByteCount{Count: tt.count}

			if err.Error() != tt.expected {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}

// Helper function tests

func TestParseHashAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		expected kmssvc.HashAlgorithm
		wantErr  bool
	}{
		// SHA1 variants
		{"sha1", kmssvc.HashAlgorithmSHA1, false},
		{"sha-1", kmssvc.HashAlgorithmSHA1, false},
		{"SHA1", kmssvc.HashAlgorithmSHA1, false},
		{"SHA-1", kmssvc.HashAlgorithmSHA1, false},

		// SHA256 variants
		{"sha256", kmssvc.HashAlgorithmSHA256, false},
		{"sha-256", kmssvc.HashAlgorithmSHA256, false},
		{"SHA256", kmssvc.HashAlgorithmSHA256, false},
		{"SHA-256", kmssvc.HashAlgorithmSHA256, false},
		{"sha_256", kmssvc.HashAlgorithmSHA256, false},

		// SHA384 variants
		{"sha384", kmssvc.HashAlgorithmSHA384, false},
		{"sha-384", kmssvc.HashAlgorithmSHA384, false},
		{"SHA384", kmssvc.HashAlgorithmSHA384, false},

		// SHA512 variants
		{"sha512", kmssvc.HashAlgorithmSHA512, false},
		{"sha-512", kmssvc.HashAlgorithmSHA512, false},
		{"SHA512", kmssvc.HashAlgorithmSHA512, false},

		// SHA3-256 variants
		{"sha3-256", kmssvc.HashAlgorithmSHA3256, false},
		{"sha3256", kmssvc.HashAlgorithmSHA3256, false},
		{"SHA3-256", kmssvc.HashAlgorithmSHA3256, false},

		// SHA3-384 variants
		{"sha3-384", kmssvc.HashAlgorithmSHA3384, false},
		{"sha3384", kmssvc.HashAlgorithmSHA3384, false},

		// SHA3-512 variants
		{"sha3-512", kmssvc.HashAlgorithmSHA3512, false},
		{"sha3512", kmssvc.HashAlgorithmSHA3512, false},

		// Invalid algorithms
		{"md5", kmssvc.HashAlgorithmUnspecified, true},
		{"invalid", kmssvc.HashAlgorithmUnspecified, true},
		{"", kmssvc.HashAlgorithmUnspecified, true},
		{"sha0", kmssvc.HashAlgorithmUnspecified, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseHashAlgorithm(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseHashAlgorithm(%q) expected error, got nil", tt.input)
				}
				var hashErr ErrInvalidHashAlgorithm
				if !errors.As(err, &hashErr) {
					t.Errorf("expected ErrInvalidHashAlgorithm, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("parseHashAlgorithm(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("parseHashAlgorithm(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestFormatHashAlgorithm(t *testing.T) {
	tests := []struct {
		input    kmssvc.HashAlgorithm
		expected string
	}{
		{kmssvc.HashAlgorithmSHA1, "SHA-1"},
		{kmssvc.HashAlgorithmSHA256, "SHA-256"},
		{kmssvc.HashAlgorithmSHA384, "SHA-384"},
		{kmssvc.HashAlgorithmSHA512, "SHA-512"},
		{kmssvc.HashAlgorithmSHA3256, "SHA3-256"},
		{kmssvc.HashAlgorithmSHA3384, "SHA3-384"},
		{kmssvc.HashAlgorithmSHA3512, "SHA3-512"},
		{kmssvc.HashAlgorithmUnspecified, "UNSPECIFIED"},
		{kmssvc.HashAlgorithm("BOGUS"), "BOGUS"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatHashAlgorithm(tt.input)

			if result != tt.expected {
				t.Errorf("formatHashAlgorithm(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseKMSKeyAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		expected kmssvc.KeyAlgorithm
		wantErr  bool
	}{
		// AES variants
		{"aes-128", kmssvc.KeyAlgorithmAES128, false},
		{"AES_128", kmssvc.KeyAlgorithmAES128, false},
		{"aes-192", kmssvc.KeyAlgorithmAES192, false},
		{"AES_192", kmssvc.KeyAlgorithmAES192, false},
		{"aes-256", kmssvc.KeyAlgorithmAES256, false},
		{"AES_256", kmssvc.KeyAlgorithmAES256, false},

		// ChaCha20 variants
		{"chacha20-poly1305", kmssvc.KeyAlgorithmChaCha20Poly, false},
		{"CHACHA20_POLY1305", kmssvc.KeyAlgorithmChaCha20Poly, false},

		// RSA variants
		{"rsa-2048", kmssvc.KeyAlgorithmRSA2048, false},
		{"RSA_2048", kmssvc.KeyAlgorithmRSA2048, false},
		{"rsa-3072", kmssvc.KeyAlgorithmRSA3072, false},
		{"RSA_3072", kmssvc.KeyAlgorithmRSA3072, false},
		{"rsa-4096", kmssvc.KeyAlgorithmRSA4096, false},
		{"RSA_4096", kmssvc.KeyAlgorithmRSA4096, false},

		// ECDSA variants
		{"ec-p256", kmssvc.KeyAlgorithmECDSAP256, false},
		{"ECDSA_P256", kmssvc.KeyAlgorithmECDSAP256, false},
		{"ec-p384", kmssvc.KeyAlgorithmECDSAP384, false},
		{"ECDSA_P384", kmssvc.KeyAlgorithmECDSAP384, false},
		{"ec-p521", kmssvc.KeyAlgorithmECDSAP521, false},
		{"ECDSA_P521", kmssvc.KeyAlgorithmECDSAP521, false},

		// EdDSA variants
		{"ed25519", kmssvc.KeyAlgorithmED25519, false},
		{"ED25519", kmssvc.KeyAlgorithmED25519, false},

		// HMAC variants
		{"hmac-sha256", kmssvc.KeyAlgorithmHMACSHA256, false},
		{"HMAC_SHA256", kmssvc.KeyAlgorithmHMACSHA256, false},
		{"hmac-sha384", kmssvc.KeyAlgorithmHMACSHA384, false},
		{"HMAC_SHA384", kmssvc.KeyAlgorithmHMACSHA384, false},
		{"hmac-sha512", kmssvc.KeyAlgorithmHMACSHA512, false},
		{"HMAC_SHA512", kmssvc.KeyAlgorithmHMACSHA512, false},

		// Invalid algorithms
		{"invalid", kmssvc.KeyAlgorithmUnspecified, true},
		{"", kmssvc.KeyAlgorithmUnspecified, true},
		{"aes", kmssvc.KeyAlgorithmUnspecified, true},
		{"rsa", kmssvc.KeyAlgorithmUnspecified, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := kmssvc.ParseKeyAlgorithm(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("kmssvc.ParseKeyAlgorithm(%q) expected error, got nil", tt.input)
				}
				var algErr kmssvc.ErrInvalidKeyAlgorithm
				if !errors.As(err, &algErr) {
					t.Errorf("expected kmssvc.ErrInvalidKeyAlgorithm, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("kmssvc.ParseKeyAlgorithm(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("kmssvc.ParseKeyAlgorithm(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestFormatRandomBytes(t *testing.T) {
	testData := []byte{0x01, 0x02, 0x03, 0x04}

	tests := []struct {
		name     string
		format   string
		expected string
	}{
		{"base64 format", "base64", "AQIDBA=="},
		{"hex format", "hex", "01020304"},
		{"raw format", "raw", "\x01\x02\x03\x04"},
		{"default (base64)", "unknown", "AQIDBA=="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatRandomBytes(testData, tt.format)
			if result != tt.expected {
				t.Errorf("formatRandomBytes(..., %q) = %q, want %q", tt.format, result, tt.expected)
			}
		})
	}
}

func TestCryptoCommands_GetFlagsNotCalledOnCreation(t *testing.T) {
	constructors := map[string]func(func() *cli.CommonFlags) *cobra.Command{
		"crypto":  NewCryptoCommand,
		"encrypt": newCryptoEncryptCommand,
		"decrypt": newCryptoDecryptCommand,
		"sign":    newCryptoSignCommand,
		"random":  newCryptoRandomCommand,
		"datakey": newCryptoDataKeyCommand,
		"hash":    newCryptoHashCommand,
		"hmac":    newCryptoHMACCommand,
		"verify":  newCryptoVerifyCommand,
	}

	for name, newCommand := range constructors {
		t.Run(name, func(t *testing.T) {
			callCount := 0
			getFlags := func() *cli.CommonFlags {
				callCount++
				return &cli.CommonFlags{}
			}

			_ = newCommand(getFlags)

			if callCount != 0 {
				t.Errorf("getFlags was called %d times during creation, expected 0", callCount)
			}
		})
	}
}

// Encrypt command tests

func TestNewCryptoEncryptCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoEncryptCommand(getFlags)

	if cmd.Use != "encrypt" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "encrypt")
	}

	if cmd.Short != "Encrypt data with a key" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewCryptoEncryptCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoEncryptCommand(getFlags)

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

func TestNewCryptoEncryptCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoEncryptCommand(getFlags)

	expectedContent := []string{
		"Encrypt plaintext",
		"server-side",
		"--input",
		"stdin",
		"--output",
		"context",
		"AAD",
		"Examples:",
	}

	for _, content := range expectedContent {
		if !strings.Contains(cmd.Long, content) {
			t.Errorf("Long description should contain %q", content)
		}
	}
}

// Decrypt command tests

func TestNewCryptoDecryptCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoDecryptCommand(getFlags)

	if cmd.Use != "decrypt" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "decrypt")
	}

	if cmd.Short != "Decrypt data" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewCryptoDecryptCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoDecryptCommand(getFlags)

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
		{"key-version", "", "0"},
		{"base64-input", "", "true"},
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

func TestNewCryptoDecryptCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoDecryptCommand(getFlags)

	expectedContent := []string{
		"Decrypt ciphertext",
		"server-side",
		"context",
		"AAD",
		"--input",
		"stdin",
		"base64",
		"key version",
		"Examples:",
	}

	for _, content := range expectedContent {
		if !strings.Contains(cmd.Long, content) {
			t.Errorf("Long description should contain %q", content)
		}
	}
}

// Data key command tests

func TestNewCryptoDataKeyCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoDataKeyCommand(getFlags)

	if cmd.Use != "datakey" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "datakey")
	}

	if cmd.Short != "Data encryption key operations" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewCryptoDataKeyCommand_HasSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoDataKeyCommand(getFlags)

	expectedSubcommands := []string{"generate", "wrapped"}
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

func TestNewGenerateDataKeyCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newGenerateDataKeyCommand(getFlags)

	if cmd.Use != "generate" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "generate")
	}

	if cmd.Short != "Generate a data encryption key" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewGenerateDataKeyCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newGenerateDataKeyCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"key-id", "", ""},
		{"algorithm", "", "aes-256"},
		{"key-size", "", "256"},
		{"context", "", ""},
		{"output", "o", ""},
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

func TestNewGenerateWrappedDataKeyCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newGenerateWrappedDataKeyCommand(getFlags)

	if cmd.Use != "wrapped" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "wrapped")
	}

	if cmd.Short != "Generate a wrapped data encryption key" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

// Sign command tests

func TestNewCryptoSignCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoSignCommand(getFlags)

	if cmd.Use != "sign" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "sign")
	}

	if cmd.Short != "Create a digital signature" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewCryptoSignCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoSignCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"key-id", "", ""},
		{"input", "i", ""},
		{"output", "o", ""},
		{"hash", "", "sha256"},
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

func TestNewCryptoSignCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoSignCommand(getFlags)

	expectedContent := []string{
		"digital signature",
		"asymmetric key",
		"RSA",
		"ECDSA",
		"EdDSA",
		"sha256",
		"sha384",
		"sha512",
		"Examples:",
	}

	for _, content := range expectedContent {
		if !strings.Contains(cmd.Long, content) {
			t.Errorf("Long description should contain %q", content)
		}
	}
}

// Random command tests

func TestNewCryptoRandomCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoRandomCommand(getFlags)

	if cmd.Use != "random" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "random")
	}

	if cmd.Short != "Generate random bytes" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewCryptoRandomCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoRandomCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"bytes", "", "32"},
		{"output", "o", ""},
		{"format", "", "base64"},
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

func TestNewCryptoRandomCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoRandomCommand(getFlags)

	expectedContent := []string{
		"cryptographically secure",
		"CSPRNG",
		"base64",
		"hex",
		"raw",
		"encryption keys",
		"nonces",
		"Examples:",
	}

	for _, content := range expectedContent {
		if !strings.Contains(cmd.Long, content) {
			t.Errorf("Long description should contain %q", content)
		}
	}
}

// Flag struct tests

func TestEncryptFlags_Fields(t *testing.T) {
	flags := encryptFlags{
		keyID:      "my-key",
		inputPath:  "/path/to/input.txt",
		outputPath: "/path/to/output.enc",
		context:    "user=alice",
		nonce:      "base64nonce",
		base64Out:  true,
	}

	if flags.keyID != "my-key" {
		t.Errorf("keyID = %q, want %q", flags.keyID, "my-key")
	}
	if flags.inputPath != "/path/to/input.txt" {
		t.Errorf("inputPath = %q", flags.inputPath)
	}
	if flags.outputPath != "/path/to/output.enc" {
		t.Errorf("outputPath = %q", flags.outputPath)
	}
	if flags.context != "user=alice" {
		t.Errorf("context = %q", flags.context)
	}
	if flags.nonce != "base64nonce" {
		t.Errorf("nonce = %q", flags.nonce)
	}
	if !flags.base64Out {
		t.Error("base64Out should be true")
	}
}

func TestDecryptFlags_Fields(t *testing.T) {
	flags := decryptFlags{
		keyID:      "my-key",
		inputPath:  "/path/to/input.enc",
		outputPath: "/path/to/output.txt",
		context:    "user=alice",
		nonce:      "base64nonce",
		keyVersion: 2,
		base64In:   true,
	}

	if flags.keyID != "my-key" {
		t.Errorf("keyID = %q, want %q", flags.keyID, "my-key")
	}
	if flags.inputPath != "/path/to/input.enc" {
		t.Errorf("inputPath = %q", flags.inputPath)
	}
	if flags.outputPath != "/path/to/output.txt" {
		t.Errorf("outputPath = %q", flags.outputPath)
	}
	if flags.context != "user=alice" {
		t.Errorf("context = %q", flags.context)
	}
	if flags.nonce != "base64nonce" {
		t.Errorf("nonce = %q", flags.nonce)
	}
	if flags.keyVersion != 2 {
		t.Errorf("keyVersion = %d, want 2", flags.keyVersion)
	}
	if !flags.base64In {
		t.Error("base64In should be true")
	}
}

func TestDataKeyFlags_Fields(t *testing.T) {
	flags := dataKeyFlags{
		keyID:      "master-key",
		algorithm:  "aes-256",
		keySize:    256,
		context:    "purpose=backup",
		outputPath: "/path/to/output.bin",
	}

	if flags.keyID != "master-key" {
		t.Errorf("keyID = %q, want %q", flags.keyID, "master-key")
	}
	if flags.algorithm != "aes-256" {
		t.Errorf("algorithm = %q", flags.algorithm)
	}
	if flags.keySize != 256 {
		t.Errorf("keySize = %d, want 256", flags.keySize)
	}
	if flags.context != "purpose=backup" {
		t.Errorf("context = %q", flags.context)
	}
	if flags.outputPath != "/path/to/output.bin" {
		t.Errorf("outputPath = %q", flags.outputPath)
	}
}

func TestSignFlags_Fields(t *testing.T) {
	flags := signFlags{
		keyID:         "signing-key",
		inputPath:     "/path/to/document.pdf",
		outputPath:    "/path/to/signature.sig",
		hashAlgorithm: "sha256",
		base64Out:     true,
	}

	if flags.keyID != "signing-key" {
		t.Errorf("keyID = %q, want %q", flags.keyID, "signing-key")
	}
	if flags.inputPath != "/path/to/document.pdf" {
		t.Errorf("inputPath = %q", flags.inputPath)
	}
	if flags.outputPath != "/path/to/signature.sig" {
		t.Errorf("outputPath = %q", flags.outputPath)
	}
	if flags.hashAlgorithm != "sha256" {
		t.Errorf("hashAlgorithm = %q", flags.hashAlgorithm)
	}
	if !flags.base64Out {
		t.Error("base64Out should be true")
	}
}

func TestRandomFlags_Fields(t *testing.T) {
	flags := randomFlags{
		numBytes:   64,
		outputPath: "/path/to/random.bin",
		format:     "hex",
	}

	if flags.numBytes != 64 {
		t.Errorf("numBytes = %d, want 64", flags.numBytes)
	}
	if flags.outputPath != "/path/to/random.bin" {
		t.Errorf("outputPath = %q", flags.outputPath)
	}
	if flags.format != "hex" {
		t.Errorf("format = %q", flags.format)
	}
}

func TestDecodeBase64Input_Valid(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "aGVsbG8=", "hello"},
		{"empty", "", ""},
		{"with padding", "dGVzdA==", "test"},
		{"longer text", "VGhlIHF1aWNrIGJyb3duIGZveA==", "The quick brown fox"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decodeBase64Input([]byte(tt.input))
			if err != nil {
				t.Errorf("decodeBase64Input(%q) unexpected error: %v", tt.input, err)
				return
			}
			if string(result) != tt.expected {
				t.Errorf("decodeBase64Input(%q) = %q, want %q", tt.input, string(result), tt.expected)
			}
		})
	}
}

func TestDecodeBase64Input_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"invalid characters", "!!!invalid!!!"},
		{"wrong padding", "aGVsbG8"},
		{"truncated", "aGVsb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeBase64Input([]byte(tt.input))
			if err == nil {
				t.Errorf("decodeBase64Input(%q) expected error, got nil", tt.input)
				return
			}
			var base64Err ErrInvalidBase64
			if !errors.As(err, &base64Err) {
				t.Errorf("expected ErrInvalidBase64, got %T: %v", err, err)
			}
		})
	}
}

// Hash command tests

func TestNewCryptoHashCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoHashCommand(getFlags)

	if cmd.Use != "hash" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "hash")
	}

	if cmd.Short != "Compute a cryptographic hash" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewCryptoHashCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoHashCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"input", "i", ""},
		{"output", "o", ""},
		{"algorithm", "", "sha256"},
		{"format", "", "hex"},
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

func TestNewCryptoHashCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoHashCommand(getFlags)

	expectedContent := []string{
		"cryptographic hash",
		"SHA-256",
		"SHA-384",
		"SHA-512",
		"SHA3-256",
		"BLAKE2",
		"hex",
		"base64",
		"Examples:",
	}

	for _, content := range expectedContent {
		if !strings.Contains(cmd.Long, content) {
			t.Errorf("Long description should contain %q", content)
		}
	}
}

func TestHashFlags_Fields(t *testing.T) {
	flags := hashFlags{
		inputPath:  "/path/to/input.txt",
		outputPath: "/path/to/hash.txt",
		algorithm:  "sha512",
		format:     "base64",
	}

	if flags.inputPath != "/path/to/input.txt" {
		t.Errorf("inputPath = %q", flags.inputPath)
	}
	if flags.outputPath != "/path/to/hash.txt" {
		t.Errorf("outputPath = %q", flags.outputPath)
	}
	if flags.algorithm != "sha512" {
		t.Errorf("algorithm = %q", flags.algorithm)
	}
	if flags.format != "base64" {
		t.Errorf("format = %q", flags.format)
	}
}

func TestFormatHashOutput(t *testing.T) {
	testData := []byte{0x01, 0x02, 0x03, 0x04}

	tests := []struct {
		name     string
		format   string
		expected string
	}{
		{"hex format", "hex", "01020304"},
		{"base64 format", "base64", "AQIDBA=="},
		{"default (hex)", "unknown", "01020304"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatHashOutput(testData, tt.format)
			if result != tt.expected {
				t.Errorf("formatHashOutput(..., %q) = %q, want %q", tt.format, result, tt.expected)
			}
		})
	}
}

// HMAC command tests

func TestNewCryptoHMACCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoHMACCommand(getFlags)

	if cmd.Use != "hmac" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "hmac")
	}

	if cmd.Short != "HMAC operations" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewCryptoHMACCommand_HasSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoHMACCommand(getFlags)

	expectedSubcommands := []string{"generate", "verify"}
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

func TestNewHMACGenerateCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newHMACGenerateCommand(getFlags)

	if cmd.Use != "generate" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "generate")
	}

	if cmd.Short != "Generate an HMAC" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewHMACGenerateCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newHMACGenerateCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"key-id", "", ""},
		{"input", "i", ""},
		{"output", "o", ""},
		{"hash", "", "sha256"},
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

func TestNewHMACVerifyCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newHMACVerifyCommand(getFlags)

	if cmd.Use != "verify" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "verify")
	}

	if cmd.Short != "Verify an HMAC" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewHMACVerifyCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newHMACVerifyCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"key-id", "", ""},
		{"input", "i", ""},
		{"hmac-file", "", ""},
		{"hmac", "", ""},
		{"hash", "", "sha256"},
		{"key-version", "", "0"},
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

func TestHMACGenerateFlags_Fields(t *testing.T) {
	flags := hmacGenerateFlags{
		keyID:         "hmac-key",
		inputPath:     "/path/to/data.txt",
		outputPath:    "/path/to/data.hmac",
		hashAlgorithm: "sha384",
		base64Out:     true,
	}

	if flags.keyID != "hmac-key" {
		t.Errorf("keyID = %q", flags.keyID)
	}
	if flags.inputPath != "/path/to/data.txt" {
		t.Errorf("inputPath = %q", flags.inputPath)
	}
	if flags.outputPath != "/path/to/data.hmac" {
		t.Errorf("outputPath = %q", flags.outputPath)
	}
	if flags.hashAlgorithm != "sha384" {
		t.Errorf("hashAlgorithm = %q", flags.hashAlgorithm)
	}
	if !flags.base64Out {
		t.Error("base64Out should be true")
	}
}

func TestHMACVerifyFlags_Fields(t *testing.T) {
	flags := hmacVerifyFlags{
		keyID:         "hmac-key",
		inputPath:     "/path/to/data.txt",
		hmacPath:      "/path/to/data.hmac",
		hmac:          "base64hmac",
		hashAlgorithm: "sha256",
		keyVersion:    2,
	}

	if flags.keyID != "hmac-key" {
		t.Errorf("keyID = %q", flags.keyID)
	}
	if flags.inputPath != "/path/to/data.txt" {
		t.Errorf("inputPath = %q", flags.inputPath)
	}
	if flags.hmacPath != "/path/to/data.hmac" {
		t.Errorf("hmacPath = %q", flags.hmacPath)
	}
	if flags.hmac != "base64hmac" {
		t.Errorf("hmac = %q", flags.hmac)
	}
	if flags.hashAlgorithm != "sha256" {
		t.Errorf("hashAlgorithm = %q", flags.hashAlgorithm)
	}
	if flags.keyVersion != 2 {
		t.Errorf("keyVersion = %d", flags.keyVersion)
	}
}

// Verify command tests

func TestNewCryptoVerifyCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoVerifyCommand(getFlags)

	if cmd.Use != "verify" {
		t.Errorf("unexpected Use: got %q, want %q", cmd.Use, "verify")
	}

	if cmd.Short != "Verify a digital signature" {
		t.Errorf("unexpected Short: got %q", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewCryptoVerifyCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoVerifyCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"key-id", "", ""},
		{"input", "i", ""},
		{"signature-file", "", ""},
		{"signature", "", ""},
		{"hash", "", "sha256"},
		{"key-version", "", "0"},
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

func TestNewCryptoVerifyCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCryptoVerifyCommand(getFlags)

	expectedContent := []string{
		"Verify a digital signature",
		"server-side",
		"--signature",
		"--signature-file",
		"--input",
		"stdin",
		"key version",
		"Examples:",
	}

	for _, content := range expectedContent {
		if !strings.Contains(cmd.Long, content) {
			t.Errorf("Long description should contain %q", content)
		}
	}
}

func TestVerifyFlags_Fields(t *testing.T) {
	flags := verifyFlags{
		keyID:         "verify-key",
		inputPath:     "/path/to/document.pdf",
		signaturePath: "/path/to/signature.sig",
		signature:     "base64sig",
		hashAlgorithm: "sha384",
		keyVersion:    3,
	}

	if flags.keyID != "verify-key" {
		t.Errorf("keyID = %q", flags.keyID)
	}
	if flags.inputPath != "/path/to/document.pdf" {
		t.Errorf("inputPath = %q", flags.inputPath)
	}
	if flags.signaturePath != "/path/to/signature.sig" {
		t.Errorf("signaturePath = %q", flags.signaturePath)
	}
	if flags.signature != "base64sig" {
		t.Errorf("signature = %q", flags.signature)
	}
	if flags.hashAlgorithm != "sha384" {
		t.Errorf("hashAlgorithm = %q", flags.hashAlgorithm)
	}
	if flags.keyVersion != 3 {
		t.Errorf("keyVersion = %d", flags.keyVersion)
	}
}
