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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// Tests for key_import.go functions

func TestParseWrappingAlgorithm_ValidAlgorithms(t *testing.T) {
	tests := []struct {
		input    string
		expected pb.WrappingAlgorithm
	}{
		{"aes-kw", pb.WrappingAlgorithm_WRAP_ALG_AES_KW},
		{"aeskw", pb.WrappingAlgorithm_WRAP_ALG_AES_KW},
		{"AES-KW", pb.WrappingAlgorithm_WRAP_ALG_AES_KW},
		{"aes-kwp", pb.WrappingAlgorithm_WRAP_ALG_AES_KWP},
		{"aeskwp", pb.WrappingAlgorithm_WRAP_ALG_AES_KWP},
		{"aes-gcm", pb.WrappingAlgorithm_WRAP_ALG_AES_GCM},
		{"aesgcm", pb.WrappingAlgorithm_WRAP_ALG_AES_GCM},
		{"rsa-oaep-sha256", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256},
		{"rsaoaepsha256", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256},
		{"RSA-OAEP-SHA256", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256},
		{"rsa-oaep-sha384", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384},
		{"rsaoaepsha384", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384},
		{"rsa-oaep-sha512", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512},
		{"rsaoaepsha512", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512},
		{"ecdh-es-a256kw", pb.WrappingAlgorithm_WRAP_ALG_ECDH_ES_A256KW},
		{"ecdhesa256kw", pb.WrappingAlgorithm_WRAP_ALG_ECDH_ES_A256KW},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseWrappingAlgorithm(tt.input)
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("parseWrappingAlgorithm(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseWrappingAlgorithm_InvalidAlgorithms(t *testing.T) {
	invalidInputs := []string{
		"",
		"invalid",
		"aes",
		"rsa-oaep",
		"unknown-algorithm",
		"aes-256-gcm",
	}

	for _, input := range invalidInputs {
		t.Run(input, func(t *testing.T) {
			result, err := parseWrappingAlgorithm(input)
			if err == nil {
				t.Errorf("expected error for %q, got result %v", input, result)
			}
			if _, ok := err.(ErrInvalidWrappingAlgorithm); !ok {
				t.Errorf("expected ErrInvalidWrappingAlgorithm for %q, got %T", input, err)
			}
		})
	}
}

func TestFormatWrappingAlgorithm_AllAlgorithms(t *testing.T) {
	tests := []struct {
		input    pb.WrappingAlgorithm
		expected string
	}{
		{pb.WrappingAlgorithm_WRAP_ALG_AES_KW, "AES-KW"},
		{pb.WrappingAlgorithm_WRAP_ALG_AES_KWP, "AES-KWP"},
		{pb.WrappingAlgorithm_WRAP_ALG_AES_GCM, "AES-GCM"},
		{pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256, "RSA-OAEP-SHA256"},
		{pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384, "RSA-OAEP-SHA384"},
		{pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512, "RSA-OAEP-SHA512"},
		{pb.WrappingAlgorithm_WRAP_ALG_ECDH_ES_A256KW, "ECDH-ES+A256KW"},
		{pb.WrappingAlgorithm_WRAP_ALG_UNSPECIFIED, "UNSPECIFIED"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatWrappingAlgorithm(tt.input)
			if result != tt.expected {
				t.Errorf("formatWrappingAlgorithm(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseExportFormat_ValidFormats(t *testing.T) {
	tests := []struct {
		input    string
		expected pb.ExportFormat
	}{
		{"raw", pb.ExportFormat_EXPORT_FORMAT_RAW},
		{"RAW", pb.ExportFormat_EXPORT_FORMAT_RAW},
		{"jwk", pb.ExportFormat_EXPORT_FORMAT_JWK},
		{"JWK", pb.ExportFormat_EXPORT_FORMAT_JWK},
		{"pem", pb.ExportFormat_EXPORT_FORMAT_PEM},
		{"PEM", pb.ExportFormat_EXPORT_FORMAT_PEM},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseExportFormat(tt.input)
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("parseExportFormat(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseExportFormat_InvalidFormats(t *testing.T) {
	invalidInputs := []string{
		"",
		"invalid",
		"der",
		"pkcs8",
		"unknown",
	}

	for _, input := range invalidInputs {
		t.Run(input, func(t *testing.T) {
			result, err := parseExportFormat(input)
			if err == nil {
				t.Errorf("expected error for %q, got result %v", input, result)
			}
			if _, ok := err.(ErrInvalidExportFormat); !ok {
				t.Errorf("expected ErrInvalidExportFormat for %q, got %T", input, err)
			}
		})
	}
}

func TestFormatExportFormat_AllFormats(t *testing.T) {
	tests := []struct {
		input    pb.ExportFormat
		expected string
	}{
		{pb.ExportFormat_EXPORT_FORMAT_RAW, "RAW"},
		{pb.ExportFormat_EXPORT_FORMAT_JWK, "JWK"},
		{pb.ExportFormat_EXPORT_FORMAT_PEM, "PEM"},
		{pb.ExportFormat_EXPORT_FORMAT_UNSPECIFIED, "UNSPECIFIED"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatExportFormat(tt.input)
			if result != tt.expected {
				t.Errorf("formatExportFormat(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// Tests for key_policy.go functions

func TestParseDuration_ValidDurations(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"1h", time.Hour},
		{"24h", 24 * time.Hour},
		{"30m", 30 * time.Minute},
		{"1s", time.Second},
		{"1d", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
		{"365d", 365 * 24 * time.Hour},
		{"2h30m", 2*time.Hour + 30*time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseDuration(tt.input)
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("parseDuration(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseDuration_InvalidDurations(t *testing.T) {
	invalidInputs := []string{
		"",
		"invalid",
		"abc",
		"1y", // years not supported
		"-1d",
	}

	for _, input := range invalidInputs {
		t.Run(input, func(t *testing.T) {
			_, err := parseDuration(input)
			if err == nil {
				t.Errorf("expected error for %q", input)
			}
		})
	}
}

// Tests for error types that are not covered in other test files

func TestErrInvalidWrappingAlgorithm_Error(t *testing.T) {
	err := ErrInvalidWrappingAlgorithm{Algorithm: "test-alg"}
	errStr := err.Error()

	if !strings.Contains(errStr, "invalid wrapping algorithm") {
		t.Errorf("error message %q should contain 'invalid wrapping algorithm'", errStr)
	}
	if !strings.Contains(errStr, "test-alg") {
		t.Errorf("error message %q should contain 'test-alg'", errStr)
	}
}

func TestErrInvalidExportFormat_Error(t *testing.T) {
	err := ErrInvalidExportFormat{Format: "bad-format"}
	errStr := err.Error()

	if !strings.Contains(errStr, "invalid export format") {
		t.Errorf("error message %q should contain 'invalid export format'", errStr)
	}
	if !strings.Contains(errStr, "bad-format") {
		t.Errorf("error message %q should contain 'bad-format'", errStr)
	}
}

func TestErrSetKeyPolicyFailed_Error(t *testing.T) {
	err := ErrSetKeyPolicyFailed{KeyID: "my-key", Err: ErrInvalidKeyAlgorithm{Algorithm: "test"}}
	errStr := err.Error()

	if !strings.Contains(errStr, "failed to set policy") {
		t.Errorf("error message %q should contain 'failed to set policy'", errStr)
	}
	if !strings.Contains(errStr, "my-key") {
		t.Errorf("error message %q should contain 'my-key'", errStr)
	}
}

func TestErrInvalidDuration_Error(t *testing.T) {
	err := ErrInvalidDuration{Value: "1y", Err: ErrInvalidKeyAlgorithm{Algorithm: "test"}}
	errStr := err.Error()

	if !strings.Contains(errStr, "invalid duration format") {
		t.Errorf("error message %q should contain 'invalid duration format'", errStr)
	}
	if !strings.Contains(errStr, "1y") {
		t.Errorf("error message %q should contain '1y'", errStr)
	}
}

func TestErrKeyRevokeFailed_Error(t *testing.T) {
	err := ErrKeyRevokeFailed{KeyID: "my-key", Err: ErrInvalidKeyAlgorithm{Algorithm: "test"}}
	errStr := err.Error()

	if !strings.Contains(errStr, "failed to revoke key") {
		t.Errorf("error message %q should contain 'failed to revoke key'", errStr)
	}
	if !strings.Contains(errStr, "my-key") {
		t.Errorf("error message %q should contain 'my-key'", errStr)
	}
}

func TestErrRevocationReasonRequired_Error(t *testing.T) {
	err := ErrRevocationReasonRequired{}
	errStr := err.Error()

	if !strings.Contains(errStr, "revocation reason is required") {
		t.Errorf("error message %q should contain 'revocation reason is required'", errStr)
	}
}

func TestErrSetKeySafetyFailed_Error(t *testing.T) {
	err := ErrSetKeySafetyFailed{KeyID: "my-key", Err: ErrInvalidKeyAlgorithm{Algorithm: "test"}}
	errStr := err.Error()

	if !strings.Contains(errStr, "failed to set safety limits") {
		t.Errorf("error message %q should contain 'failed to set safety limits'", errStr)
	}
	if !strings.Contains(errStr, "my-key") {
		t.Errorf("error message %q should contain 'my-key'", errStr)
	}
}

func TestErrClearKeySafetyFailed_Error(t *testing.T) {
	err := ErrClearKeySafetyFailed{KeyID: "my-key", Err: ErrInvalidKeyAlgorithm{Algorithm: "test"}}
	errStr := err.Error()

	if !strings.Contains(errStr, "failed to clear safety limits") {
		t.Errorf("error message %q should contain 'failed to clear safety limits'", errStr)
	}
	if !strings.Contains(errStr, "my-key") {
		t.Errorf("error message %q should contain 'my-key'", errStr)
	}
}

func TestErrSafetyCheckFailed_Error(t *testing.T) {
	err := ErrSafetyCheckFailed{Err: ErrInvalidKeyAlgorithm{Algorithm: "test"}}
	errStr := err.Error()

	if !strings.Contains(errStr, "failed to perform safety check") {
		t.Errorf("error message %q should contain 'failed to perform safety check'", errStr)
	}
}

func TestErrSafetyReportFailed_Error(t *testing.T) {
	err := ErrSafetyReportFailed{Err: ErrInvalidKeyAlgorithm{Algorithm: "test"}}
	errStr := err.Error()

	if !strings.Contains(errStr, "failed to generate safety report") {
		t.Errorf("error message %q should contain 'failed to generate safety report'", errStr)
	}
}

// Tests for batch parsing functions

func TestParseBatchEncryptInput_FromFile_JSON(t *testing.T) {
	tempDir := t.TempDir()
	inputFile := filepath.Join(tempDir, "input.json")

	items := []BatchEncryptItem{
		{Plaintext: "secret1"},
		{Plaintext: "secret2"},
		{Plaintext: "secret3"},
	}

	data, err := json.Marshal(items)
	if err != nil {
		t.Fatalf("failed to marshal items: %v", err)
	}

	if err := os.WriteFile(inputFile, data, 0600); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}

	result, err := parseBatchEncryptInput(inputFile, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != len(items) {
		t.Errorf("expected %d items, got %d", len(items), len(result))
	}

	for i, item := range result {
		if item.Plaintext != items[i].Plaintext {
			t.Errorf("item %d: expected %q, got %q", i, items[i].Plaintext, item.Plaintext)
		}
	}
}

func TestParseBatchEncryptInput_FromFile_Lines(t *testing.T) {
	tempDir := t.TempDir()
	inputFile := filepath.Join(tempDir, "input.txt")

	lines := []string{"secret1", "secret2", "secret3"}
	data := []byte(strings.Join(lines, "\n"))

	if err := os.WriteFile(inputFile, data, 0600); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}

	result, err := parseBatchEncryptInput(inputFile, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != len(lines) {
		t.Errorf("expected %d items, got %d", len(lines), len(result))
	}

	for i, item := range result {
		if item.Plaintext != lines[i] {
			t.Errorf("item %d: expected %q, got %q", i, lines[i], item.Plaintext)
		}
	}
}

func TestParseBatchEncryptInput_InvalidJSON_FromFile(t *testing.T) {
	tempDir := t.TempDir()
	inputFile := filepath.Join(tempDir, "input.json")

	if err := os.WriteFile(inputFile, []byte("not valid json"), 0600); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}

	_, err := parseBatchEncryptInput(inputFile, true)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
	if _, ok := err.(ErrInvalidBatchFormat); !ok {
		t.Errorf("expected ErrInvalidBatchFormat, got %T", err)
	}
}

func TestParseBatchEncryptInput_NonexistentFile(t *testing.T) {
	_, err := parseBatchEncryptInput("/nonexistent/path/file.json", true)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	if _, ok := err.(ErrInvalidInputFile); !ok {
		t.Errorf("expected ErrInvalidInputFile, got %T", err)
	}
}

func TestParseBatchDecryptInput_FromFile_JSON(t *testing.T) {
	tempDir := t.TempDir()
	inputFile := filepath.Join(tempDir, "input.json")

	items := []BatchDecryptItem{
		{Ciphertext: "encrypted1"},
		{Ciphertext: "encrypted2"},
	}

	data, err := json.Marshal(items)
	if err != nil {
		t.Fatalf("failed to marshal items: %v", err)
	}

	if err := os.WriteFile(inputFile, data, 0600); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}

	result, err := parseBatchDecryptInput(inputFile, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != len(items) {
		t.Errorf("expected %d items, got %d", len(items), len(result))
	}

	for i, item := range result {
		if item.Ciphertext != items[i].Ciphertext {
			t.Errorf("item %d: expected %q, got %q", i, items[i].Ciphertext, item.Ciphertext)
		}
	}
}

func TestParseBatchDecryptInput_InvalidJSON_FromFile(t *testing.T) {
	tempDir := t.TempDir()
	inputFile := filepath.Join(tempDir, "input.json")

	if err := os.WriteFile(inputFile, []byte("not valid json"), 0600); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}

	_, err := parseBatchDecryptInput(inputFile, true)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
	if _, ok := err.(ErrInvalidBatchFormat); !ok {
		t.Errorf("expected ErrInvalidBatchFormat, got %T", err)
	}
}

// Test command structure for extended key commands

func TestKeyExportCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyExportCommand(getFlags)

	// Check required flags exist
	if cmd.Flags().Lookup("wrapping-key") == nil {
		t.Error("missing --wrapping-key flag")
	}
	if cmd.Flags().Lookup("wrapping-algorithm") == nil {
		t.Error("missing --wrapping-algorithm flag")
	}
	if cmd.Flags().Lookup("format") == nil {
		t.Error("missing --format flag")
	}
	if cmd.Flags().Lookup("version") == nil {
		t.Error("missing --version flag")
	}
	if cmd.Flags().Lookup("output-file") == nil {
		t.Error("missing --output-file flag")
	}
}

func TestKeyUnwrapCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyUnwrapCommand(getFlags)

	// Check flags exist
	if cmd.Flags().Lookup("key-id") == nil {
		t.Error("missing --key-id flag")
	}
	if cmd.Flags().Lookup("wrapping-key") == nil {
		t.Error("missing --wrapping-key flag")
	}
	if cmd.Flags().Lookup("algorithm") == nil {
		t.Error("missing --algorithm flag")
	}
}

func TestKeyVersionsCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyVersionsCommand(getFlags)

	// Check flags exist
	if cmd.Flags().Lookup("limit") == nil {
		t.Error("missing --limit flag")
	}
	if cmd.Flags().Lookup("cursor") == nil {
		t.Error("missing --cursor flag")
	}
}

func TestKeySafetySetCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeySafetySetCommand(getFlags)

	// Check flags exist
	if cmd.Flags().Lookup("max-operations") == nil {
		t.Error("missing --max-operations flag")
	}
	if cmd.Flags().Lookup("max-bytes") == nil {
		t.Error("missing --max-bytes flag")
	}
	if cmd.Flags().Lookup("warning-percent") == nil {
		t.Error("missing --warning-percent flag")
	}
}

func TestKeyPolicySetCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyPolicySetCommand(getFlags)

	// Check flags exist
	if cmd.Flags().Lookup("allow-principal") == nil {
		t.Error("missing --allow flag")
	}
	if cmd.Flags().Lookup("deny-principal") == nil {
		t.Error("missing --deny flag")
	}
	if cmd.Flags().Lookup("expires-in") == nil {
		t.Error("missing --expires-in flag")
	}
}

func TestKeyMetadataUpdateCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyMetadataUpdateCommand(getFlags)

	// Check flags exist
	if cmd.Flags().Lookup("name") == nil {
		t.Error("missing --name flag")
	}
	if cmd.Flags().Lookup("description") == nil {
		t.Error("missing --description flag")
	}
	if cmd.Flags().Lookup("tag") == nil {
		t.Error("missing --tag flag")
	}
}

// Test that all key subcommands have proper structure

func TestKeyCommand_AllExtendedSubcommandsPresent(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewKeyCommand(getFlags)

	// Get all actual subcommand names
	actualSubcommands := make(map[string]bool)
	for _, subcmd := range cmd.Commands() {
		actualSubcommands[subcmd.Name()] = true
	}

	// Check for required subcommands
	requiredSubcommands := []string{
		"generate", "get", "list", "delete", "rotate",
		"export", "import", "versions", "revoke",
		"status", "metadata", "policy", "safety",
		"algorithms", "backend-test", "unwrap",
	}

	for _, expected := range requiredSubcommands {
		if !actualSubcommands[expected] {
			t.Errorf("missing subcommand: %s", expected)
		}
	}
}
