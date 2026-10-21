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

//go:build integration

package kms

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
)

// failingPlatformCTL returns an adapter whose platformctl exits 1 without
// output, so every call fails with the command line the adapter built.
func failingPlatformCTL(t *testing.T) *CLIAdapter {
	t.Helper()
	return scriptedPlatformCTL(t, "exit 1")
}

// scriptedPlatformCTL stands a shell script in for platformctl.
func scriptedPlatformCTL(t *testing.T, script string) *CLIAdapter {
	t.Helper()
	path := filepath.Join(t.TempDir(), "platformctl")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755))
	return NewCLIAdapterWithConfig(path, "", 10*time.Second)
}

// commandLine returns the command line of a failed CLI call.
func commandLine(t *testing.T, err error) string {
	t.Helper()
	var failed ErrCLICommandFailed
	require.True(t, errors.As(err, &failed), "want ErrCLICommandFailed, got %v", err)
	return failed.Command
}

func TestCLIAdapter_SendsTheDocumentedAESSpelling(t *testing.T) {
	adapter := failingPlatformCTL(t)
	ctx := context.Background()

	_, err := adapter.KeyGenerate(ctx, KeyGenerateOptions{KeyID: "k", Algorithm: "AES-256-GCM"})
	assert.Contains(t, commandLine(t, err), "kms key generate k --algorithm aes-256")

	_, err = adapter.DEKCreate(ctx, DEKCreateOptions{Path: "p", Algorithm: "AES-256-GCM"})
	assert.Contains(t, commandLine(t, err), "kms dek create p --algorithm aes-256")
}

func TestCLIKeyAlgorithm_EverySpellingParsesInTheCLI(t *testing.T) {
	for suiteName := range cliKeyAlgorithms {
		_, err := kmssvc.ParseKeyAlgorithm(suiteName)
		require.Error(t, err, "%s parses as is; the mapping is not needed", suiteName)

		_, err = kmssvc.ParseKeyAlgorithm(cliKeyAlgorithm(suiteName))
		assert.NoError(t, err, "%s -> %s", suiteName, cliKeyAlgorithm(suiteName))
	}
}

func TestCLIKeyAlgorithm_PassesOtherNamesThrough(t *testing.T) {
	assert.Equal(t, "ECDSA-P256", cliKeyAlgorithm("ECDSA-P256"))
	assert.Equal(t, "not-an-algorithm", cliKeyAlgorithm("not-an-algorithm"),
		"an unknown name reaches the CLI unchanged, so the CLI's own error reports it")
}

func TestCLIAdapter_RunCommandInputSelectsJSONAndPipesStdin(t *testing.T) {
	adapter := scriptedPlatformCTL(t, `printf '%s|%s|%s' "$PLATFORMCTL_OUTPUT" "$*" "$(cat)"`)

	output, err := adapter.runCommandInput(context.Background(), []byte("payload"), "kms", "crypto", "hash")
	require.NoError(t, err)
	assert.Equal(t, "json|kms crypto hash|payload", string(output))
}

func TestCLIAdapter_RunCommandInputReportsTheFailedCommand(t *testing.T) {
	adapter := failingPlatformCTL(t)

	_, err := adapter.runCommandInput(context.Background(), []byte("payload"), "kms", "crypto", "hash")
	assert.Equal(t, "kms crypto hash", commandLine(t, err))
}

func TestCLIAdapter_SendsTheDocumentedKeyAndCryptoFlags(t *testing.T) {
	adapter := failingPlatformCTL(t)
	ctx := context.Background()

	_, err := adapter.KeyStatus(ctx, "k", 2, false)
	assert.Equal(t, "kms key status disable k --version 2", commandLine(t, err))

	_, err = adapter.KeyRotate(ctx, "k", false)
	assert.Equal(t, "kms key rotate k --retain-old=false", commandLine(t, err))

	_, err = adapter.KeyPolicySet(ctx, "k", KeyPolicySetOptions{MaxUsageCount: 10})
	assert.Equal(t, "kms key policy set k --max-usage 10", commandLine(t, err))

	_, err = adapter.CryptoEncrypt(ctx, CryptoEncryptOptions{KeyID: "k", Plaintext: []byte("p"), Context: []byte("aad")})
	assert.Equal(t, "kms crypto encrypt --key-id k --context aad", commandLine(t, err))

	_, err = adapter.CryptoDecrypt(ctx, CryptoDecryptOptions{KeyID: "k", Ciphertext: []byte("c"), KeyVersion: 3})
	assert.Equal(t, "kms crypto decrypt --key-id k --key-version 3", commandLine(t, err))

	_, err = adapter.CryptoVerify(ctx, CryptoVerifyOptions{KeyID: "k", Message: []byte("m"), Signature: []byte{1}, KeyVersion: 4})
	assert.Equal(t, "kms crypto verify --key-id k --signature AQ== --key-version 4", commandLine(t, err))

	_, err = adapter.CryptoVerifyHMAC(ctx, CryptoVerifyHMACOptions{KeyID: "k", Message: []byte("m"), HMAC: []byte{1}, KeyVersion: 5})
	assert.Equal(t, "kms crypto hmac verify --key-id k --hmac AQ== --key-version 5", commandLine(t, err))

	_, err = adapter.CryptoHash(ctx, []byte("d"), "sha256")
	assert.Equal(t, "kms crypto hash --format base64 --algorithm sha256", commandLine(t, err))
}

func TestCLIAdapter_DecryptReadsThePlaintextRaw(t *testing.T) {
	adapter := scriptedPlatformCTL(t, `printf '{"key_id":"k","key_version":1,"plaintext":"hello","timestamp":"1700000000"}'`)

	result, err := adapter.CryptoDecrypt(context.Background(), CryptoDecryptOptions{KeyID: "k", Ciphertext: []byte("c")})
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), result.Plaintext)
	assert.Equal(t, time.Unix(1700000000, 0), result.Timestamp)
}

func TestCLIAdapter_RevokeReadsTheStatusBackFromMetadata(t *testing.T) {
	adapter := scriptedPlatformCTL(t, `case "$*" in
*"metadata get"*) printf '{"key_id":"k","status":"COMPROMISED","updated_at":"2026-10-21T12:00:00Z"}' ;;
*) printf '[SUCCESS] Key k revoked' ;;
esac`)

	result, err := adapter.KeyRevoke(context.Background(), "k", "exposed")
	require.NoError(t, err)
	assert.Equal(t, "k", result.KeyID)
	assert.Equal(t, "COMPROMISED", result.Status)
	assert.Equal(t, time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC), result.RevokedAt.UTC())
}

func TestCLIAdapter_RevokeFailsWhenMetadataIsUnreadable(t *testing.T) {
	adapter := scriptedPlatformCTL(t, `case "$*" in
*"metadata get"*) printf '{"key_id":"k","updated_at":"yesterday"}' ;;
*) printf '[SUCCESS] Key k revoked' ;;
esac`)

	_, err := adapter.KeyRevoke(context.Background(), "k", "exposed")
	var decodeErr ErrCLIFieldDecodeFailed
	require.True(t, errors.As(err, &decodeErr), "want ErrCLIFieldDecodeFailed, got %v", err)
	assert.Equal(t, "updated_at", decodeErr.Field)
}

func TestCLIAdapter_PolicySetReadsThePolicyBack(t *testing.T) {
	adapter := scriptedPlatformCTL(t, `case "$*" in
*"policy get"*) printf '{"key_id":"k","version":2,"max_usage_count":10000,"updated_at":"2026-10-21T12:00:00Z"}' ;;
*) printf '[SUCCESS] Policy updated' ;;
esac`)

	result, err := adapter.KeyPolicySet(context.Background(), "k", KeyPolicySetOptions{MaxUsageCount: 10000})
	require.NoError(t, err)
	assert.Equal(t, "k", result.KeyID)
	assert.Equal(t, int32(2), result.PolicyVersion)
}

func TestDecodeCLIBase64(t *testing.T) {
	decoded, err := decodeCLIBase64("Op", "field", "AQI=")
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2}, decoded)

	decoded, err = decodeCLIBase64("Op", "field", "")
	require.NoError(t, err)
	assert.Nil(t, decoded)
}

func TestDecodeCLIBase64_RejectsInvalidInput(t *testing.T) {
	_, err := decodeCLIBase64("Op", "field", "not base64!")
	var decodeErr ErrCLIFieldDecodeFailed
	require.True(t, errors.As(err, &decodeErr), "want ErrCLIFieldDecodeFailed, got %v", err)
	assert.Equal(t, "field", decodeErr.Field)
	assert.Error(t, decodeErr.Unwrap())
}

func TestParseCLIUnixTimestamp(t *testing.T) {
	parsed, err := parseCLIUnixTimestamp("Op", "1700000000")
	require.NoError(t, err)
	assert.Equal(t, time.Unix(1700000000, 0), parsed)

	parsed, err = parseCLIUnixTimestamp("Op", "-")
	require.NoError(t, err)
	assert.True(t, parsed.IsZero())
}

func TestParseCLIUnixTimestamp_RejectsNonNumericInput(t *testing.T) {
	_, err := parseCLIUnixTimestamp("Op", "2026-10-21")
	var decodeErr ErrCLIFieldDecodeFailed
	require.True(t, errors.As(err, &decodeErr), "want ErrCLIFieldDecodeFailed, got %v", err)
	assert.Equal(t, "timestamp", decodeErr.Field)
}

func TestParseCLIRFC3339(t *testing.T) {
	parsed, err := parseCLIRFC3339("Op", "created_at", "2026-10-21T12:00:00Z")
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC), parsed.UTC())

	parsed, err = parseCLIRFC3339("Op", "created_at", "")
	require.NoError(t, err)
	assert.True(t, parsed.IsZero())
}

func TestParseCLIRFC3339_RejectsUnixSeconds(t *testing.T) {
	_, err := parseCLIRFC3339("Op", "created_at", "1700000000")
	var decodeErr ErrCLIFieldDecodeFailed
	require.True(t, errors.As(err, &decodeErr), "want ErrCLIFieldDecodeFailed, got %v", err)
	assert.Equal(t, "created_at", decodeErr.Field)
}
