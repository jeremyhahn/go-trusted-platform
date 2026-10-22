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
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
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

	// kms dek create has no --algorithm: it always makes AES-256-GCM.
	_, err = adapter.DEKCreate(ctx, DEKCreateOptions{Path: "p", Algorithm: "AES-256-GCM"})
	line := commandLine(t, err)
	assert.Contains(t, line, "kms dek create p")
	assert.NotContains(t, line, "--algorithm")
}

func TestCLIAdapter_DEKRefusesOptionsWithoutACLIFlag(t *testing.T) {
	adapter := failingPlatformCTL(t)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
		want ErrCLINoFlag
	}{
		{"another algorithm", func() error {
			_, err := adapter.DEKCreate(ctx, DEKCreateOptions{Path: "p", Algorithm: "ChaCha20-Poly1305"})
			return err
		}, ErrCLINoFlag{Operation: "DEKCreate", Flag: "--algorithm"}},
		{"a description", func() error {
			_, err := adapter.DEKCreate(ctx, DEKCreateOptions{Path: "p", Description: "d"})
			return err
		}, ErrCLINoFlag{Operation: "DEKCreate", Flag: "--description"}},
		{"a list cursor", func() error {
			_, err := adapter.DEKList(ctx, DEKListOptions{Cursor: "c"})
			return err
		}, ErrCLINoFlag{Operation: "DEKList", Flag: "--cursor"}},
		{"a delete migrate-to", func() error {
			_, err := adapter.DEKDelete(ctx, "p", DEKDeleteOptions{MigrateTo: "q"})
			return err
		}, ErrCLINoFlag{Operation: "DEKDelete", Flag: "--migrate-to"}},
		{"a background rotation", func() error {
			_, err := adapter.DEKRotate(ctx, "p", true)
			return err
		}, ErrCLINoFlag{Operation: "DEKRotate", Flag: "--background"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// failingPlatformCTL fails every command it runs, so the typed
			// refusal proves no command ran.
			require.ErrorIs(t, tt.call(), tt.want)
		})
	}
}

func TestCLIAdapter_DEKCreateSendsLimitsOnCreate(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "create-args")
	adapter := scriptedPlatformCTL(t, `case "$*" in
*"dek create"*) echo "$*" > `+argsFile+`; printf '{"path":"p","algorithm":"AES-256-GCM","version":1,"status":"active","is_default":true,"created_at":"2026-10-21T12:00:00Z"}' ;;
*) exit 1 ;;
esac`)

	result, err := adapter.DEKCreate(context.Background(), DEKCreateOptions{
		Path: "p", Algorithm: "AES-256-GCM", MaxOperations: 1000, MaxBytes: 2000, WarningPercent: 75,
	})
	require.NoError(t, err)
	assert.Equal(t, "p", result.Path)
	assert.Equal(t, uint64(1), result.Version)
	assert.Equal(t, time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC), result.CreatedAt.UTC())

	sent, err := os.ReadFile(argsFile)
	require.NoError(t, err)
	assert.Equal(t, "kms dek create p --max-operations 1000 --max-bytes 2000 --warn-percent 75\n", string(sent),
		"one call: set-safety's SetDEKSafety is not served by the SDK's gRPC transport")
}

func TestCLIAdapter_DEKCreateReportsTheFailedCreate(t *testing.T) {
	adapter := failingPlatformCTL(t)

	_, err := adapter.DEKCreate(context.Background(), DEKCreateOptions{Path: "p", MaxOperations: 10})
	assert.Equal(t, "kms dek create p --max-operations 10", commandLine(t, err))
}

func TestCLIAdapter_DEKStatusReadsTheFlatJSON(t *testing.T) {
	adapter := scriptedPlatformCTL(t, `printf '{"path":"p","algorithm":"AES-256-GCM","version":2,"status":"active","is_default":true,`+
		`"created_at":"2026-10-21T12:00:00Z","rotated_at":"2026-10-21T13:00:00Z","usage_count":3,"bytes_used":4,`+
		`"max_usage_count":5000,"max_bytes_used":500000,"warning_percent":75,"backend_type":"software",`+
		`"reencryption":{"in_progress":true,"total_keys":10,"processed_keys":4,"failed_keys":1,"percent_complete":40,"started_at":"2026-10-21T13:30:00Z"}}'`)

	result, err := adapter.DEKStatus(context.Background(), "p")
	require.NoError(t, err)
	assert.Equal(t, "p", result.Path)
	assert.Equal(t, uint64(2), result.Version)
	assert.True(t, result.IsDefault)
	assert.Equal(t, time.Date(2026, 10, 21, 13, 0, 0, 0, time.UTC), result.RotatedAt.UTC())
	assert.Equal(t, uint64(5000), result.MaxUsageCount)
	assert.Equal(t, uint64(500000), result.MaxBytesUsed)
	assert.Equal(t, int32(75), result.WarningPercent)
	assert.Equal(t, "software", result.BackendType)
	assert.True(t, result.ReencryptionInProgress)
	assert.Equal(t, int64(10), result.TotalKeys)
	assert.Equal(t, int64(4), result.ProcessedKeys)
	assert.Equal(t, int64(1), result.FailedKeys)
	assert.Equal(t, time.Date(2026, 10, 21, 13, 30, 0, 0, time.UTC), result.ReencryptionStartedAt.UTC())
}

func TestCLIAdapter_DEKListReadsEveryDEK(t *testing.T) {
	adapter := scriptedPlatformCTL(t, `printf '{"deks":[`+
		`{"path":"a","algorithm":"AES-256-GCM","version":1,"status":"active","is_default":true,"created_at":"2026-10-21T12:00:00Z"},`+
		`{"path":"b","algorithm":"AES-256-GCM","version":3,"status":"active","is_default":false}],"total_count":2}'`)

	result, err := adapter.DEKList(context.Background(), DEKListOptions{Prefix: "/t", Limit: 2})
	require.NoError(t, err)
	require.Len(t, result.DEKs, 2)
	assert.Equal(t, "a", result.DEKs[0].Path)
	assert.Equal(t, time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC), result.DEKs[0].CreatedAt.UTC())
	assert.Equal(t, uint64(3), result.DEKs[1].Version)
	assert.True(t, result.DEKs[1].CreatedAt.IsZero(), "an omitted created_at reads as the zero time")
	assert.False(t, result.HasMore)
}

func TestCLIAdapter_DEKGetRejectsATimeThatIsNotRFC3339(t *testing.T) {
	adapter := scriptedPlatformCTL(t, `printf '{"path":"p","algorithm":"AES-256-GCM","version":1,"status":"active","is_default":true,"created_at":"1700000000"}'`)

	_, err := adapter.DEKGet(context.Background(), "p")
	var decode ErrCLIFieldDecodeFailed
	require.True(t, errors.As(err, &decode), "want ErrCLIFieldDecodeFailed, got %v", err)
	assert.Equal(t, "DEKGet", decode.Operation)
	assert.Equal(t, "created_at", decode.Field)
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

func TestCLIAdapter_HashReportsTheSuiteAlgorithmName(t *testing.T) {
	adapter := scriptedPlatformCTL(t, `cat >/dev/null; printf '{"algorithm":"SHA-256","hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","timestamp":"1700000000"}'`)

	result, err := adapter.CryptoHash(context.Background(), []byte("data"), "SHA256")
	require.NoError(t, err)
	assert.Equal(t, "SHA256", result.Algorithm, "the gRPC and QUIC adapters report SHA256")
	assert.Len(t, result.Hash, 32)
}

func TestCLIHashAlgorithmName_MapsWhatTheCLIPrints(t *testing.T) {
	printed := map[kmssvc.HashAlgorithm]string{
		kmssvc.HashAlgorithmSHA1:   "SHA1",
		kmssvc.HashAlgorithmSHA256: "SHA256",
		kmssvc.HashAlgorithmSHA384: "SHA384",
		kmssvc.HashAlgorithmSHA512: "SHA512",
	}
	for algorithm, want := range printed {
		assert.Equal(t, want, cliHashAlgorithmName(string(algorithm)), "%s", algorithm)
	}
}

func TestCLIHashAlgorithmName_PassesOtherNamesThrough(t *testing.T) {
	assert.Equal(t, "SHA3-256", cliHashAlgorithmName(string(kmssvc.HashAlgorithmSHA3256)))
	assert.Equal(t, "not-a-hash", cliHashAlgorithmName("not-a-hash"),
		"an unknown name is reported as printed, so the assertion names it")
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

func TestCLIAdapter_SecretsStoreSendsTheDocumentedFlags(t *testing.T) {
	adapter := failingPlatformCTL(t)
	ctx := context.Background()

	_, err := adapter.SecretsStore(ctx, SecretsStoreOptions{Name: "n", Data: []byte("pw"), Description: "d"})
	assert.Equal(t, "kms secrets store n --value cHc= --base64 --description d", commandLine(t, err))
}

func TestCLIAdapter_SecretsStoreRefusesAFlagItHasNoFlagFor(t *testing.T) {
	adapter := failingPlatformCTL(t)
	ctx := context.Background()

	for _, opts := range []SecretsStoreOptions{
		{Name: "n", TenantID: "t"},
		{Name: "n", KeyID: "k"},
		{Name: "n", Algorithm: "aes-256"},
	} {
		_, err := adapter.SecretsStore(ctx, opts)
		var noFlag helpers.ErrCLINoFlag
		require.True(t, errors.As(err, &noFlag), "want ErrCLINoFlag, got %v", err)
	}
}

func TestCLIAdapter_SecretsSendsTheDocumentedVerbs(t *testing.T) {
	adapter := failingPlatformCTL(t)
	ctx := context.Background()

	_, err := adapter.SecretsRotate(ctx, SecretsRotateOptions{Name: "n", NewData: []byte("pw")})
	assert.Equal(t, "kms secrets rotate n --value cHc= --base64", commandLine(t, err))

	_, err = adapter.SecretsVersion(ctx, "n", 3)
	assert.Equal(t, "kms secrets version n 3", commandLine(t, err))

	_, err = adapter.SecretsVersions(ctx, "n", SecretsVersionsOptions{Limit: 10})
	assert.Equal(t, "kms secrets versions n", commandLine(t, err))

	_, err = adapter.SecretsRollback(ctx, "n", 1)
	assert.Equal(t, "kms secrets rollback n 1", commandLine(t, err))

	_, err = adapter.SecretsStatus(ctx, "n", true)
	assert.Equal(t, "kms secrets status enable n", commandLine(t, err))

	_, err = adapter.SecretsStatus(ctx, "n", false)
	assert.Equal(t, "kms secrets status disable n", commandLine(t, err))

	_, err = adapter.SecretsDelete(ctx, "n", true)
	assert.Equal(t, "kms secrets delete n", commandLine(t, err))

	_, err = adapter.SecretsList(ctx, SecretsListOptions{Limit: 5})
	assert.Equal(t, "kms secrets list --limit 5", commandLine(t, err))
}

func TestCLIAdapter_SecretsListRefusesCursor(t *testing.T) {
	adapter := failingPlatformCTL(t)
	ctx := context.Background()

	_, err := adapter.SecretsList(ctx, SecretsListOptions{Cursor: "c"})
	var noFlag helpers.ErrCLINoFlag
	require.True(t, errors.As(err, &noFlag), "want ErrCLINoFlag, got %v", err)
	assert.Equal(t, "--cursor", noFlag.Flag)

	_, err = adapter.SecretsVersions(ctx, "n", SecretsVersionsOptions{Cursor: "c"})
	require.True(t, errors.As(err, &noFlag), "want ErrCLINoFlag, got %v", err)
}

func TestCLIAdapter_SecretsGetReadsTheStoredBytes(t *testing.T) {
	adapter := scriptedPlatformCTL(t, `printf '{"name":"n","version":2,"value":"dGVzdA==","description":"d","created_at":"2026-10-21T12:00:00Z"}'`)

	result, err := adapter.SecretsGet(context.Background(), "n")
	require.NoError(t, err)
	assert.Equal(t, "n", result.SecretID)
	assert.Equal(t, uint64(2), result.Version)
	assert.Equal(t, []byte("test"), result.Data)
	assert.Equal(t, time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC), result.CreatedAt.UTC())
}

func TestCLIAdapter_SecretsGetFailsWhenTheVerbPrintsNoJSON(t *testing.T) {
	adapter := scriptedPlatformCTL(t, `echo "not json"`)

	_, err := adapter.SecretsGet(context.Background(), "n")
	var malformed helpers.ErrSecretsCLIOutput
	require.True(t, errors.As(err, &malformed), "want ErrSecretsCLIOutput, got %v", err)
	assert.Equal(t, "get", malformed.Operation)
}

func TestCLIAdapter_SecretsRotateReportsTheEmbeddedTransportGap(t *testing.T) {
	adapter := scriptedPlatformCTL(t, `echo "embedded: unknown method: quicbaas.Secrets.Rotate" >&2; exit 1`)

	_, err := adapter.SecretsRotate(context.Background(), SecretsRotateOptions{Name: "n", NewData: []byte("pw")})
	var gap helpers.ErrCLIUpstreamGap
	require.True(t, errors.As(err, &gap), "want ErrCLIUpstreamGap, got %v", err)
	assert.Equal(t, helpers.SecretsSDKGapIssue, gap.Issue)
}

func TestCLIAdapter_SecretsListReadsNamesAndVersionsDecode(t *testing.T) {
	lister := scriptedPlatformCTL(t, `case "$*" in
*"secrets list"*) printf '{"secrets":["a","b"],"has_more":true}' ;;
*"secrets versions"*) printf '{"name":"n","versions":[{"version":1,"created_by":"b","created_at":"2026-10-21T12:00:00Z"}]}' ;;
*) exit 1 ;;
esac`)

	ctx := context.Background()

	list, err := lister.SecretsList(ctx, SecretsListOptions{})
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, []string{list.Secrets[0].Name, list.Secrets[1].Name})
	assert.Equal(t, int32(2), list.TotalCount)
	assert.True(t, list.HasMore)

	versions, err := lister.SecretsVersions(ctx, "n", SecretsVersionsOptions{})
	require.NoError(t, err)
	assert.Equal(t, "n", versions.SecretID)
	require.Len(t, versions.Versions, 1)
	assert.Equal(t, uint64(1), versions.Versions[0].Version)
	assert.Equal(t, "b", versions.Versions[0].CreatedBy)
	assert.Equal(t, time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC), versions.Versions[0].CreatedAt.UTC())
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
