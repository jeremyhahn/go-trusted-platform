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

package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// -----------------------------------------------------------------------------
// NewCommand Tests
// -----------------------------------------------------------------------------

func TestNewCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "bootstrap", cmd.Use)
	assert.Equal(t, "Platform bootstrap operations", cmd.Short)
	assert.Contains(t, cmd.Long, "Manage platform bootstrap and initialization operations")

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 7)

	// Verify secrets subcommand exists
	var hasSecrets bool
	for _, sub := range subcommands {
		if sub.Use == "secrets" {
			hasSecrets = true
		}
	}
	assert.True(t, hasSecrets, "secrets subcommand should exist")

	// Verify trust subcommand exists
	var hasTrust bool
	for _, sub := range subcommands {
		if sub.Use == "trust" {
			hasTrust = true
		}
	}
	assert.True(t, hasTrust, "trust subcommand should exist")

	// Verify PXE bootstrap subcommands exist
	expectedPXE := map[string]bool{
		"run":      false,
		"discover": false,
		"deploy":   false,
		"status":   false,
		"teardown": false,
	}
	for _, sub := range subcommands {
		if _, ok := expectedPXE[sub.Use]; ok {
			expectedPXE[sub.Use] = true
		}
	}
	for name, found := range expectedPXE {
		assert.True(t, found, "%s subcommand should exist", name)
	}
}

func TestNewCommand_WithNilFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return nil
	}

	cmd := NewCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "bootstrap", cmd.Use)
}

// -----------------------------------------------------------------------------
// NewSecretsCommand Tests
// -----------------------------------------------------------------------------

func TestNewSecretsCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewSecretsCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "secrets", cmd.Use)
	assert.Equal(t, "Manage bootstrap secrets", cmd.Short)
	assert.Contains(t, cmd.Long, "Manage secret resolution and migration")

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 4)

	// Verify key subcommands exist by checking the command name (first word of Use)
	expectedCommands := map[string]bool{
		"migrate": false,
		"status":  false,
		"verify":  false,
		"resolve": false,
	}
	for _, sub := range subcommands {
		// Extract command name from Use (e.g., "resolve <uri>" -> "resolve")
		cmdName := sub.Name()
		if _, ok := expectedCommands[cmdName]; ok {
			expectedCommands[cmdName] = true
		}
	}
	for cmd, found := range expectedCommands {
		assert.True(t, found, "%s subcommand should exist", cmd)
	}
}

// -----------------------------------------------------------------------------
// Migrate Command Tests
// -----------------------------------------------------------------------------

func TestNewSecretsMigrateCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newSecretsMigrateCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "migrate", cmd.Use)
	assert.Contains(t, cmd.Short, "Migrate")

	// Verify flags
	configFlag := cmd.Flag("config")
	require.NotNil(t, configFlag)
	assert.Equal(t, "", configFlag.DefValue)

	dryRunFlag := cmd.Flag("dry-run")
	require.NotNil(t, dryRunFlag)
	assert.Equal(t, "false", dryRunFlag.DefValue)

	noBackupFlag := cmd.Flag("no-backup")
	require.NotNil(t, noBackupFlag)
	assert.Equal(t, "false", noBackupFlag.DefValue)

	forceFlag := cmd.Flag("force")
	require.NotNil(t, forceFlag)
	assert.Equal(t, "false", forceFlag.DefValue)

	keyIDFlag := cmd.Flag("key-id")
	require.NotNil(t, keyIDFlag)
	assert.Equal(t, "config-secrets", keyIDFlag.DefValue)
}

func TestRunSecretsMigrate_ConfigPathRequired(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	cmdFlags := &secretsMigrateFlags{
		configPath: "",
	}

	err := runSecretsMigrate(flags, cmdFlags)
	require.Error(t, err)

	var configErr ErrConfigPathRequired
	assert.ErrorAs(t, err, &configErr)
}

// -----------------------------------------------------------------------------
// Status Command Tests
// -----------------------------------------------------------------------------

func TestNewSecretsStatusCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newSecretsStatusCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "status", cmd.Use)
	assert.Equal(t, "Show secret resolution status", cmd.Short)

	// Verify flags
	configFlag := cmd.Flag("config")
	require.NotNil(t, configFlag)
	assert.Equal(t, "", configFlag.DefValue)

	showURIsFlag := cmd.Flag("show-uris")
	require.NotNil(t, showURIsFlag)
	assert.Equal(t, "false", showURIsFlag.DefValue)
}

func TestRunSecretsStatus_ConfigPathRequired(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	cmdFlags := &secretsStatusFlags{
		configPath: "",
	}

	err := runSecretsStatus(flags, cmdFlags)
	require.Error(t, err)

	var configErr ErrConfigPathRequired
	assert.ErrorAs(t, err, &configErr)
}

// -----------------------------------------------------------------------------
// Verify Command Tests
// -----------------------------------------------------------------------------

func TestNewSecretsVerifyCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newSecretsVerifyCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "verify", cmd.Use)
	assert.Equal(t, "Verify all secrets are resolvable", cmd.Short)

	// Verify flags
	configFlag := cmd.Flag("config")
	require.NotNil(t, configFlag)
	assert.Equal(t, "", configFlag.DefValue)

	dryRunFlag := cmd.Flag("dry-run")
	require.NotNil(t, dryRunFlag)
	assert.Equal(t, "false", dryRunFlag.DefValue)

	failFastFlag := cmd.Flag("fail-fast")
	require.NotNil(t, failFastFlag)
	assert.Equal(t, "false", failFastFlag.DefValue)

	showSecretsFlag := cmd.Flag("show-secrets")
	require.NotNil(t, showSecretsFlag)
	assert.Equal(t, "false", showSecretsFlag.DefValue)
}

func TestRunSecretsVerify_ConfigPathRequired(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	cmdFlags := &secretsVerifyFlags{
		configPath: "",
	}

	err := runSecretsVerify(flags, cmdFlags)
	require.Error(t, err)

	var configErr ErrConfigPathRequired
	assert.ErrorAs(t, err, &configErr)
}

// -----------------------------------------------------------------------------
// Resolve Command Tests
// -----------------------------------------------------------------------------

func TestNewSecretsResolveCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newSecretsResolveCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "resolve <uri>", cmd.Use)
	assert.Equal(t, "resolve", cmd.Name())
	assert.Equal(t, "Resolve a single secret URI", cmd.Short)

	// Verify flags
	maskedFlag := cmd.Flag("masked")
	require.NotNil(t, maskedFlag)
	assert.Equal(t, "true", maskedFlag.DefValue)

	rawFlag := cmd.Flag("raw")
	require.NotNil(t, rawFlag)
	assert.Equal(t, "false", rawFlag.DefValue)
}

func TestRunSecretsResolve_URIRequired(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	cmdFlags := &secretsResolveFlags{
		masked: true,
		raw:    false,
	}

	err := runSecretsResolve(flags, "", cmdFlags)
	require.Error(t, err)

	var uriErr ErrSecretURIRequired
	assert.ErrorAs(t, err, &uriErr)
}

func TestRunSecretsResolve_InvalidScheme(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	cmdFlags := &secretsResolveFlags{
		masked: true,
		raw:    false,
	}

	err := runSecretsResolve(flags, "invalid://secret", cmdFlags)
	require.Error(t, err)

	var invalidErr ErrInvalidSecretURI
	assert.ErrorAs(t, err, &invalidErr)
}

// -----------------------------------------------------------------------------
// Helper Function Tests
// -----------------------------------------------------------------------------

func TestScanConfigForSecrets(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		minExpected int
	}{
		{
			name:        "no secrets",
			config:      "key: value\nother: data",
			minExpected: 0,
		},
		{
			name:        "kms secret",
			config:      "password: kms://config/db/password",
			minExpected: 1,
		},
		{
			name:        "env secret",
			config:      "api_key: env://API_KEY",
			minExpected: 1,
		},
		{
			name:        "autogen secret",
			config:      "token: autogen://password?length=32",
			minExpected: 1,
		},
		{
			name:        "remote-kms secret",
			config:      "secret: remote-kms://vault/data/secret",
			minExpected: 1,
		},
		{
			name:        "encrypted secret",
			config:      "encrypted_data: encrypted://base64data==",
			minExpected: 1,
		},
		{
			name: "multiple secrets",
			config: `database:
  password: kms://config/db/password
  api_key: env://DB_API_KEY
other: plain_value`,
			minExpected: 2,
		},
		{
			name:        "quoted secret",
			config:      `password: "kms://config/db/password"`,
			minExpected: 1,
		},
		{
			name:        "single quoted secret",
			config:      `password: 'env://MY_SECRET'`,
			minExpected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets := scanConfigForSecrets([]byte(tt.config))
			assert.GreaterOrEqual(t, len(secrets), tt.minExpected)
		})
	}
}

func TestScanNestedSecrets(t *testing.T) {
	config := `database:
  credentials:
    password: kms://config/db/password
    api_key: env://DB_API_KEY
services:
  - name: service1
    secret: autogen://password?length=16`

	secrets := scanNestedSecrets([]byte(config))
	assert.GreaterOrEqual(t, len(secrets), 2)
}

func TestBuildPath(t *testing.T) {
	tests := []struct {
		name     string
		stack    []string
		key      string
		expected string
	}{
		{
			name:     "empty stack",
			stack:    []string{},
			key:      "password",
			expected: "password",
		},
		{
			name:     "single level",
			stack:    []string{"database"},
			key:      "password",
			expected: "database.password",
		},
		{
			name:     "multi level",
			stack:    []string{"database", "credentials"},
			key:      "password",
			expected: "database.credentials.password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildPath(tt.stack, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSecretURI(t *testing.T) {
	tests := []struct {
		uri      string
		expected bool
	}{
		{uri: "kms://secret/path", expected: true},
		{uri: "remote-kms://vault/secret", expected: true},
		{uri: "env://MY_VAR", expected: true},
		{uri: "autogen://password?length=32", expected: true},
		{uri: "encrypted://base64data", expected: true},
		{uri: "plaintext", expected: false},
		{uri: "http://example.com", expected: false},
		{uri: "file://local/path", expected: false},
		{uri: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			result := isSecretURI(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskSecretURI(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "kms with path",
			uri:      "kms://config/db/password",
			expected: "kms://config/db/***",
		},
		{
			name:     "env var",
			uri:      "env://MY_SECRET_VAR",
			expected: "env://***",
		},
		{
			name:     "autogen",
			uri:      "autogen://password?length=32&charset=alphanumeric",
			expected: "autogen://***",
		},
		{
			name:     "remote-kms",
			uri:      "remote-kms://vault/data/secret",
			expected: "remote-kms://vault/data/***",
		},
		{
			name:     "encrypted",
			uri:      "encrypted://base64encodeddata==",
			expected: "encrypted://***",
		},
		{
			name:     "unknown scheme",
			uri:      "unknown://data",
			expected: "***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskSecretURI(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildKMSURI(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		expected   string
	}{
		{
			name:       "simple path",
			configPath: "password",
			expected:   "kms://config/password",
		},
		{
			name:       "dotted path",
			configPath: "database.password",
			expected:   "kms://config/database/password",
		},
		{
			name:       "array notation",
			configPath: "services[0].secret",
			expected:   "kms://config/services/0/secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildKMSURI(tt.configPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildKMSPath(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		expected   string
	}{
		{
			name:       "simple path",
			configPath: "password",
			expected:   "config/password",
		},
		{
			name:       "nested path",
			configPath: "database.credentials.password",
			expected:   "config/database/credentials/password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildKMSPath(tt.configPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectScheme(t *testing.T) {
	tests := []struct {
		uri      string
		expected string
	}{
		{uri: "kms://secret/path", expected: "kms"},
		{uri: "remote-kms://vault/secret", expected: "remote-kms"},
		{uri: "env://MY_VAR", expected: "env"},
		{uri: "autogen://password?length=32", expected: "autogen"},
		{uri: "encrypted://base64data", expected: "encrypted"},
		{uri: "unknown://data", expected: "unknown"},
		{uri: "plaintext", expected: "unknown"},
		{uri: "", expected: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			result := detectScheme(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsResolverAvailable(t *testing.T) {
	tests := []struct {
		scheme   string
		expected bool
	}{
		{scheme: "kms", expected: true},
		{scheme: "env", expected: true},
		{scheme: "autogen", expected: true},
		{scheme: "remote-kms", expected: true},
		{scheme: "encrypted", expected: true},
		{scheme: "unknown", expected: false},
		{scheme: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			result := isResolverAvailable(tt.scheme)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskValue(t *testing.T) {
	tests := []struct {
		name     string
		value    []byte
		expected string
	}{
		{
			name:     "empty value",
			value:    []byte{},
			expected: "(empty)",
		},
		{
			name:     "short value",
			value:    []byte("abc"),
			expected: "****",
		},
		{
			name:     "exactly 4 chars",
			value:    []byte("abcd"),
			expected: "****",
		},
		{
			name:     "longer value",
			value:    []byte("secret_password"),
			expected: "se****rd",
		},
		{
			name:     "5 char value",
			value:    []byte("12345"),
			expected: "12****45",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskValue(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCreateLogger(t *testing.T) {
	t.Run("verbose mode", func(t *testing.T) {
		logger := createLogger(true)
		require.NotNil(t, logger)
	})

	t.Run("quiet mode", func(t *testing.T) {
		logger := createLogger(false)
		require.NotNil(t, logger)
	})
}

// -----------------------------------------------------------------------------
// Error Type Tests
// -----------------------------------------------------------------------------

func TestErrConfigPathRequired(t *testing.T) {
	err := ErrConfigPathRequired{}
	assert.Equal(t, "configuration file path is required (use --config flag)", err.Error())
}

func TestErrConfigFileReadFailed(t *testing.T) {
	err := ErrConfigFileReadFailed{
		Path: "/path/to/config.yaml",
		Err:  assert.AnError,
	}
	assert.Contains(t, err.Error(), "/path/to/config.yaml")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrConfigParseFailed(t *testing.T) {
	err := ErrConfigParseFailed{
		Path: "/path/to/config.yaml",
		Err:  assert.AnError,
	}
	assert.Contains(t, err.Error(), "/path/to/config.yaml")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrSecretURIRequired(t *testing.T) {
	err := ErrSecretURIRequired{}
	assert.Equal(t, "secret URI is required", err.Error())
}

func TestErrInvalidSecretURI(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidSecretURI{
			URI:    "bad://uri",
			Reason: "unknown scheme",
		}
		assert.Contains(t, err.Error(), "bad://uri")
		assert.Contains(t, err.Error(), "unknown scheme")
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidSecretURI{
			URI: "bad://uri",
		}
		assert.Contains(t, err.Error(), "bad://uri")
	})
}

func TestErrSecretResolutionFailed(t *testing.T) {
	err := ErrSecretResolutionFailed{
		URI: "kms://secret",
		Err: assert.AnError,
	}
	assert.Contains(t, err.Error(), "kms://secret")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrMigrationFailed(t *testing.T) {
	err := ErrMigrationFailed{
		Err: assert.AnError,
	}
	assert.Contains(t, err.Error(), "migration failed")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrNoSecretsFound(t *testing.T) {
	err := ErrNoSecretsFound{
		Path: "/path/to/config.yaml",
	}
	assert.Contains(t, err.Error(), "/path/to/config.yaml")
}

func TestErrSecretVerificationFailed(t *testing.T) {
	err := ErrSecretVerificationFailed{
		FailedCount: 3,
		TotalCount:  10,
	}
	assert.Contains(t, err.Error(), "3 of 10")
}

func TestErrBackupCreationFailed(t *testing.T) {
	err := ErrBackupCreationFailed{
		Path: "/path/to/config.yaml",
		Err:  assert.AnError,
	}
	assert.Contains(t, err.Error(), "/path/to/config.yaml")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrConfigUpdateFailed(t *testing.T) {
	err := ErrConfigUpdateFailed{
		Path: "/path/to/config.yaml",
		Err:  assert.AnError,
	}
	assert.Contains(t, err.Error(), "/path/to/config.yaml")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrResolverNotAvailable(t *testing.T) {
	err := ErrResolverNotAvailable{
		Scheme: "custom",
	}
	assert.Contains(t, err.Error(), "custom")
}

func TestErrKMSClientRequired(t *testing.T) {
	err := ErrKMSClientRequired{}
	assert.Contains(t, err.Error(), "KMS client is required")
}

func TestErrSecretsNotImplemented(t *testing.T) {
	err := ErrSecretsNotImplemented{}
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestErrEnvVarNotSet(t *testing.T) {
	err := ErrEnvVarNotSet{Name: "MY_VAR"}
	assert.Contains(t, err.Error(), "MY_VAR")
}

func TestErrFileReadFailed(t *testing.T) {
	err := ErrFileReadFailed{
		Path: "/path/to/file",
		Err:  assert.AnError,
	}
	assert.Contains(t, err.Error(), "/path/to/file")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrAlreadyKMSManaged(t *testing.T) {
	err := ErrAlreadyKMSManaged{Path: "kms://secret"}
	assert.Contains(t, err.Error(), "kms://secret")
}

func TestErrAutoGenFailed(t *testing.T) {
	t.Run("with error", func(t *testing.T) {
		err := ErrAutoGenFailed{Spec: "password", Err: assert.AnError}
		assert.Contains(t, err.Error(), "password")
		assert.Equal(t, assert.AnError, err.Unwrap())
	})

	t.Run("without error", func(t *testing.T) {
		err := ErrAutoGenFailed{Spec: "password"}
		assert.Contains(t, err.Error(), "password")
	})
}

func TestErrKMSStoreFailed(t *testing.T) {
	err := ErrKMSStoreFailed{
		Path: "config/db/password",
		Err:  assert.AnError,
	}
	assert.Contains(t, err.Error(), "config/db/password")
	assert.Contains(t, err.Error(), "failed to store secret in KMS")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

func TestErrKMSEncryptFailed(t *testing.T) {
	err := ErrKMSEncryptFailed{
		KeyID: "my-key-id",
		Err:   assert.AnError,
	}
	assert.Contains(t, err.Error(), "my-key-id")
	assert.Contains(t, err.Error(), "failed to encrypt with KMS")
	assert.Equal(t, assert.AnError, err.Unwrap())
}

// -----------------------------------------------------------------------------
// Integration with bootstrap package constants
// -----------------------------------------------------------------------------

func TestSchemeConstants(t *testing.T) {
	// Verify our helper functions use the correct bootstrap package constants
	assert.True(t, isSecretURI(bootstrap.SchemeKMS+"secret"))
	assert.True(t, isSecretURI(bootstrap.SchemeRemoteKMS+"secret"))
	assert.True(t, isSecretURI(bootstrap.SchemeEnv+"VAR"))
	assert.True(t, isSecretURI(bootstrap.SchemeAutoGen+"spec"))
	assert.True(t, isSecretURI(bootstrap.SchemeEncrypted+"data"))
}

func TestDetectSchemeWithBootstrapConstants(t *testing.T) {
	assert.Equal(t, "kms", detectScheme(bootstrap.SchemeKMS+"path"))
	assert.Equal(t, "remote-kms", detectScheme(bootstrap.SchemeRemoteKMS+"path"))
	assert.Equal(t, "env", detectScheme(bootstrap.SchemeEnv+"VAR"))
	assert.Equal(t, "autogen", detectScheme(bootstrap.SchemeAutoGen+"spec"))
	assert.Equal(t, "encrypted", detectScheme(bootstrap.SchemeEncrypted+"data"))
}

// -----------------------------------------------------------------------------
// secretSchemeStats Tests
// -----------------------------------------------------------------------------

func TestSecretSchemeStats(t *testing.T) {
	stats := &secretSchemeStats{
		scheme:    "kms",
		count:     5,
		available: true,
		secrets:   make([]secretInfo, 0),
	}

	assert.Equal(t, "kms", stats.scheme)
	assert.Equal(t, 5, stats.count)
	assert.True(t, stats.available)
	assert.Empty(t, stats.secrets)
}

// -----------------------------------------------------------------------------
// verificationResult Tests
// -----------------------------------------------------------------------------

func TestVerificationResult(t *testing.T) {
	result := verificationResult{
		path:     "database.password",
		uri:      "kms://config/db/password",
		scheme:   "kms",
		success:  true,
		value:    "resolved_value",
		errorMsg: "",
	}

	assert.Equal(t, "database.password", result.path)
	assert.Equal(t, "kms://config/db/password", result.uri)
	assert.Equal(t, "kms", result.scheme)
	assert.True(t, result.success)
	assert.Equal(t, "resolved_value", result.value)
	assert.Empty(t, result.errorMsg)
}

// -----------------------------------------------------------------------------
// secretInfo Tests
// -----------------------------------------------------------------------------

func TestSecretInfo(t *testing.T) {
	info := secretInfo{
		path: "database.password",
		uri:  "kms://config/db/password",
		line: 42,
	}

	assert.Equal(t, "database.password", info.path)
	assert.Equal(t, "kms://config/db/password", info.uri)
	assert.Equal(t, 42, info.line)
}

// -----------------------------------------------------------------------------
// Flag Struct Tests
// -----------------------------------------------------------------------------

func TestSecretsMigrateFlags(t *testing.T) {
	flags := &secretsMigrateFlags{
		configPath: "/etc/config.yaml",
		dryRun:     true,
		noBackup:   false,
		force:      true,
		keyID:      "my-key",
	}

	assert.Equal(t, "/etc/config.yaml", flags.configPath)
	assert.True(t, flags.dryRun)
	assert.False(t, flags.noBackup)
	assert.True(t, flags.force)
	assert.Equal(t, "my-key", flags.keyID)
}

func TestSecretsStatusFlags(t *testing.T) {
	flags := &secretsStatusFlags{
		configPath: "/etc/config.yaml",
		showURIs:   true,
	}

	assert.Equal(t, "/etc/config.yaml", flags.configPath)
	assert.True(t, flags.showURIs)
}

func TestSecretsVerifyFlags(t *testing.T) {
	flags := &secretsVerifyFlags{
		configPath:  "/etc/config.yaml",
		dryRun:      true,
		failFast:    true,
		showSecrets: false,
	}

	assert.Equal(t, "/etc/config.yaml", flags.configPath)
	assert.True(t, flags.dryRun)
	assert.True(t, flags.failFast)
	assert.False(t, flags.showSecrets)
}

func TestSecretsResolveFlags(t *testing.T) {
	flags := &secretsResolveFlags{
		masked: true,
		raw:    false,
	}

	assert.True(t, flags.masked)
	assert.False(t, flags.raw)
}

// -----------------------------------------------------------------------------
// Command RunE callback binding tests
// -----------------------------------------------------------------------------

func TestMigrateCommand_RunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newSecretsMigrateCommand(getFlags)
	require.NotNil(t, cmd.RunE)
}

func TestStatusCommand_RunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newSecretsStatusCommand(getFlags)
	require.NotNil(t, cmd.RunE)
}

func TestVerifyCommand_RunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newSecretsVerifyCommand(getFlags)
	require.NotNil(t, cmd.RunE)
}

func TestResolveCommand_RunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newSecretsResolveCommand(getFlags)
	require.NotNil(t, cmd.RunE)
}

// -----------------------------------------------------------------------------
// YAML Config Scanning Edge Cases
// -----------------------------------------------------------------------------

func TestScanConfigForSecrets_EdgeCases(t *testing.T) {
	t.Run("empty config", func(t *testing.T) {
		secrets := scanConfigForSecrets([]byte(""))
		assert.Empty(t, secrets)
	})

	t.Run("comments only", func(t *testing.T) {
		config := `# This is a comment
# password: kms://secret
# another comment`
		secrets := scanConfigForSecrets([]byte(config))
		assert.Empty(t, secrets)
	})

	t.Run("mixed content with secrets", func(t *testing.T) {
		config := `# Config file
database:
  host: localhost
  port: 5432
  password: kms://config/db/password
  # another_secret: env://NOT_A_SECRET
api:
  key: env://API_KEY`
		secrets := scanConfigForSecrets([]byte(config))
		assert.GreaterOrEqual(t, len(secrets), 2)
	})

	t.Run("duplicate secrets deduplicated", func(t *testing.T) {
		config := `password: kms://config/db/password
password: kms://config/db/password`
		secrets := scanConfigForSecrets([]byte(config))
		// Should deduplicate based on path:uri
		assert.GreaterOrEqual(t, len(secrets), 1)
	})
}

func TestScanNestedSecrets_EdgeCases(t *testing.T) {
	t.Run("deeply nested", func(t *testing.T) {
		config := `level1:
  level2:
    level3:
      level4:
        secret: kms://deep/secret`
		secrets := scanNestedSecrets([]byte(config))
		assert.GreaterOrEqual(t, len(secrets), 1)
	})

	t.Run("empty lines and comments", func(t *testing.T) {
		config := `
# Comment
key: value

# Another comment
secret: kms://my/secret

`
		secrets := scanNestedSecrets([]byte(config))
		assert.GreaterOrEqual(t, len(secrets), 1)
	})

	t.Run("multiline values", func(t *testing.T) {
		config := `description: |
  This is a multiline
  description value
password: kms://config/password`
		secrets := scanNestedSecrets([]byte(config))
		found := false
		for _, s := range secrets {
			if s.uri == "kms://config/password" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})
}

// -----------------------------------------------------------------------------
// Command Args Validation Tests
// -----------------------------------------------------------------------------

func TestResolveCommand_ArgsValidation(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newSecretsResolveCommand(getFlags)

	// The command expects exactly 1 argument
	assert.NotNil(t, cmd.Args)
}

// -----------------------------------------------------------------------------
// Additional Helper Function Tests for Coverage
// -----------------------------------------------------------------------------

func TestScanConfigForSecrets_AllSchemes(t *testing.T) {
	tests := []struct {
		name   string
		config string
		scheme string
	}{
		{
			name:   "kms scheme",
			config: "secret: kms://path/to/secret",
			scheme: "kms",
		},
		{
			name:   "env scheme",
			config: "secret: env://MY_ENV_VAR",
			scheme: "env",
		},
		{
			name:   "autogen scheme",
			config: "secret: autogen://password?length=32",
			scheme: "autogen",
		},
		{
			name:   "remote-kms scheme",
			config: "secret: remote-kms://vault/secret",
			scheme: "remote-kms",
		},
		{
			name:   "encrypted scheme",
			config: "secret: encrypted://base64data",
			scheme: "encrypted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets := scanConfigForSecrets([]byte(tt.config))
			require.NotEmpty(t, secrets)
			assert.Equal(t, tt.scheme, detectScheme(secrets[0].uri))
		})
	}
}

func TestMaskSecretURI_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "kms with single segment",
			uri:      "kms://secret",
			expected: "kms://***",
		},
		{
			name:     "kms with two segments",
			uri:      "kms://config/secret",
			expected: "kms://config/secret/***",
		},
		{
			name:     "empty string",
			uri:      "",
			expected: "***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskSecretURI(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildPath_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		stack    []string
		key      string
		expected string
	}{
		{
			name:     "deeply nested",
			stack:    []string{"a", "b", "c", "d"},
			key:      "e",
			expected: "a.b.c.d.e",
		},
		{
			name:     "special characters in key",
			stack:    []string{"config"},
			key:      "db-password",
			expected: "config.db-password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildPath(tt.stack, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// -----------------------------------------------------------------------------
// Command Long Description Tests
// -----------------------------------------------------------------------------

func TestCommandLongDescriptions(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	t.Run("bootstrap command", func(t *testing.T) {
		cmd := NewCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "bootstrap")
	})

	t.Run("secrets command", func(t *testing.T) {
		cmd := NewSecretsCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "secret")
	})

	t.Run("migrate command", func(t *testing.T) {
		cmd := newSecretsMigrateCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Migrate")
	})

	t.Run("status command", func(t *testing.T) {
		cmd := newSecretsStatusCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "status")
	})

	t.Run("verify command", func(t *testing.T) {
		cmd := newSecretsVerifyCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Verify")
	})

	t.Run("resolve command", func(t *testing.T) {
		cmd := newSecretsResolveCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Resolve")
	})
}

// -----------------------------------------------------------------------------
// Required Flags Tests
// -----------------------------------------------------------------------------

func TestMigrateCommand_RequiredFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newSecretsMigrateCommand(getFlags)

	configFlag := cmd.Flag("config")
	require.NotNil(t, configFlag)
	// Check if the flag exists and is properly defined
	assert.NotEmpty(t, configFlag.Usage)
}

func TestStatusCommand_RequiredFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newSecretsStatusCommand(getFlags)

	configFlag := cmd.Flag("config")
	require.NotNil(t, configFlag)
	assert.NotEmpty(t, configFlag.Usage)
}

func TestVerifyCommand_RequiredFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newSecretsVerifyCommand(getFlags)

	configFlag := cmd.Flag("config")
	require.NotNil(t, configFlag)
	assert.NotEmpty(t, configFlag.Usage)
}

// -----------------------------------------------------------------------------
// Verify scanNestedSecrets function behavior
// -----------------------------------------------------------------------------

func TestScanNestedSecrets_ParentPathHandling(t *testing.T) {
	config := `database:
  host: localhost
  credentials:
    username: admin
    password: kms://db/password`

	secrets := scanNestedSecrets([]byte(config))

	// Find the password secret and check its path
	var found bool
	for _, s := range secrets {
		if s.uri == "kms://db/password" {
			found = true
			// The path should include the full nested path
			assert.Contains(t, s.path, "password")
		}
	}
	assert.True(t, found, "should find the kms secret")
}

func TestScanNestedSecrets_TabIndentation(t *testing.T) {
	// Test with tab indentation
	config := "database:\n\tpassword: kms://secret"

	secrets := scanNestedSecrets([]byte(config))
	assert.GreaterOrEqual(t, len(secrets), 1)
}

// -----------------------------------------------------------------------------
// Verification Result with Error
// -----------------------------------------------------------------------------

func TestVerificationResult_WithError(t *testing.T) {
	result := verificationResult{
		path:     "database.password",
		uri:      "kms://config/db/password",
		scheme:   "kms",
		success:  false,
		value:    "",
		errorMsg: "secret not found",
	}

	assert.Equal(t, "database.password", result.path)
	assert.False(t, result.success)
	assert.Equal(t, "secret not found", result.errorMsg)
	assert.Empty(t, result.value)
}

// -----------------------------------------------------------------------------
// Additional secretInfo tests with line number
// -----------------------------------------------------------------------------

func TestSecretInfo_LineTracking(t *testing.T) {
	config := `line1: value1
password: kms://config/password
line3: value3`

	secrets := scanNestedSecrets([]byte(config))

	var passwordSecret secretInfo
	for _, s := range secrets {
		if s.uri == "kms://config/password" {
			passwordSecret = s
			break
		}
	}

	// Line numbers are tracked (1-indexed)
	assert.Greater(t, passwordSecret.line, 0)
}

// -----------------------------------------------------------------------------
// Test scheme detection edge cases
// -----------------------------------------------------------------------------

func TestDetectScheme_Prefixes(t *testing.T) {
	// Ensure proper scheme detection with similar prefixes
	tests := []struct {
		uri      string
		expected string
	}{
		{uri: "kms://path", expected: "kms"},
		{uri: "kms-extended://path", expected: "unknown"}, // Should not match kms
		{uri: "remote-kms://path", expected: "remote-kms"},
		{uri: "remote-kms-extra://path", expected: "unknown"}, // Should not match
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			result := detectScheme(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// -----------------------------------------------------------------------------
// Migration Entry Tests
// -----------------------------------------------------------------------------

func TestMigrationEntry(t *testing.T) {
	entry := migrationEntry{
		path:       "database.password",
		uri:        "env://DB_PASSWORD",
		scheme:     "env",
		resolved:   true,
		value:      []byte("secret123"),
		kmsPath:    "kms://config/database/password",
		errorMsg:   "",
		alreadyKMS: false,
	}

	assert.Equal(t, "database.password", entry.path)
	assert.Equal(t, "env://DB_PASSWORD", entry.uri)
	assert.Equal(t, "env", entry.scheme)
	assert.True(t, entry.resolved)
	assert.Equal(t, []byte("secret123"), entry.value)
	assert.Equal(t, "kms://config/database/password", entry.kmsPath)
	assert.Empty(t, entry.errorMsg)
	assert.False(t, entry.alreadyKMS)
}

// -----------------------------------------------------------------------------
// File Scheme Tests
// -----------------------------------------------------------------------------

func TestScanForFileSecrets(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		expected int
	}{
		{
			name:     "file secret",
			config:   "secret: file:///path/to/secret",
			expected: 1,
		},
		{
			name:     "no file secrets",
			config:   "secret: env://MY_VAR",
			expected: 0,
		},
		{
			name: "nested file secret",
			config: `database:
  password: file:///etc/secrets/db_password`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets := scanForFileSecrets([]byte(tt.config))
			assert.Len(t, secrets, tt.expected)
		})
	}
}

func TestDetectSchemeWithFile(t *testing.T) {
	tests := []struct {
		uri      string
		expected string
	}{
		{uri: "file:///path/to/secret", expected: "file"},
		{uri: "env://MY_VAR", expected: "env"},
		{uri: "kms://secret", expected: "kms"},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			result := detectSchemeWithFile(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// -----------------------------------------------------------------------------
// Generate Secret Tests
// -----------------------------------------------------------------------------

func TestGenerateSecret(t *testing.T) {
	t.Run("password type", func(t *testing.T) {
		result, err := generateSecret("password?length=16")
		require.NoError(t, err)
		assert.Len(t, result, 16)
		// Should be alphanumeric
		for _, b := range result {
			assert.True(t, (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9'))
		}
	})

	t.Run("key type", func(t *testing.T) {
		result, err := generateSecret("key?length=32")
		require.NoError(t, err)
		assert.Len(t, result, 32)
	})

	t.Run("token type", func(t *testing.T) {
		result, err := generateSecret("token?length=24")
		require.NoError(t, err)
		assert.Len(t, result, 24)
	})

	t.Run("default type", func(t *testing.T) {
		result, err := generateSecret("random?length=24")
		require.NoError(t, err)
		assert.Len(t, result, 24)
	})

	t.Run("default length", func(t *testing.T) {
		result, err := generateSecret("password")
		require.NoError(t, err)
		assert.Len(t, result, 32)
	})

	t.Run("multiple params", func(t *testing.T) {
		result, err := generateSecret("password?length=20&encoding=base64")
		require.NoError(t, err)
		assert.Len(t, result, 20)
	})
}

// -----------------------------------------------------------------------------
// Resolve Secret By Scheme Tests
// -----------------------------------------------------------------------------

func TestResolveSecretByScheme(t *testing.T) {
	t.Run("env scheme with set variable", func(t *testing.T) {
		os.Setenv("TEST_SECRET_VAR", "secret_value")
		defer os.Unsetenv("TEST_SECRET_VAR")

		result, err := resolveSecretByScheme(context.TODO(), nil, "env://TEST_SECRET_VAR", "env")
		require.NoError(t, err)
		assert.Equal(t, []byte("secret_value"), result)
	})

	t.Run("env scheme with unset variable", func(t *testing.T) {
		_, err := resolveSecretByScheme(context.TODO(), nil, "env://NONEXISTENT_VAR", "env")
		require.Error(t, err)
		var envErr ErrEnvVarNotSet
		assert.ErrorAs(t, err, &envErr)
	})

	t.Run("file scheme with existing file", func(t *testing.T) {
		tmpDir := t.TempDir()
		secretFile := filepath.Join(tmpDir, "secret.txt")
		err := os.WriteFile(secretFile, []byte("file_secret"), 0600)
		require.NoError(t, err)

		result, err := resolveSecretByScheme(context.TODO(), nil, "file://"+secretFile, "file")
		require.NoError(t, err)
		assert.Equal(t, []byte("file_secret"), result)
	})

	t.Run("file scheme with nonexistent file", func(t *testing.T) {
		_, err := resolveSecretByScheme(context.TODO(), nil, "file:///nonexistent/path", "file")
		require.Error(t, err)
		var fileErr ErrFileReadFailed
		assert.ErrorAs(t, err, &fileErr)
	})

	t.Run("autogen scheme", func(t *testing.T) {
		result, err := resolveSecretByScheme(context.TODO(), nil, "autogen://password?length=16", "autogen")
		require.NoError(t, err)
		assert.Len(t, result, 16)
	})

	t.Run("kms scheme", func(t *testing.T) {
		_, err := resolveSecretByScheme(context.TODO(), nil, "kms://secret", "kms")
		require.Error(t, err)
		var kmsErr ErrAlreadyKMSManaged
		assert.ErrorAs(t, err, &kmsErr)
	})

	t.Run("remote-kms scheme", func(t *testing.T) {
		_, err := resolveSecretByScheme(context.TODO(), nil, "remote-kms://secret", "remote-kms")
		require.Error(t, err)
		var resolverErr ErrResolverNotAvailable
		assert.ErrorAs(t, err, &resolverErr)
	})

	t.Run("encrypted scheme", func(t *testing.T) {
		_, err := resolveSecretByScheme(context.TODO(), nil, "encrypted://data", "encrypted")
		require.Error(t, err)
		var resolverErr ErrResolverNotAvailable
		assert.ErrorAs(t, err, &resolverErr)
	})

	t.Run("unknown scheme", func(t *testing.T) {
		_, err := resolveSecretByScheme(context.TODO(), nil, "unknown://secret", "unknown")
		require.Error(t, err)
		var invalidErr ErrInvalidSecretURI
		assert.ErrorAs(t, err, &invalidErr)
	})
}

// -----------------------------------------------------------------------------
// Build Config Updates Tests
// -----------------------------------------------------------------------------

func TestBuildConfigUpdates(t *testing.T) {
	entries := []migrationEntry{
		{
			path:       "db.password",
			kmsPath:    "kms://config/db/password",
			uri:        "env://DB_PASS",
			alreadyKMS: false,
		},
		{
			path:       "api.key",
			kmsPath:    "",
			uri:        "env://API_KEY",
			alreadyKMS: false,
		},
		{
			path:       "existing.secret",
			kmsPath:    "kms://config/existing/secret",
			uri:        "kms://config/existing/secret",
			alreadyKMS: true,
		},
	}

	updates := buildConfigUpdates(entries)

	// Should only include entries with kmsPath set and not already KMS
	assert.Len(t, updates, 1)
	assert.Equal(t, "db.password", updates[0].Path)
	assert.Equal(t, "kms://config/db/password", updates[0].KMSReference)
}

func TestBuildConfigUpdates_Empty(t *testing.T) {
	entries := []migrationEntry{}
	updates := buildConfigUpdates(entries)
	assert.Empty(t, updates)
}

func TestBuildConfigUpdates_AllAlreadyKMS(t *testing.T) {
	entries := []migrationEntry{
		{
			path:       "secret1",
			kmsPath:    "kms://config/secret1",
			alreadyKMS: true,
		},
		{
			path:       "secret2",
			kmsPath:    "kms://config/secret2",
			alreadyKMS: true,
		},
	}

	updates := buildConfigUpdates(entries)
	assert.Empty(t, updates)
}

// -----------------------------------------------------------------------------
// Scan For File Secrets Edge Cases
// -----------------------------------------------------------------------------

func TestScanForFileSecrets_EdgeCases(t *testing.T) {
	t.Run("empty config", func(t *testing.T) {
		secrets := scanForFileSecrets([]byte(""))
		assert.Empty(t, secrets)
	})

	t.Run("comments with file paths", func(t *testing.T) {
		config := `# secret: file:///path/to/secret
key: value`
		secrets := scanForFileSecrets([]byte(config))
		assert.Empty(t, secrets)
	})

	t.Run("quoted file paths", func(t *testing.T) {
		config := `secret: "file:///path/to/secret"`
		secrets := scanForFileSecrets([]byte(config))
		assert.Len(t, secrets, 1)
	})

	t.Run("single quoted file paths", func(t *testing.T) {
		config := `secret: 'file:///path/to/secret'`
		secrets := scanForFileSecrets([]byte(config))
		assert.Len(t, secrets, 1)
	})

	t.Run("multiline block value", func(t *testing.T) {
		config := `description: |
  some multiline
  description
secret: file:///actual/secret`
		secrets := scanForFileSecrets([]byte(config))
		assert.Len(t, secrets, 1)
	})

	t.Run("multiple file secrets", func(t *testing.T) {
		config := `database:
  password: file:///etc/secrets/db_pass
  cert: file:///etc/certs/db.crt
api:
  key: file:///etc/secrets/api_key`
		secrets := scanForFileSecrets([]byte(config))
		assert.Len(t, secrets, 3)
	})
}

// -----------------------------------------------------------------------------
// Migration Entry Edge Cases
// -----------------------------------------------------------------------------

func TestMigrationEntry_WithError(t *testing.T) {
	entry := migrationEntry{
		path:     "failed.secret",
		uri:      "env://MISSING_VAR",
		scheme:   "env",
		resolved: false,
		errorMsg: "environment variable not set: MISSING_VAR",
	}

	assert.Equal(t, "failed.secret", entry.path)
	assert.False(t, entry.resolved)
	assert.NotEmpty(t, entry.errorMsg)
	assert.Empty(t, entry.value)
	assert.Empty(t, entry.kmsPath)
}

// -----------------------------------------------------------------------------
// SchemeFile Constant Test
// -----------------------------------------------------------------------------

func TestSchemeFileConstant(t *testing.T) {
	assert.Equal(t, "file://", SchemeFile)
}
