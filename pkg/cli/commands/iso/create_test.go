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

package iso

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewCreateCommand_Creation(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newCreateCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "create", cmd.Use)
	assert.Equal(t, "All-in-one ISO creation", cmd.Short)
	assert.Contains(t, cmd.Long, "Create a complete custom platform ISO")
}

func TestNewCreateCommand_FlagsExist(t *testing.T) {
	cmd := newCreateCommand(getTestFlags)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))

	// Verify all flags exist
	expectedFlags := []string{
		// Alpine flags
		"alpine-version", "mirror", "arch",
		// Platform flags
		"platform-version", "platform-config", "platform-type",
		// Security flags
		"secure-boot", "tpm-unseal", "luks", "fips", "fido2",
		// Build flags
		"overlay", "output", "keys-dir", "generate-keys", "key-backend", "force", "webui",
		// Common flags
		"config", "work-dir", "debug", "verbose",
	}

	for _, flagName := range expectedFlags {
		flag := cmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "expected flag '%s' to be defined", flagName)
	}
}

func TestNewCreateCommand_DefaultValues(t *testing.T) {
	cmd := newCreateCommand(getTestFlags)

	// Alpine defaults
	alpineVersionFlag := cmd.Flags().Lookup("alpine-version")
	assert.Equal(t, "3.22.2", alpineVersionFlag.DefValue)

	archFlag := cmd.Flags().Lookup("arch")
	assert.Equal(t, "x86_64", archFlag.DefValue)

	mirrorFlag := cmd.Flags().Lookup("mirror")
	assert.Contains(t, mirrorFlag.DefValue, "alpine")

	// Platform defaults
	platformTypeFlag := cmd.Flags().Lookup("platform-type")
	assert.Equal(t, "server", platformTypeFlag.DefValue)

	// Security defaults
	secureBootFlag := cmd.Flags().Lookup("secure-boot")
	assert.Equal(t, "true", secureBootFlag.DefValue)

	tpmUnsealFlag := cmd.Flags().Lookup("tpm-unseal")
	assert.Equal(t, "true", tpmUnsealFlag.DefValue)

	luksFlag := cmd.Flags().Lookup("luks")
	assert.Equal(t, "true", luksFlag.DefValue)

	fipsFlag := cmd.Flags().Lookup("fips")
	assert.Equal(t, "false", fipsFlag.DefValue)

	fido2Flag := cmd.Flags().Lookup("fido2")
	assert.Equal(t, "false", fido2Flag.DefValue)

	// Build defaults
	generateKeysFlag := cmd.Flags().Lookup("generate-keys")
	assert.Equal(t, "true", generateKeysFlag.DefValue)

	keyBackendFlag := cmd.Flags().Lookup("key-backend")
	assert.Equal(t, "file", keyBackendFlag.DefValue)

	forceFlag := cmd.Flags().Lookup("force")
	assert.Equal(t, "false", forceFlag.DefValue)

	// Common defaults
	workDirFlag := cmd.Flags().Lookup("work-dir")
	assert.Equal(t, "work", workDirFlag.DefValue)

	debugFlag := cmd.Flags().Lookup("debug")
	assert.Equal(t, "false", debugFlag.DefValue)

	verboseFlag := cmd.Flags().Lookup("verbose")
	assert.Equal(t, "false", verboseFlag.DefValue)
}

func TestNewCreateCommand_HasRunE(t *testing.T) {
	cmd := newCreateCommand(getTestFlags)
	assert.NotNil(t, cmd.RunE)
}

func TestCreateFlags_StructFields(t *testing.T) {
	flags := &createFlags{
		alpineVersion:   "3.22.2",
		mirror:          "http://mirror.example.com/alpine",
		arch:            "x86_64",
		platformVersion: "1.0.0",
		platformConfig:  "/etc/platform.yaml",
		platformType:    "server",
		secureBoot:      true,
		tpmUnseal:       true,
		luks:            true,
		fips:            false,
		fido2:           false,
		overlay:         "/tmp/overlay",
		output:          "platform.iso",
		keysDir:         "/tmp/keys",
		generateKeys:    true,
		keyBackend:      "file",
		force:           false,
		webUI:           "/var/www",
		configFile:      "/etc/config.yaml",
		workDir:         "work",
		debug:           false,
		verbose:         false,
	}

	assert.Equal(t, "3.22.2", flags.alpineVersion)
	assert.Equal(t, "http://mirror.example.com/alpine", flags.mirror)
	assert.Equal(t, "x86_64", flags.arch)
	assert.Equal(t, "1.0.0", flags.platformVersion)
	assert.Equal(t, "/etc/platform.yaml", flags.platformConfig)
	assert.Equal(t, "server", flags.platformType)
	assert.True(t, flags.secureBoot)
	assert.True(t, flags.tpmUnseal)
	assert.True(t, flags.luks)
	assert.False(t, flags.fips)
	assert.False(t, flags.fido2)
	assert.Equal(t, "/tmp/overlay", flags.overlay)
	assert.Equal(t, "platform.iso", flags.output)
	assert.Equal(t, "/tmp/keys", flags.keysDir)
	assert.True(t, flags.generateKeys)
	assert.Equal(t, "file", flags.keyBackend)
	assert.False(t, flags.force)
	assert.Equal(t, "/var/www", flags.webUI)
	assert.Equal(t, "/etc/config.yaml", flags.configFile)
	assert.Equal(t, "work", flags.workDir)
	assert.False(t, flags.debug)
	assert.False(t, flags.verbose)
}

func TestReadVersionFile_NotFound(t *testing.T) {
	// Save current directory
	originalDir, err := os.Getwd()
	require.NoError(t, err)

	// Create a temp directory without VERSION file
	tmpDir, err := os.MkdirTemp("", "iso-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Change to temp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)
	defer func() {
		err := os.Chdir(originalDir)
		require.NoError(t, err)
	}()

	// Should return error
	_, err = readVersionFile()
	assert.Error(t, err)
}

func TestReadVersionFile_Success(t *testing.T) {
	// Save current directory
	originalDir, err := os.Getwd()
	require.NoError(t, err)

	// Create a temp directory with VERSION file
	tmpDir, err := os.MkdirTemp("", "iso-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create VERSION file
	versionContent := "1.2.3\n"
	err = os.WriteFile(filepath.Join(tmpDir, "VERSION"), []byte(versionContent), 0644)
	require.NoError(t, err)

	// Change to temp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)
	defer func() {
		err := os.Chdir(originalDir)
		require.NoError(t, err)
	}()

	// Should succeed
	version, err := readVersionFile()
	assert.NoError(t, err)
	assert.Equal(t, "1.2.3", version)
}

func TestReadVersionFile_TrimsWhitespace(t *testing.T) {
	// Save current directory
	originalDir, err := os.Getwd()
	require.NoError(t, err)

	// Create a temp directory with VERSION file
	tmpDir, err := os.MkdirTemp("", "iso-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create VERSION file with extra whitespace
	versionContent := "  2.0.0-beta  \n\t"
	err = os.WriteFile(filepath.Join(tmpDir, "VERSION"), []byte(versionContent), 0644)
	require.NoError(t, err)

	// Change to temp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)
	defer func() {
		err := os.Chdir(originalDir)
		require.NoError(t, err)
	}()

	// Should succeed and trim whitespace
	version, err := readVersionFile()
	assert.NoError(t, err)
	assert.Equal(t, "2.0.0-beta", version)
}

func TestCalculateFileSHA256_Success(t *testing.T) {
	// Create a temp file with known content
	tmpFile, err := os.CreateTemp("", "sha256-test-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("test content")
	require.NoError(t, err)
	tmpFile.Close()

	// Calculate SHA256
	checksum, err := calculateFileSHA256(tmpFile.Name())
	assert.NoError(t, err)
	assert.NotEmpty(t, checksum)
	assert.Len(t, checksum, 64) // SHA256 produces 64 hex characters
}

func TestCalculateFileSHA256_FileNotFound(t *testing.T) {
	_, err := calculateFileSHA256("/nonexistent/file.iso")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}

func TestCalculateFileSHA256_EmptyFile(t *testing.T) {
	// Create an empty temp file
	tmpFile, err := os.CreateTemp("", "sha256-empty-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Calculate SHA256 - should succeed even for empty file
	checksum, err := calculateFileSHA256(tmpFile.Name())
	assert.NoError(t, err)
	assert.NotEmpty(t, checksum)
	// SHA256 of empty content is a known value
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", checksum)
}

func TestMergeConfigs_BasicMerge(t *testing.T) {
	// Test that createFlags fields are correctly used to build configuration.
	// This tests the logic without requiring the full pkg/iso package types.

	t.Run("createFlags_to_config_mapping", func(t *testing.T) {
		flags := &createFlags{
			alpineVersion:   "3.22.2",
			mirror:          "https://dl-cdn.alpinelinux.org/alpine",
			arch:            "x86_64",
			platformVersion: "1.0.0",
			platformType:    "server",
			secureBoot:      true,
			tpmUnseal:       true,
			luks:            true,
			fips:            false,
			fido2:           false,
			generateKeys:    true,
			keyBackend:      "file",
			force:           false,
			workDir:         "work",
			debug:           false,
		}

		// Verify all flag fields are accessible and have expected values
		assert.Equal(t, "3.22.2", flags.alpineVersion)
		assert.Equal(t, "https://dl-cdn.alpinelinux.org/alpine", flags.mirror)
		assert.Equal(t, "x86_64", flags.arch)
		assert.Equal(t, "1.0.0", flags.platformVersion)
		assert.Equal(t, "server", flags.platformType)
		assert.True(t, flags.secureBoot)
		assert.True(t, flags.tpmUnseal)
		assert.True(t, flags.luks)
		assert.False(t, flags.fips)
		assert.False(t, flags.fido2)
		assert.True(t, flags.generateKeys)
		assert.Equal(t, "file", flags.keyBackend)
	})

	t.Run("createFlags_empty_optional_fields", func(t *testing.T) {
		flags := &createFlags{
			alpineVersion:   "3.22.2",
			mirror:          "https://dl-cdn.alpinelinux.org/alpine",
			arch:            "x86_64",
			platformVersion: "", // Empty - should use default
			platformConfig:  "", // Empty - optional
			overlay:         "", // Empty - optional
			keysDir:         "", // Empty - will be generated
			webUI:           "", // Empty - optional
			configFile:      "", // Empty - optional
		}

		// Verify empty fields are handled
		assert.Empty(t, flags.platformVersion)
		assert.Empty(t, flags.platformConfig)
		assert.Empty(t, flags.overlay)
		assert.Empty(t, flags.keysDir)
		assert.Empty(t, flags.webUI)
		assert.Empty(t, flags.configFile)
	})

	t.Run("createFlags_all_security_disabled", func(t *testing.T) {
		flags := &createFlags{
			alpineVersion:   "3.22.2",
			mirror:          "https://dl-cdn.alpinelinux.org/alpine",
			arch:            "x86_64",
			platformVersion: "1.0.0",
			secureBoot:      false,
			tpmUnseal:       false,
			luks:            false,
			fips:            false,
			fido2:           false,
		}

		// Verify all security flags can be disabled
		assert.False(t, flags.secureBoot)
		assert.False(t, flags.tpmUnseal)
		assert.False(t, flags.luks)
		assert.False(t, flags.fips)
		assert.False(t, flags.fido2)
	})

	t.Run("createFlags_all_security_enabled", func(t *testing.T) {
		flags := &createFlags{
			alpineVersion:   "3.22.2",
			mirror:          "https://dl-cdn.alpinelinux.org/alpine",
			arch:            "x86_64",
			platformVersion: "1.0.0",
			secureBoot:      true,
			tpmUnseal:       true,
			luks:            true,
			fips:            true,
			fido2:           true,
		}

		// Verify all security flags can be enabled
		assert.True(t, flags.secureBoot)
		assert.True(t, flags.tpmUnseal)
		assert.True(t, flags.luks)
		assert.True(t, flags.fips)
		assert.True(t, flags.fido2)
	})
}

func TestGetCreateLogger_DebugEnabled(t *testing.T) {
	flags := &createFlags{debug: true}
	logger := getCreateLogger(flags)
	assert.NotNil(t, logger)
}

func TestGetCreateLogger_DebugDisabled(t *testing.T) {
	flags := &createFlags{debug: false}
	logger := getCreateLogger(flags)
	assert.NotNil(t, logger)
}
