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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
)

// =============================================================================
// mergeConfigs
// =============================================================================

func TestMergeConfigs_NoOverrides(t *testing.T) {
	base := &pkgiso.ISOBuildConfig{
		AlpineVersion: "3.22.2",
		AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
		Architecture:  "x86_64",
		OutputISO:     "output.iso",
		OutputLabel:   "MY-LABEL",
		WorkDir:       "work",
	}

	override := &pkgiso.ISOBuildConfig{
		AlpineVersion: "3.22.2",
		AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
		Architecture:  "x86_64",
		WorkDir:       "work",
	}

	result := mergeConfigs(base, override)
	assert.Equal(t, "3.22.2", result.AlpineVersion)
	assert.Equal(t, "https://dl-cdn.alpinelinux.org/alpine", result.AlpineMirror)
	assert.Equal(t, "x86_64", result.Architecture)
	assert.Equal(t, "output.iso", result.OutputISO)
	assert.Equal(t, "MY-LABEL", result.OutputLabel)
	assert.Equal(t, "work", result.WorkDir)
}

func TestMergeConfigs_WithOverrides(t *testing.T) {
	base := &pkgiso.ISOBuildConfig{
		AlpineVersion: "3.22.2",
		AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
		Architecture:  "x86_64",
		OutputISO:     "base.iso",
		WorkDir:       "work",
	}

	override := &pkgiso.ISOBuildConfig{
		AlpineVersion: "3.23.0",
		Architecture:  "aarch64",
		OutputISO:     "custom.iso",
		OutputLabel:   "CUSTOM",
		WorkDir:       "custom-work",
		KeysDir:       "/keys",
		SecureBoot:    true,
		FIPS:          true,
		Debug:         true,
	}

	result := mergeConfigs(base, override)
	assert.Equal(t, "3.23.0", result.AlpineVersion)
	assert.Equal(t, "aarch64", result.Architecture)
	assert.Equal(t, "custom.iso", result.OutputISO)
	assert.Equal(t, "CUSTOM", result.OutputLabel)
	assert.Equal(t, "custom-work", result.WorkDir)
	assert.Equal(t, "/keys", result.KeysDir)
	assert.True(t, result.SecureBoot)
	assert.True(t, result.FIPS)
	assert.True(t, result.Debug)
}

func TestMergeConfigs_BooleanOverrides(t *testing.T) {
	base := &pkgiso.ISOBuildConfig{
		SecureBoot:    true,
		GenerateKeys:  true,
		TPMAutoUnseal: true,
		LUKSTPMOnly:   true,
		FIPS:          true,
		EnableFIDO2:   true,
		Force:         true,
		Debug:         true,
	}

	override := &pkgiso.ISOBuildConfig{
		SecureBoot:    false,
		GenerateKeys:  false,
		TPMAutoUnseal: false,
		LUKSTPMOnly:   false,
		FIPS:          false,
		EnableFIDO2:   false,
		Force:         false,
		Debug:         false,
	}

	result := mergeConfigs(base, override)
	assert.False(t, result.SecureBoot)
	assert.False(t, result.GenerateKeys)
	assert.False(t, result.TPMAutoUnseal)
	assert.False(t, result.LUKSTPMOnly)
	assert.False(t, result.FIPS)
	assert.False(t, result.EnableFIDO2)
	assert.False(t, result.Force)
	assert.False(t, result.Debug)
}

func TestMergeConfigs_EmptyStringOverridesNotApplied(t *testing.T) {
	base := &pkgiso.ISOBuildConfig{
		OutputISO:   "base.iso",
		OutputLabel: "BASE",
	}

	override := &pkgiso.ISOBuildConfig{
		OutputISO:   "",
		OutputLabel: "",
	}

	result := mergeConfigs(base, override)
	assert.Equal(t, "base.iso", result.OutputISO)
	assert.Equal(t, "BASE", result.OutputLabel)
}

// =============================================================================
// isTerminalFD
// =============================================================================

func TestIsTerminalFD_Stdout(t *testing.T) {
	// In test environment, stdout is typically not a terminal (it's a pipe)
	result := isTerminalFD(os.Stdout.Fd())
	assert.IsType(t, false, result)
}

func TestIsTerminalFD_InvalidFD(t *testing.T) {
	result := isTerminalFD(99999)
	assert.False(t, result)
}

func TestHasInteractiveTTYCS(t *testing.T) {
	// In test environment, should return false (pipes, not terminal)
	result := hasInteractiveTTYCS()
	assert.False(t, result)
}

// =============================================================================
// removeExistingISOFiles
// =============================================================================

func TestRemoveExistingISOFiles_NonExistentFiles(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &pkgiso.ISOConfig{
		WorkDir: tmpDir,
		ISO:     "test-nonexistent.iso",
	}

	// Should not panic even when files don't exist
	require.NotPanics(t, func() {
		removeExistingISOFiles(cfg)
	})
}

func TestRemoveExistingISOFiles_WithExistingFiles(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &pkgiso.ISOConfig{
		WorkDir: tmpDir,
		ISO:     "test.iso",
	}

	// Create files that removeExistingISOFiles would delete
	isoPath := cfg.ISOPath()
	checksumPath := cfg.ChecksumPath()

	err := os.WriteFile(isoPath, []byte("fake iso"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(checksumPath, []byte("fake checksum"), 0644)
	require.NoError(t, err)

	// Verify files exist
	_, err = os.Stat(isoPath)
	require.NoError(t, err)

	removeExistingISOFiles(cfg)

	// Files should be deleted
	_, err = os.Stat(isoPath)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(checksumPath)
	assert.True(t, os.IsNotExist(err))
}
