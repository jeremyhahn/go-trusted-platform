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

package commands

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	platforminitrd "github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/securewipe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldConfirmSeal(t *testing.T) {
	assert.True(t, shouldConfirmSeal(true, platforminitrd.StrategyNameTPMPCR))
	assert.False(t, shouldConfirmSeal(true, "Keyfile"), "a keyfile unlock is the seal NOT working")
	assert.False(t, shouldConfirmSeal(true, "TPM-Upgrade"), "the non-PCR upgrade seal proves nothing about the PCR policy")
	assert.False(t, shouldConfirmSeal(true, ""), "no unlock, no proof")
	assert.False(t, shouldConfirmSeal(false, platforminitrd.StrategyNameTPMPCR), "a container this process did not mount is not its to destroy")
}

// espWithInstaller lays out <esp>/tpm2/installer.luks.
func espWithInstaller(t *testing.T) (string, string) {
	t.Helper()
	esp := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(esp, "tpm2"), 0o755))
	installer := filepath.Join(esp, "tpm2", "installer.luks")
	require.NoError(t, os.WriteFile(installer, []byte("container"), 0o600))
	return esp, installer
}

func TestSealConfirmation_WipesOnTPMPCRUnlock(t *testing.T) {
	esp, installer := espWithInstaller(t)
	var wipedPath string
	var wipedPasses int
	var lines []string
	synced := false
	c := sealConfirmation{
		efiPath: esp, installerMounted: true, unlockedWith: platforminitrd.StrategyNameTPMPCR, passes: 3,
		wipe: func(path string, passes int, report func(string)) error {
			wipedPath, wipedPasses = path, passes
			report("pass")
			return os.Remove(path)
		},
		sync:   func() { synced = true },
		report: func(s string) { lines = append(lines, s) },
	}

	wiped, err := c.run()

	require.NoError(t, err)
	assert.True(t, wiped)
	assert.True(t, synced, "the unlink is made durable before the boot goes on")
	assert.Equal(t, installer, wipedPath)
	assert.Equal(t, 3, wipedPasses)
	assert.NoFileExists(t, installer)
	require.Len(t, lines, 3)
	assert.Contains(t, lines[0], "Seal confirmed by TPM-PCR unlock")
	assert.Contains(t, lines[2], "installer.luks securely wiped")
}

func TestSealConfirmation_DefaultsToOnePass(t *testing.T) {
	esp, _ := espWithInstaller(t)
	var wipedPasses int
	c := sealConfirmation{
		efiPath: esp, installerMounted: true, unlockedWith: platforminitrd.StrategyNameTPMPCR,
		wipe:   func(_ string, passes int, _ func(string)) error { wipedPasses = passes; return nil },
		sync:   func() {},
		report: func(string) {},
	}

	_, err := c.run()

	require.NoError(t, err)
	assert.Equal(t, securewipe.PassesNIST, wipedPasses)
}

func TestSealConfirmation_PreservesTheContainer(t *testing.T) {
	t.Run("after a keyfile unlock", func(t *testing.T) {
		esp, installer := espWithInstaller(t)
		var lines []string
		c := sealConfirmation{
			efiPath: esp, installerMounted: true, unlockedWith: "Keyfile",
			wipe:   func(string, int, func(string)) error { t.Fatal("must not wipe"); return nil },
			report: func(s string) { lines = append(lines, s) },
		}

		wiped, err := c.run()

		require.NoError(t, err)
		assert.False(t, wiped)
		assert.FileExists(t, installer)
		require.Len(t, lines, 1)
		assert.Contains(t, lines[0], "preserved until a TPM-PCR unlock proves the seal")
	})

	t.Run("when this process did not mount it", func(t *testing.T) {
		esp, installer := espWithInstaller(t)
		c := sealConfirmation{
			efiPath: esp, installerMounted: false, unlockedWith: platforminitrd.StrategyNameTPMPCR,
			wipe:   func(string, int, func(string)) error { t.Fatal("must not wipe"); return nil },
			report: func(string) { t.Fatal("nothing to say on a boot without an installer") },
		}

		wiped, err := c.run()

		require.NoError(t, err)
		assert.False(t, wiped)
		assert.FileExists(t, installer)
	})
}

func TestSealConfirmation_Errors(t *testing.T) {
	t.Run("the container vanished after the mount", func(t *testing.T) {
		esp := t.TempDir()
		c := sealConfirmation{efiPath: esp, installerMounted: true, unlockedWith: platforminitrd.StrategyNameTPMPCR, report: func(string) {}}

		wiped, err := c.run()

		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.False(t, wiped)
	})

	t.Run("a failed wipe is reported and the file is left as the wipe left it", func(t *testing.T) {
		esp, installer := espWithInstaller(t)
		c := sealConfirmation{
			efiPath: esp, installerMounted: true, unlockedWith: platforminitrd.StrategyNameTPMPCR,
			wipe:   func(string, int, func(string)) error { return errors.New("EIO") },
			report: func(string) {},
		}

		wiped, err := c.run()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "EIO")
		assert.False(t, wiped)
		assert.FileExists(t, installer)
	})
}

func TestLoadSecureWipePassesFromConfig(t *testing.T) {
	// The searched paths are absolute and neither exists on a build host,
	// so the default is what a fresh initrd gets.
	assert.Equal(t, securewipe.PassesNIST, loadSecureWipePassesFromConfig())
}
