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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestCopyPlatformInitrdBinary_AbsenceIsFatal pins the defect in #48.
//
// The absence was DETECTED and then reported as success: os.Stat found the
// binary missing, logged a warning, and returned nil. `iso create` therefore
// exited 0 and shipped a 792 MB ISO whose autoinstall died at the
// platform-initrd step, an hour later, inside a VM.
//
// The pairing matters. The first case is the fix; the second is the guard on
// the fix — "no binary specified" must stay a no-op, because a caller that
// never asked for platform-initrd has not failed to supply it.
func TestCopyPlatformInitrdBinary_AbsenceIsFatal(t *testing.T) {
	newCustomizer := func(t *testing.T) *Customizer {
		t.Helper()
		return NewCustomizer(&PlatformISOConfig{
			Directories: DirectoryConfig{
				ISO:     filepath.Join(t.TempDir(), "iso"),
				Overlay: filepath.Join(t.TempDir(), "overlay"),
			},
		}, logging.DefaultLogger())
	}

	t.Run("a path that does not exist fails the build", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "bin", "platform-initrd")

		err := newCustomizer(t).CopyPlatformInitrdBinary(context.Background(), missing)

		require.Error(t, err,
			"a missing platform-initrd must fail the build; returning nil here is what "+
				"shipped an unbootable 792 MB ISO (#48)")
		require.Contains(t, err.Error(), "platform-initrd",
			"the error must name the missing component")
		require.Contains(t, err.Error(), "make platform-initrd",
			"the error must name the remedy: it is a separate target from `make build`, "+
				"which is why the binary was absent in the first place")
	})

	t.Run("no binary specified stays a no-op", func(t *testing.T) {
		err := newCustomizer(t).CopyPlatformInitrdBinary(context.Background(), "")

		require.NoError(t, err,
			"an empty path means the caller did not ask for platform-initrd; failing "+
				"here would refuse builds that never wanted it")
	})
}

// TestConfigureBootloader_EFIUpdateFailureIsFatal pins the second half of #48.
//
// The previous handling warned "UEFI boot may fail" and continued — a message
// that predicts the failure it is about to cause. The Alpine ISO's bootx64.efi
// carries a hardcoded search directive for the original volume label, so an ISO
// whose bootloader was not updated does not boot under UEFI at all.
func TestConfigureBootloader_EFIUpdateFailureIsFatal(t *testing.T) {
	isoDir := filepath.Join(t.TempDir(), "iso")
	require.NoError(t, os.MkdirAll(filepath.Join(isoDir, "boot", "grub"), 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(isoDir, "boot", "grub", "grub.cfg"),
		[]byte("linux /boot/vmlinuz-lts quiet\n"), 0644))

	// Deliberately no efi/boot/bootx64.efi: UpdateEFIBootloader cannot proceed.
	customizer := NewCustomizer(&PlatformISOConfig{
		Directories: DirectoryConfig{
			ISO:     isoDir,
			Overlay: filepath.Join(t.TempDir(), "overlay"),
		},
	}, logging.DefaultLogger())

	err := customizer.ConfigureBootloader(context.Background())

	require.Error(t, err,
		"an EFI bootloader update failure must fail the build; warning "+
			"\"UEFI boot may fail\" and continuing ships the artifact that fails (#48)")
	require.Contains(t, err.Error(), "UEFI",
		"the error must say what the caller loses, not just that a step failed")
}
