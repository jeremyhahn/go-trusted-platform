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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runNBDInstallTarget runs the autoinstall's nbd_install_target, the exact
// shell the live environment runs, against a command line file.
func runNBDInstallTarget(t *testing.T, cmdline string) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cmdline")
	require.NoError(t, os.WriteFile(path, []byte(cmdline+"\n"), 0o600))
	script := nbdInstallTargetFunction + "\nnbd_install_target \"$1\"\n"
	out, err := exec.Command("sh", "-c", script, "sh", path).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func TestNBDInstallTarget_DisklessNBDNodeInstallsOntoTheExport(t *testing.T) {
	out, err := runNBDInstallTarget(t,
		"console=ttyS0 alpine_start=autoinstall platform_boot_model=diskless-nbd platform_nbd_server=10.0.0.1:10809")

	require.NoError(t, err)
	assert.Equal(t, "/dev/nbd0", out)
}

func TestNBDInstallTarget_OtherNodesScanTheirDisks(t *testing.T) {
	for name, cmdline := range map[string]string{
		"disk":                     "console=ttyS0 alpine_start=autoinstall",
		"diskless":                 "alpine_start=autoinstall platform_boot_model=diskless",
		"nbd server without model": "alpine_start=autoinstall platform_nbd_server=10.0.0.1:10809",
		"model as a substring":     "alpine_start=autoinstall xplatform_boot_model=diskless-nbd",
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runNBDInstallTarget(t, cmdline)

			require.Error(t, err, "a %s node must fall through to the local-disk scan", name)
			assert.Empty(t, out)
		})
	}
}

func TestNBDInstallTarget_UnreadableCmdlineScansDisks(t *testing.T) {
	script := nbdInstallTargetFunction + "\nnbd_install_target \"$1\"\n"
	out, err := exec.Command("sh", "-c", script, "sh", filepath.Join(t.TempDir(), "missing")).CombinedOutput()

	require.Error(t, err)
	assert.Empty(t, strings.TrimSpace(string(out)))
}

// The live environment picks the NBD export before it scans local disks, and
// the scan's "no suitable disk" error is reached only when it did not.
func TestAutoinstallScript_NBDTargetBeforeDiskScan(t *testing.T) {
	script := autoinstallScriptFor(t, "poweroff")

	pick := strings.Index(script, "if INSTALL_DISK=$(nbd_install_target /proc/cmdline); then")
	scan := strings.Index(script, "for disk in /dev/sda")
	noDisk := strings.Index(script, `error "No suitable installation disk found`)
	install := strings.Index(script, `--disk \"$INSTALL_DISK\"`)
	require.GreaterOrEqual(t, pick, 0, "the autoinstall never asks for the NBD target")
	assert.Contains(t, script, nbdInstallTargetFunction)
	assert.Less(t, pick, scan)
	assert.Less(t, scan, noDisk)
	assert.Less(t, noDisk, install)
	elseBranch := script[pick:noDisk]
	assert.Contains(t, elseBranch, "\nelse\n", "the local-disk scan is not the NBD target's else branch")
}
