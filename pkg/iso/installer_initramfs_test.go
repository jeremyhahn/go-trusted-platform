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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/iso/isotest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// netbootCustomizer is a customizer whose work directory is a test
// directory, with the netboot release's initramfs written beside it.
func netbootCustomizer(t *testing.T, initramfs []byte) (*Customizer, string) {
	t.Helper()
	cfg := validPlatformISOConfig()
	cfg.Directories.Work = t.TempDir()
	path := filepath.Join(t.TempDir(), "initramfs-lts")
	require.NoError(t, os.WriteFile(path, initramfs, 0o644))
	return NewCustomizer(cfg, logging.DefaultLogger()), path
}

// TestInstallerInitramfs_MakesTheReleaseInitramfsTheInstallers: the
// release's initramfs comes back as the installer's — the autoinstall
// overlay, /init patched to install it and to DHCP on every NIC, every entry
// root's — and nothing the ISO's CD-flavour initramfs needs on top.
func TestInstallerInitramfs_MakesTheReleaseInitramfsTheInstallers(t *testing.T) {
	release, err := isotest.NetbootInitramfs()
	require.NoError(t, err)
	c, path := netbootCustomizer(t, release)

	require.NoError(t, c.InstallerInitramfs(context.Background(), path))

	files := isotest.ReadInitramfs(t, path)
	assert.Equal(t, c.buildAutoinstallScript(), files["overlay/root/autoinstall.sh"])
	assert.Contains(t, files["overlay/etc/inittab"], "::sysinit:/root/run-autoinstall.sh")
	assert.Contains(t, files, "overlay/root/run-autoinstall.sh")
	assert.Contains(t, files["init"], "if grep -q alpine_start=autoinstall /proc/cmdline")
	assert.Contains(t, files["init"], "trusted-platform: multi-NIC DHCP")
	assert.Equal(t, "#!/bin/sh\n", files["usr/share/udhcpc/default.script"], "the release's own udhcpc script is kept")
	for rel := range files {
		assert.False(t, strings.HasPrefix(rel, "usr/lib/dracut/"), "%s: the dracut module is the installed system's, not the live initramfs's", rel)
	}
	assert.NoDirExists(t, filepath.Join(c.config.Directories.Work, "netboot-initramfs-tmp"), "the unpacked tree is removed")
}

// TestInstallerInitramfs_Errors: what is not an Alpine initramfs, or has an
// /init the patches cannot anchor to, is refused rather than served.
func TestInstallerInitramfs_Errors(t *testing.T) {
	t.Run("not an initramfs", func(t *testing.T) {
		c, path := netbootCustomizer(t, []byte("not a cpio archive"))
		assert.Error(t, c.InstallerInitramfs(context.Background(), path))
	})
	for name, init := range map[string]string{
		"init without the setup_inittab_console call": strings.Replace(isotest.AlpineInit, "setup_inittab_console\n", "", 1),
		"init without the configure_ip DHCP block":    strings.Replace(isotest.AlpineInit, "\t\t$MOCK udhcpc -i \"$iface\" -f -q\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			initramfs, err := isotest.Initramfs(map[string]string{"init": init})
			require.NoError(t, err)
			c, path := netbootCustomizer(t, initramfs)
			var msg *MessageError
			require.ErrorAs(t, c.InstallerInitramfs(context.Background(), path), &msg)
		})
	}
	t.Run("missing file", func(t *testing.T) {
		c, _ := netbootCustomizer(t, nil)
		assert.Error(t, c.InstallerInitramfs(context.Background(), filepath.Join(t.TempDir(), "absent")))
	})
}
