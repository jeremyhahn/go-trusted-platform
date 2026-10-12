package iso

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// diskCmdline is the command line the installer signs for an encrypted
	// LVM disk node.
	diskCmdline = "root=/dev/platform/root rd.luks.uuid=5b1c7a52 rd.luks.name=5b1c7a52=cryptroot rd.lvm=1 rd.lvm.vg=platform rootfstype=ext4 ro console=ttyS0"
	// disklessCmdline is the command line the installer signs for a
	// diskless node: the verified image and no local root.
	disklessCmdline = "platform_boot_model=diskless platform_rootfs_url=http://192.0.2.10/set/rootfs.squashfs " +
		"platform_verity_url=http://192.0.2.10/set/rootfs.verity platform_roothash=1111 ro console=ttyS0"
)

// runBootModelShell sources the shipped helpers under /bin/sh, with dracut's
// info helper stubbed, runs script against a command-line file holding
// cmdline (none when cmdline is nil) and returns stdout.
func runBootModelShell(t *testing.T, cmdline *string, script string) string {
	t.Helper()
	dir := t.TempDir()
	helper := filepath.Join(dir, "boot-model.sh")
	require.NoError(t, os.WriteFile(helper, []byte(platformdBootModelShell), 0o600))
	cmdlineFile := filepath.Join(dir, "cmdline")
	if cmdline != nil {
		require.NoError(t, os.WriteFile(cmdlineFile, []byte(*cmdline+"\n"), 0o600))
	}
	out, err := exec.Command("/bin/sh", "-c", `info() { :; }; . "$0" && `+script, helper, cmdlineFile).CombinedOutput()
	require.NoError(t, err, "shell output: %s", out)
	return strings.TrimSpace(string(out))
}

func TestPlatformdBootModelShell(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmdline string
		want    string
	}{
		{name: "a diskless node", cmdline: disklessCmdline, want: "diskless"},
		{name: "the selector last on the line", cmdline: "ro platform_boot_model=diskless", want: "diskless"},
		{name: "tab separated", cmdline: "ro\tplatform_boot_model=diskless\tquiet", want: "diskless"},
		{name: "a disk node", cmdline: diskCmdline, want: "disk"},
		{name: "stray diskless parameters without the selector", cmdline: diskCmdline + " platform_roothash=1111 platform_rootfs_url=http://192.0.2.10/r", want: "disk"},
		{name: "another model", cmdline: "platform_boot_model=nbd", want: "disk"},
		{name: "a longer value", cmdline: "platform_boot_model=disklessx", want: "disk"},
		{name: "a longer key", cmdline: "xplatform_boot_model=diskless", want: "disk"},
		{name: "an empty line", cmdline: "", want: "disk"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, runBootModelShell(t, &tc.cmdline, `platformd_boot_model "$1"`))
		})
	}

	t.Run("no command line file", func(t *testing.T) {
		assert.Equal(t, "disk", runBootModelShell(t, nil, `platformd_boot_model "$1"`))
	})
}

func TestPlatformdSetRootShell(t *testing.T) {
	const report = `platformd_set_root "$1"; echo "root=$root rootok=$rootok rootfstype=$rootfstype"`

	t.Run("a disk node keeps its LUKS root", func(t *testing.T) {
		cmdline := diskCmdline
		assert.Equal(t, "root=/dev/platform/root rootok=1 rootfstype=ext4", runBootModelShell(t, &cmdline, report))
	})

	t.Run("a diskless node names no device", func(t *testing.T) {
		cmdline := disklessCmdline
		assert.Equal(t, "root="+platformdDisklessRoot+" rootok=1 rootfstype=", runBootModelShell(t, &cmdline, report))
	})

	t.Run("a diskless parameter is not read as root=", func(t *testing.T) {
		cmdline := "platform_roothash=1111 rd.root=/dev/sdz9 rootfstype=ext4"
		assert.Equal(t, "root= rootok= rootfstype=ext4", runBootModelShell(t, &cmdline, report))
	})

	t.Run("no command line file leaves dracut's defaults", func(t *testing.T) {
		assert.Equal(t, "root= rootok= rootfstype=", runBootModelShell(t, nil, report))
	})
}

func TestCopyDracutModule_DisklessMode(t *testing.T) {
	tmpDir := t.TempDir()
	isoDir := filepath.Join(tmpDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0o755))
	customizer := NewCustomizer(&PlatformISOConfig{
		Directories: DirectoryConfig{ISO: isoDir, Overlay: filepath.Join(tmpDir, "overlay")},
	}, logging.DefaultLogger())
	require.NoError(t, customizer.CopyDracutModule(context.Background()))

	moduleDir := filepath.Join(isoDir, "dracut-platformd", "90platformd")
	hooks := map[string]string{}
	for _, name := range []string{"module-setup.sh", "platformd-unlock.sh", "platformd-root.sh", "platformd-finished.sh", "platformd-mount.sh"} {
		path := filepath.Join(moduleDir, name)
		out, err := exec.Command("/bin/sh", "-n", path).CombinedOutput()
		require.NoError(t, err, "%s does not parse: %s", name, out)
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		hooks[name] = string(raw)
	}

	t.Run("the unlock hook takes the diskless root before looking for LUKS", func(t *testing.T) {
		unlock := hooks["platformd-unlock.sh"]
		dispatch := strings.Index(unlock, `if [ "$(platformd_boot_model /etc/kernel/cmdline)" = "diskless" ]; then`+"\n    platformd_diskless_root\n    return 0")
		luks := strings.Index(unlock, "# Find LUKS device by UUID")
		require.NotEqual(t, -1, dispatch, "the unlock hook has no diskless dispatch")
		require.NotEqual(t, -1, luks)
		assert.Less(t, dispatch, luks)
		assert.Less(t, strings.Index(unlock, "/tmp/platformd-unlock-done"), dispatch, "a mounted root is not mounted twice")
		assert.Contains(t, unlock, "platformd_run_initrd boot --diskless --root-mount")
	})

	t.Run("a disk install still unlocks LUKS", func(t *testing.T) {
		unlock := hooks["platformd-unlock.sh"]
		assert.Contains(t, unlock, `platformd_run_initrd boot --device "$LUKS_DEV" --name "$LUKS_NAME" $PCR_FLAG`)
		assert.Contains(t, unlock, `ln -sf "$ROOT_DEV" /dev/root`)
		assert.Contains(t, hooks["platformd-root.sh"], "platformd_set_root /etc/kernel/cmdline")
	})

	t.Run("dracut waits for and mounts nothing else on a diskless node", func(t *testing.T) {
		assert.Contains(t, hooks["platformd-finished.sh"], `if [ "$root" = "`+platformdDisklessRoot+`" ]; then`)
		assert.Contains(t, hooks["platformd-mount.sh"], `if [ "$root" = "`+platformdDisklessRoot+`" ]; then`)
	})

	t.Run("the initramfs carries the diskless root's modules and tools", func(t *testing.T) {
		setup := hooks["module-setup.sh"]
		assert.Contains(t, setup, "instmods dm_verity squashfs overlay")
		assert.Contains(t, setup, " dmsetup tr mountpoint;")
		assert.Contains(t, setup, "platformd_install_network() {")
		assert.Contains(t, setup, `platformd_install_network "" /etc/kernel/cmdline || return 1`,
			"the root is fetched over DHCP: the build must carry udhcpc and its lease script")
	})
}

// seedNode runs platformd_seed_node_settings for one node against root, with
// the NET_* values platformd_network_up would have set from that node's
// network.conf, and returns the shell's combined output.
func seedNode(t *testing.T, root, resolv string, env ...string) (string, error) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "seed.sh")
	require.NoError(t, os.WriteFile(script, []byte(platformdStaticCIDRShell+platformdDisklessRootShell), 0600))
	cmd := exec.Command("/bin/sh", "-c", `. "$0" && platformd_seed_node_settings "$1" "$2"`, script, root, resolv)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// sharedRoot is a copy of the shared root's node-specific files, as every node
// of a media set sees them: a hostname, an interfaces file and a resolv.conf
// symlink into /run.
func sharedRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc", "network"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc", "hostname"), []byte("shared\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc", "network", "interfaces"), []byte("iface eth0 inet dhcp\n"), 0o644))
	require.NoError(t, os.Symlink("/run/shared-resolv.conf", filepath.Join(root, "etc", "resolv.conf")))
	return root
}

func TestPlatformdDisklessRootShell_NodesKeepTheirOwnSettings(t *testing.T) {
	resolv := filepath.Join(t.TempDir(), "resolv.conf")
	require.NoError(t, os.WriteFile(resolv, []byte("nameserver 192.0.2.53\n"), 0o644))
	read := func(root, name string) string {
		b, err := os.ReadFile(filepath.Join(root, name))
		require.NoError(t, err)
		return string(b)
	}

	nodeA, nodeB := sharedRoot(t), sharedRoot(t)
	out, err := seedNode(t, nodeA, resolv, "NET_HOSTNAME=node-a", "NET_IFACE=eth1", "NET_TYPE=static",
		"NET_IP=198.51.100.10", "NET_PREFIX=24", "NET_GW=198.51.100.1")
	require.NoError(t, err, out)
	out, err = seedNode(t, nodeB, resolv, "NET_HOSTNAME=node-b", "NET_TYPE=dhcp")
	require.NoError(t, err, out)

	assert.Equal(t, "node-a\n", read(nodeA, "etc/hostname"))
	assert.Equal(t, "node-b\n", read(nodeB, "etc/hostname"))
	assert.Contains(t, read(nodeA, "etc/network/interfaces"), "iface eth1 inet static")
	assert.Contains(t, read(nodeA, "etc/network/interfaces"), "address 198.51.100.10/24")
	assert.Contains(t, read(nodeA, "etc/network/interfaces"), "gateway 198.51.100.1")
	assert.Contains(t, read(nodeB, "etc/network/interfaces"), "iface eth0 inet dhcp")
	assert.NotContains(t, read(nodeB, "etc/network/interfaces"), "198.51.100")
	for _, root := range []string{nodeA, nodeB} {
		assert.Equal(t, "nameserver 192.0.2.53\n", read(root, "etc/resolv.conf"))
		info, err := os.Lstat(filepath.Join(root, "etc", "resolv.conf"))
		require.NoError(t, err)
		assert.True(t, info.Mode().IsRegular(), "the shared root's resolv.conf symlink is replaced, not written through")
	}
}

func TestPlatformdDisklessRootShell_SeedFailsOnAnUnwritableRoot(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	_, err := seedNode(t, file, "/nonexistent", "NET_HOSTNAME=node-a")
	assert.Error(t, err)
}

func TestPlatformdDisklessRootShell_SeedsBeforeTheRootIsReleased(t *testing.T) {
	seed := strings.Index(platformdDisklessRootShell, `platformd_seed_node_settings "${NEWROOT:-/sysroot}"`)
	done := strings.Index(platformdDisklessRootShell, "touch /tmp/platformd-unlock-done")
	require.NotEqual(t, -1, seed)
	assert.Less(t, seed, done)
}
