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

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ima"
	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

const efiGlobal = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

// hostTree is a directory standing in for the host's efivarfs, securityfs,
// sysfs and /etc.
type hostTree struct {
	t    *testing.T
	root string
}

func newHostTree(t *testing.T) *hostTree {
	return &hostTree{t: t, root: t.TempDir()}
}

func (h *hostTree) path(rel string) string { return filepath.Join(h.root, rel) }

func (h *hostTree) write(rel, content string) {
	h.t.Helper()
	require.NoError(h.t, os.MkdirAll(filepath.Dir(h.path(rel)), 0o755))
	require.NoError(h.t, os.WriteFile(h.path(rel), []byte(content), 0o644))
}

func (h *hostTree) mkdir(rel string) {
	h.t.Helper()
	require.NoError(h.t, os.MkdirAll(h.path(rel), 0o755))
}

// efivar writes a UEFI boolean variable: four attribute bytes, then the value.
func (h *hostTree) efivar(name string, value byte) {
	h.write(filepath.Join("efivars", name+"-"+efiGlobal), string([]byte{0x06, 0, 0, 0, value}))
}

// rootOn records a root mount on the block device major:minor.
func (h *hostTree) rootOn(devNum, source string) {
	h.write("mountinfo", "1 0 0:2 / /proc rw - proc proc rw\n"+
		"22 1 "+devNum+" / / rw,relatime shared:1 - ext4 "+source+" rw\n")
}

func (h *hostTree) posture() *HostPosture {
	return &HostPosture{
		EfivarsDir:    h.path("efivars"),
		SecurityFSDir: h.path("security"),
		MountInfoPath: h.path("mountinfo"),
		SysfsDir:      h.path("sys"),
		OSReleasePath: h.path("os-release"),
		AgentVersion:  "1.2.3",
		KernelRelease: func() (string, error) { return "6.12.0-test", nil },
		Now:           func() time.Time { return time.Unix(1760300000, 0) },
	}
}

// encryptedHost is a UEFI host with Secure Boot on, IMA measuring, and root
// on a LUKS mapping.
func encryptedHost(t *testing.T) *hostTree {
	h := newHostTree(t)
	h.efivar("SecureBoot", 1)
	h.efivar("SetupMode", 0)
	h.write("security/ima/ascii_runtime_measurements", "10 abc ima-ng sha256:00 boot_aggregate\n")
	h.write("security/ima/policy", "")
	h.rootOn("253:0", "/dev/mapper/root")
	h.write("sys/dev/block/253:0/dm/uuid", "CRYPT-LUKS2-0123-root\n")
	h.write("os-release", "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n")
	return h
}

func TestHostPosture_CollectsEveryFact(t *testing.T) {
	report, err := encryptedHost(t).posture().Collect(context.Background())

	require.NoError(t, err)
	sum := sha256.Sum256([]byte("10 abc ima-ng sha256:00 boot_aggregate\n"))
	assert.Equal(t, &gwvpn.PostureReport{
		SecureBoot:    gwvpn.SecureBootPosture{Available: true, Enabled: true},
		IMA:           gwvpn.IMAPosture{Available: true, Enabled: true, PolicyLoaded: true, LogDigest: hex.EncodeToString(sum[:])},
		FDE:           gwvpn.FDEPosture{RootEncrypted: true},
		AgentVersion:  "1.2.3",
		OSRelease:     "Debian GNU/Linux 13 (trixie)",
		KernelRelease: "6.12.0-test",
		CollectedAt:   time.Unix(1760300000, 0).UTC(),
	}, report)
}

func TestHostPosture_ReportsWhatTheHostCannotHaveAsUnavailable(t *testing.T) {
	h := newHostTree(t)
	h.rootOn("8:2", "/dev/sda2")
	h.mkdir("sys/dev/block/8:2")

	report, err := h.posture().Collect(context.Background())

	require.NoError(t, err)
	assert.Equal(t, gwvpn.SecureBootPosture{}, report.SecureBoot, "a BIOS boot has no efivarfs")
	assert.Equal(t, gwvpn.IMAPosture{}, report.IMA, "no securityfs")
	assert.False(t, report.FDE.RootEncrypted)
	assert.Empty(t, report.OSRelease)
}

func TestHostPosture_SecureBootOffAndSetupMode(t *testing.T) {
	h := encryptedHost(t)
	h.efivar("SecureBoot", 0)
	h.efivar("SetupMode", 1)

	report, err := h.posture().Collect(context.Background())

	require.NoError(t, err)
	assert.Equal(t, gwvpn.SecureBootPosture{Available: true, Enabled: false, SetupMode: true}, report.SecureBoot)
}

func TestHostPosture_IMAWithoutAnIMADirectoryIsNotEnabled(t *testing.T) {
	h := encryptedHost(t)
	require.NoError(t, os.RemoveAll(h.path("security/ima")))
	h.mkdir("security")

	report, err := h.posture().Collect(context.Background())

	require.NoError(t, err)
	assert.Equal(t, gwvpn.IMAPosture{}, report.IMA)
}

func TestHostPosture_FindsLUKSUnderOtherDeviceMapperLayers(t *testing.T) {
	h := encryptedHost(t)
	require.NoError(t, os.RemoveAll(h.path("sys")))
	h.rootOn("253:1", "/dev/mapper/vg-root")
	h.write("sys/dev/block/253:1/dm/uuid", "LVM-abcdef\n")
	h.mkdir("sys/dev/block/253:1/slaves/dm-0")
	h.write("sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-0123-crypt\n")

	report, err := h.posture().Collect(context.Background())

	require.NoError(t, err)
	assert.True(t, report.FDE.RootEncrypted)
}

func TestHostPosture_PlainDeviceMapperIsNotEncryption(t *testing.T) {
	h := encryptedHost(t)
	require.NoError(t, os.RemoveAll(h.path("sys")))
	h.rootOn("253:1", "/dev/mapper/vg-root")
	h.write("sys/dev/block/253:1/dm/uuid", "LVM-abcdef\n")
	h.mkdir("sys/dev/block/253:1/slaves/sda2")
	h.mkdir("sys/class/block/sda2")

	report, err := h.posture().Collect(context.Background())

	require.NoError(t, err)
	assert.False(t, report.FDE.RootEncrypted)
}

func TestHostPosture_StopsWalkingACyclicStack(t *testing.T) {
	h := encryptedHost(t)
	require.NoError(t, os.RemoveAll(h.path("sys")))
	h.rootOn("253:1", "/dev/mapper/loop")
	h.mkdir("sys/dev/block/253:1/slaves/dm-1")
	h.mkdir("sys/class/block/dm-1/slaves/dm-1")

	report, err := h.posture().Collect(context.Background())

	require.NoError(t, err)
	assert.False(t, report.FDE.RootEncrypted)
}

// Root on LVM or RAID is encrypted only when every path down to the physical
// devices passes through LUKS; an unreadable part of the tree fails closed.
func TestHostPosture_RootIsEncryptedOnlyWhenEveryBackingDeviceIs(t *testing.T) {
	tests := []struct {
		name      string
		tree      func(h *hostTree)
		encrypted bool
	}{
		{"LVM over two LUKS volumes", func(h *hostTree) {
			h.mkdir("sys/dev/block/253:1/slaves/dm-0")
			h.mkdir("sys/dev/block/253:1/slaves/dm-2")
			h.write("sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-0123-a\n")
			h.write("sys/class/block/dm-2/dm/uuid", "CRYPT-LUKS2-0123-b\n")
		}, true},
		{"LVM over one LUKS volume and one plain partition", func(h *hostTree) {
			h.mkdir("sys/dev/block/253:1/slaves/dm-0")
			h.mkdir("sys/dev/block/253:1/slaves/sdb1")
			h.write("sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-0123-a\n")
			h.mkdir("sys/class/block/sdb1")
		}, false},
		{"LVM on RAID on LUKS", func(h *hostTree) {
			h.mkdir("sys/dev/block/253:1/slaves/md0")
			h.mkdir("sys/class/block/md0/slaves/dm-0")
			h.mkdir("sys/class/block/md0/slaves/dm-2")
			h.write("sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-0123-a\n")
			h.write("sys/class/block/dm-2/dm/uuid", "CRYPT-LUKS2-0123-b\n")
		}, true},
		{"LVM on RAID with one plain member", func(h *hostTree) {
			h.mkdir("sys/dev/block/253:1/slaves/md0")
			h.mkdir("sys/class/block/md0/slaves/dm-0")
			h.mkdir("sys/class/block/md0/slaves/sdb1/slaves")
			h.write("sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-0123-a\n")
		}, false},
		{"a mapping with no backing devices", func(h *hostTree) {
			h.mkdir("sys/dev/block/253:1/slaves")
		}, false},
		{"an unreadable slave list", func(h *hostTree) {
			h.mkdir("sys/dev/block/253:1/slaves/dm-0")
			h.mkdir("sys/dev/block/253:1/slaves/md0")
			h.write("sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-0123-a\n")
			h.write("sys/class/block/md0/slaves", "")
		}, false},
		{"an unreadable dm uuid", func(h *hostTree) {
			h.mkdir("sys/dev/block/253:1/slaves/dm-0")
			h.mkdir("sys/dev/block/253:1/slaves/dm-2")
			h.write("sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-0123-a\n")
			h.mkdir("sys/class/block/dm-2/dm/uuid")
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := encryptedHost(t)
			require.NoError(t, os.RemoveAll(h.path("sys")))
			h.rootOn("253:1", "/dev/mapper/vg-root")
			h.write("sys/dev/block/253:1/dm/uuid", "LVM-abcdef\n")
			tt.tree(h)

			report, err := h.posture().Collect(context.Background())

			require.NoError(t, err)
			assert.Equal(t, tt.encrypted, report.FDE.RootEncrypted)
		})
	}
}

func TestHostPosture_UsesTheLastMountOnRoot(t *testing.T) {
	h := encryptedHost(t)
	h.write("mountinfo", "22 1 8:2 / / rw - ext4 /dev/sda2 rw\n"+
		"30 22 253:0 / / rw - ext4 /dev/mapper/root rw\n")
	h.mkdir("sys/dev/block/8:2")

	report, err := h.posture().Collect(context.Background())

	require.NoError(t, err)
	assert.True(t, report.FDE.RootEncrypted, "the later mount hides the earlier one")
}

func TestHostPosture_FallsBackToTheSourceDeviceForAnonymousDeviceNumbers(t *testing.T) {
	h := encryptedHost(t)
	require.NoError(t, os.RemoveAll(h.path("sys")))
	h.write("dev/nvme0n1p2", "")
	h.rootOn("0:30", h.path("dev/nvme0n1p2"))
	h.write("sys/class/block/nvme0n1p2/dm/uuid", "CRYPT-LUKS1-0123-root\n")

	report, err := h.posture().Collect(context.Background())

	require.NoError(t, err)
	assert.True(t, report.FDE.RootEncrypted)
}

func TestHostPosture_BtrfsRootIsEncryptedOnlyWhenEveryMemberDeviceIs(t *testing.T) {
	tests := []struct {
		name      string
		tree      func(h *hostTree)
		encrypted bool
	}{
		{"a single LUKS member", func(h *hostTree) {
			h.mkdir("sys/fs/btrfs/features")
			h.mkdir("sys/fs/btrfs/0123-fsid/devices/dm-0")
		}, true},
		{"every member on LUKS", func(h *hostTree) {
			h.mkdir("sys/fs/btrfs/0123-fsid/devices/dm-0")
			h.mkdir("sys/fs/btrfs/0123-fsid/devices/dm-1")
			h.write("sys/class/block/dm-1/dm/uuid", "CRYPT-LUKS2-0123-b\n")
		}, true},
		{"one plain member", func(h *hostTree) {
			h.mkdir("sys/fs/btrfs/0123-fsid/devices/dm-0")
			h.mkdir("sys/fs/btrfs/0123-fsid/devices/sdb1")
			h.mkdir("sys/class/block/sdb1")
		}, false},
		{"a member that cannot be read", func(h *hostTree) {
			h.mkdir("sys/fs/btrfs/0123-fsid/devices/dm-0")
			h.mkdir("sys/fs/btrfs/0123-fsid/devices/dm-1")
			h.mkdir("sys/class/block/dm-1/dm/uuid")
		}, false},
		{"a member missing from the block class", func(h *hostTree) {
			h.mkdir("sys/fs/btrfs/0123-fsid/devices/dm-0")
			h.mkdir("sys/fs/btrfs/0123-fsid/devices/dm-1")
		}, false},
		{"the source in no btrfs filesystem", func(h *hostTree) {
			h.mkdir("sys/fs/btrfs/4567-fsid/devices/dm-1")
			h.write("sys/class/block/dm-1/dm/uuid", "CRYPT-LUKS2-0123-b\n")
		}, false},
		{"no btrfs filesystems in sysfs", func(h *hostTree) {}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := encryptedHost(t)
			require.NoError(t, os.RemoveAll(h.path("sys")))
			h.write("dev/dm-0", "")
			h.write("mountinfo", "22 1 0:30 /@ / rw - btrfs "+h.path("dev/dm-0")+" rw\n")
			h.write("sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-0123-a\n")
			tt.tree(h)

			report, err := h.posture().Collect(context.Background())

			require.NoError(t, err)
			assert.Equal(t, tt.encrypted, report.FDE.RootEncrypted)
		})
	}
}

func TestHostPosture_AnUnresolvableSourceIsNotEncryption(t *testing.T) {
	for _, source := range []string{"overlay", "/dev/does-not-exist"} {
		t.Run(source, func(t *testing.T) {
			h := encryptedHost(t)
			h.write("mountinfo", "22 1 0:30 / / rw - overlay "+source+" rw\n")

			report, err := h.posture().Collect(context.Background())

			require.NoError(t, err)
			assert.False(t, report.FDE.RootEncrypted)
		})
	}
}

func TestHostPosture_FailsOnAFactThatExistsButCannotBeRead(t *testing.T) {
	tests := []struct {
		name     string
		sabotage func(h *hostTree)
		fact     string
	}{
		{"corrupt efivar", func(h *hostTree) { h.write("efivars/SecureBoot-"+efiGlobal, "\x06") }, "secure_boot"},
		{"unreadable IMA log", func(h *hostTree) {
			require.NoError(t, os.Remove(h.path("security/ima/ascii_runtime_measurements")))
			h.mkdir("security/ima/ascii_runtime_measurements")
		}, "ima"},
		{"no mount table", func(h *hostTree) { require.NoError(t, os.Remove(h.path("mountinfo"))) }, "fde"},
		{"unreadable os-release", func(h *hostTree) {
			require.NoError(t, os.Remove(h.path("os-release")))
			h.mkdir("os-release")
		}, "os_release"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := encryptedHost(t)
			tt.sabotage(h)

			_, err := h.posture().Collect(context.Background())

			var fact *ErrPostureFact
			require.ErrorAs(t, err, &fact)
			assert.Equal(t, tt.fact, fact.Fact)
		})
	}
}

func TestHostPosture_AMountTableWithoutRootIsAnError(t *testing.T) {
	h := encryptedHost(t)
	h.write("mountinfo", "1 0 0:2 / /proc rw - proc proc rw\nmalformed line\n")

	_, err := h.posture().Collect(context.Background())

	var noRoot *ErrNoRootMount
	require.ErrorAs(t, err, &noRoot)
	assert.Equal(t, h.path("mountinfo"), noRoot.MountInfo)
}

func TestHostPosture_ReportsAKernelReleaseFailure(t *testing.T) {
	p := encryptedHost(t).posture()
	p.KernelRelease = func() (string, error) { return "", &errFake{"uname"} }

	_, err := p.Collect(context.Background())

	var fact *ErrPostureFact
	require.ErrorAs(t, err, &fact)
	assert.Equal(t, "kernel_release", fact.Fact)
}

func TestHostPosture_HonoursACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := encryptedHost(t).posture().Collect(ctx)

	assert.ErrorIs(t, err, context.Canceled)
}

func TestHostPosture_ReadsPrettyNameInEveryQuoting(t *testing.T) {
	tests := []struct {
		content string
		want    string
	}{
		{"PRETTY_NAME=\"Fedora Linux 43\"\n", "Fedora Linux 43"},
		{"PRETTY_NAME='Alpine Linux v3.22'\n", "Alpine Linux v3.22"},
		{"  PRETTY_NAME=Arch\n", "Arch"},
		{"NAME=Debian\n", ""},
	}
	for _, tt := range tests {
		h := encryptedHost(t)
		h.write("os-release", tt.content)
		got, err := h.posture().osRelease()
		require.NoError(t, err)
		assert.Equal(t, tt.want, got)
	}
}

func TestNewHostPosture_ReadsTheRunningHost(t *testing.T) {
	p := NewHostPosture("1.2.3")

	assert.Equal(t, uefi.EfivarsPath, p.EfivarsDir)
	assert.Equal(t, ima.DefaultSecurityFSPath, p.SecurityFSDir)
	assert.Equal(t, "/proc/self/mountinfo", p.MountInfoPath)
	release, err := p.KernelRelease()
	require.NoError(t, err)
	assert.NotEmpty(t, release)
}
