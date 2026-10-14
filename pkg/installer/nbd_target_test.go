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

package installer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const nbdLiveCmdline = "console=ttyS0 alpine_start=autoinstall platform_boot_model=diskless-nbd platform_nbd_server=10.0.0.1:10809"

// fakeNBDSysfs builds a sysfs root holding block/nbd0 with the given files;
// a nil map leaves nbd0 out entirely, as when the nbd module is not loaded.
func fakeNBDSysfs(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if files == nil {
		return root
	}
	dir := filepath.Join(root, "block", "nbd0")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
	}
	return root
}

func attachedNBDSysfs(t *testing.T) string {
	return fakeNBDSysfs(t, map[string]string{"pid": "412\n", "size": "16777216\n"})
}

func TestCheckNBDAttached_Attached(t *testing.T) {
	assert.NoError(t, checkNBDAttached(attachedNBDSysfs(t), nbdTargetDevice))
}

func TestCheckNBDAttached_Refused(t *testing.T) {
	for name, tc := range map[string]struct {
		files  map[string]string
		reason string
	}{
		"no nbd0 block device":       {nil, "no such block device"},
		"loaded but not attached":    {map[string]string{"size": "0\n"}, "not attached"},
		"attached with size 0":       {map[string]string{"pid": "412\n", "size": "0\n"}, "size 0"},
		"size missing":               {map[string]string{"pid": "412\n"}, "size unreadable"},
		"size is not a sector count": {map[string]string{"pid": "412\n", "size": "lots\n"}, "not a number"},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkNBDAttached(fakeNBDSysfs(t, tc.files), nbdTargetDevice)
			var targetErr *NBDTargetError
			require.ErrorAs(t, err, &targetErr)
			assert.Equal(t, nbdTargetDevice, targetErr.Device)
			assert.Contains(t, targetErr.Reason, tc.reason)
		})
	}
}

// TestInstall_DisklessNBDInstallsOntoTheExport runs Phase A for a
// diskless-nbd node through the disk steps a disk install uses: it clears
// the TPM, partitions /dev/nbd0 (not the configured disk), LUKS2-formats its
// second partition, and mounts the first, the metadata area, where the
// installer writes the seal artifacts. The OS step then sees the export.
func TestInstall_DisklessNBDInstallsOntoTheExport(t *testing.T) {
	r := newInstallRecorder(t, nbdLiveCmdline)
	r.installer.sysfsRoot = attachedNBDSysfs(t)
	// A Pi profile partitions its local disk MBR; the export is GPT anyway.
	r.installer.config.Disk.PartitionTable = PartitionTableMBR
	anyArg := mock.Anything
	r.disk.On("CreatePartitionTable", anyArg, PartitionTableGPT).Return(nil)
	r.disk.On("CreateEFIPartition", anyArg, 0).Return(nil)
	r.disk.On("CreateRootPartition", anyArg).Return(nil)
	r.disk.On("SetupLUKS", anyArg, "", r.installer.config.Disk.Encryption).Return("/dev/mapper/cryptroot", nil)
	r.disk.On("CreateLVMPhysicalVolume", anyArg, "/dev/mapper/cryptroot").Return(nil)
	r.disk.On("CreateLVMVolumeGroup", anyArg, "vg0", []string{"/dev/mapper/cryptroot"}).Return(nil)
	r.disk.On("CreateLVMLogicalVolume", anyArg, "vg0", "root", "100%FREE").Return("/dev/mapper/vg0-root", nil)
	r.disk.On("FormatFilesystem", anyArg, "/dev/mapper/vg0-root", "ext4", "root").Return(nil)
	r.disk.On("Mount", anyArg, "/dev/mapper/vg0-root", "/mnt", "ext4", uintptr(0)).Return(nil)
	r.disk.On("EnsureDeviceNode", anyArg, "/dev/nbd0p1", anyArg).Return(nil)
	r.disk.On("Mount", anyArg, "/dev/nbd0p1", "/mnt/boot/efi", "vfat", uintptr(0)).Return(nil)
	r.os.On("InstallBase", anyArg, "/mnt").Return(nil)
	var installed *DiskInfo
	r.os.On("ConfigureSystem", anyArg, "/mnt", anyArg).
		Run(func(args mock.Arguments) { installed = args.Get(2).(*DiskInfo) }).
		Return(errors.New("stop after the disk"))

	err := r.installer.Install(context.Background())

	require.ErrorContains(t, err, "stop after the disk")
	assert.Empty(t, *r.modprobes, "the TPM clear ran; it would evict the IDevID the export attaches with")
	r.disk.AssertExpectations(t)
	assert.Equal(t, nbdTargetDevice, r.installer.config.Disk.Device)
	assert.Equal(t, PartitionTableGPT, r.installer.config.Disk.PartitionTable)
	require.NotNil(t, installed)
	assert.Equal(t, nbdTargetDevice, installed.Device)
	assert.Equal(t, "/dev/nbd0p1", installed.EFIPartition)
	assert.Equal(t, "/dev/nbd0p2", installed.RootPartition)
	assert.Equal(t, "/dev/mapper/cryptroot", installed.MappedDevice)
}

// TestInstall_RefusesAnUnusableNBDTargetBeforeAnythingDestructive: a
// diskless-nbd install whose export is missing, unattached or empty, or whose
// config would leave it unencrypted, stops before the TPM clear or any
// format, and leaves the configured device alone.
func TestInstall_RefusesAnUnusableNBDTargetBeforeAnythingDestructive(t *testing.T) {
	for name, tc := range map[string]struct {
		files       map[string]string
		unencrypted bool
	}{
		"no nbd0":            {files: nil},
		"nbd0 not attached":  {files: map[string]string{"size": "0\n"}},
		"export of size 0":   {files: map[string]string{"pid": "412\n", "size": "0\n"}},
		"no disk.encryption": {files: map[string]string{"pid": "412\n", "size": "16777216\n"}, unencrypted: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newInstallRecorder(t, nbdLiveCmdline)
			r.installer.sysfsRoot = fakeNBDSysfs(t, tc.files)
			r.installer.config.Disk.PartitionTable = PartitionTableMBR
			if tc.unencrypted {
				r.installer.config.Disk.Encryption = nil
			}
			r.disk.On("CreatePartitionTable", mock.Anything, mock.Anything).Return(errors.New("disk touched")).Maybe()

			err := r.installer.Install(context.Background())

			var installErr *InstallerError
			require.ErrorAs(t, err, &installErr)
			assert.Equal(t, ErrorTypeNBDTarget, installErr.Type)
			var targetErr *NBDTargetError
			require.ErrorAs(t, err, &targetErr)
			assert.Equal(t, nbdTargetDevice, targetErr.Device)
			assert.Empty(t, *r.modprobes, "the TPM was not cleared")
			r.disk.AssertNotCalled(t, "CreatePartitionTable", mock.Anything, mock.Anything)
			assert.Equal(t, "/dev/sda", r.installer.config.Disk.Device)
			assert.Equal(t, PartitionTableMBR, r.installer.config.Disk.PartitionTable)
		})
	}
}

// TestInstall_DiskNodeIgnoresNBD: a disk node never looks at nbd0,
// so an absent one does not stop it and its configured device is kept.
func TestInstall_DiskNodeIgnoresNBD(t *testing.T) {
	r := newInstallRecorder(t, "console=ttyS0 alpine_start=autoinstall platform_nbd_server=10.0.0.1:10809")
	r.installer.sysfsRoot = fakeNBDSysfs(t, nil)
	r.disk.On("CreatePartitionTable", mock.Anything, PartitionTableGPT).Return(errors.New("disk error"))

	err := r.installer.Install(context.Background())

	require.ErrorContains(t, err, "disk setup failed")
	assert.Equal(t, "/dev/sda", r.installer.config.Disk.Device)
	assert.NotEmpty(t, *r.modprobes, "a disk node's TPM is cleared before the install")
}

func TestDisklessCmdlineParams_NBDNodeSignsOnlyTheServer(t *testing.T) {
	inst := &installer{config: createTestConfig(), logger: createTestLogger()}
	// Everything here but the model and the server is the live line's own,
	// and none of it may reach the signed command line.
	live := nbdLiveCmdline + " root=/dev/sda2 rd.luks.uuid=attacker platform_rootfs_url=http://evil/root.sqfs platform_debug_sink=http://10.0.0.1:8080"

	params, err := inst.disklessCmdlineParams(context.Background(), live)
	require.NoError(t, err)
	assert.Equal(t, []string{"platform_boot_model=diskless-nbd", "platform_nbd_server=10.0.0.1:10809"}, params)

	args := inst.ukiRootCmdlineParams(encryptedLVMDisk, params)
	assert.Equal(t, params, args)
	joined := " " + strings.Join(append(args, hostUKICmdlineParams(live, false)...), " ")
	for _, local := range []string{"root=", "rd.luks", "rd.lvm", "rootfstype=", "platform_rootfs_url", "platform_debug_sink", "console="} {
		assert.NotContains(t, joined, " "+local)
	}
}

func TestDisklessCmdlineParams_NBDServerRefused(t *testing.T) {
	inst := &installer{config: createTestConfig(), logger: createTestLogger()}
	for name, live := range map[string]string{
		"no server":    "platform_boot_model=diskless-nbd",
		"no port":      "platform_boot_model=diskless-nbd platform_nbd_server=10.0.0.1",
		"server twice": "platform_boot_model=diskless-nbd platform_nbd_server=10.0.0.1:10809 platform_nbd_server=10.0.0.2:10809",
	} {
		t.Run(name, func(t *testing.T) {
			params, err := inst.disklessCmdlineParams(context.Background(), live)
			var installErr *InstallerError
			require.ErrorAs(t, err, &installErr)
			assert.Equal(t, ErrorTypeUKIBuild, installErr.Type)
			assert.Nil(t, params)
		})
	}
}

func TestEspFstabSource(t *testing.T) {
	t.Run("a diskless-nbd node mounts the export's metadata partition by path", func(t *testing.T) {
		assert.Equal(t, "/dev/nbd0p1", espFstabSource(&DiskInfo{Device: nbdTargetDevice, EFIPartition: "/dev/nbd0p1"}))
	})
	t.Run("a disk node keeps the EFI label", func(t *testing.T) {
		assert.Equal(t, "LABEL=EFI", espFstabSource(&DiskInfo{Device: "/dev/sda", EFIPartition: "/dev/sda1"}))
	})
}

func TestErrNBDTarget(t *testing.T) {
	cause := &NBDTargetError{Device: nbdTargetDevice, Reason: "not attached"}
	err := ErrNBDTarget("refusing to install", cause)

	var installErr *InstallerError
	require.ErrorAs(t, err, &installErr)
	assert.Equal(t, ErrorTypeNBDTarget, installErr.Type)
	assert.ErrorIs(t, err, cause)
	assert.Equal(t, "/dev/nbd0: not attached", cause.Error())
}
