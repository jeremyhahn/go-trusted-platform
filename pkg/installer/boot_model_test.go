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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/nbd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
)

// writeLiveCmdline writes cmdline to a file the installer reads in place of
// /proc/cmdline and returns its path.
func writeLiveCmdline(t *testing.T, cmdline string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cmdline")
	require.NoError(t, os.WriteFile(path, []byte(cmdline+"\n"), 0o600))
	return path
}

// installRecorder is an installer whose TPM clear, disk setup and OS install
// are observable: a TPM clear with no device present runs the modprobe
// fallback, which is recorded, and the disk and OS steps go to mocks.
type installRecorder struct {
	installer *installer
	disk      *MockDiskManager
	os        *MockOSInstaller
	modprobes *[]string
}

func newInstallRecorder(t *testing.T, cmdline string) *installRecorder {
	t.Helper()
	dir := t.TempDir()
	withTPMDeviceCandidates(t, []string{filepath.Join(dir, "missing-tpmrm0"), filepath.Join(dir, "missing-tpm0")})
	modprobes := stubTPMModprobe(t)
	origTimeout := tpmDeviceWaitTimeout
	tpmDeviceWaitTimeout = 10 * time.Millisecond
	t.Cleanup(func() { tpmDeviceWaitTimeout = origTimeout })

	disk := new(MockDiskManager)
	osInstaller := new(MockOSInstaller)
	return &installRecorder{
		installer: &installer{
			config:      createTestConfig(),
			logger:      createTestLogger(),
			diskManager: disk,
			osInstaller: osInstaller,
			ukiBuilder:  new(MockUKIBuilder),
			cmdlineFile: writeLiveCmdline(t, cmdline),
		},
		disk:      disk,
		os:        osInstaller,
		modprobes: modprobes,
	}
}

// TestInstall_RefusesDisklessNBDWithoutServerBeforeAnythingDestructive is the
// fail-closed path for a diskless-nbd line with no NBD server to sign into
// the UKI: Install refuses it before it clears the TPM, partitions the disk or
// installs the OS.
func TestInstall_RefusesDisklessNBDWithoutServerBeforeAnythingDestructive(t *testing.T) {
	r := newInstallRecorder(t, "console=ttyS0 alpine_start=autoinstall platform_boot_model=diskless-nbd")
	// Stops a regression at the first disk step so it reports below.
	r.disk.On("CreatePartitionTable", mock.Anything, mock.Anything).Return(errors.New("disk touched")).Maybe()

	err := r.installer.Install(context.Background())

	var installErr *InstallerError
	require.ErrorAs(t, err, &installErr)
	assert.Equal(t, ErrorTypeBootModel, installErr.Type)
	assert.Empty(t, *r.modprobes, "the TPM was not cleared")
	r.disk.AssertNotCalled(t, "CreatePartitionTable", mock.Anything, mock.Anything)
	r.os.AssertNotCalled(t, "InstallBase", mock.Anything, mock.Anything)
}

// TestInstall_DiskNodeReachesTheTPMAndDisk is the control for the test above:
// on the same recorder a disk node's install clears the TPM and partitions
// the disk, so an empty record there means the steps did not run.
func TestInstall_DiskNodeReachesTheTPMAndDisk(t *testing.T) {
	r := newInstallRecorder(t, "console=ttyS0 alpine_start=autoinstall")
	ctx := context.Background()
	r.disk.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(errors.New("disk error"))

	err := r.installer.Install(ctx)

	require.ErrorContains(t, err, "disk setup failed")
	assert.NotEmpty(t, *r.modprobes, "the TPM clear ran")
	r.disk.AssertExpectations(t)
}

func TestCheckBootModel_Installable(t *testing.T) {
	for name, tc := range map[string]struct {
		cmdline string
		model   string
	}{
		"no command line":     {"", ""},
		"a disk node":         {"console=ttyS0 alpine_start=autoinstall", ""},
		"a diskless node":     {"alpine_start=autoinstall platform_boot_model=diskless", disklessroot.BootModel},
		"a diskless-nbd node": {"alpine_start=autoinstall platform_boot_model=diskless-nbd platform_nbd_server=10.0.0.1:10809", nbd.BootModel},
	} {
		t.Run(name, func(t *testing.T) {
			model, err := checkBootModel(tc.cmdline)
			require.NoError(t, err)
			assert.Equal(t, tc.model, model)
		})
	}
}

func TestCheckBootModel_Refused(t *testing.T) {
	for name, cmdline := range map[string]string{
		"a diskless-nbd node without its server": "alpine_start=autoinstall platform_boot_model=diskless-nbd",
		"a malformed NBD server":                 "platform_boot_model=diskless-nbd platform_nbd_server=10.0.0.1",
		"an unknown model":                       "platform_boot_model=nbd",
		"the boot model twice":                   "platform_boot_model=diskless platform_boot_model=diskless",
	} {
		t.Run(name, func(t *testing.T) {
			model, err := checkBootModel(cmdline)
			var installErr *InstallerError
			require.ErrorAs(t, err, &installErr)
			assert.Equal(t, ErrorTypeBootModel, installErr.Type)
			assert.Error(t, installErr.Cause, "the parse failure is kept as the cause")
			assert.Empty(t, model)
		})
	}
}

func TestLiveCmdline_ReadsTheBootCommandLine(t *testing.T) {
	inst := &installer{config: createTestConfig(), cmdlineFile: writeLiveCmdline(t, "platform_boot_model=diskless")}

	assert.Equal(t, "platform_boot_model=diskless\n", inst.liveCmdline())
}

func TestLiveCmdline_NoneToRead(t *testing.T) {
	t.Run("an unreadable command line selects a disk node", func(t *testing.T) {
		inst := &installer{config: createTestConfig(), cmdlineFile: filepath.Join(t.TempDir(), "missing")}
		assert.Empty(t, inst.liveCmdline())
	})
	t.Run("an image target ignores the build host's", func(t *testing.T) {
		config := createTestConfig()
		config.Target = InstallTargetImage
		inst := &installer{config: config, cmdlineFile: writeLiveCmdline(t, "platform_boot_model=diskless-nbd")}
		assert.Empty(t, inst.liveCmdline())
	})
}
