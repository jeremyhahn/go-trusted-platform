package installer

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// releaseRecorder records every operation releaseDisk performs, in order,
// and answers from the tables the test fills.
type releaseRecorder struct {
	calls          []string
	unmountErr     map[string]error // keyed by "<target>:<flags>"
	removeDMErr    error
	lockErr        error
	mappingPresent bool // device-mapper still reports the mapping after removal
}

func (r *releaseRecorder) ops() diskRelease {
	return diskRelease{
		unmount: func(target string, flags int) error {
			key := target + ":" + map[int]string{0: "regular", unix.MNT_DETACH: "detach"}[flags]
			r.calls = append(r.calls, "unmount "+key)
			return r.unmountErr[key]
		},
		removeDM: func(name string) error {
			r.calls = append(r.calls, "removeDM "+name)
			return r.removeDMErr
		},
		lockLUKS: func(name string) error {
			r.calls = append(r.calls, "lockLUKS "+name)
			return r.lockErr
		},
		mappingExists: func(name string) bool {
			r.calls = append(r.calls, "mappingExists "+name)
			return r.mappingPresent
		},
	}
}

func newReleaseInstaller(target InstallTarget, mappedName string) *installer {
	return &installer{
		logger: logging.DefaultLogger(),
		config: &Config{
			Target: target,
			Disk:   &DiskConfig{Encryption: &EncryptionConfig{MappedName: mappedName}},
		},
	}
}

func fullDiskInfo() *DiskInfo {
	return &DiskInfo{
		Device:           "/dev/loop3",
		MappedDevice:     "/dev/mapper/cryptroot",
		LVMVolumeGroup:   "vg0",
		LVMLogicalVolume: "root",
		LVMDevice:        "/dev/mapper/vg0-root",
	}
}

func TestReleaseDisk_ReleasesEverythingInReverseOrder(t *testing.T) {
	rec := &releaseRecorder{}
	inst := newReleaseInstaller(InstallTargetImage, "")

	require.NoError(t, inst.releaseDisk(context.Background(), fullDiskInfo(), rec.ops()))

	assert.Equal(t, []string{
		"unmount /mnt/dev:detach",
		"unmount /mnt/sys:detach",
		"unmount /mnt/proc:detach",
		"unmount /mnt/boot/efi:regular",
		"unmount /mnt:regular",
		"removeDM vg0-root",
		"mappingExists vg0-root",
		"lockLUKS cryptroot",
	}, rec.calls)
}

func TestReleaseDisk_UsesTheConfiguredLUKSMappingName(t *testing.T) {
	rec := &releaseRecorder{}
	inst := newReleaseInstaller(InstallTargetImage, "imageroot")

	require.NoError(t, inst.releaseDisk(context.Background(), fullDiskInfo(), rec.ops()))

	assert.Contains(t, rec.calls, "lockLUKS imageroot")
	assert.NotContains(t, rec.calls, "lockLUKS cryptroot")
}

func TestReleaseDisk_FallsBackToLazyUnmount(t *testing.T) {
	rec := &releaseRecorder{unmountErr: map[string]error{"/mnt:regular": unix.EBUSY}}
	inst := newReleaseInstaller(InstallTargetImage, "")

	require.NoError(t, inst.releaseDisk(context.Background(), fullDiskInfo(), rec.ops()))

	assert.Contains(t, rec.calls, "unmount /mnt:regular")
	assert.Contains(t, rec.calls, "unmount /mnt:detach")
}

func TestReleaseDisk_WithoutLVMOrLUKSOnlyUnmounts(t *testing.T) {
	rec := &releaseRecorder{}
	inst := newReleaseInstaller(InstallTargetImage, "")

	require.NoError(t, inst.releaseDisk(context.Background(), &DiskInfo{Device: "/dev/loop3"}, rec.ops()))

	for _, call := range rec.calls {
		assert.NotContains(t, call, "removeDM")
		assert.NotContains(t, call, "lockLUKS")
	}
}

func TestReleaseDisk_ReportsEveryFailureAndKeepsGoing(t *testing.T) {
	dmErr := errors.New("device busy")
	lockErr := errors.New("still mapped")
	rec := &releaseRecorder{
		unmountErr:  map[string]error{"/mnt:regular": unix.EBUSY, "/mnt:detach": unix.EBUSY},
		removeDMErr: dmErr,
		lockErr:     lockErr,
	}
	inst := newReleaseInstaller(InstallTargetImage, "")

	err := inst.releaseDisk(context.Background(), fullDiskInfo(), rec.ops())

	require.Error(t, err)
	assert.ErrorIs(t, err, dmErr)
	assert.ErrorIs(t, err, lockErr)
	var installerErr *InstallerError
	require.True(t, errors.As(err, &installerErr))
	assert.Contains(t, err.Error(), "could not unmount /mnt")
	// The LUKS close still ran after the LVM removal failed.
	assert.Contains(t, rec.calls, "lockLUKS cryptroot")
}

func TestReleaseDisk_ReportsAMappingThatNeverDisappears(t *testing.T) {
	rec := &releaseRecorder{mappingPresent: true}
	inst := newReleaseInstaller(InstallTargetImage, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the wait ends immediately instead of polling for ten seconds

	err := inst.releaseDisk(ctx, fullDiskInfo(), rec.ops())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "device-mapper to drop vg0-root")
	assert.Contains(t, rec.calls, "lockLUKS cryptroot", "the LUKS close still runs")
}

func TestWaitForMappingRemoval(t *testing.T) {
	polls := 0
	gone := func(string) bool { polls++; return polls < 3 } // present twice, then gone
	require.NoError(t, waitForMappingRemoval(context.Background(), "vg0-root", gone))
	assert.Equal(t, 3, polls)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Error(t, waitForMappingRemoval(ctx, "vg0-root", func(string) bool { return true }))
}

func TestKernelFlavor(t *testing.T) {
	cases := map[string]string{"": "lts", "linux-lts": "lts", "linux-rpi": "rpi", "linux-virt": "virt", "custom": "custom"}
	for pkg, want := range cases {
		inst := &installer{config: &Config{OS: &OSConfig{KernelPackage: pkg}}}
		assert.Equal(t, want, inst.kernelFlavor(), "package %q", pkg)
	}
	assert.Equal(t, "lts", (&installer{}).kernelFlavor(), "no config at all")
}

func TestReleasesDiskOnFailure(t *testing.T) {
	assert.True(t, newReleaseInstaller(InstallTargetImage, "").releasesDiskOnFailure())
	assert.False(t, newReleaseInstaller(InstallTargetDisk, "").releasesDiskOnFailure())
	assert.False(t, newReleaseInstaller("", "").releasesDiskOnFailure())
	assert.False(t, (&installer{logger: logging.DefaultLogger()}).releasesDiskOnFailure())
}

func TestAfterFailedInstall_ReleasesOnlyAFailedImageInstall(t *testing.T) {
	cases := []struct {
		name     string
		target   InstallTarget
		info     *DiskInfo
		err      error
		released bool
	}{
		{"image target, failed, disk set up", InstallTargetImage, fullDiskInfo(), errors.New("os install failed"), true},
		{"image target, succeeded", InstallTargetImage, fullDiskInfo(), nil, false},
		{"image target, failed before the disk was set up", InstallTargetImage, nil, errors.New("partitioning failed"), false},
		{"disk target, failed", InstallTargetDisk, fullDiskInfo(), errors.New("os install failed"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &releaseRecorder{}
			inst := newReleaseInstaller(tc.target, "")
			inst.release = rec.ops()

			assert.Equal(t, tc.released, inst.afterFailedInstall(tc.info, tc.err))
			assert.Equal(t, tc.released, len(rec.calls) > 0)
		})
	}
}

func TestErrDiskRelease(t *testing.T) {
	cause := errors.New("EBUSY")
	err := ErrDiskRelease("closing the LUKS mapping cryptroot", cause)

	var installerErr *InstallerError
	require.True(t, errors.As(err, &installerErr))
	assert.Equal(t, ErrorTypeDiskRelease, installerErr.Type)
	assert.ErrorIs(t, err, cause)
}
