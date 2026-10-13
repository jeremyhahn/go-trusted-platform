package installer

import (
	"context"
	"errors"
	"time"

	"github.com/anatol/devmapper.go"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"golang.org/x/sys/unix"
)

// releaseOnFailure lists the install targets whose disk resources are
// released when Install fails. A live install (disk target) leaves them in
// place: the operator is on the node, the mounts are what they debug with,
// and the reboot that follows clears everything. An image build has no
// reboot. The loop device, the LUKS mapping and the LVM logical volume it
// created are the build host's, and a failed build that keeps them open
// stops the next build from attaching the same image and leaks
// device-mapper state until someone finds it by hand.
var releaseOnFailure = map[InstallTarget]bool{
	InstallTargetImage: true,
}

// releasesDiskOnFailure reports whether a failed Install releases the disk
// resources setupDisk created.
func (i *installer) releasesDiskOnFailure() bool {
	return i.config != nil && releaseOnFailure[i.config.Target]
}

// releaseTimeout bounds the whole release. It runs on its own context
// because the install that failed may have failed by cancellation, and a
// cancelled context must not also cancel the cleanup of what it left open.
const releaseTimeout = 30 * time.Second

// diskRelease holds the operations releaseDisk performs. Production uses
// the syscalls and libraries the success path uses; tests substitute
// recorders, because unmounting and closing device-mapper devices are the
// only parts of this that cannot run in a unit test.
type diskRelease struct {
	unmount       func(target string, flags int) error
	removeDM      func(name string) error
	lockLUKS      func(name string) error
	mappingExists func(name string) bool
}

// defaultDiskRelease is the production diskRelease.
func defaultDiskRelease() diskRelease {
	return diskRelease{
		unmount:       unix.Unmount,
		removeDM:      devmapper.Remove,
		lockLUKS:      luks2.Lock,
		mappingExists: mappingExists,
	}
}

// mappingExists asks device-mapper whether a mapping is still registered.
// It is the kernel's answer, not the presence of /dev/mapper/<name>: a
// static /dev (the factory-image assemble container's) keeps the node
// after the mapping is gone, and a devtmpfs drops it a moment later, so
// the node proves nothing either way.
func mappingExists(name string) bool {
	_, err := devmapper.InfoByName(name)
	return err == nil
}

// waitForMappingRemoval waits until device-mapper no longer knows name.
// devmapper.Remove can return before the removal is complete, and a LUKS
// close that follows fails confusingly while the logical volume above it
// is still held.
func waitForMappingRemoval(ctx context.Context, name string, exists func(string) bool) error {
	return pollUntil(ctx, 10*time.Second, 100*time.Millisecond, func() bool { return !exists(name) })
}

// chrootMounts are the pseudo-filesystems the OS installer binds into the
// new root for chroot operations.
var chrootMounts = []string{"/mnt/dev", "/mnt/sys", "/mnt/proc"}

// afterFailedInstall releases the disk resources when an install failed on
// a target that asks for it. It is the seam Install's deferred call goes
// through, so the decision is testable without partitioning anything. It
// reports whether a release ran.
func (i *installer) afterFailedInstall(info *DiskInfo, installErr error) bool {
	if installErr == nil || info == nil || !i.releasesDiskOnFailure() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
	defer cancel()
	i.logger.Warn("[INSTALLER] Install failed; releasing the disk resources it left open", "error", installErr)
	if err := i.releaseDisk(ctx, info, i.release); err != nil {
		i.logger.Warn("[INSTALLER] Disk release was incomplete", "error", err)
	}
	return true
}

// releaseDisk undoes setupDisk after a failed install, in the reverse of
// the order it built things: the chroot pseudo-filesystems, the EFI and
// root mounts (lazily when a regular unmount fails), the LVM logical
// volume, then the LUKS mapping. Every step runs whatever the earlier ones
// did, because a mapping that stays open is the expensive failure; the
// steps that failed are reported together.
func (i *installer) releaseDisk(ctx context.Context, info *DiskInfo, ops diskRelease) error {
	var failures []error

	for _, mount := range chrootMounts {
		if err := ops.unmount(mount, unix.MNT_DETACH); err == nil {
			i.logger.Info("[INSTALLER] Unmounted chroot mount", "path", mount)
		}
	}
	unix.Sync()

	for _, mountPoint := range []string{espMountPoint, "/mnt"} {
		if err := i.unmountOrFail(mountPoint, ops.unmount); err != nil {
			failures = append(failures, err)
		}
	}
	unix.Sync()

	if info.LVMDevice != "" {
		name := info.LVMVolumeGroup + "-" + info.LVMLogicalVolume
		i.logger.Info("[INSTALLER] Removing device-mapper device", "name", name)
		if err := ops.removeDM(name); err != nil {
			failures = append(failures, ErrDiskRelease("removing the logical volume mapping "+name, err))
		} else if err := waitForMappingRemoval(ctx, name, ops.mappingExists); err != nil {
			failures = append(failures, ErrDiskRelease("waiting for device-mapper to drop "+name, err))
		}
		unix.Sync()
	}

	if info.MappedDevice != "" {
		name := i.luksMappedName()
		i.logger.Info("[INSTALLER] Closing LUKS device", "name", name)
		// A name nothing has open is already released.
		if err := ops.lockLUKS(name); err != nil && !errors.Is(err, luks2.ErrVolumeNotUnlocked) {
			failures = append(failures, ErrDiskRelease("closing the LUKS mapping "+name, err))
		}
	}
	unix.Sync()

	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	i.logger.Info("[INSTALLER] Disk resources released")
	return nil
}

// installLUKSCloseAttempts bounds closing the root mapping at the end of an
// install. go-luks2 v0.2.0's Lock already retries a busy mapping for about 3s
// before it returns luks2.ErrMappingBusy, so three attempts with a 1s and a 2s
// backoff give about 12s.
const installLUKSCloseAttempts = 3

// closeInstalledLUKS closes the root LUKS mapping at the end of a successful
// install; the close is what flushes the encrypted data. Only a busy mapping is
// retried, and a name nothing has open is already closed. When Lock gives up,
// the mapping is removed through device-mapper directly. The only error is a
// cancelled ctx.
func (i *installer) closeInstalledLUKS(ctx context.Context, name string, ops diskRelease, backoff time.Duration) error {
	var lockErr error
	for attempt := 1; attempt <= installLUKSCloseAttempts; attempt++ {
		i.logger.Info("[INSTALLER] Closing LUKS device", "name", name, "attempt", attempt)
		lockErr = ops.lockLUKS(name)
		if lockErr == nil || errors.Is(lockErr, luks2.ErrVolumeNotUnlocked) {
			i.logger.Info("[INSTALLER] LUKS device closed", "name", name)
			return nil
		}
		i.logger.Warn("[INSTALLER] Failed to close LUKS device", "error", lockErr, "attempt", attempt)
		if !errors.Is(lockErr, luks2.ErrMappingBusy) || attempt == installLUKSCloseAttempts {
			break
		}
		// The wait is cancellable so a cancelled install stops writing to
		// disks instead of running out the backoff.
		select {
		case <-ctx.Done():
			i.logger.Warn("[INSTALLER] cancelled while waiting to retry LUKS close", "error", ctx.Err())
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * backoff):
		}
		unix.Sync()
	}

	i.logger.Warn("[INSTALLER] LUKS close failed, trying devmapper.Remove directly", "name", name, "error", lockErr)
	unix.Sync()
	if err := ops.removeDM(name); err != nil {
		i.logger.Warn("[INSTALLER] devmapper.Remove failed - DATA MAY NOT BE PERSISTED!", "device", name, "error", err)
		return nil
	}
	i.logger.Info("[INSTALLER] devmapper.Remove succeeded", "name", name)
	return nil
}

// luksMappedName is the device-mapper name of the root LUKS mapping.
func (i *installer) luksMappedName() string {
	if i.config != nil && i.config.Disk != nil && i.config.Disk.Encryption != nil && i.config.Disk.Encryption.MappedName != "" {
		return i.config.Disk.Encryption.MappedName
	}
	return "cryptroot"
}
