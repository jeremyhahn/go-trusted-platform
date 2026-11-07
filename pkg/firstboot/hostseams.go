package firstboot

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/partition"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi/firmware"
)

// Host seams. Each variable below defaults to the real host call and is
// never reassigned by production code; unit tests point them at a temporary
// directory or an in-memory fake so the firstboot flows run without root,
// devices or mounts (#964, rulings DS-4884 and DS-4886).

// hostRoot prefixes every fixed host path firstboot touches (the EFI tpm2
// directory, the installer container, /etc, /root, /var/lib, /dev and
// /sys probes). It is empty in production, so hostPath returns the path
// unchanged.
var hostRoot = ""

// hostPath returns p rooted under hostRoot.
func hostPath(p string) string {
	if hostRoot == "" {
		return p
	}
	return filepath.Join(hostRoot, p)
}

var (
	// hostCommand runs a command and returns its combined output.
	hostCommand commandRunner = execRunner

	// hostCommandStdout runs a command and returns its standard output.
	hostCommandStdout commandRunner = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).Output()
	}

	// hostStartProcess starts a long-running child process.
	hostStartProcess = func(cmd *exec.Cmd) error { return cmd.Start() }

	// hostLookPath resolves an executable on PATH.
	hostLookPath = exec.LookPath

	// hostMount and hostUnmount mount and unmount filesystems.
	hostMount   = syscall.Mount
	hostUnmount = syscall.Unmount

	// hostSync flushes filesystem buffers to disk.
	hostSync = syscall.Sync

	// findESP locates the EFI system partition beside the root device.
	findESP = partition.FindESP

	// hostIsSocket and hostIsDevice report a path's file type.
	hostIsSocket = func(path string) bool { return fileModeIs(path, os.ModeSocket) }
	hostIsDevice = func(path string) bool { return fileModeIs(path, os.ModeDevice) }

	// firmwareIsAvailable and firmwareSetTrustedPlatform reach the firmware
	// trusted-platform switch.
	firmwareIsAvailable        = firmware.IsAvailable
	firmwareSetTrustedPlatform = firmware.SetTrustedPlatform

	// The LUKS operations firstboot performs on the installer container and
	// the root volume.
	luksIsLUKS              = luks2.IsLUKS
	luksKillSlot            = luks2.KillSlot
	luksSetupLoopDevice     = luks2.SetupLoopDevice
	luksDetachLoopDevice    = luks2.DetachLoopDevice
	luksUnlock              = luks2.Unlock
	luksLock                = luks2.Lock
	luksGetMappedDevicePath = luks2.GetMappedDevicePath
	luksWipe                = luks2.Wipe

	// openTPM2 opens the TPM; tpmRetryDelay spaces the open attempts.
	openTPM2      = xkmssdk.NewTPM2
	tpmRetryDelay = 2 * time.Second
)

// fileModeIs reports whether path exists and has the mode bit set.
func fileModeIs(path string, bit os.FileMode) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&bit != 0
}

// The helpers below run a cleanup step through its seam and log a failure as
// a warning. Callers use them where the step is best effort: a failed cleanup
// must not change what the caller returns.

// unmountOrWarn unmounts target and warns when the unmount fails.
func unmountOrWarn(logger *logging.Logger, target string, flags int) {
	if err := hostUnmount(target, flags); err != nil {
		logger.Warn("Failed to unmount", "mount_point", target, "error", err)
	}
}

// lockOrWarn closes the LUKS mapping name and warns when the close fails.
func lockOrWarn(logger *logging.Logger, name string) {
	if err := luksLock(name); err != nil {
		logger.Warn("Failed to close LUKS mapping", "mapping", name, "error", err)
	}
}

// detachOrWarn detaches loopDev and warns when the detach fails.
func detachOrWarn(logger *logging.Logger, loopDev string) {
	if err := luksDetachLoopDevice(loopDev); err != nil {
		logger.Warn("Failed to detach loop device", "device", loopDev, "error", err)
	}
}
