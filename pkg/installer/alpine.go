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
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
)

// alpineInstaller implements OSInstaller for Alpine Linux
type alpineInstaller struct {
	config *OSConfig
	logger *logging.Logger
	// quirk holds the hardware-specific settings resolved from the target
	// machine's Redfish manufacturer/model at construction time. All
	// vendor-specific paths (serial console device, kernel cmdline, Samba
	// protocol) read from this field — never from hardcoded strings.
	quirk quirks.Quirk
}

// newAlpineInstaller creates a new Alpine Linux installer
func newAlpineInstaller(logger *logging.Logger, config *OSConfig) (OSInstaller, error) {
	return &alpineInstaller{
		config: config,
		logger: logger,
		quirk:  quirks.Resolve(config.HardwareManufacturer, config.HardwareModel),
	}, nil
}

// hasPreFetchedPackages checks if the ISO has pre-fetched packages available.
// It looks for a .pre-fetch marker file which indicates the ISO was built with
// the --pre-fetch flag to include all packages for offline installation.
// This distinguishes from Alpine's boot repository (apks/) which only contains
// packages needed for the live system, not the full installation.
func (ai *alpineInstaller) hasPreFetchedPackages() bool {
	for _, mountPoint := range []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"} {
		// Check for the .pre-fetch marker file that indicates the ISO
		// was built with pre-fetched packages for offline installation
		markerPath := filepath.Join(mountPoint, ".pre-fetch")
		if _, err := os.Stat(markerPath); err == nil {
			return true
		}
	}
	return false
}

// getPreFetchPath returns the path to pre-fetched packages, or empty string if not found.
// Checks the prefetched (full installation) repo first, then falls back to the
// live-system apks repo for backward compatibility.
func (ai *alpineInstaller) getPreFetchPath() string {
	arch := "x86_64"
	if ai.config.Architecture != "" {
		arch = ai.config.Architecture
	}

	for _, mountPoint := range []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"} {
		// Prefer apks-prefetch (built by --pre-fetch with full deps).
		// Fall back to apks (live-media boot repo) only as a last resort.
		for _, repoDir := range []string{"apks-prefetch", "apks"} {
			apksPath := filepath.Join(mountPoint, repoDir, arch)
			if _, err := os.Stat(apksPath); err == nil {
				return apksPath
			}
		}
	}
	return ""
}

// configureLocalRepository sets up APK to use the pre-fetched local repository.
// The repository path lives on the live ISO at /media/cdrom/apks-prefetch/{arch};
// for apk to reach it from inside the chroot the path must resolve there too.
// Rather than bind-mount /media/cdrom (which would have to be unmounted before
// the chroot teardown and complicates cleanup ordering), the package directory
// is copied into the chroot at /var/cache/apk-prefetch/{arch}. apk reads from
// that absolute path inside the chroot.
func (ai *alpineInstaller) configureLocalRepository(ctx context.Context, rootPath string) error {
	preFetchPath := ai.getPreFetchPath()
	if preFetchPath == "" {
		return ErrOSInstall("pre-fetch path not found", nil)
	}

	arch := "x86_64"
	if ai.config.Architecture != "" {
		arch = ai.config.Architecture
	}

	ai.logger.Info("[ALPINE] Configuring local APK repository", "path", preFetchPath)

	// Copy the prefetched repository into the chroot so the path resolves
	// when apk runs under `chroot /mnt`.
	chrootRepoBase := filepath.Join(rootPath, "var", "cache", "apk-prefetch")
	chrootRepoArch := filepath.Join(chrootRepoBase, arch)
	if err := os.MkdirAll(chrootRepoArch, 0755); err != nil {
		return ErrOSInstall("failed to create chroot prefetch directory", err)
	}

	// Use cp -a for a fast recursive copy that preserves permissions and
	// any tar.gz APKINDEX layout. This avoids re-implementing a Go-side
	// recursive copy with all the symlink/sparse-file edge cases.
	cpCmd := exec.CommandContext(ctx, "cp", "-a", preFetchPath+"/.", chrootRepoArch+"/")
	if output, err := cpCmd.CombinedOutput(); err != nil {
		return ErrOSInstall(fmt.Sprintf("failed to copy prefetch repo into chroot: %s", string(output)), err)
	}
	ai.logger.Info("[ALPINE] Prefetch repo copied into chroot", "dest", chrootRepoArch)

	// Write repositories file pointing at the chroot-relative path.
	chrootRepoPath := "/var/cache/apk-prefetch"
	repoContent := fmt.Sprintf("%s\n", chrootRepoPath)
	repoPath := filepath.Join(rootPath, "etc", "apk", "repositories")
	if err := os.MkdirAll(filepath.Dir(repoPath), 0755); err != nil {
		return ErrOSInstall("failed to create chroot apk config directory", err)
	}
	if err := os.WriteFile(repoPath, []byte(repoContent), 0644); err != nil {
		return ErrOSInstall("failed to write local apk repositories", err)
	}

	// Ensure /etc/apk/world exists (apk requires it).
	worldPath := filepath.Join(rootPath, "etc", "apk", "world")
	if _, err := os.Stat(worldPath); os.IsNotExist(err) {
		if err := os.WriteFile(worldPath, []byte(""), 0644); err != nil {
			ai.logger.Warn("[ALPINE] Failed to create world file", "error", err)
		}
	}

	return nil
}

// InstallBase installs the Alpine Linux base system
func (ai *alpineInstaller) InstallBase(ctx context.Context, rootPath string) error {
	ai.logger.Info("[ALPINE] Installing base system", "version", ai.config.Version)

	// Determine Alpine version
	version := "3.22.2"
	if ai.config.Version != "" {
		version = ai.config.Version
	}

	// Determine architecture
	arch := "x86_64"
	if ai.config.Architecture != "" {
		arch = ai.config.Architecture
	}

	ai.logger.Debug("[ALPINE] Installation parameters", "version", version, "arch", arch)

	// Determine mirror URL
	mirror := "https://dl-cdn.alpinelinux.org/alpine"
	if ai.config.Mirror != "" {
		mirror = ai.config.Mirror
	}

	// Trim trailing slashes to prevent double slashes in URLs
	mirror = strings.TrimSuffix(mirror, "/")

	ai.logger.Debug("[ALPINE] Using mirror", "mirror", mirror)

	// Download and extract Alpine base
	// Note: Alpine mirrors use major.minor in paths (e.g., v3.22) but full version in tarball name
	// Extract major.minor version for URL path (e.g., "3.22.2" -> "3.22")
	versionParts := strings.Split(version, ".")
	majorMinor := version // Default to full version if split fails
	if len(versionParts) >= 2 {
		majorMinor = fmt.Sprintf("%s.%s", versionParts[0], versionParts[1])
	}

	tarballName := fmt.Sprintf("alpine-minirootfs-%s-%s.tar.gz", version, arch)
	tarballURL := fmt.Sprintf("%s/v%s/releases/%s/%s",
		mirror, majorMinor, arch, tarballName)

	// Prefer the locally-cached minirootfs (placed by the prefetch builder
	// at the ISO root). This keeps the install offline-capable on networks
	// that cannot reach an Alpine mirror — including bootstrap/provisioning
	// VLANs that have no upstream egress.
	var tarballReader io.Reader
	var localTarball *os.File
	for _, candidate := range []string{
		filepath.Join("/media/cdrom", tarballName),
		filepath.Join("/media/cdrom", "alpine-minirootfs.tar.gz"),
	} {
		if f, err := os.Open(candidate); err == nil {
			ai.logger.Info("[ALPINE] Using locally-cached minirootfs", "path", candidate)
			localTarball = f
			tarballReader = f
			defer func() {
				if err := f.Close(); err != nil {
					ai.logger.Warn("[ALPINE] Failed to close local minirootfs", "error", err)
				}
			}()
			break
		}
	}

	if localTarball == nil {
		ai.logger.Info("[ALPINE] Downloading base system from mirror", "url", tarballURL)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL, nil)
		if err != nil {
			return ErrOSInstall("failed to build minirootfs request", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return ErrOSInstall("failed to download Alpine base", err)
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				ai.logger.Warn("[ALPINE] Failed to close response body", "error", err)
			}
		}()

		if resp.StatusCode != 200 {
			return ErrOSInstall(fmt.Sprintf("failed to download Alpine base: HTTP %d", resp.StatusCode), nil)
		}
		tarballReader = resp.Body
	}

	// Extract tarball to rootPath
	ai.logger.Info("[ALPINE] Extracting base system", "path", rootPath)

	cmd := exec.CommandContext(ctx, "tar", "-xzf", "-", "-C", rootPath)
	cmd.Stdin = tarballReader

	if output, err := cmd.CombinedOutput(); err != nil {
		ai.logger.Errorf("[ALPINE] Extraction failed: output=%s", string(output))
		return ErrOSInstall("failed to extract Alpine base", err)
	}

	// Check if we have pre-fetched packages available for offline installation
	useLocalRepo := ai.hasPreFetchedPackages()
	if useLocalRepo {
		ai.logger.Info("[ALPINE] Pre-fetched packages detected, using local APK repository")
		if err := ai.configureLocalRepository(ctx, rootPath); err != nil {
			ai.logger.Warn("[ALPINE] Failed to configure local repository, falling back to network", "error", err)
			useLocalRepo = false
		}
	}

	// Only set up network repositories if not using local repo
	if !useLocalRepo {
		// Setup apk repositories
		ai.logger.Info("[ALPINE] Setting up APK repositories")

		repoContent := fmt.Sprintf("%s/v%s/main\n%s/v%s/community\n",
			mirror, majorMinor, mirror, majorMinor)

		repoPath := filepath.Join(rootPath, "etc", "apk", "repositories")
		if err := os.WriteFile(repoPath, []byte(repoContent), 0644); err != nil {
			return ErrOSInstall("failed to write apk repositories", err)
		}
	}

	// Setup DNS before chroot operations
	ai.logger.Debug("[ALPINE] Configuring DNS for chroot environment")
	resolvPath := filepath.Join(rootPath, "etc", "resolv.conf")
	resolvContent := "nameserver 8.8.8.8\nnameserver 8.8.4.4\n"
	if err := os.WriteFile(resolvPath, []byte(resolvContent), 0644); err != nil {
		return ErrOSInstall("failed to write resolv.conf", err)
	}

	// Mount pseudo-filesystems required for chroot operations to work properly
	// These are needed for network connectivity and device access during package installation
	ai.logger.Info("[ALPINE] Setting up chroot environment with pseudo-filesystems")
	if err := ai.setupChrootMounts(ctx, rootPath); err != nil {
		return ErrOSInstall("failed to setup chroot mounts", err)
	}
	defer ai.cleanupChrootMounts(rootPath)

	// Install base packages using chroot.
	// When using the local prefetch repo, the minirootfs we just extracted
	// (frozen at e.g. 3.22.2) may have older versions than the rolling v3.22
	// main repo (e.g. 3.22.4 + busybox-r20). apk add lets us upgrade those
	// in-place via `--upgrade` AND we explicitly include the busybox triplet
	// (busybox / busybox-binsh / busybox-suid) so apk's resolver upgrades all
	// three together — otherwise it fails with
	// `breaks: busybox-binsh-1.37.0-r19[busybox=1.37.0-r19]`.
	ai.logger.Info("[ALPINE] Installing base packages")

	packages := []string{
		"alpine-base",
		// busybox triplet must be installed together so apk's resolver
		// can upgrade all three from the older minirootfs versions to the
		// rolling main repo versions atomically.
		"busybox",
		"busybox-binsh",
		"busybox-suid",
		// NOTE: No cryptsetup or lvm2 - platform-initrd handles LUKS unlock natively via go-luks2
		"e2fsprogs",
		"dosfstools",
		"device-mapper",          // Device mapper support (dmsetup)
		"device-mapper-udev",     // Udev rules for device mapper
		"dracut",                 // Use dracut for initramfs and UKI generation
		"dracut-modules-network", // Network support for dracut
		"musl-fts",               // Required by dracut-install
		"binutils",               // Provides objcopy for UKI building
		"systemd-efistub",        // Provides EFI stub for UKI building (Alpine 3.22+)
		// NOTE: kmod removed — Alpine uses busybox built-in modprobe
		// NOTE: gcompat/libc6-compat removed — platformd is statically linked
		"ca-certificates",        // Required for update-ca-certificates to work
		// NOTE: sbsigntool is no longer required - UKI signing uses native authenticode (pkg/authenticode)
	}

	// Add kernel ONLY if NOT in FIPS mode
	// When FIPS is enabled, we use our custom-built FIPS kernel instead of Alpine's stock kernel
	if !ai.config.FIPS {
		ai.logger.Info("[ALPINE] Adding linux-lts kernel")
		packages = append(packages, "linux-lts") // Includes all kernel modules
		// linux-lts pulls the virtual `linux-firmware-any`. With only
		// `linux-firmware-none` in the prefetch (a 0-byte stub) the
		// dependency is satisfied by the stub. Without this explicit
		// install, APK's resolver picks the first compatible provider
		// it finds — often `linux-firmware-brcm` on Alpine 3.22.4+ —
		// which then declares strict-version deps on subpackages like
		// `linux-firmware-cypress` and `linux-firmware-synaptics` that
		// aren't in the offline prefetch set. The chroot-install then
		// fails with `(no such package)`. The "-none" stub provides
		// `linux-firmware-any` with no transitive subpackage deps, so
		// it satisfies the constraint without dragging in WiFi/BT
		// firmware our X10 servers never use.
		packages = append(packages, "linux-firmware-none")
	} else {
		ai.logger.Info("[ALPINE] Skipping linux-lts kernel (using custom FIPS kernel)")

		// Create /lib/modules directory since linux-lts package won't create it
		// This is required by the FIPS kernel installation process
		modulesDir := filepath.Join(rootPath, "lib", "modules")
		if err := os.MkdirAll(modulesDir, 0755); err != nil {
			return ErrOSInstall("failed to create kernel modules directory", err)
		}
		ai.logger.Info("[ALPINE] Created kernel modules directory", "path", modulesDir)
	}

	// Add LVM packages if filesystem type is LVM
	if ai.config.FilesystemType == FilesystemLVM {
		ai.logger.Info("[ALPINE] Adding LVM packages for LVM filesystem")
		packages = append(packages, "lvm2", "lvm2-openrc")
	}

	// Add FIDO2 packages if FIDO2 support is enabled
	if ai.config.EnableFIDO2 {
		ai.logger.Info("[ALPINE] Adding FIDO2 packages for security key support")
		packages = append(packages,
			"libfido2",  // FIDO2 library
			"fido2",     // FIDO2 command-line tools (fido2-token, fido2-cred, fido2-assert)
			"coreutils", // Required for FIDO2 enrollment scripts (base64, etc.)
		)
	}

	// Add IMA packages if IMA is enabled
	if ai.config.IMA != nil && ai.config.IMA.Enabled {
		ai.logger.Info("[ALPINE] Adding IMA packages for integrity measurement")
		packages = append(packages,
			"ima-evm-utils", // IMA/EVM utilities (evmctl)
			"keyutils",      // Key management utilities for IMA keyring
			"attr",          // Extended attributes support
		)
		// Add audit if audit logging is enabled
		if ai.config.IMA.AuditEnabled {
			packages = append(packages, "audit", "audit-openrc")
		}
	}

	// Install all base packages in a single apk add invocation so the
	// resolver can upgrade interrelated packages (e.g. the busybox triplet)
	// atomically. Single-package installs serialise the resolver and break
	// when a later package's deps require upgrading something installed by
	// an earlier step.
	ai.logger.Info("[ALPINE] Installing base package set",
		"count", len(packages),
		"packages", strings.Join(packages, ","))

	args := []string{rootPath, "apk", "add", "--no-cache", "--upgrade"}
	if useLocalRepo {
		// Allow untrusted for local repository (packages were verified during pre-fetch)
		args = append(args, "--allow-untrusted")
	}
	args = append(args, packages...)

	chrootCmd := exec.CommandContext(ctx, "chroot", args...)
	if output, err := chrootCmd.CombinedOutput(); err != nil {
		ai.logger.Errorf("[ALPINE] Base package installation failed: output=%s", string(output))
		return ErrOSInstall("failed to install base packages", err)
	}

	// Ensure /lib64 symlink exists for glibc binary compatibility
	// The platformd binary is compiled with glibc and expects /lib64/ld-linux-x86-64.so.2
	lib64Path := filepath.Join(rootPath, "lib64")
	if _, err := os.Lstat(lib64Path); os.IsNotExist(err) {
		// Create /lib64 -> /lib symlink for glibc ld-linux-x86-64.so.2 compatibility
		if err := os.Symlink("/lib", lib64Path); err != nil {
			ai.logger.Warn("[ALPINE] Failed to create /lib64 symlink", "error", err)
		} else {
			ai.logger.Info("[ALPINE] Created /lib64 -> /lib symlink for glibc compatibility")
		}
	} else {
		ai.logger.Debug("[ALPINE] /lib64 already exists, skipping symlink creation")
	}

	// Copy platformd dracut module to target system
	ai.logger.Info("[ALPINE] Copying platformd dracut module to target system")

	// The module is on the ISO - try common mount points
	var platformInitrdSrc string
	for _, mountPoint := range []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"} {
		testPath := filepath.Join(mountPoint, "dracut-platformd/90platformd")
		if _, err := os.Stat(testPath); err == nil {
			platformInitrdSrc = testPath
			break
		}
	}

	if platformInitrdSrc == "" {
		ai.logger.Warn("[ALPINE] Platform-initrd dracut module not found on ISO")
		ai.logger.Warn("[ALPINE] Checked: /media/cdrom, /media/usb, /mnt/cdrom")
	}

	platformInitrdDst := filepath.Join(rootPath, "usr/lib/dracut/modules.d/90platformd")

	// Check if source module exists in ISO
	if _, err := os.Stat(platformInitrdSrc); err == nil {
		// Create destination directory
		if err := os.MkdirAll(platformInitrdDst, 0755); err != nil {
			ai.logger.Warn("[ALPINE] Failed to create platformd module directory", "error", err)
		} else {
			// Copy all files from source to destination
			cmd := exec.CommandContext(ctx, "cp", "-r", platformInitrdSrc+"/.", platformInitrdDst)
			if output, err := cmd.CombinedOutput(); err != nil {
				ai.logger.Warn("[ALPINE] Failed to copy platformd module", "error", err, "output", string(output))
			} else {
				ai.logger.Info("[ALPINE] Platform-initrd dracut module copied successfully")
			}
		}
	} else {
		ai.logger.Warn("[ALPINE] Platform-initrd dracut module not found in ISO", "path", platformInitrdSrc)
	}

	ai.logger.Info("[ALPINE] Base system installed successfully")
	return nil
}

// ConfigureSystem configures system files (fstab, crypttab, etc.)
func (ai *alpineInstaller) ConfigureSystem(ctx context.Context, rootPath string, diskInfo *DiskInfo) error {
	ai.logger.Info("[ALPINE] Configuring system files")

	// Create /etc/fstab
	ai.logger.Debug("[ALPINE] Creating /etc/fstab")

	fstabLines := []string{
		"# <device> <mountpoint> <fstype> <options> <dump> <pass>",
	}

	// Add EFI partition (mount at /boot/efi to match reference Alpine architecture)
	if diskInfo.EFIPartition != "" {
		fstabLines = append(fstabLines,
			fmt.Sprintf("%s /boot/efi vfat defaults 0 2", diskInfo.EFIPartition))
	}

	// Add root partition
	rootDevice := diskInfo.RootPartition
	if diskInfo.LVMDevice != "" {
		// Using LVM - mount the logical volume, not the LUKS container
		rootDevice = diskInfo.LVMDevice
	} else if diskInfo.MappedDevice != "" {
		// Using LUKS without LVM
		rootDevice = diskInfo.MappedDevice
	}
	fstabLines = append(fstabLines,
		fmt.Sprintf("%s / ext4 defaults 0 1", rootDevice))

	fstabPath := filepath.Join(rootPath, "etc", "fstab")
	if err := os.WriteFile(fstabPath, []byte(strings.Join(fstabLines, "\n")+"\n"), 0644); err != nil {
		return ErrOSInstall("failed to write fstab", err)
	}

	// Create /etc/crypttab if using LUKS
	if diskInfo.MappedDevice != "" {
		ai.logger.Debug("[ALPINE] Creating /etc/crypttab")

		crypttabLine := fmt.Sprintf("cryptroot %s none luks\n", diskInfo.RootPartition)
		crypttabPath := filepath.Join(rootPath, "etc", "crypttab")
		if err := os.WriteFile(crypttabPath, []byte(crypttabLine), 0644); err != nil {
			return ErrOSInstall("failed to write crypttab", err)
		}
	}

	// Setup DNS
	ai.logger.Debug("[ALPINE] Configuring DNS")
	resolvPath := filepath.Join(rootPath, "etc", "resolv.conf")
	resolvContent := "nameserver 8.8.8.8\nnameserver 8.8.4.4\n"
	if err := os.WriteFile(resolvPath, []byte(resolvContent), 0644); err != nil {
		return ErrOSInstall("failed to write resolv.conf", err)
	}

	// Configure hostname
	ai.logger.Debug("[ALPINE] Configuring hostname")
	hostname := "trusted-platform"
	if ai.config.Hostname != "" {
		hostname = ai.config.Hostname
	}
	hostnamePath := filepath.Join(rootPath, "etc", "hostname")
	if err := os.WriteFile(hostnamePath, []byte(hostname+"\n"), 0644); err != nil {
		return ErrOSInstall("failed to write hostname", err)
	}

	// Fix Alpine dracut dm module issue - create symlink for udev rules
	// See: https://gitlab.alpinelinux.org/alpine/aports/-/issues/15464
	ai.logger.Debug("[ALPINE] Creating udev rules symlink for dracut dm module")
	libUdevDir := filepath.Join(rootPath, "lib", "udev", "rules.d")
	if err := os.MkdirAll(libUdevDir, 0755); err != nil {
		ai.logger.Warnf("[ALPINE] Failed to create /lib/udev/rules.d: %v", err)
	} else {
		// Symlink device-mapper udev rules from /usr/lib to /lib
		usrUdevRules := filepath.Join(rootPath, "usr", "lib", "udev", "rules.d")
		if entries, err := os.ReadDir(usrUdevRules); err == nil {
			for _, entry := range entries {
				if strings.Contains(entry.Name(), "dm-") || strings.Contains(entry.Name(), "device-mapper") {
					srcPath := filepath.Join("/usr/lib/udev/rules.d", entry.Name())
					dstPath := filepath.Join(libUdevDir, entry.Name())
					if err := os.Symlink(srcPath, dstPath); err != nil {
						ai.logger.Warnf("[ALPINE] Failed to symlink %s: %v", entry.Name(), err)
					}
				}
			}
		}
	}

	// Create /etc/alpine-tpm.conf with TPM and security settings
	ai.logger.Debug("[ALPINE] Creating /etc/alpine-tpm.conf")
	tpmConfPath := filepath.Join(rootPath, "etc", "alpine-tpm.conf")
	tpmConfContent := fmt.Sprintf(`# Alpine TPM and Security Configuration
# Generated by platformd installer

# Enable TPM auto-unseal on boot
TPM_AUTOUNSEAL=1

# PCRs to seal/unseal against
TPM_SEAL_PCR=0,7,9

# Automatically reseal TPM when kernel is upgraded
TPM_AUTO_UPGRADE_SEAL=%d

# Enable kernel lockdown mode
LOCKDOWN=%d

# Enable FIPS mode
FIPS=%d
`,
		boolToInt(ai.config.TPMAutoUpgradeSeal),
		boolToInt(ai.config.Lockdown),
		boolToInt(ai.config.FIPS))

	if err := os.WriteFile(tpmConfPath, []byte(tpmConfContent), 0644); err != nil {
		return ErrOSInstall("failed to write alpine-tpm.conf", err)
	}
	ai.logger.Info("[ALPINE] Created /etc/alpine-tpm.conf",
		"fips", ai.config.FIPS,
		"lockdown", ai.config.Lockdown,
		"tpm_auto_upgrade_seal", ai.config.TPMAutoUpgradeSeal)

	// Copy platformd binary from ISO or config
	var platformdSrc string
	if ai.config.PlatformdBinary != "" {
		platformdSrc = ai.config.PlatformdBinary
	} else {
		// Look for platformd binary on ISO mount points
		for _, isoMount := range []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"} {
			testPath := filepath.Join(isoMount, "platformd-bin", "platformd")
			if _, err := os.Stat(testPath); err == nil {
				platformdSrc = testPath
				break
			}
		}
	}

	if platformdSrc != "" {
		ai.logger.Info("[ALPINE] Installing platformd binary", "source", platformdSrc)

		// Create /usr/bin directory if it doesn't exist
		// NOTE: We use /usr/bin because the dracut module (module-setup.sh) and
		// unlock script (platformd-unlock.sh) expect platformd at /usr/bin/platformd
		usrBin := filepath.Join(rootPath, "usr", "bin")
		if err := os.MkdirAll(usrBin, 0755); err != nil {
			return ErrOSInstall("failed to create /usr/bin", err)
		}

		// Read source binary
		binaryData, err := os.ReadFile(platformdSrc)
		if err != nil {
			return ErrOSInstall(fmt.Sprintf("failed to read platformd binary from %s", platformdSrc), err)
		}

		// Write to destination with executable permissions
		destPath := filepath.Join(usrBin, "platformd")
		if err := os.WriteFile(destPath, binaryData, 0755); err != nil {
			return ErrOSInstall("failed to write platformd to /usr/bin", err)
		}

		// Explicitly sync to ensure file is written to disk before poweroff
		syncCmd := exec.CommandContext(ctx, "sync")
		if err := syncCmd.Run(); err != nil {
			ai.logger.Warn("[ALPINE] Failed to sync filesystem after platformd install", "error", err)
		}

		// Verify the file was written correctly
		if stat, err := os.Stat(destPath); err != nil {
			return ErrOSInstall("platformd binary verification failed - file not found after write", err)
		} else if stat.Size() != int64(len(binaryData)) {
			return ErrOSInstall(fmt.Sprintf("platformd binary verification failed - size mismatch: got %d, expected %d", stat.Size(), len(binaryData)), nil)
		} else if stat.Mode().Perm() != 0755 {
			return ErrOSInstall(fmt.Sprintf("platformd binary verification failed - wrong permissions: got %o, expected 0755", stat.Mode().Perm()), nil)
		}

		ai.logger.Info("[ALPINE] Successfully installed platformd binary", "path", destPath, "size", len(binaryData))

		// Create symlink at /usr/sbin/platformd -> /usr/bin/platformd
		// Some systemd services and firstboot scripts expect platformd at /usr/sbin
		usrSbin := filepath.Join(rootPath, "usr", "sbin")
		if err := os.MkdirAll(usrSbin, 0755); err != nil {
			ai.logger.Warn("[ALPINE] Failed to create /usr/sbin directory", "error", err)
		} else {
			symlinkPath := filepath.Join(usrSbin, "platformd")
			// Remove existing symlink if present
			if err := os.Remove(symlinkPath); err != nil && !os.IsNotExist(err) {
				ai.logger.Warn("[ALPINE] Failed to remove existing symlink", "error", err)
			}
			if err := os.Symlink("/usr/bin/platformd", symlinkPath); err != nil {
				ai.logger.Warn("[ALPINE] Failed to create /usr/sbin/platformd symlink", "error", err)
			} else {
				ai.logger.Info("[ALPINE] Created symlink /usr/sbin/platformd -> /usr/bin/platformd")
			}
		}
	} else {
		ai.logger.Warn("[ALPINE] Platformd binary not found on ISO or in config, system services may not work")
	}

	// NOTE: Three-binary architecture:
	// - platformd: daemon-only (serve, version)
	// - platformctl: CLI for all user operations
	// - platform-initrd: boot-only (boot, firstboot, recovery) for initramfs
	// The dracut module uses "platform-initrd boot" for TPM unlock

	// Install platform-initrd binary to /usr/bin/platform-initrd
	// This is CRITICAL — the dracut module calls /usr/bin/platform-initrd during boot
	var platformInitrdBinarySrc string
	for _, isoMount := range []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"} {
		testPath := filepath.Join(isoMount, "platformd-bin", "platform-initrd")
		if _, err := os.Stat(testPath); err == nil {
			platformInitrdBinarySrc = testPath
			break
		}
	}
	if platformInitrdBinarySrc != "" {
		ai.logger.Info("[ALPINE] Installing platform-initrd binary", "source", platformInitrdBinarySrc)
		binaryData, err := os.ReadFile(platformInitrdBinarySrc)
		if err != nil {
			return ErrOSInstall(fmt.Sprintf("failed to read platform-initrd binary from %s", platformInitrdBinarySrc), err)
		}
		destPath := filepath.Join(rootPath, "usr", "bin", "platform-initrd")
		if err := os.WriteFile(destPath, binaryData, 0755); err != nil {
			return ErrOSInstall("failed to write platform-initrd to /usr/bin", err)
		}
		syncCmd := exec.CommandContext(ctx, "sync")
		if err := syncCmd.Run(); err != nil {
			ai.logger.Warn("[ALPINE] Failed to sync after platform-initrd install", "error", err)
		}
		ai.logger.Info("[ALPINE] Successfully installed platform-initrd binary", "path", destPath, "size", len(binaryData))
	} else {
		ai.logger.Warn("[ALPINE] platform-initrd binary not found on ISO, boot will fail")
	}

	// Install WebUI if available on ISO
	if err := ai.installWebUI(ctx, rootPath); err != nil {
		ai.logger.Warn("[ALPINE] Failed to install WebUI, continuing without it", "error", err)
	}

	// Configure IMA (Integrity Measurement Architecture) if enabled
	if err := ai.configureIMA(ctx, rootPath); err != nil {
		ai.logger.Warn("[ALPINE] Failed to configure IMA, continuing without it", "error", err)
	}

	// Install CA bundle to OS trust store if provided on ISO
	if err := ai.installCABundle(ctx, rootPath); err != nil {
		ai.logger.Warn("[ALPINE] Failed to install CA bundle, continuing without it", "error", err)
	}

	ai.logger.Info("[ALPINE] System configuration complete")
	return nil
}

// boolToInt converts a boolean to an integer (1 or 0)
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// InstallKernel installs kernel and generates initramfs using dracut
// NOTE: This method now uses dracut instead of mkinitfs.
// The actual UKI building is deferred to the buildUKI step in installer.go
// because dracut's --uefi flag combines initramfs generation and UKI building.
func (ai *alpineInstaller) InstallKernel(ctx context.Context, rootPath string) error {
	ai.logger.Info("[ALPINE] Installing kernel")

	// In FIPS mode, we skip the standard kernel installation and version detection
	// because we'll install a custom FIPS-capable kernel later
	if ai.config.FIPS {
		ai.logger.Info("[ALPINE] Skipping standard kernel installation (FIPS mode - using custom FIPS kernel)")
		return nil
	}

	// Kernel is already installed by InstallBase (linux-lts package)
	ai.logger.Info("[ALPINE] Kernel installed by base packages")

	// Detect installed kernel version by looking at /lib/modules/
	modulesPath := filepath.Join(rootPath, "lib", "modules")
	entries, err := os.ReadDir(modulesPath)
	if err != nil {
		return ErrOSInstall("failed to read kernel modules directory", err)
	}

	if len(entries) == 0 {
		return ErrOSInstall("no kernel modules found in /lib/modules", nil)
	}

	// Use the first (and typically only) kernel version found
	kernelVersion := entries[0].Name()
	ai.logger.Debug("[ALPINE] Detected kernel version", "version", kernelVersion)

	// Configure dracut to include platformd module (no crypt/cryptsetup needed)
	ai.logger.Info("[ALPINE] Configuring dracut for platformd LUKS support")

	dracutConfDir := filepath.Join(rootPath, "etc", "dracut.conf.d")
	if err := os.MkdirAll(dracutConfDir, 0755); err != nil {
		return ErrOSInstall("failed to create dracut config directory", err)
	}

	// Create dracut configuration file
	// This ensures dracut includes necessary modules for LUKS and our custom platformd
	dracutConfPath := filepath.Join(dracutConfDir, "10-platform.conf")

	// Build dracut configuration based on enabled features
	var dracutConfBuilder strings.Builder
	dracutConfBuilder.WriteString(`# Platform-specific dracut configuration
# NOTE: No crypt module needed - platform-initrd uses go-luks2 for all LUKS operations
# This eliminates the cryptsetup binary dependency entirely

# Add platformd custom module (handles TPM unlock and password fallback)
add_dracutmodules+=" platformd "

# Add LVM support if needed
add_dracutmodules+=" lvm "

# Compress initramfs with gzip (best compatibility)
compress="gzip"

# Include kernel modules for common storage devices
add_drivers+=" nvme sd_mod ahci "

# Serial console drivers — MUST be in initramfs so kernel output survives
# the transition from UEFI ConOut (EFI stub) to the real kernel console.
# Without these, the kernel goes silent on the BMC SOL after "EFI stub:
# Measured initrd data into PCR 9" because no driver is bound to ttyS1
# until rootfs modules are loaded — but LUKS unlock happens first, so any
# initrd panic or hang is invisible to the operator.
#
#   8250, 8250_pci, 8250_port — generic PC-style UARTs (most vendors)
#   serial_base                — core serial bus (required by 8250 on
#                                newer kernels)
#
# NOTE: We deliberately do NOT add 8250_aspeed_vuart here. That module
# does not exist in the Alpine LTS kernel package, and dracut prints a
# fatal-looking error when it cannot find it. On Supermicro X10 boards
# the BMC SOL serial concentrator is wired to COM1 at the standard IO
# port 0x3f8, matching the BIOS "Serial Port Console Redirection = COM1"
# setting. The in-tree 8250 driver claims it via the
# "earlycon=uart8250,io,0x3f8,115200n8" cmdline anchor we set in
# pkg/installer/installer.go. No vendor-specific module needed.
force_drivers+=" 8250 8250_pci serial_base "
`)

	// Add IMA support if enabled
	// Note: IMA is a kernel feature, not a dracut module. Support is enabled via:
	// 1. Kernel command line parameters (ima=on, ima_policy=tcb, etc.)
	// 2. Loading TPM kernel modules for PCR measurements
	// 3. Installing IMA tools and policy files in the initramfs
	if ai.config.IMA != nil && ai.config.IMA.Enabled {
		ai.logger.Info("[ALPINE] Adding IMA support to dracut configuration")
		dracutConfBuilder.WriteString(`
# IMA (Integrity Measurement Architecture) support
# IMA is enabled via kernel cmdline params, not as a dracut module

# Include TPM-related kernel modules for IMA measurements
add_drivers+=" tpm tpm_tis tpm_crb "

# Install IMA-related binaries
install_items+=" /usr/bin/evmctl /usr/bin/keyctl "

# Copy IMA policy to initramfs
install_items+=" /etc/ima/ima-policy "
`)
	}

	dracutConf := dracutConfBuilder.String()
	if err := os.WriteFile(dracutConfPath, []byte(dracutConf), 0644); err != nil {
		return ErrOSInstall("failed to write dracut configuration", err)
	}

	ai.logger.Info("[ALPINE] Dracut configured for kernel", "version", kernelVersion)
	ai.logger.Info("[ALPINE] Initramfs and UKI will be generated by dracut in buildUKI step")

	return nil
}

// SetRootPassword sets the root password
func (ai *alpineInstaller) SetRootPassword(ctx context.Context, rootPath, password string) error {
	ai.logger.Info("[ALPINE] Setting root password")

	if password == "" {
		ai.logger.Warn("[ALPINE] No password provided, skipping")
		return nil
	}

	// Use chroot and chpasswd to set root password
	cmd := exec.CommandContext(ctx, "chroot", rootPath, "chpasswd")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return ErrOSInstall("failed to create stdin pipe for chpasswd", err)
	}

	if err := cmd.Start(); err != nil {
		return ErrOSInstall("failed to start chpasswd", err)
	}

	// Write "root:password" to stdin
	if _, err := fmt.Fprintf(stdin, "root:%s\n", password); err != nil {
		if closeErr := stdin.Close(); closeErr != nil {
			ai.logger.Warn("[ALPINE] Failed to close stdin pipe", "error", closeErr)
		}
		if waitErr := cmd.Wait(); waitErr != nil {
			ai.logger.Warn("[ALPINE] chpasswd wait failed", "error", waitErr)
		}
		return ErrOSInstall("failed to write password", err)
	}
	if err := stdin.Close(); err != nil {
		ai.logger.Warn("[ALPINE] Failed to close stdin pipe", "error", err)
	}

	if err := cmd.Wait(); err != nil {
		return ErrOSInstall("chpasswd failed", err)
	}

	ai.logger.Info("[ALPINE] Root password set successfully")
	return nil
}

// EnableServices enables essential OpenRC services for the default runlevel
func (ai *alpineInstaller) EnableServices(ctx context.Context, rootPath string) error {
	ai.logger.Info("[ALPINE] Enabling essential OpenRC services")

	// First, configure console output settings
	if err := ai.configureConsole(rootPath); err != nil {
		ai.logger.Warn("[ALPINE] Failed to configure console", "error", err)
		// Don't fail installation if console configuration fails
	}

	// Configure kernel modules to load at boot
	if err := ai.configureKernelModules(rootPath); err != nil {
		ai.logger.Warn("[ALPINE] Failed to configure kernel modules", "error", err)
	}

	// List of essential services to enable in the default runlevel.
	// Each entry is skipped if its /etc/init.d file isn't present, so
	// the list can safely contain services whose packages are only
	// conditionally installed (ssh, OVS). The OVS trio must be
	// enabled in boot runlevel (not default) so the datapath module
	// and ovsdb-server are ready before platformd tries to speak
	// OVSDB in initSDN.
	defaultServices := []string{
		"networking", // Network configuration
		"chronyd",    // Time synchronization (if available)
		"local",      // Local startup scripts
		"sshd",       // SSH server (if installed)
	}

	// OVS services: ovs-modules loads the openvswitch kernel module,
	// ovsdb-server serves the OVSDB socket platformd talks to, and
	// ovs-vswitchd is the dataplane daemon. These go into the `boot`
	// runlevel so they're up before `default` services (networking,
	// platformd) that depend on the bridge being present.
	bootServices := []string{
		"ovs-modules",
		"ovsdb-server",
		"ovs-vswitchd",
	}
	for _, service := range bootServices {
		servicePath := filepath.Join(rootPath, "etc/init.d", service)
		if _, err := os.Stat(servicePath); os.IsNotExist(err) {
			ai.logger.Debug("[ALPINE] OVS service not found, skipping",
				"service", service)
			continue
		}
		cmd := exec.CommandContext(ctx, "chroot", rootPath, "rc-update", "add", service, "boot")
		if output, err := cmd.CombinedOutput(); err != nil {
			ai.logger.Warn("[ALPINE] Failed to enable OVS service",
				"service", service,
				"error", err,
				"output", string(output))
			continue
		}
		ai.logger.Info("[ALPINE] Enabled OVS service (boot runlevel)", "service", service)
	}

	// Enable each service in the default runlevel
	for _, service := range defaultServices {
		// Check if service exists before trying to enable it
		servicePath := filepath.Join(rootPath, "etc/init.d", service)
		if _, err := os.Stat(servicePath); os.IsNotExist(err) {
			ai.logger.Debug("[ALPINE] Service not found, skipping", "service", service)
			continue
		}

		// Enable the service using rc-update
		cmd := exec.CommandContext(ctx, "chroot", rootPath, "rc-update", "add", service, "default")
		if output, err := cmd.CombinedOutput(); err != nil {
			ai.logger.Warn("[ALPINE] Failed to enable service",
				"service", service,
				"error", err,
				"output", string(output))
			// Don't fail installation if service enablement fails
			continue
		}

		ai.logger.Info("[ALPINE] Enabled service", "service", service)
	}

	ai.logger.Info("[ALPINE] OpenRC services enabled successfully")
	return nil
}

// configureConsole creates console configuration files for the installed system.
// The serial-console device name (e.g. ttyS0, ttyS1) is taken from the
// hardware quirk resolved at construction time so the inittab is correct for
// boards whose BMC SOL concentrator is wired to a non-default UART
// (e.g. Supermicro X10SDV-TP8F uses ttyS1/COM2).
func (ai *alpineInstaller) configureConsole(rootPath string) error {
	ai.logger.Info("[ALPINE] Configuring console output",
		"sol_port", ai.quirk.SOLPort)

	// Create /etc/rc.conf for verbose OpenRC output
	rcConfPath := filepath.Join(rootPath, "etc", "rc.conf")
	rcConfContent := `# OpenRC configuration for verbose console output
# DISABLE logging to file so everything goes to console
rc_logger="NO"

# Enable verbose output to see what's happening
rc_verbose="YES"

# Disable parallel startup to see sequential output
rc_parallel="NO"

# Enable color output for better readability
rc_nocolor="NO"

# Show interactive prompt if needed (helps debug boot issues)
rc_interactive="NO"
`
	if err := os.WriteFile(rcConfPath, []byte(rcConfContent), 0644); err != nil {
		return fmt.Errorf("failed to create rc.conf: %w", err)
	}
	ai.logger.Info("[ALPINE] Created /etc/rc.conf")

	// Create /etc/inittab with getty configuration (busybox getty syntax).
	// The serial console device is driven by the hardware quirk (ai.quirk.SOLPort)
	// so the getty binds to the correct UART for the target board.
	inittabPath := filepath.Join(rootPath, "etc", "inittab")
	solPort := ai.quirk.SOLPort
	inittabContent := fmt.Sprintf(`# /etc/inittab

::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default

# Set up a couple of getty's
tty1::respawn:/sbin/getty 38400 tty1
tty2::respawn:/sbin/getty 38400 tty2
tty3::respawn:/sbin/getty 38400 tty3
tty4::respawn:/sbin/getty 38400 tty4
tty5::respawn:/sbin/getty 38400 tty5
tty6::respawn:/sbin/getty 38400 tty6

# Serial console — bound to the SOL UART for this hardware platform.
%s::respawn:/sbin/getty 115200 %s vt100

# Stuff to do for the 3-finger salute
::ctrlaltdel:/sbin/reboot

# Stuff to do before rebooting
::shutdown:/sbin/openrc shutdown
`, solPort, solPort)
	if err := os.WriteFile(inittabPath, []byte(inittabContent), 0644); err != nil {
		return fmt.Errorf("failed to create inittab: %w", err)
	}
	ai.logger.Info("[ALPINE] Created /etc/inittab with getty configuration")

	// NOTE: Network interfaces are configured by ConfigureNetwork() which is called
	// separately in the installation workflow. Do NOT create /etc/network/interfaces
	// here as it would overwrite any custom network configuration (e.g., static IP).

	return nil
}

// configureKernelModules writes /etc/modules with kernel modules to load at boot.
// This is required for bare metal servers where NIC drivers (igb, ixgbe) are
// kernel modules that must be explicitly loaded.
func (ai *alpineInstaller) configureKernelModules(rootPath string) error {
	modules := ai.config.KernelModules

	// Always include common bare metal NIC drivers for x86_64.
	// These are kernel modules in Alpine (not built-in) and are
	// required for networking on Intel-based servers.
	defaultModules := []string{"igb", "ixgbe", "e1000e", "i40e"}
	seen := make(map[string]bool)
	for _, m := range modules {
		seen[m] = true
	}
	for _, m := range defaultModules {
		if !seen[m] {
			modules = append(modules, m)
		}
	}

	if len(modules) == 0 {
		ai.logger.Debug("[ALPINE] No kernel modules configured")
		return nil
	}

	ai.logger.Info("[ALPINE] Configuring kernel modules to load at boot",
		"modules", modules)

	modulesPath := filepath.Join(rootPath, "etc/modules")

	// Read existing content (Alpine has default entries like af_packet, ipv6)
	existing := ""
	if data, err := os.ReadFile(modulesPath); err == nil {
		existing = string(data)
	}

	// Append configured modules (skip duplicates)
	var content strings.Builder
	content.WriteString(existing)
	if !strings.HasSuffix(existing, "\n") && existing != "" {
		content.WriteString("\n")
	}

	for _, mod := range modules {
		if !strings.Contains(existing, mod) {
			content.WriteString(mod)
			content.WriteString("\n")
			ai.logger.Info("[ALPINE] Added kernel module", "module", mod)
		}
	}

	if err := os.WriteFile(modulesPath, []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("failed to write /etc/modules: %w", err)
	}

	ai.logger.Info("[ALPINE] Kernel modules configured", "path", modulesPath)
	return nil
}

// InstallPackages installs additional packages from configuration
func (ai *alpineInstaller) InstallPackages(ctx context.Context, rootPath string) error {
	if len(ai.config.Packages) == 0 {
		ai.logger.Info("[ALPINE] No additional packages to install")
		return nil
	}

	ai.logger.Info("[ALPINE] Installing additional packages", "count", len(ai.config.Packages))

	// Check if tpm2-tools is in the package list and add dependencies
	packages := make([]string, len(ai.config.Packages))
	copy(packages, ai.config.Packages)
	needsTPMSetup := false

	for _, pkg := range ai.config.Packages {
		if pkg == "tpm2-tools" {
			needsTPMSetup = true
			// Ensure tpm2-tss is installed as a dependency
			hasTPMTSS := false
			for _, p := range packages {
				if p == "tpm2-tss" {
					hasTPMTSS = true
					break
				}
			}
			if !hasTPMTSS {
				ai.logger.Info("[ALPINE] Adding tpm2-tss as dependency for tpm2-tools")
				packages = append(packages, "tpm2-tss")
			}
			// TCTI device module is required for tpm2-tools to talk to /dev/tpmrm0
			// On Alpine, it's a separate package from tpm2-tss
			hasTCTIDevice := false
			for _, p := range packages {
				if p == "tpm2-tss-tcti-device" {
					hasTCTIDevice = true
					break
				}
			}
			if !hasTCTIDevice {
				ai.logger.Info("[ALPINE] Adding tpm2-tss-tcti-device for TPM device communication")
				packages = append(packages, "tpm2-tss-tcti-device")
			}
			break
		}
	}

	// Build apk add command with all packages.
	// --allow-untrusted is required when installing from the embedded
	// /var/cache/apk-prefetch repo because the regenerated APKINDEX is
	// unsigned (the package files themselves are byte-identical to the
	// official Alpine mirror, but apk has no key for our local index).
	args := []string{rootPath, "apk", "add", "--no-cache"}
	if ai.hasPreFetchedPackages() {
		args = append(args, "--allow-untrusted")
	}
	args = append(args, packages...)

	cmd := exec.CommandContext(ctx, "chroot", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		ai.logger.Errorf("[ALPINE] Package installation failed: %s", string(output))
		return ErrOSInstall("failed to install packages", err)
	}

	ai.logger.Info("[ALPINE] Successfully installed packages",
		"packages", strings.Join(packages, ", "))

	// Set up TPM2 TSS driver if needed
	if needsTPMSetup {
		if err := ai.setupTPM2TSS(ctx, rootPath); err != nil {
			ai.logger.Warn("[ALPINE] Failed to set up TPM2 TSS driver", "error", err)
			// Don't fail package installation if TPM setup fails
		}
	}

	return nil
}

// InstallDebugSSH installs and configures SSH for debug mode access.
// This installs the openssh package and configures sshd to allow root logins.
// Should only be called when Config.Debug is true.
func (ai *alpineInstaller) InstallDebugSSH(ctx context.Context, rootPath string) error {
	ai.logger.Info("[ALPINE] Installing SSH for debug mode")

	// Install openssh-server explicitly — the `openssh` meta-package
	// pulls in openssh-client by default but NOT openssh-server, so
	// /etc/init.d/sshd never gets installed and EnableServices logs
	// `Service not found, skipping sshd`. Adding openssh-server brings
	// the sshd binary AND its OpenRC init script. See InstallPackages
	// for the --allow-untrusted rationale (offline prefetch repo).
	apkArgs := []string{rootPath, "apk", "add", "--no-cache"}
	if ai.hasPreFetchedPackages() {
		apkArgs = append(apkArgs, "--allow-untrusted")
	}
	// Alpine 3.22+ splits openssh into many sub-packages. The OpenRC
	// init script (/etc/init.d/sshd) lives in
	// `openssh-server-common-openrc`, NOT in `openssh-server`. Without
	// it, EnableServices' rc-update add sshd default skips with
	// "Service not found", and sshd never starts on boot.
	apkArgs = append(apkArgs, "openssh", "openssh-server", "openssh-server-common-openrc")
	cmd := exec.CommandContext(ctx, "chroot", apkArgs...)
	if output, err := cmd.CombinedOutput(); err != nil {
		ai.logger.Errorf("[ALPINE] Failed to install openssh: %s", string(output))
		return ErrOSInstall("failed to install openssh for debug mode", err)
	}
	ai.logger.Info("[ALPINE] openssh package installed")

	// Configure sshd to allow root logins
	sshdConfigPath := filepath.Join(rootPath, "etc", "ssh", "sshd_config")

	// Read existing sshd_config
	configData, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return ErrOSInstall("failed to read sshd_config", err)
	}

	// Check if PermitRootLogin is already configured
	configStr := string(configData)
	if strings.Contains(configStr, "PermitRootLogin yes") {
		ai.logger.Info("[ALPINE] PermitRootLogin already enabled in sshd_config")
	} else {
		// Update or add PermitRootLogin yes
		lines := strings.Split(configStr, "\n")
		found := false
		for i, line := range lines {
			// Match commented or uncommented PermitRootLogin lines
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#PermitRootLogin") || strings.HasPrefix(trimmed, "PermitRootLogin") {
				lines[i] = "PermitRootLogin yes"
				found = true
				break
			}
		}

		if !found {
			// Add PermitRootLogin yes at the end
			lines = append(lines, "# Debug mode: allow root login", "PermitRootLogin yes")
		}

		newConfig := strings.Join(lines, "\n")
		if err := os.WriteFile(sshdConfigPath, []byte(newConfig), 0644); err != nil {
			return ErrOSInstall("failed to write sshd_config", err)
		}
		ai.logger.Info("[ALPINE] Configured PermitRootLogin yes in sshd_config")
	}

	// Generate SSH host keys if they don't exist
	hostKeyPath := filepath.Join(rootPath, "etc", "ssh", "ssh_host_rsa_key")
	if _, err := os.Stat(hostKeyPath); os.IsNotExist(err) {
		ai.logger.Info("[ALPINE] Generating SSH host keys")
		keygenCmd := exec.CommandContext(ctx, "chroot", rootPath, "ssh-keygen", "-A")
		if output, err := keygenCmd.CombinedOutput(); err != nil {
			ai.logger.Warnf("[ALPINE] Failed to generate SSH host keys: %s", string(output))
			// Don't fail - keys will be generated on first sshd start
		} else {
			ai.logger.Info("[ALPINE] SSH host keys generated")
		}
	}

	ai.logger.Info("[ALPINE] SSH debug mode configuration complete")
	return nil
}

// setupTPM2TSS configures TPM2 TSS driver and udev rules
func (ai *alpineInstaller) setupTPM2TSS(ctx context.Context, rootPath string) error {
	ai.logger.Info("[ALPINE] Setting up TPM2 TSS driver")

	// 1. Create tss group and user if they don't exist
	ai.logger.Info("[ALPINE] Creating tss user and group")

	// Create tss group (GID 59 is commonly used for tss)
	groupCmd := exec.CommandContext(ctx, "chroot", rootPath, "addgroup", "-S", "-g", "59", "tss")
	if output, err := groupCmd.CombinedOutput(); err != nil {
		// Group might already exist, check output
		if !strings.Contains(string(output), "already exists") {
			ai.logger.Warnf("[ALPINE] Failed to create tss group: %s", string(output))
		}
	}

	// Create tss user (UID 59 is commonly used for tss)
	userCmd := exec.CommandContext(ctx, "chroot", rootPath, "adduser", "-S", "-D", "-H",
		"-u", "59", "-G", "tss", "-s", "/sbin/nologin", "tss")
	if output, err := userCmd.CombinedOutput(); err != nil {
		// User might already exist, check output
		if !strings.Contains(string(output), "already exists") {
			ai.logger.Warnf("[ALPINE] Failed to create tss user: %s", string(output))
		}
	}

	// 2. Create udev rules for TPM device access
	ai.logger.Info("[ALPINE] Creating udev rules for TPM devices")

	udevRulesDir := filepath.Join(rootPath, "etc", "udev", "rules.d")
	if err := os.MkdirAll(udevRulesDir, 0755); err != nil {
		return fmt.Errorf("failed to create udev rules directory: %w", err)
	}

	// TPM2 udev rules - grants access to tss group
	tpmUdevRules := `# TPM2 TSS udev rules
# This file is automatically generated during installation

# TPM Character Devices
KERNEL=="tpm[0-9]*", MODE="0660", OWNER="tss", GROUP="tss"
KERNEL=="tpmrm[0-9]*", MODE="0660", OWNER="tss", GROUP="tss"

# TPM Device Mapper
SUBSYSTEM=="tpm", MODE="0660", OWNER="tss", GROUP="tss"

# Allow root and tss group access
KERNEL=="tpm[0-9]*", TAG+="systemd", ENV{SYSTEMD_WANTS}+="tpm2.target"
KERNEL=="tpmrm[0-9]*", TAG+="systemd", ENV{SYSTEMD_WANTS}+="tpm2.target"
`

	tpmUdevRulesPath := filepath.Join(udevRulesDir, "60-tpm2-tss.rules")
	if err := os.WriteFile(tpmUdevRulesPath, []byte(tpmUdevRules), 0644); err != nil {
		return fmt.Errorf("failed to write TPM udev rules: %w", err)
	}
	ai.logger.Info("[ALPINE] Created TPM2 udev rules", "path", "/etc/udev/rules.d/60-tpm2-tss.rules")

	// 3. Create symlink in /lib/udev/rules.d for Alpine compatibility
	// (similar to device-mapper udev rules fix)
	libUdevDir := filepath.Join(rootPath, "lib", "udev", "rules.d")
	if err := os.MkdirAll(libUdevDir, 0755); err != nil {
		ai.logger.Warnf("[ALPINE] Failed to create /lib/udev/rules.d: %v", err)
	} else {
		srcPath := "/etc/udev/rules.d/60-tpm2-tss.rules"
		dstPath := filepath.Join(libUdevDir, "60-tpm2-tss.rules")
		if err := os.Symlink(srcPath, dstPath); err != nil {
			ai.logger.Warnf("[ALPINE] Failed to symlink TPM udev rules to /lib: %v", err)
		} else {
			ai.logger.Info("[ALPINE] Symlinked TPM udev rules to /lib/udev/rules.d")
		}
	}

	// 4. Create TPM2 state directory
	ai.logger.Info("[ALPINE] Creating TPM2 state directories")

	tpmStateDir := filepath.Join(rootPath, "var", "lib", "tpm2-tss")
	if err := os.MkdirAll(tpmStateDir, 0750); err != nil {
		return fmt.Errorf("failed to create TPM2 state directory: %w", err)
	}

	// Set ownership to tss:tss using chroot
	chownCmd := exec.CommandContext(ctx, "chroot", rootPath, "chown", "-R", "tss:tss", "/var/lib/tpm2-tss")
	if output, err := chownCmd.CombinedOutput(); err != nil {
		ai.logger.Warnf("[ALPINE] Failed to set TPM2 state directory ownership: %s", string(output))
	}

	// 5. Create system-wide TPM2 configuration directory
	tpmConfigDir := filepath.Join(rootPath, "etc", "tpm2-tss")
	if err := os.MkdirAll(tpmConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create TPM2 config directory: %w", err)
	}

	// Create fapi-config.json for FAPI (Feature API)
	fapiConfig := `{
  "profile_dir": "/etc/tpm2-tss/fapi-profiles/",
  "user_dir": "/var/lib/tpm2-tss/user/keystore",
  "system_dir": "/var/lib/tpm2-tss/system/keystore",
  "log_dir": "/var/log/tpm2-tss",
  "profile_name": "P_ECCP256SHA256",
  "tcti": "device:/dev/tpmrm0",
  "ek_cert_less": "yes"
}
`
	fapiConfigPath := filepath.Join(tpmConfigDir, "fapi-config.json")
	if err := os.WriteFile(fapiConfigPath, []byte(fapiConfig), 0644); err != nil {
		ai.logger.Warnf("[ALPINE] Failed to write FAPI config: %v", err)
	} else {
		ai.logger.Info("[ALPINE] Created TPM2 FAPI configuration")
	}

	// 6. Set up TPM2TOOLS_TCTI environment variable for tpm2-tools
	ai.logger.Info("[ALPINE] Configuring TPM2TOOLS_TCTI environment variable")
	envFilePath := filepath.Join(rootPath, "etc", "environment")
	envContent := "TPM2TOOLS_TCTI=device:/dev/tpmrm0\n"

	// Read existing environment file if it exists
	existingEnv, err := os.ReadFile(envFilePath)
	if err == nil {
		// Append to existing content
		envContent = string(existingEnv) + envContent
	}

	if err := os.WriteFile(envFilePath, []byte(envContent), 0644); err != nil {
		ai.logger.Warnf("[ALPINE] Failed to write environment file: %v", err)
	} else {
		ai.logger.Info("[ALPINE] Set TPM2TOOLS_TCTI environment variable")
	}

	// 7. Add root user to tss group for administrative access
	ai.logger.Info("[ALPINE] Adding root user to tss group")
	addGroupCmd := exec.CommandContext(ctx, "chroot", rootPath, "addgroup", "root", "tss")
	if output, err := addGroupCmd.CombinedOutput(); err != nil {
		ai.logger.Warnf("[ALPINE] Failed to add root to tss group: %s", string(output))
	}

	ai.logger.Info("[ALPINE] TPM2 TSS driver setup completed successfully")
	return nil
}

// ExecutePostInstall executes post-install scripts from configuration
func (ai *alpineInstaller) ExecutePostInstall(ctx context.Context, rootPath string) error {
	// Check if any post-install scripts are configured
	if ai.config.PostInstall == "" && ai.config.PostInstallScript == "" {
		ai.logger.Info("[ALPINE] No post-install scripts to execute")
		return nil
	}

	ai.logger.Info("[ALPINE] Executing post-install scripts")

	// Create post-install executor
	executor := NewPostInstallExecutor(ai.logger, ai.config)

	// Execute the scripts
	if err := executor.Execute(ctx, rootPath); err != nil {
		return ErrOSInstall("post-install script execution failed", err)
	}

	ai.logger.Info("[ALPINE] Post-install scripts executed successfully")
	return nil
}

// installWebUI extracts and installs the WebUI from the ISO to the installed system
func (ai *alpineInstaller) installWebUI(ctx context.Context, rootPath string) error {
	// Determine installation path - use config if provided, else default
	// Default matches the webservice.home setting in the platform config
	installPath := ai.config.WebUIInstallPath
	if installPath == "" {
		installPath = "/var/lib/trusted-platform/public_html"
	}

	// Possible WebUI source locations on the ISO (mounted at /media/cdrom during installation)
	webUISources := []struct {
		path      string
		isTarball bool
	}{
		{"/media/cdrom/webui", false},             // Directory
		{"/media/cdrom/webui.tar.gz", true},       // Tarball
		{"/media/cdrom/public_html", false},       // Alternative directory name
		{"/media/cdrom/public_html.tar.gz", true}, // Alternative tarball name
	}

	var sourcePath string
	var isTarball bool

	// Find WebUI on the ISO
	for _, source := range webUISources {
		if _, err := os.Stat(source.path); err == nil {
			sourcePath = source.path
			isTarball = source.isTarball
			ai.logger.Info("[ALPINE] Found WebUI on ISO", "source", sourcePath)
			break
		}
	}

	if sourcePath == "" {
		ai.logger.Debug("[ALPINE] No WebUI found on ISO, skipping WebUI installation")
		return nil
	}

	// Create parent directory with proper ownership
	parentDir := filepath.Dir(filepath.Join(rootPath, installPath))
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	// Create installation directory
	destPath := filepath.Join(rootPath, installPath)
	if err := os.MkdirAll(destPath, 0755); err != nil {
		return fmt.Errorf("failed to create WebUI directory: %w", err)
	}

	ai.logger.Info("[ALPINE] Installing WebUI", "source", sourcePath, "destination", destPath)

	if isTarball {
		// Extract tarball with --strip-components=1 to remove the top-level directory
		// The tarball is created as "tar czf public_html.tar.gz public_html" which includes
		// the public_html/ directory at the root. We need to strip it so the contents
		// go directly into destPath.
		cmd := exec.CommandContext(ctx, "tar", "-xzf", sourcePath, "-C", destPath, "--strip-components=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to extract WebUI tarball: %w\nOutput: %s", err, string(output))
		}
	} else {
		// Copy directory contents
		cmd := exec.CommandContext(ctx, "cp", "-a", sourcePath+"/.", destPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to copy WebUI directory: %w\nOutput: %s", err, string(output))
		}
	}

	// Set appropriate permissions for web serving:
	// - Directories: 755 (rwxr-xr-x) - readable and traversable by all
	// - Files: 644 (rw-r--r--) - readable by all
	// - Owner: root (or can be changed to a dedicated web user)

	// Set directory permissions to 755
	findDirsCmd := exec.CommandContext(ctx, "find", destPath, "-type", "d", "-exec", "chmod", "755", "{}", ";")
	if err := findDirsCmd.Run(); err != nil {
		ai.logger.Warn("[ALPINE] Failed to set WebUI directory permissions", "error", err)
	}

	// Set file permissions to 644
	findFilesCmd := exec.CommandContext(ctx, "find", destPath, "-type", "f", "-exec", "chmod", "644", "{}", ";")
	if err := findFilesCmd.Run(); err != nil {
		ai.logger.Warn("[ALPINE] Failed to set WebUI file permissions", "error", err)
	}

	// Set ownership to root:root (platformd runs as root)
	chownCmd := exec.CommandContext(ctx, "chown", "-R", "root:root", destPath)
	if err := chownCmd.Run(); err != nil {
		ai.logger.Warn("[ALPINE] Failed to set WebUI ownership", "error", err)
	}

	// Verify index.html exists - create a basic landing page if missing
	rootIndex := filepath.Join(destPath, "index.html")
	if _, err := os.Stat(rootIndex); os.IsNotExist(err) {
		ai.logger.Info("[ALPINE] WebUI missing index.html - creating basic landing page")
		if err := ai.createLandingPage(ctx, destPath); err != nil {
			ai.logger.Warn("[ALPINE] Failed to create landing page", "error", err)
		}
	}

	ai.logger.Info("[ALPINE] WebUI installed successfully",
		"path", destPath,
		"dir_perms", "755",
		"file_perms", "644",
		"owner", "root:root")
	return nil
}

// createLandingPage creates a basic index.html landing page that lists available subdirectories
func (ai *alpineInstaller) createLandingPage(ctx context.Context, webUIPath string) error {
	// Find subdirectories
	entries, err := os.ReadDir(webUIPath)
	if err != nil {
		return fmt.Errorf("failed to read webui directory: %w", err)
	}

	var subdirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			subdirs = append(subdirs, entry.Name())
		}
	}

	// Generate HTML
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trusted Platform</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               margin: 0; padding: 40px; background: #1a1a2e; color: #eee; }
        h1 { color: #00d4ff; }
        .container { max-width: 800px; margin: 0 auto; }
        .sites { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 20px; margin-top: 30px; }
        .site { background: #16213e; border-radius: 8px; padding: 20px; transition: transform 0.2s; }
        .site:hover { transform: translateY(-5px); }
        .site a { color: #00d4ff; text-decoration: none; font-size: 1.1em; }
        .site a:hover { text-decoration: underline; }
        .status { margin-top: 30px; padding: 20px; background: #16213e; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Trusted Platform</h1>
        <p>Platform services are running. Select a dashboard below:</p>
        <div class="sites">
`

	if len(subdirs) > 0 {
		for _, dir := range subdirs {
			html += fmt.Sprintf(`            <div class="site"><a href="/%s/">%s</a></div>
`, dir, dir)
		}
	} else {
		html += `            <div class="site">No dashboards configured</div>
`
	}

	html += `        </div>
        <div class="status">
            <h3>System Status</h3>
            <p>API endpoint: <a href="/api/v1/system/info">/api/v1/system/info</a></p>
        </div>
    </div>
</body>
</html>
`

	indexPath := filepath.Join(webUIPath, "index.html")
	if err := os.WriteFile(indexPath, []byte(html), 0644); err != nil {
		return fmt.Errorf("failed to write index.html: %w", err)
	}

	ai.logger.Info("[ALPINE] Created landing page", "path", indexPath, "subdirs", len(subdirs))
	return nil
}

// ConfigureNetwork configures network interfaces, DNS, bridges, bonds, and VLANs
func (ai *alpineInstaller) ConfigureNetwork(ctx context.Context, rootPath string, netConfig *NetworkConfig) error {
	if netConfig == nil {
		ai.logger.Info("[ALPINE] No network configuration provided, using default DHCP")
		return ai.configureDefaultNetwork(rootPath)
	}

	ai.logger.Info("[ALPINE] Configuring network",
		"interfaces", len(netConfig.Interfaces),
		"bridges", len(netConfig.Bridges),
		"bonds", len(netConfig.Bonds),
		"vlans", len(netConfig.VLANs))

	// Configure DNS
	if netConfig.DNS != nil || netConfig.DNSMasq != nil {
		if err := ai.configureDNS(ctx, rootPath, netConfig.DNS, netConfig.DNSMasq); err != nil {
			return fmt.Errorf("failed to configure DNS: %w", err)
		}
	}

	// Build /etc/network/interfaces content
	var interfaces strings.Builder
	interfaces.WriteString("# /etc/network/interfaces\n")
	interfaces.WriteString("# Generated by Trusted Platform installer\n\n")

	// Always add loopback interface
	interfaces.WriteString("# Loopback interface\n")
	interfaces.WriteString("auto lo\n")
	interfaces.WriteString("iface lo inet loopback\n\n")

	// Configure bonds first (member interfaces need to be configured before the bond)
	for _, bond := range netConfig.Bonds {
		bondConfig := ai.generateBondConfig(&bond)
		interfaces.WriteString(bondConfig)

		// Skip Linux-style VLAN sub-interfaces for OVS bonds. For OVS
		// bonds the VLANs (bond.VLANs) are OVS-internal tags handled by
		// the bridge/port at the OVS layer; emitting `bond0.200` Linux
		// stanzas points at a kernel device that does not exist and
		// causes ifupdown failures.
		bondType := bond.Type
		if bondType == "" {
			bondType = BondTypeOVS
		}
		if bondType == BondTypeOVS {
			interfaces.WriteString(fmt.Sprintf(
				"# Bond %s VLANs handled inside OVS by platformd; no Linux stanzas emitted.\n\n",
				bond.Name))
			continue
		}

		// Generate VLAN sub-interfaces for this bond
		for _, bv := range bond.VLANs {
			vlanConfig := ai.generateBondVLANConfig(netConfig, bond.Name, &bv)
			interfaces.WriteString(vlanConfig)
		}
	}

	// Configure VLANs
	for _, vlan := range netConfig.VLANs {
		vlanConfig := ai.generateVLANConfig(&vlan)
		interfaces.WriteString(vlanConfig)
	}

	// Configure bridges
	for _, br := range netConfig.Bridges {
		bridgeConfig := ai.generateBridgeConfig(&br)
		interfaces.WriteString(bridgeConfig)
	}

	// Configure regular interfaces
	if len(netConfig.Interfaces) == 0 {
		// No explicit interface config, add default DHCP on eth0
		interfaces.WriteString("# Primary network interface (DHCP)\n")
		interfaces.WriteString("auto eth0\n")
		interfaces.WriteString("iface eth0 inet dhcp\n")
		interfaces.WriteString("    hostname $(hostname)\n\n")
	} else {
		for _, iface := range netConfig.Interfaces {
			ifaceConfig := ai.generateInterfaceConfig(&iface)
			interfaces.WriteString(ifaceConfig)
		}
	}

	// Write /etc/network/interfaces
	interfacesPath := filepath.Join(rootPath, "etc", "network", "interfaces")
	if err := os.MkdirAll(filepath.Dir(interfacesPath), 0755); err != nil {
		return fmt.Errorf("failed to create network directory: %w", err)
	}
	// Diagnostic dump of the generated content so misconfigurations (e.g.
	// missing iface fields → `ifup: don't have all variables for X/inet`)
	// are visible in install.log without needing to mount the LUKS disk.
	for i, line := range strings.Split(interfaces.String(), "\n") {
		ai.logger.Debug("[ALPINE] interfaces line", "i", i, "line", line)
	}
	if err := os.WriteFile(interfacesPath, []byte(interfaces.String()), 0644); err != nil {
		return fmt.Errorf("failed to write network interfaces: %w", err)
	}
	ai.logger.Info("[ALPINE] Created /etc/network/interfaces")

	// Install additional packages if needed
	if err := ai.installNetworkPackages(ctx, rootPath, netConfig); err != nil {
		ai.logger.Warn("[ALPINE] Failed to install some network packages", "error", err)
	}

	return nil
}

// configureDefaultNetwork creates default DHCP configuration
func (ai *alpineInstaller) configureDefaultNetwork(rootPath string) error {
	interfacesContent := `# /etc/network/interfaces
# Generated by Trusted Platform installer

# Loopback interface
auto lo
iface lo inet loopback

# Primary network interface (DHCP)
auto eth0
iface eth0 inet dhcp
    hostname $(hostname)
`
	interfacesPath := filepath.Join(rootPath, "etc", "network", "interfaces")
	if err := os.MkdirAll(filepath.Dir(interfacesPath), 0755); err != nil {
		return fmt.Errorf("failed to create network directory: %w", err)
	}
	if err := os.WriteFile(interfacesPath, []byte(interfacesContent), 0644); err != nil {
		return fmt.Errorf("failed to write network interfaces: %w", err)
	}
	ai.logger.Info("[ALPINE] Created default /etc/network/interfaces (DHCP)")
	return nil
}

// configureDNS configures /etc/resolv.conf and optionally dnsmasq.
//
// Three paths:
//  1. NetworkConfig.DNSMasq.Enabled — install dnsmasq, write a config that
//     forwards to UpstreamServers, point resolv.conf at 127.0.0.1.
//  2. dns.UpstreamDNS legacy single-server form — same dnsmasq path with one
//     upstream entry.
//  3. neither — write a plain resolv.conf with whatever Nameservers the
//     config lists.
//
// Path (1) is the path operators actually use in YAML overrides
// (`network.dnsmasq.enabled: true`). The previous code only wired path (2),
// so overrides that listed nameservers=[127.0.0.1] under DNS quietly
// resulted in NO dnsmasq install + a broken resolver loop on first boot.
func (ai *alpineInstaller) configureDNS(ctx context.Context, rootPath string, dns *DNSConfig, dnsmasq *DNSMasqConfig) error {
	if dnsmasq != nil && dnsmasq.Enabled {
		return ai.configureDNSMasqFromConfig(ctx, rootPath, dns, dnsmasq)
	}

	if dns != nil && dns.UpstreamDNS != "" {
		return ai.configureDNSWithDnsmasq(ctx, rootPath, dns)
	}

	if dns == nil {
		return nil
	}

	// Standard resolv.conf configuration
	var resolv strings.Builder
	resolv.WriteString("# /etc/resolv.conf\n")
	resolv.WriteString("# Generated by Trusted Platform installer\n\n")

	// Add search domains
	if len(dns.SearchDomains) > 0 {
		resolv.WriteString("search ")
		resolv.WriteString(strings.Join(dns.SearchDomains, " "))
		resolv.WriteString("\n")
	}

	// Add nameservers
	for _, ns := range dns.Nameservers {
		fmt.Fprintf(&resolv, "nameserver %s\n", ns)
	}

	// Add options
	if len(dns.Options) > 0 {
		resolv.WriteString("options ")
		resolv.WriteString(strings.Join(dns.Options, " "))
		resolv.WriteString("\n")
	}

	resolvPath := filepath.Join(rootPath, "etc", "resolv.conf")
	if err := os.WriteFile(resolvPath, []byte(resolv.String()), 0644); err != nil {
		return fmt.Errorf("failed to write resolv.conf: %w", err)
	}
	ai.logger.Info("[ALPINE] Created /etc/resolv.conf",
		"nameservers", dns.Nameservers,
		"search", dns.SearchDomains)
	return nil
}

// configureDNSMasqFromConfig installs and configures dnsmasq from the
// dedicated NetworkConfig.DNSMasq block (the form operators actually write
// in YAML overrides). It supports multiple upstream servers and a
// LocalDomain for split-horizon resolution.
func (ai *alpineInstaller) configureDNSMasqFromConfig(ctx context.Context, rootPath string, dns *DNSConfig, dnsmasq *DNSMasqConfig) error {
	ai.logger.Info("[ALPINE] Configuring dnsmasq",
		"upstream_servers", dnsmasq.UpstreamServers,
		"local_domain", dnsmasq.LocalDomain)

	// Install dnsmasq inside the chroot so the prefetch repo path
	// (/var/cache/apk-prefetch) resolves. See configureDNSWithDnsmasq
	// for the full rationale.
	if err := ai.setupChrootMounts(ctx, rootPath); err != nil {
		return fmt.Errorf("failed to setup chroot mounts for dnsmasq install: %w", err)
	}
	defer ai.cleanupChrootMounts(rootPath)

	apkArgs := []string{rootPath, "apk", "add", "--no-cache"}
	if ai.hasPreFetchedPackages() {
		apkArgs = append(apkArgs, "--allow-untrusted")
	}
	apkArgs = append(apkArgs, "dnsmasq", "dnsmasq-openrc")
	cmd := exec.CommandContext(ctx, "chroot", apkArgs...)
	if output, err := cmd.CombinedOutput(); err != nil {
		ai.logger.Errorf("[ALPINE] Failed to install dnsmasq: output=%s, error=%v", string(output), err)
		return fmt.Errorf("failed to install dnsmasq: %w", err)
	}

	// Build /etc/dnsmasq.conf
	var conf strings.Builder
	conf.WriteString("# /etc/dnsmasq.conf\n")
	conf.WriteString("# Generated by Trusted Platform installer\n\n")
	conf.WriteString("no-resolv\n")
	conf.WriteString("listen-address=127.0.0.1\n")
	conf.WriteString("bind-interfaces\n")
	conf.WriteString("cache-size=1000\n")

	for _, srv := range dnsmasq.UpstreamServers {
		fmt.Fprintf(&conf, "server=%s\n", srv)
	}

	if dnsmasq.LocalDomain != "" {
		fmt.Fprintf(&conf, "domain=%s\n", dnsmasq.LocalDomain)
		fmt.Fprintf(&conf, "local=/%s/\n", dnsmasq.LocalDomain)
	}

	confPath := filepath.Join(rootPath, "etc", "dnsmasq.conf")
	if err := os.WriteFile(confPath, []byte(conf.String()), 0644); err != nil {
		return fmt.Errorf("failed to write dnsmasq.conf: %w", err)
	}
	ai.logger.Info("[ALPINE] Wrote dnsmasq.conf", "path", confPath)

	// Enable at boot so the resolver is up before platformd starts.
	enableCmd := exec.CommandContext(ctx, "chroot", rootPath, "rc-update", "add", "dnsmasq", "default")
	if output, err := enableCmd.CombinedOutput(); err != nil {
		ai.logger.Warn("[ALPINE] Failed to enable dnsmasq service",
			"output", string(output), "error", err)
		// Non-fatal — operator can rc-update add manually.
	} else {
		ai.logger.Info("[ALPINE] Enabled dnsmasq service in default runlevel")
	}

	// Point resolv.conf at the local dnsmasq. If the operator listed
	// other nameservers under dns.Nameservers we honor them too — but
	// dnsmasq goes first so cached/local-domain answers are used.
	var resolv strings.Builder
	resolv.WriteString("# /etc/resolv.conf\n")
	resolv.WriteString("# Generated by Trusted Platform installer (dnsmasq mode)\n\n")
	if dns != nil && len(dns.SearchDomains) > 0 {
		resolv.WriteString("search ")
		resolv.WriteString(strings.Join(dns.SearchDomains, " "))
		resolv.WriteString("\n")
	}
	resolv.WriteString("nameserver 127.0.0.1\n")
	if dns != nil {
		for _, ns := range dns.Nameservers {
			if ns == "127.0.0.1" || ns == "::1" {
				continue
			}
			fmt.Fprintf(&resolv, "nameserver %s\n", ns)
		}
		if len(dns.Options) > 0 {
			resolv.WriteString("options ")
			resolv.WriteString(strings.Join(dns.Options, " "))
			resolv.WriteString("\n")
		}
	}
	resolvPath := filepath.Join(rootPath, "etc", "resolv.conf")
	if err := os.WriteFile(resolvPath, []byte(resolv.String()), 0644); err != nil {
		return fmt.Errorf("failed to write resolv.conf: %w", err)
	}
	ai.logger.Info("[ALPINE] Created /etc/resolv.conf pointing at local dnsmasq")
	return nil
}

// configureDNSWithDnsmasq sets up dnsmasq to forward DNS to a server on a non-standard port
func (ai *alpineInstaller) configureDNSWithDnsmasq(ctx context.Context, rootPath string, dns *DNSConfig) error {
	ai.logger.Info("[ALPINE] Configuring dnsmasq for upstream DNS forwarding",
		"upstream", dns.UpstreamDNS)

	// Install dnsmasq package via chroot so the embedded
	// /var/cache/apk-prefetch repo path resolves correctly. Using
	// `apk --root` from outside the chroot would try to read the path
	// from the host filesystem and fail with "No such file or directory".
	// The chroot lifecycle (proc/sys/dev mounts) is set up here for the
	// install and torn down on the deferred cleanup.
	ai.logger.Info("[ALPINE] Installing dnsmasq package")
	if err := ai.setupChrootMounts(ctx, rootPath); err != nil {
		return fmt.Errorf("failed to setup chroot mounts for dnsmasq install: %w", err)
	}
	defer ai.cleanupChrootMounts(rootPath)
	dnsmasqArgs := []string{rootPath, "apk", "add", "--no-cache"}
	if ai.hasPreFetchedPackages() {
		dnsmasqArgs = append(dnsmasqArgs, "--allow-untrusted")
	}
	dnsmasqArgs = append(dnsmasqArgs, "dnsmasq")
	cmd := exec.CommandContext(ctx, "chroot", dnsmasqArgs...)
	if output, err := cmd.CombinedOutput(); err != nil {
		ai.logger.Errorf("[ALPINE] Failed to install dnsmasq: output=%s, error=%v", string(output), err)
		return fmt.Errorf("failed to install dnsmasq: %w", err)
	}

	// Create dnsmasq configuration
	var dnsmasqConf strings.Builder
	dnsmasqConf.WriteString("# dnsmasq configuration\n")
	dnsmasqConf.WriteString("# Generated by Trusted Platform installer\n\n")

	// Don't read /etc/resolv.conf
	dnsmasqConf.WriteString("no-resolv\n")

	// Forward all queries to upstream DNS server (format: ip#port)
	fmt.Fprintf(&dnsmasqConf, "server=%s\n", dns.UpstreamDNS)

	// Listen only on localhost
	dnsmasqConf.WriteString("listen-address=127.0.0.1\n")
	dnsmasqConf.WriteString("bind-interfaces\n")

	// Cache DNS queries
	dnsmasqConf.WriteString("cache-size=1000\n")

	// Log queries for debugging (optional)
	dnsmasqConf.WriteString("log-queries\n")

	// Write dnsmasq config
	dnsmasqConfPath := filepath.Join(rootPath, "etc", "dnsmasq.conf")
	if err := os.WriteFile(dnsmasqConfPath, []byte(dnsmasqConf.String()), 0644); err != nil {
		return fmt.Errorf("failed to write dnsmasq.conf: %w", err)
	}
	ai.logger.Info("[ALPINE] Created dnsmasq.conf", "upstream", dns.UpstreamDNS)

	// Enable dnsmasq service at boot
	cmd = exec.Command("chroot", rootPath, "rc-update", "add", "dnsmasq", "default")
	if output, err := cmd.CombinedOutput(); err != nil {
		ai.logger.Warn("[ALPINE] Failed to enable dnsmasq service", "output", string(output), "error", err)
		// Non-fatal - service may need to be enabled manually
	}

	// Configure resolv.conf to use local dnsmasq
	var resolv strings.Builder
	resolv.WriteString("# /etc/resolv.conf\n")
	resolv.WriteString("# Generated by Trusted Platform installer\n")
	resolv.WriteString("# DNS queries forwarded via dnsmasq to upstream server\n\n")

	// Add search domains
	if len(dns.SearchDomains) > 0 {
		resolv.WriteString("search ")
		resolv.WriteString(strings.Join(dns.SearchDomains, " "))
		resolv.WriteString("\n")
	}

	// Point to local dnsmasq
	resolv.WriteString("nameserver 127.0.0.1\n")

	// Add options
	if len(dns.Options) > 0 {
		resolv.WriteString("options ")
		resolv.WriteString(strings.Join(dns.Options, " "))
		resolv.WriteString("\n")
	}

	resolvPath := filepath.Join(rootPath, "etc", "resolv.conf")
	if err := os.WriteFile(resolvPath, []byte(resolv.String()), 0644); err != nil {
		return fmt.Errorf("failed to write resolv.conf: %w", err)
	}

	ai.logger.Info("[ALPINE] Configured DNS with dnsmasq",
		"upstream", dns.UpstreamDNS,
		"search", dns.SearchDomains)

	return nil
}

// generateInterfaceConfig generates Alpine-style interface configuration
func (ai *alpineInstaller) generateInterfaceConfig(iface *InterfaceConfig) string {
	var config strings.Builder

	fmt.Fprintf(&config, "# Interface: %s\n", iface.Name)

	if iface.AutoStart {
		fmt.Fprintf(&config, "auto %s\n", iface.Name)
	}

	switch iface.Type {
	case InterfaceTypeDHCP:
		fmt.Fprintf(&config, "iface %s inet dhcp\n", iface.Name)
		config.WriteString("    hostname $(hostname)\n")

	case InterfaceTypeStatic:
		fmt.Fprintf(&config, "iface %s inet static\n", iface.Name)

		// Handle CIDR notation or separate netmask
		if strings.Contains(iface.IPv4Address, "/") {
			fmt.Fprintf(&config, "    address %s\n", iface.IPv4Address)
		} else {
			fmt.Fprintf(&config, "    address %s\n", iface.IPv4Address)
			if iface.IPv4Netmask != "" {
				fmt.Fprintf(&config, "    netmask %s\n", iface.IPv4Netmask)
			}
		}

		if iface.IPv4Gateway != "" {
			fmt.Fprintf(&config, "    gateway %s\n", iface.IPv4Gateway)
		}

	case InterfaceTypeManual:
		fmt.Fprintf(&config, "iface %s inet manual\n", iface.Name)

	case InterfaceTypeDisabled:
		fmt.Fprintf(&config, "# %s is disabled\n", iface.Name)
		return config.String()
	}

	// Add MTU if specified
	if iface.MTU > 0 {
		fmt.Fprintf(&config, "    mtu %d\n", iface.MTU)
	}

	// Add interface-specific DNS
	if len(iface.DNS) > 0 {
		for _, dns := range iface.DNS {
			fmt.Fprintf(&config, "    dns-nameservers %s\n", dns)
		}
	}

	// Add static routes
	for _, route := range iface.Routes {
		if route.Metric > 0 {
			fmt.Fprintf(&config, "    up ip route add %s via %s metric %d\n",
				route.Destination, route.Gateway, route.Metric)
		} else {
			fmt.Fprintf(&config, "    up ip route add %s via %s\n",
				route.Destination, route.Gateway)
		}
	}

	// Add IPv6 configuration
	if iface.IPv6Address != "" {
		fmt.Fprintf(&config, "\niface %s inet6 static\n", iface.Name)
		fmt.Fprintf(&config, "    address %s\n", iface.IPv6Address)
		if iface.IPv6Gateway != "" {
			fmt.Fprintf(&config, "    gateway %s\n", iface.IPv6Gateway)
		}
	} else if iface.IPv6AutoConf {
		fmt.Fprintf(&config, "\niface %s inet6 auto\n", iface.Name)
	}

	config.WriteString("\n")
	return config.String()
}

// generateBridgeConfig generates bridge interface configuration.
//
// For Type=ovs bridges, the Linux bridge device is NOT created here —
// platformd creates the OVS bridge at runtime via a native OVSDB
// transaction (see pkg/app/sdn.go::initOVSBridges + initBridgeIPs)
// and assigns any VLAN-scoped IPs from bonds[].vlans[]. Writing Linux
// bridge_ports stanzas on top of an OVS bridge causes ifenslave to
// race ovs-vswitchd for the bridge name. Member interfaces still get
// their "manual" stanzas so they come up cleanly for OVS to claim.
//
// For Type=linux (or unset, for legacy configs), we emit the
// traditional bridge-utils /etc/network/interfaces stanza.
func (ai *alpineInstaller) generateBridgeConfig(br *BridgeConfig) string {
	var config strings.Builder

	// Default empty Type to OVS so new deployments don't accidentally
	// pin themselves to the Linux bridge driver. Explicit type=linux
	// preserves existing behaviour.
	bridgeType := br.Type
	if bridgeType == "" {
		bridgeType = BridgeTypeOVS
	}

	if bridgeType == BridgeTypeOVS {
		// For OVS bridges, emit only a comment. The members listed under
		// br.Interfaces are OVS construct names (bond0, port0, etc.) that
		// do NOT exist as Linux devices, so ifupdown can't bring them up.
		// Their physical underlay NICs are emitted by generateBondConfig.
		// Writing `auto <ovs-port-name>` here causes
		//   `ip: can't find device 'bond0'`
		// during /etc/init.d/networking start.
		fmt.Fprintf(&config, "# Bridge: %s (OVS — created at runtime by platformd; no Linux stanza)\n\n", br.Name)
		return config.String()
	}

	// Linux bridge path (bridge-utils).
	fmt.Fprintf(&config, "# Bridge: %s\n", br.Name)

	// Configure member interfaces as manual (no IP)
	for _, member := range br.Interfaces {
		fmt.Fprintf(&config, "auto %s\n", member)
		fmt.Fprintf(&config, "iface %s inet manual\n", member)
		config.WriteString("\n")
	}

	if br.AutoStart {
		fmt.Fprintf(&config, "auto %s\n", br.Name)
	}

	if br.DHCP {
		fmt.Fprintf(&config, "iface %s inet dhcp\n", br.Name)
	} else if br.IPv4Address != "" {
		fmt.Fprintf(&config, "iface %s inet static\n", br.Name)
		if strings.Contains(br.IPv4Address, "/") {
			fmt.Fprintf(&config, "    address %s\n", br.IPv4Address)
		} else {
			fmt.Fprintf(&config, "    address %s\n", br.IPv4Address)
			if br.IPv4Netmask != "" {
				fmt.Fprintf(&config, "    netmask %s\n", br.IPv4Netmask)
			}
		}
		if br.IPv4Gateway != "" {
			fmt.Fprintf(&config, "    gateway %s\n", br.IPv4Gateway)
		}
	} else {
		fmt.Fprintf(&config, "iface %s inet manual\n", br.Name)
	}

	// Bridge-specific options
	fmt.Fprintf(&config, "    bridge_ports %s\n", strings.Join(br.Interfaces, " "))

	if br.STP {
		config.WriteString("    bridge_stp on\n")
	} else {
		config.WriteString("    bridge_stp off\n")
	}

	if br.ForwardDelay > 0 {
		fmt.Fprintf(&config, "    bridge_fd %d\n", br.ForwardDelay)
	}

	config.WriteString("\n")
	return config.String()
}

// generateBondConfig generates bond interface configuration.
//
// For Type=ovs bonds, the kernel bond device is NOT created here —
// platformd creates the bond inside OVS at runtime via a native OVSDB
// transaction (see pkg/app/sdn.go::initOVSBonds). All we do for OVS
// bonds is mark the member NICs as manually configured + brought up
// so ovs-vswitchd can claim them before platformd issues the AddBond.
// Writing the Linux bond-slaves stanzas on top of an OVS bond causes
// the kernel bonding driver to race OVS for the member NICs and
// produces a broken hybrid state.
//
// For Type=linux (or unset, for legacy configs), we emit the
// traditional ifenslave-style /etc/network/interfaces bond.
func (ai *alpineInstaller) generateBondConfig(bond *BondConfig) string {
	var config strings.Builder

	// Default empty Type to OVS so new deployments don't accidentally
	// pin themselves to the kernel bonding driver. Explicit type=linux
	// preserves existing behaviour.
	bondType := bond.Type
	if bondType == "" {
		bondType = BondTypeOVS
	}

	if bondType == BondTypeOVS {
		fmt.Fprintf(&config, "# Bond: %s (OVS — bond created at runtime by platformd initOVSBonds)\n", bond.Name)
		for _, iface := range bond.Interfaces {
			fmt.Fprintf(&config, "auto %s\n", iface)
			fmt.Fprintf(&config, "iface %s inet manual\n", iface)
			fmt.Fprintf(&config, "    up ip link set $IFACE up\n")
			fmt.Fprintf(&config, "    down ip link set $IFACE down\n")
			config.WriteString("\n")
		}
		return config.String()
	}

	fmt.Fprintf(&config, "# Bond: %s (linux kernel bonding)\n", bond.Name)

	// Configure member interfaces
	for _, iface := range bond.Interfaces {
		fmt.Fprintf(&config, "auto %s\n", iface)
		fmt.Fprintf(&config, "iface %s inet manual\n", iface)
		fmt.Fprintf(&config, "    bond-master %s\n", bond.Name)
		config.WriteString("\n")
	}

	if bond.AutoStart {
		fmt.Fprintf(&config, "auto %s\n", bond.Name)
	}

	if bond.DHCP {
		fmt.Fprintf(&config, "iface %s inet dhcp\n", bond.Name)
	} else if bond.IPv4Address != "" {
		fmt.Fprintf(&config, "iface %s inet static\n", bond.Name)
		if strings.Contains(bond.IPv4Address, "/") {
			fmt.Fprintf(&config, "    address %s\n", bond.IPv4Address)
		} else {
			fmt.Fprintf(&config, "    address %s\n", bond.IPv4Address)
			if bond.IPv4Netmask != "" {
				fmt.Fprintf(&config, "    netmask %s\n", bond.IPv4Netmask)
			}
		}
		if bond.IPv4Gateway != "" {
			fmt.Fprintf(&config, "    gateway %s\n", bond.IPv4Gateway)
		}
	} else {
		fmt.Fprintf(&config, "iface %s inet manual\n", bond.Name)
	}

	// Bond-specific options
	fmt.Fprintf(&config, "    bond-slaves %s\n", strings.Join(bond.Interfaces, " "))
	fmt.Fprintf(&config, "    bond-mode %s\n", bond.Mode)

	if bond.MIIMon > 0 {
		fmt.Fprintf(&config, "    bond-miimon %d\n", bond.MIIMon)
	}

	if bond.Primary != "" {
		fmt.Fprintf(&config, "    bond-primary %s\n", bond.Primary)
	}

	config.WriteString("\n")
	return config.String()
}

// generateBondVLANConfig generates an 802.1Q VLAN sub-interface on a bond.
// The VLAN ID is resolved from the referenced SubnetConfig by name.
func (ai *alpineInstaller) generateBondVLANConfig(netConfig *NetworkConfig, bondName string, bv *BondVLANConfig) string {
	var config strings.Builder

	subnet := netConfig.SubnetByName(bv.Subnet)
	if subnet == nil || subnet.VLANID == 0 {
		return ""
	}

	ifaceName := fmt.Sprintf("%s.%d", bondName, subnet.VLANID)

	fmt.Fprintf(&config, "# Bond VLAN: %s (subnet %s, VLAN %d)\n", ifaceName, bv.Subnet, subnet.VLANID)

	if bv.AutoStart {
		fmt.Fprintf(&config, "auto %s\n", ifaceName)
	}

	if bv.IPv4Address != "" {
		fmt.Fprintf(&config, "iface %s inet static\n", ifaceName)
		fmt.Fprintf(&config, "    address %s\n", bv.IPv4Address)
		if subnet.Gateway != "" {
			fmt.Fprintf(&config, "    gateway %s\n", subnet.Gateway)
		}
	} else {
		fmt.Fprintf(&config, "iface %s inet manual\n", ifaceName)
	}

	config.WriteString("\n")
	return config.String()
}

// generateVLANConfig generates VLAN interface configuration
func (ai *alpineInstaller) generateVLANConfig(vlan *VLANConfig) string {
	var config strings.Builder

	fmt.Fprintf(&config, "# VLAN: %s (ID %d on %s)\n", vlan.Name, vlan.ID, vlan.Parent)

	if vlan.AutoStart {
		fmt.Fprintf(&config, "auto %s\n", vlan.Name)
	}

	if vlan.DHCP {
		fmt.Fprintf(&config, "iface %s inet dhcp\n", vlan.Name)
	} else if vlan.IPv4Address != "" {
		fmt.Fprintf(&config, "iface %s inet static\n", vlan.Name)
		if strings.Contains(vlan.IPv4Address, "/") {
			fmt.Fprintf(&config, "    address %s\n", vlan.IPv4Address)
		} else {
			fmt.Fprintf(&config, "    address %s\n", vlan.IPv4Address)
			if vlan.IPv4Netmask != "" {
				fmt.Fprintf(&config, "    netmask %s\n", vlan.IPv4Netmask)
			}
		}
		if vlan.IPv4Gateway != "" {
			fmt.Fprintf(&config, "    gateway %s\n", vlan.IPv4Gateway)
		}
	} else {
		fmt.Fprintf(&config, "iface %s inet manual\n", vlan.Name)
	}

	// VLAN options - using vlan-raw-device for Alpine
	fmt.Fprintf(&config, "    vlan-raw-device %s\n", vlan.Parent)

	config.WriteString("\n")
	return config.String()
}

// installNetworkPackages installs required packages for advanced networking
func (ai *alpineInstaller) installNetworkPackages(ctx context.Context, rootPath string, netConfig *NetworkConfig) error {
	var packages []string

	// Always install ifupdown-ng. busybox's built-in /sbin/ifup cannot
	// parse CIDR notation (`address 198.18.1.139/24`) and fails with
	// `ifup: don't have all variables for X/inet`. ifupdown-ng handles
	// CIDR natively. /sbin/ifup is whichever package wins last during
	// install; explicitly installing ifupdown-ng makes it the provider.
	packages = append(packages, "ifupdown-ng")

	// Check if we need bridge utilities
	if len(netConfig.Bridges) > 0 {
		for _, br := range netConfig.Bridges {
			if br.Type == BridgeTypeOVS {
				packages = append(packages, "openvswitch")
			} else {
				packages = append(packages, "bridge")
			}
		}
	}

	// Bonding does NOT require a separate apk package on Alpine: the
	// kernel module ships with linux-lts and is loaded via
	// /etc/modules (wire that up in the template's os.kernel-modules
	// list, not here). Historical behaviour tried `apk add bonding`,
	// which doesn't exist in any Alpine repo and caused a WARN + the
	// install to proceed without networking ever coming up.

	// Check if we need VLAN support
	if len(netConfig.VLANs) > 0 {
		packages = append(packages, "vlan")
	}

	if len(packages) == 0 {
		return nil
	}

	// Deduplicate packages
	seen := make(map[string]bool)
	unique := []string{}
	for _, pkg := range packages {
		if !seen[pkg] {
			seen[pkg] = true
			unique = append(unique, pkg)
		}
	}

	ai.logger.Info("[ALPINE] Installing network packages", "packages", unique)

	args := []string{rootPath, "apk", "add", "--no-cache"}
	if ai.hasPreFetchedPackages() {
		args = append(args, "--allow-untrusted")
	}
	args = append(args, unique...)

	cmd := exec.CommandContext(ctx, "chroot", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		ai.logger.Warn("[ALPINE] Failed to install network packages",
			"error", err,
			"output", string(output))
		return fmt.Errorf("failed to install network packages: %w", err)
	}

	return nil
}

// Name returns the OS name
func (ai *alpineInstaller) Name() OperatingSystem {
	return OSAlpine
}

// configureIMA sets up Linux Integrity Measurement Architecture
func (ai *alpineInstaller) configureIMA(ctx context.Context, rootPath string) error {
	if ai.config.IMA == nil || !ai.config.IMA.Enabled {
		ai.logger.Debug("[ALPINE] IMA not enabled, skipping configuration")
		return nil
	}

	ai.logger.Info("[ALPINE] Configuring Linux Integrity Measurement Architecture (IMA)")

	// Create IMA configuration directory
	imaDir := filepath.Join(rootPath, "etc", "ima")
	if err := os.MkdirAll(imaDir, 0755); err != nil {
		return fmt.Errorf("failed to create IMA directory: %w", err)
	}

	// Generate IMA policy based on configuration
	policy := ai.generateIMAPolicy()

	// Write IMA policy file
	policyPath := filepath.Join(imaDir, "ima-policy")
	if err := os.WriteFile(policyPath, []byte(policy), 0644); err != nil {
		return fmt.Errorf("failed to write IMA policy: %w", err)
	}
	ai.logger.Info("[ALPINE] Created IMA policy", "path", "/etc/ima/ima-policy")

	// Create IMA configuration file for runtime reference
	imaConf := fmt.Sprintf(`# IMA Configuration
# Generated by Trusted Platform installer

IMA_ENABLED=1
IMA_POLICY=%s
IMA_HASH=%s
IMA_AUDIT=%d
IMA_APPRAISE=%s
IMA_EVM=%d
`,
		ai.config.IMA.Policy,
		ai.config.IMA.HashAlgorithm,
		boolToInt(ai.config.IMA.AuditEnabled),
		ai.config.IMA.AppraiseMode,
		boolToInt(ai.config.IMA.EVM))

	confPath := filepath.Join(imaDir, "ima.conf")
	if err := os.WriteFile(confPath, []byte(imaConf), 0644); err != nil {
		ai.logger.Warn("[ALPINE] Failed to write IMA config file", "error", err)
	}

	// Create OpenRC local.d script to load IMA policy on boot
	// This loads the custom policy after the kernel built-in policy
	localDDir := filepath.Join(rootPath, "etc", "local.d")
	if err := os.MkdirAll(localDDir, 0755); err != nil {
		ai.logger.Warn("[ALPINE] Failed to create local.d directory", "error", err)
	} else {
		imaStartScript := `#!/bin/sh
# Load custom IMA policy on boot
# Generated by Trusted Platform installer

# Check if IMA is available
if [ ! -d /sys/kernel/security/ima ]; then
    echo "IMA not available in kernel"
    exit 0
fi

# Load custom policy if it exists
if [ -f /etc/ima/ima-policy ]; then
    echo "Loading custom IMA policy..."
    cat /etc/ima/ima-policy > /sys/kernel/security/ima/policy 2>/dev/null || {
        echo "Warning: Could not load IMA policy (may require secure boot)"
    }
fi

# Load IMA keys for signature verification (if available)
if [ -f /etc/ima/ima-public-key.pem ]; then
    keyctl padd asymmetric "" %:.ima < /etc/ima/ima-public-key.pem 2>/dev/null || {
        echo "Warning: Could not load IMA public key"
    }
fi
`
		startScriptPath := filepath.Join(localDDir, "ima.start")
		if err := os.WriteFile(startScriptPath, []byte(imaStartScript), 0755); err != nil {
			ai.logger.Warn("[ALPINE] Failed to write IMA start script", "error", err)
		} else {
			ai.logger.Info("[ALPINE] Created IMA local.d start script")
		}

		// Create platformd debug script for integration testing.
		// The serial device is driven by the hardware quirk so the output
		// reaches the operator via the correct UART/SOL port.
		serialDev := "/dev/" + ai.quirk.SOLPort
		platformdDebugScript := fmt.Sprintf(`#!/bin/sh
# Output platformd logs to serial console for debugging.
# Generated by Trusted Platform installer — serial device: %s

# Wait for platformd to start and generate some logs
sleep 15

echo "=== PLATFORMD DEBUG LOG START ===" > %s

# Dump platformd.log (stdout/stderr from OpenRC)
echo "--- platformd.log ---" > %s
if [ -f /var/log/trusted-platform/platformd.log ]; then
    cat /var/log/trusted-platform/platformd.log > %s 2>/dev/null
else
    echo "platformd.log not found" > %s
fi

# Dump trusted-platform.log (App.Logger structured logging)
echo "--- trusted-platform.log ---" > %s
if [ -f /var/log/trusted-platform/trusted-platform.log ]; then
    cat /var/log/trusted-platform/trusted-platform.log > %s 2>/dev/null
else
    echo "trusted-platform.log not found" > %s
fi

echo "=== PLATFORMD DEBUG LOG END ===" > %s

# Keep tailing both logs to serial console
tail -f /var/log/trusted-platform/platformd.log /var/log/trusted-platform/trusted-platform.log > %s 2>/dev/null &
`,
			serialDev,
			serialDev,
			serialDev, serialDev, serialDev,
			serialDev, serialDev, serialDev,
			serialDev,
			serialDev,
		)
		platformdDebugPath := filepath.Join(localDDir, "platformd-debug.start")
		if err := os.WriteFile(platformdDebugPath, []byte(platformdDebugScript), 0755); err != nil {
			ai.logger.Warn("[ALPINE] Failed to write platformd debug script", "error", err)
		} else {
			ai.logger.Info("[ALPINE] Created platformd debug local.d script")
		}
	}

	// Enable audit service if audit logging is enabled
	if ai.config.IMA.AuditEnabled {
		auditServicePath := filepath.Join(rootPath, "etc/init.d/auditd")
		if _, err := os.Stat(auditServicePath); err == nil {
			// Enable auditd service
			rcCmd := exec.CommandContext(ctx, "chroot", rootPath, "rc-update", "add", "auditd", "default")
			if output, err := rcCmd.CombinedOutput(); err != nil {
				ai.logger.Warn("[ALPINE] Failed to enable auditd service", "error", err, "output", string(output))
			} else {
				ai.logger.Info("[ALPINE] Enabled auditd service for IMA audit logging")
			}
		}
	}

	ai.logger.Info("[ALPINE] IMA configuration complete",
		"policy", ai.config.IMA.Policy,
		"hash", ai.config.IMA.HashAlgorithm,
		"audit", ai.config.IMA.AuditEnabled)

	return nil
}

// generateIMAPolicy creates an IMA policy based on configuration
func (ai *alpineInstaller) generateIMAPolicy() string {
	var policy strings.Builder

	policy.WriteString("# Linux IMA Policy\n")
	policy.WriteString("# Generated by Trusted Platform installer\n")
	policy.WriteString("# This policy extends the kernel built-in policy\n\n")

	// Add policy rules based on policy type
	switch ai.config.IMA.Policy {
	case "tcb":
		// Trusted Computing Base - measure executables, libraries, kernel modules
		policy.WriteString("# TCB Policy - Trusted Computing Base\n")
		policy.WriteString("measure func=BPRM_CHECK mask=MAY_EXEC pcr=10 template=ima-ng\n")
		policy.WriteString("measure func=MMAP_CHECK mask=MAY_EXEC pcr=10 template=ima-ng\n")
		policy.WriteString("measure func=MODULE_CHECK pcr=10 template=ima-ng\n")
		policy.WriteString("measure func=FIRMWARE_CHECK pcr=10 template=ima-ng\n")
		policy.WriteString("measure func=KEXEC_KERNEL_CHECK pcr=10 template=ima-ng\n")
		policy.WriteString("measure func=KEXEC_INITRAMFS_CHECK pcr=10 template=ima-ng\n")

	case "appraise_tcb":
		// TCB with signature verification
		policy.WriteString("# TCB with Appraisal Policy\n")
		policy.WriteString("measure func=BPRM_CHECK mask=MAY_EXEC pcr=10 template=ima-sig\n")
		policy.WriteString("measure func=MMAP_CHECK mask=MAY_EXEC pcr=10 template=ima-sig\n")
		policy.WriteString("appraise func=BPRM_CHECK mask=MAY_EXEC fowner=0 appraise_type=imasig\n")
		policy.WriteString("appraise func=MMAP_CHECK mask=MAY_EXEC fowner=0 appraise_type=imasig\n")
		policy.WriteString("measure func=MODULE_CHECK pcr=10 template=ima-sig\n")
		policy.WriteString("appraise func=MODULE_CHECK appraise_type=imasig\n")

	case "secure_boot":
		// Minimal policy for secure boot
		policy.WriteString("# Secure Boot Policy\n")
		policy.WriteString("measure func=KEXEC_KERNEL_CHECK pcr=10 template=ima-ng\n")
		policy.WriteString("measure func=KEXEC_INITRAMFS_CHECK pcr=10 template=ima-ng\n")
		policy.WriteString("measure func=MODULE_CHECK pcr=10 template=ima-ng\n")

	case "critical_data":
		// Critical kernel data only
		policy.WriteString("# Critical Data Policy\n")
		policy.WriteString("measure func=CRITICAL_DATA pcr=10 template=ima-buf\n")

	default:
		// Default to TCB
		policy.WriteString("# Default TCB Policy\n")
		policy.WriteString("measure func=BPRM_CHECK mask=MAY_EXEC pcr=10 template=ima-ng\n")
		policy.WriteString("measure func=MMAP_CHECK mask=MAY_EXEC pcr=10 template=ima-ng\n")
		policy.WriteString("measure func=MODULE_CHECK pcr=10 template=ima-ng\n")
	}

	// Add custom monitor paths if specified
	if len(ai.config.IMA.MonitorPaths) > 0 {
		policy.WriteString("\n# Custom monitored paths\n")
		for _, path := range ai.config.IMA.MonitorPaths {
			// For files, measure on open for read
			fmt.Fprintf(&policy, "measure func=FILE_CHECK mask=MAY_READ uid=0 pcr=10 obj_type=%s\n", path)
		}
	}

	// Add dont_measure rules for noise reduction
	policy.WriteString("\n# Reduce noise - don't measure log files and temporary data\n")
	policy.WriteString("dont_measure fsmagic=0x9fa0\n")     // procfs
	policy.WriteString("dont_measure fsmagic=0x62656572\n") // sysfs
	policy.WriteString("dont_measure fsmagic=0x64626720\n") // debugfs
	policy.WriteString("dont_measure fsmagic=0x01021994\n") // tmpfs
	policy.WriteString("dont_measure fsmagic=0x858458f6\n") // ramfs
	policy.WriteString("dont_measure fsmagic=0x73636673\n") // securityfs

	return policy.String()
}

// installCABundle installs the CA bundle from the ISO or the
// dynamically-fetched orchestrator endpoint into the OS trust store.
//
// Precedence:
//  1. /tmp/ca-bundle.pem — fetched by autoinstall.sh from the
//     bootstrap orchestrator's pxeboot /config/mac/<mac>/ca-bundle.pem
//     endpoint. Used for client nodes enrolling with a CP whose CA
//     didn't exist at ISO build time.
//  2. /media/cdrom/configs/ca-bundle.pem (or /media/usb, /mnt/cdrom) —
//     baked into the ISO at build time. Used when the operator
//     pre-bakes the CA (single-node, air-gapped, CP-is-only-node).
//
// If neither path exists the step is a no-op — the installed system
// starts with stock root CAs and ACME enrollment on a private CA
// will fail (the node owner is expected to provide the trust anchor
// via one of the two paths above).
func (ai *alpineInstaller) installCABundle(ctx context.Context, rootPath string) error {
	var caBundleSrc string

	// Priority 1: orchestrator-fetched bundle. autoinstall.sh writes
	// it to /tmp/ca-bundle.pem after Priority 1 config fetch.
	if _, err := os.Stat("/tmp/ca-bundle.pem"); err == nil {
		caBundleSrc = "/tmp/ca-bundle.pem"
	}

	// Priority 2: ISO-baked bundle.
	if caBundleSrc == "" {
		for _, mountPoint := range []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"} {
			testPath := filepath.Join(mountPoint, "configs", "ca-bundle.pem")
			if _, err := os.Stat(testPath); err == nil {
				caBundleSrc = testPath
				break
			}
		}
	}

	if caBundleSrc == "" {
		ai.logger.Debug("[ALPINE] No CA bundle found (ISO or /tmp/), skipping CA installation")
		return nil
	}

	ai.logger.Info("[ALPINE] Installing CA bundle to OS trust store", "source", caBundleSrc)

	// Read the CA bundle
	caBundleData, err := os.ReadFile(caBundleSrc)
	if err != nil {
		return fmt.Errorf("failed to read CA bundle: %w", err)
	}

	// Create the CA certificates directory
	// Alpine uses /usr/local/share/ca-certificates/ for custom CA certificates
	caCertsDir := filepath.Join(rootPath, "usr", "local", "share", "ca-certificates")
	if err := os.MkdirAll(caCertsDir, 0755); err != nil {
		return fmt.Errorf("failed to create CA certificates directory: %w", err)
	}

	// Write the CA bundle to the trust store
	// The file must have .crt extension for update-ca-certificates to recognize it
	destPath := filepath.Join(caCertsDir, "trusted-platform-ca.crt")
	if err := os.WriteFile(destPath, caBundleData, 0644); err != nil {
		return fmt.Errorf("failed to write CA bundle: %w", err)
	}
	ai.logger.Info("[ALPINE] CA bundle copied to trust store", "path", "/usr/local/share/ca-certificates/trusted-platform-ca.crt")

	// Run update-ca-certificates to add the CA to the system trust store.
	// This requires chroot pseudo-filesystems (proc, sys, dev) which may not
	// be mounted since InstallBase cleans them up before ConfigureSystem runs.
	ai.logger.Info("[ALPINE] Setting up chroot for update-ca-certificates")
	if err := ai.setupChrootMounts(ctx, rootPath); err != nil {
		ai.logger.Warn("[ALPINE] Failed to setup chroot mounts for CA update", "error", err)
		// Don't fail - the CA file is in place, manual update can be done later
		return nil
	}
	defer ai.cleanupChrootMounts(rootPath)

	ai.logger.Info("[ALPINE] Running update-ca-certificates")
	cmd := exec.CommandContext(ctx, "chroot", rootPath, "update-ca-certificates")
	if output, err := cmd.CombinedOutput(); err != nil {
		ai.logger.Warn("[ALPINE] update-ca-certificates failed", "error", err, "output", string(output))
		// Don't fail - the CA file is in place, manual update can be done later
		return nil
	}

	ai.logger.Info("[ALPINE] CA bundle installed successfully to OS trust store")
	return nil
}

// setupChrootMounts mounts pseudo-filesystems required for chroot operations
// This is necessary for network connectivity inside chroot (apk add needs /proc, /sys, /dev)
func (ai *alpineInstaller) setupChrootMounts(ctx context.Context, rootPath string) error {
	ai.logger.Debug("[ALPINE] Mounting pseudo-filesystems for chroot")

	// Define mounts in order: proc, sysfs, devtmpfs (bind mount)
	mounts := []struct {
		fstype  string
		source  string
		target  string
		options string
	}{
		{"proc", "proc", filepath.Join(rootPath, "proc"), ""},
		{"sysfs", "sysfs", filepath.Join(rootPath, "sys"), ""},
		{"", "/dev", filepath.Join(rootPath, "dev"), "bind"},
	}

	for _, m := range mounts {
		// Create target directory if it doesn't exist
		if err := os.MkdirAll(m.target, 0755); err != nil {
			return fmt.Errorf("failed to create mount point %s: %w", m.target, err)
		}

		var mountCmd *exec.Cmd
		if m.options == "bind" {
			mountCmd = exec.CommandContext(ctx, "mount", "--bind", m.source, m.target)
		} else {
			mountCmd = exec.CommandContext(ctx, "mount", "-t", m.fstype, m.source, m.target)
		}

		if output, err := mountCmd.CombinedOutput(); err != nil {
			// Clean up any mounts we already made
			ai.cleanupChrootMounts(rootPath)
			return fmt.Errorf("failed to mount %s: %w (output: %s)", m.target, err, string(output))
		}
		ai.logger.Debug("[ALPINE] Mounted", "target", m.target)
	}

	ai.logger.Debug("[ALPINE] Pseudo-filesystems mounted successfully")
	return nil
}

// cleanupChrootMounts unmounts pseudo-filesystems in reverse order
func (ai *alpineInstaller) cleanupChrootMounts(rootPath string) {
	ai.logger.Debug("[ALPINE] Unmounting pseudo-filesystems")

	// Unmount in reverse order: dev, sys, proc
	targets := []string{
		filepath.Join(rootPath, "dev"),
		filepath.Join(rootPath, "sys"),
		filepath.Join(rootPath, "proc"),
	}

	for _, target := range targets {
		// Check if mounted before trying to unmount
		cmd := exec.Command("mountpoint", "-q", target)
		if err := cmd.Run(); err != nil {
			// Not mounted, skip
			continue
		}

		umountCmd := exec.Command("umount", "-l", target) // -l for lazy unmount to avoid busy errors
		if output, err := umountCmd.CombinedOutput(); err != nil {
			ai.logger.Warn("[ALPINE] Failed to unmount", "target", target, "error", err, "output", string(output))
		} else {
			ai.logger.Debug("[ALPINE] Unmounted", "target", target)
		}
	}
}
