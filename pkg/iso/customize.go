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
	"bytes"
	"context"
	"crypto/x509"
	"debug/elf"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/nbd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/runner"
	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
	storageluks "github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// Customizer handles ISO customization operations
type Customizer struct {
	config     *PlatformISOConfig
	overlayDir string
	logger     *logging.Logger

	// sbMediaSigning records, once applySecurityOverrides has run
	// (sbMediaSigningKnown), whether the FINALIZED baked config signs the
	// UKI with the media-staged DB material. A remote/KMS db ref needs no
	// local key staging — and must not have private signing keys embedded
	// in the ISO (#50).
	sbMediaSigning      bool
	sbMediaSigningKnown bool
	// sbMediaKeyFile and sbMediaCertFile are the exact filenames the baked
	// config's media db refs name (DB.key/DB.crt for the injected default),
	// so staging can verify the referenced files — not a hardcoded pair —
	// exist on the media.
	sbMediaKeyFile  string
	sbMediaCertFile string
	// sbEnforce records whether the finalized baked config carries
	// secure-boot.enforce: true. An enforcing build must stage the PK and
	// KEK enrollment certificates the installer will enroll
	// (resolveSecureBootEnrollCerts) — the installer warns past their
	// absence, so a build shipping without them would produce a node with
	// enforce requested and NO enforcement (round-9 review).
	sbEnforce bool
	// sbPKCertFile and sbKEKCertFile are the staged filenames the
	// installer will resolve the enrollment certificates from: the
	// baked pk/kek cert-uri media basenames, or the PK.crt/KEK.crt
	// convention the installer falls back to.
	sbPKCertFile  string
	sbKEKCertFile string
}

// NewCustomizer creates a new ISO customizer
func NewCustomizer(config *PlatformISOConfig, logger *logging.Logger) *Customizer {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &Customizer{
		config:     config,
		overlayDir: config.Directories.Overlay,
		logger:     logger,
	}
}

// CustomizeAll runs all customization steps in the correct order
func (c *Customizer) CustomizeAll(ctx context.Context) error {
	c.logger.Info("Starting complete ISO customization")

	// Check prerequisites
	if err := c.checkPrerequisites(); err != nil {
		return &WrappedError{Msg: "prerequisites check failed", Err: err}
	}

	if err := c.StageMedia(ctx); err != nil {
		return err
	}

	return c.customizeLiveISO(ctx)
}

// StageMedia lays down everything the installer reads from the install
// media root (/media/cdrom on the live system): the generated installer and
// initrd configuration, the pre-fetched apk repository, the platform
// binaries, the platform configuration and CA bundle, the dracut module,
// the Secure Boot keys, the FIPS artifacts and the web UI. It is the half
// of CustomizeAll that does not depend on the Alpine live ISO, so a disk
// image builder can call it directly and supply its own boot chain.
func (c *Customizer) StageMedia(ctx context.Context) error {
	// Generate configuration files
	c.logger.Info("Generating installation configuration")
	if err := c.GenerateInstallConfig(); err != nil {
		return &WrappedError{Msg: "failed to generate install config", Err: err}
	}

	// Pre-fetch APK packages for offline installation (if enabled)
	if c.config.Build.PreFetch {
		c.logger.Info("Pre-fetching APK packages for offline installation")
		if err := c.BuildPreFetchRepository(ctx); err != nil {
			return &WrappedError{Msg: "failed to pre-fetch packages", Err: err}
		}
	}

	// Copy platformd binary (single binary for all operations including boot, firstboot, install)
	if c.config.Platform.PlatformdBinary != "" {
		c.logger.Info("Copying platformd binary")
		if err := c.CopyPlatformdBinary(ctx, c.config.Platform.PlatformdBinary); err != nil {
			return &WrappedError{Msg: "failed to copy platformd binary", Err: err}
		}
	}

	// Copy the platformctl CLI binaries: the regular one is the installer's
	// entry point, the static one serves Alpine/musl. Each is installed only
	// when the build names it; a named binary that is missing fails the
	// build (#351). Neither is inferred from PlatformdBinary.
	if err := c.CopyPlatformctlBinary(ctx, c.config.Platform.PlatformctlBinary); err != nil {
		return &WrappedError{Msg: "failed to copy platformctl binary", Err: err}
	}
	if err := c.requireStaticInstaller(); err != nil {
		return err
	}
	if err := c.CopyPlatformctlStaticBinary(ctx, c.config.Platform.PlatformctlStaticBinary); err != nil {
		return &WrappedError{Msg: "failed to copy platformctl-static binary", Err: err}
	}

	// Copy platform-initrd binary for boot operations in initramfs (CRITICAL)
	// This binary is called by the dracut hook during boot to unlock LUKS
	platformInitrdBinary := ""
	if c.config.Platform.PlatformdBinary != "" {
		platformInitrdBinary = filepath.Join(filepath.Dir(c.config.Platform.PlatformdBinary), "platform-initrd")
	}
	if platformInitrdBinary != "" {
		c.logger.Info("Copying platform-initrd binary", "path", platformInitrdBinary)
		if err := c.CopyPlatformInitrdBinary(ctx, platformInitrdBinary); err != nil {
			// This is critical for boot - log the error but try to continue
			c.logger.Warn("Failed to copy platform-initrd binary", "error", err)
		}
	}

	// Copy gatewayd for gateway-role nodes (#66). Boot-critical when the
	// bundled platform config enables the gateway role; otherwise optional.
	gatewayRole, err := isoTargetsGatewayRole(c.config.Platform.ConfigFile)
	if err != nil {
		return &WrappedError{Msg: "failed to decide the ISO's gateway role", Err: err}
	}
	if err := c.CopyGatewaydBinary(ctx, gatewaydBinaryPath(c.config.Platform.PlatformdBinary), gatewayRole); err != nil {
		return &WrappedError{Msg: "failed to copy gatewayd binary", Err: err}
	}

	// Copy platform configuration file (for TPM keystore SRK handle 0x81000002)
	// Platform config is REQUIRED - it must contain seal-pcrs for TPM sealing
	c.logger.Info("Bundling platform configuration")
	if err := c.CopyPlatformConfig(ctx, c.config.Platform.ConfigFile); err != nil {
		return &WrappedError{Msg: "failed to bundle platform config", Err: err}
	}

	// Copy CA bundle for client trust store (secure delivery via ISO)
	if c.config.Platform.CABundlePath != "" {
		c.logger.Info("Bundling CA certificate bundle")
		if err := c.CopyCABundle(ctx, c.config.Platform.CABundlePath); err != nil {
			c.logger.Warn("Failed to bundle CA certificate", "error", err)
		}
	}

	// Copy objcopy binary if specified
	if c.config.Platform.ObjcopyBinary != "" && c.config.Platform.ObjcopyBinary != "objcopy" {
		c.logger.Info("Copying objcopy binary")
		if err := c.copyObjcopyBinary(ctx, c.config.Platform.ObjcopyBinary); err != nil {
			// Log warning but don't fail - objcopy is optional
			c.logger.Warn("Failed to copy objcopy binary", "error", err)
		}
	}

	// Copy dracut module to ISO for installation
	c.logger.Info("Copying dracut module to ISO")
	if err := c.CopyDracutModule(ctx); err != nil {
		return &WrappedError{Msg: "failed to copy dracut module", Err: err}
	}

	// Copy Secure Boot keys to ISO overlay
	c.logger.Info("Copying Secure Boot keys to ISO overlay")
	if err := c.CopySecureBootKeys(ctx); err != nil {
		return &WrappedError{Msg: "failed to copy Secure Boot keys", Err: err}
	}

	// Copy pre-built FIPS artifacts to ISO
	if c.config.Security.FIPS {
		c.logger.Info("Copying pre-built FIPS artifacts to ISO")
		if err := c.CopyFIPSArtifacts(ctx); err != nil {
			return &WrappedError{Msg: "failed to copy FIPS artifacts", Err: err}
		}
	}

	// Copy WebUI to ISO for installation
	if c.config.Platform.WebUIPath != "" {
		c.logger.Info("Copying WebUI to ISO")
		if err := c.CopyWebUI(ctx, c.config.Platform.WebUIPath); err != nil {
			return &WrappedError{Msg: "failed to copy WebUI", Err: err}
		}
	}

	return nil
}

// customizeLiveISO is the Alpine-live-ISO-specific half of CustomizeAll:
// the initramfs surgery that boots straight into the autoinstaller, the
// standalone autoinstall script and the GRUB/EFI bootloader rewrite.
func (c *Customizer) customizeLiveISO(ctx context.Context) error {
	// Modify initramfs:
	//   - Inject the platformd dracut module (existing behavior)
	//   - Create the autoinstall overlay (inittab + autoinstall.sh +
	//     run-autoinstall.sh) under /overlay in the initramfs root
	//   - Patch Alpine's /init script so that, when the kernel cmdline
	//     carries alpine_start=autoinstall, the overlay files are copied
	//     to the switched-root filesystem before /sbin/init starts. The
	//     custom inittab then takes over with BusyBox init running
	//     run-autoinstall.sh as a sysinit entry — no OpenRC, no apkovl.
	c.logger.Info("Modifying initramfs")
	if err := c.ModifyInitramfs(ctx); err != nil {
		return &WrappedError{Msg: "failed to modify initramfs", Err: err}
	}

	// Generate autoinstall script (standalone copy for debugging)
	c.logger.Info("Generating autoinstall script")
	if err := c.GenerateAutoinstallScript(ctx); err != nil {
		return &WrappedError{Msg: "failed to generate autoinstall script", Err: err}
	}

	// Configure bootloader
	c.logger.Info("Configuring bootloader")
	if err := c.ConfigureBootloader(ctx); err != nil {
		return &WrappedError{Msg: "failed to configure bootloader", Err: err}
	}

	// Clean up temporary files
	c.logger.Info("Cleaning up temporary files")
	if err := c.cleanup(); err != nil {
		c.logger.Warn("Failed to clean up temporary files", "error", err)
	}

	c.logger.Info("ISO customization completed successfully")
	return nil
}

// ModifyInitramfs extracts, modifies, and repacks the initramfs with platformd
func (c *Customizer) ModifyInitramfs(ctx context.Context) error {
	c.logger.Info("Modifying initramfs with platformd dracut module")

	// Find initramfs in ISO
	initramfsPath, err := c.findInitramfs()
	if err != nil {
		return &WrappedError{Msg: "failed to find initramfs", Err: err}
	}
	c.logger.Debug("Found initramfs", "path", initramfsPath)

	// Create temporary directory for extraction
	tmpDir := filepath.Join(c.config.Directories.Work, "initramfs-tmp")
	if err := os.RemoveAll(tmpDir); err != nil {
		return &WrappedError{Msg: "failed to remove old initramfs temp dir", Err: err}
	}
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create initramfs temp dir", Err: err}
	}

	// Extract initramfs
	c.logger.Info("Extracting initramfs")
	if err := extractInitramfs(initramfsPath, tmpDir); err != nil {
		return &WrappedError{Msg: "failed to extract initramfs", Err: err}
	}

	// Create dracut module structure
	c.logger.Info("Creating dracut module structure")
	if err := c.createDracutModule(tmpDir); err != nil {
		return &WrappedError{Msg: "failed to create dracut module", Err: err}
	}

	// Make it the installer's initramfs: the autoinstall overlay and the
	// Alpine /init patches (see makeInstallerInitramfs).
	if err := c.makeInstallerInitramfs(tmpDir); err != nil {
		return err
	}

	// Inject NIC kernel drivers into the initramfs. PXE-booted nodes have no
	// CD and cannot fetch the modloop squashfs until networking is up, but the
	// NIC drivers needed to bring networking up live inside that very modloop —
	// a boot-time deadlock. injectNetworkModules breaks it by pre-staging the
	// drivers (plus their dependency closure) from the local modloop into the
	// initramfs and running depmod so the kernel autoloads the NIC by PCI alias
	// before ip=dhcp runs. See injectNetworkModules for the full rationale.
	c.logger.Info("Injecting NIC kernel modules into initramfs")
	if err := c.injectNetworkModules(ctx, tmpDir); err != nil {
		return &WrappedError{Msg: "failed to inject network modules", Err: err}
	}

	// Inject the busybox udhcpc default.script. Alpine's ISO initramfs-lts is
	// built for CD/USB installs and omits udhcpc's apply-script, so PXE DHCP
	// obtains a lease but never puts the IP on the interface (configure_ip's
	// `[ ! -e default.script ]` guard fails) -> no network -> emergency shell.
	c.logger.Info("Injecting udhcpc default.script")
	if err := c.injectUdhcpcScript(ctx, tmpDir); err != nil {
		return &WrappedError{Msg: "failed to inject udhcpc script", Err: err}
	}

	// Repack initramfs
	c.logger.Info("Repacking initramfs")
	if err := repackInitramfs(tmpDir, initramfsPath); err != nil {
		return &WrappedError{Msg: "failed to repack initramfs", Err: err}
	}

	// Verify repacked initramfs
	c.logger.Info("Verifying repacked initramfs")
	if err := c.verifyInitramfs(initramfsPath); err != nil {
		return &WrappedError{Msg: "failed to verify initramfs", Err: err}
	}

	c.logger.Info("Initramfs modification completed successfully")
	return nil
}

// makeInstallerInitramfs turns an extracted Alpine live initramfs into the
// installer's, the part every medium's initramfs shares:
//   - the /overlay directory the patched /init copies into the switched-root
//     filesystem before exec'ing /sbin/init: a custom BusyBox inittab that
//     runs run-autoinstall.sh as sysinit then powers off, the autoinstall
//     script (buildAutoinstallScript) and its run-autoinstall.sh wrapper,
//     which mounts /proc /sys /dev and the modloop, loads kernel modules and
//     brings networking up (OpenRC is bypassed) before chaining to it;
//   - Alpine's /init patched to copy /overlay into $sysroot when the kernel
//     cmdline carries alpine_start=autoinstall (without the marker the normal
//     live flow runs untouched);
//   - configure_ip() patched to try DHCP on every carrier-up NIC.
func (c *Customizer) makeInstallerInitramfs(initramfsDir string) error {
	c.logger.Info("Creating autoinstall overlay")
	if err := c.createAutoinstallOverlay(initramfsDir); err != nil {
		return &WrappedError{Msg: "failed to create autoinstall overlay", Err: err}
	}
	c.logger.Info("Patching Alpine init script")
	if err := c.patchInitScript(initramfsDir); err != nil {
		return &WrappedError{Msg: "failed to patch init script", Err: err}
	}
	// Bare-metal igb/ixgbe NICs take a few seconds to negotiate carrier;
	// Alpine brings the link up and immediately runs udhcpc, which broadcasts
	// before the link is ready, gets no lease, and the modloop fetch then
	// fails -> emergency shell. See patchConfigureIPCarrierWait.
	c.logger.Info("Patching Alpine configure_ip for carrier wait")
	if err := c.patchConfigureIPCarrierWait(initramfsDir); err != nil {
		return &WrappedError{Msg: "failed to patch configure_ip carrier wait", Err: err}
	}
	return nil
}

// InstallerInitramfs rewrites a netboot release's initramfs at path as the
// installer's (makeInstallerInitramfs), with this media's autoinstall. It
// adds only that: unlike the ISO's CD-flavour initramfs, a netboot initramfs
// (mkinitfs's network feature) already carries the NIC drivers and udhcpc's
// default.script, and the platformd dracut module belongs to the installed
// system's initramfs, not the live one.
func (c *Customizer) InstallerInitramfs(ctx context.Context, path string) error {
	tmpDir := filepath.Join(c.config.Directories.Work, "netboot-initramfs-tmp")
	if err := os.RemoveAll(tmpDir); err != nil {
		return &WrappedError{Msg: "failed to remove old initramfs temp dir", Err: err}
	}
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create initramfs temp dir", Err: err}
	}
	if err := extractInitramfs(path, tmpDir); err != nil {
		return &WrappedError{Msg: "failed to extract initramfs", Err: err}
	}
	if err := c.makeInstallerInitramfs(tmpDir); err != nil {
		return err
	}
	if err := repackInitramfs(tmpDir, path); err != nil {
		return &WrappedError{Msg: "failed to repack initramfs", Err: err}
	}
	if err := os.RemoveAll(tmpDir); err != nil {
		return &WrappedError{Msg: "failed to remove initramfs temp dir", Err: err}
	}
	if err := c.verifyInitramfs(path); err != nil {
		return &WrappedError{Msg: "failed to verify initramfs", Err: err}
	}
	return nil
}

// CopyPlatformBinary copies the platformd binary to the ISO
func (c *Customizer) CopyPlatformBinary(ctx context.Context, binaryPath string) error {
	c.logger.Info("Copying platformd binary", "source", binaryPath)

	// Validate binary
	if err := c.validateTargetBinary(binaryPath); err != nil {
		return &WrappedError{Msg: "binary validation failed", Err: err}
	}

	// Create destination directory
	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create destination directory", Err: err}
	}

	// Copy binary
	destPath := filepath.Join(destDir, "platformd")
	if err := copyFile(binaryPath, destPath); err != nil {
		return &WrappedError{Msg: "failed to copy binary", Err: err}
	}

	// Set executable permissions
	if err := os.Chmod(destPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to set executable permissions", Err: err}
	}

	// Calculate and log checksum
	checksum, err := calculateSHA256(destPath)
	if err != nil {
		c.logger.Warn("Failed to calculate checksum", "error", err)
	} else {
		c.logger.Info("Binary copied successfully",
			"destination", destPath,
			"sha256", checksum)
	}

	// Also copy to overlay for installed system
	overlayBinDir := filepath.Join(c.overlayDir, "usr", "bin")
	if err := os.MkdirAll(overlayBinDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create overlay bin directory", Err: err}
	}

	overlayPath := filepath.Join(overlayBinDir, "platformd")
	if err := copyFile(binaryPath, overlayPath); err != nil {
		return &WrappedError{Msg: "failed to copy binary to overlay", Err: err}
	}

	if err := os.Chmod(overlayPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to set overlay binary permissions", Err: err}
	}

	c.logger.Debug("Binary also copied to overlay", "path", overlayPath)
	return nil
}

// CopyPlatformdBinary copies the platformd binary to the ISO for installation
func (c *Customizer) CopyPlatformdBinary(ctx context.Context, binaryPath string) error {
	c.logger.Info("Copying platformd binary", "source", binaryPath)

	// Validate binary
	if err := c.validateTargetBinary(binaryPath); err != nil {
		return &WrappedError{Msg: "binary validation failed", Err: err}
	}

	// Create destination directory
	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create destination directory", Err: err}
	}

	// Copy binary
	destPath := filepath.Join(destDir, "platformd")
	if err := copyFile(binaryPath, destPath); err != nil {
		return &WrappedError{Msg: "failed to copy binary", Err: err}
	}

	// Set executable permissions
	if err := os.Chmod(destPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to set executable permissions", Err: err}
	}

	// Calculate and log checksum
	checksum, err := calculateSHA256(destPath)
	if err != nil {
		c.logger.Warn("Failed to calculate checksum", "error", err)
	} else {
		c.logger.Info("Platformd binary copied successfully",
			"destination", destPath,
			"sha256", checksum)
	}

	return nil
}

// CopyPlatformctlBinary copies the platformctl CLI binary to the ISO for installation.
// This is optional - if not provided, only platformd will be installed.
func (c *Customizer) CopyPlatformctlBinary(ctx context.Context, binaryPath string) error {
	if binaryPath == "" {
		c.logger.Debug("No platformctl binary specified, skipping")
		return c.removeStagedBinary("platformctl")
	}

	c.logger.Info("Copying platformctl binary", "source", binaryPath)

	// Validate binary exists
	if _, err := os.Stat(binaryPath); err != nil {
		return &MissingInputError{Input: "platformctl binary", Path: binaryPath, Err: err}
	}

	// Validate binary
	if err := c.validateTargetBinary(binaryPath); err != nil {
		return &WrappedError{Msg: "platformctl binary validation failed", Err: err}
	}

	// Create destination directory
	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create destination directory", Err: err}
	}

	// Copy binary
	destPath := filepath.Join(destDir, "platformctl")
	if err := copyFile(binaryPath, destPath); err != nil {
		return &WrappedError{Msg: "failed to copy platformctl binary", Err: err}
	}

	// Set executable permissions
	if err := os.Chmod(destPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to set executable permissions", Err: err}
	}

	// Calculate and log checksum
	checksum, err := calculateSHA256(destPath)
	if err != nil {
		c.logger.Warn("Failed to calculate checksum", "error", err)
	} else {
		c.logger.Info("Platformctl binary copied successfully",
			"destination", destPath,
			"sha256", checksum)
	}

	return nil
}

// requireStaticInstaller rejects a dynamically linked platformctl when the
// build supplies no platformctl-static: the Alpine autoinstall script then
// runs the regular platformctl (buildAutoinstallScript), and a glibc binary
// has no loader or libraries on Alpine's musl userland. The staged copy is
// removed so a failed build leaves no unrunnable installer behind.
func (c *Customizer) requireStaticInstaller() error {
	platform := c.config.Platform
	if platform.PlatformctlStaticBinary != "" || platform.PlatformctlBinary == "" {
		return nil
	}
	if err := validateStaticBinary(platform.PlatformctlBinary); err != nil {
		if removeErr := c.removeStagedBinary("platformctl"); removeErr != nil {
			return removeErr
		}
		return err
	}
	return nil
}

// CopyPlatformctlStaticBinary copies the static platformctl CLI binary to the ISO for installation.
// The static binary is required for Alpine Linux which uses musl libc (incompatible with glibc).
func (c *Customizer) CopyPlatformctlStaticBinary(ctx context.Context, binaryPath string) error {
	if binaryPath == "" {
		c.logger.Debug("No platformctl-static binary specified, skipping")
		return c.removeStagedBinary("platformctl-static")
	}

	c.logger.Info("Copying platformctl-static binary", "source", binaryPath)

	// Validate binary exists
	if _, err := os.Stat(binaryPath); err != nil {
		return &MissingInputError{Input: "platformctl-static binary", Path: binaryPath, Err: err}
	}

	// Validate binary
	if err := c.validateTargetBinary(binaryPath); err != nil {
		return &WrappedError{Msg: "platformctl-static binary validation failed", Err: err}
	}
	if err := validateStaticBinary(binaryPath); err != nil {
		return err
	}

	// Create destination directory
	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create destination directory", Err: err}
	}

	// Copy binary
	destPath := filepath.Join(destDir, "platformctl-static")
	if err := copyFile(binaryPath, destPath); err != nil {
		return &WrappedError{Msg: "failed to copy platformctl-static binary", Err: err}
	}

	// Set executable permissions
	if err := os.Chmod(destPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to set executable permissions", Err: err}
	}

	// Calculate and log checksum
	checksum, err := calculateSHA256(destPath)
	if err != nil {
		c.logger.Warn("Failed to calculate checksum", "error", err)
	} else {
		c.logger.Info("Platformctl-static binary copied successfully",
			"destination", destPath,
			"sha256", checksum)
	}

	return nil
}

// removeStagedBinary removes platformd-bin/name from the media tree. An
// unset optional input is not installed, and a tree customized again must
// not keep the copy an earlier run staged (#1152).
func (c *Customizer) removeStagedBinary(name string) error {
	path := filepath.Join(c.config.Directories.ISO, "platformd-bin", name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return &WrappedError{Msg: "failed to remove stale " + name + " binary", Err: err}
	}
	return nil
}

// CopyPlatformInitrdBinary copies the platform-initrd binary to the ISO and overlay.
// This binary is CRITICAL for boot - it's called by dracut hooks to unlock LUKS.
// The binary must be in /usr/bin/platform-initrd in the initramfs.
func (c *Customizer) CopyPlatformInitrdBinary(ctx context.Context, binaryPath string) error {
	if binaryPath == "" {
		c.logger.Debug("No platform-initrd binary specified, skipping")
		return nil
	}

	c.logger.Info("Copying platform-initrd binary", "source", binaryPath)

	// Absence is fatal, not a warning.
	//
	// This line used to Warn and return nil. That made the ABSENCE indetectable
	// by the caller — its `if err != nil` branch could only ever fire on a
	// validation failure — so `iso create` exited 0 and shipped a 792 MB ISO
	// whose autoinstall died at the platform-initrd step, an hour later, inside
	// a VM (#48).
	//
	// platform-initrd is what dracut calls to unlock LUKS at boot. No
	// configuration makes an installer ISO without it useful, so this does not
	// depend on what the caller asked for.
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		return ErrBootCriticalBinaryMissing("platform-initrd", binaryPath,
			"build it with `make platform-initrd` (it is a separate target from `make build`)")
	}

	// Validate binary
	if err := c.validateTargetBinary(binaryPath); err != nil {
		return &WrappedError{Msg: "platform-initrd binary validation failed", Err: err}
	}

	// Create destination directory on ISO
	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create destination directory", Err: err}
	}

	// Copy binary to ISO
	destPath := filepath.Join(destDir, "platform-initrd")
	if err := copyFile(binaryPath, destPath); err != nil {
		return &WrappedError{Msg: "failed to copy platform-initrd binary", Err: err}
	}

	// Set executable permissions
	if err := os.Chmod(destPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to set executable permissions", Err: err}
	}

	c.logger.Debug("Platform-initrd binary copied to ISO", "path", destPath)

	// CRITICAL: Also copy to overlay for installed system
	// This ensures the binary is available in /usr/bin/platform-initrd after installation
	// The dracut hook calls /usr/bin/platform-initrd during boot
	overlayBinDir := filepath.Join(c.overlayDir, "usr", "bin")
	if err := os.MkdirAll(overlayBinDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create overlay bin directory", Err: err}
	}

	overlayPath := filepath.Join(overlayBinDir, "platform-initrd")
	if err := copyFile(binaryPath, overlayPath); err != nil {
		return &WrappedError{Msg: "failed to copy platform-initrd binary to overlay", Err: err}
	}

	if err := os.Chmod(overlayPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to set overlay binary permissions", Err: err}
	}

	c.logger.Debug("Platform-initrd binary also copied to overlay", "path", overlayPath)

	// Calculate and log checksum
	checksum, err := calculateSHA256(destPath)
	if err != nil {
		c.logger.Warn("Failed to calculate checksum", "error", err)
	} else {
		c.logger.Info("Platform-initrd binary copied successfully",
			"destination", destPath,
			"sha256", checksum)
	}

	return nil
}

// CopyPlatformConfig copies the platformd.yaml configuration file to the ISO
// This config file is used by platformd binaries for consistent TPM configuration.
// The config MUST exist and MUST contain seal-pcrs for TPM sealing.
func (c *Customizer) CopyPlatformConfig(ctx context.Context, configPath string) error {
	c.logger.Info("Copying platform configuration file", "source", configPath)

	// In dynamic config mode, skip embedding config - the device will fetch
	// its config from the server at boot time via kernel cmdline params.
	if configPath == "" && c.config.Platform.ConfigServerURL != "" {
		c.logger.Info("Dynamic config mode: skipping config embed, device will fetch from server",
			"server", c.config.Platform.ConfigServerURL)
		return nil
	}

	// Platform config is REQUIRED when not in dynamic config mode
	if configPath == "" {
		return ErrPlatformConfigRequired()
	}

	// Validate config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return ErrPlatformConfigNotFound(configPath)
	}

	// Read config file
	srcData, err := os.ReadFile(configPath)
	if err != nil {
		return ErrPlatformConfigRead(configPath, err)
	}

	// Validate config contains seal-pcrs (required for TPM sealing)
	if !bytes.Contains(srcData, []byte("seal-pcrs:")) {
		return ErrPlatformConfigMissingSealPCRs(configPath)
	}

	// Create configs directory in ISO
	destDir := filepath.Join(c.config.Directories.ISO, "configs")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return ErrConfigDirCreate(destDir, err)
	}
	// Apply runtime security flag overrides (FIPS, FIDO2, lockdown)
	// These come from ISO build flags and may override what's in the config file
	// Fail closed: shipping the original config after a failed override
	// would silently drop the build's security posture (FIPS, lockdown,
	// Secure Boot coherence) from the baked artifact.
	modifiedData, err := c.applySecurityOverrides(srcData)
	if err != nil {
		return &WrappedError{Msg: "failed to apply security overrides to platform config", Err: err}
	}
	modifiedData, err = c.applyInstallerOverrides(modifiedData)
	if err != nil {
		return &WrappedError{Msg: "failed to apply installer overrides to platform config", Err: err}
	}

	// Use installer.yaml as the single source of truth for autoinstall.sh
	configFilename := "installer.yaml"

	// Copy config file to ISO
	destPath := filepath.Join(destDir, configFilename)
	if err := os.WriteFile(destPath, modifiedData, 0644); err != nil {
		return ErrPlatformConfigWrite(destPath, err)
	}

	c.logger.Info("Platform config copied successfully",
		"source", configPath,
		"destination", destPath,
		"size", len(srcData))

	return nil
}

// CopyCABundle copies the CA certificate bundle to the ISO for installation
// into the client's OS trust store. This is the secure way to establish trust
// between client and server - the CA cert is delivered via the same trusted
// channel as the installer itself (the ISO).
func (c *Customizer) CopyCABundle(ctx context.Context, bundlePath string) error {
	if bundlePath == "" {
		c.logger.Debug("No CA bundle path specified, skipping")
		return nil
	}

	c.logger.Info("Copying CA bundle to ISO", "source", bundlePath)

	// Validate bundle file exists
	if _, err := os.Stat(bundlePath); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("CA bundle not found: %s", bundlePath)}
	}

	// Create configs directory in ISO
	destDir := filepath.Join(c.config.Directories.ISO, "configs")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create configs directory", Err: err}
	}

	// Copy bundle file
	destPath := filepath.Join(destDir, "ca-bundle.pem")
	srcData, err := os.ReadFile(bundlePath)
	if err != nil {
		return &WrappedError{Msg: "failed to read CA bundle", Err: err}
	}

	if err := os.WriteFile(destPath, srcData, 0644); err != nil {
		return &WrappedError{Msg: "failed to write CA bundle", Err: err}
	}

	c.logger.Info("CA bundle copied successfully",
		"source", bundlePath,
		"destination", destPath)

	return nil
}

// hasFoldPrefix reports whether s starts with prefix, comparing the prefix
// case-insensitively (URI schemes are case-insensitive; paths are not).
func hasFoldPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// mediaSigningEnabled reports whether this build signs boot artifacts with a
// DB key staged on the media.
//
// Conservative before applySecurityOverrides has run: with the finalized
// config not yet known, a Secure Boot build is assumed to be media-signing,
// so the key requirement fails closed rather than open.
//
// Extracted so CopySecureBootKeys (which fails the build when the key
// material is absent) and signISOBootloader (which needs that material) ask
// exactly the same question. Two copies of this expression that drifted apart
// would produce a build that demands keys and then does not use them, or
// worse, the reverse.
func (c *Customizer) mediaSigningEnabled() bool {
	return c.config.Security.SecureBoot && (!c.sbMediaSigningKnown || c.sbMediaSigning)
}

// SecureBootRemoteSigning reports whether the platform configuration at
// configPath carries a secure-boot db signing reference classified as
// remote/KMS. The ISO orchestration consults this BEFORE its key-generation
// step: a remote-signing build's contract is that no local private signing
// key is needed — or produced — so generation must never run for it
// (round-16 review). A config without a secure-boot db section reports
// false: the security override injects the media-staged default there, and
// media signing legitimately generates local keys. A db reference the
// installer could never resolve is a typed error, the same one the
// override pass would raise later.
func SecureBootRemoteSigning(configPath string) (bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false, &WrappedError{Msg: "failed to read platform config for secure-boot classification", Err: err}
	}
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return false, &WrappedError{Msg: "failed to parse platform config for secure-boot classification", Err: err}
	}
	sb, _ := config["secure-boot"].(map[interface{}]interface{})
	if sb == nil {
		return false, nil
	}
	db, _ := sb["db"].(map[interface{}]interface{})
	if db == nil {
		return false, nil
	}
	keyURI, _ := db["key-uri"].(string)
	certURI, _ := db["cert-uri"].(string)
	keyFile, _, err := classifySecureBootDBRef(keyURI, certURI)
	if err != nil {
		return false, err
	}
	return keyFile == "", nil
}

// pathsOverlap reports whether a and b resolve to the same filesystem
// location OR one contains the other, following symlinks when the paths
// exist and comparing absolute cleaned paths otherwise. Either direction
// of containment is an overlap: replacing a directory that holds the
// source destroys the source, and replacing a directory the source holds
// destroys part of it (round-14 review).
func pathsOverlap(a, b string) bool {
	resolve := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			p = real
		}
		return filepath.Clean(p)
	}
	ra, rb := resolve(a), resolve(b)
	contains := func(parent, child string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	return contains(ra, rb) || contains(rb, ra)
}

// secureBootMediaFileName returns the filename a file:// URI names directly
// under SecureBootKeysMediaDir, reporting false for any other reference.
func secureBootMediaFileName(uri string) (string, bool) {
	if !hasFoldPrefix(uri, "file://") {
		return "", false
	}
	path := uri[len("file://"):]
	if !strings.HasPrefix(path, SecureBootKeysMediaDir+"/") {
		return "", false
	}
	return strings.TrimPrefix(path, SecureBootKeysMediaDir+"/"), true
}

// classifySecureBootDBRef validates the db signing reference of a Secure
// Boot-enabled baked config against the same rules the installer enforces:
// SecureBootConfig.Validate requires only db.key-uri (kms:// or file://,
// schemes case-insensitive) and permits an omitted cert-uri — the installer
// derives the sibling DB.crt beside a file:// key
// (loadFileURISecureBootSigner), and a kms:// signer obtains the
// certificate with the signature. It returns the media-staged filenames
// when the reference points at the install media (empty strings for a
// kms:// remote pair), and a typed error for a reference the installer
// could never resolve: a missing key half, a mixed media/remote pair, an
// unsupported scheme, a file:// path outside the install media (nothing
// guarantees it exists in the live environment), or a media reference that
// is not a plain filename directly under SecureBootKeysMediaDir.
func classifySecureBootDBRef(keyURI, certURI string) (keyFile, certFile string, err error) {
	keyURI = strings.TrimSpace(keyURI)
	certURI = strings.TrimSpace(certURI)
	if keyURI == "" {
		return "", "", &MessageError{Msg: "secure-boot.db must carry key-uri when Secure Boot is enabled"}
	}

	keyName, keyIsMedia := secureBootMediaFileName(keyURI)
	certName, certIsMedia := secureBootMediaFileName(certURI)
	if certURI == "" {
		// Omitted cert-uri follows the key: the sibling DB.crt on the
		// media, or nothing for a remote signer.
		certIsMedia = keyIsMedia
		if keyIsMedia {
			certName = "DB.crt"
		}
	}
	if keyIsMedia != certIsMedia {
		return "", "", &MessageError{Msg: "secure-boot.db key-uri and cert-uri must both reference the install media or both a remote signer"}
	}
	if !keyIsMedia {
		if hasFoldPrefix(keyURI, "file://") || hasFoldPrefix(certURI, "file://") {
			return "", "", &MessageError{Msg: "secure-boot.db file:// references must point under " + SecureBootKeysMediaDir + " — other local paths do not exist in the install environment"}
		}
		// The installer supports only kms:// and file:// references; any
		// other scheme would pass the build and then deterministically
		// fail SecureBootConfig.Validate on the target.
		if !hasFoldPrefix(keyURI, "kms://") || (certURI != "" && !hasFoldPrefix(certURI, "kms://")) {
			return "", "", &MessageError{Msg: "secure-boot.db remote references must use the kms:// scheme — the installer supports only kms:// and file:// URIs"}
		}
		return "", "", nil
	}

	keyFile = keyName
	certFile = certName
	for _, name := range []string{keyFile, certFile} {
		if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
			return "", "", &MessageError{Msg: "secure-boot.db media reference must name a file directly under " + SecureBootKeysMediaDir + ", got: " + name}
		}
	}
	return keyFile, certFile, nil
}

// applySecurityOverrides applies runtime flag overrides to the platform config YAML.
// This handles ISO build flags (--fips, --fido2, --lockdown) that may override
// values in the platform config file.
func (c *Customizer) applySecurityOverrides(data []byte) ([]byte, error) {
	// Parse YAML into a generic map to preserve all fields
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, &WrappedError{Msg: "failed to parse installer config YAML", Err: err}
	}

	// Apply FIDO2 override from runtime flag
	if osConfig, ok := config["os"].(map[interface{}]interface{}); ok {
		osConfig["enable-fido2"] = c.config.Security.EnableFIDO2
		c.logger.Debug("Applied enable-fido2 override", "value", c.config.Security.EnableFIDO2)
	}

	// Apply other security overrides if set
	if osConfig, ok := config["os"].(map[interface{}]interface{}); ok {
		// FIPS override
		if c.config.Security.FIPS {
			osConfig["fips"] = true
			c.logger.Debug("Applied fips override", "value", true)
		}
		// Lockdown override
		if c.config.Security.Lockdown {
			osConfig["lockdown"] = true
			if c.config.Security.LockdownMode != "" {
				osConfig["lockdown-mode"] = c.config.Security.LockdownMode
			}
			c.logger.Debug("Applied lockdown override", "value", true, "mode", c.config.Security.LockdownMode)
		}
	}

	// Apply FIPS PBKDF override to disk encryption config
	// FIPS 140-3 does not approve Argon2id, so PBKDF2 must be used
	if c.config.Security.FIPS {
		if diskConfig, ok := config["disk"].(map[interface{}]interface{}); ok {
			if encConfig, ok := diskConfig["encryption"].(map[interface{}]interface{}); ok {
				encConfig["pbkdf"] = "pbkdf2"
				c.logger.Debug("Applied FIPS pbkdf override", "value", "pbkdf2")
			}
		}
	}

	// Apply TPM sealing override
	if c.config.Security.TPM.AutoUnseal {
		config["enable-tpm-sealing"] = true
		c.logger.Debug("Applied enable-tpm-sealing override", "value", true)
	}

	// Secure Boot coherence (#50): the ISO build's --secure-boot flag is
	// the single source of truth. Building with keys generated and
	// enrolled while the baked config leaves secure-boot.enabled unset
	// ships an UNSIGNED UKI that enforcing firmware rejects — the
	// mismatch only surfaces as a boot failure on the target. The
	// override forces the baked config to agree in BOTH directions.
	sbSection, _ := config["secure-boot"].(map[interface{}]interface{})
	c.sbMediaSigningKnown = true
	c.sbMediaSigning = false
	c.sbEnforce = false
	if c.config.Security.SecureBoot {
		if sbSection == nil {
			sbSection = map[interface{}]interface{}{}
			config["secure-boot"] = sbSection
		}
		sbSection["enabled"] = true
		// An enforcing baked config must resolve its PK/KEK enrollment
		// certificates at install time — the installer warns past their
		// absence, so the BUILD is where a dangling reference must fail
		// (round-9 review). Resolve which staged filenames the installer
		// will look for: the baked cert-uri media basenames, the
		// PK.crt/KEK.crt fallback for an omitted or kms:// cert-uri, and
		// a hard build error for a file:// path outside the install
		// media, which cannot exist in the live install environment.
		c.sbEnforce, _ = sbSection["enforce"].(bool)
		c.sbPKCertFile, c.sbKEKCertFile = "PK.crt", "KEK.crt"
		if c.sbEnforce {
			for _, enroll := range []struct {
				section string
				dest    *string
			}{
				{"pk", &c.sbPKCertFile},
				{"kek", &c.sbKEKCertFile},
			} {
				m, _ := sbSection[enroll.section].(map[interface{}]interface{})

				// SecureBootConfig.Validate requires pk.key-uri and
				// kek.key-uri whenever enforce is set (kms:// or file://
				// scheme). The same config would deterministically fail
				// validation ON THE TARGET — surface it as a build error
				// instead (round-10 review).
				keyURI := ""
				if m != nil {
					keyURI, _ = m["key-uri"].(string)
					keyURI = strings.TrimSpace(keyURI)
				}
				if keyURI == "" {
					return nil, &MessageError{Msg: "secure-boot.enforce is set but " + enroll.section +
						".key-uri is missing — the installer's SecureBootConfig.Validate rejects this on the target"}
				}
				if !hasFoldPrefix(keyURI, "kms://") && !hasFoldPrefix(keyURI, "file://") {
					return nil, &MessageError{Msg: "secure-boot.enforce is set but " + enroll.section +
						".key-uri scheme must be kms:// or file://, got: " + keyURI}
				}

				uri := ""
				if m != nil {
					uri, _ = m["cert-uri"].(string)
					uri = strings.TrimSpace(uri)
				}
				if uri == "" || !hasFoldPrefix(uri, "file://") {
					// Omitted or remote: the installer falls back to the
					// staged convention name.
					continue
				}
				name, isMedia := secureBootMediaFileName(uri)
				if !isMedia || name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
					return nil, &MessageError{Msg: "secure-boot.enforce is set but " + enroll.section +
						".cert-uri names a file:// path outside " + SecureBootKeysMediaDir +
						" — the installer could never resolve it: " + uri}
				}
				*enroll.dest = name
			}
		}
		// Ensure a resolvable DB signing reference: default to the keys
		// staged on the install media (the build stages them when Secure
		// Boot is enabled) unless the config already carries one — an
		// existing remote/KMS ref is preserved and needs NO local keys. An
		// existing ref is VALIDATED, not trusted: an incomplete, mixed, or
		// non-media file:// pair would bake enabled: true over signing
		// material the installer can never resolve.
		if db, hasDB := sbSection["db"].(map[interface{}]interface{}); hasDB {
			keyURI, _ := db["key-uri"].(string)
			certURI, _ := db["cert-uri"].(string)
			keyFile, certFile, err := classifySecureBootDBRef(keyURI, certURI)
			if err != nil {
				return nil, err
			}
			c.sbMediaSigning = keyFile != ""
			c.sbMediaKeyFile = keyFile
			c.sbMediaCertFile = certFile
		} else {
			sbSection["resign-mode"] = "local"
			sbSection["db"] = map[interface{}]interface{}{
				"key-uri":  "file://" + SecureBootKeysMediaDir + "/DB.key",
				"cert-uri": "file://" + SecureBootKeysMediaDir + "/DB.crt",
			}
			c.sbMediaSigning = true
			c.sbMediaKeyFile = "DB.key"
			c.sbMediaCertFile = "DB.crt"
		}
		c.logger.Debug("Applied secure-boot override", "enabled", true, "media_signing", c.sbMediaSigning)
	} else if sbSection != nil {
		sbSection["enabled"] = false
		c.logger.Debug("Applied secure-boot override", "enabled", false)
	}

	// Marshal back to YAML
	modifiedData, err := yaml.Marshal(config)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to marshal modified config", Err: err}
	}

	return modifiedData, nil
}

// BuildPreFetchRepository downloads all required packages and creates a local APK repository
func (c *Customizer) BuildPreFetchRepository(ctx context.Context) error {
	prefetchConfig, err := c.preFetchConfig()
	if err != nil {
		return err
	}

	// Create pre-fetch builder
	builder := NewPreFetchBuilder(prefetchConfig, c.logger)

	// Build the local repository
	if err := builder.BuildLocalRepository(ctx); err != nil {
		return err
	}

	c.logger.Info("Pre-fetch repository created successfully",
		"location", filepath.Join(c.config.Directories.ISO, "apks"))

	return nil
}

// preFetchConfig derives the offline repository's package inputs from the
// ISO configuration, including the gateway role of the bundled platform
// config (#603).
func (c *Customizer) preFetchConfig() (*PreFetchConfig, error) {
	gatewayRole, err := isoTargetsGatewayRole(c.config.Platform.ConfigFile)
	if err != nil {
		return nil, err
	}

	// Extract Alpine version major.minor (e.g., "3.22.2" -> "3.22")
	version := c.config.Alpine.Version
	versionParts := strings.Split(version, ".")
	majorMinor := version
	if len(versionParts) >= 2 {
		majorMinor = fmt.Sprintf("%s.%s", versionParts[0], versionParts[1])
	}

	// Create PreFetchConfig from our PlatformISOConfig
	prefetchConfig := &PreFetchConfig{
		Mirror:         c.config.Alpine.Mirror,
		Version:        majorMinor, // Use major.minor for APK repos
		FullVersion:    version,    // Full version (e.g., 3.22.2) for release tarballs
		Architecture:   string(c.config.architecture()),
		KernelPackage:  c.config.Installer.KernelPackage,
		SkipKernel:     c.config.Installer.KernelArtifactsDir != "",
		WorkDir:        c.config.Directories.Work,
		ISODir:         c.config.Directories.ISO,
		FIPS:           c.config.Security.FIPS,
		EnableFIDO2:    c.config.Security.EnableFIDO2,
		FilesystemLVM:  c.config.RootFS.Type == "lvm",
		IMAEnabled:     false,
		ExtraPackages:  append([]string(nil), c.config.Installer.ExtraPackages...),
		GatewayRole:    gatewayRole,
		PlatformAPKDir: c.config.Installer.PlatformAPKDir,
	}

	// Check if mirror is empty and set default
	if prefetchConfig.Mirror == "" {
		prefetchConfig.Mirror = "https://dl-cdn.alpinelinux.org/alpine"
	}
	return prefetchConfig, nil
}

// Secure Boot key staging. The ISO embeds the PK/KEK/DB certificates and the
// DB keypair in ONE canonical location: <iso-root>/secure-boot-keys. During
// installation the Alpine live environment mounts the install media at
// /media/cdrom (USB and legacy mounts are probed by the installer's
// install-media loader), so SecureBootKeysMediaDir is the single source of
// truth for the file:// SecureBootKeyRef URIs written into the generated
// installer config. See docs/firmware/secure-boot.md.
const (
	// SecureBootKeysISODirName is the staging directory name at the ISO root.
	SecureBootKeysISODirName = "secure-boot-keys"

	// SecureBootKeysMediaDir is where the staged keys appear at install time
	// (the live ISO's primary install-media mount).
	SecureBootKeysMediaDir = "/media/cdrom/" + SecureBootKeysISODirName
)

// IsSecureBootPublicArtifact positively identifies data as the public
// enrollment artifact its filename claims: certificate files must parse as
// X.509 certificates (PEM or DER) and signature lists must be strictly
// valid EFI structures holding only public entries. Remote/KMS-signing
// builds stage ONLY positively identified artifacts — an extension check
// alone would embed a DER-encoded private key named DB.der.
//
// .auth (EFI_VARIABLE_AUTHENTICATION_2) files are NOT staged: their
// PKCS#7 SignedData carries unconstrained fields (EncryptedDigest,
// signer blobs) that structural parsing cannot prove free of smuggled
// secret bytes, and nothing in the install flow consumes staged .auth
// files — the installer constructs its own Setup-Mode authentication
// payloads from the staged certificates (round-12 review).
func IsSecureBootPublicArtifact(name string, data []byte) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".crt", ".cer", ".der":
		return parsesAsCertificates(data)
	case ".esl":
		return validSignatureList(data)
	}
	return false
}

// parsesAsCertificates reports whether data holds only X.509 certificates,
// as PEM CERTIFICATE blocks or raw (possibly concatenated) DER. The ENTIRE
// input must be certificate material: any non-certificate PEM block, and any
// leading, interstitial, or trailing non-whitespace bytes, disqualify the
// file — pem.Decode silently skips unrecognized bytes, so a certificate
// concatenated with raw DER private-key material would otherwise pass.
func parsesAsCertificates(data []byte) bool {
	rest := bytes.TrimSpace(data)
	if len(rest) == 0 {
		return false
	}

	if bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
		for {
			rest = bytes.TrimSpace(rest)
			if len(rest) == 0 {
				return true
			}
			if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
				return false
			}
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil || block.Type != "CERTIFICATE" {
				return false
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return false
			}
		}
	}

	// Raw DER: x509.ParseCertificates consumes the whole input or errors,
	// so trailing bytes cannot smuggle non-certificate material.
	certs, err := x509.ParseCertificates(data)
	return err == nil && len(certs) > 0
}

// validSignatureList strictly validates data as one or more
// EFI_SIGNATURE_LIST structures using the repository's UEFI parser
// (uefi.ParseSignatureLists — internally consistent sizes, full
// consumption, SignatureSize >= GUID), and then positively identifies
// every entry as public material: X.509 entries must parse as
// certificates, hash entries must be exactly their digest length, and any
// other signature type — or an empty list, whose "optional header" could
// carry arbitrary smuggled bytes — is rejected.
func validSignatureList(data []byte) bool {
	lists, err := uefi.ParseSignatureLists(data)
	if err != nil || len(lists) == 0 {
		return false
	}
	for _, list := range lists {
		if list.SignatureCount() == 0 || len(list.Header) > 0 {
			return false
		}
		switch {
		case list.IsX509():
			for _, sig := range list.Signatures {
				if _, certErr := x509.ParseCertificate(sig.Data); certErr != nil {
					return false
				}
			}
		case list.IsSHA256():
			for _, sig := range list.Signatures {
				if len(sig.Data) != 32 {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// CopySecureBootKeys copies Secure Boot keys to the ISO for installation.
// If keys don't exist, they are automatically generated.
// Keys are always embedded in the ISO regardless of the SecureBoot setting,
// making the ISO "Secure Boot ready" even when SecureBoot is not explicitly enabled.
func (c *Customizer) CopySecureBootKeys(ctx context.Context) error {
	c.logger.Info("Preparing Secure Boot keys for ISO")

	// The finalized baked config decides how strict staging must be: only
	// a config that signs with the media-staged DB material requires the
	// local keys (fail-closed then); a preserved remote/KMS db ref needs
	// no local private keys and MUST NOT have them embedded in the ISO.
	// When applySecurityOverrides has not run (standalone invocation),
	// conservatively assume media signing.
	mediaSigning := c.mediaSigningEnabled()
	// Private keys are omitted from the media for the explicit
	// remote/KMS-signing case and for a network-served medium (a netboot
	// media set), which never carries private key material and cannot sign
	// with media-staged keys at all. Otherwise an SB-off build keeps the
	// historical "Secure Boot ready" behavior of staging the full key set.
	servedPublicOnly := c.config.Security.PublicKeysOnly
	if servedPublicOnly && mediaSigning {
		return &MessageError{Msg: "a network-served medium cannot sign with media-staged Secure Boot keys: keep the DB key in the KMS (secure-boot.resign-mode: remote, kms:// references)"}
	}
	skipPrivateKeys := servedPublicOnly || (c.config.Security.SecureBoot && c.sbMediaSigningKnown && !c.sbMediaSigning)
	// An enforcing baked config makes staging fail-closed regardless of
	// where signing happens: the installer resolves the PK/KEK enrollment
	// certificates from the staged media and warns past their absence, so
	// an ISO built without them would report success while producing a
	// node with enforce requested and NO enforcement (round-9 review).
	enforcing := c.config.Security.SecureBoot && c.sbEnforce

	// Source keys directory
	keysDir := c.config.Directories.Keys
	if keysDir == "" {
		keysDir = filepath.Join(c.config.Directories.Work, "secure-boot-keys")
		c.config.Directories.Keys = keysDir
	}

	// Destination in ISO directory (accessible at SecureBootKeysMediaDir during installation)
	// The directory is REPLACED, never merged: the extracted base ISO tree
	// may already carry a secure-boot-keys directory (a previous build, a
	// repacked ISO), and merging would let a stale private key survive a
	// switch to remote/KMS signing — the staging allowlist only filters
	// what THIS build copies (round-11 review). Replacement runs before
	// any early return so no path leaves stale material behind, and it
	// must never destroy the SOURCE: a --keys-dir overlapping the staging
	// directory (either direction, symlinks resolved) is rejected before
	// anything is removed (rounds 13-14).
	destDir := filepath.Join(c.config.Directories.ISO, SecureBootKeysISODirName)
	if pathsOverlap(keysDir, destDir) {
		return &MessageError{Msg: "secure-boot keys directory (" + keysDir + ") and the ISO staging directory (" +
			destDir + ") overlap — staging replaces the destination, which would delete the source keys; " +
			"point --keys-dir somewhere outside the ISO tree"}
	}
	if err := os.RemoveAll(destDir); err != nil {
		return &WrappedError{Msg: "failed to clear stale secure-boot-keys directory in ISO", Err: err}
	}
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create secure-boot-keys directory in ISO", Err: err}
	}

	// Check if keys exist, generate if not. Fail closed when Secure Boot
	// is enabled (#50): the security override bakes media-staged DB
	// signing references into the config, so a build that warns past key
	// generation would ship secure-boot.enabled: true with DANGLING
	// file:// refs — the failure then surfaces as an unsigned or
	// unbootable UKI on the target instead of a build error here.
	//
	// Remote/KMS signing never RUNS generation: its contract is that no
	// local private signing key is needed — or produced. GenerateAll
	// would export PK.key/KEK.key/DB.key onto the build host even though
	// the ISO later omits them (round-15 review). Only pre-existing
	// public artifacts are staged; an enforcing remote build without its
	// PK/KEK enrollment certificates fails at the gate below.
	if skipPrivateKeys {
		c.logger.Info("Remote/KMS signing configured — skipping local Secure Boot key generation")
	} else if err := c.ensureSecureBootKeysExist(ctx, keysDir); err != nil {
		if mediaSigning || enforcing {
			return &WrappedError{Msg: "Secure Boot signing/enforcement configured but key generation/staging failed", Err: err}
		}
		c.logger.Warn("Failed to ensure Secure Boot keys exist", "error", err)
		// Continue without keys - the ISO will still be bootable without Secure Boot
		return nil
	}

	// Verify the source keys directory exists
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		if mediaSigning || enforcing {
			return &MessageError{Msg: "Secure Boot signing/enforcement configured but the keys directory is missing: " + keysDir}
		}
		c.logger.Warn("Secure Boot keys directory not found", "path", keysDir)
		return nil
	}

	// Copy all files from keys directory
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return &WrappedError{Msg: "failed to read keys directory", Err: err}
	}

	if len(entries) == 0 {
		if mediaSigning || enforcing {
			return &MessageError{Msg: "Secure Boot signing/enforcement configured but keys directory is empty: " + keysDir}
		}
		c.logger.Warn("Secure Boot keys directory is empty", "path", keysDir)
		return nil
	}

	filesCopied := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Remote/KMS signing needs no local private keys on the media —
		// and must not ship them; enrollment needs certificates only. This
		// is an ALLOWLIST of public artifacts: denying known private-key
		// suffixes would still embed material named DB.pem or signing.p8.
		srcPath := filepath.Join(keysDir, entry.Name())
		destPath := filepath.Join(destDir, entry.Name())

		// Remote/KMS signing stages ONLY positively identified public
		// enrollment artifacts — content-validated, since neither a
		// denylist nor an extension check proves a file holds no private
		// material.
		if skipPrivateKeys {
			data, readErr := os.ReadFile(srcPath)
			if readErr != nil || !IsSecureBootPublicArtifact(entry.Name(), data) {
				c.logger.Warn("Skipping artifact not identified as public enrollment material (remote/KMS signing configured)",
					"file", entry.Name())
				continue
			}
		}

		if err := copyFile(srcPath, destPath); err != nil {
			if mediaSigning {
				return &WrappedError{Msg: "Secure Boot media signing configured but key file copy failed: " + entry.Name(), Err: err}
			}
			c.logger.Warn("Failed to copy key file", "file", entry.Name(), "error", err)
			continue
		}

		c.logger.Debug("Copied key file", "file", entry.Name())
		filesCopied++
	}

	if filesCopied > 0 {
		c.logger.Info("Secure Boot keys copied successfully to ISO",
			"count", filesCopied,
			"destination", destDir)
	}

	// Verify the exact files the baked config's media db refs name exist on
	// the staged media, so the config can never reference signing material
	// the ISO does not carry — a custom.key ref is checked as custom.key,
	// not as the default pair.
	if mediaSigning {
		requiredKey, requiredCert := c.sbMediaKeyFile, c.sbMediaCertFile
		if requiredKey == "" || requiredCert == "" {
			requiredKey, requiredCert = "DB.key", "DB.crt"
		}
		for _, required := range []string{requiredKey, requiredCert} {
			if _, err := os.Stat(filepath.Join(destDir, required)); err != nil {
				return &MessageError{Msg: "Secure Boot media signing configured but staged media is missing " + required}
			}
		}
		// Existence is not usability: the staged pair must be exactly the
		// material the installer's signing path will accept — parseable
		// key, parseable certificate, matching public keys — or the
		// failure surfaces only as an unsignable UKI on the target
		// (round-11 review).
		if _, _, err := authenticode.LoadSigningPair(
			filepath.Join(destDir, requiredKey), filepath.Join(destDir, requiredCert)); err != nil {
			return &WrappedError{Msg: "Secure Boot media signing configured but the staged DB pair is unusable", Err: err}
		}
	}

	// An enforcing build must positively stage the PK and KEK enrollment
	// certificates the installer will enroll (round-9 review): the
	// installer's enforceSecureBoot resolves them from the staged media
	// (resolveSecureBootEnrollCerts) and warns past their absence, so
	// only a build error here prevents a node with secure-boot.enforce
	// requested and no enforcement. The staged files must BE certificate
	// material, not merely exist.
	if enforcing {
		requiredPK, requiredKEK := c.sbPKCertFile, c.sbKEKCertFile
		if requiredPK == "" || requiredKEK == "" {
			requiredPK, requiredKEK = "PK.crt", "KEK.crt"
		}
		for _, required := range []string{requiredPK, requiredKEK} {
			data, readErr := os.ReadFile(filepath.Join(destDir, required))
			if readErr != nil {
				return &MessageError{Msg: "secure-boot.enforce is set but the staged media is missing enrollment certificate " + required}
			}
			if !parsesAsCertificates(data) {
				return &MessageError{Msg: "secure-boot.enforce is set but staged " + required + " is not X.509 certificate material"}
			}
		}
	}
	return nil
}

// ensureSecureBootKeysExist checks if Secure Boot keys exist and generates them if not.
// This ensures the ISO is always "Secure Boot ready" regardless of the SecureBoot flag.
func (c *Customizer) ensureSecureBootKeysExist(ctx context.Context, keysDir string) error {
	// Check if required key files exist
	dbKeyPath := filepath.Join(keysDir, "DB.key")
	dbCertPath := filepath.Join(keysDir, "DB.crt")

	dbKeyExists := false
	dbCertExists := false
	if _, err := os.Stat(dbKeyPath); err == nil {
		dbKeyExists = true
	}
	if _, err := os.Stat(dbCertPath); err == nil {
		dbCertExists = true
	}

	// If both key and cert exist, we're good
	if dbKeyExists && dbCertExists {
		c.logger.Debug("Secure Boot keys already exist", "path", keysDir)
		return nil
	}

	// Generate keys if they don't exist
	c.logger.Info("Secure Boot keys not found, generating automatically", "path", keysDir)

	xkmsConfig := &secureboot.XKMSConfig{
		KeysDir:      keysDir,
		Backend:      secureboot.BackendFile,
		CommonName:   "Trusted Platform",
		Country:      "US",
		Organization: "Trusted Platform",
		KeySize:      2048,
		ValidYears:   10,
		ExportKeys:   true, // Always export for Secure Boot enrollment
	}

	km, err := secureboot.NewXKMSManager(xkmsConfig, c.logger)
	if err != nil {
		return &WrappedError{Msg: "failed to create key manager", Err: err}
	}
	defer km.Close()

	// Generate all keys (PK, KEK, DB)
	if err := km.GenerateAll(ctx); err != nil {
		return &WrappedError{Msg: "failed to generate Secure Boot keys", Err: err}
	}

	c.logger.Info("Secure Boot keys generated successfully", "path", keysDir)
	return nil
}

// CopyFIPSArtifacts builds FIPS artifacts by running containers and copies them to the ISO
func (c *Customizer) CopyFIPSArtifacts(ctx context.Context) error {
	runtime := c.config.Security.FIPSConfig.ContainerRuntime
	opensslContainer := c.config.Security.FIPSConfig.OpenSSLContainer
	kernelContainer := c.config.Security.FIPSConfig.KernelContainer

	c.logger.Info("Building FIPS artifacts using containers",
		"runtime", runtime,
		"openssl_container", opensslContainer,
		"kernel_container", kernelContainer)

	// Create work directory for build artifacts
	artifactsWorkDir := filepath.Join(c.config.Directories.Work, "fips-artifacts")
	if err := os.MkdirAll(artifactsWorkDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create artifacts work directory", Err: err}
	}

	// Create subdirectories for each artifact type
	opensslOutputDir := filepath.Join(artifactsWorkDir, "openssl-output")
	kernelOutputDir := filepath.Join(artifactsWorkDir, "kernel-output")

	if err := os.MkdirAll(opensslOutputDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create OpenSSL output directory", Err: err}
	}
	if err := os.MkdirAll(kernelOutputDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create kernel output directory", Err: err}
	}

	// Create FIPS artifacts directory in ISO
	destDir := filepath.Join(c.config.Directories.ISO, "fips-artifacts")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create FIPS artifacts directory in ISO", Err: err}
	}

	// 1. Build complete FIPS-validated OpenSSL by running the container
	c.logger.Info("Building complete FIPS-validated OpenSSL (OpenSSL 3.1.2, Certificate #4985)", "container", opensslContainer)

	if err := runBuilderContainer(ctx, c.containerRunner(), runtime, "OpenSSL FIPS module", opensslContainer, opensslOutputDir,
		"cd build/docker/openssl-fips-provider && make build"); err != nil {
		return err
	}

	// Copy complete FIPS OpenSSL installation to ISO
	// According to official OpenSSL FIPS documentation and the reference project:
	//   - We MUST install the ENTIRE OpenSSL from a FIPS 140-3 validated version
	//   - OpenSSL 3.1.2 is FIPS 140-3 validated (Certificate #4985, valid until March 10, 2030)
	//   - The complete validated OpenSSL installation (binaries, libraries, FIPS module)
	//     must be installed as a unit - we cannot mix validated components with unvalidated ones
	//
	// The container outputs to /output which contains:
	//  - /output/usr/bin/openssl (OpenSSL binary)
	//  - /output/usr/lib/libssl.so.3, /output/usr/lib/libcrypto.so.3 (libraries)
	//  - /output/usr/lib/ossl-modules/fips.so (FIPS provider module)
	//  - /output/etc/ssl/* (configuration files)

	// 1. Copy usr/ directory (binaries, libraries, FIPS module)
	usrSrc := filepath.Join(opensslOutputDir, "usr")
	usrDest := filepath.Join(destDir, "usr")

	if _, err := os.Stat(usrSrc); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("complete OpenSSL installation not found in output at %s", usrSrc), Err: err}
	}

	cpUsrCmd := exec.CommandContext(ctx, "cp", "-a", usrSrc, destDir)
	if output, err := cpUsrCmd.CombinedOutput(); err != nil {
		return &CommandOutputError{Msg: "failed to copy OpenSSL usr directory", Err: err, Detail: fmt.Sprintf("\nOutput: %s", string(output))}
	}

	// 2. Copy etc/ directory (SSL configuration)
	etcSrc := filepath.Join(opensslOutputDir, "etc")

	if _, err := os.Stat(etcSrc); err == nil {
		cpEtcCmd := exec.CommandContext(ctx, "cp", "-a", etcSrc, destDir)
		if output, err := cpEtcCmd.CombinedOutput(); err != nil {
			c.logger.Warn("Failed to copy SSL configuration (may not be critical)",
				"output", string(output),
				"error", err)
		}
	}

	// 3. Verify the complete OpenSSL installation
	fipsModulePath := filepath.Join(usrDest, "lib", "ossl-modules", "fips.so")
	opensslBinPath := filepath.Join(usrDest, "bin", "openssl")
	libsslPath := filepath.Join(usrDest, "lib", "libssl.so.3")
	libcryptoPath := filepath.Join(usrDest, "lib", "libcrypto.so.3")

	for _, path := range []string{fipsModulePath, opensslBinPath, libsslPath, libcryptoPath} {
		if _, err := os.Stat(path); err != nil {
			return &MessageError{Msg: fmt.Sprintf("FIPS OpenSSL installation incomplete - missing: %s", path)}
		}
	}

	checksum, err := calculateSHA256(fipsModulePath)
	if err != nil {
		c.logger.Warn("Failed to calculate FIPS module checksum", "error", err)
	} else {
		c.logger.Info("FIPS provider module built and copied",
			"container", opensslContainer,
			"destination", fipsModulePath,
			"sha256", checksum)
	}

	// 2. Build FIPS kernel by running the container
	c.logger.Info("Building FIPS-capable kernel (this may take 15-30 minutes)", "container", kernelContainer)

	if err := runBuilderContainer(ctx, c.containerRunner(), runtime, "FIPS kernel", kernelContainer, kernelOutputDir,
		"cd build/docker/fips-kernel-builder && make build"); err != nil {
		return err
	}

	// Copy kernel to ISO
	kernelSrc := filepath.Join(kernelOutputDir, "vmlinuz-fips")
	kernelDest := filepath.Join(destDir, "vmlinuz-fips")

	if _, err := os.Stat(kernelSrc); err != nil {
		return &WrappedError{Msg: "FIPS kernel not found in output", Err: err}
	}

	if err := copyFile(kernelSrc, kernelDest); err != nil {
		return &WrappedError{Msg: "failed to copy FIPS kernel to ISO", Err: err}
	}

	kernelChecksum, err := calculateSHA256(kernelDest)
	if err != nil {
		c.logger.Warn("Failed to calculate kernel checksum", "error", err)
	} else {
		c.logger.Info("FIPS kernel built and copied",
			"container", kernelContainer,
			"destination", kernelDest,
			"sha256", kernelChecksum)
	}

	// 3. Copy kernel modules tarball
	c.logger.Info("Copying FIPS kernel modules")

	// Find the modules tarball in the output directory
	pattern := filepath.Join(kernelOutputDir, "modules-fips-*.tar.gz")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return &MessageError{Msg: fmt.Sprintf("kernel modules tarball not found in %s", kernelOutputDir)}
	}

	modulesSrc := matches[0]
	modulesDest := filepath.Join(destDir, "modules-fips.tar.gz")

	if err := copyFile(modulesSrc, modulesDest); err != nil {
		return &WrappedError{Msg: "failed to copy kernel modules to ISO", Err: err}
	}

	modulesChecksum, err := calculateSHA256(modulesDest)
	if err != nil {
		c.logger.Warn("Failed to calculate modules checksum", "error", err)
	} else {
		c.logger.Info("FIPS kernel modules copied",
			"source", filepath.Base(modulesSrc),
			"destination", modulesDest,
			"sha256", modulesChecksum)
	}

	// Write checksums file
	checksumsPath := filepath.Join(destDir, "SHA256SUMS")
	checksumsContent := fmt.Sprintf("%s  fips.so\n%s  vmlinuz-fips\n%s  modules-fips.tar.gz\n",
		checksum, kernelChecksum, modulesChecksum)
	if err := os.WriteFile(checksumsPath, []byte(checksumsContent), 0644); err != nil {
		c.logger.Warn("Failed to write checksums file", "error", err)
	} else {
		c.logger.Debug("Checksums file created", "path", checksumsPath)
	}

	c.logger.Info("FIPS artifacts built and copied successfully",
		"runtime", runtime,
		"openssl_container", opensslContainer,
		"kernel_container", kernelContainer,
		"fips_module", "fips.so",
		"kernel", "vmlinuz-fips",
		"modules", "modules-fips.tar.gz")

	return nil
}

// runBuilderContainer runs a FIPS builder image to completion and copies its
// /output directory to outputDir.
//
// The output comes out with `cp`, not a bind mount: the daemon resolves a bind
// mount on its own filesystem, which is not this process's when the build runs
// in a CI job container, so the artifacts would never reach outputDir.
func runBuilderContainer(ctx context.Context, run runner.Runner, runtime, what, image, outputDir, buildHint string) error {
	container := runner.Container{
		Image: image,
		Out:   []runner.Copy{{Host: outputDir, Container: "/output"}},
	}
	if err := container.Run(ctx, run, runtime); err != nil {
		return &CommandOutputError{
			Msg:    fmt.Sprintf("failed to build %s using container %s", what, image),
			Err:    err,
			Detail: "\nHint: Build the container image first with: " + buildHint,
		}
	}
	return nil
}

// containerRunner runs the container runtime. In debug mode its output streams
// to the terminal; otherwise it is captured and reported with the error.
func (c *Customizer) containerRunner() runner.Runner {
	if !c.config.Build.Debug {
		return runner.Exec
	}
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return nil, cmd.Run()
	}
}

// GenerateAutoinstallScript generates the automated installation script
func (c *Customizer) GenerateAutoinstallScript(ctx context.Context) error {
	c.logger.Info("Generating autoinstall script")

	// This generates a standalone copy of the autoinstall script for debugging.
	// The actual boot hook is created by CreateApkovl
	// But we provide this method for API completeness and flexibility
	scriptPath := filepath.Join(c.config.Directories.Work, "autoinstall.sh")

	script := c.buildAutoinstallScript()

	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return &WrappedError{Msg: "failed to write autoinstall script", Err: err}
	}

	c.logger.Info("Autoinstall script generated", "path", scriptPath)
	return nil
}

// ConfigureBootloader configures GRUB for automated installation
func (c *Customizer) ConfigureBootloader(ctx context.Context) error {
	c.logger.Info("Configuring GRUB bootloader")

	// Find GRUB config
	grubPath := filepath.Join(c.config.Directories.ISO, "boot", "grub", "grub.cfg")
	if _, err := os.Stat(grubPath); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("GRUB config not found: %s", grubPath)}
	}

	// Read existing config
	content, err := os.ReadFile(grubPath)
	if err != nil {
		return &WrappedError{Msg: "failed to read GRUB config", Err: err}
	}

	// Modify config for autoinstall
	modified := string(content)

	// Strip ONLY gfxterm/framebuffer video setup (gfxmode, gfxterm, all_video,
	// loadfont, gfxpayload). These initialize a graphical framebuffer that
	// doesn't exist on X10-class headless servers and produces the classic
	// "error: no suitable video mode found. Booting in blind mode" failure.
	//
	// We DELIBERATELY do NOT strip the plain `console` terminal — that is
	// GRUB's firmware-provided console (EFI ConOut on UEFI, VGA text mode
	// on legacy BIOS). On Supermicro X10 the BMC snoops that firmware
	// console and mirrors it to the iKVM viewer, so keeping it means the
	// GRUB menu, the "Booting ..." message, and the kernel's early output
	// are all visible to a human operator watching iKVM. The serial
	// terminal runs alongside it for the bootstrap orchestrator's SOL
	// capture channel.
	videoStripKeywords := []string{
		"gfxmode",
		"gfxterm",
		"all_video",
		"loadfont",
		"gfxpayload",
	}
	{
		lines := strings.Split(modified, "\n")
		filtered := make([]string, 0, len(lines))
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			strip := false
			for _, kw := range videoStripKeywords {
				if strings.Contains(trimmed, kw) {
					strip = true
					break
				}
			}
			if !strip {
				filtered = append(filtered, line)
			}
		}
		modified = strings.Join(filtered, "\n")
	}
	// Inject serial-ONLY terminal config before the first menuentry.
	// Do NOT add `console` to the ISO grub.cfg terminal_output — the
	// `console` terminal forces GRUB to initialize the gfxterm video
	// subsystem, which on headless Supermicro X10 boards fails with
	// "error: no suitable video mode found. Booting in blind mode"
	// and leaves iKVM frozen on the error frame. Serial-only in this
	// file means GRUB never tries the video path at the menuentry
	// stage. The embedded EFI grub.cfg we build via grub-mkstandalone
	// already had `terminal_output serial console` to reach iKVM at
	// GRUB startup; by the time this ISO grub.cfg runs we are past
	// that point and can narrow to serial without losing visibility.
	if !strings.Contains(modified, "terminal_output") {
		lines := strings.Split(modified, "\n")
		for i, line := range lines {
			if strings.Contains(line, "menuentry") {
				serialCfg := []string{
					"serial --unit=0 --speed=115200",
					"serial --unit=1 --speed=115200",
					"terminal_input serial",
					"terminal_output serial",
				}
				lines = append(lines[:i], append(serialCfg, lines[i:]...)...)
				break
			}
		}
		modified = strings.Join(lines, "\n")
	}

	// Remove 'quiet' parameter to see boot messages
	modified = strings.ReplaceAll(modified, " quiet", "")
	modified = strings.ReplaceAll(modified, "quiet ", "")

	// Rename menu entry from "Linux lts" to "Trusted Alpine LTS"
	modified = strings.ReplaceAll(modified, `menuentry "Linux lts"`, `menuentry "Trusted Alpine LTS"`)
	modified = strings.ReplaceAll(modified, `menuentry 'Linux lts'`, `menuentry 'Trusted Alpine LTS'`)

	// Deliberately do NOT prepend `set gfxmode=...` or `set gfxpayload=...`
	// to the ISO grub.cfg. Those variables are already set in the embedded
	// EFI grub.cfg we build into bootx64.efi via grub-mkstandalone, and
	// they persist through the sourcing of this ISO grub.cfg. Re-setting
	// them here was the regression that produced "error: no suitable
	// video mode found. Booting in blind mode" on Supermicro X10. The
	// video-strip pass above already removes any stock Alpine gfxmode /
	// gfxpayload / gfxterm / loadfont / all_video lines so nothing in
	// this config file can retrigger GRUB's mode-set path. This matches
	// the 1fbd40f baseline exactly.

	// Add console and autoinstall parameters
	// Look for kernel command lines and add our parameters
	lines := strings.Split(modified, "\n")
	for i, line := range lines {
		// Match "linux" followed by whitespace (space or tab) and contains vmlinuz
		if (strings.Contains(line, "linux\t") || strings.Contains(line, "linux ")) && strings.Contains(line, "/boot/vmlinuz") {
			// The ISO is built generically — it must boot on any supported
			// hardware.  Vendor-specific console wiring (e.g. which ttyS
			// port the BMC SOL concentrator is wired to) is resolved at
			// install time via pkg/quirks.  For the ISO bootloader we use
			// the cross-vendor defaults from quirks.Default(), which provide
			// dual UART coverage (COM1 + COM2), EFI early console, and VGA
			// mirroring — safe on all known server platforms.
			if !strings.Contains(line, "console=ttyS0") {
				defaultQuirk := quirks.Default()
				line += " " + strings.Join(defaultQuirk.KernelCmdline, " ")
				// Also include tty1 for BMC framebuffer mirroring; not in
				// the Default() list to keep it minimal, but necessary in
				// the ISO boot path where we do not know the target platform.
				if !strings.Contains(line, "console=tty1") {
					line += " console=tty1"
				}
			}
			// alpine_start=autoinstall is the marker our patched Alpine
			// init script looks for. When present, the patched init copies
			// /overlay/etc/inittab, /overlay/root/autoinstall.sh, and
			// /overlay/root/run-autoinstall.sh out of the initramfs and
			// into $sysroot before switch_root. BusyBox init then runs
			// with our custom inittab, which launches run-autoinstall.sh
			// as a sysinit entry and calls /sbin/poweroff -f when it
			// returns. No apkovl extraction, no OpenRC runlevels.
			if !strings.Contains(line, "alpine_start=autoinstall") {
				line += " alpine_start=autoinstall"
			}
			// Append dynamic config params when in server-fetch mode
			dynamicParams := c.buildDynamicConfigParams()
			if dynamicParams != "" && !strings.Contains(line, "platform_config=") {
				line += " " + dynamicParams
			}
			// Always enable debug mode for the install. The autoinstall.sh
			// upload_install_log function reads platform_debug_sink from
			// /proc/cmdline and PUTs install.log there on every exit path.
			// A configured sink is baked in at ISO build time; without one
			// the script derives the sink from the DHCP server, so no
			// deployment's address is ever assumed here.
			if !strings.Contains(line, "platform_debug=") {
				line += " platform_debug=1"
			}
			if !strings.Contains(line, "platform_debug_sink=") {
				if sink := c.config.Platform.DebugSink; sink != "" {
					line += " platform_debug_sink=" + sink
				} else {
					c.logger.Info("No debug sink configured; the install script will derive it from the DHCP server")
				}
			}
			// platform_apk_mirror=<url> — the INSTALL-time APK repository
			// base. buildAutoinstallScript reads this from /proc/cmdline and
			// uses it when /media/cdrom is absent. It's harmless on vmedia/CD
			// boots (the cdrom branch wins), but baking it here means an ISO
			// booted on a network where the local apks are incomplete can
			// still reach a mirror. Empty config leaves it off so the
			// autoinstall public-mirror fallback applies.
			if c.config.Alpine.APKMirror != "" && !strings.Contains(line, "platform_apk_mirror=") {
				line += " platform_apk_mirror=" + c.config.Alpine.APKMirror
			}
			// platform_hostname=<name> — baked into the kernel cmdline so
			// autoinstall.sh's resolve_platform_hostname can read it from
			// /proc/cmdline without needing to locate and awk-scan the
			// installer YAML at runtime. The shell-native YAML fallback
			// is still in place, but it fails silently on live Alpine
			// when /media/cdrom is not (yet) mounted at hook-run time,
			// causing the install.log forensic upload to hit
			// /installs/unknown/ instead of /installs/<hostname>/. Baking
			// the value into the kernel cmdline at ISO-build time removes
			// that dependency entirely: /proc/cmdline is always readable.
			if hostname := c.resolveHostnameForCmdline(); hostname != "" && !strings.Contains(line, "platform_hostname=") {
				line += " platform_hostname=" + hostname
			}
			lines[i] = line
		}
	}
	modified = strings.Join(lines, "\n")

	// Write back modified config
	if err := os.WriteFile(grubPath, []byte(modified), 0644); err != nil {
		return &WrappedError{Msg: "failed to write GRUB config", Err: err}
	}

	c.logger.Info("GRUB bootloader configured for autoinstall")

	// Update EFI bootloader with correct volume label.
	//
	// This used to warn "UEFI boot may fail" and continue — a message that
	// predicts the failure it is about to cause. The Alpine ISO's bootx64.efi
	// carries a hardcoded search directive for the original volume label, so
	// without this the artifact does not boot under UEFI at all (#48).
	if err := c.UpdateEFIBootloader(ctx); err != nil {
		return ErrBootloaderUpdateFailed(err)
	}

	return nil
}

// UpdateEFIBootloader updates the EFI bootloader to use the correct volume label.
// This is necessary because the Alpine ISO's bootx64.efi has a hardcoded search
// directive for the original Alpine volume label.
// The EFI bootloader is located at /efi/boot/bootx64.efi in the ISO directory.
// Requires grub-mkstandalone to be installed.
func (c *Customizer) UpdateEFIBootloader(ctx context.Context) error {
	c.logger.Info("Updating EFI bootloader with correct volume label")

	// The actual EFI bootloader is at /efi/boot/bootx64.efi, not inside efi.img
	efiBootDir := filepath.Join(c.config.Directories.ISO, "efi", "boot")
	bootx64Path := filepath.Join(efiBootDir, "bootx64.efi")

	if _, err := os.Stat(bootx64Path); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("EFI bootloader not found: %s", bootx64Path)}
	}

	// Find grub-mkstandalone
	grubMkstandalone := "grub-mkstandalone"
	if _, err := exec.LookPath(grubMkstandalone); err != nil {
		grubMkstandalone = "grub2-mkstandalone"
		if _, err := exec.LookPath(grubMkstandalone); err != nil {
			return &MessageError{Msg: "grub-mkstandalone not found: install grub2-common or grub-common package"}
		}
	}

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "efi-update-*")
	if err != nil {
		return &WrappedError{Msg: "failed to create temp directory", Err: err}
	}
	defer os.RemoveAll(tmpDir)

	// Get the volume label from config
	volumeLabel := c.config.Output.Label
	if volumeLabel == "" {
		volumeLabel = "TRUSTED_PLATFORM"
	}

	// Read the ISO grub.cfg to get the full boot menu config
	isoGrubCfg := filepath.Join(c.config.Directories.ISO, "boot", "grub", "grub.cfg")
	grubCfgBytes, err := os.ReadFile(isoGrubCfg)
	if err != nil {
		return &WrappedError{Msg: "failed to read ISO grub.cfg", Err: err}
	}

	// Create embedded GRUB config that searches for the ISO volume by label,
	// then includes the full boot menu inline as a fallback. The iso9660 and
	// search_label modules are included explicitly via --install-modules.
	grubCfgContent := fmt.Sprintf(`# Force text-mode video configuration for headless Supermicro X10 boards.
# gfxmode=text + gfxpayload=text keeps GRUB and the kernel payload
# transition in firmware text mode, which the X10 BMC mirrors cleanly
# to iKVM. Any graphical-framebuffer path (gfxpayload=keep, gfxpayload=
# 1024x768, etc.) triggers "error: no suitable video mode found.
# Booting in blind mode" on these boards and leaves iKVM frozen on
# the last GRUB frame. This matches the 1fbd40f baseline.
set gfxmode=text
set gfxpayload=text

# Initialize serial UARTs and route GRUB output to serial ONLY. The
# "console" GRUB terminal forces gfxterm initialization which probes
# for a framebuffer mode and fails on headless Supermicro X10 boards
# with "error: no suitable video mode found. Booting in blind mode".
# We deliberately lose iKVM visibility of the GRUB startup/menu
# phase — iKVM still sees BIOS/POST and the initial EFI firmware
# output, then text from the Linux kernel's efifb/vgacon takes over
# after GRUB hands off. SOL captures everything via serial.
insmod serial
serial --unit=0 --speed=115200
serial --unit=1 --speed=115200
terminal_input serial
terminal_output serial

# Zero timeout -- boot immediately without waiting for user input.
# This ensures headless servers don't hang at an invisible GRUB menu.
set timeout=0
set default=0

insmod iso9660
insmod search_label
insmod part_gpt
insmod part_msdos
search --no-floppy --set=root --label "%s"

%s`, volumeLabel, string(grubCfgBytes))

	grubCfgPath := filepath.Join(tmpDir, "grub.cfg")
	if err := os.WriteFile(grubCfgPath, []byte(grubCfgContent), 0644); err != nil {
		return &WrappedError{Msg: "failed to write GRUB config", Err: err}
	}

	// Create new bootx64.efi with grub-mkstandalone, including modules needed
	// to read ISO9660 filesystems and search by volume label.
	newEFIPath := filepath.Join(tmpDir, "bootx64.efi")
	// Set GRUB_TERMINAL=serial to prevent video initialization at build time.
	mkstandaloneCmd := exec.CommandContext(ctx, grubMkstandalone,
		"--format=x86_64-efi",
		"--output="+newEFIPath,
		"--locales=",
		"--fonts=",
		// Explicitly list only the modules we need. NO video, gfxterm, gfxmenu,
		// all_video, efi_gop, efi_uga, or vbe — these cause "no suitable video
		// mode found" on headless servers and halt at the GRUB screen.
		"--install-modules=iso9660 search search_label part_gpt part_msdos fat linux normal configfile echo test serial loopback",
		"boot/grub/grub.cfg="+grubCfgPath,
	)
	mkstandaloneCmd.Env = append(os.Environ(), "GRUB_TERMINAL=serial")

	if output, err := mkstandaloneCmd.CombinedOutput(); err != nil {
		return &CommandOutputError{Msg: "grub-mkstandalone failed", Err: err, Detail: fmt.Sprintf(", output: %s", string(output))}
	}

	// Check generated file size
	newInfo, err := os.Stat(newEFIPath)
	if err != nil {
		return &WrappedError{Msg: "failed to stat new bootx64.efi", Err: err}
	}
	c.logger.Debug("Generated new bootx64.efi", "size", newInfo.Size())

	// Sign BEFORE the two consumers below, not after.
	//
	// The ISO filesystem copy (bootx64Path) and the El Torito boot image
	// (efi.img, built from newEFIPath) are separate copies of this binary, and
	// firmware boots the El Torito one. Signing after the copy would leave the
	// image firmware actually loads unsigned while the filesystem copy looked
	// correct -- the fix would appear to work and change nothing.
	if err := c.signISOBootloader(ctx, newEFIPath); err != nil {
		return err
	}

	// Replace the original bootx64.efi with the new one
	if err := copyFile(newEFIPath, bootx64Path); err != nil {
		return &WrappedError{Msg: "failed to replace bootx64.efi", Err: err}
	}

	c.logger.Info("EFI bootloader updated with volume label", "label", volumeLabel, "path", bootx64Path)

	// Regenerate efi.img (El Torito UEFI boot image) with the new bootx64.efi.
	// UEFI firmware boots from the El Torito catalog which points to efi.img,
	// not from the ISO filesystem's /efi/boot/bootx64.efi directly.
	efiImgPath := filepath.Join(c.config.Directories.ISO, "boot", "grub", "efi.img")
	if err := c.regenerateEFIImage(newEFIPath, efiImgPath); err != nil {
		return &WrappedError{Msg: "failed to regenerate efi.img", Err: err}
	}

	return nil
}

// signISOBootloader signs the regenerated EFI bootloader with the Secure Boot
// DB key staged on the media, so firmware enforcing Secure Boot will load the
// installer ISO instead of refusing it with "Access Denied" (#59).
//
// No-op unless this build signs with media-staged keys. When it does, the key
// material is guaranteed: CopySecureBootKeys runs earlier in Customize and
// fails the build when the staged DB pair is absent, and validates it as a
// usable signing pair rather than merely present files
// (authenticode.LoadSigningPair). There is deliberately no
// "keys missing" branch here -- that build has already failed.
//
// SCOPE: this signs the BOOTLOADER only. The kernel and initrd on the ISO
// remain unsigned, and with no shim in the chain nothing verifies them once
// grub is running. Firmware verifies the loader, not the system. See #354.
func (c *Customizer) signISOBootloader(ctx context.Context, efiPath string) error {
	if !c.mediaSigningEnabled() {
		return nil
	}

	keyFile, certFile := c.sbMediaKeyFile, c.sbMediaCertFile
	if keyFile == "" || certFile == "" {
		keyFile, certFile = "DB.key", "DB.crt"
	}
	stagedDir := filepath.Join(c.config.Directories.ISO, SecureBootKeysISODirName)

	signer, err := authenticode.NewFileSigner(
		ctx,
		filepath.Join(stagedDir, keyFile),
		filepath.Join(stagedDir, certFile),
		c.logger,
	)
	if err != nil {
		return &WrappedError{Msg: "Secure Boot media signing configured but the ISO bootloader signer could not be built", Err: err}
	}

	// SignFile cannot write over its own input -- it creates the output before
	// reading the input -- so sign to a sibling and swap.
	signedPath := efiPath + ".signed"
	if err := signer.SignFile(efiPath, signedPath); err != nil {
		return &WrappedError{Msg: "failed to sign the ISO EFI bootloader", Err: err}
	}
	defer os.Remove(signedPath)

	// Verify what was produced rather than trusting that signing succeeded.
	// A bootloader that fails verification here would fail it in firmware, as
	// an Access Denied at boot with no build-time signal.
	if err := signer.VerifyFile(signedPath); err != nil {
		return &WrappedError{Msg: "the signed ISO EFI bootloader failed verification", Err: err}
	}

	if err := copyFile(signedPath, efiPath); err != nil {
		return &WrappedError{Msg: "failed to install the signed ISO EFI bootloader", Err: err}
	}

	c.logger.Info("Signed ISO EFI bootloader with Secure Boot DB key",
		"path", efiPath, "key", keyFile, "cert", certFile)
	return nil
}

// regenerateEFIImage creates a new FAT filesystem image containing the
// bootx64.efi at /efi/boot/bootx64.efi, suitable for use as an El Torito
// UEFI boot image in the ISO.
func (c *Customizer) regenerateEFIImage(bootx64Src, efiImgDst string) error {
	c.logger.Info("Regenerating efi.img with custom bootloader")

	// Get the size of the new bootx64.efi to calculate image size
	info, err := os.Stat(bootx64Src)
	if err != nil {
		return &WrappedError{Msg: "failed to stat bootx64.efi", Err: err}
	}

	// Calculate image size: bootx64.efi size + overhead for FAT filesystem structures.
	// Round up to nearest MB, minimum 4MB to ensure FAT12/16 compatibility.
	imgSizeBytes := info.Size() + 512*1024 // 512KB overhead for FAT metadata
	imgSizeMB := (imgSizeBytes / (1024 * 1024)) + 1
	if imgSizeMB < 4 {
		imgSizeMB = 4
	}

	// Create a new empty image file
	truncateCmd := exec.Command("truncate", "-s", fmt.Sprintf("%dM", imgSizeMB), efiImgDst)
	if output, err := truncateCmd.CombinedOutput(); err != nil {
		return &CommandOutputError{Msg: "failed to create efi.img", Err: err, Detail: fmt.Sprintf(", output: %s", string(output))}
	}

	// Format as FAT filesystem
	mkfsCmd := exec.Command("mkfs.vfat", "-F", "12", efiImgDst)
	if output, err := mkfsCmd.CombinedOutput(); err != nil {
		return &CommandOutputError{Msg: "failed to format efi.img", Err: err, Detail: fmt.Sprintf(", output: %s", string(output))}
	}

	// Use mtools to copy files into the FAT image without mounting
	// Create directory structure: /efi/boot/
	mmd := exec.Command("mmd", "-i", efiImgDst, "::efi", "::efi/boot")
	if output, err := mmd.CombinedOutput(); err != nil {
		return &CommandOutputError{Msg: "failed to create directories in efi.img", Err: err, Detail: fmt.Sprintf(", output: %s", string(output))}
	}

	// Copy bootx64.efi into the image
	mcopy := exec.Command("mcopy", "-i", efiImgDst, bootx64Src, "::efi/boot/bootx64.efi")
	if output, err := mcopy.CombinedOutput(); err != nil {
		return &CommandOutputError{Msg: "failed to copy bootx64.efi into efi.img", Err: err, Detail: fmt.Sprintf(", output: %s", string(output))}
	}

	newInfo, err := os.Stat(efiImgDst)
	if err != nil {
		return &WrappedError{Msg: "failed to stat new efi.img", Err: err}
	}
	c.logger.Info("efi.img regenerated", "size", newInfo.Size(), "path", efiImgDst)
	return nil
}

// Helper functions

// checkPrerequisites verifies that all required resources are available
func (c *Customizer) checkPrerequisites() error {
	// Check ISO directory exists
	if _, err := os.Stat(c.config.Directories.ISO); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("ISO directory not found: %s", c.config.Directories.ISO)}
	}

	// Check required binaries
	requiredCommands := []string{"cpio", "gzip", "file", "awk"}
	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			return &MessageError{Msg: fmt.Sprintf("required command not found: %s", cmd)}
		}
	}

	// Check platformd binary if specified
	if c.config.Platform.PlatformdBinary != "" {
		if _, err := os.Stat(c.config.Platform.PlatformdBinary); os.IsNotExist(err) {
			return &MessageError{Msg: fmt.Sprintf("platformd binary not found: %s", c.config.Platform.PlatformdBinary)}
		}
	}

	// Check secure boot keys if enabled
	if c.config.Security.SecureBoot {
		keyPath := filepath.Join(c.config.Directories.Keys, "DB.key")
		certPath := filepath.Join(c.config.Directories.Keys, "DB.crt")
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			c.logger.Warn("Secure boot key not found", "path", keyPath)
		}
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			c.logger.Warn("Secure boot certificate not found", "path", certPath)
		}
	}

	return nil
}

// findInitramfs locates the initramfs file in the extracted ISO
func (c *Customizer) findInitramfs() (string, error) {
	// Common locations for Alpine initramfs
	patterns := []string{
		filepath.Join(c.config.Directories.ISO, "boot", "initramfs-*"),
		filepath.Join(c.config.Directories.ISO, "boot", "initrd*"),
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if len(matches) > 0 {
			return matches[0], nil
		}
	}

	return "", &MessageError{Msg: "initramfs not found in ISO directory"}
}

// createDracutModule creates dracut module structure in the initramfs
func (c *Customizer) createDracutModule(initramfsDir string) error {
	moduleDir := filepath.Join(initramfsDir, "usr", "lib", "dracut", "modules.d", "90platformd")
	if err := os.MkdirAll(moduleDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create module directory", Err: err}
	}

	// Create module-setup.sh
	moduleSetup := `#!/bin/bash
# Dracut module for platform-initrd (boot-only binary)
# NOTE: platform-initrd is the minimal binary for initramfs boot operations
#       platformd is the daemon-only binary, platformctl is the CLI

check() {
    return 0
}

depends() {
    # No crypt module needed - platform-initrd uses go-luks2 for all LUKS operations
    echo systemd
}

install() {
    inst_binary /usr/bin/platform-initrd
    inst_simple "$moddir/platform-initrd-boot.sh" /usr/bin/platform-initrd-boot.sh

    # Install configuration files
    if [ -f /etc/trusted-platform/platformd.yaml ]; then
        inst_simple /etc/trusted-platform/platformd.yaml
    fi
    if [ -f /etc/platformd/install.yaml ]; then
        inst_simple /etc/platformd/install.yaml
    fi
    if [ -f /etc/platformd/initrd.yaml ]; then
        inst_simple /etc/platformd/initrd.yaml
    fi
}
`
	moduleSetupPath := filepath.Join(moduleDir, "module-setup.sh")
	if err := os.WriteFile(moduleSetupPath, []byte(moduleSetup), 0755); err != nil {
		return &WrappedError{Msg: "failed to write module-setup.sh", Err: err}
	}

	// Create platform-initrd-boot.sh wrapper script for dracut
	wrapperScript := `#!/bin/bash
# Platform-initrd boot wrapper for dracut (calls platform-initrd boot)

platform-initrd boot "$@"
`
	wrapperPath := filepath.Join(moduleDir, "platform-initrd-boot.sh")
	if err := os.WriteFile(wrapperPath, []byte(wrapperScript), 0755); err != nil {
		return &WrappedError{Msg: "failed to write wrapper script", Err: err}
	}

	c.logger.Debug("Dracut module created", "path", moduleDir)
	return nil
}

// createAutoinstallOverlay creates the overlay directory structure for autoinstall
func (c *Customizer) createAutoinstallOverlay(initramfsDir string) error {
	overlayDir := filepath.Join(initramfsDir, "overlay")
	if err := os.MkdirAll(filepath.Join(overlayDir, "etc"), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(overlayDir, "root"), 0755); err != nil {
		return err
	}

	// Create inittab for autoinstall
	// Skip OpenRC entirely — it hangs in the live ISO environment because
	// services expect a fully configured system. The run-autoinstall.sh wrapper
	// already mounts /dev, /proc, /sys, modloop, starts mdev, loads modules,
	// and configures networking manually. BusyBox init just needs to launch it.
	inittab := `::sysinit:/root/run-autoinstall.sh
::sysinit:/sbin/poweroff -f
::ctrlaltdel:/sbin/reboot
`
	inittabPath := filepath.Join(overlayDir, "etc", "inittab")
	if err := os.WriteFile(inittabPath, []byte(inittab), 0644); err != nil {
		return &WrappedError{Msg: "failed to write inittab", Err: err}
	}

	// Create autoinstall script
	autoinstallScript := c.buildAutoinstallScript()
	autoinstallPath := filepath.Join(overlayDir, "root", "autoinstall.sh")
	if err := os.WriteFile(autoinstallPath, []byte(autoinstallScript), 0755); err != nil {
		return &WrappedError{Msg: "failed to write autoinstall.sh", Err: err}
	}

	// Create wrapper script
	// Detect the active console from the kernel (last entry in
	// /sys/class/tty/console/active is the primary console).
	// Falls back to /dev/console which always routes to the active console.
	wrapperScript := `#!/bin/sh
# Autoinstall wrapper - launched by BusyBox init after switch_root
# Redirect all output to the kernel's primary console for visibility in logs.
# The last entry of /sys/class/tty/console/active is the primary console: ttyS0
# on an x86 serial console, ttyAMA0 or ttyS1 on a Raspberry Pi, tty0 on a
# machine with only a display.
console=/dev/console
if [ -r /sys/class/tty/console/active ]; then
    active=$(cat /sys/class/tty/console/active)
    active=${active##* }
    if [ -n "$active" ] && [ -c "/dev/$active" ]; then
        console="/dev/$active"
    fi
fi
exec > "$console" 2>&1 || exec > /dev/console 2>&1 || true

echo "[autoinstall] run-autoinstall.sh starting (PID $$)"
echo "[autoinstall] run-autoinstall.sh starting (PID $$)" > /dev/kmsg 2>/dev/null

# ensure_modloop locates and mounts the kernel-modules squashfs so that
# modprobe can load drivers that are NOT built into the kernel or baked
# into the initramfs (dm-mod, dm-crypt, ext4, tpm, ...). It is idempotent
# and safe to call repeatedly: it returns immediately once /lib/modules
# is populated. Two delivery paths are handled, which is why it is invoked
# both before and after the network is brought up:
#   - Virtual-media / CD boot: modloop-lts lives on the mounted ISO and
#     needs no network, so the early (pre-network) call succeeds.
#   - PXE / diskless boot: there is no CD; the modloop is served over
#     HTTP and its URL is passed on the kernel cmdline as modloop=. That
#     fetch needs networking, so the post-network call is the one that
#     succeeds for PXE. Without this fallback the live system runs with
#     ONLY the initramfs-injected modules — networking comes up (NIC
#     drivers are injected) but dm_mod/dm_crypt are absent, so the
#     installer's LUKS step dies on a missing /dev/mapper/control.
ensure_modloop() {
    _kver=$(uname -r)
    if [ -d "/lib/modules/$_kver/kernel" ]; then
        return 0
    fi
    # 1. Local media (CD / virtual-media).
    mkdir -p /media/cdrom
    mountpoint -q /media/cdrom 2>/dev/null || \
        mount -t iso9660 /dev/sr0 /media/cdrom 2>/dev/null || \
        mount -t iso9660 /dev/cdrom /media/cdrom 2>/dev/null || true
    _modloop=""
    for f in /media/cdrom/boot/modloop-lts /media/*/boot/modloop-lts; do
        [ -f "$f" ] && _modloop="$f" && break
    done
    # 2. PXE fallback: fetch from the modloop= URL on the kernel cmdline.
    if [ -z "$_modloop" ]; then
        _modloop_url=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | sed -n 's/^modloop=//p' | head -n1)
        case "$_modloop_url" in
            http://*|https://*|ftp://*)
                if [ ! -f /tmp/modloop-lts ]; then
                    echo "[autoinstall] Fetching modloop over network: $_modloop_url" > /dev/kmsg 2>/dev/null
                    wget -q -O /tmp/modloop-lts "$_modloop_url" 2>/dev/null || \
                    busybox wget -q -O /tmp/modloop-lts "$_modloop_url" 2>/dev/null || \
                        rm -f /tmp/modloop-lts
                fi
                [ -f /tmp/modloop-lts ] && _modloop=/tmp/modloop-lts
                ;;
        esac
    fi
    if [ -z "$_modloop" ]; then
        echo "[autoinstall] modloop not yet available (no CD; network may still be down)" > /dev/kmsg 2>/dev/null
        return 1
    fi
    mkdir -p /.modloop
    mountpoint -q /.modloop 2>/dev/null || \
        mount -t squashfs -o loop,ro "$_modloop" /.modloop 2>/dev/null
    if [ -d "/.modloop/modules" ]; then
        # Link the modules directory so modprobe resolves modules.dep.
        rm -rf /lib/modules 2>/dev/null
        ln -sf /.modloop/modules /lib/modules
        echo "[autoinstall] modloop mounted ($_modloop): $(ls /lib/modules/ 2>/dev/null)" > /dev/kmsg 2>/dev/null
        return 0
    fi
    echo "[autoinstall] WARNING: modloop mounted but has no modules dir" > /dev/kmsg 2>/dev/null
    return 1
}

# load_essential_modules loads every kernel module the installer needs
# from the now-mounted modloop. It is idempotent (modprobe no-ops if a
# module is already loaded) and called both before and after the network
# comes up so that on PXE — where modloop only mounts after networking —
# the device-mapper, filesystem and TPM drivers are present by the time
# the main installer runs.
load_essential_modules() {
    modprobe af_packet 2>/dev/null || true
    modprobe virtio_net 2>/dev/null || true
    modprobe virtio_blk 2>/dev/null || true
    modprobe virtio_pci 2>/dev/null || true
    modprobe e1000 2>/dev/null || true
    modprobe e1000e 2>/dev/null || true
    modprobe igb 2>/dev/null || true
    modprobe ixgbe 2>/dev/null || true
    modprobe mlx5_core 2>/dev/null || true
    modprobe bnxt_en 2>/dev/null || true
    modprobe dm_mod 2>/dev/null || true
    modprobe dm_crypt 2>/dev/null || true
    # Filesystem modules — must be loaded BEFORE the installer's mount(2)
    # syscall on the freshly-formatted /mnt. The installer runs mkfs.ext4
    # (userspace tool, works without kernel support) successfully but then
    # silently dies on mount() when the ext4 kernel driver is not present.
    modprobe ext4 2>/dev/null || true
    modprobe ext2 2>/dev/null || true
    modprobe jbd2 2>/dev/null || true
    modprobe crc16 2>/dev/null || true
    # LVM and device-mapper targets used by the LUKS + LVM + ext4 stack.
    modprobe dm_mirror 2>/dev/null || true
    modprobe dm_thin_pool 2>/dev/null || true
    # TPM modules — required for installer's TPM2_Clear step. Without these,
    # /dev/tpm0 is absent during install and stale TPM state from prior
    # installations causes PCR_POLICY_FAIL at first boot.
    modprobe tpm 2>/dev/null || true
    modprobe tpm_tis 2>/dev/null || true
    modprobe tpm_tis_core 2>/dev/null || true
    modprobe tpm_crb 2>/dev/null || true
}

# Mount essential filesystems if not already mounted
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts /dev/shm /run 2>/dev/null || true
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs tmpfs /dev/shm 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true

# Mount the modloop (kernel modules squashfs) - required for AF_PACKET, dm_crypt, etc.
# Alpine's init adds modloop as an OpenRC service; since we bypass OpenRC, we mount it
# manually via ensure_modloop. On CD/virtual-media this succeeds now (no network needed);
# on PXE the modloop is served over HTTP and only becomes reachable once networking is
# up, so this early call is a best-effort no-op there — the post-network call below is
# the one that mounts it for PXE.
echo "[autoinstall] Mounting modloop..." > /dev/kmsg 2>/dev/null
ensure_modloop || true

# Start mdev for device hotplug (BusyBox device manager)
echo "[autoinstall] Starting mdev..." > /dev/kmsg 2>/dev/null
echo /sbin/mdev > /proc/sys/kernel/hotplug 2>/dev/null || true
mdev -s 2>/dev/null || true

# Load essential kernel modules. On CD/virtual-media modloop is mounted
# above so these load now; on PXE modloop isn't reachable until the
# network is up, so this early pass is best-effort and the modules are
# (re)loaded by the post-network pass below.
echo "[autoinstall] Loading kernel modules..." > /dev/kmsg 2>/dev/null
load_essential_modules
sleep 1

# Re-scan devices after module loading
mdev -s 2>/dev/null || true

# Bring up networking manually (no OpenRC available)
echo "[autoinstall] Bringing up network..." > /dev/kmsg 2>/dev/null
ip link set lo up 2>/dev/null || true

# Find first ethernet interface
ETH_IF=""
for iface in /sys/class/net/eth* /sys/class/net/en*; do
    [ -e "$iface" ] || continue
    ETH_IF=$(basename "$iface")
    break
done

if [ -n "$ETH_IF" ]; then
    echo "[autoinstall] Configuring interface: $ETH_IF" > /dev/kmsg 2>/dev/null
    ip link set "$ETH_IF" up
    echo "[autoinstall] Link state: $(cat /sys/class/net/$ETH_IF/operstate 2>/dev/null)" > /dev/kmsg 2>/dev/null
    echo "[autoinstall] MAC: $(cat /sys/class/net/$ETH_IF/address 2>/dev/null)" > /dev/kmsg 2>/dev/null

    # Ensure ISO is mounted (may have been skipped if modules were in initramfs)
    mkdir -p /media/cdrom 2>/dev/null || true
    mountpoint -q /media/cdrom 2>/dev/null || \
        mount -t iso9660 /dev/sr0 /media/cdrom 2>/dev/null || \
        mount -t iso9660 /dev/cdrom /media/cdrom 2>/dev/null || true

    # Check for static IP configuration in installer.yaml on the ISO.
    # The YAML may contain multiple "interfaces:" keys (bonds, bridges, network).
    # Use awk to scan specifically for the network.interfaces block (top-level
    # "interfaces:" at exactly 2-space indent under "network:") and extract the
    # first entry with type=static. This is robust against bond/bridge sections
    # that also contain "interfaces:" keys at deeper indent levels.
    STATIC_CONFIGURED=false
    INSTALLER_YAML="/media/cdrom/configs/installer.yaml"
    if [ -f "$INSTALLER_YAML" ]; then
        # Extract the network.interfaces block: look for top-level "interfaces:"
        # (2-space indent, preceded by "network:" at column 0) and collect
        # entries until the next top-level key. Then grep within that block.
        NET_IFACES_BLOCK=$(awk '
            /^network:/ { innet=1; next }
            innet && /^[a-zA-Z]/ { innet=0 }
            innet && /^  interfaces:/ { inifaces=1; next }
            inifaces && /^  [a-zA-Z]/ { inifaces=0 }
            inifaces && /^[a-zA-Z]/ { inifaces=0 }
            inifaces { print }
        ' "$INSTALLER_YAML" 2>/dev/null)
        IFACE_TYPE=$(echo "$NET_IFACES_BLOCK" | grep "type:" | head -1 | sed 's/.*type:\s*//' | tr -d ' "')
        if [ "$IFACE_TYPE" = "static" ]; then
            echo "[autoinstall] Static IP configuration detected in installer.yaml" > /dev/kmsg 2>/dev/null

            IPV4_ADDR=$(echo "$NET_IFACES_BLOCK" | grep "ipv4-address:" | head -1 | sed 's/.*ipv4-address:\s*//' | tr -d ' "')
            IPV4_MASK=$(echo "$NET_IFACES_BLOCK" | grep "ipv4-netmask:" | head -1 | sed 's/.*ipv4-netmask:\s*//' | tr -d ' "')
            IPV4_GW=$(echo "$NET_IFACES_BLOCK" | grep "ipv4-gateway:" | head -1 | sed 's/.*ipv4-gateway:\s*//' | tr -d ' "')
            DNS_SERVERS=$(grep -A5 "dns:" "$INSTALLER_YAML" 2>/dev/null | grep -A3 "nameservers:" | grep "^\s*-" | sed 's/.*-\s*//' | tr -d ' "' | tr '\n' ' ')

            if [ -n "$IPV4_ADDR" ] && [ -n "$IPV4_GW" ]; then
                # Calculate CIDR prefix from netmask
                case "$IPV4_MASK" in
                    255.255.255.0)   CIDR="24" ;;
                    255.255.255.128) CIDR="25" ;;
                    255.255.255.192) CIDR="26" ;;
                    255.255.255.224) CIDR="27" ;;
                    255.255.255.240) CIDR="28" ;;
                    255.255.255.248) CIDR="29" ;;
                    255.255.255.252) CIDR="30" ;;
                    255.255.0.0)     CIDR="16" ;;
                    255.0.0.0)       CIDR="8" ;;
                    *)               CIDR="24" ;;
                esac

                echo "[autoinstall] Configuring $ETH_IF: ${IPV4_ADDR}/${CIDR} gw ${IPV4_GW}" > /dev/kmsg 2>/dev/null
                ip addr add "${IPV4_ADDR}/${CIDR}" dev "$ETH_IF" 2>/dev/null || true
                ip route add default via "$IPV4_GW" 2>/dev/null || true

                # Install-time DNS: skip loopback (no resolver in live env)
                # and append IPv4 gateway as fallback so apk can resolve
                # external mirrors. Post-install OS DNS is rewritten later
                # from the original installer.yaml.
                if [ -n "$DNS_SERVERS" ] || [ -n "$IPV4_GW" ]; then
                    : > /etc/resolv.conf
                    for dns in $DNS_SERVERS; do
                        case "$dns" in
                            127.*|::1)
                                echo "[autoinstall] skipping loopback DNS $dns" > /dev/kmsg 2>/dev/null
                                ;;
                            *)
                                echo "nameserver $dns" >> /etc/resolv.conf
                                ;;
                        esac
                    done
                    if [ -n "$IPV4_GW" ]; then
                        echo "nameserver $IPV4_GW" >> /etc/resolv.conf
                    fi
                    if [ ! -s /etc/resolv.conf ]; then
                        echo "nameserver 8.8.8.8" >> /etc/resolv.conf
                    fi
                    echo "[autoinstall] DNS configured (install-time)" > /dev/kmsg 2>/dev/null
                fi

                STATIC_CONFIGURED=true
                echo "[autoinstall] Static network configured successfully" > /dev/kmsg 2>/dev/null
            fi
        fi
    fi

    # Fall back to DHCP only if static config was not applied
    if [ "$STATIC_CONFIGURED" = "false" ]; then
        echo "[autoinstall] No static config, falling back to DHCP" > /dev/kmsg 2>/dev/null
        if command -v udhcpc >/dev/null 2>&1; then
            UDHCPC_SCRIPT=""
            for s in /usr/share/udhcpc/default.script /etc/udhcpc/default.script; do
                [ -x "$s" ] && UDHCPC_SCRIPT="$s" && break
            done
            if [ -n "$UDHCPC_SCRIPT" ]; then
                echo "[autoinstall] Running udhcpc with script: $UDHCPC_SCRIPT" > /dev/kmsg 2>/dev/null
                udhcpc -i "$ETH_IF" -n -t 5 -T 3 -A 3 -s "$UDHCPC_SCRIPT" -v 2>&1 | while read line; do
                    echo "[autoinstall] udhcpc: $line" > /dev/kmsg 2>/dev/null
                done
            else
                echo "[autoinstall] No udhcpc script found, running without script" > /dev/kmsg 2>/dev/null
                udhcpc -i "$ETH_IF" -n -t 5 -T 3 -A 3 -v 2>&1 | while read line; do
                    echo "[autoinstall] udhcpc: $line" > /dev/kmsg 2>/dev/null
                done
            fi
        elif command -v dhcpcd >/dev/null 2>&1; then
            echo "[autoinstall] Running dhcpcd on $ETH_IF..." > /dev/kmsg 2>/dev/null
            dhcpcd -w --timeout 30 "$ETH_IF" 2>/dev/null || true
        fi
    fi

    # Log IP address
    IP_ADDR=$(ip -4 addr show "$ETH_IF" 2>/dev/null | grep -o 'inet [^ ]*' | head -1)
    echo "[autoinstall] Network: $ETH_IF $IP_ADDR" > /dev/kmsg 2>/dev/null
else
    echo "[autoinstall] WARNING: No ethernet interface found" > /dev/kmsg 2>/dev/null
fi

# Post-network modloop mount. On PXE the modloop is served over HTTP and
# only became reachable once the interface above obtained a lease, so this
# is where it actually mounts for diskless nodes. On CD/virtual-media it is
# already mounted and ensure_modloop returns immediately. After mounting we
# reload the essential modules so the device-mapper, ext4 and TPM drivers
# are present before the main installer formats the disk and opens LUKS.
if ensure_modloop; then
    echo "[autoinstall] Loading kernel modules (post-network)..." > /dev/kmsg 2>/dev/null
    load_essential_modules
    mdev -s 2>/dev/null || true
fi

/bin/sh /root/autoinstall.sh
RESULT=$?
echo "[autoinstall] autoinstall.sh exited with code: ${RESULT}" > /dev/kmsg 2>/dev/null
echo "[autoinstall] autoinstall.sh exited with code: ${RESULT}"

# If running as PID 1, poweroff directly since there's no init to return to
if [ $$ -eq 1 ]; then
    echo "[autoinstall] running as PID 1, calling poweroff" > /dev/kmsg 2>/dev/null
    exec poweroff -f
fi
`
	wrapperPath := filepath.Join(overlayDir, "root", "run-autoinstall.sh")
	if err := os.WriteFile(wrapperPath, []byte(wrapperScript), 0755); err != nil {
		return &WrappedError{Msg: "failed to write wrapper script", Err: err}
	}

	c.logger.Debug("Autoinstall overlay created", "path", overlayDir)
	return nil
}

// patchInitScript patches Alpine's init script to copy overlay to sysroot
// autoinstallInjectionMarker opens the block patchInitScript adds to init.
const autoinstallInjectionMarker = "# Autoinstall injection"

func (c *Customizer) patchInitScript(initramfsDir string) error {
	initPath := filepath.Join(initramfsDir, "init")
	if _, err := os.Stat(initPath); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("init script not found: %s", initPath)}
	}

	patchContent := `
` + autoinstallInjectionMarker + ` - copy overlay to sysroot and use BusyBox init with custom inittab
if grep -q alpine_start=autoinstall /proc/cmdline 2>/dev/null; then
  echo "Applying autoinstall configuration..." > /dev/kmsg
  mkdir -p "$sysroot"/root "$sysroot"/etc
  if [ -f /overlay/root/autoinstall.sh ]; then
    cp -f /overlay/root/autoinstall.sh "$sysroot"/root/autoinstall.sh && echo "autoinstall.sh copied" > /dev/kmsg || echo "autoinstall.sh copy failed" > /dev/kmsg
    chmod +x "$sysroot"/root/autoinstall.sh
  fi
  if [ -f /overlay/root/run-autoinstall.sh ]; then
    cp -f /overlay/root/run-autoinstall.sh "$sysroot"/root/run-autoinstall.sh && echo "run-autoinstall.sh copied" > /dev/kmsg || echo "run-autoinstall.sh copy failed" > /dev/kmsg
    chmod +x "$sysroot"/root/run-autoinstall.sh
  fi
  # Install custom inittab that runs OpenRC sysinit/boot then autoinstall
  # Using BusyBox init ensures /dev, /proc, /sys are properly set up
  if [ -f /overlay/etc/inittab ]; then
    cp -f /overlay/etc/inittab "$sysroot"/etc/inittab && echo "inittab installed" > /dev/kmsg || echo "inittab copy failed" > /dev/kmsg
  fi
  echo "autoinstall configured via inittab" > /dev/kmsg
fi
`

	// Write patch content to temporary file
	patchPath := filepath.Join(initramfsDir, "patch.txt")
	if err := os.WriteFile(patchPath, []byte(strings.TrimSpace(patchContent)), 0644); err != nil {
		return &WrappedError{Msg: "failed to write patch content", Err: err}
	}
	defer os.Remove(patchPath)

	// Use awk to inject patch after setup_inittab_console function
	// Read patch content from file to avoid quoting issues
	awkScript := `
/^setup_inittab_console$/ && !injected {
    print;
    print "";
    while ((getline line < "` + patchPath + `") > 0) {
        print line;
    }
    close("` + patchPath + `");
    print "";
    injected=1;
    next;
}
{ print }
`

	// Create temporary awk script
	awkScriptPath := filepath.Join(initramfsDir, "patch.awk")
	if err := os.WriteFile(awkScriptPath, []byte(awkScript), 0644); err != nil {
		return &WrappedError{Msg: "failed to write awk script", Err: err}
	}
	defer os.Remove(awkScriptPath)

	// Apply patch using awk
	cmd := exec.Command("awk", "-f", awkScriptPath, initPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &CommandOutputError{Msg: "failed to patch init script", Err: err, Detail: fmt.Sprintf("\nOutput: %s", string(output))}
	}
	// awk passes an init without the anchor through unchanged: that init
	// would boot a live system that never installs.
	if !strings.Contains(string(output), autoinstallInjectionMarker) {
		return &MessageError{Msg: "autoinstall patch: setup_inittab_console call not found in init (Alpine init layout changed?)"}
	}

	// Write patched init
	if err := os.WriteFile(initPath, output, 0755); err != nil {
		return &WrappedError{Msg: "failed to write patched init", Err: err}
	}

	c.logger.Debug("Init script patched successfully")
	return nil
}

// patchConfigureIPCarrierWait inserts a link-carrier wait into Alpine's init
// configure_ip() so DHCP waits for the NIC PHY to negotiate carrier before
// broadcasting. Alpine brings the interface up with `ip link set ... up` and
// immediately runs udhcpc; on bare-metal igb/ixgbe NICs the PHY takes a few
// seconds to establish carrier, so the udhcpc broadcast goes out before the
// link is ready, no lease is obtained, and the subsequent modloop= HTTP fetch
// fails — dropping the node to the Alpine emergency shell. We splice a bounded
// (30s) carrier-wait between the link-up and the udhcpc call.
func (c *Customizer) patchConfigureIPCarrierWait(initramfsDir string) error {
	initPath := filepath.Join(initramfsDir, "init")
	data, err := os.ReadFile(initPath)
	if err != nil {
		return &WrappedError{Msg: "failed to read init for carrier-wait patch", Err: err}
	}

	// The configure_ip() DHCP branch (two-tab indented) in Alpine's init.
	// Stock Alpine brings up a single selected interface and runs udhcpc once.
	// On a multi-NIC bare-metal node Alpine's "first interface up" selection
	// favours a fast-linking 10GbE port that has no DHCP server, while the
	// provisioning igb/ixgbe NIC is still negotiating carrier — so the single
	// attempt never gets a lease, apk can't fetch the base system, and the
	// node drops to the initramfs emergency shell. Replace the single attempt
	// with a bounded loop that brings up every ethernet and tries DHCP on each
	// carrier-up NIC until one obtains a lease.
	const oldBlock = "\t\t$MOCK ip link set dev \"$iface\" up\n" +
		"\t\t$MOCK udhcpc -i \"$iface\" -f -q"
	const newBlock = "\t\t# trusted-platform: multi-NIC DHCP (see iso/customize.go)\n" +
		"\t\tfor _tpif in $(ethernets); do $MOCK ip link set dev \"$_tpif\" up; done\n" +
		"\t\t_tp_ok=1; _tp_n=0\n" +
		"\t\twhile [ \"$_tp_ok\" != 0 ] && [ \"$_tp_n\" -lt 30 ]; do\n" +
		"\t\t\tfor _tpif in $(ethernets); do\n" +
		"\t\t\t\t[ \"$(cat /sys/class/net/\"$_tpif\"/carrier 2>/dev/null)\" = 1 ] || continue\n" +
		"\t\t\t\tif $MOCK udhcpc -i \"$_tpif\" -f -q -n -t 2 -T 2; then iface=\"$_tpif\"; _tp_ok=0; break; fi\n" +
		"\t\t\tdone\n" +
		"\t\t\t[ \"$_tp_ok\" = 0 ] && break\n" +
		"\t\t\tsleep 1; _tp_n=$((_tp_n+1))\n" +
		"\t\tdone\n" +
		"\t\t[ \"$_tp_ok\" = 0 ]"

	if !strings.Contains(string(data), oldBlock) {
		return &MessageError{Msg: "carrier-wait patch: configure_ip udhcpc block not found in init (Alpine init layout changed?)"}
	}

	patched := strings.Replace(string(data), oldBlock, newBlock, 1)
	if err := os.WriteFile(initPath, []byte(patched), 0755); err != nil {
		return &WrappedError{Msg: "failed to write carrier-wait-patched init", Err: err}
	}

	c.logger.Info("Patched configure_ip with link-carrier wait")
	return nil
}

// injectUdhcpcScript copies busybox's udhcpc default.script (and udhcpc.conf)
// out of the ISO's busybox apk into the initramfs. Alpine's ISO initramfs-lts
// is built for CD/USB installs and omits udhcpc's apply-script; without it
// configure_ip's `[ ! -e /usr/share/udhcpc/default.script ]` guard fails, so
// PXE DHCP obtains a lease but never configures the interface and the node
// drops to the emergency shell. apk archives are concatenated gzip tar
// streams, which GNU tar -z reads directly.
func (c *Customizer) injectUdhcpcScript(ctx context.Context, initramfsDir string) error {
	pattern := filepath.Join(c.config.Directories.ISO, "apks", "*", "busybox-*.apk")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to search for busybox apk (%s)", pattern), Err: err}
	}
	if len(matches) == 0 {
		return &MessageError{Msg: fmt.Sprintf("busybox apk not found under %s for udhcpc script injection", pattern)}
	}
	apkPath := matches[0]

	cmd := exec.CommandContext(ctx, "tar", "xzf", apkPath, "-C", initramfsDir,
		"usr/share/udhcpc/default.script", "etc/udhcpc/udhcpc.conf")
	if out, err := cmd.CombinedOutput(); err != nil {
		return &CommandOutputError{Msg: fmt.Sprintf("failed to extract udhcpc script from %s", apkPath), Err: err, Detail: fmt.Sprintf("\nOutput: %s", string(out))}
	}

	scriptPath := filepath.Join(initramfsDir, "usr", "share", "udhcpc", "default.script")
	if _, statErr := os.Stat(scriptPath); statErr != nil {
		return &WrappedError{Msg: fmt.Sprintf("udhcpc default.script missing after extraction from %s", apkPath), Err: statErr}
	}
	if err := os.Chmod(scriptPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to chmod udhcpc default.script", Err: err}
	}

	c.logger.Info("Injected udhcpc default.script into initramfs", "apk", filepath.Base(apkPath))
	return nil
}

// verifyInitramfs verifies that the repacked initramfs contains expected files
func (c *Customizer) verifyInitramfs(initramfsPath string) error {
	// Create temporary directory for verification
	verifyDir := filepath.Join(c.config.Directories.Work, "verify-initramfs")
	if err := os.RemoveAll(verifyDir); err != nil {
		return &WrappedError{Msg: "failed to remove old verify dir", Err: err}
	}
	if err := os.MkdirAll(verifyDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create verify dir", Err: err}
	}
	defer os.RemoveAll(verifyDir)

	// Extract initramfs
	if err := extractInitramfs(initramfsPath, verifyDir); err != nil {
		return &WrappedError{Msg: "failed to extract for verification", Err: err}
	}

	// Check for expected files
	expectedFiles := []string{
		"overlay/etc/inittab",
		"overlay/root/autoinstall.sh",
		"overlay/root/run-autoinstall.sh",
	}

	for _, file := range expectedFiles {
		path := filepath.Join(verifyDir, file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return &MessageError{Msg: fmt.Sprintf("verification failed: %s not found in initramfs", file)}
		}
	}

	c.logger.Debug("Initramfs verification passed")
	return nil
}

// PXEPayloadFunction is the autoinstall's fetch_install_payload BASE CDROM:
// it rebuilds the CD an installer booted over the network does not have,
// from the media set it booted. BASE/payload.list names every entry
// (<sha256> <kind> <dest> <src>, container.PayloadEntry); each is fetched
// from BASE/<src>, checked against its digest, and placed at CDROM/<dest>
// (kind file) or extracted into it (kind tar). Anything missing, corrupt or
// escaping CDROM ends the install through error(): an installer run with a
// partial payload fails later and less legibly — the gatewayd that was once
// left off a hard-coded list aborted every gateway install after it had
// already partitioned the disk. The list is the build's, so nothing the
// build ships can be forgotten here.
const PXEPayloadFunction = `fetch_install_payload() {
    _base="$1"
    _cdrom="$2"
    log "Fetching the install payload from $_base (PXE has no CD)"
    mkdir -p "$_cdrom"
    _work="$(mktemp -d)" || error "cannot create a work directory"
    wget -q -O "$_work/payload.list" "$_base/payload.list" || error "cannot fetch $_base/payload.list"
    _count=0
    while read -r _sum _kind _dest _src; do
        case "$_sum" in ""|"#"*) continue ;; esac
        [ -n "$_src" ] || error "malformed payload entry for $_dest"
        case "/$_dest/$_src/" in */../*|*//*) error "payload entry $_dest escapes the CD" ;; esac
        _tmp="$_work/entry"
        wget -q -O "$_tmp" "$_base/$_src" || error "cannot fetch payload $_src"
        echo "$_sum  $_tmp" | sha256sum -c - >/dev/null 2>&1 || error "payload $_src does not match its digest"
        case "$_kind" in
            file)
                mkdir -p "$_cdrom/$(dirname "$_dest")"
                mv "$_tmp" "$_cdrom/$_dest"
                case "$_dest" in platformd-bin/*) chmod +x "$_cdrom/$_dest" ;; esac
                ;;
            tar)
                mkdir -p "$_cdrom/$_dest"
                tar -xzf "$_tmp" -C "$_cdrom/$_dest" || error "cannot extract payload $_src"
                rm -f "$_tmp"
                ;;
            *)
                error "payload entry $_dest has unknown kind $_kind"
                ;;
        esac
        _count=$((_count + 1))
    done < "$_work/payload.list"
    rm -rf "$_work"
    [ -x "$_cdrom/platformd-bin/platformctl" ] || error "the payload provided no platformd-bin/platformctl"
    : > "$_cdrom/.payload-complete"
    log "Install payload in place ($_count entries)"
}`

// NodeConfigFunction is the autoinstall's stage_node_config CONFIG CDROM CA:
// on a CD rebuilt from a media set's payload (.payload-complete), the config
// the install runs with — the node's own, fetched per MAC — replaces the
// set's baked configs/installer.yaml, and the fetched CA bundle its
// ca-bundle.pem: the installer copies both onto the target as the installed
// system's runtime config, and a node must never come up with the generic
// one. A failure ends the install. A real CD (virtual media) is read-only
// and left alone.
const NodeConfigFunction = `stage_node_config() {
    _config="$1"
    _cdrom="$2"
    _ca="$3"
    [ -f "$_cdrom/.payload-complete" ] || return 0
    [ -n "$_config" ] || return 0
    [ "$_config" = "$_cdrom/configs/installer.yaml" ] && return 0
    mkdir -p "$_cdrom/configs"
    cp -f "$_config" "$_cdrom/configs/installer.yaml" || error "cannot stage the node's platform config for the installed system"
    log "Staged the node's platform config to $_cdrom/configs/installer.yaml"
    if [ -f "$_ca" ]; then
        cp -f "$_ca" "$_cdrom/configs/ca-bundle.pem" || error "cannot stage the node's CA bundle"
        log "Staged the node's CA bundle to $_cdrom/configs/ca-bundle.pem"
    fi
}`

// nbdNodeShell defines platformd_nbd_node CMDLINE, which returns 0 when the
// command line file CMDLINE selects the diskless-nbd boot model
// (platform_boot_model=diskless-nbd as a whole word) and 1 otherwise,
// including when the file cannot be read. disklessroot's platformd_boot_model
// cannot answer this: pkg/bootstrap/nbd, which owns the model, imports it.
const nbdNodeShell = `platformd_nbd_node() {
    for _arg in $(cat "$1" 2>/dev/null); do
        if [ "$_arg" = "` + disklessroot.ParamBootModel + `=` + nbd.BootModel + `" ]; then
            return 0
        fi
    done
    return 1
}
`

// nbdInstallTargetFunction is the autoinstall's nbd_install_target CMDLINE:
// on a diskless-nbd node (platform_boot_model=diskless-nbd in the live
// command line file CMDLINE) it prints /dev/nbd0, the NBD export the install
// goes to, and returns 0; on any other node it prints nothing and returns 1,
// and the local-disk scan runs as before. The node may have no local disk,
// and the installer forces /dev/nbd0 for this model anyway, refusing before
// the TPM or a disk is touched when the export is not attached; the
// installer, not this function, validates the rest of the command line.
const nbdInstallTargetFunction = nbdNodeShell + `nbd_install_target() {
    platformd_nbd_node "$1" || return 1
    echo /dev/nbd0
}`

// buildAutoinstallScript generates the autoinstall script content
func (c *Customizer) buildAutoinstallScript() string {
	var sb strings.Builder

	sb.WriteString(`#!/bin/sh
# Automated installation script with platformd integration
set -e

INSTALL_LOG="/tmp/autoinstall-debug.log"
log() {
    echo "[autoinstall] $1" 2>/dev/null || true
    echo "[autoinstall] $1" >> "$INSTALL_LOG" 2>/dev/null || true
    echo "[autoinstall] $1" > /dev/kmsg 2>/dev/null || true
    sync
}

# The console run-autoinstall.sh hands this script can refuse writes: the
# ISO test install's guest refused the first one, and set -e ended the
# install right after its script-start checkpoint. log() keeps every line in
# $INSTALL_LOG and the kernel log, so a console that refuses writes gets
# none: a failed console write must never stop the install.
if ! echo "[autoinstall] autoinstall.sh started" 2>/dev/null; then
    exec >/dev/null 2>&1
fi

# Log kernel cmdline immediately for debugging
echo "=== KERNEL CMDLINE ===" >> "$INSTALL_LOG"
cat /proc/cmdline >> "$INSTALL_LOG" 2>/dev/null
echo "=== NETWORK STATE ===" >> "$INSTALL_LOG"
ip addr >> "$INSTALL_LOG" 2>/dev/null
echo "=== ISO BUILD TIMESTAMP ===" >> "$INSTALL_LOG"
date >> "$INSTALL_LOG" 2>/dev/null

error() {
    echo "[autoinstall] ERROR: $1" >&2 || true
    echo "[autoinstall] ERROR: $1" > /dev/kmsg 2>/dev/null || true
    sync
    exit 1
}

# resolve_platform_hostname extracts os.hostname from the embedded
# platformd config file. The config is the single source of truth for
# every node-specific field; the installer reads it from the ISO at
# /etc/platformd/config.yaml (copied in by the iso customizer) or from
# the fetch cache in dynamic-config mode (/etc/platformd/config.yaml
# written by the dynamic-config fetcher before autoinstall runs).
#
# Returns the hostname string on stdout, empty string if not set.
# Falls back to the Alpine live env's hostname command only when the
# config file is missing entirely — which only happens in development
# or misconfigured builds.
#
# Shell-native YAML scan: looks for the first indented "hostname:" key
# inside the top-level "os:" block. Handles quoted and unquoted values.
# Avoids python/yq dependencies because the live installer environment
# has neither.
resolve_platform_hostname() {
    # Priority -1: per-MAC hostname published by the orchestrator to the
    # pxeboot HTTP server at /config/mac/<mac>/hostname. Overrides the
    # shared-ISO baked-in value because a single ISO is used for all
    # nodes in a deployment. The orchestrator knows each node's target
    # hostname from bootstrap.yaml and publishes it under every MAC the
    # BMC enumerated, so this hit succeeds regardless of which NIC eth0
    # maps to in the live ISO. Best-effort with short timeouts: if the
    # sink is unreachable we fall through to the cmdline/YAML paths
    # and the node gets the generic baked hostname.
    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep -h '^server-identifier\|^dhcp-server-identifier' /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease* 2>/dev/null | tail -1 | sed 's/.*identifier //; s/[ ;].*//')
        if [ -z "$DHCP_SERVER" ]; then
            DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        fi
        [ -n "$DHCP_SERVER" ] && SINK="${DHCP_SERVER}:8080"
    fi
    if [ -n "$SINK" ]; then
        # Iterate EVERY local eth*/en* interface and try each MAC against
        # the orchestrator's per-MAC hostname endpoint. Multi-NIC hosts
        # (common: Supermicro X10 has up to 4 onboard + add-in cards)
        # may have a primary NIC whose MAC differs from whatever was
        # hand-entered in bootstrap.yaml. The orchestrator stages the
        # hostname under every MAC it knows, so the first MAC that
        # matches wins. Without this loop a node with a different
        # primary-NIC MAC than the YAML-configured MAC never finds its
        # per-node hostname and falls back to the generic baked value.
        for iface in /sys/class/net/eth* /sys/class/net/en*; do
            [ -e "$iface" ] || continue
            MAC_RAW=$(cat "$iface/address" 2>/dev/null)
            [ -n "$MAC_RAW" ] || continue
            MAC_LC=$(echo "$MAC_RAW" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-f]//g')
            [ ${#MAC_LC} -eq 12 ] || continue
            MAC_PATH=$(echo "$MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3-\4-\5-\6/')
            if command -v curl >/dev/null 2>&1; then
                HN_MAC=$(curl --silent --max-time 5 "http://${SINK}/config/mac/${MAC_PATH}/hostname" 2>/dev/null)
            else
                HN_MAC=$(wget -qO- -T 5 "http://${SINK}/config/mac/${MAC_PATH}/hostname" 2>/dev/null)
            fi
            HN_MAC=$(echo "$HN_MAC" | tr -d '[:space:]')
            if [ -n "$HN_MAC" ] && [ "${HN_MAC:0:1}" != "<" ]; then
                echo "[autoinstall] resolved hostname from orchestrator config: ${HN_MAC} (mac=${MAC_PATH})" > /dev/kmsg 2>/dev/null || true
                echo "$HN_MAC"
                return 0
            fi
        done
    fi

    # Priority 0: kernel cmdline platform_hostname=<value>. Baked into
    # the GRUB cmdline at ISO-build time from the merged platformd
    # config's os.hostname field. /proc/cmdline is always readable, no
    # filesystem mounts or YAML parsing needed — the most robust path.
    for param in $(cat /proc/cmdline 2>/dev/null); do
        case "$param" in
            platform_hostname=*)
                HN_CMDLINE="${param#platform_hostname=}"
                if [ -n "$HN_CMDLINE" ]; then
                    echo "$HN_CMDLINE"
                    return 0
                fi
                ;;
        esac
    done

    # Fallback candidate YAML paths, in preference order:
    # 1. The installer.Config yaml in the overlay — populated by
    #    buildInstallerConfig with hostname sourced from the merged
    #    platformd config. This is the canonical runtime path under
    #    the live Alpine environment.
    # 2. The merged platformd config on the CD mount (legacy/fallback).
    CFG="/etc/platformd/install.yaml"
    [ ! -f "$CFG" ] && CFG="/etc/platformd/config.yaml"
    [ ! -f "$CFG" ] && CFG="/media/cdrom/configs/installer.yaml"
    [ ! -f "$CFG" ] && CFG="/mnt/cdrom/configs/installer.yaml"
    if [ -f "$CFG" ]; then
        # awk scan: track when we enter the "os:" block at indent 0,
        # then emit the first indented "hostname:" value we see before
        # we hit another top-level key.
        HN=$(awk '
            /^os:[[:space:]]*$/ { inos = 1; next }
            /^[a-zA-Z]/        { if (inos) { inos = 0 } }
            inos && /^[[:space:]]+hostname:/ {
                sub(/^[[:space:]]+hostname:[[:space:]]*/, "")
                gsub(/["'"'"']/, "")
                sub(/[[:space:]]+$/, "")
                print
                exit
            }
        ' "$CFG" 2>/dev/null)
        if [ -n "$HN" ]; then
            echo "$HN"
            return 0
        fi
    fi
    # Final fallback: Alpine live env hostname command. Usually returns
    # (none) or localhost; the caller normalizes those to "unknown".
    hostname 2>/dev/null
}

# fetch_orchestrator_ca_bundle pulls the control-plane CA bundle from the
# orchestrator's per-MAC config endpoint and saves it to
# /tmp/cp-ca-bundle.pem. Called BEFORE the installer runs so the
# post-install chroot can install it into the system trust store.
#
# The orchestrator stages the bundle at /config/mac/<MAC>/ca-bundle.pem
# for every non-CP node it provisions. Without this delivery, GW and
# compute nodes boot with no trust anchor for the CP's local CA, which
# makes their first ACME enrollment attempt fail with
# "x509: certificate signed by unknown authority" — they then fall
# back to issuing their own local CA and never enroll with the cluster.
#
# Mirrors resolve_platform_hostname's MAC iteration loop so multi-NIC
# hosts (Supermicro X10 onboard quad NIC + add-in cards) find their
# orchestrator-staged value regardless of which interface enumerates
# as eth0. Best-effort: failure here logs a warning and the install
# continues — the runtime BootstrapTrust path can still recover via
# DANE/Noise/SPKI when configured.
fetch_orchestrator_ca_bundle() {
    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep -h '^server-identifier\|^dhcp-server-identifier' /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease* 2>/dev/null | tail -1 | sed 's/.*identifier //; s/[ ;].*//')
        if [ -z "$DHCP_SERVER" ]; then
            DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        fi
        [ -n "$DHCP_SERVER" ] && SINK="${DHCP_SERVER}:8080"
    fi
    if [ -z "$SINK" ]; then
        echo "[autoinstall] no orchestrator sink resolved - CA bundle delivery skipped" > /dev/kmsg 2>/dev/null || true
        return 1
    fi

    # Iterate every local NIC's MAC and try the orchestrator-staged
    # bundle path. First successful fetch wins.
    for iface in /sys/class/net/eth* /sys/class/net/en*; do
        [ -e "$iface" ] || continue
        MAC_RAW=$(cat "$iface/address" 2>/dev/null)
        [ -n "$MAC_RAW" ] || continue
        MAC_LC=$(echo "$MAC_RAW" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-f]//g')
        [ ${#MAC_LC} -eq 12 ] || continue
        MAC_PATH=$(echo "$MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3-\4-\5-\6/')
        URL="http://${SINK}/config/mac/${MAC_PATH}/ca-bundle.pem"
        if command -v curl >/dev/null 2>&1; then
            curl --silent --show-error --max-time 10 --fail -o /tmp/cp-ca-bundle.pem.tmp "$URL" 2>/dev/null
            RC=$?
        elif command -v wget >/dev/null 2>&1; then
            wget --quiet --timeout=10 -O /tmp/cp-ca-bundle.pem.tmp "$URL" 2>/dev/null
            RC=$?
        else
            return 1
        fi
        if [ "$RC" -eq 0 ] && [ -s /tmp/cp-ca-bundle.pem.tmp ]; then
            # Sanity check — must contain a PEM CERTIFICATE block, not
            # an HTML 404 page from a misconfigured pxeboot endpoint.
            if grep -q "BEGIN CERTIFICATE" /tmp/cp-ca-bundle.pem.tmp; then
                mv /tmp/cp-ca-bundle.pem.tmp /tmp/cp-ca-bundle.pem
                echo "[autoinstall] fetched orchestrator CA bundle from ${URL} ($(wc -c < /tmp/cp-ca-bundle.pem) bytes)" > /dev/kmsg 2>/dev/null || true
                return 0
            fi
        fi
        rm -f /tmp/cp-ca-bundle.pem.tmp
    done
    echo "[autoinstall] no orchestrator CA bundle staged for any local MAC - skipped" > /dev/kmsg 2>/dev/null || true
    return 1
}

# fetch_orchestrator_spki_pin pulls the orchestrator-staged SPKI pin
# (base64-std SHA-256 of the CP CA's SPKI) from the per-MAC config
# endpoint and saves it to /tmp/cp-spki-pin. The post-install mount
# block writes it into /etc/trusted-platform/bootstrap-spki-pin so the
# platform's BootstrapTrust SPKI strategy has a value to pin against.
#
# This is the parallel "trust anchor" delivery path to ca-bundle.pem.
# The bundle path is preferred when it succeeds (no per-request DNS
# round-trip on every TLS handshake), but the pin path survives in
# scenarios where the orchestrator HTTP endpoint can serve TXT-style
# values but not large binary bundles (rare but historically real on
# embedded CGI stacks). They are independent and either is sufficient.
fetch_orchestrator_spki_pin() {
    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep -h '^server-identifier\|^dhcp-server-identifier' /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease* 2>/dev/null | tail -1 | sed 's/.*identifier //; s/[ ;].*//')
        if [ -z "$DHCP_SERVER" ]; then
            DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        fi
        [ -n "$DHCP_SERVER" ] && SINK="${DHCP_SERVER}:8080"
    fi
    [ -z "$SINK" ] && return 1

    for iface in /sys/class/net/eth* /sys/class/net/en*; do
        [ -e "$iface" ] || continue
        MAC_RAW=$(cat "$iface/address" 2>/dev/null)
        [ -n "$MAC_RAW" ] || continue
        MAC_LC=$(echo "$MAC_RAW" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-f]//g')
        [ ${#MAC_LC} -eq 12 ] || continue
        MAC_PATH=$(echo "$MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3-\4-\5-\6/')
        URL="http://${SINK}/config/mac/${MAC_PATH}/bootstrap-spki-pin"
        if command -v curl >/dev/null 2>&1; then
            PIN=$(curl --silent --show-error --max-time 5 --fail "$URL" 2>/dev/null)
        elif command -v wget >/dev/null 2>&1; then
            PIN=$(wget --quiet --timeout=5 -O- "$URL" 2>/dev/null)
        else
            return 1
        fi
        PIN=$(echo "$PIN" | tr -d '[:space:]')
        # Sanity check: base64-encoded SHA-256 is exactly 44 chars and
        # matches [A-Za-z0-9+/]{43}=. Reject anything else (HTML 404,
        # garbage, empty body) so we never persist a malformed pin.
        case "$PIN" in
            ?????????????????????????????????????????????) ;;
            *) continue ;;
        esac
        echo "$PIN" > /tmp/cp-spki-pin
        echo "[autoinstall] fetched orchestrator SPKI pin from ${URL} (${#PIN} chars)" > /dev/kmsg 2>/dev/null || true
        return 0
    done
    echo "[autoinstall] no orchestrator SPKI pin staged for any local MAC - skipped" > /dev/kmsg 2>/dev/null || true
    return 1
}

# upload_install_log uploads /tmp/install.log to the bootstrap container's
# HTTP forensic sink. Resolves the sink in this order:
#   1. Kernel cmdline platform_debug_sink=host:port
#   2. The DHCP server IP from the dhclient lease (the bootstrap container
#      IS the DHCP server in our deployment, so this is always reachable)
#   3. The default gateway as a last resort
# Best-effort: a failed upload logs a warning and returns 0 so the
# surrounding cleanup continues unchanged.
upload_install_log() {
    upload_install_log_with_code "$?"
}

# upload_install_log_with_code is the implementation. The trap calls this
# directly with the exit code captured BEFORE upload_checkpoint runs, so we
# don't lose the original install exit code in the postmortem.
upload_install_log_with_code() {
    INSTALL_EXIT_CODE="$1"
    [ -z "$INSTALL_EXIT_CODE" ] && INSTALL_EXIT_CODE=0
    set +e

    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep -h '^server-identifier\|^dhcp-server-identifier' /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease* 2>/dev/null | tail -1 | sed 's/.*identifier //; s/[ ;].*//')
        if [ -z "$DHCP_SERVER" ]; then
            DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        fi
        if [ -n "$DHCP_SERVER" ]; then
            SINK="${DHCP_SERVER}:8080"
        fi
    fi

    if [ -z "$SINK" ]; then
        echo "[autoinstall] no upload sink resolved - install.log will NOT be uploaded" > /dev/kmsg 2>/dev/null || true
        set -e
        return $INSTALL_EXIT_CODE
    fi

    # Identifier for the upload path. Primary: MAC of the first usable
    # ethernet interface (stable, always-known, survives the generic
    # "server" hostname baked into shared ISOs). Fallback: resolved
    # platform hostname. MAC beats hostname because the orchestrator
    # side knows each node's MAC from bootstrap.yaml but has no way to
    # know which generic hostname a shared ISO baked in.
    MAC_RAW=""
    for iface in /sys/class/net/eth* /sys/class/net/en*; do
        [ -e "$iface" ] || continue
        MAC_RAW=$(cat "$iface/address" 2>/dev/null)
        [ -n "$MAC_RAW" ] && break
    done
    MAC_LC=$(echo "$MAC_RAW" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-f]//g')
    # Format as aa-bb-cc-dd-ee-ff when we have exactly 12 hex chars.
    MAC_PATH=""
    if [ ${#MAC_LC} -eq 12 ]; then
        MAC_PATH=$(echo "$MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3-\4-\5-\6/')
    fi

    HOSTNAME_LC=$(resolve_platform_hostname)
    HOSTNAME_LC=$(echo "$HOSTNAME_LC" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.\-]/-/g')
    case "$HOSTNAME_LC" in
        ""|"-none-"|"none"|"localhost"|"alpine"|"alpinelinux") HOSTNAME_LC="unknown" ;;
    esac

    # Primary upload URL (MAC-keyed when we have one) and fallback
    # (hostname-keyed). Both are attempted — the MAC path is what the
    # orchestrator polls; the hostname path is kept for human
    # debugging and backward compat.
    if [ -n "$MAC_PATH" ]; then
        URL="http://${SINK}/installs/mac/${MAC_PATH}/install.log"
    else
        URL="http://${SINK}/installs/${HOSTNAME_LC}/install.log"
    fi
    URL_FALLBACK="http://${SINK}/installs/${HOSTNAME_LC}/install.log"
    echo "[autoinstall] uploading install.log to ${URL} (exit=${INSTALL_EXIT_CODE})" > /dev/kmsg 2>/dev/null || true

    # Append a postmortem manifest with hardware/system context. Invaluable
    # for diagnosing install failures after the live env is gone.
    {
        echo ""
        echo "=== POSTMORTEM MANIFEST ==="
        echo "exit_code: ${INSTALL_EXIT_CODE}"
        echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
        echo "hostname: ${HOSTNAME_LC}"
        echo "kernel_cmdline: $(cat /proc/cmdline 2>/dev/null)"
        echo ""
        echo "--- lsblk ---"
        lsblk 2>&1 || true
        echo ""
        echo "--- ip addr ---"
        ip addr 2>&1 || true
        echo ""
        echo "--- mount ---"
        mount 2>&1 || true
        echo ""
        echo "--- dmesg tail ---"
        dmesg 2>&1 | tail -200 || true
        echo ""
        echo "=== END POSTMORTEM ==="
    } >> /tmp/install.log 2>/dev/null || true

    # Upload to primary URL (MAC-keyed) and, when that differs from the
    # hostname-keyed URL, ALSO upload to the fallback path. The pxeboot
    # HTTP sink accepts both; the orchestrator will find whichever
    # matches its poll path first.
    _upload_one_url() {
        _U="$1"
        if command -v curl >/dev/null 2>&1; then
            curl --silent --show-error --max-time 30 \
                 --request PUT --upload-file /tmp/install.log "${_U}" \
                 > /dev/kmsg 2>&1 || \
                echo "[autoinstall] curl PUT to ${_U} failed (continuing)" > /dev/kmsg 2>/dev/null || true
        else
            BODY_LEN=$(wc -c < /tmp/install.log 2>/dev/null || echo 0)
            HOST_PART="${SINK%:*}"
            PORT_PART="${SINK##*:}"
            # Extract path from URL: strip scheme://host:port prefix.
            _PATH=$(echo "$_U" | sed 's|^[^/]*//[^/]*||')
            {
                printf 'PUT %s HTTP/1.1\r\n' "${_PATH}"
                printf 'Host: %s\r\n' "${SINK}"
                printf 'Content-Length: %s\r\n' "${BODY_LEN}"
                printf 'Connection: close\r\n'
                printf 'Content-Type: text/plain\r\n'
                printf '\r\n'
                cat /tmp/install.log 2>/dev/null
            } | nc -w 30 "${HOST_PART}" "${PORT_PART}" > /dev/kmsg 2>&1 || \
                echo "[autoinstall] nc PUT to ${_U} failed (continuing)" > /dev/kmsg 2>/dev/null || true
        fi
    }

    _upload_one_url "${URL}"
    if [ -n "${URL_FALLBACK}" ] && [ "${URL_FALLBACK}" != "${URL}" ]; then
        _upload_one_url "${URL_FALLBACK}"
    fi

    echo "[autoinstall] upload attempt complete" > /dev/kmsg 2>/dev/null || true
    set -e
    return $INSTALL_EXIT_CODE
}

# upload_checkpoint uploads a tiny heartbeat file to mark that the script
# reached this stage. Used at multiple points (script-start, pre-install,
# post-install, success, failure) so we can pinpoint which stage the install
# is dying at when the full install.log doesn't make it off the box.
upload_checkpoint() {
    CHECKPOINT_NAME="$1"
    set +e

    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep -h '^server-identifier\|^dhcp-server-identifier' /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease* 2>/dev/null | tail -1 | sed 's/.*identifier //; s/[ ;].*//')
        [ -z "$DHCP_SERVER" ] && DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        [ -n "$DHCP_SERVER" ] && SINK="${DHCP_SERVER}:8080"
    fi
    if [ -z "$SINK" ]; then
        echo "[checkpoint:$CHECKPOINT_NAME] no sink resolved" > /dev/kmsg 2>/dev/null || true
        set -e
        return
    fi

    HOSTNAME_LC=$(resolve_platform_hostname)
    HOSTNAME_LC=$(echo "$HOSTNAME_LC" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.\-]/-/g')
    case "$HOSTNAME_LC" in
        ""|"-none-"|"none"|"localhost"|"alpine"|"alpinelinux") HOSTNAME_LC="unknown" ;;
    esac

    PAYLOAD="checkpoint=$CHECKPOINT_NAME timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date) sink=$SINK"
    URL="http://${SINK}/installs/${HOSTNAME_LC}/checkpoint-${CHECKPOINT_NAME}.txt"
    echo "[checkpoint:$CHECKPOINT_NAME] PUT $URL" > /dev/kmsg 2>/dev/null || true

    if command -v curl >/dev/null 2>&1; then
        printf '%s\n' "$PAYLOAD" | curl --silent --show-error --max-time 10 \
             --request PUT --data-binary @- "${URL}" > /dev/kmsg 2>&1 || \
            echo "[checkpoint:$CHECKPOINT_NAME] curl failed" > /dev/kmsg 2>/dev/null || true
    else
        BODY_LEN=$(printf '%s\n' "$PAYLOAD" | wc -c)
        HOST_PART="${SINK%:*}"
        PORT_PART="${SINK##*:}"
        {
            printf 'PUT /installs/%s/checkpoint-%s.txt HTTP/1.1\r\n' "${HOSTNAME_LC}" "${CHECKPOINT_NAME}"
            printf 'Host: %s\r\n' "${SINK}"
            printf 'Content-Length: %s\r\n' "${BODY_LEN}"
            printf 'Connection: close\r\n'
            printf '\r\n'
            printf '%s\n' "$PAYLOAD"
        } | nc -w 10 "${HOST_PART}" "${PORT_PART}" > /dev/kmsg 2>&1 || \
            echo "[checkpoint:$CHECKPOINT_NAME] nc failed" > /dev/kmsg 2>/dev/null || true
    fi
    set -e
}

# Trap upload + log exit on EVERY exit path. CRITICAL: capture $? FIRST
# and pass it explicitly to upload_install_log, otherwise running
# upload_checkpoint first clobbers $? to its own success exit code (0)
# and the postmortem reports exit_code:0 even when the install actually
# failed. This is exactly the bug that masked the original UKI build
# failure as "successful install" — every checkpoint says success because
# the original install error was overwritten before the trap reached the
# upload step.
#
# set -e is live inside the trap, and a command that fails there replaces
# the script's exit status: an install that succeeded would exit non-zero,
# and a failed one would exit with the wrong code. Every command in the trap
# therefore ends in || true, so the script exits with $TRAP_RC.
trap 'TRAP_RC=$?; upload_checkpoint exit-trap || true; upload_install_log_with_code "$TRAP_RC" || true; echo "[autoinstall] script exiting with status $TRAP_RC" > /dev/kmsg 2>/dev/null || true' EXIT INT TERM

# CHECKPOINT 1: script started. If this never lands on the bootstrap host,
# the autoinstall.sh isn't running at all (init/inittab problem).
upload_checkpoint script-start

log "Starting platformd system installation..."

# Load common bare metal NIC drivers before configuring network
log "Loading kernel modules for bare metal NICs..."
for mod in igb ixgbe e1000e i40e ice mlx5_core bnxt_en; do
    modprobe "$mod" 2>/dev/null && log "  Loaded: $mod" || true
done
sleep 2

# Configure networking from installer.yaml if available
log "Configuring network..."
INSTALLER_YAML="/media/cdrom/configs/installer.yaml"
if [ -f "$INSTALLER_YAML" ]; then
    log "Reading network configuration from installer.yaml..."

    # Extract network interface configuration using grep/sed
    # Check if static IP is configured
    IFACE_TYPE=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "type:" | head -1 | sed 's/.*type:\s*//' | tr -d ' "')

    if [ "$IFACE_TYPE" = "static" ]; then
        log "Static IP configuration detected"

        # Extract network settings
        IFACE_NAME=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "name:" | head -1 | sed 's/.*name:\s*//' | tr -d ' "')
        IPV4_ADDR=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "ipv4-address:" | head -1 | sed 's/.*ipv4-address:\s*//' | tr -d ' "')
        IPV4_MASK=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "ipv4-netmask:" | head -1 | sed 's/.*ipv4-netmask:\s*//' | tr -d ' "')
        IPV4_GW=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "ipv4-gateway:" | head -1 | sed 's/.*ipv4-gateway:\s*//' | tr -d ' "')

        # Extract DNS servers
        DNS_SERVERS=$(grep -A5 "dns:" "$INSTALLER_YAML" | grep -A3 "nameservers:" | grep "^\s*-" | sed 's/.*-\s*//' | tr -d ' "' | tr '\n' ' ')

        # Default interface name if not specified
        [ -z "$IFACE_NAME" ] && IFACE_NAME="eth0"

        if [ -n "$IPV4_ADDR" ] && [ -n "$IPV4_GW" ]; then
            log "Configuring $IFACE_NAME with IP: $IPV4_ADDR, Gateway: $IPV4_GW"

            # Bring up interface
            ip link set "$IFACE_NAME" up 2>/dev/null || true

            # Calculate CIDR prefix from netmask
            # Common netmasks: 255.255.255.0 = /24, 255.255.255.240 = /28
            case "$IPV4_MASK" in
                255.255.255.0)   CIDR="24" ;;
                255.255.255.128) CIDR="25" ;;
                255.255.255.192) CIDR="26" ;;
                255.255.255.224) CIDR="27" ;;
                255.255.255.240) CIDR="28" ;;
                255.255.255.248) CIDR="29" ;;
                255.255.255.252) CIDR="30" ;;
                255.255.254.0)   CIDR="23" ;;
                255.255.252.0)   CIDR="22" ;;
                255.255.248.0)   CIDR="21" ;;
                255.255.240.0)   CIDR="20" ;;
                255.255.0.0)     CIDR="16" ;;
                255.0.0.0)       CIDR="8" ;;
                *)               CIDR="24" ;;  # Default to /24
            esac

            # Configure IP address
            ip addr add "${IPV4_ADDR}/${CIDR}" dev "$IFACE_NAME" 2>/dev/null || true

            # Add default route
            ip route add default via "$IPV4_GW" 2>/dev/null || true

            # Configure DNS for install-time. The post-install platformd
            # commonly points at 127.0.0.1 (local dnsmasq), but the live
            # install environment has no resolver — apk update would fail
            # against external mirrors. Drop loopback during install AND
            # always append the IPv4 gateway as a working fallback so apk
            # can resolve the mirror. The post-install OS gets the original
            # /etc/resolv.conf written from the YAML in a later step.
            if [ -n "$DNS_SERVERS" ] || [ -n "$IPV4_GW" ]; then
                log "Configuring install-time DNS"
                : > /etc/resolv.conf
                for dns in $DNS_SERVERS; do
                    case "$dns" in
                        127.*|::1)
                            log "  skipping loopback DNS $dns (no resolver in live env)"
                            ;;
                        *)
                            echo "nameserver $dns" >> /etc/resolv.conf
                            log "  nameserver $dns"
                            ;;
                    esac
                done
                if [ -n "$IPV4_GW" ]; then
                    echo "nameserver $IPV4_GW" >> /etc/resolv.conf
                    log "  nameserver $IPV4_GW (gateway fallback)"
                fi
                # If still empty (no DNS, no gateway), fall back to public.
                if [ ! -s /etc/resolv.conf ]; then
                    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
                    log "  nameserver 8.8.8.8 (last-resort fallback)"
                fi
            fi

            log "Static network configuration complete"
            ip addr show "$IFACE_NAME"
            ip route show
        else
            log "Incomplete static config, falling back to DHCP"
            setup-interfaces -a 2>&1 || true
            rc-service networking start 2>&1 || true
        fi
    else
        log "DHCP or no network type specified, using auto-configuration"
        setup-interfaces -a 2>&1 || true
        rc-service networking start 2>&1 || true
    fi
else
    log "No installer.yaml found, using DHCP"
    setup-interfaces -a 2>&1 || true
    rc-service networking start 2>&1 || true
fi
sleep 2

# Mount the ISO/CD-ROM if not already mounted
log "Mounting boot media..."
mkdir -p /media/cdrom
if ! mountpoint -q /media/cdrom 2>/dev/null; then
    mount -t iso9660 /dev/sr0 /media/cdrom 2>/dev/null || \
    mount -t iso9660 /dev/cdrom /media/cdrom 2>/dev/null || \
    log "Warning: Could not mount CD-ROM, packages may not be available offline"
fi

`)

	// Repository auto-detect (cdrom > mirror > public). PXE-booted nodes
	// have NO /media/cdrom — they fetch only vmlinuz+initramfs over the
	// network — so the historical local-only repo list left apk with zero
	// repositories after switch_root and the install died installing
	// "0 packages" (no /sbin/init). Detect the boot medium at runtime:
	//   1. local CD repos    — vmedia/CD boot (OFFLINE, original behavior)
	//   2. configured mirror — platform_apk_mirror= kernel cmdline param
	//   3. public dl-cdn     — last-resort fallback for connected networks
	// The Alpine release branch (vMAJOR.MINOR) and the public mirror base
	// are baked from the build config in this small fmt.Sprintf, which
	// carries ONLY literal values (no shell %-expansions) to stay clear of
	// format verbs; the branch falls back to /etc/alpine-release at runtime
	// if empty so the repository URLs are always well-formed.
	fmt.Fprintf(&sb, "ALPINE_BRANCH=%q\nPUBLIC_APK_MIRROR=%q\n",
		alpineReleaseBranch(c.config.Alpine.Version), PublicAlpineMirror)

	sb.WriteString(`if [ -z "$ALPINE_BRANCH" ] && [ -r /etc/alpine-release ]; then
    ALPINE_BRANCH="v$(cut -d. -f1-2 /etc/alpine-release)"
fi

# platform_apk_mirror= is appended to the PXE kernel cmdline by the bootstrap
# server (pkg/bootstrap/container/server.go) and to the ISO grub.cfg when an
# install mirror is configured. It is ABSENT on plain vmedia/CD boots, which
# is exactly why the offline /media/cdrom branch below takes priority.
APK_MIRROR=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_apk_mirror=' | cut -d= -f2- | tail -1)
APK_MIRROR="${APK_MIRROR%/}"

log "Setting up repositories (auto-detect: cdrom > mirror > public)..."
[ -f /etc/apk/repositories ] && cp /etc/apk/repositories /etc/apk/repositories.original 2>/dev/null || true

if [ -d /media/cdrom/apks-prefetch ]; then
    # OFFLINE vmedia/CD boot — use the pre-fetched local repos. These
    # packages are unsigned, so apk must be told to trust them. The stock
    # /media/cdrom/apks lacks lvm2, parted and the rest, so a CD built with
    # --pre-fetch=false takes the mirror branches below.
    log "Using local CD repositories (offline install)"
    cat > /etc/apk/repositories << 'REPOEOF'
/media/cdrom/apks
/media/cdrom/apks-prefetch
REPOEOF
    APK_ALLOW_UNTRUSTED="--allow-untrusted"
elif [ -n "$APK_MIRROR" ]; then
    # Configured install mirror (typical PXE path). Packages are signed by
    # Alpine's keys (present in the live env), so verification stays on.
    log "Using configured APK mirror: $APK_MIRROR ($ALPINE_BRANCH)"
    {
        echo "$APK_MIRROR/$ALPINE_BRANCH/main"
        echo "$APK_MIRROR/$ALPINE_BRANCH/community"
    } > /etc/apk/repositories
    APK_ALLOW_UNTRUSTED=""
else
    # No offline repository and no mirror — fall back to the public Alpine
    # mirror so internet-connected installs still work out of the box.
    log "No offline CD repository and no mirror configured; falling back to public mirror"
    {
        echo "$PUBLIC_APK_MIRROR/$ALPINE_BRANCH/main"
        echo "$PUBLIC_APK_MIRROR/$ALPINE_BRANCH/community"
    } > /etc/apk/repositories
    APK_ALLOW_UNTRUSTED=""
fi
log "Updating package index..."
apk update $APK_ALLOW_UNTRUSTED 2>&1 | tail -5 | while IFS= read -r line; do log "  $line"; done || \
    log "Warning: apk update returned non-zero (continuing with cached index)"
`)

	sb.WriteString(`

# Install required packages from the local pre-fetched repository.
# Capture full apk stderr so failures are debuggable from SOL output.
# Disable set -e around the capture so we can record the exit code and
# stderr instead of letting the script abort silently.
log "Installing disk management tools..."
set +e
APK_OUT=$(apk add --no-cache $APK_ALLOW_UNTRUSTED \
    parted \
    e2fsprogs \
    e2fsprogs-extra \
    lvm2 \
    lvm2-libs \
    dosfstools \
    util-linux \
    kmod \
    kmod-libs \
    device-mapper \
    device-mapper-libs \
    device-mapper-event-libs \
    eudev \
    libaio \
    xz-libs \
    zstd-libs \
    readline \
    ncurses-libs 2>&1)
APK_RC=$?
set -e
if [ $APK_RC -ne 0 ]; then
    log "apk add failed with exit code $APK_RC. Output:"
    printf '%s\n' "$APK_OUT" | while IFS= read -r line; do log "  apk> $line"; done
    log "Repositories configured:"
    cat /etc/apk/repositories | while IFS= read -r line; do log "  repo> $line"; done
    log "Available repos on /media/cdrom:"
    ls -la /media/cdrom/apks/x86_64/ 2>&1 | head -3 | while IFS= read -r line; do log "  apks> $line"; done
    ls -la /media/cdrom/apks-prefetch/x86_64/ 2>&1 | head -3 | while IFS= read -r line; do log "  prefetch> $line"; done
    error "Failed to install required packages (apk exit=$APK_RC)"
fi
log "$(printf '%s' "$APK_OUT" | tail -3)"

# Decompression/compression tooling for the initramfs rebuild step. dracut
# can produce gzip, xz, or zstd initramfs depending on kernel CONFIG_RD_*
# and dracut.conf. The Go installer auto-detects the format from magic
# bytes (pkg/installer/installer.go:detectInitramfsDecompressor) and
# shells out to the matching streaming tool. The full set must be
# available in the live env, otherwise the install dies in the UKI
# extract-modify-repack pipeline with an obscure "command not found".
log "Installing initramfs codec tools (gzip/xz/zstd/lz4/lzop)..."
apk add --no-cache $APK_ALLOW_UNTRUSTED \
    gzip \
    xz \
    zstd \
    lz4 \
    lzop \
    bzip2 || log "Warning: some initramfs codecs may not be available; install will fail if dracut uses them"

# cpio binary in busybox accepts only short options. The Go installer's
# inject step uses cpio -idm (short form), which IS busybox-compatible.
# Future maintainers: do NOT reintroduce GNU long options like
# --no-absolute-filenames which silently break in busybox.

# Install glibc compatibility layer for platformd binary
log "Installing glibc compatibility layer..."
apk add --no-cache $APK_ALLOW_UNTRUSTED gcompat libc6-compat || log "Warning: glibc compatibility packages may not be fully available"

# Install OpenSSL libraries needed by platformd
log "Installing OpenSSL libraries..."
apk add --no-cache $APK_ALLOW_UNTRUSTED openssl-dev || log "Warning: OpenSSL dev package not available"

# Install SoftHSM if the platform config references it
if grep -q "libsofthsm" /media/cdrom/configs/*.yaml 2>/dev/null; then
    log "Platform config references SoftHSM, installing softhsm package..."
    apk add --no-cache $APK_ALLOW_UNTRUSTED softhsm || log "Warning: SoftHSM package not available"
else
    log "SoftHSM not referenced in config, skipping installation"
fi

log "Required packages installed successfully"
sync
sleep 1

# Load required kernel modules for device-mapper and LUKS
log "Loading kernel modules..."
modprobe dm_mod 2>/dev/null || log "Warning: dm_mod may already be loaded"
modprobe dm_crypt 2>/dev/null || log "Warning: dm_crypt may already be loaded"
modprobe loop 2>/dev/null || log "Warning: loop may already be loaded"

# Trigger udev to create device nodes (including /dev/mapper/control)
log "Triggering udev to create device nodes..."
if command -v udevadm >/dev/null 2>&1; then
    udevadm trigger --type=devices 2>/dev/null || true
    udevadm settle --timeout=10 2>/dev/null || true
fi

# Verify /dev/mapper/control exists
if [ -e /dev/mapper/control ]; then
    log "Device-mapper control node ready: /dev/mapper/control"
else
    # Manually create dm control node if udev didn't
    log "Creating device-mapper control node manually..."
    mkdir -p /dev/mapper
    if [ ! -e /dev/mapper/control ]; then
        # Get dm control major/minor from /proc/misc
        DM_MINOR=$(grep -w "device-mapper" /proc/misc 2>/dev/null | awk '{print $1}')
        if [ -n "$DM_MINOR" ]; then
            mknod /dev/mapper/control c 10 "$DM_MINOR" 2>/dev/null || log "Warning: Could not create control node"
        fi
    fi
fi

# Verify device-mapper is working
if [ -e /dev/mapper/control ]; then
    log "Device-mapper ready"
else
    error "Device-mapper control node not available - LUKS will fail"
fi

# PXE install payload. On virtual media the installer reads its assets
# from the CD at /media/cdrom. A node booted over the network has none: the
# media set it booted serves them, and its payload.list says what goes
# where (fetch_install_payload). No-op on virtual media (platform_bin_url
# unset) and done once (the completion marker).
PLATFORM_BIN_URL=""
for param in $(cat /proc/cmdline); do
    case "$param" in
        platform_bin_url=*) PLATFORM_BIN_URL="${param#platform_bin_url=}" ;;
    esac
done
if [ -n "$PLATFORM_BIN_URL" ] && [ ! -f /media/cdrom/.payload-complete ]; then
    # Defensive network bring-up: the wrapper already configured the boot
    # NIC, but retry once if there is no default route yet.
    if ! ip route 2>/dev/null | grep -q default; then
        ip link set eth0 up 2>/dev/null || true
        udhcpc -i eth0 -t 10 -T 3 -n 2>/dev/null || true
    fi
` + PXEPayloadFunction + `
    fetch_install_payload "${PLATFORM_BIN_URL%/}" /media/cdrom
fi

# Find platformctl binary (CLI binary for installation operations)
# Prefer static binary for Alpine/musl compatibility
PLATFORM_BIN=""
if [ -x /usr/bin/platformctl-static ]; then
    PLATFORM_BIN="/usr/bin/platformctl-static"
    log "Found platformctl-static in /usr/bin"
elif [ -x /usr/bin/platformctl ]; then
    PLATFORM_BIN="/usr/bin/platformctl"
    log "Found platformctl in /usr/bin"
elif [ -x /media/cdrom/platformd-bin/platformctl-static ]; then
    PLATFORM_BIN="/media/cdrom/platformd-bin/platformctl-static"
    log "Found platformctl-static on CD-ROM"
elif [ -x /media/cdrom/platformd-bin/platformctl ]; then
    PLATFORM_BIN="/media/cdrom/platformd-bin/platformctl"
    log "Found platformctl on CD-ROM"
else
    error "platformctl binary not found"
fi

# Copy the installer binary (platformctl) AND the bundled platformd (which
# the installer re-exec's into the target rootfs) off the virtual CD into
# tmpfs BEFORE invoking the install. The ATEN virtual CD on Supermicro
# X10 regularly glitches partway through a multi-minute install — we see
# kernel messages like:
#   sr0: rw=0, sector=80, nr_sectors = 4 limit=0
#   bio_check_eod: attempt to access beyond end of device
# When the glitch happens while the Go runtime is paging in code from
# mmap'd text sections that live on the CD, the file-backed pages become
# invalid and the next instruction fetch hits a nonexistent physical
# address, raising SIGBUS (bus error code=0x2). Copying to tmpfs
# eliminates all mmap backing from removable media so the process has
# nothing to lose when the CD hiccups.
TMPFS_BIN_DIR=/run/platformd-bin
mkdir -p "$TMPFS_BIN_DIR"
# Re-mount /run as tmpfs only if it isn't already one. On the Alpine
# live ISO /run is typically already tmpfs; on some minimal setups it
# isn't mounted at all.
if ! mountpoint -q /run 2>/dev/null; then
    mount -t tmpfs -o size=128m tmpfs /run 2>/dev/null || true
fi
log "Copying installer binary to tmpfs to isolate from virtual CD glitches"
if cp -f "$PLATFORM_BIN" "$TMPFS_BIN_DIR/platformctl" 2>&1; then
    chmod +x "$TMPFS_BIN_DIR/platformctl"
    PLATFORM_BIN="$TMPFS_BIN_DIR/platformctl"
    log "Installer binary copied: $PLATFORM_BIN"
else
    log "WARNING: tmpfs copy failed, falling back to CD-ROM binary path"
fi
# Same treatment for the platformd binary that the installer embeds
# into the target UKI. The installer reads this at install time so a
# mid-install CD glitch here also crashes the process.
if [ -f /media/cdrom/platformd-bin/platformd ]; then
    if cp -f /media/cdrom/platformd-bin/platformd "$TMPFS_BIN_DIR/platformd" 2>&1; then
        chmod +x "$TMPFS_BIN_DIR/platformd"
        log "platformd binary copied to tmpfs: $TMPFS_BIN_DIR/platformd"
    fi
fi

# Find installer configuration file
# Priority 1: Fetch from control plane via platform_config= kernel param
# Priority 2: Embedded in ISO at /media/cdrom/configs/installer.yaml
INSTALLER_CONFIG=""

# Read platform_config URL from kernel cmdline
PLATFORM_CONFIG_URL=""
for param in $(cat /proc/cmdline); do
    case "$param" in
        platform_config=*) PLATFORM_CONFIG_URL="${param#platform_config=}" ;;
    esac
done

if [ -n "$PLATFORM_CONFIG_URL" ]; then
    log "Config source: kernel param platform_config=$PLATFORM_CONFIG_URL"

    # Bring up network with DHCP if not already up. Do this BEFORE MAC
    # enumeration so interfaces that are plumbed but not yet up still
    # get their MAC returned by ip link.
    if ! ip addr show eth0 2>/dev/null | grep -q "inet "; then
        log "Bringing up eth0 with DHCP for config fetch..."
        ip link set eth0 up 2>/dev/null
        udhcpc -i eth0 -t 10 -T 3 -n 2>/dev/null || true
    fi

    # Build the list of candidate MACs from all local NICs. The
    # bootstrap orchestrator publishes each node's merged config under
    # EVERY MAC it knows about (YAML + BMC-discovered), so we try each
    # local MAC against the config server and the first 2xx wins.
    #
    # See docs/installer/iso-building.md §Config Delivery Modes
    # (3. Dynamic fetch) for the URL shape and
    # docs/architecture/bootstrap-flow.md §6 for the per-MAC keying
    # rationale.
    CA_BUNDLE="/media/cdrom/configs/ca-bundle.pem"
    WGET_OPTS="--no-check-certificate"
    if [ -f "$CA_BUNDLE" ]; then
        WGET_OPTS="--ca-certificate=$CA_BUNDLE"
        log "Using CA bundle: $CA_BUNDLE"
    fi

    # Normalize the base URL — strip any trailing slash.
    PLATFORM_CONFIG_BASE="${PLATFORM_CONFIG_URL%/}"

    # Detect URL shape. Path-style (e.g. .../config/mac) expects
    #   <base>/<mac-dashed>/installer.yaml
    # Legacy query-style expects
    #   <base>?mac=<mac-colons>
    # Default to path-style since that is the orchestrator's served
    # endpoint (pkg/ipxe/http_server.go).
    for _iface_path in /sys/class/net/eth* /sys/class/net/en*; do
        [ -e "$_iface_path" ] || continue
        _MAC_RAW=$(cat "$_iface_path/address" 2>/dev/null)
        [ -n "$_MAC_RAW" ] || continue
        _MAC_LC=$(echo "$_MAC_RAW" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-f]//g')
        [ ${#_MAC_LC} -eq 12 ] || continue
        _MAC_DASHED=$(echo "$_MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3-\4-\5-\6/')
        _MAC_COLONS=$(echo "$_MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1:\2:\3:\4:\5:\6/')

        # Try path-style (orchestrator convention) first.
        _URL_PATH="${PLATFORM_CONFIG_BASE}/${_MAC_DASHED}/installer.yaml"
        log "Trying config fetch: ${_URL_PATH}"
        if wget -q $WGET_OPTS -O /tmp/platform-config.yaml "$_URL_PATH" 2>&1; then
            if [ -s /tmp/platform-config.yaml ] && ! head -1 /tmp/platform-config.yaml | grep -qE '^<'; then
                INSTALLER_CONFIG="/tmp/platform-config.yaml"
                log "Config fetched from ${_URL_PATH} ($(wc -c < /tmp/platform-config.yaml) bytes)"

                # Also fetch the CP's CA bundle from the same path.
                # Orchestrator publishes it alongside installer.yaml for
                # non-CP nodes so the installer can add the private CA
                # to the OS trust store before first-boot ACME enrollment.
                # 404 is not an error — CP-role nodes don't need it.
                _URL_CA="${PLATFORM_CONFIG_BASE}/${_MAC_DASHED}/ca-bundle.pem"
                if wget -q $WGET_OPTS -O /tmp/ca-bundle.pem "$_URL_CA" 2>&1; then
                    if [ -s /tmp/ca-bundle.pem ] && head -1 /tmp/ca-bundle.pem | grep -q 'BEGIN CERTIFICATE'; then
                        log "CA bundle fetched from ${_URL_CA} ($(wc -c < /tmp/ca-bundle.pem) bytes)"
                    else
                        rm -f /tmp/ca-bundle.pem
                    fi
                fi
                break
            fi
        fi

        # Fall back to legacy query-style for production config-delivery
        # servers that expect ?mac=<colon-mac> (see
        # docs/provisioning/config-delivery.md).
        _URL_QUERY="${PLATFORM_CONFIG_BASE}?mac=${_MAC_COLONS}"
        log "Trying config fetch (legacy): ${_URL_QUERY}"
        if wget -q $WGET_OPTS -O /tmp/platform-config.yaml "$_URL_QUERY" 2>&1; then
            if [ -s /tmp/platform-config.yaml ] && ! head -1 /tmp/platform-config.yaml | grep -qE '^<'; then
                INSTALLER_CONFIG="/tmp/platform-config.yaml"
                log "Config fetched from ${_URL_QUERY} ($(wc -c < /tmp/platform-config.yaml) bytes)"
                break
            fi
        fi
    done

    if [ -z "$INSTALLER_CONFIG" ]; then
        log "WARNING: Dynamic config fetch failed for all local MACs, falling back to embedded config"
    fi
fi

# Priority 1b: Implicit per-MAC config via platform_debug_sink.
# Virtual-media boot has no way to set kernel cmdline params, so the
# orchestrator's per-MAC installer.yaml at the pxeboot HTTP sink
# cannot be reached via platform_config=. When platform_debug_sink is
# set (always true for debug installs) derive the config URL from it
# and retry the per-MAC fetch before falling back to the ISO-baked stub.
if [ -z "$INSTALLER_CONFIG" ]; then
    PLATFORM_DEBUG_SINK=""
    for param in $(cat /proc/cmdline); do
        case "$param" in
            platform_debug_sink=*) PLATFORM_DEBUG_SINK="${param#platform_debug_sink=}" ;;
        esac
    done

    if [ -n "$PLATFORM_DEBUG_SINK" ]; then
        log "Trying per-MAC config via debug sink: http://${PLATFORM_DEBUG_SINK}/config/mac"

        # Reuse the same DHCP bootstrap as Priority 1.
        if ! ip addr show eth0 2>/dev/null | grep -q "inet "; then
            log "Bringing up eth0 with DHCP to reach debug sink..."
            ip link set eth0 up 2>/dev/null
            udhcpc -i eth0 -t 10 -T 3 -n 2>/dev/null || true
        fi

        SINK_BASE="http://${PLATFORM_DEBUG_SINK}/config/mac"
        for _iface_path in /sys/class/net/eth* /sys/class/net/en*; do
            [ -e "$_iface_path" ] || continue
            _MAC_RAW=$(cat "$_iface_path/address" 2>/dev/null)
            [ -n "$_MAC_RAW" ] || continue
            _MAC_LC=$(echo "$_MAC_RAW" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-f]//g')
            [ ${#_MAC_LC} -eq 12 ] || continue
            _MAC_DASHED=$(echo "$_MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3-\4-\5-\6/')

            _URL_PATH="${SINK_BASE}/${_MAC_DASHED}/installer.yaml"
            log "Trying config fetch (debug sink): ${_URL_PATH}"
            if wget -q -O /tmp/platform-config.yaml "$_URL_PATH" 2>&1; then
                if [ -s /tmp/platform-config.yaml ] && ! head -1 /tmp/platform-config.yaml | grep -qE '^<'; then
                    INSTALLER_CONFIG="/tmp/platform-config.yaml"
                    log "Config fetched from ${_URL_PATH} ($(wc -c < /tmp/platform-config.yaml) bytes)"

                    # Also fetch matching CA bundle (best-effort).
                    _URL_CA="${SINK_BASE}/${_MAC_DASHED}/ca-bundle.pem"
                    if wget -q -O /tmp/ca-bundle.pem "$_URL_CA" 2>&1; then
                        if [ -s /tmp/ca-bundle.pem ] && head -1 /tmp/ca-bundle.pem | grep -q 'BEGIN CERTIFICATE'; then
                            log "CA bundle fetched from ${_URL_CA} ($(wc -c < /tmp/ca-bundle.pem) bytes)"
                        else
                            rm -f /tmp/ca-bundle.pem
                        fi
                    fi
                    break
                fi
            fi
        done

        if [ -z "$INSTALLER_CONFIG" ]; then
            log "WARNING: Debug sink per-MAC fetch failed for all local MACs, falling back to embedded config"
        fi
    fi
fi

# Priority 2: Embedded config in ISO
if [ -z "$INSTALLER_CONFIG" ] && [ -f /media/cdrom/configs/installer.yaml ]; then
    INSTALLER_CONFIG="/media/cdrom/configs/installer.yaml"
    log "Found installer configuration: $INSTALLER_CONFIG"
fi

if [ -z "$INSTALLER_CONFIG" ]; then
    log "No installer configuration found, using defaults"
fi

# Detect target installation disk. A diskless-nbd node installs onto its NBD
# export, never a local disk (nbd_install_target).
` + nbdInstallTargetFunction + `
if INSTALL_DISK=$(nbd_install_target /proc/cmdline); then
    log "diskless-nbd node: installing onto its NBD export $INSTALL_DISK; no local disk is chosen"
else
    # Skip removable devices (BMC virtual CD-ROM) and small devices (< 8GB)
    INSTALL_DISK=""
    log "Auto-detecting installation disk..."
    lsblk -d -o NAME,SIZE,TYPE,TRAN,RO,RM 2>/dev/null | while read line; do log "  $line"; done

    for disk in /dev/sda /dev/sdb /dev/sdc /dev/nvme0n1 /dev/vda; do
        [ -b "$disk" ] || continue
        DEVNAME=$(basename $disk)
        REMOVABLE=$(cat /sys/block/$DEVNAME/removable 2>/dev/null || echo "1")
        if [ "$REMOVABLE" = "1" ]; then
            log "  Skipping $disk (removable - likely virtual CD)"
            continue
        fi
        READONLY=$(cat /sys/block/$DEVNAME/ro 2>/dev/null || echo "1")
        if [ "$READONLY" = "1" ]; then
            log "  Skipping $disk (read-only)"
            continue
        fi
        SIZE_SECTORS=$(cat /sys/block/$DEVNAME/size 2>/dev/null || echo "0")
        SIZE_GB=$((SIZE_SECTORS * 512 / 1024 / 1024 / 1024))
        if [ "$SIZE_GB" -lt 8 ]; then
            log "  Skipping $disk (${SIZE_GB}GB - too small)"
            continue
        fi
        INSTALL_DISK="$disk"
        log "Found installation target: $INSTALL_DISK (${SIZE_GB}GB)"
        break
    done

    if [ -z "$INSTALL_DISK" ]; then
        error "No suitable installation disk found (need non-removable disk >= 8GB)"
    fi
fi

log "Installing Alpine Linux with TPM-based disk encryption"
log "Target disk: $INSTALL_DISK"

# PXE: the installer copies the runtime platform config from
# /media/cdrom/configs/ into /etc/trusted-platform/config.yaml on the target,
# and platformd (--config-dir=/etc/trusted-platform) needs it to serve. The
# CD rebuilt from the media set carries the set's baked config; the node's
# own (fetched per MAC) must replace it (stage_node_config).
` + NodeConfigFunction + `
stage_node_config "$INSTALLER_CONFIG" /media/cdrom /tmp/ca-bundle.pem

# Resolve hostname from embedded platform config (same function used for
# install log upload path). Falls back to "trusted-platform" if unset.
PLATFORM_HOSTNAME=$(resolve_platform_hostname)
PLATFORM_HOSTNAME=$(echo "$PLATFORM_HOSTNAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.\-]/-/g')
case "$PLATFORM_HOSTNAME" in
    ""|"-none-"|"none"|"localhost"|"alpine"|"alpinelinux"|"unknown") PLATFORM_HOSTNAME="trusted-platform" ;;
esac
log "Resolved platform hostname: $PLATFORM_HOSTNAME"

# Fetch the control-plane CA bundle from the orchestrator (best-effort).
# Saved to /tmp/cp-ca-bundle.pem; the post-install mount block installs
# it into the chroot's system trust store. Without this, GW and compute
# nodes can't validate the CP's TLS cert on first-boot ACME enrollment.
fetch_orchestrator_ca_bundle || true
# Capture the SPKI pin too (parallel trust-anchor path). Saved to
# /tmp/cp-spki-pin; post-install writes to
# /etc/trusted-platform/bootstrap-spki-pin so platformd's SPKI
# bootstrap strategy can pin against it when bundle delivery fails.
fetch_orchestrator_spki_pin || true

# Build installation command (using platformctl CLI binary)
# If installer config exists, use it; otherwise use command-line flags.
# When --config is provided, the config file is the single source of
# truth for hostname, root-password, and encryption password. CLI
# flags are only used to override when absolutely needed. The install
# command only applies flag overrides when the flag is explicitly
# provided (cobra Changed check), so omitting them lets the config
# file values take effect.
if [ -n "$INSTALLER_CONFIG" ]; then
    log "Using installer configuration file: $INSTALLER_CONFIG"
    sleep 1
    log "Building installation command..."
    # Config file provides hostname, root-password, encryption settings.
    # Only pass --password in debug mode as a known dev passphrase;
    # in production the config's encryption settings are authoritative.
    INSTALL_CMD="$PLATFORM_BIN install system \
        --config \"$INSTALLER_CONFIG\" \
        --os alpine \
        --disk \"$INSTALL_DISK\" \
        --automated \
        --verbose \
        --debug"
    # Per-node hostname override. The config file baked into the shared
    # ISO carries a generic hostname ("server"); PLATFORM_HOSTNAME
    # resolution above picked up the per-MAC value published by the
    # orchestrator. Always pass --hostname so the installed system
    # takes the orchestrator-assigned name rather than the shared
    # default. Cobra's Changed-check means the installer only applies
    # this flag when explicitly provided, which is exactly what we
    # want.
    INSTALL_CMD="$INSTALL_CMD --hostname \"$PLATFORM_HOSTNAME\""
    # In debug mode, force a known LUKS passphrase for dev convenience
    if grep -q 'platform_debug=1' /proc/cmdline 2>/dev/null; then
        INSTALL_CMD="$INSTALL_CMD --password \"password\""
        log "Debug mode: using known LUKS passphrase"
    fi
    log "Installation command built successfully (hostname=$PLATFORM_HOSTNAME)"
else
    # No config file — fallback to CLI flags with defaults.
    # This is the degraded/test path.
    INSTALL_CMD="$PLATFORM_BIN install system \
        --os alpine \
        --disk \"$INSTALL_DISK\" \
        --password \"password\" \
        --root-password \"password\" \
        --hostname \"$PLATFORM_HOSTNAME\" \
        --automated \
        --verbose \
        --debug"
`)

	// Add optional flags based on configuration (only when no config file is used)
	sb.WriteString(`
fi

# Point the OS install at the configured APK mirror (parsed above from the
# platform_apk_mirror= cmdline param). The installer uses --mirror BOTH for
# the minirootfs URL (when not locally cached) AND for the installed
# system's /etc/apk/repositories. On PXE/provisioning networks with no
# upstream egress the public dl-cdn default is unreachable, so without this
# the OS base-system install fails. Applies to both the config-file and
# fallback command branches.
if [ -n "$APK_MIRROR" ]; then
    INSTALL_CMD="$INSTALL_CMD --mirror \"$APK_MIRROR\""
    log "OS install mirror: $APK_MIRROR"
fi

# Add additional flags if not using config file. The ':' keeps the body
# non-empty when no security flag is configured; an empty one does not parse.
if [ -z "$INSTALLER_CONFIG" ]; then
    :
`)

	if c.config.Security.FIPS {
		sb.WriteString(`    INSTALL_CMD="$INSTALL_CMD --fips"
    log "FIPS mode: enabled"
`)
	}

	if c.config.Security.Lockdown {
		sb.WriteString(`    INSTALL_CMD="$INSTALL_CMD --lockdown"
`)
		if c.config.Security.LockdownMode != "" {
			fmt.Fprintf(&sb, `    INSTALL_CMD="$INSTALL_CMD --lockdown-mode \"%s\""
    log "Kernel lockdown: enabled (mode: %s)"
`, c.config.Security.LockdownMode, c.config.Security.LockdownMode)
		} else {
			sb.WriteString(`    log "Kernel lockdown: enabled (mode: confidentiality)"
`)
		}
	}

	if c.config.Security.TPM.AutoUpgradeSeal {
		sb.WriteString(`    INSTALL_CMD="$INSTALL_CMD --tpm-auto-upgrade-seal"
    log "TPM auto-upgrade seal: enabled"
`)
	}

	sb.WriteString(`fi
`)

	// Add platformd binary if configured
	if c.config.Platform.PlatformdBinary != "" {
		sb.WriteString(`
# Add platformd binary if it exists on the ISO
# Prefer the tmpfs copy (isolates from virtual-CD glitches — see the
# platformctl binary copy block above for rationale). Falls back to the
# CD-ROM path if the copy did not succeed.
PLATFORMD_PATH="/run/platformd-bin/platformd"
if [ ! -f "$PLATFORMD_PATH" ]; then
    PLATFORMD_PATH="/media/cdrom/platformd-bin/platformd"
fi
if [ -f "$PLATFORMD_PATH" ]; then
    INSTALL_CMD="$INSTALL_CMD --platformd-binary \"$PLATFORMD_PATH\""
    log "Platformd binary: $PLATFORMD_PATH"
fi
`)
	}

	// Execute installation and handle result
	afterAction := c.config.Platform.AfterInstallAction
	if afterAction == "" {
		afterAction = "poweroff"
	}

	sb.WriteString(`
# Execute the installation command
log "About to execute installation command..."
sleep 1
log "Command: $INSTALL_CMD"
sleep 1
log "Starting installation now..."
set +e
eval "$INSTALL_CMD" > /tmp/install.log 2>&1
INSTALL_RESULT=$?
set -e
# Log the install output to kernel log for serial capture
while IFS= read -r line; do
    echo "[autoinstall] install: $line" > /dev/kmsg 2>/dev/null
done < /tmp/install.log
log "Installation command exited with code: $INSTALL_RESULT"
sleep 1

if [ $INSTALL_RESULT -eq 0 ]; then
    log "Installation completed successfully"

    # Persist kernel modules to installed system's /etc/modules
    # The Go installer unmounts /mnt before returning, so we re-open LUKS/LVM
    set +e
    log "Persisting kernel modules to installed system..."
    LVM_DEV="/dev/mapper/vg0-root"
    MODULES_WRITTEN=false

    if [ -n "$INSTALL_DISK" ]; then
        LUKS_PART="${INSTALL_DISK}2"
        if echo "$INSTALL_DISK" | grep -q "nvme"; then
            LUKS_PART="${INSTALL_DISK}p2"
        fi

        log "  Re-opening LUKS on $LUKS_PART..."
        echo -n "password" | cryptsetup luksOpen "$LUKS_PART" cryptroot --key-file=- 2>/dev/null
        if [ $? -eq 0 ]; then
            log "  LUKS opened"
            vgchange -ay vg0 2>/dev/null
            sleep 1
            if [ -b "$LVM_DEV" ]; then
                mount "$LVM_DEV" /mnt 2>/dev/null
                if [ -d /mnt/etc ]; then
                    log "  Rootfs mounted at /mnt"

                    # Add detected NIC modules
                    for mod in igb ixgbe e1000e i40e ice mlx5_core bnxt_en; do
                        if lsmod 2>/dev/null | grep -q "^${mod} "; then
                            if ! grep -q "^${mod}$" /mnt/etc/modules 2>/dev/null; then
                                echo "$mod" >> /mnt/etc/modules
                                log "  Added module: $mod"
                                MODULES_WRITTEN=true
                            fi
                        fi
                    done

                    if [ "$MODULES_WRITTEN" = "true" ]; then
                        log "  Modules persisted to /mnt/etc/modules"
                    else
                        log "  No additional modules needed"
                    fi

                    # Install the orchestrator-staged CA bundle into the
                    # system trust store so the FIRST platformd boot can
                    # validate the control plane's TLS cert during ACME
                    # enrollment. Without this step the new node's
                    # ACME client hits "x509: certificate signed by
                    # unknown authority" and falls back to issuing its
                    # own local CA — exactly the failure mode that left
                    # GW/compute unenrolled in the 2026-04-29 deploy.
                    #
                    # Best-effort: missing bundle / missing host tooling
                    # logs and continues. The runtime BootstrapTrust
                    # path can still recover via SPKI/Noise when wired.
                    if [ -s /tmp/cp-ca-bundle.pem ] && [ -d /mnt/usr ]; then
                        log "  Installing orchestrator CA bundle to system trust store..."
                        mkdir -p /mnt/usr/local/share/ca-certificates
                        cp /tmp/cp-ca-bundle.pem /mnt/usr/local/share/ca-certificates/cp-ca-bundle.crt
                        chmod 0644 /mnt/usr/local/share/ca-certificates/cp-ca-bundle.crt
                        # Also stage at /etc/ssl/certs/ for tools that read
                        # there directly without consulting ca-certificates.
                        mkdir -p /mnt/etc/ssl/certs
                        cp /tmp/cp-ca-bundle.pem /mnt/etc/ssl/certs/cp-ca-bundle.pem
                        chmod 0644 /mnt/etc/ssl/certs/cp-ca-bundle.pem
                        # Run update-ca-certificates inside the chroot so
                        # the OpenSSL bundle (/etc/ssl/certs/ca-certificates.crt)
                        # picks up the new anchor. Bind-mount /proc /sys /dev
                        # so the chroot tool can resolve its prerequisites.
                        for sub in proc sys dev; do
                            if [ ! -d /mnt/$sub ]; then mkdir -p /mnt/$sub; fi
                            mount --bind /$sub /mnt/$sub 2>/dev/null || true
                        done
                        if chroot /mnt /usr/sbin/update-ca-certificates >/dev/null 2>&1; then
                            log "  CA bundle installed and trust store refreshed"
                        else
                            log "  WARNING: update-ca-certificates failed inside chroot - bundle is staged but not yet hashed"
                        fi
                        for sub in dev sys proc; do
                            umount /mnt/$sub 2>/dev/null || true
                        done
                    else
                        if [ -s /tmp/cp-ca-bundle.pem ]; then
                            log "  /mnt/usr not present - cannot install CA bundle"
                        else
                            log "  No orchestrator CA bundle staged - relying on runtime trust bootstrap"
                        fi
                    fi

                    # Persist the orchestrator-staged SPKI pin so the
                    # platform's BootstrapTrust SPKI strategy has a
                    # value to pin against. The platform reads from
                    # /etc/trusted-platform/bootstrap-spki-pin via the
                    # trust.bootstrap.spki.pin-file config key.
                    if [ -s /tmp/cp-spki-pin ] && [ -d /mnt/etc ]; then
                        mkdir -p /mnt/etc/trusted-platform
                        cp /tmp/cp-spki-pin /mnt/etc/trusted-platform/bootstrap-spki-pin
                        chmod 0644 /mnt/etc/trusted-platform/bootstrap-spki-pin
                        log "  SPKI pin persisted to /etc/trusted-platform/bootstrap-spki-pin"
                    fi

                    sync
                    umount /mnt 2>/dev/null || true
                fi
            fi
            vgchange -an vg0 2>/dev/null || true
            cryptsetup luksClose cryptroot 2>/dev/null || true
            log "  LUKS closed after module persistence"
        else
            log "  WARNING: Could not re-open LUKS for module persistence"
        fi
    fi
    set -e
`)

	if afterAction == "poweroff" {
		sb.WriteString(`    log "System will poweroff..."
    # CRITICAL: Properly unmount filesystems and sync before poweroff
    # to ensure all data (especially installer.luks on EFI) is written to disk
    log "Syncing filesystems before unmount..."
    sync

    # DEBUG: Verify LUKS header exists before unmount
    if [ -f /mnt/boot/efi/tpm2/installer.luks ]; then
        MAGIC=$(head -c 6 /mnt/boot/efi/tpm2/installer.luks | xxd -p)
        log "DEBUG: installer.luks magic bytes before unmount: $MAGIC"
        if [ "$MAGIC" = "4c554b53babe" ]; then
            log "DEBUG: LUKS header VALID before unmount"
        else
            log "DEBUG: LUKS header MISSING before unmount!"
        fi
    else
        log "DEBUG: installer.luks NOT FOUND before unmount!"
    fi

    # DEBUG: Verify main LUKS partition header (${INSTALL_DISK}2)
    if [ -b ${INSTALL_DISK}2 ]; then
        VDAMAG=$(head -c 6 ${INSTALL_DISK}2 | xxd -p)
        log "DEBUG: ${INSTALL_DISK}2 LUKS header magic bytes: $VDAMAG"
        if [ "$VDAMAG" = "4c554b53babe" ]; then
            log "DEBUG: ${INSTALL_DISK}2 LUKS header VALID!"
        else
            log "DEBUG: ${INSTALL_DISK}2 LUKS header CORRUPTED! Expected 4c554b53babe, got $VDAMAG"
        fi
    else
        log "DEBUG: ${INSTALL_DISK}2 does not exist as block device!"
    fi

    log "Unmounting EFI partition..."
    umount /mnt/boot/efi 2>/dev/null || true
    sync

    # DEBUG: Remount and verify again to ensure write went through
    mount ${INSTALL_DISK}1 /mnt/boot/efi 2>/dev/null || true
    if [ -f /mnt/boot/efi/tpm2/installer.luks ]; then
        MAGIC=$(head -c 6 /mnt/boot/efi/tpm2/installer.luks | xxd -p)
        log "DEBUG: installer.luks magic bytes after remount: $MAGIC"
        if [ "$MAGIC" = "4c554b53babe" ]; then
            log "DEBUG: LUKS header VALID after remount - data persisted!"
        else
            log "DEBUG: LUKS header MISSING after remount! Write did NOT persist!"
        fi
    fi
    umount /mnt/boot/efi 2>/dev/null || true

    log "Unmounting remaining filesystems..."
    umount /mnt/proc 2>/dev/null || true
    umount /mnt/sys 2>/dev/null || true
    umount /mnt/dev 2>/dev/null || true
    umount /mnt 2>/dev/null || true
    sync
    sleep 3

    # Upload the install.log BEFORE poweroff. The EXIT trap will not fire
    # because poweroff halts the system before the script reaches its
    # natural exit point. Calling upload_install_log_with_code explicitly
    # here with the captured $INSTALL_RESULT is the only way to guarantee
    # the postmortem makes it off the box on the success path.
    log "Uploading install.log forensic capture before poweroff..."
    upload_checkpoint pre-poweroff || true
    upload_install_log_with_code "$INSTALL_RESULT" || true

    log "Powering off..."
    poweroff
`)
	} else {
		sb.WriteString(`    log "System will reboot..."
    # CRITICAL: Properly unmount filesystems and sync before reboot
    # Copy install debug log to the installed system for post-boot analysis
    log "Copying install debug log to installed system..."
    cp "$INSTALL_LOG" /mnt/var/log/autoinstall-debug.log 2>/dev/null || true
    cp /tmp/install.log /mnt/var/log/install.log 2>/dev/null || true

    log "Syncing and unmounting filesystems..."
    sync
    umount /mnt/boot/efi 2>/dev/null || true
    umount /mnt/proc 2>/dev/null || true
    umount /mnt/sys 2>/dev/null || true
    umount /mnt/dev 2>/dev/null || true
    umount /mnt 2>/dev/null || true
    sync
    sleep 3

    # Upload the install.log BEFORE reboot. The EXIT trap will not fire
    # because reboot halts the system before the script reaches its
    # natural exit point. See poweroff branch above for rationale.
    log "Uploading install.log forensic capture before reboot..."
    upload_checkpoint pre-reboot || true
    upload_install_log_with_code "$INSTALL_RESULT" || true

    reboot
`)
	}

	sb.WriteString(`else
    log "INSTALLATION FAILED — install.log dump follows"
    cat /tmp/install.log 2>&1 || true
    log "Uploading install.log forensic capture after install failure (exit_code=$INSTALL_RESULT)..."
    upload_checkpoint install-failed || true
    upload_install_log_with_code "$INSTALL_RESULT" || true
    error "Installation failed"
fi
`)

	return sb.String()
}

// copyObjcopyBinary copies the objcopy binary to ISO (for UKI building during installation)
func (c *Customizer) copyObjcopyBinary(ctx context.Context, binaryPath string) error {
	c.logger.Info("Copying objcopy binary", "source", binaryPath)

	// Validate binary exists
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("objcopy binary not found: %s", binaryPath)}
	}

	// Create destination directory
	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create destination directory", Err: err}
	}

	// Copy binary
	destPath := filepath.Join(destDir, "objcopy")
	if err := copyFile(binaryPath, destPath); err != nil {
		return &WrappedError{Msg: "failed to copy binary", Err: err}
	}

	// Set executable permissions
	if err := os.Chmod(destPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to set executable permissions", Err: err}
	}

	// Create llvm-objcopy symlink for compatibility
	symlinkPath := filepath.Join(destDir, "llvm-objcopy")
	os.Remove(symlinkPath) // Remove if exists
	if err := os.Symlink("objcopy", symlinkPath); err != nil {
		c.logger.Warn("Failed to create llvm-objcopy symlink", "error", err)
	}

	c.logger.Info("Objcopy binary copied successfully", "destination", destPath)
	return nil
}

// CopyDracutModule generates and copies the dracut module files to the ISO for use during installation
func (c *Customizer) CopyDracutModule(ctx context.Context) error {
	c.logger.Info("Generating dracut module files for ISO")

	// Create destination directory on ISO
	// The installer looks for /media/cdrom/dracut-platformd/90platformd
	destDir := filepath.Join(c.config.Directories.ISO, "dracut-platformd", "90platformd")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create dracut module destination directory", Err: err}
	}

	// Generate module-setup.sh
	moduleSetupPath := filepath.Join(destDir, "module-setup.sh")
	moduleSetupContent := `#!/bin/bash
# Dracut module for platformd TPM-based LUKS unlock
# This module integrates platformd into the initramfs for automatic disk decryption

check() {
    # Don't use require_binaries during chroot build - it can fail
    # The binary will be available when the module is installed
    return 0
}

depends() {
    # No crypt module needed - platform-initrd uses go-luks2 for all LUKS operations
    # This removes the cryptsetup binary dependency entirely
    return 0
}

` + platformdInstallNetworkShell + `
install() {
    # Install platform-initrd binary for boot operations (CRITICAL)
    # This is the minimal binary with boot, firstboot, recovery commands
    # NOTE: platformd is the daemon-only binary, platformctl is the CLI
    # We use inst_simple instead of inst_binary because platform-initrd is a
    # statically linked Go binary with no dynamic library dependencies.
    # inst_binary uses ldd and can fail for static binaries; inst_simple just copies.
    if [ ! -e /usr/bin/platform-initrd ]; then
        derror "PLATFORMD: /usr/bin/platform-initrd not found - boot WILL fail!"
        ls -la /usr/bin/platform-initrd 2>&1 | while read line; do derror "PLATFORMD: $line"; done
        return 1
    fi
    if ! inst_simple /usr/bin/platform-initrd /usr/bin/platform-initrd; then
        derror "PLATFORMD: inst_simple failed for /usr/bin/platform-initrd"
        return 1
    fi
    # Ensure executable permissions on the copied file
    chmod +x "${initdir}/usr/bin/platform-initrd" 2>/dev/null || true
    dinfo "PLATFORMD: Installed /usr/bin/platform-initrd via inst_simple"

    # Install required system utilities individually to avoid silent failures.
    # NOTE: No cryptsetup needed - platform-initrd uses go-luks2 for all LUKS operations
    for _bin in dd cat rm mkdir mount umount findmnt grep awk sleep head tee basename cp chmod \
                modprobe lsmod blkid losetup stat dmsetup tr mountpoint; do
        inst_multiple "$_bin" 2>/dev/null || dinfo "PLATFORMD: binary $_bin not found, skipping"
    done

    # LVM binary: try multiple paths (Alpine uses /sbin/lvm, others use /usr/sbin/lvm)
    if [ -x /sbin/lvm ]; then
        inst_binary /sbin/lvm
        dinfo "PLATFORMD: Installed /sbin/lvm"
    elif [ -x /usr/sbin/lvm ]; then
        inst_binary /usr/sbin/lvm
        dinfo "PLATFORMD: Installed /usr/sbin/lvm"
    else
        inst_multiple lvm 2>/dev/null || dwarn "PLATFORMD: lvm binary not found!"
    fi

    # Install libraries needed for device mapper and LVM
    # NOTE: No libcryptsetup needed - go-luks2 is pure Go
    inst_libdir_file "libdevmapper.so*" 2>/dev/null || true
    inst_libdir_file "liblvm2*.so*" 2>/dev/null || true
    inst_libdir_file "libdevmapper-event*.so*" 2>/dev/null || true

    # Network bring-up (platformd_network_up): the diskless root fetch and
    # the first-boot network.conf diagnostic. dracut's network modules are
    # omitted, so the DHCP client and its lease script are installed here.
    platformd_install_network "" /etc/kernel/cmdline || return 1

    # Install firstboot keyfile if it exists (for automated firstboot unlock)
    # The installer creates this keyfile on the EFI partition during installation
    # It's embedded in the initramfs for firstboot, then deleted after TPM provisioning
    if [ -f /boot/efi/tpm2/luks-firstboot.key ]; then
        inst_simple /boot/efi/tpm2/luks-firstboot.key /etc/luks-firstboot.key
        dinfo "PLATFORMD: Embedded firstboot keyfile in initramfs"
    fi

    # Embed kernel cmdline into initramfs for root device detection
    # The installer writes /etc/kernel/cmdline with all params built from config:
    #   root=, rd.luks.uuid=, rd.luks.name=, rd.lvm=1, rd.lvm.vg=, rootfstype=
    # Our hooks parse this as the single source of truth for boot configuration.
    if [ -f /etc/kernel/cmdline ]; then
        inst_simple /etc/kernel/cmdline /etc/kernel/cmdline
        dinfo "PLATFORMD: Embedded /etc/kernel/cmdline in initramfs"

        # Install as cmdline.d override so dracut's getarg returns our values
        # for ALL modules. Dracut reads /proc/cmdline first, then /etc/cmdline.d/*.conf.
        # Last occurrence wins, so our values override the (possibly wrong) UKI cmdline.
        mkdir -p "${initdir}/etc/cmdline.d"
        cp /etc/kernel/cmdline "${initdir}/etc/cmdline.d/99-platformd.conf"
        dinfo "PLATFORMD: Installed cmdline.d override for dracut getarg"
    fi

    # Install cmdline hook to set root device from embedded /etc/kernel/cmdline
    # This also sets the root/rootok shell variables for dracut's internal state
    inst_hook cmdline 99 "${moddir}/platformd-root.sh"

    # Install hook for platform-initrd LUKS unlock - priority 10 runs early in settled phase
    inst_hook initqueue/settled 10 "${moddir}/platformd-unlock.sh"

    # Install initqueue/finished hook to tell dracut root device is available
    # This prevents dracut from waiting 200+ seconds for a wrong UUID device
    inst_hook initqueue/finished 99 "${moddir}/platformd-finished.sh"

    # Install mount hook to explicitly mount root if dracut's standard handler fails
    inst_hook mount 99 "${moddir}/platformd-mount.sh"

    dinfo "PLATFORMD: Module installed successfully"
    return 0
}

installkernel() {
    # Install TPM kernel modules
    instmods tpm tpm_tis tpm_crb tpm_tis_spi spi-gpio spi-bitbang spi-bcm2835 tpm_vtpm_proxy 2>/dev/null || true

    # Install device mapper module
    instmods dm_mod dm_crypt 2>/dev/null || true

    # Install loop device module (required for installer.luks container)
    instmods loop 2>/dev/null || true

    # Diskless root: dm-verity over a squashfs image under a tmpfs overlay,
    # fetched over the network
    instmods dm_verity squashfs overlay 2>/dev/null || true
    instmods virtio_net e1000 e1000e igb ixgbe i40e ice mlx5_core bnxt_en 2>/dev/null || true

    # Install filesystem modules for EFI partition
    instmods vfat fat nls_cp437 nls_iso8859_1 2>/dev/null || true

    # Install ext4 module for installer container filesystem
    instmods ext4 2>/dev/null || true

    # Install storage controller modules for hardware and QEMU testing
    # ahci: SATA/AHCI controller (required - CONFIG_SATA_AHCI=m in Alpine kernel)
    # nvme: NVMe storage (common on modern hardware)
    instmods ahci libahci virtio_pci virtio_blk ata_piix nvme 2>/dev/null || true
}
`
	if err := os.WriteFile(moduleSetupPath, []byte(moduleSetupContent), 0755); err != nil {
		return &WrappedError{Msg: "failed to write module-setup.sh", Err: err}
	}
	c.logger.Debug("Generated module-setup.sh")

	// Generate platformd-unlock.sh (the main unlock hook)
	// NOTE: All LUKS operations use platformd with go-luks2 - NO cryptsetup calls!
	unlockScriptPath := filepath.Join(destDir, "platformd-unlock.sh")
	wrapperScript := `#!/bin/sh
# Platformd unlock hook for dracut
# All config values come from kernel cmdline params (built from installer config).
# Params: root=, rd.luks.uuid=, rd.luks.name=<uuid>=<name>, rd.lvm=1, rd.lvm.vg=
# Fallback: parse /etc/kernel/cmdline embedded in initramfs.

# Load dracut library for proper integration
type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

# Helper: parse a param from the embedded /etc/kernel/cmdline
# Used as fallback when getarg fails (UKI cmdline may be wrong)
kcarg() {
    if [ -f /etc/kernel/cmdline ]; then
        _val=$(grep -o "$1=[^ ]*" /etc/kernel/cmdline | head -1)
        if [ -n "$_val" ]; then
            echo "${_val#*=}"
            return
        fi
    fi
}

` + platformdStaticCIDRShell + platformdNetworkUpShell + platformdBootModelShell + platformdRunInitrdShell + platformdDisklessRootShell + `
# Check for completion marker to prevent re-execution in initqueue loop
if [ -f /tmp/platformd-unlock-done ]; then
    return 0
fi

# Check for failure marker to prevent infinite loops
if [ -f /tmp/platformd-unlock-failed ]; then
    return 0
fi

# A diskless node (platform_boot_model=diskless in the signed command line)
# has no local root to find or unlock: its root is the verified image.
if [ "$(platformd_boot_model /etc/kernel/cmdline)" = "diskless" ]; then
    platformd_diskless_root
    return 0
fi

# Parse config from kernel cmdline with /etc/kernel/cmdline fallback
# rd.luks.name format: <uuid>=<name>
_luks_name_param="$(getarg rd.luks.name=)"
if [ -z "$_luks_name_param" ]; then
    _luks_name_param="$(kcarg rd.luks.name)"
fi

LUKS_UUID=""
LUKS_NAME=""
if [ -n "$_luks_name_param" ]; then
    LUKS_UUID="${_luks_name_param%%=*}"
    LUKS_NAME="${_luks_name_param#*=}"
fi

# Fallback UUID from rd.luks.uuid
if [ -z "$LUKS_UUID" ]; then
    LUKS_UUID="$(getarg rd.luks.uuid=)"
    [ -z "$LUKS_UUID" ] && LUKS_UUID="$(kcarg rd.luks.uuid)"
    LUKS_UUID="${LUKS_UUID#luks-}"
fi

# LVM volume group from rd.lvm.vg
LVM_VG="$(getarg rd.lvm.vg=)"
[ -z "$LVM_VG" ] && LVM_VG="$(kcarg rd.lvm.vg)"

# Root device from root=
ROOT_DEV="$(getarg root=)"
[ -z "$ROOT_DEV" ] && ROOT_DEV="$(kcarg root)"

# Check if LUKS device is already open
if [ -n "$LUKS_NAME" ] && [ -e "/dev/mapper/$LUKS_NAME" ]; then
    info "PLATFORMD: LUKS already unlocked ($LUKS_NAME)"
    # Activate LVM if configured
    if [ -n "$LVM_VG" ]; then
        if [ -z "$ROOT_DEV" ] || [ ! -e "$ROOT_DEV" ]; then
            info "PLATFORMD: Activating LVM (VG=$LVM_VG)..."
            /sbin/lvm vgscan 2>&1 || warn "PLATFORMD: vgscan failed"
            /sbin/lvm vgchange -ay "$LVM_VG" 2>&1 || warn "PLATFORMD: vgchange failed"
        fi
    fi
    # Create /dev/root symlink so dracut can find root device
    if [ -n "$ROOT_DEV" ] && [ -e "$ROOT_DEV" ]; then
        ln -sf "$ROOT_DEV" /dev/root 2>/dev/null || true
        info "PLATFORMD: Root device ready: $ROOT_DEV"
    else
        warn "PLATFORMD: Root device $ROOT_DEV not found after activation"
    fi
    touch /tmp/platformd-unlock-done
    return 0
fi

info "PLATFORMD: Starting unlock process..."
info "PLATFORMD: rd.luks.name: UUID=$LUKS_UUID NAME=$LUKS_NAME"

# Find LUKS device by UUID
LUKS_DEV=""
if [ -n "$LUKS_UUID" ]; then
    LUKS_DEV="/dev/disk/by-uuid/$LUKS_UUID"
    if [ ! -b "$LUKS_DEV" ]; then
        LUKS_DEV="/dev/disk/by-uuid/luks-$LUKS_UUID"
    fi
fi

# Fallback: scan common partitions for LUKS magic bytes
if [ -z "$LUKS_DEV" ] || [ ! -b "$LUKS_DEV" ]; then
    info "PLATFORMD: Scanning for LUKS device..."
    for dev in ${INSTALL_DISK}2 /dev/sda2 /dev/nvme0n1p2 /dev/vda3 /dev/sda3; do
        if [ -b "$dev" ]; then
            MAGIC=$(dd if="$dev" bs=6 count=1 2>/dev/null | od -A n -t x1 | tr -d ' ' | head -c 12)
            if [ "$MAGIC" = "4c554b53babe" ]; then
                LUKS_DEV="$dev"
                info "PLATFORMD: Found LUKS device: $LUKS_DEV"
                break
            fi
        fi
    done
fi

if [ -z "$LUKS_DEV" ] || [ ! -b "$LUKS_DEV" ]; then
    warn "PLATFORMD: No LUKS device found, skipping unlock"
    touch /tmp/platformd-unlock-failed
    return 0
fi

info "PLATFORMD: Target device: $LUKS_DEV -> $LUKS_NAME"

# Find EFI partition by scanning for FAT32/EFI partitions.
# Can't rely on a specific device path since BMC virtual media may shift
# disk numbering. LUKS_DEV is often a /dev/disk/by-uuid/... symlink, so
# resolve it first — the earlier sed-only approach stripped trailing digits
# from the UUID itself and produced a bogus "${LUKS_DISK}1" that pointed
# at the LUKS partition (causing the vfat mount below to fail silently
# while skipping the scan fallback).
EFI_PART=""
LUKS_DEV_REAL=$(readlink -f "$LUKS_DEV" 2>/dev/null || echo "$LUKS_DEV")

# Probe a candidate: block device AND mountable vfat filesystem
# containing EFI/ or tpm2/{installer.luks,pcr-banks} (our markers).
probe_efi() {
    candidate="$1"
    if [ ! -b "$candidate" ]; then
        return 1
    fi
    mkdir -p /tmp/efi-probe
    if mount -t vfat "$candidate" /tmp/efi-probe 2>/dev/null; then
        if [ -d /tmp/efi-probe/EFI ] || [ -f /tmp/efi-probe/tpm2/installer.luks ] || [ -f /tmp/efi-probe/tpm2/pcr-banks ]; then
            umount /tmp/efi-probe 2>/dev/null
            EFI_PART="$candidate"
            return 0
        fi
        umount /tmp/efi-probe 2>/dev/null
    fi
    return 1
}

# First try by LUKS device: derive the disk node and look for partition 1.
case "$LUKS_DEV_REAL" in
    /dev/sd?[0-9]*|/dev/hd?[0-9]*|/dev/vd?[0-9]*)
        LUKS_DISK=$(echo "$LUKS_DEV_REAL" | sed 's/[0-9]*$//')
        probe_efi "${LUKS_DISK}1" || true
        ;;
    /dev/nvme[0-9]*n[0-9]*p[0-9]*|/dev/mmcblk[0-9]*p[0-9]*|/dev/loop[0-9]*p[0-9]*)
        LUKS_DISK=$(echo "$LUKS_DEV_REAL" | sed 's/p[0-9]*$//')
        probe_efi "${LUKS_DISK}p1" || true
        ;;
esac

# Fallback: scan all candidate first partitions.
if [ -z "$EFI_PART" ]; then
    for part in /dev/sda1 /dev/sdb1 /dev/sdc1 /dev/nvme0n1p1 /dev/nvme1n1p1 /dev/vda1 /dev/mmcblk0p1; do
        if probe_efi "$part"; then
            break
        fi
    done
fi

UNLOCK_SUCCESS=0
BOOT_MODE=""

# Mount EFI partition and detect boot mode
if [ -n "$EFI_PART" ]; then
    info "PLATFORMD: Checking boot mode on $EFI_PART..."
    mkdir -p /boot/efi
    if mount -t vfat "$EFI_PART" /boot/efi 2>/dev/null; then
        if [ -f /boot/efi/tpm2/installer.luks ]; then
            BOOT_MODE="firstboot"
            info "PLATFORMD: Detected FIRSTBOOT mode (installer.luks exists)"
        elif [ -f /boot/efi/tpm2/pcr-banks ]; then
            BOOT_MODE="boot"
            info "PLATFORMD: Detected BOOT mode (pcr-banks exists)"
        else
            warn "PLATFORMD: No installer.luks or pcr-banks found - cannot determine boot mode"
        fi
    else
        warn "PLATFORMD: Failed to mount EFI partition"
    fi
fi

# For FIRSTBOOT mode, bring up networking from /boot/efi/tpm2/network.conf
# (written by the installer). Nothing in the initramfs needs the network:
# platform-initrd boot unlocks the root volume offline, and ACME enrollment
# runs after switch_root in the platformd firstboot service. Applying the
# address here proves the installed static config on the serial console
# before the real root ever depends on it, and sets the hostname the
# IAK/IDevID certificates are named after.
if [ "$BOOT_MODE" = "firstboot" ]; then
    info "PLATFORMD: Bringing up network from network.conf (diagnostic only; enrollment runs after switch_root)..."
    platformd_network_up /boot/efi/tpm2/network.conf
fi

modprobe loop 2>/dev/null || true

info "PLATFORMD: Loading TPM kernel modules..."
modprobe tpm 2>/dev/null || true
modprobe tpm_tis 2>/dev/null || true
modprobe tpm_crb 2>/dev/null || true
modprobe tpm_vtpm_proxy 2>/dev/null || true

sleep 1

if [ -c /dev/tpm0 ]; then
    info "PLATFORMD: Triggering TPM driver initialization..."
    dd if=/dev/tpm0 bs=1 count=1 2>/dev/null || true
fi

if ! mountpoint -q /sys/kernel/security 2>/dev/null; then
    info "PLATFORMD: Mounting securityfs for TPM event log..."
    mkdir -p /sys/kernel/security 2>/dev/null || true
    mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
fi

# binary_bios_measurements is a securityfs seq_file: it always stats as
# 0 bytes, so stat -c%s and test -s say "empty" for a populated log. The
# only test is a read. The kernel creates the file only when it found a log
# (EFI TCG2 table or ACPI TPM2), so absence means no log at all.
TPM_EVENTLOG="/sys/kernel/security/tpm0/binary_bios_measurements"
EVENTLOG_SIZE=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    if [ -f "$TPM_EVENTLOG" ]; then
        EVENTLOG_SIZE=$(head -c 4096 "$TPM_EVENTLOG" 2>/dev/null | wc -c | tr -d ' ')
        if [ "${EVENTLOG_SIZE:-0}" -gt 0 ]; then
            info "PLATFORMD: TPM event log available: $TPM_EVENTLOG (first read: $EVENTLOG_SIZE bytes)"
            break
        fi
        info "PLATFORMD: TPM event log file exists but reads empty, waiting... ($i/10)"
    else
        info "PLATFORMD: Waiting for TPM event log file... ($i/10)"
    fi
    cat /dev/tpm0 >/dev/null 2>&1 || true
    sleep 1
done
if [ ! -f "$TPM_EVENTLOG" ] || [ "${EVENTLOG_SIZE:-0}" -eq 0 ]; then
    warn "PLATFORMD: TPM event log not available or empty - attestation data will be incomplete"
fi

# DIAGNOSTIC: Show what's actually in /usr/bin to debug platform-initrd availability
warn "PLATFORMD: DIAGNOSTIC - listing /usr/bin contents:"
ls -la /usr/bin/ 2>&1 | head -20 | while read line; do warn "PLATFORMD: $line"; done
warn "PLATFORMD: DIAGNOSTIC - searching for platform-initrd anywhere in initramfs:"
find / -name "platform-initrd*" 2>/dev/null | while read line; do warn "PLATFORMD: FOUND: $line"; done
warn "PLATFORMD: DIAGNOSTIC - stat /usr/bin/platform-initrd:"
stat /usr/bin/platform-initrd 2>&1 | while read line; do warn "PLATFORMD: $line"; done

if [ -x /usr/bin/platform-initrd ]; then
    # Read seal-pcrs from the pcr-banks file on EFI (written by installer
    # at install time with just seal-pcrs=..., then rewritten by firstboot
    # with the full authoritative set). Passing --pcrs explicitly avoids
    # the chicken-and-egg where platform-initrd's fallback to
    # config.yaml-inside-installer.luks only works if /boot/efi mounted
    # successfully — and it's a defense-in-depth for the mount succeeding.
    PCR_FLAG=""
    PCR_BANKS_PATH="/boot/efi/tpm2/pcr-banks"
    if [ -f "$PCR_BANKS_PATH" ]; then
        SEAL_PCRS=$(awk -F= '$1=="seal-pcrs"{print $2}' "$PCR_BANKS_PATH" 2>/dev/null | head -1)
        if [ -n "$SEAL_PCRS" ]; then
            PCR_FLAG="--pcrs $SEAL_PCRS"
            info "PLATFORMD: Read seal-pcrs=$SEAL_PCRS from $PCR_BANKS_PATH"
        fi
    fi

    info "PLATFORMD: Running platform-initrd boot (mode: $BOOT_MODE)..."
    platformd_run_initrd boot --device "$LUKS_DEV" --name "$LUKS_NAME" $PCR_FLAG
    rc=$?
    if [ $rc -eq 0 ]; then
        info "PLATFORMD: Boot successful"
        UNLOCK_SUCCESS=1
    else
        warn "PLATFORMD: Boot failed (rc=$rc)"
    fi
else
    warn "PLATFORMD: platform-initrd not found at /usr/bin/platform-initrd"
fi

umount /boot/efi 2>/dev/null || true

# If unlock succeeded, activate LVM and create root device symlink
if [ $UNLOCK_SUCCESS -eq 1 ]; then
    if [ -e "/dev/mapper/$LUKS_NAME" ]; then
        # Activate LVM if VG specified in kernel cmdline
        if [ -n "$LVM_VG" ]; then
            info "PLATFORMD: Activating LVM (VG=$LVM_VG)..."
            /sbin/lvm vgscan 2>&1 || warn "PLATFORMD: vgscan failed"
            /sbin/lvm vgchange -ay "$LVM_VG" 2>&1 || warn "PLATFORMD: vgchange failed"
        fi

        # Create root symlink from kernel cmdline root= param
        if [ -n "$ROOT_DEV" ] && [ -e "$ROOT_DEV" ]; then
            info "PLATFORMD: Root device ready: $ROOT_DEV"
            ln -sf "$ROOT_DEV" /dev/root 2>/dev/null || true
        else
            warn "PLATFORMD: Root device $ROOT_DEV not found after activation"
        fi
    fi
    touch /tmp/platformd-unlock-done
else
    warn "PLATFORMD: Unlock failed, falling back to manual entry"
    touch /tmp/platformd-unlock-failed
fi

return 0
`
	if err := os.WriteFile(unlockScriptPath, []byte(wrapperScript), 0755); err != nil {
		return &WrappedError{Msg: "failed to write platformd-unlock.sh", Err: err}
	}
	c.logger.Debug("Generated platformd-unlock.sh")

	// Generate platformd-root.sh (cmdline hook to set root device)
	// This reads root= from /etc/kernel/cmdline embedded in the initramfs,
	// overriding any incorrect cmdline that dracut may have embedded in the UKI.
	rootScriptPath := filepath.Join(destDir, "platformd-root.sh")
	rootScript := `#!/bin/sh
# Platformd root detection hook for dracut (cmdline phase)
# Reads the root from the embedded /etc/kernel/cmdline the installer built and
# signed into the UKI: the diskless root for platform_boot_model=diskless,
# otherwise root= and rootfstype= (the root device, LUKS and LVM params).
# This overrides any incorrect cmdline that dracut may embed in the UKI .cmdline section.

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

` + platformdBootModelShell + `
platformd_set_root /etc/kernel/cmdline
`
	if err := os.WriteFile(rootScriptPath, []byte(rootScript), 0755); err != nil {
		return &WrappedError{Msg: "failed to write platformd-root.sh", Err: err}
	}
	c.logger.Debug("Generated platformd-root.sh")

	// Generate platformd-finished.sh (initqueue/finished hook)
	// This tells dracut the root device is ready so it stops waiting.
	// dracut's initqueue loop runs finished hooks to check if it should proceed.
	// Return 0 = root is ready, return 1 = keep waiting.
	finishedScriptPath := filepath.Join(destDir, "platformd-finished.sh")
	finishedScript := `#!/bin/sh
# Tell dracut root device is available (initqueue/finished hook)
# Returns 0 when root is ready, 1 to keep waiting.

# The diskless root is ready once the unlock hook has mounted it.
if [ "$root" = "` + platformdDisklessRoot + `" ]; then
    mountpoint -q "${NEWROOT:-/sysroot}"
    return $?
fi

# Check if the root device (set by cmdline hook from /etc/kernel/cmdline) exists
if [ -n "$root" ] && [ -e "$root" ]; then
    return 0
fi

# Check /dev/root symlink (created by unlock hook after LVM activation)
if [ -e /dev/root ]; then
    return 0
fi

return 1
`
	if err := os.WriteFile(finishedScriptPath, []byte(finishedScript), 0755); err != nil {
		return &WrappedError{Msg: "failed to write platformd-finished.sh", Err: err}
	}
	c.logger.Debug("Generated platformd-finished.sh")

	// Generate platformd-mount.sh (mount hook to mount root filesystem)
	// This is a fallback in case dracut's standard mount handler fails.
	mountScriptPath := filepath.Join(destDir, "platformd-mount.sh")
	mountScript := `#!/bin/sh
# Platformd mount hook for dracut
# Mounts root filesystem if dracut's standard handler hasn't done it yet.
# All values come from dracut variables (set by cmdline hooks parsing /etc/kernel/cmdline).

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

# Skip if already mounted
if mountpoint -q "$NEWROOT" 2>/dev/null; then
    return 0
fi

# The diskless root is mounted by the unlock hook or not at all: there is no
# device here to fall back to.
if [ "$root" = "` + platformdDisklessRoot + `" ]; then
    warn "PLATFORMD: Diskless root is not mounted at $NEWROOT"
    return 1
fi

_root="$root"
_fstype="${rootfstype:-ext4}"

# Try /dev/root symlink if root variable is empty
if [ -z "$_root" ] && [ -e /dev/root ]; then
    _root="/dev/root"
fi

if [ -z "$_root" ]; then
    warn "PLATFORMD: No root device set, cannot mount"
    return 1
fi

if [ ! -e "$_root" ]; then
    info "PLATFORMD: Waiting for root device $_root..."
    udevadm settle 2>/dev/null || true
fi

if [ -e "$_root" ]; then
    info "PLATFORMD: Mounting root filesystem $_root (type=$_fstype) at $NEWROOT"
    mount -t "$_fstype" -o ro "$_root" "$NEWROOT"
    if [ $? -eq 0 ]; then
        info "PLATFORMD: Root filesystem mounted successfully"
    else
        warn "PLATFORMD: Failed to mount root filesystem"
        return 1
    fi
else
    warn "PLATFORMD: Root device $_root does not exist"
    return 1
fi
return 0
`
	if err := os.WriteFile(mountScriptPath, []byte(mountScript), 0755); err != nil {
		return &WrappedError{Msg: "failed to write platformd-mount.sh", Err: err}
	}
	c.logger.Debug("Generated platformd-mount.sh")

	c.logger.Info("Dracut module generated successfully", "destination", destDir)
	return nil
}

// CopyWebUI copies the WebUI (public_html) directory or tarball to the ISO
// The WebUI can be provided as a directory path or as a .tar.gz file
func (c *Customizer) CopyWebUI(ctx context.Context, webUIPath string) error {
	c.logger.Info("Copying WebUI to ISO", "source", webUIPath)

	// Validate path exists
	info, err := os.Stat(webUIPath)
	if err != nil {
		return &WrappedError{Msg: "WebUI path not found", Err: err}
	}

	switch {
	case info.IsDir():
		// Copy directory contents to webui/ directory on ISO
		destDir := filepath.Join(c.config.Directories.ISO, "webui")
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return &WrappedError{Msg: "failed to create webui directory", Err: err}
		}

		c.logger.Debug("Copying WebUI directory", "source", webUIPath, "destination", destDir)

		// Use cp -a to preserve permissions and structure
		cpCmd := exec.CommandContext(ctx, "cp", "-a", webUIPath+"/.", destDir)
		if output, err := cpCmd.CombinedOutput(); err != nil {
			return &CommandOutputError{Msg: "failed to copy WebUI directory", Err: err, Detail: fmt.Sprintf("\nOutput: %s", string(output))}
		}
	case strings.HasSuffix(webUIPath, ".tar.gz"), strings.HasSuffix(webUIPath, ".tgz"):
		// Copy tarball directly to ISO (no directory created - installer will extract from tarball)
		destFile := filepath.Join(c.config.Directories.ISO, "webui.tar.gz")
		if err := copyFile(webUIPath, destFile); err != nil {
			return &WrappedError{Msg: "failed to copy WebUI tarball", Err: err}
		}
		c.logger.Debug("Copied WebUI tarball", "destination", destFile)
	default:
		return &MessageError{Msg: fmt.Sprintf("WebUI path must be a directory or .tar.gz file: %s", webUIPath)}
	}

	// Log success
	if info.IsDir() {
		c.logger.Info("WebUI directory copied successfully",
			"destination", filepath.Join(c.config.Directories.ISO, "webui"))
	} else {
		checksum, err := calculateSHA256(filepath.Join(c.config.Directories.ISO, "webui.tar.gz"))
		if err != nil {
			c.logger.Warn("Failed to calculate WebUI checksum", "error", err)
		} else {
			c.logger.Info("WebUI tarball copied successfully",
				"sha256", checksum)
		}
	}

	return nil
}

// cleanup removes temporary files created during customization
func (c *Customizer) cleanup() error {
	// Remove initramfs temp directory
	tmpDir := filepath.Join(c.config.Directories.Work, "initramfs-tmp")
	if err := os.RemoveAll(tmpDir); err != nil {
		return &WrappedError{Msg: "failed to remove initramfs temp dir", Err: err}
	}

	// Remove verify directory
	verifyDir := filepath.Join(c.config.Directories.Work, "verify-initramfs")
	if err := os.RemoveAll(verifyDir); err != nil {
		return &WrappedError{Msg: "failed to remove verify dir", Err: err}
	}

	return nil
}

// Helper utility functions

// extractInitramfs extracts initramfs to the specified directory
func extractInitramfs(initramfsPath, outputDir string) error {
	// Detect compression type
	fileCmd := exec.Command("file", initramfsPath)
	output, err := fileCmd.Output()
	if err != nil {
		return &WrappedError{Msg: "failed to detect file type", Err: err}
	}

	fileType := string(output)

	// Change to output directory for extraction
	oldDir, err := os.Getwd()
	if err != nil {
		return &WrappedError{Msg: "failed to get working directory", Err: err}
	}
	defer os.Chdir(oldDir)

	if err := os.Chdir(outputDir); err != nil {
		return &WrappedError{Msg: "failed to change to output directory", Err: err}
	}

	var decompressCmd *exec.Cmd

	switch {
	case strings.Contains(fileType, "gzip"):
		decompressCmd = exec.Command("gunzip", "-c", initramfsPath)
	case strings.Contains(fileType, "XZ"), strings.Contains(fileType, "xz"):
		decompressCmd = exec.Command("xz", "-dc", initramfsPath)
	case strings.Contains(fileType, "Zstandard"), strings.Contains(fileType, "zstd"):
		decompressCmd = exec.Command("zstd", "-dc", initramfsPath)
	default:
		// Try as uncompressed cpio
		cpioCmd := exec.Command("cpio", "-idm")
		cpioCmd.Stdin, err = os.Open(initramfsPath)
		if err != nil {
			return &WrappedError{Msg: "failed to open initramfs", Err: err}
		}
		if err := cpioCmd.Run(); err != nil {
			return &WrappedError{Msg: "failed to extract initramfs", Err: err}
		}
		return nil
	}

	// Pipe decompressor to cpio
	cpioCmd := exec.Command("cpio", "-idm")
	cpioCmd.Stdin, err = decompressCmd.StdoutPipe()
	if err != nil {
		return &WrappedError{Msg: "failed to create pipe", Err: err}
	}

	if err := cpioCmd.Start(); err != nil {
		return &WrappedError{Msg: "failed to start cpio", Err: err}
	}

	if err := decompressCmd.Start(); err != nil {
		return &WrappedError{Msg: "failed to start decompressor", Err: err}
	}

	if err := cpioCmd.Wait(); err != nil {
		return &WrappedError{Msg: "cpio extraction failed", Err: err}
	}

	if err := decompressCmd.Wait(); err != nil {
		return &WrappedError{Msg: "decompression failed", Err: err}
	}

	return nil
}

// repackInitramfs repacks the modified initramfs
func repackInitramfs(initramfsDir, outputPath string) error {
	// Change to initramfs directory
	oldDir, err := os.Getwd()
	if err != nil {
		return &WrappedError{Msg: "failed to get working directory", Err: err}
	}
	defer os.Chdir(oldDir)

	if err := os.Chdir(initramfsDir); err != nil {
		return &WrappedError{Msg: "failed to change to initramfs directory", Err: err}
	}

	// Create temporary file for new initramfs
	tmpFile := outputPath + ".new"

	// Create cpio archive and compress with zstd. Every entry is owned by
	// root (-R 0:0) whoever runs the build: the files are the early root
	// filesystem's, not the builder's.
	findCmd := exec.Command("find", ".")
	cpioCmd := exec.Command("cpio", "-o", "-H", "newc", "-R", "0:0")
	zstdCmd := exec.Command("zstd", "-19", "-T0")

	// Setup pipes
	cpioCmd.Stdin, err = findCmd.StdoutPipe()
	if err != nil {
		return &WrappedError{Msg: "failed to create find->cpio pipe", Err: err}
	}

	zstdCmd.Stdin, err = cpioCmd.StdoutPipe()
	if err != nil {
		return &WrappedError{Msg: "failed to create cpio->zstd pipe", Err: err}
	}

	// Create output file
	outFile, err := os.Create(tmpFile)
	if err != nil {
		return &WrappedError{Msg: "failed to create output file", Err: err}
	}
	defer outFile.Close()

	zstdCmd.Stdout = outFile

	// Start commands in order
	if err := zstdCmd.Start(); err != nil {
		return &WrappedError{Msg: "failed to start zstd", Err: err}
	}

	if err := cpioCmd.Start(); err != nil {
		return &WrappedError{Msg: "failed to start cpio", Err: err}
	}

	if err := findCmd.Start(); err != nil {
		return &WrappedError{Msg: "failed to start find", Err: err}
	}

	// Wait for completion
	if err := findCmd.Wait(); err != nil {
		return &WrappedError{Msg: "find failed", Err: err}
	}

	if err := cpioCmd.Wait(); err != nil {
		return &WrappedError{Msg: "cpio failed", Err: err}
	}

	if err := zstdCmd.Wait(); err != nil {
		return &WrappedError{Msg: "zstd failed", Err: err}
	}

	// Replace original with new file
	if err := os.Rename(tmpFile, outputPath); err != nil {
		return &WrappedError{Msg: "failed to replace initramfs", Err: err}
	}

	return nil
}

// validateBinary validates that the file is a valid ELF 64-bit binary
// elfMachineForArch maps a target architecture to the ELF machine every
// bundled binary must have been compiled for.
var elfMachineForArch = map[uki.Architecture]elf.Machine{
	uki.ArchX86_64:  elf.EM_X86_64,
	uki.ArchAArch64: elf.EM_AARCH64,
	uki.ArchRISCV64: elf.EM_RISCV,
}

// validateTargetBinary checks that a binary is a 64-bit ELF compiled for
// the architecture the media targets.
func (c *Customizer) validateTargetBinary(path string) error {
	want, ok := elfMachineForArch[c.config.architecture()]
	if !ok {
		return &UnsupportedArchitectureError{Arch: string(c.config.architecture())}
	}
	return validateBinary(path, want)
}

// validateStaticBinary checks that the ELF at path names no program
// interpreter (PT_INTERP): a CGO_ENABLED=0 Go binary is statically linked
// and runs on Alpine's musl userland; a dynamic one does not.
func validateStaticBinary(path string) error {
	elfFile, err := elf.Open(path)
	if err != nil {
		return &WrappedError{Msg: "not a valid ELF binary", Err: err}
	}
	defer elfFile.Close()
	for _, prog := range elfFile.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		interp, err := io.ReadAll(prog.Open())
		if err != nil {
			return &WrappedError{Msg: "failed to read the program interpreter", Err: err}
		}
		return &DynamicBinaryError{Path: path, Interpreter: strings.TrimRight(string(interp), "\x00")}
	}
	return nil
}

// validateBinary checks that path is a regular 64-bit ELF file compiled for
// the want machine.
func validateBinary(path string, want elf.Machine) error {
	// Check file exists
	info, err := os.Stat(path)
	if err != nil {
		return &WrappedError{Msg: "binary not found", Err: err}
	}

	// Check it's a regular file
	if !info.Mode().IsRegular() {
		return &MessageError{Msg: fmt.Sprintf("not a regular file: %s", path)}
	}

	// Open and parse as ELF
	file, err := os.Open(path)
	if err != nil {
		return &WrappedError{Msg: "failed to open binary", Err: err}
	}
	defer file.Close()

	elfFile, err := elf.Open(path)
	if err != nil {
		return &WrappedError{Msg: "not a valid ELF binary", Err: err}
	}
	defer elfFile.Close()

	// Check it's 64-bit
	if elfFile.Class != elf.ELFCLASS64 {
		return &MessageError{Msg: fmt.Sprintf("binary is not 64-bit (ELF class: %v)", elfFile.Class)}
	}

	// Check architecture
	if elfFile.Machine != want {
		return &BinaryArchMismatchError{Path: path, Want: want, Got: elfFile.Machine}
	}

	return nil
}

// GenerateInstallConfig generates installation configuration from ISO build config
// and writes it to the overlay directory for embedding in the initrd.
func (c *Customizer) GenerateInstallConfig() error {
	// In dynamic config mode, skip generating install config - the device will
	// fetch its configuration from the server at boot time.
	if fetchesInstallConfig(c.config.Platform.ConfigServerURL, c.config.Platform.ConfigFile) {
		c.logger.Info("Dynamic config mode: skipping install config generation",
			"server", c.config.Platform.ConfigServerURL)
		return nil
	}

	c.logger.Info("Generating installation configuration from ISO build config")

	// Create installer.Config from PlatformISOConfig
	installConfig, err := c.buildInstallerConfig()
	if err != nil {
		return &WrappedError{Msg: "failed to build installer config", Err: err}
	}

	// Generate initrd.Config for boot-time use
	initrdConfig := c.buildInitrdConfig()

	// Create directory structure in overlay
	configDir := filepath.Join(c.overlayDir, "etc", "platformd")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create config directory", Err: err}
	}

	// Write installer configuration
	installConfigPath := filepath.Join(configDir, "install.yaml")
	if err := c.writeInstallerConfig(installConfig, installConfigPath); err != nil {
		return &WrappedError{Msg: "failed to write installer config", Err: err}
	}

	// Write initrd configuration
	initrdConfigPath := filepath.Join(configDir, "initrd.yaml")
	if err := c.writeInitrdConfig(initrdConfig, initrdConfigPath); err != nil {
		return &WrappedError{Msg: "failed to write initrd config", Err: err}
	}

	c.logger.Info("Installation configuration generated successfully",
		"installer_config", installConfigPath,
		"initrd_config", initrdConfigPath)

	return nil
}

// buildInstallerConfig converts PlatformISOConfig to installer.Config
func (c *Customizer) buildInstallerConfig() (*installer.Config, error) {
	config := &installer.Config{
		Debug: c.config.Build.Debug,
	}

	// Build disk configuration
	config.Disk = &installer.DiskConfig{
		Device:           "/dev/sda", // Default device, can be overridden at install time
		PartitionTable:   installer.PartitionTableGPT,
		EFIPartitionSize: 538, // Standard EFI partition size
	}
	if c.config.Installer.Device != "" {
		config.Disk.Device = c.config.Installer.Device
	}
	if c.config.Installer.PartitionTable != "" {
		config.Disk.PartitionTable = installer.PartitionTable(c.config.Installer.PartitionTable)
	}
	config.HardwareManufacturer = c.config.Installer.HardwareManufacturer
	config.HardwareModel = c.config.Installer.HardwareModel
	config.Target = installer.InstallTarget(c.config.Installer.Target)
	if c.config.Installer.BootFirmware != "" {
		config.Boot = &installer.BootConfig{Firmware: installer.BootFirmwareType(c.config.Installer.BootFirmware)}
	}

	// Set root filesystem type
	switch c.config.RootFS.Type {
	case "lvm":
		config.Disk.RootFilesystem = installer.FilesystemLVM
		config.Disk.LVMVolumeGroup = "vg0"
		config.Disk.LVMLogicalVolume = "root"
	case "ext4":
		config.Disk.RootFilesystem = installer.FilesystemExt4
	default:
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported root filesystem type: %s", c.config.RootFS.Type)}
	}

	// Configure LUKS encryption if enabled
	if c.config.LUKS.Enabled {
		// Use PBKDF2 for FIPS mode (Argon2id is not FIPS-approved)
		pbkdf := "argon2id"
		if c.config.Security.FIPS {
			pbkdf = "pbkdf2"
		}
		config.Disk.Encryption = &installer.EncryptionConfig{
			Version:    "luks2",
			Cipher:     "aes-xts-plain64",
			KeySize:    512,
			Hash:       "sha256",
			PBKDF:      pbkdf,
			MappedName: "cryptroot",
			// Password will be set interactively during installation
			// or can be provided via kernel command line parameter
		}
	}

	// Build OS configuration. The hostname is sourced from the merged
	// platformd config file (which honors --overrides) instead of
	// being hardcoded — see readOSHostnameFromConfig. Falls back to
	// the historical "trusted-platform" default only when no config
	// file is supplied or the config doesn't set os.hostname. This
	// is the single source of truth that feeds:
	//
	//   - installer.Config.OS.Hostname → /etc/hostname on the installed
	//     system
	//   - autoinstall.sh resolve_platform_hostname → install-log upload
	//     path /installs/{hostname}/install.log
	//   - orchestrator bootstrap run → install-log polling URL
	//
	// One hostname, one place, no parallel cmdline plumbing.
	hostname := readOSHostnameFromConfig(c.config.Platform.ConfigFile)
	if hostname == "" {
		hostname = "trusted-platform"
	}
	prefetch, err := c.preFetchConfig()
	if err != nil {
		return nil, err
	}
	config.OS = &installer.OSConfig{
		OS:                 installer.OSAlpine,
		Version:            c.config.Alpine.Version,
		Architecture:       string(c.config.architecture()),
		KernelPackage:      c.config.Installer.KernelPackage,
		Packages:           prefetch.installedPackages(),
		Services:           append([]string(nil), c.config.Installer.ExtraServices...),
		Hostname:           hostname,
		Mirror:             c.config.Alpine.Mirror,
		FilesystemType:     config.Disk.RootFilesystem,
		FIPS:               c.config.Security.FIPS,
		Lockdown:           c.config.Security.Lockdown,
		LockdownMode:       c.config.Security.LockdownMode,
		TPMAutoUpgradeSeal: c.config.Security.TPM.AutoUpgradeSeal,
		// PlatformdBinary intentionally empty - installer finds binary on ISO at /media/cdrom/platformd-bin/platformd
		EnableFIDO2: c.config.Security.EnableFIDO2,
	}

	// Build UKI configuration (if platformd binary is available)
	if c.config.Platform.PlatformdBinary != "" {
		config.UKI = &installer.UKIConfig{
			Cmdline: c.buildKernelCmdline(),
		}
	}

	// Configure Secure Boot if enabled
	if c.config.Security.SecureBoot {
		// The DB keypair is staged on the install media by CopySecureBootKeys
		// (ISO root secure-boot-keys/, mounted at SecureBootKeysMediaDir during
		// installation). Reference it via file:// so offline ISO signing
		// resolves the keypair locally. Non-cdrom media (USB) falls through the
		// installer's documented resolver chain to on-node generation.
		config.SecureBoot = &installer.SecureBootConfig{
			Enabled:    true,
			ResignMode: installer.SecureBootResignModeLocal,
			DB: installer.SecureBootKeyRef{
				KeyURI:  "file://" + SecureBootKeysMediaDir + "/DB.key",
				CertURI: "file://" + SecureBootKeysMediaDir + "/DB.crt",
			},
		}
	}

	// Configure TPM sealing
	config.EnableTPMSealing = c.config.Security.TPM.AutoUnseal
	if config.EnableTPMSealing {
		// Parse PCR selection from string (e.g., "0,7,9" -> []uint{0, 7, 9})
		pcrs, err := parsePCRSelection(c.config.Security.TPM.SealPCR)
		if err != nil {
			c.logger.Warn("Invalid PCR selection, using defaults", "error", err)
			pcrs = []uint{0, 7, 9}
		}
		config.PCRs = pcrs
	}

	// Enable FIDO2 enrollment if FIDO2 support is enabled and LUKS is active
	if c.config.Security.EnableFIDO2 && c.config.LUKS.Enabled {
		config.EnableFIDO2Enrollment = true
	}

	return config, nil
}

// buildInitrdConfig generates initrd configuration for boot-time use
func (c *Customizer) buildInitrdConfig() *initrd.Config {
	config := initrd.DefaultConfig()

	// Set mode based on ISO configuration
	config.Mode = initrd.ModeInstall

	// Configure PCR banks and selection
	config.PCRBanks = []string{"sha256"}

	// Parse PCR selection for sealing
	if c.config.Security.TPM.SealPCR != "" {
		pcrs, err := parsePCRSelection(c.config.Security.TPM.SealPCR)
		if err != nil {
			c.logger.Warn("Invalid PCR selection, using defaults", "error", err)
		} else {
			config.PCRSelection = pcrs
		}
	}

	// Configure upgrade PCRs (typically a subset of PCRSelection)
	// Usually PCRs 0, 1, 2, 3 are used for upgrade strategy
	config.UpgradePCRSelection = []uint{0, 1, 2, 3}

	// Configure unlock methods based on LUKS settings
	config.FallbackMethods = []storageluks.UnlockMethod{}

	if c.config.LUKS.Enabled {
		if c.config.Security.TPM.AutoUnseal {
			// Add TPM unlock methods
			config.FallbackMethods = append(config.FallbackMethods,
				storageluks.UnlockTPMPCR,
				storageluks.UnlockTPMUpgrade,
			)
		}

		if !c.config.LUKS.TPMOnly {
			// Add password fallback
			config.FallbackMethods = append(config.FallbackMethods,
				storageluks.UnlockPassword,
			)
		}
	}

	// Set reasonable defaults
	config.UnlockTimeout = 30
	config.RetryCount = 3
	config.EnableAuditLog = true
	config.AuditLogPath = "/var/log/initrd-unlock.log"

	// Set FIPS mode (affects PBKDF algorithm selection - PBKDF2 vs Argon2id)
	config.FIPS = c.config.Security.FIPS

	return config
}

// buildKernelCmdline builds kernel command line parameters from config
func (c *Customizer) buildKernelCmdline() string {
	var parts []string

	// Root device will be set during installation
	parts = append(parts, "root=/dev/mapper/cryptroot")

	// LUKS configuration
	if c.config.LUKS.Enabled {
		parts = append(parts, "rd.luks.name=cryptroot")
	}

	// LVM configuration
	if c.config.RootFS.Type == "lvm" {
		parts = append(parts, "rd.lvm=1")
	}

	// Basic boot parameters — console/earlycon from the generic cross-vendor
	// default quirk.  The installed system resolves vendor-specific params
	// at install time via pkg/quirks.Resolve using Redfish hardware identifiers.
	parts = append(parts, "rootfstype=ext4", "ro")
	parts = append(parts, c.targetQuirk().KernelCmdline...)

	// Security parameters
	if c.config.Security.Lockdown {
		lockdownMode := c.config.Security.LockdownMode
		if lockdownMode == "" {
			lockdownMode = "confidentiality"
		}
		parts = append(parts, fmt.Sprintf("lockdown=%s", lockdownMode))
	}

	if c.config.Security.FIPS {
		parts = append(parts, "fips=1")
	}

	return strings.Join(parts, " ")
}

// applyInstallerOverrides writes the media target's installer settings into
// the baked platform config, the file the live installer and the installed
// node's uki-rebuild both convert into an installer.Config
// (app.App.GetInstallerConfig). The architecture is always written, because
// the media decides it; every other key is written only when the
// corresponding InstallerOverrides field is set, so an x86_64 ISO built
// without overrides bakes its template unchanged.
func (c *Customizer) applyInstallerOverrides(data []byte) ([]byte, error) {
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, &WrappedError{Msg: "failed to parse platform config YAML", Err: err}
	}
	section := func(name string) map[interface{}]interface{} {
		if existing, ok := config[name].(map[interface{}]interface{}); ok {
			return existing
		}
		created := map[interface{}]interface{}{}
		config[name] = created
		return created
	}

	osSection := section("os")
	osSection["architecture"] = string(c.config.architecture())
	ov := c.config.Installer
	// The installer installs os.packages and enables os.services; what the
	// media prefetches for the installed system goes there too.
	prefetch, err := c.preFetchConfig()
	if err != nil {
		return nil, err
	}
	if err := appendMissing(osSection, "packages", prefetch.installedPackages()); err != nil {
		return nil, err
	}
	if err := appendMissing(osSection, "services", ov.ExtraServices); err != nil {
		return nil, err
	}
	if ov.KernelPackage != "" {
		osSection["kernel-package"] = ov.KernelPackage
	}
	if ov.KernelArtifactsDir != "" {
		osSection["kernel-artifacts-dir"] = ov.KernelArtifactsDir
	}
	if ov.Device != "" || ov.PartitionTable != "" {
		disk := section("disk")
		if ov.Device != "" {
			disk["device"] = ov.Device
		}
		if ov.PartitionTable != "" {
			disk["partition-table"] = ov.PartitionTable
		}
	}
	if ov.HardwareManufacturer != "" {
		config["hardware-manufacturer"] = ov.HardwareManufacturer
	}
	if ov.HardwareModel != "" {
		config["hardware-model"] = ov.HardwareModel
	}
	if ov.Target != "" {
		config["install-target"] = ov.Target
	}
	if ov.BootFirmware != "" {
		section("boot")["firmware"] = ov.BootFirmware
	}

	modified, err := yaml.Marshal(config)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to marshal modified config", Err: err}
	}
	return modified, nil
}

// appendMissing appends to the list under key each name it does not already
// hold, after the entries the template lists, so the template's order is
// kept and nothing is listed twice. A list nothing is added to is left as it
// was, absent included.
func appendMissing(section map[interface{}]interface{}, key string, names []string) error {
	list, ok := section[key].([]interface{})
	if section[key] != nil && !ok {
		return &InstallerListError{Key: key}
	}
	added := false
	for _, name := range names {
		if !slices.Contains(list, interface{}(name)) {
			list = append(list, name)
			added = true
		}
	}
	if added {
		section[key] = list
	}
	return nil
}

// targetQuirk resolves the hardware quirk whose kernel command line the
// media's target needs: the entry for the configured manufacturer/model,
// or the generic cross-vendor default when none is configured. The
// installed system re-resolves at install time from Redfish identifiers.
func (c *Customizer) targetQuirk() quirks.Quirk {
	if c.config.Installer.HardwareManufacturer == "" && c.config.Installer.HardwareModel == "" {
		return quirks.Default()
	}
	return quirks.Resolve(c.config.Installer.HardwareManufacturer, c.config.Installer.HardwareModel)
}

// writeInstallerConfig writes installer configuration to YAML file
func (c *Customizer) writeInstallerConfig(config *installer.Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return &WrappedError{Msg: "failed to marshal config", Err: err}
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return &WrappedError{Msg: "failed to write config file", Err: err}
	}

	c.logger.Debug("Wrote installer configuration", "path", path, "size", len(data))
	return nil
}

// writeInitrdConfig writes initrd configuration to YAML file
func (c *Customizer) writeInitrdConfig(config *initrd.Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return &WrappedError{Msg: "failed to marshal config", Err: err}
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return &WrappedError{Msg: "failed to write config file", Err: err}
	}

	c.logger.Debug("Wrote initrd configuration", "path", path, "size", len(data))
	return nil
}

// parsePCRSelection parses PCR selection string (e.g., "0,7,9") to slice of uints
func parsePCRSelection(selection string) ([]uint, error) {
	if selection == "" {
		return nil, &MessageError{Msg: "empty PCR selection"}
	}

	var pcrs []uint
	for _, s := range strings.Split(selection, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		var pcr uint
		if _, err := fmt.Sscanf(s, "%d", &pcr); err != nil {
			return nil, &MessageError{Msg: fmt.Sprintf("invalid PCR value: %s", s)}
		}
		if pcr > 23 {
			return nil, &MessageError{Msg: fmt.Sprintf("PCR value out of range (0-23): %d", pcr)}
		}
		pcrs = append(pcrs, pcr)
	}

	if len(pcrs) == 0 {
		return nil, &MessageError{Msg: "no valid PCRs found"}
	}

	return pcrs, nil
}

// resolveHostnameForCmdline returns the installed-system hostname taken
// from the merged platformd config, or empty if no valid hostname is
// available. The result is baked into the GRUB kernel cmdline as
// platform_hostname=<value>; the autoinstall.sh boot hook reads that
// value from /proc/cmdline to route its install.log forensic upload to
// the right /installs/<hostname>/ bucket on the bootstrap container.
//
// Sanitization mirrors sanitizeHostnameForPath: only lowercase letters,
// digits, dots, and dashes survive. Anything else becomes a dash. This
// keeps the resulting URL component safe to slot into an HTTP path.
func (c *Customizer) resolveHostnameForCmdline() string {
	// Candidate config files, in priority order. buildInstallerConfig
	// writes the merged install.yaml into the overlay at this path,
	// which is also where the autoinstall.sh YAML fallback looks first.
	candidates := []string{
		filepath.Join(c.config.Directories.Work, "overlay", "etc", "platformd", "install.yaml"),
		filepath.Join(c.config.Directories.ISO, "configs", "installer.yaml"),
	}
	var raw string
	for _, p := range candidates {
		if v := readOSHostnameFromConfig(p); v != "" {
			raw = v
			break
		}
	}
	if raw == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range strings.ToLower(raw) {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// buildDynamicConfigParams builds kernel cmdline parameters for dynamic
// configuration mode. Returns an empty string when not in dynamic config mode.
func (c *Customizer) buildDynamicConfigParams() string {
	url := c.config.Platform.ConfigServerURL
	if url == "" {
		return ""
	}

	var params []string
	params = append(params, "platform_config="+url)

	if s := c.config.Platform.BootstrapStrategy; s != "" {
		params = append(params, "bootstrap_strategy="+s)
	}
	if s := c.config.Platform.BootstrapDNS; s != "" {
		params = append(params, "bootstrap_dns="+s)
	}
	if s := c.config.Platform.BootstrapNoiseKey; s != "" {
		params = append(params, "bootstrap_noise_key="+s)
	}
	if s := c.config.Platform.BootstrapSPKIPin; s != "" {
		params = append(params, "bootstrap_spki_pin="+s)
	}

	return strings.Join(params, " ")
}

// readOSHostnameFromConfig extracts the os.hostname field from a merged
// platformd config yaml file. Returns the raw string on success or an
// empty string on any failure (missing file, unreadable, no os block,
// no hostname key, blank value).
//
// This is used by buildInstallerConfig as the single source of truth
// for the installed-system hostname; autoinstall.sh reads the same
// value at install time via its shell-native resolve_platform_hostname
// helper. Keeping the logic simple and dependency-free (no full YAML
// unmarshaller) because it's invoked very early in ISO customization
// and the field we want is trivial to find with a line scan.
//
// NOTE: earlier drafts of this file carried a buildHostnameParam
// helper that baked a platform_hostname=X kernel cmdline parameter
// into the bootloader configs. That indirection was removed because
// we already have the merged config file to read from.
func readOSHostnameFromConfig(path string) string {
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(raw), "\n")
	inOSBlock := false
	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")
		// Detect start of "os:" top-level key (no leading whitespace).
		if strings.HasPrefix(line, "os:") && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inOSBlock = true
			continue
		}
		if inOSBlock {
			// Any other top-level key ends the os block.
			if len(line) > 0 && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "#") {
				inOSBlock = false
				continue
			}
			stripped := strings.TrimSpace(line)
			if strings.HasPrefix(stripped, "hostname:") {
				val := strings.TrimSpace(strings.TrimPrefix(stripped, "hostname:"))
				val = strings.Trim(val, `"'`)
				return val
			}
		}
	}
	return ""
}
