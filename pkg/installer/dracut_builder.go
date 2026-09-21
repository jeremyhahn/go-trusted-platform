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
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// dracutUKIBuilder implements UKIBuilder using dracut's native UKI support
type dracutUKIBuilder struct {
	logger *logging.Logger
}

// NewDracutUKIBuilder creates a new dracut-based UKI builder
func NewDracutUKIBuilder(logger *logging.Logger) UKIBuilder {
	return &dracutUKIBuilder{
		logger: logger,
	}
}

// BuildUKI builds a Unified Kernel Image using dracut
// dracut has native UKI support via the --uefi flag which combines
// initramfs generation and UKI building in one step
func (db *dracutUKIBuilder) BuildUKI(ctx context.Context, config *UKIConfig, output io.Writer) error {
	db.logger.Info("[DRACUT] Building Unified Kernel Image with dracut")

	// Validate configuration
	if config.KernelPath == "" {
		return ErrUKIBuild("kernel path is required", nil)
	}
	if config.Cmdline == "" {
		return ErrUKIBuild("kernel command line is required", nil)
	}

	// Determine kernel version from kernel path
	// Typical path: /boot/vmlinuz-6.6.67-0-lts -> 6.6.67-0-lts
	kernelVersion := filepath.Base(config.KernelPath)
	kernelVersion = strings.TrimPrefix(kernelVersion, "vmlinuz-")
	db.logger.Debug("[DRACUT] Detected kernel version", "version", kernelVersion)

	// Create temporary directory for dracut working files
	tmpDir, err := os.MkdirTemp("", "dracut-uki-*")
	if err != nil {
		return ErrUKIBuild("failed to create temporary directory", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			db.logger.Warn("[DRACUT] Failed to clean up temp directory", "error", removeErr)
		}
	}()

	// Write kernel command line to temporary file
	cmdlinePath := filepath.Join(tmpDir, "cmdline.txt")
	if err := os.WriteFile(cmdlinePath, []byte(config.Cmdline), 0644); err != nil {
		return ErrUKIBuild("failed to write cmdline file", err)
	}
	db.logger.Debug("[DRACUT] Wrote kernel command line", "path", cmdlinePath, "cmdline", config.Cmdline)

	// Write os-release if provided
	var osReleasePath string
	if config.OSRelease != "" {
		osReleasePath = filepath.Join(tmpDir, "os-release")
		if err := os.WriteFile(osReleasePath, []byte(config.OSRelease), 0644); err != nil {
			return ErrUKIBuild("failed to write os-release file", err)
		}
		db.logger.Debug("[DRACUT] Wrote os-release", "path", osReleasePath)
	}

	// Create temporary output file for the UKI
	// We need to write to a file first because dracut doesn't support stdout output
	ukiTmpPath := filepath.Join(tmpDir, "linux.efi")

	// Build dracut command with UKI generation
	// dracut will:
	// 1. Generate initramfs with platformd LUKS support (go-luks2, no cryptsetup)
	// 2. Bundle kernel + initramfs + cmdline + os-release into UKI
	// 3. Use systemd-boot stub (if available) or fall back to objcopy approach
	args := []string{
		"--force",               // Overwrite existing initramfs
		"--kver", kernelVersion, // Kernel version
		"--add", "platformd", // Add platformd module (LUKS via go-luks2)
		"--kernel-cmdline", config.Cmdline, // Kernel command line
		"--uefi",                            // Generate UKI
		"--kernel-image", config.KernelPath, // Path to kernel
		ukiTmpPath, // Output UKI path
	}

	// Add os-release if provided
	if osReleasePath != "" {
		args = append(args, "--uefi-os-release", osReleasePath)
	}

	// Add microcode if provided
	if config.MicrocodePath != "" {
		args = append(args, "--early-microcode", config.MicrocodePath)
	}

	// Look for the systemd-boot EFI stub of the architecture this binary
	// runs on (the rebuild happens on the installed node), then the legacy
	// locations.
	stubPaths := hostStubCandidates()

	var stubPath string
	for _, path := range stubPaths {
		if _, err := os.Stat(path); err == nil {
			stubPath = path
			break
		}
	}

	if stubPath != "" {
		args = append(args, "--uefi-stub", stubPath)
		db.logger.Debug("[DRACUT] Using systemd-boot EFI stub", "path", stubPath)
	} else {
		db.logger.Warn("[DRACUT] No systemd-boot EFI stub found, dracut will use fallback method")
	}

	db.logger.Info("[DRACUT] Running dracut to build UKI", "args", strings.Join(args, " "))

	// Execute dracut command
	cmd := exec.CommandContext(ctx, "dracut", args...)
	cmd.Stdout = os.Stderr // Send dracut output to stderr for visibility
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return ErrUKIBuild(fmt.Sprintf("dracut command failed: %v", err), err)
	}

	// Read the generated UKI and write to output
	ukiData, err := os.ReadFile(ukiTmpPath)
	if err != nil {
		return ErrUKIBuild("failed to read generated UKI", err)
	}

	if _, err := output.Write(ukiData); err != nil {
		return ErrUKIBuild("failed to write UKI to output", err)
	}

	db.logger.Info("[DRACUT] UKI built successfully", "size", len(ukiData))
	return nil
}

// hostStubCandidates lists the systemd-boot EFI stub locations to probe on the
// running node: the host architecture's stub as pkg/uki names it, then the
// legacy x86_64 spellings older systemd packages used.
func hostStubCandidates() []string {
	candidates := []string{}
	if stub, err := uki.StubPath(uki.HostArchitecture()); err == nil {
		candidates = append(candidates, stub)
	}
	return append(candidates,
		"/usr/lib/systemd/boot/efi/linuxx64.efi.stub",
		"/lib/systemd/boot/efi/linuxx64.efi.stub",
		"/usr/lib/systemd/boot/efi/linux.efi.stub",
	)
}
