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

package ipxe

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExtractBootFiles extracts boot files from an ISO image.
// It returns the extraction directory, kernel path, initrd path, modloop path,
// kernel arguments, and any error encountered.
//
// The extraction directory should be cleaned up by the caller when done.
//
// Example:
//
//	extractDir, kernel, initrd, modloop, args, err := ExtractBootFiles("/path/to/alpine.iso")
//	if err != nil {
//	    return err
//	}
//	defer os.RemoveAll(extractDir)
func ExtractBootFiles(isoPath string) (extractDir, kernelPath, initrdPath, modloopPath, kernelArgs string, err error) {
	// Validate ISO exists
	if _, err := os.Stat(isoPath); os.IsNotExist(err) {
		return "", "", "", "", "", fmt.Errorf("ISO file not found: %s", isoPath)
	}

	// Create temporary directory for extraction
	extractDir, err = os.MkdirTemp("", "ipxe-iso-*")
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Clean up on error
	defer func() {
		if err != nil {
			os.RemoveAll(extractDir)
		}
	}()

	// Create mount point
	mountDir := filepath.Join(extractDir, "mount")
	if err = os.MkdirAll(mountDir, 0755); err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to create mount directory: %w", err)
	}

	// Mount the ISO (requires root privileges)
	mountCmd := exec.Command("mount", "-o", "loop,ro", isoPath, mountDir)
	if err = mountCmd.Run(); err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to mount ISO: %w", err)
	}

	// Ensure unmount on exit
	defer func() {
		umountCmd := exec.Command("umount", mountDir)
		if umountErr := umountCmd.Run(); umountErr != nil {
			// Log but don't override existing error
			if err == nil {
				err = fmt.Errorf("failed to unmount ISO: %w", umountErr)
			}
		}
	}()

	// Find and copy boot files
	kernelPath, initrdPath, err = findBootFiles(mountDir)
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to find boot files: %w", err)
	}

	// Create output directory for boot files
	bootDir := filepath.Join(extractDir, "boot")
	if err = os.MkdirAll(bootDir, 0755); err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to create boot directory: %w", err)
	}

	// Copy kernel
	kernelDest := filepath.Join(bootDir, filepath.Base(kernelPath))
	if err = copyFile(kernelPath, kernelDest); err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to copy kernel: %w", err)
	}
	kernelPath = kernelDest

	// Copy initrd
	initrdDest := filepath.Join(bootDir, filepath.Base(initrdPath))
	if err = copyFile(initrdPath, initrdDest); err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to copy initrd: %w", err)
	}
	initrdPath = initrdDest

	// Find and copy modloop (optional, primarily for Alpine)
	modloop := findModloop(mountDir)
	if modloop != "" {
		modloopDest := filepath.Join(bootDir, filepath.Base(modloop))
		if copyErr := copyFile(modloop, modloopDest); copyErr == nil {
			modloopPath = modloopDest
		}
	}

	// Extract kernel arguments from boot configuration
	kernelArgs = extractKernelArgs(mountDir)

	return extractDir, kernelPath, initrdPath, modloopPath, kernelArgs, nil
}

// findBootFiles searches for kernel and initrd files in the mounted ISO.
func findBootFiles(mountDir string) (kernelPath, initrdPath string, err error) {
	// Common kernel filenames
	kernelNames := []string{
		"vmlinuz",
		"vmlinuz-lts",
		"vmlinuz-virt",
		"vmlinuz.efi",
		"boot/vmlinuz",
		"boot/vmlinuz-lts",
		"casper/vmlinuz",
		"live/vmlinuz",
	}

	// Common initrd filenames
	initrdNames := []string{
		"initramfs",
		"initramfs-lts",
		"initramfs-virt",
		"initrd",
		"initrd.gz",
		"initrd.lz",
		"boot/initramfs",
		"boot/initramfs-lts",
		"casper/initrd",
		"live/initrd",
	}

	// Search for kernel
	for _, name := range kernelNames {
		path := filepath.Join(mountDir, name)
		if _, err := os.Stat(path); err == nil {
			kernelPath = path
			break
		}
	}

	// Search for initrd
	for _, name := range initrdNames {
		path := filepath.Join(mountDir, name)
		if _, err := os.Stat(path); err == nil {
			initrdPath = path
			break
		}
	}

	// If not found in common locations, do a recursive search
	if kernelPath == "" || initrdPath == "" {
		err := filepath.Walk(mountDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}

			name := info.Name()

			// Look for kernel
			if kernelPath == "" {
				if strings.HasPrefix(name, "vmlinuz") || strings.HasPrefix(name, "bzImage") {
					kernelPath = path
				}
			}

			// Look for initrd
			if initrdPath == "" {
				if strings.HasPrefix(name, "initramfs") || strings.HasPrefix(name, "initrd") {
					initrdPath = path
				}
			}

			// Stop walking once we find both
			if kernelPath != "" && initrdPath != "" {
				return filepath.SkipAll
			}

			return nil
		})

		if err != nil {
			return "", "", fmt.Errorf("error walking ISO: %w", err)
		}
	}

	if kernelPath == "" {
		return "", "", fmt.Errorf("kernel file not found in ISO")
	}
	if initrdPath == "" {
		return "", "", fmt.Errorf("initrd file not found in ISO")
	}

	return kernelPath, initrdPath, nil
}

// findModloop searches for the modloop file (Alpine Linux specific).
// Returns empty string if not found.
func findModloop(mountDir string) string {
	// Common modloop locations for Alpine
	modloopPaths := []string{
		"boot/modloop-lts",
		"boot/modloop-virt",
		"boot/modloop",
		"modloop-lts",
		"modloop-virt",
		"modloop",
	}

	for _, path := range modloopPaths {
		fullPath := filepath.Join(mountDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath
		}
	}

	return ""
}

// extractKernelArgs attempts to extract kernel arguments from boot configuration files.
// Returns empty string if no configuration found or on error.
func extractKernelArgs(mountDir string) string {
	// Common boot config locations
	configPaths := []string{
		"boot/grub/grub.cfg",
		"boot/syslinux/syslinux.cfg",
		"isolinux/isolinux.cfg",
		"syslinux/syslinux.cfg",
		"EFI/BOOT/grub.cfg",
	}

	for _, configPath := range configPaths {
		fullPath := filepath.Join(mountDir, configPath)
		if data, err := os.ReadFile(fullPath); err == nil {
			// Parse the config file for kernel arguments
			args := parseBootConfig(string(data))
			if args != "" {
				return args
			}
		}
	}

	return ""
}

// parseBootConfig extracts kernel arguments from boot configuration content.
func parseBootConfig(content string) string {
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// GRUB format: linux /boot/vmlinuz args...
		if strings.HasPrefix(line, "linux") || strings.HasPrefix(line, "kernel") {
			parts := strings.Fields(line)
			if len(parts) > 2 {
				// Join everything after the kernel path
				return strings.Join(parts[2:], " ")
			}
		}

		// SYSLINUX format: APPEND args...
		if strings.HasPrefix(line, "APPEND") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				return strings.Join(parts[1:], " ")
			}
		}
	}

	return ""
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	if err := os.WriteFile(dst, data, 0644); err != nil {
		return fmt.Errorf("failed to write destination file: %w", err)
	}

	return nil
}
