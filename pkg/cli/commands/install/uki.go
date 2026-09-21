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

package install

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// ukiFlags contains flags for the UKI build command
type ukiFlags struct {
	kernelPath    string
	initramfsPath string
	cmdlineStr    string
	outputPath    string
	osReleasePath string
	stubPath      string
	useObjcopy    bool
	verbose       bool
	debug         bool
}

// newUKICommand creates the uki subcommand for building Unified Kernel Images
func newUKICommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &ukiFlags{}

	cmd := &cobra.Command{
		Use:   "uki",
		Short: "Build a Unified Kernel Image (UKI)",
		Long: `Build a Unified Kernel Image by combining kernel, initramfs, and command line
into a single EFI PE/COFF executable. The output is an unsigned UKI that can be
signed with the native Authenticode signer (platformctl authenticode sign).

The UKI contains:
  - Linux kernel (vmlinuz)
  - Initramfs (compressed cpio archive)
  - Kernel command line
  - Optional os-release metadata
  - EFI stub for bootloader integration

Examples:
  # Build UKI with Go PE/COFF builder (default)
  platformctl install uki \
    --kernel /boot/vmlinuz-6.6.64-0-lts \
    --initramfs /boot/initramfs-6.6.64-0-lts \
    --cmdline "root=/dev/mapper/cryptroot ro quiet" \
    --output /boot/efi/EFI/BOOT/BOOTX64.EFI

  # Build UKI with objcopy (Alpine/dracut proven approach)
  platformctl install uki \
    --kernel /boot/vmlinuz \
    --initramfs /boot/initramfs \
    --cmdline "root=/dev/mapper/cryptroot ro" \
    --output /boot/efi/EFI/Linux/linux.efi \
    --use-objcopy

  # Build UKI with custom EFI stub and os-release
  platformctl install uki \
    --kernel /boot/vmlinuz \
    --initramfs /boot/initramfs \
    --cmdline "root=/dev/mapper/cryptroot ro" \
    --output /boot/efi/EFI/BOOT/BOOTX64.EFI \
    --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
    --osrelease /etc/os-release`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runUKIBuild(flags, cmdFlags)
		},
	}

	// Add flags
	cmd.Flags().StringVar(&cmdFlags.kernelPath, "kernel", "", "Path to kernel image (vmlinuz)")
	cmd.Flags().StringVar(&cmdFlags.initramfsPath, "initramfs", "", "Path to initramfs")
	cmd.Flags().StringVar(&cmdFlags.cmdlineStr, "cmdline", "", "Kernel command line")
	cmd.Flags().StringVar(&cmdFlags.outputPath, "output", "", "Output path for UKI")
	cmd.Flags().StringVar(&cmdFlags.osReleasePath, "osrelease", "", "Path to os-release file (optional)")
	cmd.Flags().StringVar(&cmdFlags.stubPath, "stub", "", "Path to EFI stub (optional; defaults to the host architecture's systemd stub, e.g. /usr/lib/systemd/boot/efi/linuxx64.efi.stub)")
	cmd.Flags().BoolVar(&cmdFlags.useObjcopy, "use-objcopy", false, "Use objcopy-based UKI builder (proven approach from Alpine/dracut)")
	cmd.Flags().BoolVarP(&cmdFlags.verbose, "verbose", "v", false, "Enable verbose logging")
	cmd.Flags().BoolVar(&cmdFlags.debug, "debug", false, "Enable debug logging (implies verbose)")

	// Mark required flags
	cmd.MarkFlagRequired("kernel")    //nolint:errcheck
	cmd.MarkFlagRequired("initramfs") //nolint:errcheck
	cmd.MarkFlagRequired("cmdline")   //nolint:errcheck
	cmd.MarkFlagRequired("output")    //nolint:errcheck

	return cmd
}

// runUKIBuild executes the UKI build command
func runUKIBuild(_ *cli.CommonFlags, cmdFlags *ukiFlags) error {
	// Create logger
	level := slog.LevelInfo
	if cmdFlags.verbose || cmdFlags.debug {
		level = slog.LevelDebug
	}
	logger := logging.NewLogger(level, nil)

	logger.Info("[BUILD-UKI] Building Unified Kernel Image",
		"kernel", cmdFlags.kernelPath,
		"initramfs", cmdFlags.initramfsPath,
		"cmdline", cmdFlags.cmdlineStr,
		"output", cmdFlags.outputPath)

	// Open kernel
	kernelFile, err := os.Open(cmdFlags.kernelPath)
	if err != nil {
		return ErrKernelOpenFailed{Path: cmdFlags.kernelPath, Err: err}
	}
	defer kernelFile.Close()

	// Open initramfs
	initramfsFile, err := os.Open(cmdFlags.initramfsPath)
	if err != nil {
		return ErrInitramfsOpenFailed{Path: cmdFlags.initramfsPath, Err: err}
	}
	defer initramfsFile.Close()

	// Create UKI structure
	ukiStruct := &uki.UKI{
		Kernel:    kernelFile,
		Initramfs: initramfsFile,
		Cmdline:   cmdFlags.cmdlineStr,
	}

	// Add optional os-release
	if cmdFlags.osReleasePath != "" {
		osReleaseData, readErr := os.ReadFile(cmdFlags.osReleasePath)
		if readErr != nil {
			logger.Warn("Failed to read os-release file", "path", cmdFlags.osReleasePath, "error", readErr)
		} else {
			ukiStruct.OSRelease = string(osReleaseData)
			logger.Info("[BUILD-UKI] OS release included", "path", cmdFlags.osReleasePath)
		}
	}

	// Add optional stub
	if cmdFlags.stubPath != "" {
		stubFile, openErr := os.Open(cmdFlags.stubPath)
		if openErr != nil {
			return ErrStubOpenFailed{Path: cmdFlags.stubPath, Err: openErr}
		}
		defer stubFile.Close()
		ukiStruct.Stub = stubFile
		logger.Info("[BUILD-UKI] Using custom EFI stub", "path", cmdFlags.stubPath)
	}

	// Create builder (choose between Go PE/COFF or objcopy)
	var builder uki.UKIBuilder
	if cmdFlags.useObjcopy {
		logger.Info("[BUILD-UKI] Using objcopy-based builder")
		builder = uki.NewObjcopyBuilder(logger)
	} else {
		logger.Info("[BUILD-UKI] Using Go PE/COFF builder")
		builder = uki.NewBuilder(logger)
	}

	// Build UKI to output file
	if err := builder.BuildFile(ukiStruct, cmdFlags.outputPath); err != nil {
		return ErrUKIBuildFailed{Err: err}
	}

	logger.Info("[BUILD-UKI] UKI built successfully", "output", cmdFlags.outputPath)
	return nil
}
