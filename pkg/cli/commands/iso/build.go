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
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
)

// maxVolumeLabelLength is the ISO 9660 volume identifier limit.
const maxVolumeLabelLength = 32

// buildFlags holds flags for the build command
type buildFlags struct {
	sourceDir   string
	output      string
	volumeID    string
	generateSum bool
	debug       bool
}

// buildResult is what `iso build` prints (docs/installer/cli.md §4).
type buildResult struct {
	Success      bool   `json:"success" yaml:"success"`
	OutputISO    string `json:"output_iso" yaml:"output_iso"`
	SHA256       string `json:"sha256" yaml:"sha256"`
	SizeBytes    int64  `json:"size_bytes" yaml:"size_bytes"`
	ChecksumFile string `json:"checksum_file,omitempty" yaml:"checksum_file,omitempty"`
	Message      string `json:"message" yaml:"message"`
}

// newBuildCommand creates the build command
func newBuildCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &buildFlags{}

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build final bootable ISO image",
		Long: `Builds a bootable ISO image from customized ISO directory contents.

This command creates a hybrid BIOS/UEFI bootable ISO image using xorriso
with El Torito boot catalog and isohybrid MBR for USB booting support.

The resulting ISO can boot via:
- Legacy BIOS (using isolinux/syslinux)
- UEFI (using grub EFI bootloader)
- USB/HDD (via isohybrid MBR)

The local --output flag names the ISO file, so the result prints as text.

Examples:
  # Build ISO with default settings
  platformctl iso build --iso-dir work/iso --output platform.iso

  # Build with custom label
  platformctl iso build --iso-dir work/iso --output platform.iso --label MY_PLATFORM

  # Build without checksum
  platformctl iso build --iso-dir work/iso --output platform.iso --checksum=false`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBuild(cmd.Context(), getFlags(), flags, cmd.OutOrStdout())
		},
	}

	// Build flags
	cmd.Flags().StringVar(&flags.sourceDir, "iso-dir", "", "Source directory containing ISO contents (required)")
	cmd.Flags().StringVar(&flags.output, "output", "", "Output ISO file path (required)")
	cmd.Flags().StringVar(&flags.volumeID, "label", "TRUSTED_PLATFORM", "ISO volume label (max 32 chars)")
	cmd.Flags().BoolVar(&flags.generateSum, "checksum", true, "Write <output>.sha256 beside the ISO")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")

	// Mark required flags
	cli.MarkFlagsRequired(cmd, "iso-dir")
	cli.MarkFlagsRequired(cmd, "output")

	return cmd
}

// runBuild masters the ISO with xorriso from an extracted, customized tree.
func runBuild(ctx context.Context, commonFlags *cli.CommonFlags, flags *buildFlags, out io.Writer) error {
	info, err := os.Stat(flags.sourceDir)
	if err != nil || !info.IsDir() {
		return ErrDirectoryNotFound{Path: flags.sourceDir}
	}
	if len(flags.volumeID) > maxVolumeLabelLength {
		return ErrVolumeLabelTooLong{Label: flags.volumeID, MaxLength: maxVolumeLabelLength}
	}

	isoConfig := &pkgiso.ISOConfig{
		ISODir:    flags.sourceDir,
		OutputISO: flags.output,
		VolumeID:  flags.volumeID,
		Debug:     flags.debug,
	}
	if err := isoBuild(ctx, newVerbLogger(flags.debug), isoConfig); err != nil {
		return ErrBuildFailed{Reason: err.Error()}
	}

	sum, size, err := fileDigest(flags.output)
	if err != nil {
		return err
	}

	result := buildResult{
		Success:   true,
		OutputISO: flags.output,
		SHA256:    sum,
		SizeBytes: size,
		Message:   "ISO built from " + flags.sourceDir,
	}
	if flags.generateSum {
		result.ChecksumFile = flags.output + ".sha256"
		line := sum + "  " + filepath.Base(flags.output) + "\n"
		if err := os.WriteFile(result.ChecksumFile, []byte(line), 0o644); err != nil {
			return &WrappedError{Msg: "failed to write checksum file", Err: err}
		}
	}

	return printResult(out, commonFlags, result)
}
