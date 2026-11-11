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
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
)

// extractFlags holds flags for the extract command
type extractFlags struct {
	iso       string
	outputDir string
	force     bool
	workDir   string
	debug     bool
}

// extractResult is what `iso extract` prints (docs/installer/cli.md §4).
type extractResult struct {
	Success   bool   `json:"success" yaml:"success"`
	OutputDir string `json:"output_dir" yaml:"output_dir"`
	FileCount int    `json:"file_count" yaml:"file_count"`
	Message   string `json:"message" yaml:"message"`
}

// newExtractCommand creates the extract subcommand for extracting ISO contents
func newExtractCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &extractFlags{}

	cmd := &cobra.Command{
		Use:   "extract",
		Short: "Extract ISO contents for customization",
		Long: `Extracts the contents of an ISO file to a directory for customization.

This command uses 7z, bsdtar, or xorriso (tried in order) to extract
the ISO contents. All extracted files are made writable to allow for
customization before building the final ISO.

Examples:
  # Extract ISO to default location (work/iso)
  platformctl iso extract --iso alpine-standard-3.22.2-x86_64.iso

  # Extract to custom directory
  platformctl iso extract --iso alpine.iso --output-dir /tmp/my-iso

  # Force re-extraction
  platformctl iso extract --iso alpine.iso --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExtract(cmd.Context(), getFlags(), flags, cmd.OutOrStdout())
		},
	}

	// Extract flags
	cmd.Flags().StringVar(&flags.iso, "iso", "", "Path to ISO file to extract (required)")
	cmd.Flags().StringVar(&flags.outputDir, "output-dir", "", "Output directory for extracted contents (default: work/iso)")
	cmd.Flags().BoolVar(&flags.force, "force", false, "Overwrite existing extraction directory")

	// Common flags
	cmd.Flags().StringVar(&flags.workDir, "work-dir", "work", "Working directory; the default output directory is <work-dir>/iso")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")

	// Mark required flags
	cli.MarkFlagsRequired(cmd, "iso")

	return cmd
}

// runExtract executes the extract command
func runExtract(ctx context.Context, commonFlags *cli.CommonFlags, flags *extractFlags, out io.Writer) error {
	isoPath, err := filepath.Abs(flags.iso)
	if err != nil {
		return &WrappedError{Msg: "failed to resolve ISO path", Err: err}
	}
	if _, err := os.Stat(isoPath); err != nil {
		return ErrISONotFound{Path: isoPath}
	}

	outputDir := flags.outputDir
	if outputDir == "" {
		outputDir = filepath.Join(flags.workDir, "iso")
	}
	if !flags.force && directoryHasEntries(outputDir) {
		return ErrDirectoryAlreadyExists{Path: outputDir}
	}

	cfg := pkgiso.DefaultISOConfig()
	cfg.WorkDir = filepath.Dir(isoPath)
	cfg.ISO = filepath.Base(isoPath)
	cfg.ISODir = outputDir
	cfg.Debug = flags.debug

	if err := isoExtract(ctx, cfg); err != nil {
		return ErrExtractionFailed{Reason: err.Error()}
	}

	fileCount, err := countFiles(outputDir)
	if err != nil {
		return &WrappedError{Msg: "failed to count extracted files", Err: err}
	}

	return printResult(out, commonFlags, extractResult{
		Success:   true,
		OutputDir: outputDir,
		FileCount: fileCount,
		Message:   "ISO extracted from " + isoPath,
	})
}

// directoryHasEntries reports whether path is a directory with at least one
// entry. A missing or unreadable directory has none.
func directoryHasEntries(path string) bool {
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) > 0
}

// countFiles counts the regular files under root.
func countFiles(root string) (int, error) {
	count := 0
	err := filepath.WalkDir(root, func(_ string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type().IsRegular() {
			count++
		}
		return nil
	})
	return count, err
}
