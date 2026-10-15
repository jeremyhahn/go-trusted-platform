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
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// extractFlags holds flags for the extract command
type extractFlags struct {
	iso        string
	outputDir  string
	force      bool
	configFile string
	workDir    string
	debug      bool
	verbose    bool
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
			return runExtract(getFlags(), flags)
		},
	}

	// Extract flags
	cmd.Flags().StringVar(&flags.iso, "iso", "", "Path to ISO file to extract (required)")
	cmd.Flags().StringVar(&flags.outputDir, "output-dir", "", "Output directory for extracted contents (default: work/iso)")
	cmd.Flags().BoolVar(&flags.force, "force", false, "Overwrite existing extraction directory")

	// Common flags
	cmd.Flags().StringVar(&flags.configFile, "config", "", "Path to ISO build configuration file")
	cmd.Flags().StringVar(&flags.workDir, "work-dir", "work", "Working directory for ISO operations")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")
	cmd.Flags().BoolVar(&flags.verbose, "verbose", false, "Enable verbose output")

	// Mark required flags
	cli.MarkFlagsRequired(cmd, "iso")

	return cmd
}

// runExtract executes the extract command
func runExtract(commonFlags *cli.CommonFlags, flags *extractFlags) error {
	// ISO extract requires App initialization which needs daemon connection
	// Dual-mode will be added later to support local-only operations
	return ErrDaemonConnectionRequired{Command: "iso extract"}
}
