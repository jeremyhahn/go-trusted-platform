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

package vtpm

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
)

// newImportCommand creates the import subcommand for importing bundles
func newImportCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import [archive-path]",
		Short: "Import a vTPM bundle from archive",
		Long: `Import a vTPM bundle from a tar.gz archive.

The archive is validated before import:
- manifest.json is checked for required fields
- Checksums are verified
- Bundle ID uniqueness is enforced

Examples:
  # Import a bundle
  platformctl vtpm import bundle.vtpm.tar.gz

  # Import and output result as JSON
  platformctl vtpm import bundle.vtpm.tar.gz -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runImport(flags, args[0])
		},
	}

	return cmd
}

// runImport executes the import command
func runImport(flags *cli.CommonFlags, archivePath string) error {
	// Validate archive path is provided
	if archivePath == "" {
		return ErrMissingRequiredFlag{Flag: "archive-path"}
	}

	// Check if archive file exists
	fileInfo, err := os.Stat(archivePath)
	if err != nil {
		return ErrOpenArchiveFailed{Path: archivePath, Reason: err.Error()}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	printer := base.Printer()

	// Open archive file
	file, err := os.Open(archivePath)
	if err != nil {
		return ErrOpenArchiveFailed{Path: archivePath, Reason: err.Error()}
	}
	defer file.Close()

	ctx := base.Context()
	resp, err := sdkClient.ImportBundleDomain(ctx, file)
	if err != nil {
		return ErrImportBundleFailed{Reason: err.Error()}
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess("Bundle imported successfully")
			fmt.Println()
			printer.PrintKeyValue("Archive", archivePath)
			printer.PrintKeyValue("Size", formatBytes(fileInfo.Size()))

			if resp.Bundle != nil {
				fmt.Println()
				printBundleDetails(printer, resp.Bundle)
			}
		} else {
			msg := "unknown error"
			if resp.Status != nil && resp.Status.Message != "" {
				msg = resp.Status.Message
			}
			printer.PrintError(fmt.Sprintf("Import failed: %s", msg))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
