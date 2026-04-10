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
	"io"
	"os"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

const importChunkSize = 64 * 1024 // 64KB chunks for streaming

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

	client := base.Client().VTPM()
	if client == nil {
		return ErrVTPMNotAvailable{}
	}

	printer := base.Printer()

	// Open archive file
	file, err := os.Open(archivePath)
	if err != nil {
		return ErrOpenArchiveFailed{Path: archivePath, Reason: err.Error()}
	}
	defer file.Close()

	ctx := base.Context()
	stream, err := client.ImportBundle(ctx)
	if err != nil {
		return ErrImportBundleFailed{Reason: err.Error()}
	}

	// Stream file data to server
	buf := make([]byte, importChunkSize)
	var totalSent int64

	for {
		n, readErr := file.Read(buf)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return ErrImportBundleFailed{Reason: readErr.Error()}
		}

		req := &platformv1.ImportBundleRequest{
			Data: buf[:n],
		}

		if sendErr := stream.Send(req); sendErr != nil {
			return ErrImportBundleFailed{Reason: sendErr.Error()}
		}
		totalSent += int64(n)
	}

	// Close send and receive response
	resp, err := stream.CloseAndRecv()
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
