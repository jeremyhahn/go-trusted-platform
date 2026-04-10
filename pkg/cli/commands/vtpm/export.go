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

// newExportCommand creates the export subcommand for exporting bundles
func newExportCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		output    string
		overwrite bool
	)

	cmd := &cobra.Command{
		Use:   "export [bundle-id]",
		Short: "Export a vTPM bundle to archive",
		Long: `Export a vTPM bundle to a tar.gz archive for distribution.

The archive contains:
- manifest.json with metadata and checksums
- TPM state files
- OVMF NVRAM
- Secure Boot keys (if enabled)

The archive can be imported on another system using the import command.

Examples:
  # Export bundle with default filename
  platformctl vtpm export bundle-123

  # Export bundle to specific file
  platformctl vtpm export bundle-123 --output my-bundle.vtpm.tar.gz

  # Overwrite existing file
  platformctl vtpm export bundle-123 --output existing.tar.gz --overwrite`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runExport(flags, args[0], output, overwrite)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "output file path (default: bundle-{id}.vtpm.tar.gz)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite existing output file")

	return cmd
}

// runExport executes the export command
func runExport(flags *cli.CommonFlags, bundleID string, output string, overwrite bool) error {
	// Validate bundle ID is provided
	if bundleID == "" {
		return ErrMissingRequiredFlag{Flag: "bundle-id"}
	}

	// Default output filename
	if output == "" {
		output = fmt.Sprintf("bundle-%s.vtpm.tar.gz", bundleID)
	}

	// Check if output file exists
	if !overwrite {
		if _, err := os.Stat(output); err == nil {
			return ErrOutputFileExists{Path: output}
		}
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

	req := &platformv1.ExportBundleRequest{
		Id: bundleID,
	}

	ctx := base.Context()
	stream, err := client.ExportBundle(ctx, req)
	if err != nil {
		return ErrExportBundleFailed{Reason: err.Error()}
	}

	// Create output file
	file, err := os.Create(output)
	if err != nil {
		return ErrCreateOutputFileFailed{Path: output, Reason: err.Error()}
	}
	defer file.Close()

	// Stream data to file
	var totalBytes int64
	for {
		resp, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			// Clean up partial file on error
			file.Close()
			os.Remove(output)
			return ErrExportBundleFailed{Reason: recvErr.Error()}
		}

		n, writeErr := file.Write(resp.Data)
		if writeErr != nil {
			file.Close()
			os.Remove(output)
			return ErrExportBundleFailed{Reason: writeErr.Error()}
		}
		totalBytes += int64(n)
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		result := map[string]interface{}{
			"bundle_id": bundleID,
			"output":    output,
			"size":      totalBytes,
		}
		return printer.Print(result)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Bundle exported successfully: %s", output))
		printer.PrintKeyValue("Bundle ID", bundleID)
		printer.PrintKeyValue("Output File", output)
		printer.PrintKeyValue("Size", formatBytes(totalBytes))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// formatBytes formats bytes in human readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
