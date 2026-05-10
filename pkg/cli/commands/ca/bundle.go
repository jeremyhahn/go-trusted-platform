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

package ca

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
)

// newBundleCommand creates the `ca bundle` subcommand. It is a thin
// wrapper around CAService.GetCABundle that prints the PEM bundle to
// stdout by default and writes it to a file when --output is provided.
// The --output flag is optional, which makes the command suitable
// for scripting (`platformctl ca bundle | ...`).
func newBundleCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		output               string
		includeIntermediates bool
	)

	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Print or save the CA certificate bundle (PEM)",
		Long: `Fetch the Certificate Authority trust chain (root CA + intermediate CAs)
as a concatenated PEM bundle. The same bundle is returned regardless of which
transport (REST, gRPC, QUIC, MCP, Unix) the client uses.

By default the bundle is written to stdout so it can be piped to tools
that need a PEM trust store. Pass --output to write to a file instead.

Examples:
  # Print to stdout
  platformctl ca bundle

  # Save to a file
  platformctl ca bundle --output /etc/ssl/platform-ca.pem

  # Pipe into the system trust store
  platformctl ca bundle | sudo tee /usr/local/share/ca-certificates/platform.crt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runBundle(flags, output, includeIntermediates)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "",
		"output file path (default: stdout)")
	cmd.Flags().BoolVar(&includeIntermediates, "intermediates", true,
		"include intermediate CA certificates in the bundle")

	return cmd
}

// runBundle performs the GetCABundle SDK call and writes the PEM bundle
// either to the supplied path or to stdout.
func runBundle(flags *cli.CommonFlags, output string, includeIntermediates bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	grpcClient := base.Client().CA()
	if grpcClient == nil {
		return ErrCANotInitialized{}
	}

	sdkClient := casvc.NewClientFromGRPC(grpcClient)
	bundle, err := sdkClient.GetCABundleDomain(base.Context(), includeIntermediates)
	if err != nil {
		return ErrCABundleFailed{Reason: err.Error()}
	}
	if bundle == nil || len(bundle.Pem) == 0 {
		return ErrBundleEmpty{}
	}

	if output == "" {
		if _, writeErr := os.Stdout.Write(bundle.Pem); writeErr != nil {
			return ErrCABundleFailed{Reason: fmt.Sprintf("failed to write bundle to stdout: %v", writeErr)}
		}
		return nil
	}

	if err := os.WriteFile(output, bundle.Pem, 0644); err != nil {
		return ErrCABundleFailed{Reason: fmt.Sprintf("failed to write bundle: %v", err)}
	}

	printer := base.Printer()
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(map[string]interface{}{
			"success":    true,
			"output":     output,
			"cert_count": bundle.CertCount,
		})
	default:
		printer.PrintSuccess(fmt.Sprintf("CA bundle written to %s", output))
		printer.PrintKeyValue("Certificates", fmt.Sprintf("%d", bundle.CertCount))
		return nil
	}
}
