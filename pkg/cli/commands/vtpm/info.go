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

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newInfoCommand creates the info subcommand for displaying bundle information
func newInfoCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info [bundle-id]",
		Short: "Display bundle information",
		Long: `Display detailed information about a vTPM bundle.

Shows comprehensive bundle details including:
- Bundle ID, mode, and creation time
- Manifest information (hostname, Secure Boot, EK algorithm)
- EK certificate fingerprint (if present)
- Clone source (if cloned from template)
- File checksums
- TPM state paths
- OVMF state paths
- Secure Boot key paths

Examples:
  # Get bundle information
  platformctl vtpm info bundle-123

  # Output as JSON
  platformctl vtpm info bundle-123 -o json

  # Output as YAML
  platformctl vtpm info bundle-123 -o yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runInfo(flags, args[0])
		},
	}

	return cmd
}

// runInfo executes the info command
func runInfo(flags *cli.CommonFlags, bundleID string) error {
	// Validate bundle ID is provided
	if bundleID == "" {
		return ErrMissingRequiredFlag{Flag: "bundle-id"}
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

	req := &platformv1.GetBundleRequest{
		Id: bundleID,
	}

	ctx := base.Context()
	resp, err := client.GetBundle(ctx, req)
	if err != nil {
		return ErrGetBundleInfoFailed{Reason: err.Error()}
	}

	if resp.Bundle == nil {
		return ErrBundleNotFound{ID: bundleID}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printBundleInfo(printer, resp.Bundle)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printBundleInfo prints detailed bundle information
func printBundleInfo(printer *cli.Printer, bundle *platformv1.Bundle) {
	printer.PrintKeyValue("ID", bundle.Id)
	printer.PrintKeyValue("Mode", bundle.Mode.String())

	if bundle.CreatedAt != nil {
		printer.PrintKeyValue("Created", bundle.CreatedAt.AsTime().Format("2006-01-02 15:04:05 MST"))
	}

	if bundle.ClonedFrom != "" {
		printer.PrintKeyValue("Cloned From", bundle.ClonedFrom)
	}

	if bundle.Manifest != nil {
		m := bundle.Manifest
		fmt.Println()
		printer.PrintInfo("Manifest:")

		if m.Hostname != "" {
			printer.PrintKeyValue("  Hostname", m.Hostname)
		}
		printer.PrintKeyValue("  EK Algorithm", m.EkAlgorithm.String())
		printer.PrintKeyValue("  Secure Boot", formatBool(m.SecureBootEnabled))

		if m.ClonedFrom != "" {
			printer.PrintKeyValue("  Cloned From", m.ClonedFrom)
		}

		if m.EkCertificate != nil && m.EkCertificate.Fingerprint != "" {
			printer.PrintKeyValue("  EK Fingerprint", m.EkCertificate.Fingerprint)
		}

		if m.CreatedAt != nil {
			printer.PrintKeyValue("  Manifest Created", m.CreatedAt.AsTime().Format("2006-01-02 15:04:05 MST"))
		}

		if len(m.Labels) > 0 {
			fmt.Println()
			printer.PrintInfo("  Labels:")
			for k, v := range m.Labels {
				fmt.Printf("    %s: %s\n", k, v)
			}
		}

		if len(m.Checksums) > 0 {
			fmt.Println()
			printer.PrintInfo("  Checksums:")
			for filename, checksum := range m.Checksums {
				printer.PrintKeyValue(fmt.Sprintf("    %s", filename), checksum)
			}
		}
	}

	if bundle.TpmState != nil {
		t := bundle.TpmState
		fmt.Println()
		printer.PrintInfo("TPM State:")
		if t.StateDir != "" {
			printer.PrintKeyValue("  State Dir", t.StateDir)
		}
		if t.PermallFile != "" {
			printer.PrintKeyValue("  Permall File", t.PermallFile)
		}
		if t.VolatileFile != "" {
			printer.PrintKeyValue("  Volatile File", t.VolatileFile)
		}
	}

	if bundle.OvmfState != nil {
		o := bundle.OvmfState
		fmt.Println()
		printer.PrintInfo("OVMF State:")
		if o.NvramFile != "" {
			printer.PrintKeyValue("  NVRAM File", o.NvramFile)
		}
	}

	if bundle.SecureBootKeys != nil {
		s := bundle.SecureBootKeys
		fmt.Println()
		printer.PrintInfo("Secure Boot Keys:")
		if s.Dir != "" {
			printer.PrintKeyValue("  Directory", s.Dir)
		}
		if s.PkKey != "" {
			printer.PrintKeyValue("  PK Key", s.PkKey)
		}
		if s.PkCrt != "" {
			printer.PrintKeyValue("  PK Cert", s.PkCrt)
		}
		if s.KekKey != "" {
			printer.PrintKeyValue("  KEK Key", s.KekKey)
		}
		if s.KekCrt != "" {
			printer.PrintKeyValue("  KEK Cert", s.KekCrt)
		}
		if s.DbKey != "" {
			printer.PrintKeyValue("  DB Key", s.DbKey)
		}
		if s.DbCrt != "" {
			printer.PrintKeyValue("  DB Cert", s.DbCrt)
		}
	}
}
