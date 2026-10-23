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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
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
		return ErrDaemonConnectionRequired{Err: err}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	ctx := base.Context()
	resp, err := sdkClient.GetBundleDomain(ctx, bundleID)
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
func printBundleInfo(printer *cli.Printer, bundle *vtpmsvc.Bundle) {
	printer.PrintKeyValue("ID", bundle.ID)
	printer.PrintKeyValue("Mode", string(bundle.Mode))

	if bundle.CreatedAt != nil {
		printer.PrintKeyValue("Created", bundle.CreatedAt.Format("2006-01-02 15:04:05 MST"))
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
		printer.PrintKeyValue("  EK Algorithm", string(m.EKAlgorithm))
		printer.PrintKeyValue("  Secure Boot", formatBool(m.SecureBootEnabled))

		if m.ClonedFrom != "" {
			printer.PrintKeyValue("  Cloned From", m.ClonedFrom)
		}

		if m.EKCertificate != nil && m.EKCertificate.Fingerprint != "" {
			printer.PrintKeyValue("  EK Fingerprint", m.EKCertificate.Fingerprint)
		}

		if m.CreatedAt != nil {
			printer.PrintKeyValue("  Manifest Created", m.CreatedAt.Format("2006-01-02 15:04:05 MST"))
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

	if bundle.TPMState != nil {
		t := bundle.TPMState
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

	if bundle.OVMFState != nil {
		o := bundle.OVMFState
		fmt.Println()
		printer.PrintInfo("OVMF State:")
		if o.NVRAMFile != "" {
			printer.PrintKeyValue("  NVRAM File", o.NVRAMFile)
		}
	}

	if bundle.SecureBootKeys != nil {
		s := bundle.SecureBootKeys
		fmt.Println()
		printer.PrintInfo("Secure Boot Keys:")
		if s.Dir != "" {
			printer.PrintKeyValue("  Directory", s.Dir)
		}
		if s.PKKey != "" {
			printer.PrintKeyValue("  PK Key", s.PKKey)
		}
		if s.PKCert != "" {
			printer.PrintKeyValue("  PK Cert", s.PKCert)
		}
		if s.KEKKey != "" {
			printer.PrintKeyValue("  KEK Key", s.KEKKey)
		}
		if s.KEKCert != "" {
			printer.PrintKeyValue("  KEK Cert", s.KEKCert)
		}
		if s.DBKey != "" {
			printer.PrintKeyValue("  DB Key", s.DBKey)
		}
		if s.DBCert != "" {
			printer.PrintKeyValue("  DB Cert", s.DBCert)
		}
	}
}
