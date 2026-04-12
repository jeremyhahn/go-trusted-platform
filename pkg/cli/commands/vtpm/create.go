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
	"strings"

	"github.com/spf13/cobra"

	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newCreateCommand creates the create subcommand for creating pre-assigned bundles
func newCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		hostname    string
		secureBoot  bool
		ekAlgorithm string
		templateID  string
		labels      []string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a pre-assigned vTPM bundle",
		Long: `Create a pre-assigned vTPM bundle with CA-issued EK certificate.

A pre-assigned bundle includes:
- Initialized swtpm state with EK certificate in NV RAM
- OVMF NVRAM with Secure Boot keys enrolled (if enabled)
- Secure Boot keys (PK, KEK, DB) for installer use

The EK certificate is issued immediately, giving the bundle a unique
TPM identity ready for deployment.

Examples:
  # Create bundle with default settings
  platformctl vtpm create --hostname vm001.example.com

  # Create bundle with ECC EK algorithm
  platformctl vtpm create --hostname vm001.example.com --ek-algorithm ECC

  # Create bundle without Secure Boot
  platformctl vtpm create --hostname vm001.example.com --secure-boot=false

  # Create bundle from template
  platformctl vtpm create --hostname vm001.example.com --template-id my-template

  # Create bundle with labels
  platformctl vtpm create --hostname vm001.example.com --label env=prod --label tier=1

  # Create bundle and output as JSON
  platformctl vtpm create --hostname vm001.example.com -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCreate(flags, hostname, secureBoot, ekAlgorithm, templateID, labels)
		},
	}

	cmd.Flags().StringVar(&hostname, "hostname", "", "hostname for the VM (required)")
	cmd.Flags().BoolVar(&secureBoot, "secure-boot", true, "enable Secure Boot key generation and enrollment")
	cmd.Flags().StringVar(&ekAlgorithm, "ek-algorithm", "RSA", "EK algorithm (RSA or ECC)")
	cmd.Flags().StringVar(&templateID, "template-id", "", "template ID to use as base")
	cmd.Flags().StringArrayVar(&labels, "label", nil, "labels in key=value format (can be repeated)")

	_ = cmd.MarkFlagRequired("hostname")

	return cmd
}

// runCreate executes the create command
func runCreate(flags *cli.CommonFlags, hostname string, secureBoot bool, ekAlgorithm, templateID string, labels []string) error {
	// Validate arguments first before connecting
	ekAlg, err := parseEKAlgorithm(ekAlgorithm)
	if err != nil {
		return err
	}

	labelMap, err := parseLabels(labels)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	opts := &vtpmsvc.CreateBundleOptions{
		Mode:              vtpmsvc.BundleModePreAssigned,
		Hostname:          hostname,
		EKAlgorithm:       ekAlg,
		SecureBootEnabled: secureBoot,
		TemplateID:        templateID,
		Labels:            labelMap,
	}

	ctx := base.Context()
	resp, err := sdkClient.CreateBundleDomain(ctx, opts)
	if err != nil {
		return ErrCreateBundleFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Bundle != nil {
			printer.PrintSuccess(fmt.Sprintf("vTPM bundle created: %s", resp.Bundle.ID))
			fmt.Println()
			printBundleDetails(printer, resp.Bundle)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// parseEKAlgorithm parses the EK algorithm string to protobuf enum
func parseEKAlgorithm(algorithm string) (vtpmsvc.EKAlgorithm, error) {
	alg, ok := vtpmsvc.ParseEKAlgorithm(algorithm)
	if !ok {
		return vtpmsvc.EKAlgorithmUnspecified, ErrInvalidEKAlgorithm{Algorithm: algorithm}
	}
	return alg, nil
}

// parseLabels parses label strings into a map
func parseLabels(labels []string) (map[string]string, error) {
	if len(labels) == 0 {
		return nil, nil
	}
	result := make(map[string]string)
	for _, label := range labels {
		parts := strings.SplitN(label, "=", 2)
		if len(parts) != 2 {
			return nil, ErrInvalidLabel{Label: label}
		}
		result[parts[0]] = parts[1]
	}
	return result, nil
}

// printBundleDetails prints bundle details in table format
func printBundleDetails(printer *cli.Printer, bundle *vtpmsvc.Bundle) {
	printer.PrintKeyValue("ID", bundle.ID)
	printer.PrintKeyValue("Mode", string(bundle.Mode))

	if bundle.Manifest != nil {
		m := bundle.Manifest
		if m.Hostname != "" {
			printer.PrintKeyValue("Hostname", m.Hostname)
		}
		printer.PrintKeyValue("EK Algorithm", string(m.EKAlgorithm))
		printer.PrintKeyValue("Secure Boot", formatBool(m.SecureBootEnabled))
		if m.ClonedFrom != "" {
			printer.PrintKeyValue("Cloned From", m.ClonedFrom)
		}
		if m.CreatedAt != nil {
			printer.PrintKeyValue("Created", (*m.CreatedAt).Format("2006-01-02 15:04:05 MST"))
		}
		if len(m.Labels) > 0 {
			fmt.Println()
			printer.PrintInfo("Labels:")
			for k, v := range m.Labels {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}
	} else if bundle.CreatedAt != nil {
		printer.PrintKeyValue("Created", (*bundle.CreatedAt).Format("2006-01-02 15:04:05 MST"))
	}
}

// formatBool formats a boolean for display
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
