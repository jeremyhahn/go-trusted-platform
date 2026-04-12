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

	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newCloneCommand creates the clone subcommand for cloning bundles from templates
func newCloneCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		templateID string
		hostname   string
		labels     []string
	)

	cmd := &cobra.Command{
		Use:   "clone",
		Short: "Clone a bundle from a template",
		Long: `Clone a new vTPM bundle from an existing template.

The cloned bundle receives:
- A copy of the template's swtpm state
- A unique EK certificate issued at clone time
- A copy of the template's OVMF NVRAM (with Secure Boot keys)
- A copy of the template's Secure Boot keys

This allows rapid provisioning of VMs with unique TPM identities
while sharing common Secure Boot keys from the template.

Examples:
  # Clone from a template
  platformctl vtpm clone --template base-vtpm --hostname vm002.example.com

  # Clone with labels
  platformctl vtpm clone --template base-vtpm --hostname vm003.example.com --label env=prod

  # Clone and output as JSON
  platformctl vtpm clone --template base-vtpm --hostname vm003.example.com -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runClone(flags, templateID, hostname, labels)
		},
	}

	cmd.Flags().StringVar(&templateID, "template", "", "template ID to clone from (required)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "hostname for the new VM (required)")
	cmd.Flags().StringArrayVar(&labels, "label", nil, "labels in key=value format (can be repeated)")

	_ = cmd.MarkFlagRequired("template")
	_ = cmd.MarkFlagRequired("hostname")

	return cmd
}

// runClone executes the clone command
func runClone(flags *cli.CommonFlags, templateID string, hostname string, labels []string) error {
	if templateID == "" {
		return ErrMissingRequiredFlag{Flag: "template"}
	}
	if hostname == "" {
		return ErrMissingRequiredFlag{Flag: "hostname"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	labelMap, err := parseLabels(labels)
	if err != nil {
		return err
	}

	opts := &vtpmsvc.CloneOptions{
		TemplateID: templateID,
		Hostname:   hostname,
		Labels:     labelMap,
	}

	ctx := base.Context()
	resp, err := sdkClient.CloneTemplateDomain(ctx, opts)
	if err != nil {
		return ErrCloneBundleFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Bundle != nil {
			printer.PrintSuccess(fmt.Sprintf("Bundle cloned successfully: %s", resp.Bundle.ID))
			fmt.Println()
			printBundleDetails(printer, resp.Bundle)
		} else if resp.Status != nil && !resp.Status.Success {
			printer.PrintError(fmt.Sprintf("Clone failed: %s", resp.Status.Message))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
