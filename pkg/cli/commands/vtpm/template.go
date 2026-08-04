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
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
)

// newTemplateCommand creates the template subcommand group for template management
func newTemplateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Manage vTPM templates",
		Long: `Manage vTPM templates for cloning.

Templates are base images that can be cloned to create bundles.
Each clone receives a unique EK certificate while sharing the
template's Secure Boot keys.

Examples:
  # Create a new template
  platformctl vtpm template create --id base-vtpm

  # List all templates
  platformctl vtpm template list

  # Delete a template
  platformctl vtpm template delete base-vtpm`,
	}

	// Add subcommands
	cmd.AddCommand(newTemplateCreateCommand(getFlags))
	cmd.AddCommand(newTemplateListCommand(getFlags))
	cmd.AddCommand(newTemplateDeleteCommand(getFlags))

	return cmd
}

// newTemplateCreateCommand creates the template create subcommand
func newTemplateCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		id          string
		description string
		secureBoot  bool
		ekAlgorithm string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new template",
		Long: `Create a new vTPM template for cloning.

A template includes:
- Initialized swtpm state (without EK certificate)
- OVMF NVRAM with Secure Boot keys enrolled (if enabled)
- Secure Boot keys for use by all clones

The EK certificate is NOT issued for templates. Instead, it is
issued when the template is cloned, giving each clone a unique
TPM identity.

Examples:
  # Create template with default settings
  platformctl vtpm template create --id base-vtpm

  # Create template with Secure Boot enabled
  platformctl vtpm template create --id secure-base --secure-boot=true

  # Create template with ECC EK algorithm
  platformctl vtpm template create --id ecc-template --ek-algorithm ECC

  # Create template and output as JSON
  platformctl vtpm template create --id base-vtpm -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTemplateCreate(flags, id, description, secureBoot, ekAlgorithm)
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "template ID (required)")
	cmd.Flags().StringVar(&description, "description", "", "template description")
	cmd.Flags().BoolVar(&secureBoot, "secure-boot", true, "enable Secure Boot key generation")
	cmd.Flags().StringVar(&ekAlgorithm, "ek-algorithm", "RSA", "EK algorithm for clones (RSA or ECC)")

	_ = cmd.MarkFlagRequired("id")

	return cmd
}

// runTemplateCreate executes the template create command
func runTemplateCreate(flags *cli.CommonFlags, id, description string, secureBoot bool, ekAlgorithm string) error {
	// Validate ID is provided
	if id == "" {
		return ErrMissingRequiredFlag{Flag: "id"}
	}

	// Validate EK algorithm
	ekAlg, err := parseEKAlgorithm(ekAlgorithm)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	opts := &vtpmsvc.CreateTemplateOptions{
		ID:                id,
		Description:       description,
		EKAlgorithm:       ekAlg,
		SecureBootEnabled: secureBoot,
	}

	ctx := base.Context()
	resp, err := sdkClient.CreateTemplateDomain(ctx, opts)
	if err != nil {
		return ErrCreateTemplateFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Template != nil {
			printer.PrintSuccess(fmt.Sprintf("Template created: %s", resp.Template.ID))
			fmt.Println()
			printTemplateDetails(printer, resp.Template)
		} else if resp.Status != nil && !resp.Status.Success {
			printer.PrintError(fmt.Sprintf("Failed to create template: %s", resp.Status.Message))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// newTemplateListCommand creates the template list subcommand
func newTemplateListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all templates",
		Long: `List all available vTPM templates.

Displays template information including ID, Secure Boot status,
EK algorithm, and creation time.

Examples:
  # List all templates
  platformctl vtpm template list

  # Output as JSON
  platformctl vtpm template list -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTemplateList(flags)
		},
	}

	return cmd
}

// runTemplateList executes the template list command
func runTemplateList(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	ctx := base.Context()
	resp, err := sdkClient.ListTemplatesDomain(ctx)
	if err != nil {
		return ErrListTemplatesFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if len(resp.Templates) == 0 {
			printer.PrintInfo("No templates found")
			return nil
		}

		table := cli.NewTableData("ID", "Description", "EK Alg", "Secure Boot", "Created")
		for _, tmpl := range resp.Templates {
			created := ""
			if tmpl.CreatedAt != nil {
				created = (*tmpl.CreatedAt).Format("2006-01-02 15:04")
			}

			table.AddRow(
				truncateID(tmpl.ID, 20),
				truncateString(tmpl.Description, 30),
				string(tmpl.EKAlgorithm),
				formatBool(tmpl.SecureBootEnabled),
				created,
			)
		}

		if err := printer.Print(*table); err != nil {
			return err
		}

		fmt.Println()
		printer.PrintKeyValue("Total", fmt.Sprintf("%d templates", len(resp.Templates)))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// newTemplateDeleteCommand creates the template delete subcommand
func newTemplateDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "delete [template-id]",
		Short: "Delete a template",
		Long: `Delete a vTPM template and all associated files.

This operation is irreversible. Use --force to skip the confirmation prompt.

Note: This does not affect bundles that were cloned from this template.
Existing clones will continue to function normally.

Examples:
  # Delete a template (with confirmation)
  platformctl vtpm template delete base-vtpm

  # Delete a template without confirmation
  platformctl vtpm template delete base-vtpm --force`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTemplateDelete(flags, args[0], force)
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "skip confirmation prompt")

	return cmd
}

// runTemplateDelete executes the template delete command
func runTemplateDelete(flags *cli.CommonFlags, templateID string, force bool) error {
	// Validate template ID is provided
	if templateID == "" {
		return ErrMissingRequiredFlag{Flag: "template-id"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	sdkClient := vtpmsvc.NewClientFromGRPC(base.Client().VTPM())

	printer := base.Printer()

	// Confirm deletion if not forced
	if !force {
		printer.PrintWarning(fmt.Sprintf("This will permanently delete template '%s' and all associated files.", templateID))
		fmt.Print("Are you sure you want to proceed? [y/N]: ")

		reader := bufio.NewReader(os.Stdin)
		response, readErr := reader.ReadString('\n')
		if readErr != nil {
			return readErr
		}

		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			printer.PrintInfo("Operation cancelled")
			return nil
		}
	}

	ctx := base.Context()
	resp, err := sdkClient.DeleteTemplateDomain(ctx, templateID)
	if err != nil {
		return ErrDeleteTemplateFailed{Reason: err.Error()}
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess(fmt.Sprintf("Template '%s' deleted successfully", templateID))
		} else {
			msg := "unknown error"
			if resp.Status != nil && resp.Status.Message != "" {
				msg = resp.Status.Message
			}
			printer.PrintError(fmt.Sprintf("Failed to delete template: %s", msg))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printTemplateDetails prints template details in table format
func printTemplateDetails(printer *cli.Printer, tmpl *vtpmsvc.Template) {
	printer.PrintKeyValue("ID", tmpl.ID)
	if tmpl.Description != "" {
		printer.PrintKeyValue("Description", tmpl.Description)
	}
	printer.PrintKeyValue("EK Algorithm", string(tmpl.EKAlgorithm))
	printer.PrintKeyValue("Secure Boot", formatBool(tmpl.SecureBootEnabled))

	if tmpl.TPMStateDir != "" {
		printer.PrintKeyValue("TPM State Dir", tmpl.TPMStateDir)
	}
	if tmpl.NVRAMPath != "" {
		printer.PrintKeyValue("NVRAM Path", tmpl.NVRAMPath)
	}
	if tmpl.SecureBootKeysDir != "" {
		printer.PrintKeyValue("Secure Boot Keys Dir", tmpl.SecureBootKeysDir)
	}

	if tmpl.CreatedAt != nil {
		printer.PrintKeyValue("Created", (*tmpl.CreatedAt).Format("2006-01-02 15:04:05 MST"))
	}
}
