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

package kms

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrKMSClientNotInitialized is returned when the KMS client is not initialized
type ErrKMSClientNotInitialized struct{}

func (e ErrKMSClientNotInitialized) Error() string {
	return "KMS client not initialized"
}

// ErrKMSStatusFailed is returned when getting KMS status fails
type ErrKMSStatusFailed struct {
	Err error
}

func (e ErrKMSStatusFailed) Error() string {
	return fmt.Sprintf("failed to get KMS status: %v", e.Err)
}

// NewStatusCommand creates the KMS status command
func NewStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show KMS backend status",
		Long:  "Display the current status, health, and capabilities of the KMS backend",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runKMSStatus(flags)
		},
	}

	return cmd
}

// runKMSStatus retrieves and displays KMS backend status
func runKMSStatus(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	ctx := base.Context()
	resp, err := sdkClient.BackendStatusDomain(ctx)
	if err != nil {
		return ErrKMSStatusFailed{Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		return printKMSStatusTable(printer, resp)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printKMSStatusTable prints KMS status in table format
func printKMSStatusTable(printer *cli.Printer, resp *kmssvc.BackendStatusResult) error {
	// Print header based on status
	statusStr := "UNKNOWN"
	if resp.BackendStatus != "" {
		statusStr = resp.BackendStatus
	}
	statusIcon := formatStatusIcon(statusStr)
	printer.PrintInfo(fmt.Sprintf("KMS Backend Status: %s %s", statusIcon, statusStr))
	fmt.Println()

	// Print backend information
	printer.PrintKeyValue("Backend Type", resp.BackendType)

	if resp.Device != "" {
		printer.PrintKeyValue("Device", resp.Device)
	}

	if resp.Region != "" {
		printer.PrintKeyValue("Region", resp.Region)
	}

	if resp.KeyID != "" {
		printer.PrintKeyValue("Key ID", resp.KeyID)
	}

	// Print PCR information for TPM backends
	if len(resp.PcrBanks) > 0 {
		fmt.Println()
		printer.PrintInfo("PCR Configuration:")
		printer.PrintKeyValue("  PCR Banks", strings.Join(resp.PcrBanks, ", "))

		if len(resp.PcrRegisters) > 0 {
			registers := make([]string, len(resp.PcrRegisters))
			for i, r := range resp.PcrRegisters {
				registers[i] = fmt.Sprintf("%d", r)
			}
			printer.PrintKeyValue("  PCR Registers", strings.Join(registers, ", "))
		}
	}

	// Print capabilities
	if len(resp.Capabilities) > 0 {
		fmt.Println()
		printer.PrintInfo("Capabilities:")

		table := cli.NewTableData("Capability", "Supported")
		for capability, supported := range resp.Capabilities {
			supportedStr := "No"
			if supported {
				supportedStr = "Yes"
			}
			table.AddRow(formatCapabilityName(capability), supportedStr)
		}

		if err := printer.Print(*table); err != nil {
			return err
		}
	}

	// Print timestamp
	fmt.Println()
	printer.PrintKeyValue("Retrieved At", formatTimestamp(resp.Timestamp))

	return nil
}

// formatStatusIcon returns an appropriate icon for the status
func formatStatusIcon(status string) string {
	switch strings.ToLower(status) {
	case "healthy", "ready":
		return "[HEALTHY]"
	case "degraded":
		return "[DEGRADED]"
	case "unavailable", "error":
		return "[UNAVAILABLE]"
	default:
		return "[UNKNOWN]"
	}
}

// formatCapabilityName formats a capability name for display
func formatCapabilityName(name string) string {
	// Convert snake_case to Title Case
	parts := strings.Split(name, "_")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(string(part[0])) + strings.ToLower(part[1:])
		}
	}
	return strings.Join(parts, " ")
}
