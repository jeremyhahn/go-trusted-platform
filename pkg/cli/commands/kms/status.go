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
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

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

func (e ErrKMSStatusFailed) Unwrap() error {
	return e.Err
}

// kmsStatusOutput is the CLI presentation of the KMS backend status.
type kmsStatusOutput struct {
	BackendType  string          `json:"backend_type"`
	Status       string          `json:"status"`
	Device       string          `json:"device,omitempty"`
	Region       string          `json:"region,omitempty"`
	KeyID        string          `json:"key_id,omitempty"`
	PCRBanks     []string        `json:"pcr_banks,omitempty"`
	PCRRegisters []int           `json:"pcr_registers,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
}

// newKMSStatusOutput converts the SDK backend status for display.
func newKMSStatusOutput(resp *kms.BackendStatusResponse) *kmsStatusOutput {
	return &kmsStatusOutput{
		BackendType:  resp.BackendType,
		Status:       resp.Status,
		Device:       resp.Device,
		Region:       resp.Region,
		KeyID:        resp.KeyID,
		PCRBanks:     resp.PCRBanks,
		PCRRegisters: resp.PCRRegisters,
		Capabilities: resp.Capabilities,
	}
}

// NewStatusCommand creates the KMS status command
func NewStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show KMS backend status",
		Long:  "Display the current status, health, and capabilities of the KMS backend",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKMSStatus(getFlags())
		},
	}

	return cmd
}

// runKMSStatus opens the SDK connection and delegates to executeKMSStatus.
func runKMSStatus(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openKMSClient(base)
	if err != nil {
		return err
	}
	return executeKMSStatus(base.Context(), client, base.Printer(), flags.OutputFormat)
}

// executeKMSStatus retrieves and displays KMS backend status via the
// quicbaas SDK KMS client.
func executeKMSStatus(ctx context.Context, client quicbaassdk.KMSClient, printer *cli.Printer, format cli.OutputFormat) error {
	resp, err := client.BackendStatus(ctx)
	if err != nil {
		return ErrKMSStatusFailed{Err: err}
	}

	out := newKMSStatusOutput(resp)

	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(out)

	case cli.OutputFormatTable:
		return printKMSStatusTable(printer, out)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// printKMSStatusTable prints KMS status in table format
func printKMSStatusTable(printer *cli.Printer, resp *kmsStatusOutput) error {
	// Print header based on status
	statusStr := "UNKNOWN"
	if resp.Status != "" {
		statusStr = resp.Status
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
	if len(resp.PCRBanks) > 0 {
		fmt.Println()
		printer.PrintInfo("PCR Configuration:")
		printer.PrintKeyValue("  PCR Banks", strings.Join(resp.PCRBanks, ", "))

		if len(resp.PCRRegisters) > 0 {
			registers := make([]string, len(resp.PCRRegisters))
			for i, r := range resp.PCRRegisters {
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
