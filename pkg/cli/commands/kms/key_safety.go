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

//go:build key_safety

// NOTE: This file requires go-quicbaas KMS safety API features that are not yet
// released in the SDK. The local request/response types below mirror the planned
// SDK contract. Enable with: go build -tags key_safety

package kms

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// Local KMS safety request/response types
// These mirror the planned go-quicbaas SDK types for AEAD safety limits.
// Once the SDK publishes these types, replace with SDK imports.
// =============================================================================

// SetKeySafetyRequest is the request to set AEAD safety limits for a key.
type SetKeySafetyRequest struct {
	KeyId          string `json:"key_id"`
	MaxOperations  uint64 `json:"max_operations"`
	MaxBytes       uint64 `json:"max_bytes"`
	WarningPercent int32  `json:"warning_percent"`
}

// SetKeySafetyResponse is the response after setting AEAD safety limits.
type SetKeySafetyResponse struct {
	KeyId     string `json:"key_id"`
	Timestamp int64  `json:"timestamp"`
}

// GetKeySafetyRequest is the request to get AEAD safety stats for a key.
type GetKeySafetyRequest struct {
	KeyId string `json:"key_id"`
}

// GetKeySafetyResponse is the response containing AEAD safety stats.
type GetKeySafetyResponse struct {
	KeyId           string  `json:"key_id"`
	MaxOperations   uint64  `json:"max_operations"`
	MaxBytes        uint64  `json:"max_bytes"`
	WarningPercent  int32   `json:"warning_percent"`
	OperationsUsed  uint64  `json:"operations_used"`
	BytesUsed       uint64  `json:"bytes_used"`
	UsagePercent    float64 `json:"usage_percent"`
	Status          string  `json:"status"`
	HasCustomLimits bool    `json:"has_custom_limits"`
	Timestamp       int64   `json:"timestamp"`
}

// ClearKeySafetyRequest is the request to clear custom AEAD safety limits.
type ClearKeySafetyRequest struct {
	KeyId string `json:"key_id"`
}

// ClearKeySafetyResponse is the response after clearing AEAD safety limits.
type ClearKeySafetyResponse struct {
	KeyId     string `json:"key_id"`
	Timestamp int64  `json:"timestamp"`
}

// SafetyCheckRequest is the request to check for keys approaching safety limits.
type SafetyCheckRequest struct{}

// SafetyWarning represents a single safety warning for a key or DEK.
type SafetyWarning struct {
	Type           string  `json:"type"`
	Path           string  `json:"path"`
	UsagePercent   float64 `json:"usage_percent"`
	Status         string  `json:"status"`
	OperationsUsed uint64  `json:"operations_used"`
	MaxOperations  uint64  `json:"max_operations"`
	BytesUsed      uint64  `json:"bytes_used"`
	MaxBytes       uint64  `json:"max_bytes"`
}

// SafetyCheckResponse is the response containing safety warnings.
type SafetyCheckResponse struct {
	Warnings  []*SafetyWarning `json:"warnings"`
	Timestamp int64            `json:"timestamp"`
}

// SafetyReportRequest is the request to generate a comprehensive safety report.
type SafetyReportRequest struct{}

// SafetyReportResponse is the response containing the full safety report.
type SafetyReportResponse struct {
	TotalKeys      int64            `json:"total_keys"`
	TotalDeks      int64            `json:"total_deks"`
	KeysAtWarning  int64            `json:"keys_at_warning"`
	KeysAtCritical int64            `json:"keys_at_critical"`
	DeksAtWarning  int64            `json:"deks_at_warning"`
	DeksAtCritical int64            `json:"deks_at_critical"`
	AllItems       []*SafetyWarning `json:"all_items"`
	Timestamp      int64            `json:"timestamp"`
}

// =============================================================================
// Error types
// =============================================================================

// ErrSetKeySafetyFailed is returned when setting key safety limits fails
type ErrSetKeySafetyFailed struct {
	KeyID string
	Err   error
}

func (e ErrSetKeySafetyFailed) Error() string {
	return fmt.Sprintf("failed to set safety limits for key %s: %v", e.KeyID, e.Err)
}

// ErrClearKeySafetyFailed is returned when clearing key safety limits fails
type ErrClearKeySafetyFailed struct {
	KeyID string
	Err   error
}

func (e ErrClearKeySafetyFailed) Error() string {
	return fmt.Sprintf("failed to clear safety limits for key %s: %v", e.KeyID, e.Err)
}

// ErrSafetyCheckFailed is returned when safety check fails
type ErrSafetyCheckFailed struct {
	Err error
}

func (e ErrSafetyCheckFailed) Error() string {
	return fmt.Sprintf("failed to perform safety check: %v", e.Err)
}

// ErrSafetyReportFailed is returned when safety report generation fails
type ErrSafetyReportFailed struct {
	Err error
}

func (e ErrSafetyReportFailed) Error() string {
	return fmt.Sprintf("failed to generate safety report: %v", e.Err)
}

// ErrGetKeySafetyFailed is returned when getting key safety stats fails
type ErrGetKeySafetyFailed struct {
	KeyID string
	Err   error
}

func (e ErrGetKeySafetyFailed) Error() string {
	return fmt.Sprintf("failed to get safety stats for key %s: %v", e.KeyID, e.Err)
}

// =============================================================================
// Commands
// =============================================================================

// newKeySafetyCommand creates the key safety subcommand group
func newKeySafetyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "safety",
		Short: "Manage AEAD safety limits",
		Long: `Configure and monitor AEAD (Authenticated Encryption with Associated Data) safety limits.

AEAD algorithms like AES-GCM have cryptographic limits on how many operations
can be safely performed with the same key. This command group helps you:
  - Set custom safety limits for keys
  - Clear custom limits and revert to defaults
  - Check which keys are approaching their limits
  - Generate comprehensive safety reports`,
	}

	cmd.AddCommand(newKeySafetySetCommand(getFlags))
	cmd.AddCommand(newKeySafetyGetCommand(getFlags))
	cmd.AddCommand(newKeySafetyClearCommand(getFlags))
	cmd.AddCommand(newKeySafetyCheckCommand(getFlags))
	cmd.AddCommand(newKeySafetyReportCommand(getFlags))

	return cmd
}

// newKeySafetySetCommand creates the safety set subcommand
func newKeySafetySetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var maxOperations uint64
	var maxBytes uint64
	var warningPercent int32

	cmd := &cobra.Command{
		Use:   "set <key-id>",
		Short: "Set AEAD safety limits for a key",
		Long: `Configure custom AEAD safety limits for a cryptographic key.

These limits help prevent cryptographic failures by tracking usage and
warning before reaching unsafe thresholds.

Examples:
  # Set limits for a key
  platformctl kms key safety set my-key --max-operations 1000000 --max-bytes 1073741824

  # Set with custom warning threshold (default is 80%)
  platformctl kms key safety set my-key --max-operations 500000 --warning-percent 70`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runSetKeySafety(flags, args[0], maxOperations, maxBytes, warningPercent)
		},
	}

	cmd.Flags().Uint64Var(&maxOperations, "max-operations", 0, "maximum number of operations")
	cmd.Flags().Uint64Var(&maxBytes, "max-bytes", 0, "maximum bytes that can be encrypted")
	cmd.Flags().Int32Var(&warningPercent, "warning-percent", 80, "warning threshold percentage (1-99)")

	return cmd
}

// newKeySafetyGetCommand creates the safety get subcommand
func newKeySafetyGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <key-id>",
		Short: "Get AEAD safety stats for a key",
		Long: `Retrieve the AEAD safety configuration and current usage statistics for a key.

This command displays:
  - Configured safety limits (max operations, max bytes)
  - Current usage (operations used, bytes used)
  - Usage percentage and status (OK, Warning, Critical, Exceeded)
  - Whether the key has custom limits or uses defaults

Examples:
  # Get safety stats for a key
  platformctl kms key safety get my-key

  # Get stats with JSON output
  platformctl kms key safety get my-key --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGetKeySafety(flags, args[0])
		},
	}

	return cmd
}

// newKeySafetyClearCommand creates the safety clear subcommand
func newKeySafetyClearCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clear <key-id>",
		Short: "Clear custom AEAD safety limits",
		Long: `Remove custom AEAD safety limits from a key, reverting to defaults.

Examples:
  # Clear custom limits
  platformctl kms key safety clear my-key`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runClearKeySafety(flags, args[0])
		},
	}

	return cmd
}

// newKeySafetyCheckCommand creates the safety check subcommand
func newKeySafetyCheckCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check for keys approaching safety limits",
		Long: `Return warnings for keys and DEKs approaching their AEAD safety limits.

This command only shows items that are at warning, critical, or exceeded
threshold levels. Use 'safety report' for a complete view of all items.

Examples:
  # Check for warnings
  platformctl kms key safety check

  # Check with JSON output
  platformctl kms key safety check --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runSafetyCheck(flags)
		},
	}

	return cmd
}

// newKeySafetyReportCommand creates the safety report subcommand
func newKeySafetyReportCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate comprehensive safety report",
		Long: `Generate a detailed report of AEAD safety status for all keys and DEKs.

The report includes summary statistics and detailed status for each item.

Examples:
  # Generate safety report
  platformctl kms key safety report

  # Report in JSON format
  platformctl kms key safety report --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runSafetyReport(flags)
		},
	}

	return cmd
}

func runSetKeySafety(flags *cli.CommonFlags, keyID string, maxOperations, maxBytes uint64, warningPercent int32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &SetKeySafetyRequest{
		KeyId:          keyID,
		MaxOperations:  maxOperations,
		MaxBytes:       maxBytes,
		WarningPercent: warningPercent,
	}

	ctx := base.Context()
	resp, err := base.Client().KMS().SetKeySafety(ctx, req)
	if err != nil {
		return ErrSetKeySafetyFailed{KeyID: keyID, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Safety limits set for key: %s", resp.KeyId))
		fmt.Println()
		printer.PrintKeyValue("Key ID", resp.KeyId)
		printer.PrintKeyValue("Max Operations", fmt.Sprintf("%d", maxOperations))
		printer.PrintKeyValue("Max Bytes", formatDEKBytes(maxBytes))
		printer.PrintKeyValue("Warning Threshold", fmt.Sprintf("%d%%", warningPercent))
		printer.PrintKeyValue("Updated At", formatKeyTimestamp(resp.Timestamp))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runGetKeySafety(flags *cli.CommonFlags, keyID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &GetKeySafetyRequest{
		KeyId: keyID,
	}

	ctx := base.Context()
	resp, err := base.Client().KMS().GetKeySafety(ctx, req)
	if err != nil {
		return ErrGetKeySafetyFailed{KeyID: keyID, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintInfo(fmt.Sprintf("Safety Stats for Key: %s", resp.KeyId))
		fmt.Println()

		// Format max operations with custom indicator
		maxOpsStr := fmt.Sprintf("%d", resp.MaxOperations)
		if resp.HasCustomLimits {
			maxOpsStr += " (custom)"
		} else {
			maxOpsStr += " (default)"
		}

		printer.PrintKeyValue("Key ID", resp.KeyId)
		printer.PrintKeyValue("Max Operations", maxOpsStr)
		printer.PrintKeyValue("Max Bytes", formatDEKBytes(resp.MaxBytes))
		printer.PrintKeyValue("Warning At", fmt.Sprintf("%d%%", resp.WarningPercent))
		printer.PrintKeyValue("Operations Used", fmt.Sprintf("%d (%.2f%%)", resp.OperationsUsed, calculateOpPercent(resp.OperationsUsed, resp.MaxOperations)))
		printer.PrintKeyValue("Bytes Used", fmt.Sprintf("%s (%.2f%%)", formatDEKBytes(resp.BytesUsed), calculateBytePercent(resp.BytesUsed, resp.MaxBytes)))
		printer.PrintKeyValue("Overall Usage", fmt.Sprintf("%.2f%%", resp.UsagePercent))
		printer.PrintKeyValue("Status", formatSafetyStatus(resp.Status))
		printer.PrintKeyValue("Limits Type", formatLimitsType(resp.HasCustomLimits))
		printer.PrintKeyValue("Retrieved At", formatKeyTimestamp(resp.Timestamp))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// calculateOpPercent calculates the percentage of operations used
func calculateOpPercent(used, max uint64) float64 {
	if max == 0 {
		return 0
	}
	return float64(used) * 100 / float64(max)
}

// calculateBytePercent calculates the percentage of bytes used
func calculateBytePercent(used, max uint64) float64 {
	if max == 0 {
		return 0
	}
	return float64(used) * 100 / float64(max)
}

// formatLimitsType formats the limits type indicator
func formatLimitsType(hasCustom bool) string {
	if hasCustom {
		return "Custom"
	}
	return "Default (NIST SP 800-38D)"
}

func runClearKeySafety(flags *cli.CommonFlags, keyID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &ClearKeySafetyRequest{
		KeyId: keyID,
	}

	ctx := base.Context()
	resp, err := base.Client().KMS().ClearKeySafety(ctx, req)
	if err != nil {
		return ErrClearKeySafetyFailed{KeyID: keyID, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Safety limits cleared for key: %s", resp.KeyId))
		fmt.Println()
		printer.PrintKeyValue("Key ID", resp.KeyId)
		printer.PrintKeyValue("Cleared At", formatKeyTimestamp(resp.Timestamp))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runSafetyCheck(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &SafetyCheckRequest{}

	ctx := base.Context()
	resp, err := base.Client().KMS().SafetyCheck(ctx, req)
	if err != nil {
		return ErrSafetyCheckFailed{Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if len(resp.Warnings) == 0 {
			printer.PrintSuccess("No safety warnings - all keys within limits")
			return nil
		}

		printer.PrintInfo(fmt.Sprintf("Safety Warnings (%d items)", len(resp.Warnings)))
		fmt.Println()

		table := cli.NewTableData("Type", "Path/ID", "Usage %", "Status", "Operations", "Bytes")
		for _, w := range resp.Warnings {
			table.AddRow(
				w.Type,
				w.Path,
				fmt.Sprintf("%.1f%%", w.UsagePercent),
				formatSafetyStatus(w.Status),
				fmt.Sprintf("%d / %d", w.OperationsUsed, w.MaxOperations),
				fmt.Sprintf("%s / %s", formatDEKBytes(w.BytesUsed), formatDEKBytes(w.MaxBytes)),
			)
		}

		if err := printer.Print(*table); err != nil {
			return err
		}

		fmt.Println()
		printer.PrintKeyValue("Checked At", formatKeyTimestamp(resp.Timestamp))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runSafetyReport(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &SafetyReportRequest{}

	ctx := base.Context()
	resp, err := base.Client().KMS().SafetyReport(ctx, req)
	if err != nil {
		return ErrSafetyReportFailed{Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintInfo("AEAD Safety Report")
		fmt.Println()

		// Summary statistics
		printer.PrintInfo("Summary:")
		printer.PrintKeyValue("  Total Keys", fmt.Sprintf("%d", resp.TotalKeys))
		printer.PrintKeyValue("  Total DEKs", fmt.Sprintf("%d", resp.TotalDeks))
		printer.PrintKeyValue("  Keys at Warning", fmt.Sprintf("%d", resp.KeysAtWarning))
		printer.PrintKeyValue("  Keys at Critical", fmt.Sprintf("%d", resp.KeysAtCritical))
		printer.PrintKeyValue("  DEKs at Warning", fmt.Sprintf("%d", resp.DeksAtWarning))
		printer.PrintKeyValue("  DEKs at Critical", fmt.Sprintf("%d", resp.DeksAtCritical))

		if len(resp.AllItems) > 0 {
			fmt.Println()
			printer.PrintInfo("Detailed Status:")
			fmt.Println()

			table := cli.NewTableData("Type", "Path/ID", "Usage %", "Status", "Operations", "Bytes")
			for _, item := range resp.AllItems {
				table.AddRow(
					item.Type,
					item.Path,
					fmt.Sprintf("%.1f%%", item.UsagePercent),
					formatSafetyStatus(item.Status),
					fmt.Sprintf("%d / %d", item.OperationsUsed, item.MaxOperations),
					fmt.Sprintf("%s / %s", formatDEKBytes(item.BytesUsed), formatDEKBytes(item.MaxBytes)),
				)
			}

			if err := printer.Print(*table); err != nil {
				return err
			}
		}

		fmt.Println()
		printer.PrintKeyValue("Report Generated At", formatKeyTimestamp(resp.Timestamp))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// formatSafetyStatus formats a safety status string with appropriate indicator
func formatSafetyStatus(status string) string {
	switch status {
	case "warning":
		return "[WARNING] Warning"
	case "critical":
		return "[CRITICAL] Critical"
	case "exceeded":
		return "[EXCEEDED] Exceeded"
	case "ok":
		return "[OK] OK"
	default:
		return status
	}
}
