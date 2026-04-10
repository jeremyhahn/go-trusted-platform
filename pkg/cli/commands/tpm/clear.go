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

package tpm

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newClearCommand creates the clear subcommand for TPM clear operations
func newClearCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var ownerPassword string
	var confirm bool
	var force bool
	var device string

	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Clear the TPM",
		Long: `This command removes all TPM context associated with a specific Owner.

The clear operation will:
  - Flush resident objects (persistent and volatile) in the Storage and Endorsement hierarchies
  - Delete any NV Index with TPMA_NV_PLATFORMCREATE == CLEAR
  - Change the storage primary seed (SPS) to a new value from the TPM RNG
  - Change shProof and ehProof
  - SET shEnable and ehEnable
  - Set ownerAuth, endorsementAuth, and lockoutAuth to the Empty Buffer
  - Set ownerPolicy, endorsementPolicy, and lockoutPolicy to the Empty Buffer
  - Set Clock to zero
  - Set resetCount to zero
  - Set restartCount to zero
  - Set Safe to YES
  - Increment pcrUpdateCounter

WARNING: This operation is destructive and cannot be undone.

This command requires Platform Authorization or Lockout Authorization.

The --force flag uses the UEFI Physical Presence Interface (PPI) to schedule
a TPM clear on next reboot. This bypasses DA lockout and does not require any
TPM authorization. The system will reboot automatically.

Examples:
  # Clear the TPM (requires confirmation)
  platformctl tpm clear --confirm

  # Force clear via UEFI PPI (bypasses DA lockout, triggers reboot)
  platformctl tpm clear --force --confirm

  # Clear with owner password
  platformctl tpm clear --owner-password mypassword --confirm`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirm {
				cmd.Println("WARNING: This operation will clear all TPM data.")
				cmd.Println("Use --confirm to proceed.")
				return nil
			}
			if force {
				return runForceClear(device)
			}
			flags := getFlags()
			return runClear(flags, ownerPassword)
		},
	}

	cmd.Flags().StringVar(&ownerPassword, "owner-password", "", "TPM owner/lockout hierarchy password")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "confirm the clear operation")
	cmd.Flags().BoolVar(&force, "force", false, "force clear via UEFI PPI (bypasses DA lockout, triggers reboot)")
	cmd.Flags().StringVar(&device, "device", "/dev/tpm0", "TPM device path")

	return cmd
}

// runForceClear uses the go-xkms TPM library's ForceClear method to schedule
// a TPM clear via the UEFI Physical Presence Interface (PPI). This bypasses
// DA lockout. The system reboots automatically after scheduling.
func runForceClear(devicePath string) error {
	params := &xkmssdk.TPMParams{
		Config: &xkmssdk.TPMConfig{
			Device: devicePath,
		},
	}

	tpm, err := xkmssdk.NewTPM2(params)
	if err != nil && tpm == nil {
		return ErrTPMClearFailed{Reason: fmt.Sprintf("failed to open TPM: %v", err)}
	}
	defer tpm.Close()

	if err := tpm.ForceClear(); err != nil {
		return ErrTPMClearFailed{Reason: err.Error()}
	}

	fmt.Println("TPM clear scheduled via UEFI Physical Presence Interface.")
	fmt.Println("The TPM will be cleared on next reboot.")
	fmt.Println("Rebooting now...")

	if err := os.WriteFile("/proc/sysrq-trigger", []byte("b"), 0200); err != nil {
		fmt.Printf("Auto-reboot failed: %v\n", err)
		fmt.Println("Please reboot manually to complete the TPM clear.")
	}

	return nil
}

// runClear executes the clear command
func runClear(flags *cli.CommonFlags, ownerPassword string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runClearWithClient(&tpmBaseCommandAdapter{base: base}, ownerPassword)
}

// runClearWithClient runs clear with a testable interface
func runClearWithClient(base TPMBaseCommandInterface, ownerPassword string) error {
	defer base.Close()

	req := &platformv1.TPMClearRequest{
		OwnerPassword: ownerPassword,
		Confirm:       true,
	}

	ctx := base.Context()
	resp, err := base.TPMClient().Clear(ctx, req)
	if err != nil {
		return ErrTPMClearFailed{Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrTPMClearFailed{Reason: msg}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"success": resp.Status.Success,
		"message": resp.Status.Message,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess("TPM cleared successfully")
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
