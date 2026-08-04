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

package secureboot

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

// enforceResult reports the outcome of the enforce pipeline.
type enforceResult struct {
	AlreadyEnforced bool          `json:"already_enforced" yaml:"already_enforced"`
	Enroll          *enrollResult `json:"enroll,omitempty" yaml:"enroll,omitempty"`
}

// newEnforceCommand creates the enforce subcommand (dry-run by default).
func newEnforceCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &enrollOptions{}

	cmd := &cobra.Command{
		Use:   "enforce",
		Short: "Enforce UEFI Secure Boot with the verify-before-enforce gate (dry-run by default)",
		Long: `Transition the firmware into enforced UEFI Secure Boot, but only when
it is provably safe (the same gate the installer applies at deploy time).

If Secure Boot is already enforced the command reports success without
writing anything. Otherwise the firmware must be in Setup Mode and the
full enrollment pipeline runs: certificates load, the signed UKI verifies
against the DB certificate, then db -> KEK -> PK are written (PK LAST).
After a committed enrollment the firmware state is read back and the
Platform Key must be present, otherwise a typed error is returned.

Secure Boot enforcement becomes active on the next boot.`,
		Example: `  # Dry-run the enforcement gate
  platformctl secure-boot enforce

  # Enforce Secure Boot (requires Setup Mode unless already enforced)
  platformctl secure-boot enforce --commit`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			result, err := runEnforce(cmd.Context(), opts, nil)
			if err != nil {
				return err
			}
			return printEnforceResult(flags, result)
		},
	}

	addEnrollFlags(cmd, opts)
	return cmd
}

// runEnforce executes the enforcement gate. When verifier is nil the
// production Authenticode verifier is built; tests inject their own.
func runEnforce(ctx context.Context, opts *enrollOptions, verifier uefi.UKIVerifier) (*enforceResult, error) {
	status, err := uefi.ReadSecureBootStatusFromDir(opts.efivarsDir)
	if err != nil {
		return nil, err
	}

	// Already enforced: nothing to do, and enrollment would be refused by the
	// Setup Mode gate anyway.
	if status.SecureBoot && !status.SetupMode {
		return &enforceResult{AlreadyEnforced: true}, nil
	}

	enroll, err := runEnroll(ctx, opts, verifier)
	if err != nil {
		return nil, err
	}
	result := &enforceResult{Enroll: enroll}

	if enroll.DryRun {
		return result, nil
	}

	// A committed enrollment must leave a Platform Key in the firmware —
	// that is what takes it out of Setup Mode and arms enforcement on the
	// next boot.
	if !enroll.PostPKPresent {
		return nil, ErrEnforceIncomplete{Reason: "platform key not present after enrollment"}
	}
	return result, nil
}

// printEnforceResult renders an enforce result on the configured printer.
func printEnforceResult(flags *cli.CommonFlags, result *enforceResult) error {
	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)
	if flags.OutputFormat != cli.OutputFormatTable {
		return printer.Print(result)
	}
	if result.AlreadyEnforced {
		printer.PrintSuccess("Secure Boot is already enforced")
		return nil
	}
	if err := printEnrollResult(flags, result.Enroll); err != nil {
		return err
	}
	if result.Enroll.Enrolled {
		printer.PrintSuccess("Secure Boot enforcement armed — active on next boot")
	}
	return nil
}
