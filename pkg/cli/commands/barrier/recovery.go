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

// recovery.go implements the canonical "barrier recovery" command
// group with two verbs:
//
//   - "barrier recovery generate" — generate recovery shares
//   - "barrier recovery recover"  — unseal with recovery shares
//
// Recovery shares are a disaster-recovery sideband separate from the
// primary Shamir share set.
package barrier

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newRecoveryCommand builds the canonical `barrier recovery` group.
func newRecoveryCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recovery",
		Short: "Disaster-recovery share operations",
		Long: `Manage the barrier's disaster-recovery share set.

  generate  Generate new recovery shares (M-of-N).
  recover   Unseal the barrier with recovery shares.

Recovery shares are independent of the primary Shamir set used by
"barrier unseal-shares".`,
	}
	cmd.AddCommand(newRecoveryGenerateCommand(getFlags))
	cmd.AddCommand(newRecoveryRecoverCommand(getFlags))
	return cmd
}

// ---------------------------------------------------------------------------
// recovery generate
// ---------------------------------------------------------------------------

// recoveryGenerateFlags holds the canonical `recovery generate` flag set.
type recoveryGenerateFlags struct {
	threshold int
	total     int
	soPin     string
}

// newRecoveryGenerateCommand builds `barrier recovery generate`.
func newRecoveryGenerateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &recoveryGenerateFlags{}
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate recovery shares (M-of-N)",
		Long: `Generate new recovery shares.

  --threshold   Required. M — number of shares needed to recover (>= 2).
  --total       Required. N — total recovery shares to generate (>= threshold).
  --so-pin      Optional. Security Officer PIN verified against the canonical PINBackend.

The generated shares are returned to stdout and MUST be captured and
distributed to disaster-recovery custodians.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRecoveryGenerate(getFlags(), f)
		},
	}
	cmd.Flags().IntVar(&f.threshold, "threshold", 0,
		"Recovery threshold M (required, >= 2)")
	cmd.Flags().IntVar(&f.total, "total", 0,
		"Recovery total N (required, >= threshold)")
	cmd.Flags().StringVar(&f.soPin, "so-pin", "",
		"Security Officer PIN (canonical PINBackend)")
	return cmd
}

// validateRecoveryGenerateFlags applies the canonical rules.
func validateRecoveryGenerateFlags(f *recoveryGenerateFlags) error {
	if f.total < 2 {
		return ErrInvalidTotal{Total: f.total}
	}
	if f.threshold < 2 || f.threshold > f.total {
		return ErrInvalidThreshold{Threshold: f.threshold, Total: f.total}
	}
	return nil
}

// runRecoveryGenerate validates the flag set and delegates to
// dispatchRecoveryGenerate.
func runRecoveryGenerate(flags *cli.CommonFlags, f *recoveryGenerateFlags) error {
	if err := validateRecoveryGenerateFlags(f); err != nil {
		return err
	}
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	bc, qerr := openBarrierClient(base)
	if qerr != nil {
		return qerr
	}
	return dispatchRecoveryGenerate(newDispatcherFromBase(base, bc), f)
}

// ---------------------------------------------------------------------------
// recovery recover
// ---------------------------------------------------------------------------

// recoveryRecoverFlags holds the canonical `recovery recover` flag set.
type recoveryRecoverFlags struct {
	shares []string
}

// newRecoveryRecoverCommand builds `barrier recovery recover`.
func newRecoveryRecoverCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &recoveryRecoverFlags{}
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Unseal the barrier with recovery shares",
		Long: `Unseal the barrier using recovery shares.

  --share  Repeatable. Submit one recovery share per --share flag.

The verb submits the shares in a single BarrierRecoverWithKeys RPC.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRecoveryRecover(getFlags(), f)
		},
	}
	cmd.Flags().StringArrayVar(&f.shares, "share", nil,
		"Recovery share to submit (repeatable)")
	return cmd
}

// validateRecoveryRecoverFlags applies the canonical rules.
func validateRecoveryRecoverFlags(f *recoveryRecoverFlags) error {
	if len(f.shares) == 0 {
		return ErrMissingShares{}
	}
	return nil
}

// runRecoveryRecover validates the flag set and delegates to
// dispatchRecoveryRecover.
func runRecoveryRecover(flags *cli.CommonFlags, f *recoveryRecoverFlags) error {
	if err := validateRecoveryRecoverFlags(f); err != nil {
		return err
	}
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	bc, qerr := openBarrierClient(base)
	if qerr != nil {
		return qerr
	}
	return dispatchRecoveryRecover(newDispatcherFromBase(base, bc), f.shares)
}
