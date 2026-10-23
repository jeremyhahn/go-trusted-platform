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

// init_shamir.go implements the canonical "barrier init-shamir" verb
// per docs/08-bootstrap-auth-architecture.md §6.
package barrier

import (
	"github.com/spf13/cobra"

	platformbarrier "github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// initShamirFlags holds the canonical `barrier init-shamir` flag set.
type initShamirFlags struct {
	secret    string
	threshold int
	total     int
	soPin     string
	userPin   string
}

// newInitShamirCommand builds the canonical `barrier init-shamir`
// command.
func newInitShamirCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &initShamirFlags{}
	cmd := &cobra.Command{
		Use:   "init-shamir",
		Short: "Initialize the barrier with Shamir secret sharing",
		Long: `Initialize the barrier with Shamir secret sharing (M-of-N).

  --passphrase   Required. Wrapping passphrase for the master key.
  --threshold    Required. M — number of shares needed to unseal (>= 2).
  --total        Required. N — total shares to generate (>= threshold).
  --so-pin       Optional. Sets the Security Officer PIN on the canonical
                 PINBackend. Requires --user-pin (dual-control).
  --user-pin     Optional. Sets the user PIN. Requires --so-pin.

The shares are not printed. Upstream seals each share to an enrolled
Security Officer and returns only the counts; each officer claims their
share with 'platformctl ceremony claim-share begin' and 'complete'.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInitShamir(getFlags(), f)
		},
	}
	cmd.Flags().StringVar(&f.secret, "passphrase", "", "Wrapping passphrase (required)")
	cmd.Flags().IntVar(&f.threshold, "threshold", 0,
		"Shamir threshold M — number of shares needed to unseal (required, >= 2)")
	cmd.Flags().IntVar(&f.total, "total", 0,
		"Shamir total N — total shares to generate (required, >= threshold)")
	cmd.Flags().StringVar(&f.soPin, "so-pin", "",
		"Security Officer PIN (requires --user-pin)")
	cmd.Flags().StringVar(&f.userPin, "user-pin", "",
		"User PIN (requires --so-pin)")
	return cmd
}

// validateInitShamirFlags applies the canonical flag-combination rules.
func validateInitShamirFlags(f *initShamirFlags) error {
	if f.secret == "" {
		return ErrMissingSecret{}
	}
	if err := validateShamirSplit(f.threshold, f.total); err != nil {
		return err
	}
	if f.userPin != "" && f.soPin == "" {
		return ErrUserPinRequiresSOPin{}
	}
	if f.soPin != "" && f.userPin == "" {
		return ErrSOPinRequiresUserPin{}
	}
	return nil
}

// validateShamirSplit applies pkg/barrier's Shamir rule to a --threshold /
// --total pair, reporting a total too small for any split before the
// threshold itself.
func validateShamirSplit(threshold, total int) error {
	if total < platformbarrier.MinShamirThreshold {
		return ErrInvalidTotal{Total: total}
	}
	if err := platformbarrier.ValidateShamirSplit(threshold, total); err != nil {
		return ErrInvalidThreshold{Threshold: threshold, Total: total, Err: err}
	}
	return nil
}

// runInitShamir validates the flag set and delegates to dispatchInitShamir.
func runInitShamir(flags *cli.CommonFlags, f *initShamirFlags) error {
	if err := validateInitShamirFlags(f); err != nil {
		return err
	}
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	bc, err := openBarrierClient(base)
	if err != nil {
		return err
	}
	return dispatchInitShamir(newDispatcherFromBase(base, bc), f)
}
