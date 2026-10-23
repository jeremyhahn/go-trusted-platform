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

// rekey.go implements the canonical "barrier rekey" verb.
//
// Rekey is a Shamir-only operation: the server generates a fresh unseal key
// and share set itself. New shares are sealed to enrolled Security Officers
// and claimed via the ShareClaimBegin/ShareClaimComplete flow.
//
// Per the canonical PIN matrix:
//   - --so-pin      is optional (Security Officer PIN verified against the canonical PINBackend).
//   - --threshold / --total are paired (both supplied or both omitted).
//
// The rekey is share-free: new shares are sealed to enrolled Security
// Officers and claimed via the share-claim flow, so no passphrase or
// share material crosses the wire.
package barrier

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// rekeyFlags holds the canonical `barrier rekey` flag set.
type rekeyFlags struct {
	soPin     string
	threshold int
	total     int
}

// newRekeyCommand builds the canonical `barrier rekey` command.
func newRekeyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &rekeyFlags{}
	cmd := &cobra.Command{
		Use:   "rekey",
		Short: "Rekey the barrier",
		Long: `Generate a new barrier master key and optionally a new Shamir split.

  --so-pin      Optional. Security Officer PIN verified against the canonical PINBackend.
  --threshold   Optional. New Shamir threshold (paired with --total).
  --total       Optional. New Shamir total (paired with --threshold).

Rekey is a Shamir-only operation. The server generates the new key and share
material itself. The new shares are not printed: they are sealed to enrolled
Security Officers, and each officer claims theirs with
'platformctl ceremony claim-share begin' and 'complete'.

When --threshold / --total are omitted the existing share layout is preserved.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRekey(getFlags(), f)
		},
	}
	cmd.Flags().StringVar(&f.soPin, "so-pin", "",
		"Security Officer PIN (canonical PINBackend; no --user-pin counterpart on rekey)")
	cmd.Flags().IntVar(&f.threshold, "threshold", 0,
		"New Shamir threshold (paired with --total)")
	cmd.Flags().IntVar(&f.total, "total", 0,
		"New Shamir total (paired with --threshold)")
	return cmd
}

// validateRekeyFlags applies the canonical flag-combination rules.
func validateRekeyFlags(f *rekeyFlags) error {
	// --threshold and --total must be set together (or both omitted).
	thresholdSet := f.threshold != 0
	totalSet := f.total != 0
	if thresholdSet != totalSet {
		return ErrRekeyPartialFlags{}
	}
	if thresholdSet {
		return validateShamirSplit(f.threshold, f.total)
	}
	return nil
}

// runRekey validates the flag set and delegates to dispatchRekey.
func runRekey(flags *cli.CommonFlags, f *rekeyFlags) error {
	if err := validateRekeyFlags(f); err != nil {
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
	return dispatchRekey(newDispatcherFromBase(base, bc), f)
}
