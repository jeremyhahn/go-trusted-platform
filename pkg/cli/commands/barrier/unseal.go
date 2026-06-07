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

// unseal.go implements the canonical "barrier unseal" verb. Single
// passphrase unseal — the Shamir-share path lives in unseal_shares.go.
package barrier

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// unsealFlags holds the canonical `barrier unseal` flag set.
type unsealFlags struct {
	secret string
}

// newUnsealCommand builds the canonical `barrier unseal` command.
func newUnsealCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &unsealFlags{}
	cmd := &cobra.Command{
		Use:   "unseal",
		Short: "Unseal the barrier with a single passphrase",
		Long: `Unseal the barrier using a single passphrase.

For Shamir-sharded barriers use "barrier unseal-shares" instead.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUnseal(getFlags(), f)
		},
	}
	cmd.Flags().StringVar(&f.secret, "passphrase", "", "Unseal passphrase (required)")
	return cmd
}

// runUnseal validates and delegates to dispatchUnseal.
func runUnseal(flags *cli.CommonFlags, f *unsealFlags) error {
	if f.secret == "" {
		return ErrMissingSecret{}
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
	return dispatchUnseal(newDispatcherFromBase(base, bc), f.secret)
}
