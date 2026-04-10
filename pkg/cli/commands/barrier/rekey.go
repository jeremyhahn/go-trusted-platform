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

package barrier

import (
	"fmt"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newRekeyCommand creates the barrier rekey subcommand
func newRekeyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		threshold int32
		shares    int32
	)

	cmd := &cobra.Command{
		Use:   "rekey",
		Short: "Rekey the barrier",
		Long: `Generate new unseal keys for the barrier.

This operation rotates the barrier encryption keys and generates new
unseal credentials. The barrier must be unsealed to perform a rekey.

If threshold >= 2 and shares >= threshold, Shamir secret sharing mode is used.
Otherwise, a single new unseal key is generated.

The new unseal keys are only shown once and must be stored securely.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRekey(flags, threshold, shares)
		},
	}

	cmd.Flags().Int32Var(&threshold, "threshold", 1, "minimum shares required to unseal (>= 2 for Shamir mode)")
	cmd.Flags().Int32Var(&shares, "shares", 1, "total number of Shamir shares to generate")

	return cmd
}

func runRekey(flags *cli.CommonFlags, threshold, shares int32) error {
	if threshold >= 2 && shares < threshold {
		return ErrInvalidThreshold{Threshold: threshold, Shares: shares}
	}

	if shares < 1 {
		return ErrInvalidShares{Shares: shares}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	ctx := base.Context()
	resp, err := base.Client().Barrier().Rekey(ctx, &platformv1.BarrierRekeyRequest{
		Threshold: threshold,
		Shares:    shares,
	})
	if err != nil {
		return ErrBarrierRekeyFailed{Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		return printRekeyTable(printer, resp)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func printRekeyTable(printer *cli.Printer, resp *platformv1.BarrierRekeyResponse) error {
	printer.PrintSuccess("Barrier rekeyed successfully")
	fmt.Println()

	printer.PrintKeyValue("Strategy", formatStrategy(resp.Strategy))

	fmt.Println()

	if len(resp.UnsealKeys) > 0 {
		printer.PrintWarning("Store the following new unseal keys securely. They are only shown once.")
		fmt.Println()

		for i, key := range resp.UnsealKeys {
			printer.PrintKeyValue(fmt.Sprintf("Unseal Key %d", i+1), key)
		}
	}

	return nil
}
