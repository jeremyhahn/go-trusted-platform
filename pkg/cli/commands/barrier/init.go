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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	barriersvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/barrier"
)

// newInitCommand creates the barrier init subcommand
func newInitCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		secret    string
		threshold int32
		shares    int32
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the barrier",
		Long: `Initialize the barrier storage with encryption keys.

If threshold >= 2 and shares >= threshold, Shamir secret sharing mode is used.
Otherwise, single-key mode is used with the provided secret.

The unseal keys returned during initialization are only shown once and must
be stored securely. Loss of these keys means the barrier cannot be unsealed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runInit(flags, secret, threshold, shares)
		},
	}

	cmd.Flags().StringVar(&secret, "secret", "", "root secret for single-key mode")
	cmd.Flags().Int32Var(&threshold, "threshold", 1, "minimum shares required to unseal (>= 2 for Shamir mode)")
	cmd.Flags().Int32Var(&shares, "shares", 1, "total number of Shamir shares to generate")

	return cmd
}

func runInit(flags *cli.CommonFlags, secret string, threshold, shares int32) error {
	if err := validateInitParams(secret, threshold, shares); err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := barriersvc.NewClientFromGRPC(base.Client().Barrier())

	ctx := base.Context()
	result, err := sdkClient.Init(ctx, &barriersvc.InitParams{
		Secret:    secret,
		Threshold: threshold,
		Shares:    shares,
	})
	if err != nil {
		return ErrBarrierInitFailed{Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		return printInitTable(printer, result)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func validateInitParams(secret string, threshold, shares int32) error {
	// Shamir mode: threshold >= 2, shares >= threshold
	if threshold >= 2 {
		if shares < threshold {
			return ErrInvalidThreshold{Threshold: threshold, Shares: shares}
		}
		return nil
	}

	// Single-key mode: secret is required
	if secret == "" {
		return ErrMissingSecret{}
	}

	return nil
}

func printInitTable(printer *cli.Printer, result *barriersvc.InitResult) error {
	printer.PrintSuccess("Barrier initialized successfully")
	fmt.Println()

	printer.PrintKeyValue("Strategy", formatStrategy(result.Strategy))

	if result.InitializedAt != nil {
		printer.PrintKeyValue("Initialized At", result.InitializedAt.String())
	}

	if result.RootToken != "" {
		printer.PrintKeyValue("Root Token", result.RootToken)
	}

	fmt.Println()

	if len(result.UnsealKeys) > 0 {
		printer.PrintWarning("Store the following unseal keys securely. They are only shown once.")
		fmt.Println()

		for i, key := range result.UnsealKeys {
			printer.PrintKeyValue(fmt.Sprintf("Unseal Key %d", i+1), key)
		}
	}

	return nil
}
