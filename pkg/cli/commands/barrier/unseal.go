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

// newUnsealCommand creates the barrier unseal subcommand
func newUnsealCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		secret string
		share  string
	)

	cmd := &cobra.Command{
		Use:   "unseal",
		Short: "Unseal the barrier",
		Long: `Unseal the barrier to allow access to encrypted platform data.

For single-key mode, provide the secret with --secret.
For Shamir mode, provide a share with --share. Multiple unseal
commands may be needed until the threshold is reached.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runUnseal(flags, secret, share)
		},
	}

	cmd.Flags().StringVar(&secret, "secret", "", "unseal secret (single-key mode)")
	cmd.Flags().StringVar(&share, "share", "", "Shamir share for unseal")

	return cmd
}

func runUnseal(flags *cli.CommonFlags, secret, share string) error {
	// Determine the unseal key from flags
	unsealKey := secret
	if share != "" {
		unsealKey = share
	}

	if unsealKey == "" {
		return ErrMissingSecret{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := barriersvc.NewClientFromGRPC(base.Client().Barrier())

	ctx := base.Context()
	result, err := sdkClient.Unseal(ctx, &barriersvc.UnsealParams{
		Secret: unsealKey,
	})
	if err != nil {
		return ErrBarrierUnsealFailed{Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		return printUnsealTable(printer, result)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func printUnsealTable(printer *cli.Printer, result *barriersvc.UnsealResult) error {
	if !result.Sealed {
		printer.PrintSuccess("Barrier unsealed successfully")
		return nil
	}

	// Shamir mode: show progress
	printer.PrintInfo(fmt.Sprintf("Unseal progress: %d/%d shares provided",
		result.SharesProvided, result.SharesThreshold))

	return nil
}
