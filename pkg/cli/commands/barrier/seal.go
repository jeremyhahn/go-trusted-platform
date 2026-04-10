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
	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newSealCommand creates the barrier seal subcommand
func newSealCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "seal",
		Short: "Seal the barrier",
		Long: `Seal the barrier to protect all sensitive platform data at rest.

Once sealed, the barrier must be unsealed before the platform can
access encrypted data. This operation requires the barrier to be
currently unsealed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runSeal(flags)
		},
	}
}

func runSeal(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	ctx := base.Context()
	resp, err := base.Client().Barrier().Seal(ctx, &platformv1.BarrierSealRequest{})
	if err != nil {
		return ErrBarrierSealFailed{Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Sealed {
			printer.PrintSuccess("Barrier sealed successfully")
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
