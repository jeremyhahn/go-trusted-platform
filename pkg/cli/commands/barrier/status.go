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

// newStatusCommand creates the barrier status subcommand
func newStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show barrier status",
		Long:  "Display the current status of the barrier including sealed state, strategy, and initialization time.",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runStatus(flags)
		},
	}
}

func runStatus(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	ctx := base.Context()
	resp, err := base.Client().Barrier().GetStatus(ctx, &platformv1.BarrierStatusRequest{})
	if err != nil {
		return ErrBarrierStatusFailed{Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		return printStatusTable(printer, resp)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func printStatusTable(printer *cli.Printer, resp *platformv1.BarrierStatusResponse) error {
	printer.PrintKeyValue("Initialized", fmt.Sprintf("%v", resp.Initialized))
	printer.PrintKeyValue("Sealed", fmt.Sprintf("%v", resp.Sealed))
	printer.PrintKeyValue("Strategy", formatStrategy(resp.Strategy))

	if resp.Strategy == platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR {
		printer.PrintKeyValue("Threshold", fmt.Sprintf("%d", resp.Threshold))
		printer.PrintKeyValue("Total Shares", fmt.Sprintf("%d", resp.SharesTotal))
		printer.PrintKeyValue("Shares Provided", fmt.Sprintf("%d", resp.SharesProvided))
	}

	if resp.InitializedAt != nil {
		printer.PrintKeyValue("Initialized At", resp.InitializedAt.AsTime().String())
	}

	return nil
}
