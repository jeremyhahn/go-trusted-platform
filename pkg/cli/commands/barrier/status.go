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

	sdkClient := barriersvc.NewClientFromGRPC(base.Client().Barrier())

	ctx := base.Context()
	result, err := sdkClient.Status(ctx)
	if err != nil {
		return ErrBarrierStatusFailed{Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		return printStatusTable(printer, result)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func printStatusTable(printer *cli.Printer, result *barriersvc.StatusResult) error {
	printer.PrintKeyValue("Initialized", fmt.Sprintf("%v", result.Initialized))
	printer.PrintKeyValue("Sealed", fmt.Sprintf("%v", result.Sealed))
	printer.PrintKeyValue("Strategy", formatStrategy(result.Strategy))

	if result.Strategy == barriersvc.StrategyShamir {
		printer.PrintKeyValue("Threshold", fmt.Sprintf("%d", result.Threshold))
		printer.PrintKeyValue("Total Shares", fmt.Sprintf("%d", result.SharesTotal))
		printer.PrintKeyValue("Shares Provided", fmt.Sprintf("%d", result.SharesProvided))
	}

	if result.InitializedAt != nil {
		printer.PrintKeyValue("Initialized At", result.InitializedAt.String())
	}

	return nil
}
