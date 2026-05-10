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

package piv

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pivsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
)

// infoFlags holds the flag values for "piv info".
type infoFlags struct {
	slot   string
	device string
}

// newInfoCommand creates the "piv info" subcommand.
func newInfoCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &infoFlags{}

	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show detailed PIV slot information",
		Long: `Display detailed information about a single PIV slot, including the
associated public key (PEM) and certificate (PEM) if present.

Valid slot ids: 9a, 9c, 9d, 9e, F9, 82-95.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInfo(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.slot, "slot", "", "PIV slot id (9a|9c|9d|9e|F9|82-95)")
	cmd.Flags().StringVar(&f.device, "device", "", "PIV device id (optional)")

	return cmd
}

// runInfo dispatches "piv info" to the SDK.
func runInfo(commonFlags *cli.CommonFlags, f *infoFlags) error {
	if f.slot == "" {
		return ErrSlotRequired{}
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := pivsvc.NewClient()
	resp, err := client.SlotInfo(base.Context(), &pivsvc.SlotInfoRequest{Slot: f.slot, Device: f.device})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
