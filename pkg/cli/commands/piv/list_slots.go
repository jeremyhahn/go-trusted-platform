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

// listSlotsFlags holds the flag values for "piv list-slots".
type listSlotsFlags struct {
	device string
}

// newListSlotsCommand creates the "piv list-slots" subcommand.
func newListSlotsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &listSlotsFlags{}

	cmd := &cobra.Command{
		Use:   "list-slots",
		Short: "List the slots available on a PIV device",
		Long:  `Enumerate the PIV slots on the specified device, including algorithm and provisioning state.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListSlots(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "PIV device id")

	return cmd
}

// runListSlots dispatches "piv list-slots" to the SDK.
func runListSlots(commonFlags *cli.CommonFlags, f *listSlotsFlags) error {
	if f.device == "" {
		return ErrDeviceRequired{}
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := newService(base.Client())
	if err != nil {
		return err
	}
	resp, err := client.ListSlots(base.Context(), &pivsvc.ListSlotsRequest{Device: f.device})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
