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

package luks

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	lukssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
)

// listSlotsFlags holds the flag values for "luks list-slots".
type listSlotsFlags struct {
	device string
}

// newListSlotsCommand creates the "luks list-slots" subcommand.
func newListSlotsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &listSlotsFlags{}

	cmd := &cobra.Command{
		Use:   "list-slots",
		Short: "List active LUKS keyslots",
		Long:  `Enumerate the active keyslots on a LUKS device along with each slot's backend type.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListSlots(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "LUKS device path (auto-detected if empty)")

	return cmd
}

// runListSlots dispatches "luks list-slots" to the SDK.
func runListSlots(commonFlags *cli.CommonFlags, f *listSlotsFlags) error {
	if err := checkRoot(); err != nil {
		return err
	}
	device, err := resolveDevice(f.device)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := lukssvc.NewClient()
	resp, err := client.ListSlots(base.Context(), &lukssvc.ListSlotsRequest{Device: device})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
