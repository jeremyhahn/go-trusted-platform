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

// newListDevicesCommand creates the "piv list-devices" subcommand.
func newListDevicesCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list-devices",
		Short: "Enumerate attached PIV devices",
		Long:  `List PIV-capable smartcards currently attached to the host.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListDevices(getFlags())
		},
	}
}

// runListDevices dispatches "piv list-devices" to the SDK.
func runListDevices(commonFlags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := pivsvc.NewClient()
	resp, err := client.ListDevices(base.Context(), &pivsvc.ListDevicesRequest{})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
