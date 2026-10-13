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

package fido2

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	fido2svc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
)

// newListDevicesCommand creates the "fido2 list-devices" subcommand.
func newListDevicesCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list-devices",
		Short: "Enumerate attached FIDO2 authenticators",
		Long:  `List FIDO2-capable authenticators currently attached to the host over CTAP2 HID.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListDevices(getFlags())
		},
	}
}

// runListDevices dispatches "fido2 list-devices" to the SDK.
func runListDevices(commonFlags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := newService(base.Client())
	if err != nil {
		return err
	}
	resp, err := client.ListDevices(base.Context(), &fido2svc.ListDevicesRequest{})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
