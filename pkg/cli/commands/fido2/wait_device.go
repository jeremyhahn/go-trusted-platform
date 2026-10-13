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

// waitDeviceFlags holds the flag values for "fido2 wait-device".
type waitDeviceFlags struct {
	timeout int32
}

// newWaitDeviceCommand creates the "fido2 wait-device" subcommand.
func newWaitDeviceCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &waitDeviceFlags{}

	cmd := &cobra.Command{
		Use:   "wait-device",
		Short: "Block until a FIDO2 authenticator is present",
		Long:  `Block the caller until at least one FIDO2 authenticator is attached. Useful in scripts before a register or authenticate step.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWaitDevice(getFlags(), f)
		},
	}

	cmd.Flags().Int32Var(&f.timeout, "timeout", 0, "maximum seconds to wait (0 = no timeout)")

	return cmd
}

// runWaitDevice dispatches "fido2 wait-device" to the SDK.
func runWaitDevice(commonFlags *cli.CommonFlags, f *waitDeviceFlags) error {
	if f.timeout < 0 {
		return ErrInvalidTimeout{Value: f.timeout}
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
	resp, err := client.WaitDevice(base.Context(), &fido2svc.WaitDeviceRequest{TimeoutSeconds: f.timeout})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
