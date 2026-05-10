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

// infoFlags holds the flag values for "fido2 info".
type infoFlags struct {
	device string
}

// newInfoCommand creates the "fido2 info" subcommand.
func newInfoCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &infoFlags{}

	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show FIDO2 authenticator info",
		Long: `Display the device-level capability profile for a specific FIDO2 authenticator,
including AAGUID, firmware version, supported CTAP2 extensions, and options.

Note: this command operates at the device level. For LUKS volume / keyslot
information use "platformctl luks info" or "platformctl luks list-slots".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInfo(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "FIDO2 device id")

	return cmd
}

// runInfo dispatches "fido2 info" to the SDK.
func runInfo(commonFlags *cli.CommonFlags, f *infoFlags) error {
	if f.device == "" {
		return ErrDeviceRequired{}
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := fido2svc.NewClient()
	resp, err := client.Info(base.Context(), &fido2svc.InfoRequest{Device: f.device})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
