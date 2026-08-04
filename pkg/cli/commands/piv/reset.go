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

// resetFlags holds the flag values for "piv reset".
type resetFlags struct {
	device         string
	yesIUnderstand bool
}

// newResetCommand creates the "piv reset" subcommand.
func newResetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &resetFlags{}

	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Factory-reset a PIV device",
		Long: `Factory-reset a PIV device. This is DESTRUCTIVE: all keys, certs, and
slot configuration are lost.

The --yes-i-understand flag must be set to acknowledge the destructive nature
of the operation. There is no recovery from a device reset.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReset(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "PIV device id")
	cmd.Flags().BoolVar(&f.yesIUnderstand, "yes-i-understand", false,
		"confirm the destructive reset (required)")

	return cmd
}

// runReset dispatches "piv reset" to the SDK.
func runReset(commonFlags *cli.CommonFlags, f *resetFlags) error {
	if f.device == "" {
		return ErrDeviceRequired{}
	}
	if !f.yesIUnderstand {
		return ErrResetNotConfirmed{}
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := pivsvc.NewClient()
	resp, err := client.Reset(base.Context(), &pivsvc.ResetRequest{Device: f.device})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
