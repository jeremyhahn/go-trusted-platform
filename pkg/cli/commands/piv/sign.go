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
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pivsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
)

// signFlags holds the flag values for "piv sign".
type signFlags struct {
	slot      string
	inputFile string
	pin       string
}

// newSignCommand creates the "piv sign" subcommand.
func newSignCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &signFlags{}

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a payload with a PIV slot key",
		Long:  `Read raw bytes from --input-file and sign them with the key in the given slot.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSign(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.slot, "slot", "", "PIV slot id")
	cmd.Flags().StringVar(&f.inputFile, "input-file", "", "path to the payload file")
	cmd.Flags().StringVar(&f.pin, "pin", "", "user PIN")

	return cmd
}

// runSign dispatches "piv sign" to the SDK.
func runSign(commonFlags *cli.CommonFlags, f *signFlags) error {
	if f.slot == "" {
		return ErrSlotRequired{}
	}
	if f.inputFile == "" {
		return ErrInputFileRequired{}
	}
	if f.pin == "" {
		return ErrPINRequired{}
	}

	payload, err := os.ReadFile(f.inputFile)
	if err != nil {
		return ErrInputFileRead{Path: f.inputFile, Cause: err}
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
	resp, err := client.Sign(base.Context(), &pivsvc.SignRequest{
		Slot:    f.slot,
		Payload: payload,
		PIN:     f.pin,
	})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
