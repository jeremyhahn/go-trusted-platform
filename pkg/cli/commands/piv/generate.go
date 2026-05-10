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

// generateFlags holds the flag values for "piv generate".
type generateFlags struct {
	slot      string
	algorithm string
	pin       string
}

// newGenerateCommand creates the "piv generate" subcommand.
func newGenerateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &generateFlags{}

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new key in a PIV slot",
		Long: `Generate a fresh key pair in a PIV slot.

The new public key is returned in PEM form. The private key never leaves the
device.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerate(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.slot, "slot", "", "PIV slot id")
	cmd.Flags().StringVar(&f.algorithm, "algorithm", "", "key algorithm (rsa, ecdsa, ed25519)")
	cmd.Flags().StringVar(&f.pin, "pin", "", "user PIN")

	return cmd
}

// runGenerate dispatches "piv generate" to the SDK.
func runGenerate(commonFlags *cli.CommonFlags, f *generateFlags) error {
	if f.slot == "" {
		return ErrSlotRequired{}
	}
	if _, ok := algorithms[f.algorithm]; !ok {
		return ErrInvalidAlgorithm{Value: f.algorithm}
	}
	if f.pin == "" {
		return ErrPINRequired{}
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := pivsvc.NewClient()
	resp, err := client.Generate(base.Context(), &pivsvc.GenerateRequest{
		Slot:      f.slot,
		Algorithm: pivsvc.Algorithm(algorithms[f.algorithm]),
		PIN:       f.pin,
	})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
