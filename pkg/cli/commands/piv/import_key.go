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

// importFlags holds the flag values for "piv import".
type importFlags struct {
	slot    string
	keyFile string
	pin     string
}

// newImportCommand creates the "piv import" subcommand.
func newImportCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &importFlags{}

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import an externally generated private key into a PIV slot",
		Long: `Import a PEM-encoded private key into a PIV slot.

Prefer "piv generate" when possible; imported keys are not hardware-bound.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImport(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.slot, "slot", "", "PIV slot id")
	cmd.Flags().StringVar(&f.keyFile, "key-file", "", "path to the PEM private key file")
	cmd.Flags().StringVar(&f.pin, "pin", "", "user PIN")

	return cmd
}

// runImport dispatches "piv import" to the SDK.
func runImport(commonFlags *cli.CommonFlags, f *importFlags) error {
	if f.slot == "" {
		return ErrSlotRequired{}
	}
	if f.keyFile == "" {
		return ErrKeyFileRequired{}
	}
	if f.pin == "" {
		return ErrPINRequired{}
	}

	key, err := os.ReadFile(f.keyFile)
	if err != nil {
		return ErrKeyFileRead{Path: f.keyFile, Cause: err}
	}

	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := pivsvc.NewClient()
	resp, err := client.Import(base.Context(), &pivsvc.ImportRequest{
		Slot:          f.slot,
		PrivateKeyPEM: string(key),
		PIN:           f.pin,
	})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
