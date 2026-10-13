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

// attestFlags holds the flag values for "piv attest".
type attestFlags struct {
	slot string
}

// newAttestCommand creates the "piv attest" subcommand.
func newAttestCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &attestFlags{}

	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Attest a PIV slot key",
		Long: `Produce an attestation certificate for the key in the given slot.

The attestation cert is signed by the device manufacturer's attestation CA
(for example Yubico's Attestation CA for YubiKey) and can be verified by any
relying party that trusts that CA.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttest(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.slot, "slot", "", "PIV slot id")

	return cmd
}

// runAttest dispatches "piv attest" to the SDK.
func runAttest(commonFlags *cli.CommonFlags, f *attestFlags) error {
	if f.slot == "" {
		return ErrSlotRequired{}
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
	resp, err := client.Attest(base.Context(), &pivsvc.AttestRequest{Slot: f.slot})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
