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

// changePassphraseFlags holds the flag values for "luks change-passphrase".
type changePassphraseFlags struct {
	device        string
	slot          int32
	oldPassphrase string
	newPassphrase string
}

// newChangePassphraseCommand creates the "luks change-passphrase" subcommand.
func newChangePassphraseCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &changePassphraseFlags{slot: -1}

	cmd := &cobra.Command{
		Use:   "change-passphrase",
		Short: "Replace an existing passphrase keyslot",
		Long: `Replace the passphrase on an existing slot. Both --old-passphrase and
--new-passphrase are required.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runChangePassphrase(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "LUKS device path (auto-detected if empty)")
	cmd.Flags().Int32Var(&f.slot, "slot", -1, "keyslot index (0-31)")
	cmd.Flags().StringVar(&f.oldPassphrase, "old-passphrase", "", "existing passphrase for the slot")
	cmd.Flags().StringVar(&f.newPassphrase, "new-passphrase", "", "new passphrase")

	return cmd
}

// runChangePassphrase dispatches "luks change-passphrase" to the SDK.
func runChangePassphrase(commonFlags *cli.CommonFlags, f *changePassphraseFlags) error {
	if err := checkRoot(); err != nil {
		return err
	}
	if f.slot < 0 {
		return ErrSlotRequired{}
	}
	if err := validateSlot(f.slot); err != nil {
		return err
	}
	if f.oldPassphrase == "" {
		return ErrOldPassphraseRequired{}
	}
	if f.newPassphrase == "" {
		return ErrNewPassphraseRequired{}
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
	resp, err := client.ChangePassphrase(base.Context(), &lukssvc.ChangePassphraseRequest{
		Device:        device,
		Slot:          f.slot,
		OldPassphrase: f.oldPassphrase,
		NewPassphrase: f.newPassphrase,
	})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
