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

// removeKeyFlags holds the flag values for "luks remove-key".
type removeKeyFlags struct {
	device string
	slot   int32
}

// newRemoveKeyCommand creates the "luks remove-key" subcommand. It replaces
// the legacy "platformctl fido2 remove" command.
func newRemoveKeyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &removeKeyFlags{slot: -1}

	cmd := &cobra.Command{
		Use:   "remove-key",
		Short: "Remove a LUKS keyslot",
		Long: `Remove the keyslot at the given index. This operation is destructive: the
slot's key material is overwritten and cannot be recovered.

Replaces the legacy "platformctl fido2 remove" command.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemoveKey(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "LUKS device path (auto-detected if empty)")
	cmd.Flags().Int32Var(&f.slot, "slot", -1, "keyslot index (0-31)")

	return cmd
}

// runRemoveKey dispatches "luks remove-key" to the SDK.
func runRemoveKey(commonFlags *cli.CommonFlags, f *removeKeyFlags) error {
	if err := checkRoot(); err != nil {
		return err
	}
	if f.slot < 0 {
		return ErrSlotRequired{}
	}
	if err := validateSlot(f.slot); err != nil {
		return err
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
	resp, err := client.RemoveKey(base.Context(), &lukssvc.RemoveKeyRequest{
		Device: device,
		Slot:   f.slot,
	})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
