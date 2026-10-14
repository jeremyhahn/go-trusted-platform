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

// testUnlockFlags holds the flag values for "luks test-unlock".
type testUnlockFlags struct {
	device string
	slot   int32
}

// newTestUnlockCommand creates the "luks test-unlock" subcommand. It replaces
// the legacy "platformctl fido2 test" command.
func newTestUnlockCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &testUnlockFlags{slot: -1}

	cmd := &cobra.Command{
		Use:   "test-unlock",
		Short: "Verify a keyslot can unlock the device",
		Long: `Attempt to derive the master key from the specified keyslot without
actually mounting the device. Reports success or failure.

Replaces the legacy "platformctl fido2 test" command.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestUnlock(getFlags(), f)
		},
	}

	cmd.Flags().StringVar(&f.device, "device", "", "LUKS device path (auto-detected if empty)")
	cmd.Flags().Int32Var(&f.slot, "slot", -1, "keyslot index (0-31)")

	return cmd
}

// runTestUnlock dispatches "luks test-unlock" to the SDK.
func runTestUnlock(commonFlags *cli.CommonFlags, f *testUnlockFlags) error {
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

	client, err := newService(base.Client())
	if err != nil {
		return err
	}
	resp, err := client.TestUnlock(base.Context(), &lukssvc.TestUnlockRequest{
		Device: device,
		Slot:   f.slot,
	})
	if err != nil {
		return err
	}
	return base.Output(resp)
}
