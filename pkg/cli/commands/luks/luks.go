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

// Package luks provides CLI commands for LUKS2 volume management. It owns all
// LUKS use-cases that previously lived inside the fido2 package.
package luks

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	lukssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
)

// NewCommand creates the luks root command.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "luks",
		Short: "LUKS2 volume management",
		Long: `Manage LUKS2-encrypted block devices.

The luks subsystem owns all volume-level operations: header status, keyslot
listing, detailed info dumps, and enrollment of passphrase / FIDO2 / TPM2 /
recovery keyslots. It also covers slot removal and change-passphrase.

All luks subcommands require root privileges.

Migration note: the LUKS-specific subcommands formerly under "platformctl
fido2" have moved here:

  platformctl fido2 enroll  -> platformctl luks enroll-fido2
  platformctl fido2 list    -> platformctl luks list-slots
  platformctl fido2 remove  -> platformctl luks remove-key
  platformctl fido2 test    -> platformctl luks test-unlock

"platformctl fido2" is now reserved for device / WebAuthn operations.

Examples:
  # Inspect the LUKS header
  platformctl luks status --device /dev/vda3

  # List all keyslots
  platformctl luks list-slots

  # Enroll a FIDO2 key (formerly "platformctl fido2 enroll")
  platformctl luks enroll-fido2 --device /dev/vda3 \
      --existing-passphrase <pass> --credential-id <credID> --require-uv

  # Enroll a TPM2-sealed slot
  platformctl luks enroll-tpm --existing-passphrase <pass> --pcrs 7,9

  # Write a recovery key
  platformctl luks enroll-recovery --existing-passphrase <pass> \
      --output ./recovery.key

  # Test a slot unlocks without mounting
  platformctl luks test-unlock --slot 3`,
	}

	cmd.AddCommand(newStatusCommand(getFlags))
	cmd.AddCommand(newListSlotsCommand(getFlags))
	cmd.AddCommand(newInfoCommand(getFlags))
	cmd.AddCommand(newEnrollPassphraseCommand(getFlags))
	cmd.AddCommand(newEnrollFIDO2Command(getFlags))
	cmd.AddCommand(newEnrollTPMCommand(getFlags))
	cmd.AddCommand(newEnrollRecoveryCommand(getFlags))
	cmd.AddCommand(newRemoveKeyCommand(getFlags))
	cmd.AddCommand(newTestUnlockCommand(getFlags))
	cmd.AddCommand(newChangePassphraseCommand(getFlags))

	return cmd
}

// validateSlot bounds-checks a LUKS2 slot index (0-31 is the spec range).
func validateSlot(slot int32) error {
	if slot < 0 || slot > 31 {
		return ErrInvalidSlot{Slot: slot}
	}
	return nil
}

// lukssvcName names the service in ErrServiceUnavailable.
const lukssvcName = "luks"

// newService returns the LUKS service backed by the client's active
// transport, or ErrServiceUnavailable when the client exposes no LUKS service.
func newService(client platform.Client) (lukssvc.Service, error) {
	rpc := client.LUKS()
	if rpc == nil {
		return nil, platform.ErrServiceUnavailable{Service: lukssvcName}
	}
	return lukssvc.NewGRPCClientFromClient(rpc), nil
}
