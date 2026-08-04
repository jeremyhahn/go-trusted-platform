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

// Package secureboot provides CLI commands for bare-metal UEFI Secure Boot
// operations against the running firmware via efivarfs: reading the firmware
// Secure Boot state, enrolling the platform PK/KEK/db certificates, and
// enforcing Secure Boot with the verify-before-enforce brick guard.
//
// These verbs are the real-hardware counterpart to the OVMF NVRAM-file
// enrollment used for virtual machines. Every destructive step is guarded:
// enrollment requires Setup Mode, the signed UKI must verify against the db
// certificate before any key is written, and PK is always written LAST so a
// partial failure leaves the node bootable.
package secureboot

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the secure-boot root command.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "secure-boot",
		Aliases: []string{"secureboot", "sb"},
		Short:   "Bare-metal UEFI Secure Boot operations (efivarfs)",
		Long: `Manage UEFI Secure Boot on the running firmware via efivarfs.

These commands operate on REAL HARDWARE (or any UEFI environment exposing
/sys/firmware/efi/efivars). They are the bare-metal counterpart to the
OVMF NVRAM-file enrollment used for virtual machines.

Safety model:
  - status is strictly read-only.
  - enroll and enforce default to DRY-RUN; nothing is written without --commit.
  - Key enrollment requires the firmware to be in Setup Mode (clear Secure
    Boot keys in firmware setup first).
  - The signed UKI is Authenticode-verified against the db certificate BEFORE
    any variable is written (verify-before-enforce), so enforcing Secure Boot
    can never strand the node on an image the firmware refuses to boot.
  - Keys are written db -> KEK -> PK (PK LAST); Secure Boot only activates
    when PK is written, so any earlier failure leaves the node bootable.`,
		Example: `  # Report firmware Secure Boot state (read-only)
  platformctl secure-boot status

  # Rehearse key enrollment (dry-run: all guards run, nothing is written)
  platformctl secure-boot enroll

  # Enroll PK/KEK/db into the firmware (requires Setup Mode)
  platformctl secure-boot enroll --commit

  # Enforce Secure Boot: verify UKI, enroll keys, confirm firmware state
  platformctl secure-boot enforce --commit`,
	}

	cmd.AddCommand(newStatusCommand(getFlags))
	cmd.AddCommand(newEnrollCommand(getFlags))
	cmd.AddCommand(newEnforceCommand(getFlags))
	return cmd
}
