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

package tpm

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newExtendCommand creates the extend subcommand for PCR extension
func newExtendCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "extend",
		Short: "Extend platform PCR with golden measurement",
		Long: `Extends the platform PCR with the golden measurement from config.

This is required on every boot BEFORE accessing the Platform KeyStore SRK
because the SRK has PCR auth policy bound to the platform PCR.

The golden measurement is computed from PCR values specified in the config file:
  - platform-pcr: The PCR index to extend (e.g., 23)
  - platform-pcr-bank: The PCR bank algorithm (e.g., sha256)
  - golden-pcrs: PCRs included in golden measurement (e.g., [0, 7, 9, 10])

Example PCR meanings:
  - PCR 0: BIOS/UEFI firmware measurements
  - PCR 7: Secure Boot state
  - PCR 9: Kernel command line
  - PCR 10: IMA (Integrity Measurement Architecture) file measurements

This ensures TPM-sealed secrets can only be accessed when the platform
boot chain matches the expected state from when the secrets were sealed.

Examples:
  # Extend platform PCR using config file settings
  platformctl tpm extend`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ErrDaemonConnectionRequired{Operation: "extend"}
		},
	}

	return cmd
}
