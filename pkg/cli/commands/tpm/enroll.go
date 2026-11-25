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

// newEnrollCommand creates the enroll subcommand for ACME device enrollment
func newEnrollCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll device using ACME enroll-01 challenge",
		Long: `Enroll a device with a Certificate Authority using the ACME enroll-01 challenge.

This command orchestrates the full TPM-based device enrollment flow:

1. Ensures IDevID and IAK keys exist in the TPM (generates if needed)
2. Connects to the ACME server directory
3. Creates a TCG-CSR-IDEVID certificate signing request
4. Submits the enrollment request with enroll-01 challenge
5. Completes the MakeCredential/ActivateCredential challenge
6. Receives and installs IDevID and IAK certificates

The enroll-01 challenge provides cryptographic proof that the device possesses
a genuine TPM with an Endorsement Key traceable to a trusted manufacturer.

Examples:
  # Enroll using config file ACME settings
  platformctl tpm enroll

  # Enroll with explicit ACME server
  platformctl tpm enroll --acme-server https://ca.example.com/acme/directory

  # Enroll with custom common name
  platformctl tpm enroll --cn "device-001.example.com"

  # Enroll with specific IP address
  platformctl tpm enroll --ip 192.168.1.100

  # Skip confirmation prompts
  platformctl tpm enroll --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ErrDaemonConnectionRequired{Operation: "enroll"}
		},
	}

	return cmd
}
