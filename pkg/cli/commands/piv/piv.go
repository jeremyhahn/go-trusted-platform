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

// Package piv provides CLI commands for PIV (Personal Identity Verification,
// NIST SP 800-73-4) smartcard operations. It mirrors the "xkmsctl piv"
// subcommand surface.
package piv

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	pivsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
)

// NewCommand creates the piv root command.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "piv",
		Short: "PIV smartcard operations",
		Long: `Manage PIV (Personal Identity Verification) smartcards.

The PIV subsystem provides device enumeration, per-slot key management,
signing, attestation, and device reset operations for PIV-compliant
hardware (YubiKey, Feitian, etc.).

Slots are identified by their standard PIV hexadecimal ids: 9a (PIV Auth),
9c (Digital Signature), 9d (Key Management), 9e (Card Authentication),
82-95 (retired key management), and F9 (Attestation).

Examples:
  # Enumerate attached PIV devices
  platformctl piv list-devices

  # List slots on a specific device
  platformctl piv list-slots --device <device-id>

  # Inspect slot 9a
  platformctl piv info --slot 9a

  # Generate an ECDSA key in slot 9c
  platformctl piv generate --slot 9c --algorithm ecdsa --pin 123456

  # Import a key into slot 82
  platformctl piv import --slot 82 --key-file ./key.pem --pin 123456

  # Sign a payload with slot 9c
  platformctl piv sign --slot 9c --input-file ./data.bin --pin 123456

  # Attest the slot 9a key
  platformctl piv attest --slot 9a

  # Factory-reset a device (requires explicit confirmation)
  platformctl piv reset --device <device-id> --yes-i-understand`,
	}

	cmd.AddCommand(newListDevicesCommand(getFlags))
	cmd.AddCommand(newListSlotsCommand(getFlags))
	cmd.AddCommand(newInfoCommand(getFlags))
	cmd.AddCommand(newGenerateCommand(getFlags))
	cmd.AddCommand(newImportCommand(getFlags))
	cmd.AddCommand(newSignCommand(getFlags))
	cmd.AddCommand(newAttestCommand(getFlags))
	cmd.AddCommand(newResetCommand(getFlags))

	return cmd
}

const pivsvcName = "piv"

// newService returns the PIV service backed by the client's active transport,
// or ErrServiceUnavailable when the client exposes no PIV service.
func newService(client platform.Client) (pivsvc.Service, error) {
	rpc := client.PIV()
	if rpc == nil {
		return nil, platform.ErrServiceUnavailable{Service: pivsvcName}
	}
	return pivsvc.NewGRPCClientFromClient(rpc), nil
}

// algorithms maps CLI --algorithm values to SDK enum values.
var algorithms = map[string]string{
	"rsa":     "rsa",
	"ecdsa":   "ecdsa",
	"ed25519": "ed25519",
}
