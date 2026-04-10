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

//go:build pkcs11

// Package pkcs11 provides CLI commands for PKCS #11 Hardware Security Module
// operations including token management and cryptographic operations.
package pkcs11

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

const (
	// Default module paths for common PKCS#11 implementations
	moduleYKCS11   = "/usr/local/lib/libykcs11.so"
	moduleSoftHSM2 = "/usr/local/lib/softhsm/libsofthsm2.so"
	moduleOpenSC   = "/usr/local/lib/opensc-pkcs11.so"
)

// PKCS11Flags contains PKCS#11 specific flags
type PKCS11Flags struct {
	Module     string
	TokenLabel string
	Slot       int
	YKCS11     bool
	SoftHSM2   bool
	OpenSC     bool
	SOPin      string
	Pin        string
}

// NewCommand creates the pkcs11 root command for PKCS #11 token operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var pkcs11Flags PKCS11Flags

	cmd := &cobra.Command{
		Use:   "pkcs11",
		Short: "Perform PKCS #11 token operations",
		Long: `Shows library and hardware information about connected PKCS #11
Hardware Security Modules.

The PKCS #11 subsystem provides HSM token management including:
  - Token connection and authentication
  - Library and hardware information display
  - Cryptographic operations via HSM

Supported PKCS #11 implementations:
  - YubiKey (libykcs11.so)
  - SoftHSM2 (libsofthsm2.so)
  - OpenSC (opensc-pkcs11.so)
  - Custom module paths

Examples:
  # Connect to YubiKey token
  platformctl pkcs11 --ykcs11 --pin 123456

  # Connect to SoftHSM2 token
  platformctl pkcs11 --softhsm2 --label "my-token" --pin 1234

  # Use custom module path
  platformctl pkcs11 --module /path/to/pkcs11.so --slot 0

  # Connect to OpenSC token
  platformctl pkcs11 --opensc --pin 123456`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runPKCS11(flags, &pkcs11Flags)
		},
	}

	// PKCS#11 specific flags
	cmd.PersistentFlags().StringVarP(&pkcs11Flags.Module, "module", "m", "",
		"The PKCS #11 module path")
	cmd.PersistentFlags().StringVarP(&pkcs11Flags.TokenLabel, "label", "l", "",
		"The PKCS #11 token label")
	cmd.PersistentFlags().IntVarP(&pkcs11Flags.Slot, "slot", "s", -1,
		"The PKCS #11 slot number")
	cmd.PersistentFlags().BoolVar(&pkcs11Flags.YKCS11, "ykcs11", false,
		fmt.Sprintf("Use YubiKey module at %s", moduleYKCS11))
	cmd.PersistentFlags().BoolVar(&pkcs11Flags.SoftHSM2, "softhsm2", false,
		fmt.Sprintf("Use SoftHSM2 module at %s", moduleSoftHSM2))
	cmd.PersistentFlags().BoolVar(&pkcs11Flags.OpenSC, "opensc", false,
		fmt.Sprintf("Use OpenSC module at %s", moduleOpenSC))
	cmd.PersistentFlags().StringVar(&pkcs11Flags.SOPin, "so-pin", "",
		"The PKCS #11 Security Officer PIN")
	cmd.PersistentFlags().StringVar(&pkcs11Flags.Pin, "pin", "",
		"The PKCS #11 user PIN")

	return cmd
}

// runPKCS11 executes the pkcs11 command
func runPKCS11(flags *cli.CommonFlags, pkcs11Flags *PKCS11Flags) error {
	// Resolve module path from convenience flags
	module := resolveModulePath(pkcs11Flags)
	if module == "" {
		return ErrInvalidModulePath{}
	}

	// Update the flags with resolved module
	pkcs11Flags.Module = module

	// This command requires daemon connection for App initialization
	// which provides the PKCS#11 backend, logger, and configuration
	return ErrDaemonConnectionRequired{}
}

// resolveModulePath determines the PKCS#11 module path from flags
func resolveModulePath(pkcs11Flags *PKCS11Flags) string {
	// Check convenience flags first
	if pkcs11Flags.YKCS11 {
		return moduleYKCS11
	}
	if pkcs11Flags.SoftHSM2 {
		return moduleSoftHSM2
	}
	if pkcs11Flags.OpenSC {
		return moduleOpenSC
	}
	// Fall back to explicit module path
	return pkcs11Flags.Module
}
