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

package fido2

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// testFlags contains flags specific to the test command
type testFlags struct {
	device string
	debug  bool
}

// newTestCommand creates the test subcommand for testing FIDO2 unlock
func newTestCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &testFlags{}

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test FIDO2 security key unlock",
		Long: `Test if a FIDO2 security key can unlock a LUKS device without actually opening it.

This command verifies that:
  - The FIDO2 device is present and supports hmac-secret
  - The LUKS device has FIDO2 token metadata
  - The derived key successfully unlocks the device

Examples:
  # Test unlock on auto-detected device
  platformctl fido2 test

  # Test unlock on specific device
  platformctl fido2 test --device /dev/vda2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTest(getFlags(), flags)
		},
	}

	cmd.Flags().StringVarP(&flags.device, "device", "d", "", "LUKS device path (auto-detected if not specified)")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")

	return cmd
}

// runTest executes the test command
func runTest(commonFlags *cli.CommonFlags, flags *testFlags) error {
	// Check root privileges
	if err := checkRoot(); err != nil {
		return err
	}

	// Auto-detect LUKS device if not specified
	device := flags.device
	if device == "" {
		detected, err := autoDetectLUKSDevice()
		if err != nil {
			return err
		}
		device = detected
		fmt.Printf("Auto-detected LUKS device: %s\n", device)
	}

	fmt.Println("========================================================================")
	fmt.Println("FIDO2 Unlock Test")
	fmt.Println("========================================================================")
	fmt.Printf("Device: %s\n", device)
	fmt.Println("")

	unlock := installer.NewFIDO2Unlock(device, flags.debug)

	// Get token info
	token, err := unlock.GetTokenInfo()
	if err != nil {
		return ErrGetTokenInfo{Reason: err.Error()}
	}

	fmt.Printf("Found FIDO2 token:\n")
	fmt.Printf("  Relying Party: %s\n", token.FIDO2RP)
	fmt.Printf("  Keyslots: %v\n", token.Keyslots)
	credLen := len(token.FIDO2Credential)
	if credLen > 40 {
		credLen = 40
	}
	fmt.Printf("  Credential ID: %s...\n", token.FIDO2Credential[:credLen])
	fmt.Println("")

	// Test unlock
	ctx := context.Background()
	if err := unlock.TestUnlock(ctx); err != nil {
		return ErrUnlockTestFailed{Reason: err.Error()}
	}

	fmt.Println("")
	fmt.Println("========================================================================")
	fmt.Println("Test Passed!")
	fmt.Println("========================================================================")
	fmt.Println("Your FIDO2 security key can successfully unlock the LUKS device.")

	return nil
}
