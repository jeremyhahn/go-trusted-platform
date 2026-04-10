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

// enrollFlags contains flags specific to the enroll command
type enrollFlags struct {
	device     string
	passphrase string
	slot       int
	rp         string
	user       string
	fips       bool
	debug      bool
}

// newEnrollCommand creates the enroll subcommand for FIDO2 enrollment
func newEnrollCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &enrollFlags{}

	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll FIDO2 security key for LUKS unlock",
		Long: `Enroll a FIDO2 security key (like CanoKey, YubiKey) for LUKS disk encryption.

This command uses the hmac-secret extension to derive a unique encryption key from
your security key, allowing you to unlock your encrypted disk with a simple touch.

Prerequisites:
  - libfido2 and fido2 packages installed (apk add libfido2 fido2)
  - A FIDO2 device with hmac-secret support
  - An existing LUKS-encrypted device
  - Root/sudo access

Examples:
  # Auto-detect LUKS device and use default slot (3)
  platformctl fido2 enroll --passphrase "your-luks-password"

  # Specify device and custom slot
  platformctl fido2 enroll --device /dev/sda2 --slot 4 --passphrase "your-luks-password"

  # Use custom relying party ID
  platformctl fido2 enroll --device /dev/vda2 --rp "my-custom-rp" --passphrase "pass"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnroll(getFlags(), flags)
		},
	}

	cmd.Flags().StringVarP(&flags.device, "device", "d", "", "LUKS device path (auto-detected if not specified)")
	cmd.Flags().StringVarP(&flags.passphrase, "passphrase", "p", "", "Existing LUKS passphrase (required)")
	cmd.Flags().IntVarP(&flags.slot, "slot", "s", 3, "LUKS keyslot to use for FIDO2 (default: 3)")
	cmd.Flags().StringVarP(&flags.rp, "rp", "r", "luks-alpine", "FIDO2 relying party ID")
	cmd.Flags().StringVarP(&flags.user, "user", "u", "luks-user", "FIDO2 user name")
	cmd.Flags().BoolVar(&flags.fips, "fips", false, "Use FIPS-approved algorithms (PBKDF2-SHA256 instead of Argon2id)")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")

	cmd.MarkFlagRequired("passphrase")

	return cmd
}

// runEnroll executes the enroll command
func runEnroll(commonFlags *cli.CommonFlags, flags *enrollFlags) error {
	// Check root privileges
	if err := checkRoot(); err != nil {
		return err
	}

	// Validate passphrase
	if flags.passphrase == "" {
		return ErrPassphraseRequired{}
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

	config := &installer.FIDO2EnrollmentConfig{
		LUKSDevice:     device,
		LUKSPassphrase: flags.passphrase,
		TargetKeyslot:  flags.slot,
		RelyingPartyID: flags.rp,
		UserName:       flags.user,
		FIPSMode:       flags.fips,
		Debug:          flags.debug,
	}

	enrollment, err := installer.NewFIDO2Enrollment(config)
	if err != nil {
		return ErrCreateEnrollmentHandler{Reason: err.Error()}
	}

	fmt.Println("========================================================================")
	fmt.Println("FIDO2 Security Key Enrollment")
	fmt.Println("========================================================================")
	fmt.Printf("Device: %s\n", device)
	fmt.Printf("Slot: %d\n", flags.slot)
	fmt.Printf("Relying Party: %s\n", flags.rp)
	fmt.Println("")

	ctx := context.Background()
	if err := enrollment.Enroll(ctx); err != nil {
		return ErrEnrollmentFailed{Reason: err.Error()}
	}

	fmt.Println("")
	fmt.Println("========================================================================")
	fmt.Println("Enrollment Complete!")
	fmt.Println("========================================================================")
	fmt.Println("Your LUKS device can now be unlocked with:")
	fmt.Printf("  - Your security key (slot %d)\n", flags.slot)
	fmt.Println("  - Passphrase (if slot 0 is still active)")
	fmt.Println("  - TPM (if slot 1 is configured)")
	fmt.Println("")
	fmt.Println("IMPORTANT: Test FIDO2 unlock before rebooting!")
	fmt.Println("Run: platformctl fido2 test --device", device)

	return nil
}
