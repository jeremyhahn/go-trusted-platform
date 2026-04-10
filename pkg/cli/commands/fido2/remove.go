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
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// removeFlags contains flags specific to the remove command
type removeFlags struct {
	device  string
	tokenID string
	slot    int
	force   bool
	debug   bool
}

// newRemoveCommand creates the remove subcommand for removing FIDO2 tokens
func newRemoveCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &removeFlags{}

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove FIDO2 token and keyslot",
		Long: `Remove a FIDO2 token from LUKS metadata and delete its associated keyslot.

WARNING: This operation is destructive. The keyslot and token cannot be recovered
after removal. Ensure you have another way to unlock the device before proceeding.

You can specify either a token ID or a keyslot number to remove.

Examples:
  # Remove by token ID (requires confirmation)
  platformctl fido2 remove --device /dev/vda2 --token 0

  # Remove by keyslot number (requires confirmation)
  platformctl fido2 remove --device /dev/vda2 --slot 3

  # Remove without confirmation prompt
  platformctl fido2 remove --device /dev/vda2 --slot 3 --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemove(getFlags(), flags)
		},
	}

	cmd.Flags().StringVarP(&flags.device, "device", "d", "", "LUKS device path (auto-detected if not specified)")
	cmd.Flags().StringVarP(&flags.tokenID, "token", "t", "", "Token ID to remove")
	cmd.Flags().IntVarP(&flags.slot, "slot", "s", -1, "Keyslot number to remove")
	cmd.Flags().BoolVarP(&flags.force, "force", "f", false, "Skip confirmation prompt")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")

	return cmd
}

// runRemove executes the remove command
func runRemove(commonFlags *cli.CommonFlags, flags *removeFlags) error {
	// Check root privileges
	if err := checkRoot(); err != nil {
		return err
	}

	// Validate input: must specify either token ID or keyslot
	if flags.tokenID == "" && flags.slot < 0 {
		return ErrMustSpecifyTokenOrSlot{}
	}

	if flags.tokenID != "" && flags.slot >= 0 {
		return ErrCannotSpecifyBothTokenAndSlot{}
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

	// Read LUKS header and metadata
	_, metadata, err := luks2.ReadHeader(device)
	if err != nil {
		return ErrReadLUKSHeader{Reason: err.Error()}
	}

	// Determine what to remove
	var tokenIDToRemove string
	var keyslotToRemove int

	if flags.tokenID != "" {
		// Remove by token ID
		tokenIDToRemove = flags.tokenID

		// Verify token exists and is FIDO2
		if metadata.Tokens == nil {
			return ErrNoFIDO2Tokens{Device: device}
		}
		token, exists := metadata.Tokens[tokenIDToRemove]
		if !exists {
			return ErrTokenNotFound{TokenID: tokenIDToRemove}
		}
		if token.Type != "fido2-manual" {
			return ErrTokenNotFIDO2{TokenID: tokenIDToRemove, TokenType: token.Type}
		}

		// Get the first keyslot associated with this token
		if len(token.Keyslots) == 0 {
			return ErrTokenNoKeyslots{TokenID: tokenIDToRemove}
		}
		keyslotNum, err := strconv.Atoi(token.Keyslots[0])
		if err != nil {
			return ErrInvalidKeyslotID{KeyslotID: token.Keyslots[0]}
		}
		keyslotToRemove = keyslotNum

	} else {
		// Remove by keyslot number
		keyslotToRemove = flags.slot

		// Find the token that references this keyslot
		if metadata.Tokens != nil {
			for tokenID, token := range metadata.Tokens {
				if token.Type == "fido2-manual" {
					for _, ks := range token.Keyslots {
						if ks == strconv.Itoa(keyslotToRemove) {
							tokenIDToRemove = tokenID
							break
						}
					}
				}
				if tokenIDToRemove != "" {
					break
				}
			}
		}

		// It's OK if no token found - we'll still remove the keyslot
		if tokenIDToRemove == "" && flags.debug {
			fmt.Printf("No FIDO2 token found for keyslot %d (will still remove keyslot)\n", keyslotToRemove)
		}
	}

	// Verify keyslot exists
	slotIDStr := strconv.Itoa(keyslotToRemove)
	if _, exists := metadata.Keyslots[slotIDStr]; !exists {
		return ErrKeyslotNotFound{Keyslot: keyslotToRemove}
	}

	// Show what will be removed
	fmt.Println("========================================================================")
	fmt.Println("FIDO2 Token Removal")
	fmt.Println("========================================================================")
	fmt.Printf("Device: %s\n", device)
	if tokenIDToRemove != "" {
		fmt.Printf("Token ID: %s\n", tokenIDToRemove)
	}
	fmt.Printf("Keyslot: %d\n", keyslotToRemove)
	fmt.Println("")
	fmt.Println("WARNING: This operation is destructive and cannot be undone!")
	fmt.Println("Ensure you have another way to unlock this device.")

	// Confirmation prompt unless --force is used
	if !flags.force {
		fmt.Println("")
		fmt.Print("Are you sure you want to proceed? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return ErrReadConfirmation{Reason: err.Error()}
		}
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Operation cancelled.")
			return nil
		}
	}

	fmt.Println("")
	fmt.Println("Removing FIDO2 token and keyslot...")

	// Remove the keyslot using go-luks2
	if err := luks2.KillKeyslot(device, keyslotToRemove); err != nil {
		return ErrRemoveKeyslotFailed{Reason: err.Error()}
	}

	// If we have a token ID, remove the token from metadata
	if tokenIDToRemove != "" {
		// Re-read metadata after keyslot removal
		_, metadata, err := luks2.ReadHeader(device)
		if err != nil {
			return ErrRereadLUKSHeader{Reason: err.Error()}
		}

		// Remove token from metadata
		if metadata.Tokens != nil {
			delete(metadata.Tokens, tokenIDToRemove)

			// Re-read the binary header (we need it to write back)
			hdr, _, err := luks2.ReadHeader(device)
			if err != nil {
				return ErrRereadLUKSHeader{Reason: err.Error()}
			}

			// Increment sequence ID
			hdr.SequenceID++

			// Write updated metadata
			if err := luks2.WriteHeader(device, hdr, metadata); err != nil {
				return ErrWriteLUKSHeader{Reason: err.Error()}
			}

			if flags.debug {
				fmt.Printf("Removed token %s from metadata\n", tokenIDToRemove)
			}
		}
	}

	fmt.Println("")
	fmt.Println("========================================================================")
	fmt.Println("Removal Complete!")
	fmt.Println("========================================================================")
	fmt.Printf("Keyslot %d has been removed from %s\n", keyslotToRemove, device)
	if tokenIDToRemove != "" {
		fmt.Printf("Token %s has been removed from metadata\n", tokenIDToRemove)
	}

	return nil
}
