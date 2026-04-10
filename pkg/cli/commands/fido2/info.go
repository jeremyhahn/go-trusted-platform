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
	"fmt"
	"sort"
	"strconv"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// infoFlags contains flags specific to the info command
type infoFlags struct {
	device string
	debug  bool
}

// newInfoCommand creates the info subcommand for detailed FIDO2/LUKS information
func newInfoCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &infoFlags{}

	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show detailed FIDO2 and LUKS information",
		Long: `Display comprehensive information about the LUKS device including:
  - Device UUID, label, and encryption details
  - All FIDO2 tokens with full metadata
  - Associated keyslot information
  - Cipher and sector size configuration

Examples:
  # Show info for auto-detected device
  platformctl fido2 info

  # Show info for specific device
  platformctl fido2 info --device /dev/vda2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInfo(getFlags(), flags)
		},
	}

	cmd.Flags().StringVarP(&flags.device, "device", "d", "", "LUKS device path (auto-detected if not specified)")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")

	return cmd
}

// runInfo executes the info command
func runInfo(commonFlags *cli.CommonFlags, flags *infoFlags) error {
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
		if flags.debug {
			fmt.Printf("Auto-detected LUKS device: %s\n", device)
		}
	}

	// Get volume information
	volumeInfo, err := luks2.GetVolumeInfo(device)
	if err != nil {
		return ErrGetVolumeInfo{Reason: err.Error()}
	}

	// Display device information
	fmt.Println("========================================================================")
	fmt.Printf("LUKS Device Information: %s\n", device)
	fmt.Println("========================================================================")
	fmt.Printf("UUID:        %s\n", volumeInfo.UUID)
	if volumeInfo.Label != "" {
		fmt.Printf("Label:       %s\n", volumeInfo.Label)
	}
	fmt.Printf("Version:     LUKS%d\n", volumeInfo.Version)
	fmt.Printf("Cipher:      %s\n", volumeInfo.Cipher)
	fmt.Printf("Key Size:    %d bits\n", volumeInfo.KeySize)
	fmt.Printf("Sector Size: %d bytes\n", volumeInfo.SectorSize)

	// Display active keyslots
	fmt.Println("\n------------------------------------------------------------------------")
	fmt.Println("Active Keyslots")
	fmt.Println("------------------------------------------------------------------------")
	if len(volumeInfo.ActiveKeyslots) > 0 {
		sort.Ints(volumeInfo.ActiveKeyslots)
		for _, slotNum := range volumeInfo.ActiveKeyslots {
			slotIDStr := strconv.Itoa(slotNum)
			if keyslot, exists := volumeInfo.Metadata.Keyslots[slotIDStr]; exists {
				fmt.Printf("\nKeyslot %d:\n", slotNum)
				fmt.Printf("  Type:       %s\n", keyslot.Type)
				fmt.Printf("  Key Size:   %d bytes\n", keyslot.KeySize)
				if keyslot.Priority != nil {
					fmt.Printf("  Priority:   %d\n", *keyslot.Priority)
				}
				if keyslot.KDF != nil {
					fmt.Printf("  KDF:        %s\n", keyslot.KDF.Type)
					if keyslot.KDF.Hash != "" {
						fmt.Printf("  Hash:       %s\n", keyslot.KDF.Hash)
					}
				}
				if keyslot.Area != nil {
					fmt.Printf("  Encryption: %s\n", keyslot.Area.Encryption)
					fmt.Printf("  Area:       offset=%s, size=%s\n", keyslot.Area.Offset, keyslot.Area.Size)
				}
			}
		}
	} else {
		fmt.Println("No active keyslots found")
	}

	// Display FIDO2 tokens
	fmt.Println("\n------------------------------------------------------------------------")
	fmt.Println("FIDO2 Tokens")
	fmt.Println("------------------------------------------------------------------------")

	fido2Count := 0
	if volumeInfo.Metadata.Tokens != nil {
		// Sort token IDs for consistent output
		tokenIDs := make([]string, 0)
		for id, token := range volumeInfo.Metadata.Tokens {
			if token.Type == "fido2-manual" {
				tokenIDs = append(tokenIDs, id)
			}
		}
		sort.Strings(tokenIDs)

		for _, tokenID := range tokenIDs {
			token := volumeInfo.Metadata.Tokens[tokenID]
			fido2Count++

			fmt.Printf("\nToken %s:\n", tokenID)
			fmt.Printf("  Type:       %s\n", token.Type)
			fmt.Printf("  Keyslots:   %v\n", token.Keyslots)

			// Show FIDO2-specific fields
			if token.FIDO2RP != "" {
				fmt.Printf("  Relying Party: %s\n", token.FIDO2RP)
			}
			fmt.Printf("  User Presence Required: %v\n", token.FIDO2UPRequired)
			if token.FIDO2Credential != "" {
				credID := token.FIDO2Credential
				if len(credID) > 64 {
					credID = credID[:64] + "..."
				}
				fmt.Printf("  Credential ID: %s\n", credID)
			}
			if token.FIDO2Salt != "" {
				salt := token.FIDO2Salt
				if len(salt) > 32 {
					salt = salt[:32] + "..."
				}
				fmt.Printf("  Salt: %s\n", salt)
			}

			// Show which keyslots are associated
			if len(token.Keyslots) > 0 {
				fmt.Println("  Associated keyslots:")
				for _, ksID := range token.Keyslots {
					slotNum, _ := strconv.Atoi(ksID)
					if keyslot, exists := volumeInfo.Metadata.Keyslots[ksID]; exists {
						fmt.Printf("    Slot %d: %s, %d bytes, %s\n",
							slotNum,
							keyslot.Type,
							keyslot.KeySize,
							keyslot.Area.Encryption)
					}
				}
			}
		}
	}

	if fido2Count == 0 {
		fmt.Println("No FIDO2 tokens found")
	}

	// Display segments information
	fmt.Println("\n------------------------------------------------------------------------")
	fmt.Println("Data Segments")
	fmt.Println("------------------------------------------------------------------------")
	if volumeInfo.Metadata.Segments != nil {
		segmentIDs := make([]string, 0)
		for id := range volumeInfo.Metadata.Segments {
			segmentIDs = append(segmentIDs, id)
		}
		sort.Strings(segmentIDs)

		for _, segID := range segmentIDs {
			segment := volumeInfo.Metadata.Segments[segID]
			fmt.Printf("\nSegment %s:\n", segID)
			fmt.Printf("  Type:       %s\n", segment.Type)
			fmt.Printf("  Offset:     %s\n", segment.Offset)
			fmt.Printf("  Size:       %s\n", segment.Size)
			fmt.Printf("  Encryption: %s\n", segment.Encryption)
			fmt.Printf("  Sector:     %d bytes\n", segment.SectorSize)
			if segment.IVTweak != "" {
				fmt.Printf("  IV Tweak:   %s\n", segment.IVTweak)
			}
		}
	}

	fmt.Println("\n========================================================================")

	return nil
}
