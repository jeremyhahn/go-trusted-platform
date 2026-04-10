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

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// listFlags contains flags specific to the list command
type listFlags struct {
	device string
	debug  bool
}

// newListCommand creates the list subcommand for listing FIDO2 tokens
func newListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &listFlags{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List FIDO2 tokens in LUKS device",
		Long: `List all FIDO2 security tokens registered in the LUKS device metadata.

Shows token ID, associated keyslots, relying party ID, and credential ID information
for each enrolled FIDO2 token.

Examples:
  # List tokens on auto-detected device
  platformctl fido2 list

  # List tokens on specific device
  platformctl fido2 list --device /dev/vda2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(getFlags(), flags)
		},
	}

	cmd.Flags().StringVarP(&flags.device, "device", "d", "", "LUKS device path (auto-detected if not specified)")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")

	return cmd
}

// FIDO2TokenInfo contains parsed FIDO2 token information
type FIDO2TokenInfo struct {
	Type            string
	Keyslots        []string
	FIDO2Credential string
	FIDO2Salt       string
	FIDO2RP         string
	FIDO2UPRequired bool
}

// parseFIDO2Token extracts FIDO2-specific fields from a token
func parseFIDO2Token(token *luks2.Token) *FIDO2TokenInfo {
	return &FIDO2TokenInfo{
		Type:            token.Type,
		Keyslots:        token.Keyslots,
		FIDO2Credential: token.FIDO2Credential,
		FIDO2Salt:       token.FIDO2Salt,
		FIDO2RP:         token.FIDO2RP,
		FIDO2UPRequired: token.FIDO2UPRequired,
	}
}

// runList executes the list command
func runList(commonFlags *cli.CommonFlags, flags *listFlags) error {
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

	// Read LUKS header and metadata
	_, metadata, err := luks2.ReadHeader(device)
	if err != nil {
		return ErrReadLUKSHeader{Reason: err.Error()}
	}

	// Find all FIDO2 tokens
	fido2Tokens := make(map[string]*FIDO2TokenInfo)
	if metadata.Tokens != nil {
		for tokenID, token := range metadata.Tokens {
			if token.Type == "fido2-manual" {
				tokenInfo := parseFIDO2Token(token)
				fido2Tokens[tokenID] = tokenInfo
			}
		}
	}

	if len(fido2Tokens) == 0 {
		fmt.Printf("No FIDO2 tokens found on device %s\n", device)
		return nil
	}

	fmt.Println("========================================================================")
	fmt.Printf("FIDO2 Tokens on %s\n", device)
	fmt.Println("========================================================================")

	// Sort token IDs for consistent output
	tokenIDs := make([]string, 0, len(fido2Tokens))
	for id := range fido2Tokens {
		tokenIDs = append(tokenIDs, id)
	}
	sort.Strings(tokenIDs)

	for _, tokenID := range tokenIDs {
		token := fido2Tokens[tokenID]
		fmt.Printf("\nToken ID: %s\n", tokenID)
		fmt.Printf("  Type: %s\n", token.Type)
		fmt.Printf("  Keyslots: %v\n", token.Keyslots)
		fmt.Printf("  Relying Party: %s\n", token.FIDO2RP)
		fmt.Printf("  User Presence Required: %v\n", token.FIDO2UPRequired)

		// Truncate credential ID for display
		credID := token.FIDO2Credential
		if len(credID) > 64 {
			credID = credID[:64] + "..."
		}
		fmt.Printf("  Credential ID: %s\n", credID)

		// Truncate salt for display
		salt := token.FIDO2Salt
		if len(salt) > 32 {
			salt = salt[:32] + "..."
		}
		fmt.Printf("  Salt: %s\n", salt)
	}

	fmt.Println("\n========================================================================")
	fmt.Printf("Total: %d FIDO2 token(s)\n", len(fido2Tokens))

	return nil
}
