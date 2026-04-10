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

package installer

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// FIDO2Unlock handles FIDO2 security key unlock for LUKS
// This follows the reference implementation pattern from build/iso/alpine/amd64/scripts/host/
type FIDO2Unlock struct {
	luksDevice string
	debug      bool
}

// NewFIDO2Unlock creates a new FIDO2 unlock handler
func NewFIDO2Unlock(luksDevice string, debug bool) *FIDO2Unlock {
	return &FIDO2Unlock{
		luksDevice: luksDevice,
		debug:      debug,
	}
}

// GetTokenInfo retrieves FIDO2 token metadata from LUKS header using pure Go
func (f *FIDO2Unlock) GetTokenInfo() (*FIDO2Token, error) {
	// Read LUKS2 header and metadata
	_, metadata, err := luks2.ReadHeader(f.luksDevice)
	if err != nil {
		return nil, fmt.Errorf("failed to read LUKS header: %w", err)
	}

	// Search for FIDO2 token in metadata
	for _, luksToken := range metadata.Tokens {
		// Check if this is a FIDO2 token
		if luksToken.Type == "fido2-manual" && luksToken.FIDO2Credential != "" {
			return &FIDO2Token{
				Type:            luksToken.Type,
				Keyslots:        luksToken.Keyslots,
				FIDO2Credential: luksToken.FIDO2Credential,
				FIDO2Salt:       luksToken.FIDO2Salt,
				FIDO2RP:         luksToken.FIDO2RP,
				FIDO2UPRequired: luksToken.FIDO2UPRequired,
			}, nil
		}
	}

	return nil, fmt.Errorf("no FIDO2 token found in LUKS header")
}

// DeriveKey derives the LUKS key using FIDO2 hmac-secret
func (f *FIDO2Unlock) DeriveKey(ctx context.Context, token *FIDO2Token) ([]byte, error) {
	// Detect FIDO2 device
	listCmd := exec.Command("fido2-token", "-L")
	output, err := listCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list FIDO2 devices: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return nil, fmt.Errorf("no FIDO2 devices detected")
	}

	devicePath := strings.Split(lines[0], " ")[0]
	devicePath = strings.TrimSuffix(devicePath, ":")

	if f.debug {
		fmt.Printf("Using FIDO2 device: %s\n", devicePath)
	}

	// Generate challenge (same as enrollment) using SHA-256
	sha256Cmd := exec.Command("sh", "-c",
		"echo -n 'luks-enrollment-challenge' | sha256sum | head -c 64 | xxd -r -p | base64 -w0")
	challengeOutput, err := sha256Cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	challengeB64 := strings.TrimSpace(string(challengeOutput))

	// Derive HMAC-secret using stored credential ID and salt
	fmt.Println("Touch your security key to unlock...")

	assertParams := fmt.Sprintf("%s\n%s\n%s\n%s\n",
		challengeB64,
		token.FIDO2RP,
		token.FIDO2Credential,
		token.FIDO2Salt,
	)

	assertCmd := exec.CommandContext(ctx, "fido2-assert", "-G", "-h", devicePath)
	assertCmd.Stdin = strings.NewReader(assertParams)
	assertOutput, err := assertCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get HMAC-secret: %w", err)
	}

	// Extract HMAC-secret (last line)
	assertLines := strings.Split(strings.TrimSpace(string(assertOutput)), "\n")
	if len(assertLines) == 0 {
		return nil, fmt.Errorf("failed to extract HMAC-secret")
	}
	hmacSecretB64 := assertLines[len(assertLines)-1]

	hmacSecret, err := base64.StdEncoding.DecodeString(hmacSecretB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode HMAC-secret: %w", err)
	}

	if len(hmacSecret) != 32 {
		return nil, fmt.Errorf("invalid HMAC-secret length: expected 32, got %d", len(hmacSecret))
	}

	return hmacSecret, nil
}

// Unlock opens the LUKS device using FIDO2 security key
func (f *FIDO2Unlock) Unlock(ctx context.Context, mappedName string) error {
	// Get token info
	token, err := f.GetTokenInfo()
	if err != nil {
		return err
	}

	if f.debug {
		fmt.Printf("Found FIDO2 token: RP=%s, keyslots=%v\n", token.FIDO2RP, token.Keyslots)
	}

	// Derive key
	key, err := f.DeriveKey(ctx, token)
	if err != nil {
		return err
	}

	// Open LUKS device using pure Go
	if err := luks2.Unlock(f.luksDevice, key, mappedName); err != nil {
		return fmt.Errorf("failed to open LUKS device: %w", err)
	}

	fmt.Printf("LUKS device unlocked successfully as /dev/mapper/%s\n", mappedName)
	return nil
}

// TestUnlock tests if the FIDO2 key can unlock the device without actually opening it
func (f *FIDO2Unlock) TestUnlock(ctx context.Context) error {
	// Get token info
	token, err := f.GetTokenInfo()
	if err != nil {
		return err
	}

	// Derive key
	key, err := f.DeriveKey(ctx, token)
	if err != nil {
		return err
	}

	// Test passphrase by unlocking and immediately locking using pure Go
	testName := "fido2_unlock_test"

	// Clean up any existing test mapping
	if luks2.IsUnlocked(testName) {
		_ = luks2.Lock(testName)
	}

	// Try to unlock with the derived key
	if err := luks2.Unlock(f.luksDevice, key, testName); err != nil {
		return fmt.Errorf("FIDO2 key test failed: key does not unlock device")
	}

	// Immediately close the test mapping
	if err := luks2.Lock(testName); err != nil {
		fmt.Printf("Warning: failed to close test mapping: %v\n", err)
	}

	fmt.Println("FIDO2 unlock test passed successfully!")
	return nil
}
