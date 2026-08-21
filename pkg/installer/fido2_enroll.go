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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

// FIDO2Enrollment handles FIDO2 security key enrollment for LUKS
// This follows the reference implementation at build/iso/alpine/amd64/scripts/host/fido2-enroll.sh
type FIDO2Enrollment struct {
	config *FIDO2EnrollmentConfig
}

// FIDO2EnrollmentConfig contains enrollment parameters
type FIDO2EnrollmentConfig struct {
	// LUKSDevice is the LUKS-encrypted device (e.g., /dev/vda2)
	LUKSDevice string

	// LUKSPassphrase is the existing LUKS passphrase (for adding new keyslot)
	LUKSPassphrase string

	// TargetKeyslot is the LUKS keyslot to use for FIDO2 (default: 3)
	TargetKeyslot int

	// RelyingPartyID is the RP ID for FIDO2 credential (default: "luks-alpine")
	RelyingPartyID string

	// UserName is the username for FIDO2 credential (default: "luks-user")
	UserName string

	// FIPSMode forces use of FIPS-approved algorithms (PBKDF2 instead of Argon2id)
	FIPSMode bool

	// Debug enables verbose output
	Debug bool
}

// FIDO2Token contains the token metadata stored in LUKS
type FIDO2Token struct {
	Type            string   `json:"type"`
	Keyslots        []string `json:"keyslots"`
	FIDO2Credential string   `json:"fido2-credential"`
	FIDO2Salt       string   `json:"fido2-salt"`
	FIDO2RP         string   `json:"fido2-rp"`
	FIDO2UPRequired bool     `json:"fido2-up-required"`
}

// NewFIDO2Enrollment creates a new FIDO2 enrollment handler
func NewFIDO2Enrollment(config *FIDO2EnrollmentConfig) (*FIDO2Enrollment, error) {
	if config == nil {
		return nil, &MessageError{Msg: "FIDO2 enrollment config is required"}
	}

	// Set defaults
	if config.TargetKeyslot == 0 {
		config.TargetKeyslot = 3
	}
	if config.RelyingPartyID == "" {
		config.RelyingPartyID = "luks-alpine"
	}
	if config.UserName == "" {
		config.UserName = "luks-user"
	}

	return &FIDO2Enrollment{config: config}, nil
}

// DetectFIDO2Device checks if a FIDO2 device with hmac-secret support is present
// Returns device path if found, empty string if not found, error on failure
func DetectFIDO2Device() (string, error) {
	// Check if fido2-token command is available
	if _, err := exec.LookPath("fido2-token"); err != nil {
		return "", nil // Not an error, just no FIDO2 tools available
	}

	// List FIDO2 devices
	listCmd := exec.Command("fido2-token", "-L")
	output, err := listCmd.Output()
	if err != nil {
		return "", nil // No devices or error listing
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return "", nil // No devices found
	}

	// Parse first device
	firstLine := lines[0]
	devicePath := strings.Split(firstLine, " ")[0]
	devicePath = strings.TrimSuffix(devicePath, ":")

	if devicePath == "" {
		return "", nil
	}

	// Check if device supports hmac-secret
	infoCmd := exec.Command("fido2-token", "-I", devicePath)
	infoOutput, err := infoCmd.CombinedOutput()
	if err != nil {
		return "", nil
	}

	if !strings.Contains(string(infoOutput), "hmac-secret") {
		return "", nil // Device doesn't support hmac-secret
	}

	return devicePath, nil
}

// IsFIDO2Available checks if FIDO2 enrollment is possible
// Returns true if both FIDO2 tools and a compatible device are available
func IsFIDO2Available() bool {
	device, err := DetectFIDO2Device()
	if err != nil {
		return false
	}
	return device != ""
}

// CheckRequiredTools verifies that all required tools are available
func (f *FIDO2Enrollment) CheckRequiredTools() error {
	// Note: cryptsetup is no longer required - LUKS operations use pure Go luks2 library
	// Token import/export also uses pure Go luks2 library now
	tools := []string{
		"fido2-token",
		"fido2-cred",
		"fido2-assert",
		"base64",
		"xxd",
	}

	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			return &MessageError{Msg: fmt.Sprintf("%s command not found. Install required packages: apk add libfido2 fido2 coreutils", tool)}
		}
	}

	return nil
}

// DetectDevice finds a FIDO2 device with hmac-secret support
func (f *FIDO2Enrollment) DetectDevice() (string, error) {
	// List FIDO2 devices
	listCmd := exec.Command("fido2-token", "-L")
	output, err := listCmd.Output()
	if err != nil {
		return "", &WrappedError{Msg: "failed to list FIDO2 devices", Err: err}
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return "", &MessageError{Msg: "no FIDO2 devices detected. Please plug in your security key and try again"}
	}

	// Parse first device
	firstLine := lines[0]
	devicePath := strings.Split(firstLine, " ")[0]
	devicePath = strings.TrimSuffix(devicePath, ":")

	if devicePath == "" {
		return "", &MessageError{Msg: fmt.Sprintf("failed to parse device path from: %s", firstLine)}
	}

	// Check if device supports hmac-secret
	infoCmd := exec.Command("fido2-token", "-I", devicePath)
	infoOutput, err := infoCmd.CombinedOutput()
	if err != nil {
		return "", &WrappedError{Msg: "failed to get device info", Err: err}
	}

	if !strings.Contains(string(infoOutput), "hmac-secret") {
		return "", &MessageError{Msg: "FIDO2 device does not support hmac-secret extension. This device cannot be used for LUKS encryption"}
	}

	return devicePath, nil
}

// ValidateLUKSDevice verifies the device is a valid LUKS container using pure Go
func (f *FIDO2Enrollment) ValidateLUKSDevice() error {
	// Try to read LUKS2 header - will fail if not a valid LUKS2 device
	_, _, err := luks2.ReadHeader(f.config.LUKSDevice)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("%s is not a LUKS2 device", f.config.LUKSDevice), Err: err}
	}
	return nil
}

// VerifyPassphrase checks if the existing passphrase is valid using pure Go
func (f *FIDO2Enrollment) VerifyPassphrase() error {
	// Attempt to unlock with a temporary name to verify passphrase
	testName := "fido2_passphrase_test"

	// First check if already unlocked (shouldn't be, but be safe)
	if luks2.IsUnlocked(testName) {
		_ = luks2.Lock(testName)
	}

	// Try to unlock with the passphrase
	if err := luks2.Unlock(f.config.LUKSDevice, []byte(f.config.LUKSPassphrase), testName); err != nil {
		return &WrappedError{Msg: "invalid LUKS passphrase", Err: err}
	}

	// Immediately close the test mapping
	if err := luks2.Lock(testName); err != nil {
		// Log warning but don't fail - passphrase was valid
		fmt.Printf("Warning: failed to close test mapping: %v\n", err)
	}

	return nil
}

// Enroll performs the complete FIDO2 enrollment process
// This follows the reference at build/iso/alpine/amd64/scripts/host/fido2-enroll.sh
func (f *FIDO2Enrollment) Enroll(ctx context.Context) error {
	// Step 1: Check required tools
	if err := f.CheckRequiredTools(); err != nil {
		return err
	}

	// Step 2: Validate LUKS device
	if err := f.ValidateLUKSDevice(); err != nil {
		return err
	}

	// Step 3: Verify passphrase
	if err := f.VerifyPassphrase(); err != nil {
		return err
	}

	// Step 4: Detect FIDO2 device with hmac-secret support
	devicePath, err := f.DetectDevice()
	if err != nil {
		return err
	}

	if f.config.Debug {
		fmt.Printf("Using FIDO2 device: %s\n", devicePath)
	}

	// Step 5: Generate enrollment parameters
	// Generate salt (32 bytes)
	salt := make([]byte, 32)
	if _, err := randomRead(salt); err != nil {
		return &WrappedError{Msg: "failed to generate salt", Err: err}
	}
	saltB64 := base64.StdEncoding.EncodeToString(salt)

	// Generate challenge
	challengeInput := []byte("luks-enrollment-challenge")
	challengeHash := sha256.Sum256(challengeInput)
	challengeB64 := base64.StdEncoding.EncodeToString(challengeHash[:])

	// Generate user ID
	userID := make([]byte, 32)
	if _, err := randomRead(userID); err != nil {
		return &WrappedError{Msg: "failed to generate user ID", Err: err}
	}
	userIDB64 := base64.StdEncoding.EncodeToString(userID)

	// Step 6: Create FIDO2 credential with hmac-secret extension
	fmt.Println("Creating FIDO2 credential (touch your security key)...")

	credParams := fmt.Sprintf("%s\n%s\n%s\n%s\n",
		challengeB64,
		f.config.RelyingPartyID,
		f.config.UserName,
		userIDB64,
	)

	// Use standard credential (non-resident) - CanoKey QEMU has issues with resident keys
	credCmd := exec.CommandContext(ctx, "fido2-cred", "-M", "-h", devicePath)
	credCmd.Stdin = strings.NewReader(credParams)
	credOutput, err := credCmd.CombinedOutput()
	if err != nil {
		if f.config.Debug {
			fmt.Printf("fido2-cred input:\n%s\n", credParams)
			fmt.Printf("fido2-cred output: %s\n", string(credOutput))
		}
		return &CommandOutputError{Msg: "failed to create credential", Err: err, Detail: fmt.Sprintf("\nDevice output: %s", string(credOutput))}
	}

	// Parse fido2-cred output to extract credential ID
	// fido2-cred -M output format (from libfido2 man page):
	// Line 0: client_data_hash (base64) - the challenge echoed back
	// Line 1: relying_party_id (UTF-8 string)
	// Line 2: credential_format (UTF-8 string: "packed", "none", "fido-u2f")
	// Line 3: authenticator_data (base64, CBOR encoded)
	// Line 4: credential_id (base64) - THIS IS WHAT WE NEED
	// Line 5: attestation_signature (base64)
	// Line 6+: attestation_certificate (base64, if present)
	credLines := strings.Split(strings.TrimSpace(string(credOutput)), "\n")

	if f.config.Debug {
		fmt.Printf("fido2-cred output (%d lines):\n", len(credLines))
		for i, line := range credLines {
			if len(line) > 60 {
				fmt.Printf("  [%d] %s... (%d chars)\n", i, line[:60], len(line))
			} else {
				fmt.Printf("  [%d] %s\n", i, line)
			}
		}
	}

	if len(credLines) < 5 {
		return &MessageError{Msg: fmt.Sprintf("failed to extract credential from fido2-cred output: expected at least 5 lines, got %d", len(credLines))}
	}

	// Line 4 is the credential ID (base64 encoded) - use it directly
	credentialIDB64 := strings.TrimSpace(credLines[4])

	// Validate it's valid base64
	if _, err := base64.StdEncoding.DecodeString(credentialIDB64); err != nil {
		return &WrappedError{Msg: "invalid credential ID (not valid base64)", Err: err}
	}

	if f.config.Debug {
		fmt.Printf("Using credential ID from line 4: %s\n", credentialIDB64)
	}

	return f.enrollWithCredentialID(ctx, devicePath, credentialIDB64, saltB64, challengeB64)
}

// findFreeTokenSlot finds the next available LUKS token slot using pure Go
func (f *FIDO2Enrollment) findFreeTokenSlot() (int, error) {
	return luks2.FindFreeTokenSlot(f.config.LUKSDevice)
}

// randomRead fills the buffer with random bytes
func randomRead(b []byte) (n int, err error) {
	file, err := os.Open("/dev/urandom")
	if err != nil {
		return 0, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	return file.Read(b)
}

// enrollWithCredentialID performs FIDO2 enrollment using a known credential ID
// This is used when we can extract the credential ID directly from fido2-cred output
func (f *FIDO2Enrollment) enrollWithCredentialID(ctx context.Context, devicePath, credentialID, saltB64, challengeB64 string) error {
	// Step 7: Derive LUKS key using hmac-secret
	fmt.Println("Deriving LUKS key from FIDO2 device (touch your security key again)...")

	// fido2-assert -G -h input format for non-resident credentials (per Yubico libfido2 documentation):
	// Line 1: client_data_hash (challenge) - base64
	// Line 2: relying_party_id
	// Line 3: credential_id - base64 (required for non-resident credentials)
	// Line 4: hmac_salt - base64 (for -h flag)
	assertParams := fmt.Sprintf("%s\n%s\n%s\n%s\n",
		challengeB64,
		f.config.RelyingPartyID,
		credentialID,
		saltB64,
	)

	// Use non-resident credential format (no -r flag) - CanoKey QEMU has issues with resident keys
	assertCmd := exec.CommandContext(ctx, "fido2-assert", "-G", "-h", devicePath)
	assertCmd.Stdin = strings.NewReader(assertParams)
	assertOutput, err := assertCmd.CombinedOutput()
	if err != nil {
		if f.config.Debug {
			fmt.Printf("fido2-assert input:\n%s\n", assertParams)
			fmt.Printf("fido2-assert output: %s\n", string(assertOutput))
		}
		return &CommandOutputError{Msg: "failed to get HMAC-secret", Err: err, Detail: fmt.Sprintf("\nDevice output: %s", string(assertOutput))}
	}

	// Extract HMAC-secret (last line, base64 encoded)
	assertLines := strings.Split(strings.TrimSpace(string(assertOutput)), "\n")
	if len(assertLines) == 0 {
		return &MessageError{Msg: "failed to extract HMAC-secret from fido2-assert output"}
	}
	hmacSecretB64 := assertLines[len(assertLines)-1]

	hmacSecret, err := base64.StdEncoding.DecodeString(hmacSecretB64)
	if err != nil {
		return &WrappedError{Msg: "failed to decode HMAC-secret", Err: err}
	}

	if len(hmacSecret) != 32 {
		return &MessageError{Msg: fmt.Sprintf("invalid HMAC-secret length: expected 32 bytes, got %d", len(hmacSecret))}
	}

	if f.config.Debug {
		fmt.Printf("HMAC-secret derived successfully (%d bytes)\n", len(hmacSecret))
	}

	// Step 8: Add LUKS keyslot with derived key using pure Go luks2 library
	fmt.Printf("Adding LUKS key slot %d...\n", f.config.TargetKeyslot)

	// Configure key add options
	addKeyOpts := &luks2.AddKeyOptions{
		Keyslot: &f.config.TargetKeyslot,
	}
	// Honour the config flag, then apply the platform policy on top.
	//
	// The flag alone was not enough: it only set PBKDF2 when FIPSMode was
	// explicitly true, and never consulted the running kernel. On a
	// FIPS-activated host whose OS config left FIPSMode false, AddKey received
	// an empty KDF and go-luks2 defaulted it to argon2id — persisting a
	// non-approved keyslot through the FIDO2 enrolment path.
	if f.config.FIPSMode {
		addKeyOpts.KDFType = fips.KDFPBKDF2
		addKeyOpts.Hash = fips.HashSHA256
	}
	if err := fips.ResolveKeyslotPolicy(&addKeyOpts.KDFType, &addKeyOpts.Hash); err != nil {
		return &WrappedError{Msg: "LUKS keyslot policy rejected the FIDO2 enrollment options", Err: err}
	}

	// Add the FIDO2-derived key to LUKS
	if err := luks2.AddKey(f.config.LUKSDevice, []byte(f.config.LUKSPassphrase), hmacSecret, addKeyOpts); err != nil {
		return &WrappedError{Msg: "failed to add LUKS key slot", Err: err}
	}

	if f.config.Debug {
		fmt.Printf("LUKS key slot %d added successfully\n", f.config.TargetKeyslot)
	}

	// Step 9: Store metadata in LUKS token using pure Go
	fmt.Println("Storing FIDO2 metadata in LUKS token...")

	tokenID, err := f.findFreeTokenSlot()
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
		fmt.Println("FIDO2 key enrolled but metadata not stored - manual unlock required")
	} else {
		// Create luks2.Token for import
		luksToken := &luks2.Token{
			Type:            "fido2-manual",
			Keyslots:        []string{fmt.Sprintf("%d", f.config.TargetKeyslot)},
			FIDO2Credential: credentialID,
			FIDO2Salt:       saltB64,
			FIDO2RP:         f.config.RelyingPartyID,
			FIDO2UPRequired: true,
		}

		// Import token using pure Go luks2 library
		if err := luks2.ImportToken(f.config.LUKSDevice, tokenID, luksToken); err != nil {
			fmt.Printf("Warning: Failed to store FIDO2 metadata in token: %v\n", err)
			fmt.Println("FIDO2 key enrolled but metadata not stored - manual unlock required")
		} else if f.config.Debug {
			fmt.Printf("FIDO2 metadata stored in token %d\n", tokenID)
		}
	}

	fmt.Println("FIDO2 enrollment complete!")
	fmt.Printf("Your LUKS device can now be unlocked with your security key (slot %d)\n", f.config.TargetKeyslot)

	return nil
}
