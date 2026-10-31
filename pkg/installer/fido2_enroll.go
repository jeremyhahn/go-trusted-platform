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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// newFIDO2Handler opens the SDK FIDO2 handler on the HID transport. Tests
// replace it with a fake authenticator.
var newFIDO2Handler = func(cfg *fido2.Config) (fido2.Handler, error) {
	return fido2.NewHandler(cfg, fido2.NewDefaultEnumerator())
}

// The go-luks2 header writes of the enrolment. Tests replace them with an
// in-memory header.
var (
	luksAddKey            = luks2.AddKey
	luksFindFreeTokenSlot = luks2.FindFreeTokenSlot
	luksImportToken       = luks2.ImportToken
	luksKillSlot          = luks2.KillSlot
)

// FIDO2Enrollment handles FIDO2 security key enrollment for LUKS. The
// credential and the slot key come from the SDK FIDO2 handler, so the slot
// is keyed with the derivation the initrd FIDO2 strategy unlocks with.
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
	// Token import/export also uses pure Go luks2 library now.
	// The credential and key derivation use the SDK FIDO2 handler over HID;
	// fido2-token is still used to detect the device.
	tools := []string{
		"fido2-token",
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

// Enroll performs the complete FIDO2 enrollment process through the SDK
// FIDO2 handler.
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

	// Step 5: Enroll a credential and key the slot through the SDK handler
	handler, err := newFIDO2Handler(f.handlerConfig(devicePath))
	if err != nil {
		return &WrappedError{Msg: "failed to open the FIDO2 handler", Err: err}
	}
	err = f.enrollWithHandler(ctx, handler)
	if closeErr := handler.Close(); closeErr != nil {
		fmt.Printf("Warning: failed to close the FIDO2 handler: %v\n", closeErr)
	}
	return err
}

// handlerConfig returns the SDK handler configuration for the detected device.
func (f *FIDO2Enrollment) handlerConfig(devicePath string) *fido2.Config {
	cfg := fido2.DefaultConfig
	cfg.DevicePath = devicePath
	cfg.RelyingPartyID = f.config.RelyingPartyID
	cfg.Debug = f.config.Debug
	return &cfg
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

// enrollWithHandler creates the credential and keys the target slot with the
// key the SDK derives from it (UnlockWithKey). That is the key the initrd
// FIDO2 strategy derives at boot, so the slot is never keyed with the raw
// hmac-secret. The token type luks.TokenTypeFIDO2 records that derivation.
//
// The context is checked before each authenticator call and before each
// header write, and an authenticator call stops waiting when it ends, so a
// cancelled installation never writes the token. A cancellation that comes
// after the keyslot is written removes it again (rollbackKeyslot), so no
// slot is left that boot cannot unlock or a retry cannot reuse.
func (f *FIDO2Enrollment) enrollWithHandler(ctx context.Context, handler fido2.Handler) error {
	userID := make([]byte, 32)
	if _, err := randomRead(userID); err != nil {
		return &WrappedError{Msg: "failed to generate user ID", Err: err}
	}

	fmt.Println("Creating FIDO2 credential (touch your security key)...")
	result, err := awaitAuthenticator(ctx, "create the credential", func() (*fido2.EnrollmentResult, error) {
		return handler.EnrollKey(&fido2.EnrollmentConfig{
			RelyingParty: fido2.RelyingParty{ID: f.config.RelyingPartyID, Name: f.config.RelyingPartyID},
			User:         fido2.User{ID: userID, Name: f.config.UserName, DisplayName: f.config.UserName},
		})
	})
	if errors.As(err, new(*FIDO2CanceledError)) {
		return err
	}
	if err != nil {
		return &FIDO2EnrollKeyError{Err: err}
	}

	salt := result.Salt
	if len(salt) == 0 {
		salt = make([]byte, 32)
		if _, err := randomRead(salt); err != nil {
			return &WrappedError{Msg: "failed to generate salt", Err: err}
		}
	}
	rpID := result.RelyingParty.ID
	if rpID == "" {
		rpID = f.config.RelyingPartyID
	}

	fmt.Println("Deriving LUKS key from FIDO2 device (touch your security key again)...")
	key, err := awaitAuthenticator(ctx, "derive the LUKS key", func() ([]byte, error) {
		return handler.UnlockWithKey(&fido2.AuthenticationConfig{
			RelyingPartyID: rpID,
			CredentialID:   result.CredentialID,
			Salt:           salt,
		})
	})
	if errors.As(err, new(*FIDO2CanceledError)) {
		return err
	}
	if err != nil {
		return &FIDO2DeriveKeyError{Err: err}
	}
	defer clear(key)

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

	if err := ctx.Err(); err != nil {
		return &FIDO2CanceledError{Step: "add the keyslot", Err: err}
	}
	if err := luksAddKey(f.config.LUKSDevice, []byte(f.config.LUKSPassphrase), key, addKeyOpts); err != nil {
		return &FIDO2AddKeyError{Slot: f.config.TargetKeyslot, Err: err}
	}

	if f.config.Debug {
		fmt.Printf("LUKS key slot %d added successfully\n", f.config.TargetKeyslot)
	}

	if err := ctx.Err(); err != nil {
		return f.rollbackKeyslot(&FIDO2CanceledError{Step: "store the token", Err: err})
	}
	fmt.Println("Storing FIDO2 metadata in LUKS token...")

	tokenID, err := luksFindFreeTokenSlot(f.config.LUKSDevice)
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
		fmt.Println("FIDO2 key enrolled but metadata not stored - manual unlock required")
	} else {
		luksToken := &luks2.Token{
			Type:            luks.TokenTypeFIDO2,
			Keyslots:        []string{fmt.Sprintf("%d", f.config.TargetKeyslot)},
			FIDO2Credential: base64.StdEncoding.EncodeToString(result.CredentialID),
			FIDO2Salt:       base64.StdEncoding.EncodeToString(salt),
			FIDO2RP:         rpID,
			FIDO2UPRequired: true,
		}
		if err := luksImportToken(f.config.LUKSDevice, tokenID, luksToken); err != nil {
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

// rollbackKeyslot removes the keyslot this enrolment added and returns
// cause, joined with a FIDO2RollbackError when the slot could not be
// removed. go-luks2 takes no context, so the removal still runs after the
// enrolment's context has ended.
func (f *FIDO2Enrollment) rollbackKeyslot(cause error) error {
	if err := luksKillSlot(f.config.LUKSDevice, []byte(f.config.LUKSPassphrase), f.config.TargetKeyslot); err != nil {
		return errors.Join(cause, &FIDO2RollbackError{Slot: f.config.TargetKeyslot, Err: err})
	}
	return cause
}

// awaitAuthenticator runs a blocking SDK handler call, whose methods take no
// context, and stops waiting for it when ctx ends. The result channel is
// buffered, so the call's goroutine finishes even when nobody receives.
func awaitAuthenticator[T any](ctx context.Context, step string, call func() (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, &FIDO2CanceledError{Step: step, Err: err}
	}
	type outcome struct {
		value T
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		value, err := call()
		done <- outcome{value: value, err: err}
	}()
	select {
	case <-ctx.Done():
		return zero, &FIDO2CanceledError{Step: step, Err: ctx.Err()}
	case result := <-done:
		return result.value, result.err
	}
}

// FIDO2CanceledError reports that the enrolment stopped because its context
// ended before Step.
type FIDO2CanceledError struct {
	Step string
	Err  error
}

// Error implements the error interface.
func (e *FIDO2CanceledError) Error() string {
	return fmt.Sprintf("fido2: enrolment cancelled before it could %s: %v", e.Step, e.Err)
}

// Unwrap returns the context error.
func (e *FIDO2CanceledError) Unwrap() error {
	return e.Err
}

// FIDO2EnrollKeyError reports that the SDK handler could not create the
// FIDO2 credential.
type FIDO2EnrollKeyError struct {
	Err error
}

// Error implements the error interface.
func (e *FIDO2EnrollKeyError) Error() string {
	return fmt.Sprintf("fido2: failed to create the credential: %v", e.Err)
}

// Unwrap returns the handler error.
func (e *FIDO2EnrollKeyError) Unwrap() error {
	return e.Err
}

// FIDO2DeriveKeyError reports that the SDK handler could not derive the slot
// key from the new credential.
type FIDO2DeriveKeyError struct {
	Err error
}

// Error implements the error interface.
func (e *FIDO2DeriveKeyError) Error() string {
	return fmt.Sprintf("fido2: failed to derive the LUKS key: %v", e.Err)
}

// Unwrap returns the handler error.
func (e *FIDO2DeriveKeyError) Unwrap() error {
	return e.Err
}

// FIDO2RollbackError reports that the keyslot a cancelled enrolment added
// could not be removed again.
type FIDO2RollbackError struct {
	Slot int
	Err  error
}

// Error implements the error interface.
func (e *FIDO2RollbackError) Error() string {
	return fmt.Sprintf("fido2: failed to remove LUKS key slot %d after the enrolment was cancelled: %v", e.Slot, e.Err)
}

// Unwrap returns the go-luks2 error.
func (e *FIDO2RollbackError) Unwrap() error {
	return e.Err
}

// FIDO2AddKeyError reports that the derived key could not be added to the
// target keyslot.
type FIDO2AddKeyError struct {
	Slot int
	Err  error
}

// Error implements the error interface.
func (e *FIDO2AddKeyError) Error() string {
	return fmt.Sprintf("fido2: failed to add LUKS key slot %d: %v", e.Slot, e.Err)
}

// Unwrap returns the go-luks2 error.
func (e *FIDO2AddKeyError) Unwrap() error {
	return e.Err
}
