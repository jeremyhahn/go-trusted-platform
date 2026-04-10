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
	"context"
	"io"
	"os"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// =============================================================================
// Dependency Injection Interfaces for Testing
// =============================================================================

// RootChecker checks if the process is running as root
type RootChecker interface {
	CheckRoot() error
}

// DeviceDetector handles LUKS device detection
type DeviceDetector interface {
	AutoDetectLUKSDevice() (string, error)
}

// EnrollmentFactory creates FIDO2 enrollment handlers
type EnrollmentFactory interface {
	NewFIDO2Enrollment(config *installer.FIDO2EnrollmentConfig) (Enrollment, error)
}

// Enrollment provides FIDO2 enrollment operations
type Enrollment interface {
	Enroll(ctx context.Context) error
}

// UnlockFactory creates FIDO2 unlock handlers
type UnlockFactory interface {
	NewFIDO2Unlock(device string, debug bool) *installer.FIDO2Unlock
}

// ConfirmationReader reads user confirmation from stdin
type ConfirmationReader interface {
	ReadConfirmation(reader io.Reader) (string, error)
}

// =============================================================================
// Default Implementations
// =============================================================================

// defaultRootChecker implements RootChecker using os.Geteuid
type defaultRootChecker struct{}

func (d *defaultRootChecker) CheckRoot() error {
	if os.Geteuid() != 0 {
		return ErrRootRequired{}
	}
	return nil
}

// defaultDeviceDetector implements DeviceDetector using luks2.IsLUKS
type defaultDeviceDetector struct{}

func (d *defaultDeviceDetector) AutoDetectLUKSDevice() (string, error) {
	return autoDetectLUKSDevice()
}

// defaultEnrollmentFactory implements EnrollmentFactory
type defaultEnrollmentFactory struct{}

func (d *defaultEnrollmentFactory) NewFIDO2Enrollment(config *installer.FIDO2EnrollmentConfig) (Enrollment, error) {
	return installer.NewFIDO2Enrollment(config)
}

// defaultUnlockFactory implements UnlockFactory
type defaultUnlockFactory struct{}

func (d *defaultUnlockFactory) NewFIDO2Unlock(device string, debug bool) *installer.FIDO2Unlock {
	return installer.NewFIDO2Unlock(device, debug)
}

// defaultConfirmationReader implements ConfirmationReader
type defaultConfirmationReader struct{}

func (d *defaultConfirmationReader) ReadConfirmation(reader io.Reader) (string, error) {
	bufReader := bufio.NewReader(reader)
	return bufReader.ReadString('\n')
}

// =============================================================================
// Testable Dependencies
// =============================================================================

// Dependencies holds all injectable dependencies for FIDO2 commands
type Dependencies struct {
	RootChecker        RootChecker
	DeviceDetector     DeviceDetector
	EnrollmentFactory  EnrollmentFactory
	UnlockFactory      UnlockFactory
	ConfirmationReader ConfirmationReader
	Stdin              io.Reader
}

// NewDefaultDependencies creates dependencies with default implementations
func NewDefaultDependencies() *Dependencies {
	return &Dependencies{
		RootChecker:        &defaultRootChecker{},
		DeviceDetector:     &defaultDeviceDetector{},
		EnrollmentFactory:  &defaultEnrollmentFactory{},
		UnlockFactory:      &defaultUnlockFactory{},
		ConfirmationReader: &defaultConfirmationReader{},
		Stdin:              os.Stdin,
	}
}

// =============================================================================
// Validation Functions (Pure, Testable)
// =============================================================================

// ValidateRemoveInput validates input for the remove command
func ValidateRemoveInput(tokenID string, slot int) error {
	if tokenID == "" && slot < 0 {
		return ErrMustSpecifyTokenOrSlot{}
	}
	if tokenID != "" && slot >= 0 {
		return ErrCannotSpecifyBothTokenAndSlot{}
	}
	return nil
}

// ValidateEnrollInput validates input for the enroll command
func ValidateEnrollInput(passphrase string) error {
	if passphrase == "" {
		return ErrPassphraseRequired{}
	}
	return nil
}

// =============================================================================
// Token Processing Functions (Pure, Testable)
// =============================================================================

// FindFIDO2Tokens finds all FIDO2 tokens in LUKS metadata
func FindFIDO2Tokens(metadata *luks2.LUKS2Metadata) map[string]*FIDO2TokenInfo {
	fido2Tokens := make(map[string]*FIDO2TokenInfo)
	if metadata.Tokens == nil {
		return fido2Tokens
	}
	for tokenID, token := range metadata.Tokens {
		if token.Type == "fido2-manual" {
			tokenInfo := parseFIDO2Token(token)
			fido2Tokens[tokenID] = tokenInfo
		}
	}
	return fido2Tokens
}

// FindTokenByKeyslot finds the token ID that references a given keyslot
func FindTokenByKeyslot(metadata *luks2.LUKS2Metadata, keyslot int) string {
	if metadata.Tokens == nil {
		return ""
	}
	keyslotStr := intToStr(keyslot)
	for tokenID, token := range metadata.Tokens {
		if token.Type == "fido2-manual" {
			for _, ks := range token.Keyslots {
				if ks == keyslotStr {
					return tokenID
				}
			}
		}
	}
	return ""
}

// ValidateTokenForRemoval validates that a token exists and is a FIDO2 token
func ValidateTokenForRemoval(metadata *luks2.LUKS2Metadata, tokenID string) (*luks2.Token, error) {
	if metadata.Tokens == nil {
		return nil, ErrNoFIDO2Tokens{Device: ""}
	}
	token, exists := metadata.Tokens[tokenID]
	if !exists {
		return nil, ErrTokenNotFound{TokenID: tokenID}
	}
	if token.Type != "fido2-manual" {
		return nil, ErrTokenNotFIDO2{TokenID: tokenID, TokenType: token.Type}
	}
	return token, nil
}

// GetFirstKeyslotFromToken extracts the first keyslot number from a token
func GetFirstKeyslotFromToken(token *luks2.Token, tokenID string) (int, error) {
	if len(token.Keyslots) == 0 {
		return 0, ErrTokenNoKeyslots{TokenID: tokenID}
	}
	keyslotNum, err := strToInt(token.Keyslots[0])
	if err != nil {
		return 0, ErrInvalidKeyslotID{KeyslotID: token.Keyslots[0]}
	}
	return keyslotNum, nil
}

// ValidateKeyslotExists checks if a keyslot exists in the metadata
func ValidateKeyslotExists(metadata *luks2.LUKS2Metadata, keyslot int) error {
	slotIDStr := intToStr(keyslot)
	if _, exists := metadata.Keyslots[slotIDStr]; !exists {
		return ErrKeyslotNotFound{Keyslot: keyslot}
	}
	return nil
}

// TruncateString truncates a string to the specified maximum length
func TruncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// =============================================================================
// Helper functions
// =============================================================================

func intToStr(i int) string {
	return string(rune('0' + i))
}

func strToInt(s string) (int, error) {
	if len(s) == 0 {
		return 0, ErrInvalidKeyslotID{KeyslotID: s}
	}
	var result int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, ErrInvalidKeyslotID{KeyslotID: s}
		}
		result = result*10 + int(c-'0')
	}
	return result, nil
}
