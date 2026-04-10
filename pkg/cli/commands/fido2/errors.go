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

import "fmt"

// ErrRootRequired is returned when a command requires root privileges
type ErrRootRequired struct{}

func (e ErrRootRequired) Error() string {
	return "this command must be run as root"
}

// ErrDeviceNotSpecified is returned when no LUKS device is specified
type ErrDeviceNotSpecified struct{}

func (e ErrDeviceNotSpecified) Error() string {
	return "LUKS device not specified"
}

// ErrDeviceAutoDetectFailed is returned when LUKS device auto-detection fails
type ErrDeviceAutoDetectFailed struct{}

func (e ErrDeviceAutoDetectFailed) Error() string {
	return "could not auto-detect LUKS device; please specify with --device"
}

// ErrPassphraseRequired is returned when LUKS passphrase is required but not provided
type ErrPassphraseRequired struct{}

func (e ErrPassphraseRequired) Error() string {
	return "LUKS passphrase is required (--passphrase)"
}

// ErrEnrollmentFailed is returned when FIDO2 enrollment fails
type ErrEnrollmentFailed struct {
	Reason string
}

func (e ErrEnrollmentFailed) Error() string {
	return fmt.Sprintf("enrollment failed: %s", e.Reason)
}

// ErrCreateEnrollmentHandler is returned when creating the enrollment handler fails
type ErrCreateEnrollmentHandler struct {
	Reason string
}

func (e ErrCreateEnrollmentHandler) Error() string {
	return fmt.Sprintf("failed to create enrollment handler: %s", e.Reason)
}

// ErrReadLUKSHeader is returned when reading LUKS header fails
type ErrReadLUKSHeader struct {
	Reason string
}

func (e ErrReadLUKSHeader) Error() string {
	return fmt.Sprintf("failed to read LUKS header: %s", e.Reason)
}

// ErrGetVolumeInfo is returned when getting volume info fails
type ErrGetVolumeInfo struct {
	Reason string
}

func (e ErrGetVolumeInfo) Error() string {
	return fmt.Sprintf("failed to get volume info: %s", e.Reason)
}

// ErrNoFIDO2Tokens is returned when no FIDO2 tokens are found
type ErrNoFIDO2Tokens struct {
	Device string
}

func (e ErrNoFIDO2Tokens) Error() string {
	return fmt.Sprintf("no FIDO2 tokens found on device %s", e.Device)
}

// ErrTokenNotFound is returned when a specified token does not exist
type ErrTokenNotFound struct {
	TokenID string
}

func (e ErrTokenNotFound) Error() string {
	return fmt.Sprintf("token %s does not exist", e.TokenID)
}

// ErrTokenNotFIDO2 is returned when a token is not a FIDO2 token
type ErrTokenNotFIDO2 struct {
	TokenID   string
	TokenType string
}

func (e ErrTokenNotFIDO2) Error() string {
	return fmt.Sprintf("token %s is not a FIDO2 token (type: %s)", e.TokenID, e.TokenType)
}

// ErrTokenNoKeyslots is returned when a token has no associated keyslots
type ErrTokenNoKeyslots struct {
	TokenID string
}

func (e ErrTokenNoKeyslots) Error() string {
	return fmt.Sprintf("token %s has no associated keyslots", e.TokenID)
}

// ErrInvalidKeyslotID is returned when a keyslot ID is invalid
type ErrInvalidKeyslotID struct {
	KeyslotID string
}

func (e ErrInvalidKeyslotID) Error() string {
	return fmt.Sprintf("invalid keyslot ID in token: %s", e.KeyslotID)
}

// ErrKeyslotNotFound is returned when a specified keyslot does not exist
type ErrKeyslotNotFound struct {
	Keyslot int
}

func (e ErrKeyslotNotFound) Error() string {
	return fmt.Sprintf("keyslot %d does not exist", e.Keyslot)
}

// ErrRemoveKeyslotFailed is returned when removing a keyslot fails
type ErrRemoveKeyslotFailed struct {
	Reason string
}

func (e ErrRemoveKeyslotFailed) Error() string {
	return fmt.Sprintf("failed to remove keyslot: %s", e.Reason)
}

// ErrRereadLUKSHeader is returned when re-reading LUKS header fails
type ErrRereadLUKSHeader struct {
	Reason string
}

func (e ErrRereadLUKSHeader) Error() string {
	return fmt.Sprintf("failed to re-read LUKS header: %s", e.Reason)
}

// ErrWriteLUKSHeader is returned when writing LUKS header fails
type ErrWriteLUKSHeader struct {
	Reason string
}

func (e ErrWriteLUKSHeader) Error() string {
	return fmt.Sprintf("failed to update LUKS metadata: %s", e.Reason)
}

// ErrReadConfirmation is returned when reading user confirmation fails
type ErrReadConfirmation struct {
	Reason string
}

func (e ErrReadConfirmation) Error() string {
	return fmt.Sprintf("failed to read confirmation: %s", e.Reason)
}

// ErrMustSpecifyTokenOrSlot is returned when neither token nor slot is specified
type ErrMustSpecifyTokenOrSlot struct{}

func (e ErrMustSpecifyTokenOrSlot) Error() string {
	return "must specify either --token or --slot"
}

// ErrCannotSpecifyBothTokenAndSlot is returned when both token and slot are specified
type ErrCannotSpecifyBothTokenAndSlot struct{}

func (e ErrCannotSpecifyBothTokenAndSlot) Error() string {
	return "cannot specify both --token and --slot"
}

// ErrGetTokenInfo is returned when getting FIDO2 token info fails
type ErrGetTokenInfo struct {
	Reason string
}

func (e ErrGetTokenInfo) Error() string {
	return fmt.Sprintf("failed to get FIDO2 token info: %s", e.Reason)
}

// ErrUnlockTestFailed is returned when FIDO2 unlock test fails
type ErrUnlockTestFailed struct {
	Reason string
}

func (e ErrUnlockTestFailed) Error() string {
	return fmt.Sprintf("unlock test failed: %s", e.Reason)
}
