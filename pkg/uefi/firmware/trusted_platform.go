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

package firmware

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

const (
	// TrustedPlatformVariableName is the name of the TRUSTED_PLATFORM EFI variable
	TrustedPlatformVariableName = "TRUSTED_PLATFORM"
)

var (
	// TrustedPlatformGUID is a custom vendor GUID for the TRUSTED_PLATFORM variable
	// Generated using: uuidgen
	// Format: 12345678-1234-1234-1234-123456789abc
	TrustedPlatformGUID = uefi.GUID{
		Data1: 0xF47DE8A7,
		Data2: 0x8E5B,
		Data3: 0x4F4A,
		Data4: [8]byte{0xA7, 0x3C, 0x6D, 0x8F, 0x2E, 0x1B, 0x9C, 0x54},
	}

	// ErrNotTrustedPlatform indicates the system is not a Trusted Platform
	ErrNotTrustedPlatform = errors.New("not a trusted platform")
)

// TrustedPlatformAttributes are the default attributes for the TRUSTED_PLATFORM variable
// NV (persists across reboots) + BS (boot services) + RT (runtime) access
const TrustedPlatformAttributes = uefi.AttrNonVolatile |
	uefi.AttrBootserviceAccess |
	uefi.AttrRuntimeAccess

// SetTrustedPlatform sets the TRUSTED_PLATFORM EFI variable to indicate
// this system has been provisioned by the Trusted Platform
func SetTrustedPlatform() error {
	// Value is simply "true" as a byte array
	data := []byte("true")

	return WriteVariable(
		TrustedPlatformVariableName,
		TrustedPlatformGUID,
		TrustedPlatformAttributes,
		data,
	)
}

// ClearTrustedPlatform removes the TRUSTED_PLATFORM EFI variable
func ClearTrustedPlatform() error {
	err := DeleteVariable(TrustedPlatformVariableName, TrustedPlatformGUID)
	if errors.Is(err, ErrVariableNotFound) {
		// Not an error if variable doesn't exist
		return nil
	}
	return err
}

// GetTrustedPlatform reads the TRUSTED_PLATFORM EFI variable and returns
// whether the system is marked as a Trusted Platform
func GetTrustedPlatform() (bool, error) {
	data, _, err := ReadVariable(TrustedPlatformVariableName, TrustedPlatformGUID)
	if err != nil {
		if errors.Is(err, ErrVariableNotFound) {
			return false, ErrNotTrustedPlatform
		}
		return false, err
	}

	// Check if value is "true"
	return string(data) == "true", nil
}

// IsTrustedPlatform is a convenience function that returns true if the
// TRUSTED_PLATFORM variable exists and is set to "true"
func IsTrustedPlatform() bool {
	result, err := GetTrustedPlatform()
	if err != nil {
		return false
	}
	return result
}
