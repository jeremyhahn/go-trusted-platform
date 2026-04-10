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

import "fmt"

// Error types
type ErrorType string

const (
	ErrorTypeInvalidConfig ErrorType = "invalid_config"
	ErrorTypeDiskOperation ErrorType = "disk_operation"
	ErrorTypeEncryption    ErrorType = "encryption"
	ErrorTypeOSInstall     ErrorType = "os_install"
	ErrorTypeUKIBuild      ErrorType = "uki_build"
	ErrorTypeSecureBoot    ErrorType = "secure_boot"
	ErrorTypeTPM           ErrorType = "tpm"
)

// InstallerError wraps errors with additional context
type InstallerError struct {
	Type    ErrorType
	Message string
	Cause   error
}

func (e *InstallerError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *InstallerError) Unwrap() error {
	return e.Cause
}

// Error constructors
func ErrInvalidConfig(message string) error {
	return &InstallerError{
		Type:    ErrorTypeInvalidConfig,
		Message: message,
	}
}

func ErrDiskOperation(message string, cause error) error {
	return &InstallerError{
		Type:    ErrorTypeDiskOperation,
		Message: message,
		Cause:   cause,
	}
}

func ErrEncryption(message string, cause error) error {
	return &InstallerError{
		Type:    ErrorTypeEncryption,
		Message: message,
		Cause:   cause,
	}
}

func ErrOSInstall(message string, cause error) error {
	return &InstallerError{
		Type:    ErrorTypeOSInstall,
		Message: message,
		Cause:   cause,
	}
}

func ErrUKIBuild(message string, cause error) error {
	return &InstallerError{
		Type:    ErrorTypeUKIBuild,
		Message: message,
		Cause:   cause,
	}
}

func ErrSecureBoot(message string, cause error) error {
	return &InstallerError{
		Type:    ErrorTypeSecureBoot,
		Message: message,
		Cause:   cause,
	}
}

func ErrTPM(message string, cause error) error {
	return &InstallerError{
		Type:    ErrorTypeTPM,
		Message: message,
		Cause:   cause,
	}
}
