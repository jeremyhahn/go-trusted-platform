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

package iso

import "fmt"

// ErrorType categorizes ISO builder errors
type ErrorType string

const (
	ErrorTypeConfig     ErrorType = "config"
	ErrorTypePlatform   ErrorType = "platform"
	ErrorTypeCustomize  ErrorType = "customize"
	ErrorTypeBuild      ErrorType = "build"
	ErrorTypeDownload   ErrorType = "download"
	ErrorTypeExtract    ErrorType = "extract"
	ErrorTypeSecureBoot ErrorType = "secure_boot"
)

// ISOError wraps errors with additional context
type ISOError struct {
	Type    ErrorType
	Message string
	Cause   error
}

func (e *ISOError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *ISOError) Unwrap() error {
	return e.Cause
}

// Error constructors

// ErrPlatformConfigRequired is returned when platform config path is not provided
func ErrPlatformConfigRequired() error {
	return &ISOError{
		Type:    ErrorTypePlatform,
		Message: "platform config path is required - use --platform-config flag to specify the platform configuration file",
	}
}

// ErrPlatformConfigNotFound is returned when the specified platform config file doesn't exist
func ErrPlatformConfigNotFound(path string) error {
	return &ISOError{
		Type:    ErrorTypePlatform,
		Message: fmt.Sprintf("platform config not found: %s", path),
	}
}

// ErrPlatformConfigRead is returned when platform config file cannot be read
func ErrPlatformConfigRead(path string, cause error) error {
	return &ISOError{
		Type:    ErrorTypePlatform,
		Message: fmt.Sprintf("failed to read platform config: %s", path),
		Cause:   cause,
	}
}

// ErrPlatformConfigMissingSealPCRs is returned when platform config doesn't contain seal-pcrs
func ErrPlatformConfigMissingSealPCRs(path string) error {
	return &ISOError{
		Type:    ErrorTypePlatform,
		Message: fmt.Sprintf("platform config missing required 'seal-pcrs' field: %s - config MUST have 'seal-pcrs: [7, 9]' at root level for TPM sealing", path),
	}
}

// ErrPlatformConfigWrite is returned when platform config cannot be written to ISO
func ErrPlatformConfigWrite(path string, cause error) error {
	return &ISOError{
		Type:    ErrorTypePlatform,
		Message: fmt.Sprintf("failed to write platform config to ISO: %s", path),
		Cause:   cause,
	}
}

// ErrConfigDirCreate is returned when configs directory cannot be created
func ErrConfigDirCreate(path string, cause error) error {
	return &ISOError{
		Type:    ErrorTypeCustomize,
		Message: fmt.Sprintf("failed to create configs directory: %s", path),
		Cause:   cause,
	}
}
