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
	ErrorTypeCompletion    ErrorType = "completion"
	ErrorTypeDiskRelease   ErrorType = "disk_release"
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

// ErrSecureBootConfig reports an invalid Secure Boot configuration field. It is
// returned by SecureBootConfig.Validate when a required URI is missing or a URI
// scheme is neither kms:// nor file://.
type ErrSecureBootConfig struct {
	Field  string
	Reason string
}

func (e *ErrSecureBootConfig) Error() string {
	return fmt.Sprintf("secure boot config: %s: %s", e.Field, e.Reason)
}

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}

// CommandOutputError wraps a failed external command with captured output
// appended after the underlying cause.
type CommandOutputError struct {
	Msg    string
	Err    error
	Detail string
}

// Error implements the error interface.
func (e *CommandOutputError) Error() string {
	return e.Msg + ": " + e.Err.Error() + e.Detail
}

// Unwrap returns the wrapped cause.
func (e *CommandOutputError) Unwrap() error {
	return e.Err
}

// ErrCompletion reports that the installation performed its work but could
// not prove the result is durable and bootable: the unified kernel image is
// absent or empty on the EFI partition, a flush the installer depends on was
// refused, or a filesystem could not be unmounted even lazily.
//
// It exists as its own type because it is the one class of installer failure
// whose symptom appears at the NEXT boot rather than during the install. The
// caller must treat it as fatal: pkg/cli/commands/install/system.go turns it
// into a non-zero exit, and the ISO's autoinstall wrapper reads that exit code
// and stops instead of rebooting into a machine that cannot boot.
func ErrCompletion(message string, cause error) error {
	return &InstallerError{
		Type:    ErrorTypeCompletion,
		Message: message,
		Cause:   cause,
	}
}

// ErrUnknownInstallTarget reports an install target that is neither disk nor
// image.
func ErrUnknownInstallTarget(name string) error {
	return &InstallerError{Type: ErrorTypeInvalidConfig, Message: "unknown install target " + name + " (disk, image)"}
}

// ErrUnknownBootFirmware reports a boot firmware that is neither uefi nor
// uboot.
func ErrUnknownBootFirmware(name string) error {
	return &InstallerError{Type: ErrorTypeInvalidConfig, Message: "unknown boot firmware " + name + " (uefi, uboot)"}
}

// ErrInvalidMappedName reports a disk.encryption.mapped-name that go-luks2's
// Unlock would refuse (luks2.ValidateMappingName). Validation catches it
// before the installer formats the disk, not at the unlock that follows.
func ErrInvalidMappedName(name string, cause error) error {
	return &InstallerError{Type: ErrorTypeInvalidConfig, Message: "invalid disk encryption mapped-name " + name, Cause: cause}
}

// ErrBootFirmwareStage reports a failure to lay the staged boot firmware
// onto the EFI partition.
func ErrBootFirmwareStage(message string, cause error) error {
	return &InstallerError{Type: ErrorTypeUKIBuild, Message: message, Cause: cause}
}

// ErrMediaKernel reports a failure installing a platform-built kernel from
// the install media (OSConfig.KernelArtifactsDir).
func ErrMediaKernel(message string, cause error) error {
	return &InstallerError{Type: ErrorTypeOSInstall, Message: "media kernel: " + message, Cause: cause}
}

// ErrDiskRelease reports a step of the post-failure disk release that did
// not complete (release.go). It is never the error Install returns — the
// install failure is — so it is logged, and it names the resource that is
// still open on the build host.
func ErrDiskRelease(message string, cause error) error {
	return &InstallerError{Type: ErrorTypeDiskRelease, Message: message, Cause: cause}
}
