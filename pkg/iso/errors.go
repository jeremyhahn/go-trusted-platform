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

// ErrModloopNotFound is returned when the modloop squashfs cannot be located in
// the ISO root while injecting NIC kernel drivers into the initramfs.
func ErrModloopNotFound(path string, cause error) error {
	return &ISOError{
		Type:    ErrorTypeCustomize,
		Message: fmt.Sprintf("modloop squashfs not found: %s", path),
		Cause:   cause,
	}
}

// ErrInitramfsModulesDir is returned when the initramfs lib/modules directory
// cannot be read while determining the target kernel version.
func ErrInitramfsModulesDir(path string, cause error) error {
	return &ISOError{
		Type:    ErrorTypeCustomize,
		Message: fmt.Sprintf("failed to read initramfs modules directory: %s", path),
		Cause:   cause,
	}
}

// ErrKernelVersionAmbiguous is returned when the initramfs lib/modules
// directory does not contain exactly one kernel version directory, so the
// target kernel version cannot be determined unambiguously.
func ErrKernelVersionAmbiguous(path string, count int) error {
	return &ISOError{
		Type:    ErrorTypeCustomize,
		Message: fmt.Sprintf("expected exactly one kernel version directory in %s, found %d", path, count),
	}
}

// ErrModloopExtractDir is returned when the temporary extraction directory for
// the modloop squashfs cannot be created.
func ErrModloopExtractDir(cause error) error {
	return &ISOError{
		Type:    ErrorTypeCustomize,
		Message: "failed to create modloop extraction directory",
		Cause:   cause,
	}
}

// ErrModloopUnsquash is returned when unsquashfs fails to extract the modloop
// squashfs.
func ErrModloopUnsquash(path string, cause error, output string) error {
	return &ISOError{
		Type:    ErrorTypeCustomize,
		Message: fmt.Sprintf("failed to unsquashfs modloop %s: %s", path, output),
		Cause:   cause,
	}
}

// ErrModloopKernelMismatch is returned when the modloop squashfs does not
// contain a modules directory for the initramfs kernel version.
func ErrModloopKernelMismatch(kver string, cause error) error {
	return &ISOError{
		Type:    ErrorTypeCustomize,
		Message: fmt.Sprintf("modloop missing modules for kernel version %s", kver),
		Cause:   cause,
	}
}

// ErrModulesDepRead is returned when the modloop modules.dep file cannot be
// read for dependency resolution.
func ErrModulesDepRead(path string, cause error) error {
	return &ISOError{
		Type:    ErrorTypeCustomize,
		Message: fmt.Sprintf("failed to read modules.dep: %s", path),
		Cause:   cause,
	}
}

// ErrModuleDepResolve is returned when the NIC driver dependency closure cannot
// be resolved from the parsed modules.dep contents.
func ErrModuleDepResolve(cause error) error {
	return &ISOError{
		Type:    ErrorTypeCustomize,
		Message: "failed to resolve kernel module dependencies",
		Cause:   cause,
	}
}

// ErrModuleCopy is returned when a resolved kernel module cannot be copied from
// the modloop into the initramfs.
func ErrModuleCopy(relPath string, cause error) error {
	return &ISOError{
		Type:    ErrorTypeCustomize,
		Message: fmt.Sprintf("failed to copy kernel module: %s", relPath),
		Cause:   cause,
	}
}

// ErrDepmod is returned when depmod fails to regenerate the initramfs module
// dependency metadata after injecting NIC drivers.
func ErrDepmod(kver string, cause error, output string) error {
	return &ISOError{
		Type:    ErrorTypeCustomize,
		Message: fmt.Sprintf("depmod failed for kernel version %s: %s", kver, output),
		Cause:   cause,
	}
}

// ErrBootCriticalBinaryMissing is returned when a binary the booted artifact
// cannot function without is absent from the build tree.
//
// It exists because the absence used to be DETECTED and then reported as
// success: CopyPlatformInitrdBinary stat'd the path, logged a warning, and
// returned nil, so `iso create` exited 0 and shipped a 792 MB ISO whose
// autoinstall died at the platform-initrd step (#48). Absence of a
// boot-critical input must fail the build, not degrade it.
func ErrBootCriticalBinaryMissing(name, path, remedy string) error {
	return &ISOError{
		Type: ErrorTypeCustomize,
		Message: fmt.Sprintf(
			"%s is required to boot the artifact this command produces, and was not found at %s — %s",
			name, path, remedy),
	}
}

// ErrBootloaderUpdateFailed is returned when the EFI bootloader could not be
// updated for the ISO's volume label.
//
// The previous handling warned "UEFI boot may fail" and continued, which
// predicts the failure it is about to cause rather than preventing it (#48).
func ErrBootloaderUpdateFailed(cause error) error {
	return &ISOError{
		Type:    ErrorTypeCustomize,
		Message: "failed to update the EFI bootloader for this ISO's volume label; the artifact would not boot under UEFI",
		Cause:   cause,
	}
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
// or a remediation hint appended after the underlying cause.
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
