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

import (
	"fmt"
	"time"
)

// ErrInvalidArchitecture is returned when an invalid architecture is specified.
type ErrInvalidArchitecture struct {
	Architecture string
	Valid        []string
}

func (e ErrInvalidArchitecture) Error() string {
	return fmt.Sprintf("invalid architecture '%s': valid options are %v", e.Architecture, e.Valid)
}

// ErrInvalidPlatformType is returned when an invalid platform type is specified.
type ErrInvalidPlatformType struct {
	PlatformType string
	Valid        []string
}

func (e ErrInvalidPlatformType) Error() string {
	return fmt.Sprintf("invalid platform type '%s': valid options are %v", e.PlatformType, e.Valid)
}

// ErrISONotFound is returned when an ISO file is not found.
type ErrISONotFound struct {
	Path string
}

func (e ErrISONotFound) Error() string {
	return fmt.Sprintf("ISO file not found: %s", e.Path)
}

// ErrVMTimeout is returned when a test VM is still running when the
// test's --timeout expires: the guest never powered off, so QEMU was
// killed and the software TPM stopped.
type ErrVMTimeout struct {
	Timeout time.Duration
}

func (e ErrVMTimeout) Error() string {
	return fmt.Sprintf("the VM did not power off within --timeout %s; QEMU and the software TPM were stopped", e.Timeout)
}

// ErrInstallDiskNotWritten is returned when the install guest powered off
// but left its disk at MinSize bytes or less. The autoinstaller powers off
// after a failed install too, so a clean exit alone is not an install.
type ErrInstallDiskNotWritten struct {
	Disk    string
	Size    int64
	MinSize int64
}

func (e ErrInstallDiskNotWritten) Error() string {
	return fmt.Sprintf("the install guest powered off but %s holds %d bytes (an install writes over %d): the install failed; the installer console says why",
		e.Disk, e.Size, e.MinSize)
}

// ErrBootTimeout is returned when `iso test boot` (or `firstboot`) is still
// running when its --timeout expires. ConsoleTail holds the last lines of
// the guest serial console log, so the failure shows where the boot stopped.
// It unwraps to ErrVMTimeout.
type ErrBootTimeout struct {
	Timeout     time.Duration
	Elapsed     time.Duration
	ConsoleLog  string
	ConsoleTail string
}

func (e ErrBootTimeout) Error() string {
	return fmt.Sprintf("the guest did not power off within --timeout %s (ran %s); %s",
		e.Timeout, e.Elapsed.Round(time.Second), consoleReport(e.ConsoleLog, e.ConsoleTail))
}

func (e ErrBootTimeout) Unwrap() error {
	return ErrVMTimeout{Timeout: e.Timeout}
}

// ErrBootFailed is returned when QEMU fails during `iso test boot` (or
// `firstboot`). Like ErrBootTimeout it carries the console tail.
type ErrBootFailed struct {
	Err         error
	ConsoleLog  string
	ConsoleTail string
}

func (e *ErrBootFailed) Error() string {
	return fmt.Sprintf("QEMU boot failed: %v; %s", e.Err, consoleReport(e.ConsoleLog, e.ConsoleTail))
}

func (e *ErrBootFailed) Unwrap() error {
	return e.Err
}

// consoleReport describes what a boot error knows about the guest console.
func consoleReport(consoleLog, tail string) string {
	switch {
	case consoleLog == "":
		return "the guest console was on the terminal"
	case tail == "":
		return fmt.Sprintf("the console log %s is missing or empty: the guest wrote nothing to its serial port", consoleLog)
	default:
		return fmt.Sprintf("last console lines from %s:\n%s", consoleLog, tail)
	}
}

// ErrDirectoryNotFound is returned when a directory is not found.
type ErrDirectoryNotFound struct {
	Path string
}

func (e ErrDirectoryNotFound) Error() string {
	return fmt.Sprintf("directory not found: %s", e.Path)
}

// ErrDirectoryAlreadyExists is returned when a directory already exists.
type ErrDirectoryAlreadyExists struct {
	Path string
}

func (e ErrDirectoryAlreadyExists) Error() string {
	return fmt.Sprintf("directory already exists: %s (use --force to overwrite)", e.Path)
}

// ErrDownloadFailed is returned when ISO download fails.
type ErrDownloadFailed struct {
	Reason string
}

func (e ErrDownloadFailed) Error() string {
	return fmt.Sprintf("failed to download ISO: %s", e.Reason)
}

// ErrExtractionFailed is returned when ISO extraction fails.
type ErrExtractionFailed struct {
	Reason string
}

func (e ErrExtractionFailed) Error() string {
	return fmt.Sprintf("failed to extract ISO: %s", e.Reason)
}

// ErrCustomizationFailed is returned when ISO customization fails.
type ErrCustomizationFailed struct {
	Reason string
}

func (e ErrCustomizationFailed) Error() string {
	return fmt.Sprintf("failed to customize ISO: %s", e.Reason)
}

// ErrBuildFailed is returned when ISO build fails.
type ErrBuildFailed struct {
	Reason string
}

func (e ErrBuildFailed) Error() string {
	return fmt.Sprintf("failed to build ISO: %s", e.Reason)
}

// ErrConfigValidationFailed is returned when configuration validation fails.
type ErrConfigValidationFailed struct {
	Reason string
}

func (e ErrConfigValidationFailed) Error() string {
	return fmt.Sprintf("configuration validation failed: %s", e.Reason)
}

// ErrProfileNotFound is returned when an installation profile is not found.
type ErrProfileNotFound struct {
	ProfileName string
}

func (e ErrProfileNotFound) Error() string {
	return fmt.Sprintf("profile not found: %s", e.ProfileName)
}

// ErrConfigParseError is returned when configuration parsing fails.
type ErrConfigParseError struct {
	Path   string
	Reason string
}

func (e ErrConfigParseError) Error() string {
	return fmt.Sprintf("failed to parse config file '%s': %s", e.Path, e.Reason)
}

// ErrVolumeLabelTooLong is returned when volume label exceeds maximum length.
type ErrVolumeLabelTooLong struct {
	Label     string
	MaxLength int
}

func (e ErrVolumeLabelTooLong) Error() string {
	return fmt.Sprintf("volume label '%s' exceeds maximum length of %d characters", e.Label, e.MaxLength)
}

// ErrBootstrapClientCreate is returned when the bootstrap client cannot be created.
type ErrBootstrapClientCreate struct {
	Reason string
}

func (e ErrBootstrapClientCreate) Error() string {
	return fmt.Sprintf("iso: failed to create bootstrap client: %s", e.Reason)
}

// ErrCABundleFetch is returned when fetching the CA certificate bundle fails.
type ErrCABundleFetch struct {
	Reason string
}

func (e ErrCABundleFetch) Error() string {
	return fmt.Sprintf("iso: failed to fetch CA bundle: %s", e.Reason)
}

// ErrCABundleEmpty is returned when the fetched CA bundle contains no data.
type ErrCABundleEmpty struct{}

func (e ErrCABundleEmpty) Error() string {
	return "iso: CA bundle response is empty"
}

// ErrCABundleWrite is returned when writing the CA bundle to disk fails.
type ErrCABundleWrite struct {
	Path   string
	Reason string
}

func (e ErrCABundleWrite) Error() string {
	return fmt.Sprintf("iso: failed to write CA bundle to %s: %s", e.Path, e.Reason)
}

// ErrPlatformConfigRead is returned when a platform config file cannot be read.
type ErrPlatformConfigRead struct {
	Path   string
	Reason string
}

func (e ErrPlatformConfigRead) Error() string {
	return fmt.Sprintf("iso: failed to read platform config %s: %s", e.Path, e.Reason)
}

// ErrPlatformConfigUnmarshal is returned when a platform config file cannot be parsed.
type ErrPlatformConfigUnmarshal struct {
	Path   string
	Reason string
}

func (e ErrPlatformConfigUnmarshal) Error() string {
	return fmt.Sprintf("iso: failed to unmarshal platform config %s: %s", e.Path, e.Reason)
}

// ErrPlatformConfigMarshal is returned when a platform config cannot be serialized.
type ErrPlatformConfigMarshal struct {
	Reason string
}

func (e ErrPlatformConfigMarshal) Error() string {
	return fmt.Sprintf("iso: failed to marshal platform config: %s", e.Reason)
}

// ErrPlatformConfigWrite is returned when a platform config file cannot be written.
type ErrPlatformConfigWrite struct {
	Path   string
	Reason string
}

func (e ErrPlatformConfigWrite) Error() string {
	return fmt.Sprintf("iso: failed to write platform config to %s: %s", e.Path, e.Reason)
}

// ErrNetworkConfigRequired is returned when a network config is required but nil.
type ErrNetworkConfigRequired struct {
	PlatformType string
}

func (e ErrNetworkConfigRequired) Error() string {
	return fmt.Sprintf("iso: network config is required for %s platform type", e.PlatformType)
}

// ErrUnsupportedPlatformType is returned when an unsupported platform type is specified
// for network override construction.
type ErrUnsupportedPlatformType struct {
	PlatformType string
}

func (e ErrUnsupportedPlatformType) Error() string {
	return fmt.Sprintf("iso: unsupported platform type: %s", e.PlatformType)
}

// ErrOverridesWithoutTemplate is returned when --overrides is specified without --platform-config.
type ErrOverridesWithoutTemplate struct{}

func (e ErrOverridesWithoutTemplate) Error() string {
	return "iso: --overrides requires --platform-config to specify the base template"
}

// ErrOverridesMergeFailed is returned when merging override config onto the base template fails.
type ErrOverridesMergeFailed struct {
	Reason string
}

func (e ErrOverridesMergeFailed) Error() string {
	return fmt.Sprintf("iso: failed to merge overrides onto template: %s", e.Reason)
}

// ErrOverridesTempFile is returned when creating a temporary file for merged config fails.
type ErrOverridesTempFile struct {
	Reason string
}

func (e ErrOverridesTempFile) Error() string {
	return fmt.Sprintf("iso: failed to create temp file for merged config: %s", e.Reason)
}

// ErrOverridesTempFileWrite is returned when writing merged config to a temporary file fails.
type ErrOverridesTempFileWrite struct {
	Path   string
	Reason string
}

func (e ErrOverridesTempFileWrite) Error() string {
	return fmt.Sprintf("iso: failed to write merged config to %s: %s", e.Path, e.Reason)
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

// PXEServerQEMUError reports a PXE server failure that occurred alongside a
// QEMU boot failure, exposing both causes to errors.Is / errors.As.
type PXEServerQEMUError struct {
	PXEErr  error
	QEMUErr error
}

// Error implements the error interface.
func (e *PXEServerQEMUError) Error() string {
	return "PXE server error: " + e.PXEErr.Error() + " (QEMU error: " + e.QEMUErr.Error() + ")"
}

// Unwrap returns both causes for errors.Is / errors.As.
func (e *PXEServerQEMUError) Unwrap() []error {
	return []error{e.PXEErr, e.QEMUErr}
}
