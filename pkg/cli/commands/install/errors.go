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

package install

import "fmt"

// ErrDaemonConnectionRequired is returned when a command requires daemon connection
// but dual-mode is not yet implemented
type ErrDaemonConnectionRequired struct {
	Command string
}

func (e ErrDaemonConnectionRequired) Error() string {
	return fmt.Sprintf("%s: daemon connection required (dual-mode not yet implemented)", e.Command)
}

// ErrConfigLoadFailed is returned when configuration loading fails
type ErrConfigLoadFailed struct {
	Path string
	Err  error
}

func (e ErrConfigLoadFailed) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("failed to load configuration from %s: %v", e.Path, e.Err)
	}
	return fmt.Sprintf("failed to load configuration: %v", e.Err)
}

// ErrConfigValidationFailed is returned when configuration validation fails
type ErrConfigValidationFailed struct {
	Err error
}

func (e ErrConfigValidationFailed) Error() string {
	return fmt.Sprintf("invalid configuration: %v", e.Err)
}

// ErrPasswordRequired is returned when password is required but not provided
type ErrPasswordRequired struct{}

func (e ErrPasswordRequired) Error() string {
	return "password is required in automated mode"
}

// ErrInstallerCreationFailed is returned when installer creation fails
type ErrInstallerCreationFailed struct {
	Err error
}

func (e ErrInstallerCreationFailed) Error() string {
	return fmt.Sprintf("failed to create installer: %v", e.Err)
}

// ErrInstallationFailed is returned when system installation fails
type ErrInstallationFailed struct {
	Err error
}

func (e ErrInstallationFailed) Error() string {
	return fmt.Sprintf("installation failed: %v", e.Err)
}

// ErrKernelOpenFailed is returned when kernel file cannot be opened
type ErrKernelOpenFailed struct {
	Path string
	Err  error
}

func (e ErrKernelOpenFailed) Error() string {
	return fmt.Sprintf("failed to open kernel %s: %v", e.Path, e.Err)
}

// ErrInitramfsOpenFailed is returned when initramfs file cannot be opened
type ErrInitramfsOpenFailed struct {
	Path string
	Err  error
}

func (e ErrInitramfsOpenFailed) Error() string {
	return fmt.Sprintf("failed to open initramfs %s: %v", e.Path, e.Err)
}

// ErrOSReleaseReadFailed is returned when os-release file cannot be read
type ErrOSReleaseReadFailed struct {
	Path string
	Err  error
}

func (e ErrOSReleaseReadFailed) Error() string {
	return fmt.Sprintf("failed to read os-release %s: %v", e.Path, e.Err)
}

// ErrStubOpenFailed is returned when EFI stub file cannot be opened
type ErrStubOpenFailed struct {
	Path string
	Err  error
}

func (e ErrStubOpenFailed) Error() string {
	return fmt.Sprintf("failed to open EFI stub %s: %v", e.Path, e.Err)
}

// ErrUKIBuildFailed is returned when UKI build fails
type ErrUKIBuildFailed struct {
	Err error
}

func (e ErrUKIBuildFailed) Error() string {
	return fmt.Sprintf("failed to build UKI: %v", e.Err)
}
