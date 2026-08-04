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

//go:build integration

package secureboot

import "fmt"

// ErrMissingTool indicates a required host tool is not installed in the
// devcontainer. The suite never skips: a missing tool is a broken test
// environment and fails loudly.
type ErrMissingTool struct {
	Tool    string
	Purpose string
}

// Error implements the error interface.
func (e ErrMissingTool) Error() string {
	return fmt.Sprintf("secureboot integration: required tool %q not found (%s) — install it in the devcontainer image", e.Tool, e.Purpose)
}

// ErrMissingArtifact indicates a required prebuilt artifact env var is unset
// or points at a missing file. The FIPS kernel takes hours to build and is
// produced out-of-band (build/docker/fips-kernel-builder); the dedicated
// integration target consumes it via env vars and fails with this error when
// they are absent.
type ErrMissingArtifact struct {
	EnvVar  string
	Purpose string
}

// Error implements the error interface.
func (e ErrMissingArtifact) Error() string {
	return fmt.Sprintf("secureboot integration: %s is not set or does not exist (%s). "+
		"Build the FIPS kernel first: make -C build/docker/fips-kernel-builder module-key && "+
		"make -C build/docker/fips-kernel-builder build MODULE_SIGNING_KEY=~/.trusted-platform/secure-boot/module-signing-key.pem, "+
		"then export FIPS_KERNEL_IMAGE, FIPS_MODULES_TAR and FIPS_MODULE_SIGNING_KEY before running make integration-test-secureboot",
		e.EnvVar, e.Purpose)
}

// ErrFirmwareNotFound indicates no Secure Boot capable OVMF firmware image was
// found at any known location.
type ErrFirmwareNotFound struct {
	Searched []string
}

// Error implements the error interface.
func (e ErrFirmwareNotFound) Error() string {
	return fmt.Sprintf("secureboot integration: no Secure Boot OVMF firmware found (searched %v) — install the ovmf package in the devcontainer", e.Searched)
}

// ErrSerialTimeout indicates none of the awaited serial markers appeared
// before the deadline.
type ErrSerialTimeout struct {
	Markers []string
	Output  string
}

// Error implements the error interface.
func (e ErrSerialTimeout) Error() string {
	return fmt.Sprintf("secureboot integration: timed out waiting for serial markers %v; captured output:\n%s", e.Markers, e.Output)
}

// ErrNoLoadableModule indicates no zero-dependency kernel module from the
// FIPS modules tarball could be identified for the insmod cycle.
type ErrNoLoadableModule struct {
	Reason string
}

// Error implements the error interface.
func (e ErrNoLoadableModule) Error() string {
	return "secureboot integration: no candidate kernel module for the insmod cycle: " + e.Reason
}

// ErrCommandFailed wraps a host tool invocation failure with its output.
type ErrCommandFailed struct {
	Command string
	Output  string
	Err     error
}

// Error implements the error interface.
func (e ErrCommandFailed) Error() string {
	return fmt.Sprintf("secureboot integration: %s failed: %v\n%s", e.Command, e.Err, e.Output)
}

// Unwrap returns the underlying cause.
func (e ErrCommandFailed) Unwrap() error { return e.Err }
