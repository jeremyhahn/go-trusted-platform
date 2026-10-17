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

package registry

import "fmt"

// ErrRegistryClientNotInitialized is returned when the registry client is not initialized
type ErrRegistryClientNotInitialized struct{}

func (e ErrRegistryClientNotInitialized) Error() string {
	return "registry client not initialized"
}

// ErrPushFailed is returned when an image push operation fails
type ErrPushFailed struct {
	Reference string
	Err       error
}

func (e ErrPushFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to push image %s: %v", e.Reference, e.Err)
	}
	return fmt.Sprintf("failed to push image %s", e.Reference)
}

func (e ErrPushFailed) Unwrap() error {
	return e.Err
}

// ErrPullFailed is returned when an image pull operation fails
type ErrPullFailed struct {
	Reference string
	Err       error
}

func (e ErrPullFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to pull image %s: %v", e.Reference, e.Err)
	}
	return fmt.Sprintf("failed to pull image %s", e.Reference)
}

func (e ErrPullFailed) Unwrap() error {
	return e.Err
}

// ErrImageNotSigned is returned when pull --verify meets an image whose
// manifest carries no signature.
type ErrImageNotSigned struct {
	Reference string
}

func (e ErrImageNotSigned) Error() string {
	return fmt.Sprintf("image %s is not signed; --verify refuses it", e.Reference)
}

// ErrDeleteFailed is returned when an image delete operation fails
type ErrDeleteFailed struct {
	Reference string
	Err       error
}

func (e ErrDeleteFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to delete image %s: %v", e.Reference, e.Err)
	}
	return fmt.Sprintf("failed to delete image %s", e.Reference)
}

func (e ErrDeleteFailed) Unwrap() error {
	return e.Err
}

// ErrListFailed is returned when listing images fails
type ErrListFailed struct {
	Err error
}

func (e ErrListFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to list images: %v", e.Err)
	}
	return "failed to list images"
}

func (e ErrListFailed) Unwrap() error {
	return e.Err
}

// ErrInspectFailed is returned when inspecting an image fails
type ErrInspectFailed struct {
	Reference string
	Err       error
}

func (e ErrInspectFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to inspect image %s: %v", e.Reference, e.Err)
	}
	return fmt.Sprintf("failed to inspect image %s", e.Reference)
}

func (e ErrInspectFailed) Unwrap() error {
	return e.Err
}

// ErrStatusFailed is returned when getting registry status fails
type ErrStatusFailed struct {
	Err error
}

func (e ErrStatusFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to get registry status: %v", e.Err)
	}
	return "failed to get registry status"
}

func (e ErrStatusFailed) Unwrap() error {
	return e.Err
}

// ErrAttestationFailed is returned when TPM attestation fails
type ErrAttestationFailed struct {
	Reason string
	Err    error
}

func (e ErrAttestationFailed) Error() string {
	if e.Reason != "" && e.Err != nil {
		return fmt.Sprintf("attestation failed: %s: %v", e.Reason, e.Err)
	}
	if e.Err != nil {
		return fmt.Sprintf("attestation failed: %v", e.Err)
	}
	if e.Reason != "" {
		return fmt.Sprintf("attestation failed: %s", e.Reason)
	}
	return "attestation failed"
}

func (e ErrAttestationFailed) Unwrap() error {
	return e.Err
}

// ErrEncryptionKeyRequired is returned when encryption is requested but no key ID is provided
type ErrEncryptionKeyRequired struct{}

func (e ErrEncryptionKeyRequired) Error() string {
	return "encryption key ID is required when --encrypt is specified"
}

// ErrInvalidImageReference is returned when an image reference is invalid
type ErrInvalidImageReference struct {
	Reference string
	Reason    string
}

func (e ErrInvalidImageReference) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid image reference %q: %s", e.Reference, e.Reason)
	}
	return fmt.Sprintf("invalid image reference: %q", e.Reference)
}

// ErrInvalidFormat is returned when an invalid output format is specified
type ErrInvalidFormat struct {
	Format string
}

func (e ErrInvalidFormat) Error() string {
	return fmt.Sprintf("invalid format: %s (valid: json, yaml, table)", e.Format)
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
