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

package attestation

import "fmt"

// ErrGetManifestFailed is returned when manifest retrieval fails.
type ErrGetManifestFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetManifestFailed) Error() string {
	return fmt.Sprintf("failed to get manifest %s: %v", e.ID, e.Cause)
}

func (e *ErrGetManifestFailed) Unwrap() error {
	return e.Cause
}

// ErrBuildManifestFailed is returned when building a manifest fails.
type ErrBuildManifestFailed struct {
	Cause error
}

func (e *ErrBuildManifestFailed) Error() string {
	return fmt.Sprintf("failed to build manifest: %v", e.Cause)
}

func (e *ErrBuildManifestFailed) Unwrap() error {
	return e.Cause
}

// ErrVerifyManifestFailed is returned when manifest verification fails.
type ErrVerifyManifestFailed struct {
	Cause error
}

func (e *ErrVerifyManifestFailed) Error() string {
	return fmt.Sprintf("failed to verify manifest: %v", e.Cause)
}

func (e *ErrVerifyManifestFailed) Unwrap() error {
	return e.Cause
}

// ErrListManifestsFailed is returned when listing manifests fails.
type ErrListManifestsFailed struct {
	Cause error
}

func (e *ErrListManifestsFailed) Error() string {
	return fmt.Sprintf("failed to list manifests: %v", e.Cause)
}

func (e *ErrListManifestsFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteManifestFailed is returned when manifest deletion fails.
type ErrDeleteManifestFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteManifestFailed) Error() string {
	return fmt.Sprintf("failed to delete manifest %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteManifestFailed) Unwrap() error {
	return e.Cause
}

// ErrGetQuoteFailed is returned when getting attestation quote fails.
type ErrGetQuoteFailed struct {
	Cause error
}

func (e *ErrGetQuoteFailed) Error() string {
	return fmt.Sprintf("failed to get attestation quote: %v", e.Cause)
}

func (e *ErrGetQuoteFailed) Unwrap() error {
	return e.Cause
}

// ErrVerifyQuoteFailed is returned when verifying attestation quote fails.
type ErrVerifyQuoteFailed struct {
	Cause error
}

func (e *ErrVerifyQuoteFailed) Error() string {
	return fmt.Sprintf("failed to verify attestation quote: %v", e.Cause)
}

func (e *ErrVerifyQuoteFailed) Unwrap() error {
	return e.Cause
}

// ErrCollectHostAttestationFailed is returned when collecting host attestation fails.
type ErrCollectHostAttestationFailed struct {
	Cause error
}

func (e *ErrCollectHostAttestationFailed) Error() string {
	return fmt.Sprintf("failed to collect host attestation: %v", e.Cause)
}

func (e *ErrCollectHostAttestationFailed) Unwrap() error {
	return e.Cause
}

// ErrCollectVMAttestationFailed is returned when collecting VM attestation fails.
type ErrCollectVMAttestationFailed struct {
	VMID  string
	Cause error
}

func (e *ErrCollectVMAttestationFailed) Error() string {
	return fmt.Sprintf("failed to collect VM attestation for %s: %v", e.VMID, e.Cause)
}

func (e *ErrCollectVMAttestationFailed) Unwrap() error {
	return e.Cause
}

// ErrCollectContainerAttestationFailed is returned when collecting container attestation fails.
type ErrCollectContainerAttestationFailed struct {
	ContainerID string
	Cause       error
}

func (e *ErrCollectContainerAttestationFailed) Error() string {
	return fmt.Sprintf("failed to collect container attestation for %s: %v", e.ContainerID, e.Cause)
}

func (e *ErrCollectContainerAttestationFailed) Unwrap() error {
	return e.Cause
}
