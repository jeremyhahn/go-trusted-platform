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

package device

import "fmt"

// ErrCreateFailed is returned when device creation fails.
type ErrCreateFailed struct {
	Cause error
}

func (e *ErrCreateFailed) Error() string {
	return fmt.Sprintf("device creation failed: %v", e.Cause)
}

func (e *ErrCreateFailed) Unwrap() error {
	return e.Cause
}

// ErrGetFailed is returned when device retrieval fails.
type ErrGetFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrGetFailed) Error() string {
	return fmt.Sprintf("failed to get device %d: %v", e.ID, e.Cause)
}

func (e *ErrGetFailed) Unwrap() error {
	return e.Cause
}

// ErrUpdateFailed is returned when device update fails.
type ErrUpdateFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrUpdateFailed) Error() string {
	return fmt.Sprintf("failed to update device %d: %v", e.ID, e.Cause)
}

func (e *ErrUpdateFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteFailed is returned when device deletion fails.
type ErrDeleteFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrDeleteFailed) Error() string {
	return fmt.Sprintf("failed to delete device %d: %v", e.ID, e.Cause)
}

func (e *ErrDeleteFailed) Unwrap() error {
	return e.Cause
}

// ErrListFailed is returned when listing devices fails.
type ErrListFailed struct {
	Cause error
}

func (e *ErrListFailed) Error() string {
	return fmt.Sprintf("failed to list devices: %v", e.Cause)
}

func (e *ErrListFailed) Unwrap() error {
	return e.Cause
}

// ErrFindBySerialFailed is returned when finding device by serial fails.
type ErrFindBySerialFailed struct {
	Serial string
	Cause  error
}

func (e *ErrFindBySerialFailed) Error() string {
	return fmt.Sprintf("failed to find device by serial %s: %v", e.Serial, e.Cause)
}

func (e *ErrFindBySerialFailed) Unwrap() error {
	return e.Cause
}

// ErrCountFailed is returned when counting devices fails.
type ErrCountFailed struct {
	Cause error
}

func (e *ErrCountFailed) Error() string {
	return fmt.Sprintf("failed to count devices: %v", e.Cause)
}

func (e *ErrCountFailed) Unwrap() error {
	return e.Cause
}

// ErrActivateFailed is returned when device activation fails.
type ErrActivateFailed struct {
	Serial string
	Cause  error
}

func (e *ErrActivateFailed) Error() string {
	return fmt.Sprintf("failed to activate device %s: %v", e.Serial, e.Cause)
}

func (e *ErrActivateFailed) Unwrap() error {
	return e.Cause
}

// Profile-related errors

// ErrCreateProfileFailed is returned when profile creation fails.
type ErrCreateProfileFailed struct {
	Cause error
}

func (e *ErrCreateProfileFailed) Error() string {
	return fmt.Sprintf("profile creation failed: %v", e.Cause)
}

func (e *ErrCreateProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrGetProfileFailed is returned when profile retrieval fails.
type ErrGetProfileFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrGetProfileFailed) Error() string {
	return fmt.Sprintf("failed to get profile %d: %v", e.ID, e.Cause)
}

func (e *ErrGetProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrUpdateProfileFailed is returned when profile update fails.
type ErrUpdateProfileFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrUpdateProfileFailed) Error() string {
	return fmt.Sprintf("failed to update profile %d: %v", e.ID, e.Cause)
}

func (e *ErrUpdateProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteProfileFailed is returned when profile deletion fails.
type ErrDeleteProfileFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrDeleteProfileFailed) Error() string {
	return fmt.Sprintf("failed to delete profile %d: %v", e.ID, e.Cause)
}

func (e *ErrDeleteProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrListProfilesFailed is returned when listing profiles fails.
type ErrListProfilesFailed struct {
	Cause error
}

func (e *ErrListProfilesFailed) Error() string {
	return fmt.Sprintf("failed to list profiles: %v", e.Cause)
}

func (e *ErrListProfilesFailed) Unwrap() error {
	return e.Cause
}

// ErrFindProfileByMACFailed is returned when finding profile by MAC fails.
type ErrFindProfileByMACFailed struct {
	MACAddress string
	Cause      error
}

func (e *ErrFindProfileByMACFailed) Error() string {
	return fmt.Sprintf("failed to find profile by MAC %s: %v", e.MACAddress, e.Cause)
}

func (e *ErrFindProfileByMACFailed) Unwrap() error {
	return e.Cause
}

// ErrFindProfileBySerialFailed is returned when finding profile by serial fails.
type ErrFindProfileBySerialFailed struct {
	Serial string
	Cause  error
}

func (e *ErrFindProfileBySerialFailed) Error() string {
	return fmt.Sprintf("failed to find profile by serial %s: %v", e.Serial, e.Cause)
}

func (e *ErrFindProfileBySerialFailed) Unwrap() error {
	return e.Cause
}

// ErrFindMatchingProfileFailed is returned when finding matching profile fails.
type ErrFindMatchingProfileFailed struct {
	Cause error
}

func (e *ErrFindMatchingProfileFailed) Error() string {
	return fmt.Sprintf("failed to find matching profile: %v", e.Cause)
}

func (e *ErrFindMatchingProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrCountProfilesFailed is returned when counting profiles fails.
type ErrCountProfilesFailed struct {
	Cause error
}

func (e *ErrCountProfilesFailed) Error() string {
	return fmt.Sprintf("failed to count profiles: %v", e.Cause)
}

func (e *ErrCountProfilesFailed) Unwrap() error {
	return e.Cause
}

// ErrCreateTemplateFailed is returned when creating a device template fails.
type ErrCreateTemplateFailed struct {
	Cause error
}

func (e *ErrCreateTemplateFailed) Error() string {
	return fmt.Sprintf("failed to create device template: %v", e.Cause)
}

func (e *ErrCreateTemplateFailed) Unwrap() error {
	return e.Cause
}

// ErrCreateProfileFromTemplateFailed is returned when deriving a profile
// from a device template fails.
type ErrCreateProfileFromTemplateFailed struct {
	TemplateID uint64
	Cause      error
}

func (e *ErrCreateProfileFromTemplateFailed) Error() string {
	return fmt.Sprintf("failed to create profile from template %d: %v", e.TemplateID, e.Cause)
}

func (e *ErrCreateProfileFromTemplateFailed) Unwrap() error {
	return e.Cause
}

// ErrAssignProfileFailed is returned when assigning a profile to a device fails.
type ErrAssignProfileFailed struct {
	ProfileID uint64
	Cause     error
}

func (e *ErrAssignProfileFailed) Error() string {
	return fmt.Sprintf("failed to assign profile %d to device: %v", e.ProfileID, e.Cause)
}

func (e *ErrAssignProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrUnassignProfileFailed is returned when clearing a profile's device
// binding fails.
type ErrUnassignProfileFailed struct {
	ProfileID uint64
	Cause     error
}

func (e *ErrUnassignProfileFailed) Error() string {
	return fmt.Sprintf("failed to unassign profile %d from device: %v", e.ProfileID, e.Cause)
}

func (e *ErrUnassignProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrRecordAttestCertFailed is returned when recording a device's
// attestation certificate fails or is refused by the control plane's
// fail-closed preflight. Cause carries the gRPC status with every candidate
// the control plane evaluated and why it refused each.
type ErrRecordAttestCertFailed struct {
	ID    uint64
	Cause error
}

// ErrBootCertificateFailed is returned when a diskless node's boot-certificate
// request fails or is refused by the control plane.
type ErrBootCertificateFailed struct {
	Identity string
	Cause    error
}

func (e *ErrBootCertificateFailed) Error() string {
	return fmt.Sprintf("failed to fetch boot certificate for %q: %v", e.Identity, e.Cause)
}

func (e *ErrBootCertificateFailed) Unwrap() error {
	return e.Cause
}

// ErrBootDeliveryFailed is returned when a diskless node's boot-delivery
// request fails or is refused by the control plane.
type ErrBootDeliveryFailed struct {
	Cause error
}

func (e *ErrBootDeliveryFailed) Error() string {
	return fmt.Sprintf("failed to fetch boot delivery: %v", e.Cause)
}

func (e *ErrBootDeliveryFailed) Unwrap() error {
	return e.Cause
}

// ErrBootProofMissing is returned when a boot call is made without the
// callback that computes its proof over the connection's channel binding.
type ErrBootProofMissing struct{}

func (e *ErrBootProofMissing) Error() string {
	return "a boot call needs a proof callback; a proof cannot be computed before the connection exists"
}

func (e *ErrRecordAttestCertFailed) Error() string {
	return fmt.Sprintf("failed to record attestation certificate for device %d: %v", e.ID, e.Cause)
}

func (e *ErrRecordAttestCertFailed) Unwrap() error {
	return e.Cause
}

// ErrDisableFailed is returned when the control plane refuses or fails an
// operator Disable. Cause carries the gRPC status: FailedPrecondition when
// no SDN policy engine runs, the device has no switch port or its state
// cannot move to suspended.
type ErrDisableFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrDisableFailed) Error() string {
	return fmt.Sprintf("failed to disable device %d: %v", e.ID, e.Cause)
}

func (e *ErrDisableFailed) Unwrap() error {
	return e.Cause
}

// ErrEnableFailed is returned when the control plane refuses or fails an
// operator Enable. Cause carries the gRPC status: FailedPrecondition when
// the device is not disabled.
type ErrEnableFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrEnableFailed) Error() string {
	return fmt.Sprintf("failed to enable device %d: %v", e.ID, e.Cause)
}

func (e *ErrEnableFailed) Unwrap() error {
	return e.Cause
}
