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

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
)

// ErrInvalidDeviceID is returned when an invalid device ID is provided
type ErrInvalidDeviceID struct {
	ID string
}

func (e ErrInvalidDeviceID) Error() string {
	return fmt.Sprintf("invalid device ID: %s", e.ID)
}

// ErrDeviceNotFound is returned when a device is not found
type ErrDeviceNotFound struct {
	ID uint64
}

func (e ErrDeviceNotFound) Error() string {
	return fmt.Sprintf("device not found: %d", e.ID)
}

// ErrDeviceNotFoundBySerial is returned when a device is not found by serial number
type ErrDeviceNotFoundBySerial struct {
	Serial string
}

func (e ErrDeviceNotFoundBySerial) Error() string {
	return fmt.Sprintf("device not found with serial: %s", e.Serial)
}

// ErrSerialNumberRequired is returned when a serial number is required but not provided
type ErrSerialNumberRequired struct{}

func (e ErrSerialNumberRequired) Error() string {
	return "serial number is required"
}

// ErrDeleteDeviceFailed is returned when device deletion fails
type ErrDeleteDeviceFailed struct {
	ID     uint64
	Reason string
}

func (e ErrDeleteDeviceFailed) Error() string {
	return fmt.Sprintf("failed to delete device %d: %s", e.ID, e.Reason)
}

// ErrGetDeviceFailed is returned when getting a device fails
type ErrGetDeviceFailed struct {
	ID     uint64
	Reason string
}

func (e ErrGetDeviceFailed) Error() string {
	return fmt.Sprintf("failed to get device %d: %s", e.ID, e.Reason)
}

// ErrListDevicesFailed is returned when listing devices fails
type ErrListDevicesFailed struct {
	Reason string
}

func (e ErrListDevicesFailed) Error() string {
	return fmt.Sprintf("failed to list devices: %s", e.Reason)
}

// ErrFindDeviceBySerialFailed is returned when finding a device by serial fails
type ErrFindDeviceBySerialFailed struct {
	Serial string
	Reason string
}

func (e ErrFindDeviceBySerialFailed) Error() string {
	return fmt.Sprintf("failed to find device by serial %s: %s", e.Serial, e.Reason)
}

// Register command errors

// ErrRegisterSerialRequired is returned when --serial is not provided
type ErrRegisterSerialRequired struct{}

func (e ErrRegisterSerialRequired) Error() string {
	return "device register: --serial is required"
}

// ErrRegisterCreateDeviceFailed is returned when the control plane rejects
// the CreateDevice call
type ErrRegisterCreateDeviceFailed struct {
	Serial string
	Cause  error
}

func (e ErrRegisterCreateDeviceFailed) Error() string {
	return fmt.Sprintf("device register: failed to create device %q: %v", e.Serial, e.Cause)
}

func (e ErrRegisterCreateDeviceFailed) Unwrap() error {
	return e.Cause
}

// ErrRegisterEmptyResponse is returned when CreateDevice succeeds but the
// response carries no device record
type ErrRegisterEmptyResponse struct {
	Serial string
}

func (e ErrRegisterEmptyResponse) Error() string {
	return fmt.Sprintf("device register: control plane returned no device for serial %q", e.Serial)
}

// Profile command errors

// ErrInvalidProfileID is returned when an invalid profile ID is provided
type ErrInvalidProfileID struct {
	ID string
}

func (e ErrInvalidProfileID) Error() string {
	return fmt.Sprintf("device profile: invalid profile ID: %s", e.ID)
}

// ErrProfileNameRequired is returned when the profile name is not provided
type ErrProfileNameRequired struct{}

func (e ErrProfileNameRequired) Error() string {
	return "device profile: --name is required"
}

// ErrProfileInvalidRole is returned when an invalid profile role is provided
type ErrProfileInvalidRole struct {
	Role string
}

func (e ErrProfileInvalidRole) Error() string {
	return fmt.Sprintf("device profile: invalid role %q, must be one of: control-plane, gateway, worker, server, client, workstation, edge, iot, load-balancer", e.Role)
}

// ErrProfileEKCertReadFailed is returned when the EK certificate file cannot be read
type ErrProfileEKCertReadFailed struct {
	Path  string
	Cause error
}

func (e ErrProfileEKCertReadFailed) Error() string {
	return fmt.Sprintf("device profile: failed to read EK certificate %s: %v", e.Path, e.Cause)
}

func (e ErrProfileEKCertReadFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileEKCertInvalid is returned when the EK certificate is not a valid
// PEM-encoded X.509 certificate
type ErrProfileEKCertInvalid struct {
	Reason string
}

func (e ErrProfileEKCertInvalid) Error() string {
	return fmt.Sprintf("device profile: EK certificate is not a valid PEM x509 certificate: %s", e.Reason)
}

// ErrProfileConfigReadFailed is returned when the config file cannot be read
type ErrProfileConfigReadFailed struct {
	Path  string
	Cause error
}

func (e ErrProfileConfigReadFailed) Error() string {
	return fmt.Sprintf("device profile: failed to read config file %s: %v", e.Path, e.Cause)
}

func (e ErrProfileConfigReadFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileConfigParseFailed is returned when the config file cannot be parsed
type ErrProfileConfigParseFailed struct {
	Path  string
	Cause error
}

func (e ErrProfileConfigParseFailed) Error() string {
	return fmt.Sprintf("device profile: failed to parse config file %s: %v", e.Path, e.Cause)
}

func (e ErrProfileConfigParseFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileCreateFailed is returned when profile creation fails
type ErrProfileCreateFailed struct {
	Cause error
}

func (e ErrProfileCreateFailed) Error() string {
	return fmt.Sprintf("device profile: failed to create profile: %v", e.Cause)
}

func (e ErrProfileCreateFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileGetFailed is returned when fetching a profile fails
type ErrProfileGetFailed struct {
	ID    uint64
	Cause error
}

func (e ErrProfileGetFailed) Error() string {
	return fmt.Sprintf("device profile: failed to get profile %d: %v", e.ID, e.Cause)
}

func (e ErrProfileGetFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidPagination is returned when a list verb is given a page or page
// size below one, before any connection is attempted.
type ErrInvalidPagination struct {
	Page     int
	PageSize int
}

func (e ErrInvalidPagination) Error() string {
	return fmt.Sprintf("device profile: invalid pagination: page %d, page-size %d (both must be >= 1)", e.Page, e.PageSize)
}

// ErrProfileListFailed is returned when listing profiles fails
type ErrProfileListFailed struct {
	Cause error
}

func (e ErrProfileListFailed) Error() string {
	return fmt.Sprintf("device profile: failed to list profiles: %v", e.Cause)
}

func (e ErrProfileListFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileNotFound is returned when the control plane has no profile with
// the id. It matches the SDK's common.ErrNotFound under errors.Is.
type ErrProfileNotFound struct {
	ID uint64
}

func (e ErrProfileNotFound) Error() string {
	return fmt.Sprintf("device profile: profile %d not found", e.ID)
}

func (e ErrProfileNotFound) Is(target error) bool {
	return target == common.ErrNotFound
}

// ErrProfileDeleteFailed is returned when a profile delete fails for a reason
// other than a missing profile.
type ErrProfileDeleteFailed struct {
	ID    uint64
	Cause error
}

func (e ErrProfileDeleteFailed) Error() string {
	return fmt.Sprintf("device profile: failed to delete profile %d: %v", e.ID, e.Cause)
}

func (e ErrProfileDeleteFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileMatchCriteriaRequired is returned when match is given no device
// attribute to match on.
type ErrProfileMatchCriteriaRequired struct{}

func (e ErrProfileMatchCriteriaRequired) Error() string {
	return "device profile: at least one of --mac, --serial or --model is required"
}

// ErrNoMatchingProfile is returned when no profile's match rules fit the
// device. It matches the SDK's common.ErrNotFound under errors.Is.
type ErrNoMatchingProfile struct {
	MACAddress string
	Serial     string
	Model      string
}

func (e ErrNoMatchingProfile) Error() string {
	return fmt.Sprintf("device profile: no profile matches mac %q, serial %q, model %q",
		e.MACAddress, e.Serial, e.Model)
}

func (e ErrNoMatchingProfile) Is(target error) bool {
	return target == common.ErrNotFound
}

// ErrProfileMatchFailed is returned when the profile match fails for a reason
// other than no profile matching.
type ErrProfileMatchFailed struct {
	Cause error
}

func (e ErrProfileMatchFailed) Error() string {
	return fmt.Sprintf("device profile: failed to match a profile: %v", e.Cause)
}

func (e ErrProfileMatchFailed) Unwrap() error {
	return e.Cause
}

// ErrAttestEvidenceRequired is returned when device attest is run without
// --evidence-file.
type ErrAttestEvidenceRequired struct{}

func (e ErrAttestEvidenceRequired) Error() string {
	return "device attest: --evidence-file is required"
}

// ErrAttestEvidenceReadFailed is returned when the evidence file cannot be
// read.
type ErrAttestEvidenceReadFailed struct {
	Path  string
	Cause error
}

func (e ErrAttestEvidenceReadFailed) Error() string {
	return fmt.Sprintf("device attest: failed to read evidence file %s: %v", e.Path, e.Cause)
}

func (e ErrAttestEvidenceReadFailed) Unwrap() error {
	return e.Cause
}

// ErrAttestEvidenceEmpty is returned when the evidence file has no content.
type ErrAttestEvidenceEmpty struct {
	Path string
}

func (e ErrAttestEvidenceEmpty) Error() string {
	return fmt.Sprintf("device attest: evidence file %s is empty", e.Path)
}

// ErrAttestFailed is returned when the evidence could not be evaluated. A
// negative verdict is not an error.
type ErrAttestFailed struct {
	ID    uint64
	Cause error
}

func (e ErrAttestFailed) Error() string {
	return fmt.Sprintf("device attest: failed to attest device %d: %v", e.ID, e.Cause)
}

func (e ErrAttestFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileConfigIdentityRequired is returned when find-config is given no
// device identity to look up.
type ErrProfileConfigIdentityRequired struct{}

func (e ErrProfileConfigIdentityRequired) Error() string {
	return "device profile: at least one of --ek-serial or --mac is required"
}

// ErrNoConfigForDevice is returned when no profile is stored for the device
// identity. It matches the SDK's common.ErrNotFound under errors.Is.
type ErrNoConfigForDevice struct {
	EKSerial   string
	MACAddress string
}

func (e ErrNoConfigForDevice) Error() string {
	return fmt.Sprintf("device profile: no profile for ek serial %q, mac %q", e.EKSerial, e.MACAddress)
}

func (e ErrNoConfigForDevice) Is(target error) bool {
	return target == common.ErrNotFound
}

// ErrProfileFindConfigFailed is returned when the config lookup fails for a
// reason other than no profile being stored for the identity.
type ErrProfileFindConfigFailed struct {
	Cause error
}

func (e ErrProfileFindConfigFailed) Error() string {
	return fmt.Sprintf("device profile: failed to find config: %v", e.Cause)
}

func (e ErrProfileFindConfigFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileUpdateFailed is returned when updating a profile fails
type ErrProfileUpdateFailed struct {
	ID    uint64
	Cause error
}

func (e ErrProfileUpdateFailed) Error() string {
	return fmt.Sprintf("device profile: failed to update profile %d: %v", e.ID, e.Cause)
}

func (e ErrProfileUpdateFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileAssignFailed is returned when assigning a profile to a device fails.
type ErrProfileAssignFailed struct {
	ID    uint64
	Cause error
}

func (e ErrProfileAssignFailed) Error() string {
	return fmt.Sprintf("device profile: failed to assign profile %d to device: %v", e.ID, e.Cause)
}

func (e ErrProfileAssignFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileUnassignFailed is returned when clearing a profile's device
// binding fails.
type ErrProfileUnassignFailed struct {
	ID    uint64
	Cause error
}

func (e ErrProfileUnassignFailed) Error() string {
	return fmt.Sprintf("device profile: failed to unassign profile %d from device: %v", e.ID, e.Cause)
}

func (e ErrProfileUnassignFailed) Unwrap() error {
	return e.Cause
}

// ErrAssignIdentityRequired is returned when a profile assignment resolves
// neither an EK serial nor a MAC address.
type ErrAssignIdentityRequired struct{}

func (e ErrAssignIdentityRequired) Error() string {
	return "device profile: assignment requires --device, --ek-serial, or --mac"
}

// ErrRecordAttestCertFailed is returned when the control plane refuses or
// fails to record a device's attestation certificate. Reason carries the
// control plane's message, which names every candidate it evaluated and why
// each was refused.
type ErrRecordAttestCertFailed struct {
	ID     uint64
	Reason string
}

func (e ErrRecordAttestCertFailed) Error() string {
	return fmt.Sprintf("attestation certificate not recorded for device %d: %s", e.ID, e.Reason)
}

// ErrDisableDeviceFailed is returned when the control plane refuses or fails
// an operator disable.
type ErrDisableDeviceFailed struct {
	ID     uint64
	Reason string
}

func (e ErrDisableDeviceFailed) Error() string {
	return fmt.Sprintf("device %d not disabled: %s", e.ID, e.Reason)
}

// ErrEnableDeviceFailed is returned when the control plane refuses or fails
// an operator enable.
type ErrEnableDeviceFailed struct {
	ID     uint64
	Reason string
}

func (e ErrEnableDeviceFailed) Error() string {
	return fmt.Sprintf("device %d not enabled: %s", e.ID, e.Reason)
}

// ErrBootKeyUnreadable is returned when the --key file cannot be read or
// holds no PEM private key that can sign.
type ErrBootKeyUnreadable struct {
	Path  string
	Cause error
}

func (e ErrBootKeyUnreadable) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("device boot: %s holds no PEM private key that can sign", e.Path)
	}
	return fmt.Sprintf("device boot: %s is not a usable private key: %v", e.Path, e.Cause)
}

func (e ErrBootKeyUnreadable) Unwrap() error {
	return e.Cause
}

// ErrBootQuoteCommandFailed is returned when the --quote-command program
// fails or prints no evidence. Stderr carries what the program reported.
type ErrBootQuoteCommandFailed struct {
	Command string
	Stderr  string
	Cause   error
}

func (e ErrBootQuoteCommandFailed) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("device boot: quote command %s printed no evidence", e.Command)
	}
	return fmt.Sprintf("device boot: quote command %s failed: %v: %s", e.Command, e.Cause, e.Stderr)
}

func (e ErrBootQuoteCommandFailed) Unwrap() error {
	return e.Cause
}

// ErrBootCertificateFailed is returned when the control plane refuses or
// fails a boot-certificate request.
type ErrBootCertificateFailed struct {
	Identity string
	Reason   string
}

func (e ErrBootCertificateFailed) Error() string {
	return fmt.Sprintf("boot certificate not returned for %q: %s", e.Identity, e.Reason)
}

// ErrBootDeliveryFailed is returned when the control plane refuses or fails a
// boot-delivery request.
type ErrBootDeliveryFailed struct {
	Reason string
}

func (e ErrBootDeliveryFailed) Error() string {
	return fmt.Sprintf("boot delivery not returned: %s", e.Reason)
}

// ErrDeviceUpdateNoChanges is returned when `device update` is given no
// field to change, before any connection is attempted.
type ErrDeviceUpdateNoChanges struct {
	ID uint64
}

func (e ErrDeviceUpdateNoChanges) Error() string {
	return fmt.Sprintf("device update: nothing to change on device %d: give at least one of --model, --ek-cert, --attest-pub, --attest-cert, --signing-pub, --hash-algo", e.ID)
}

// ErrDeviceUpdateFailed is returned when the control plane refuses a
// device update.
type ErrDeviceUpdateFailed struct {
	ID    uint64
	Cause error
}

func (e ErrDeviceUpdateFailed) Error() string {
	return fmt.Sprintf("device update: failed to update device %d: %v", e.ID, e.Cause)
}

func (e ErrDeviceUpdateFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidTemplateID is returned when a template id is not a decimal
// uint64.
type ErrInvalidTemplateID struct {
	ID string
}

func (e ErrInvalidTemplateID) Error() string {
	return fmt.Sprintf("device template: invalid template ID %q: must be a decimal number", e.ID)
}

// ErrTemplateNameRequired is returned when `device template create` is
// given no --name.
type ErrTemplateNameRequired struct{}

func (e ErrTemplateNameRequired) Error() string {
	return "device template: --name is required"
}

// ErrTemplateNotFound is returned when the control plane has no template
// with the id. It matches the SDK's common.ErrNotFound under errors.Is.
type ErrTemplateNotFound struct {
	ID uint64
}

func (e ErrTemplateNotFound) Error() string {
	return fmt.Sprintf("device template: template %d not found", e.ID)
}

func (e ErrTemplateNotFound) Is(target error) bool {
	return target == common.ErrNotFound
}

// ErrTemplateOperationFailed is returned when the control plane refuses a
// template operation. Operation is the verb (create, get, list, update,
// delete, create-profile); ID is zero for create and list.
type ErrTemplateOperationFailed struct {
	Operation string
	ID        uint64
	Cause     error
}

func (e ErrTemplateOperationFailed) Error() string {
	if e.ID == 0 {
		return fmt.Sprintf("device template: %s failed: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("device template: %s of template %d failed: %v", e.Operation, e.ID, e.Cause)
}

func (e ErrTemplateOperationFailed) Unwrap() error {
	return e.Cause
}
