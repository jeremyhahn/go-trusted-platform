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

// ErrRegisterHostnameRequired is returned when hostname is not provided
type ErrRegisterHostnameRequired struct{}

func (e ErrRegisterHostnameRequired) Error() string {
	return "device register: --hostname is required"
}

// ErrRegisterMACRequired is returned when MAC address is not provided
type ErrRegisterMACRequired struct{}

func (e ErrRegisterMACRequired) Error() string {
	return "device register: --mac is required"
}

// ErrRegisterRoleRequired is returned when role is not provided
type ErrRegisterRoleRequired struct{}

func (e ErrRegisterRoleRequired) Error() string {
	return "device register: --role is required"
}

// ErrRegisterInvalidRole is returned when an invalid role is provided
type ErrRegisterInvalidRole struct {
	Role string
}

func (e ErrRegisterInvalidRole) Error() string {
	return fmt.Sprintf("device register: invalid role %q, must be one of: control-plane, gateway, worker", e.Role)
}

// ErrRegisterTemplateRequired is returned when template name is not provided
type ErrRegisterTemplateRequired struct{}

func (e ErrRegisterTemplateRequired) Error() string {
	return "device register: --template is required"
}

// ErrRegisterServerRequired is returned when server URL is not provided
type ErrRegisterServerRequired struct{}

func (e ErrRegisterServerRequired) Error() string {
	return "device register: --server is required"
}

// ErrRegisterReadOverrideFile is returned when the override file cannot be read
type ErrRegisterReadOverrideFile struct {
	Path  string
	Cause error
}

func (e ErrRegisterReadOverrideFile) Error() string {
	return fmt.Sprintf("device register: failed to read override file %s: %v", e.Path, e.Cause)
}

func (e ErrRegisterReadOverrideFile) Unwrap() error {
	return e.Cause
}

// ErrRegisterParseOverrideFile is returned when the override file cannot be parsed
type ErrRegisterParseOverrideFile struct {
	Path  string
	Cause error
}

func (e ErrRegisterParseOverrideFile) Error() string {
	return fmt.Sprintf("device register: failed to parse override file %s: %v", e.Path, e.Cause)
}

func (e ErrRegisterParseOverrideFile) Unwrap() error {
	return e.Cause
}

// ErrRegisterLoadCACert is returned when the CA certificate cannot be loaded
type ErrRegisterLoadCACert struct {
	Path  string
	Cause error
}

func (e ErrRegisterLoadCACert) Error() string {
	return fmt.Sprintf("device register: failed to load CA certificate %s: %v", e.Path, e.Cause)
}

func (e ErrRegisterLoadCACert) Unwrap() error {
	return e.Cause
}

// ErrRegisterInvalidCACert is returned when the CA certificate PEM is invalid
type ErrRegisterInvalidCACert struct {
	Path string
}

func (e ErrRegisterInvalidCACert) Error() string {
	return fmt.Sprintf("device register: CA certificate file contains no valid PEM data: %s", e.Path)
}

// ErrRegisterTemplateLookupFailed is returned when the template lookup fails
type ErrRegisterTemplateLookupFailed struct {
	Name  string
	Cause error
}

func (e ErrRegisterTemplateLookupFailed) Error() string {
	return fmt.Sprintf("device register: failed to look up template %q: %v", e.Name, e.Cause)
}

func (e ErrRegisterTemplateLookupFailed) Unwrap() error {
	return e.Cause
}

// ErrRegisterCreateProfileFailed is returned when creating the profile from template fails
type ErrRegisterCreateProfileFailed struct {
	Cause error
}

func (e ErrRegisterCreateProfileFailed) Error() string {
	return fmt.Sprintf("device register: failed to create profile: %v", e.Cause)
}

func (e ErrRegisterCreateProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrRegisterInvalidMACAddress is returned when the MAC address format is invalid
type ErrRegisterInvalidMACAddress struct {
	MAC string
}

func (e ErrRegisterInvalidMACAddress) Error() string {
	return fmt.Sprintf("device register: invalid MAC address %q", e.MAC)
}

// ErrRegisterInvalidServerURL is returned when the server URL cannot be parsed
type ErrRegisterInvalidServerURL struct {
	Server string
	Cause  error
}

func (e ErrRegisterInvalidServerURL) Error() string {
	return fmt.Sprintf("device register: invalid server URL %q: %v", e.Server, e.Cause)
}

func (e ErrRegisterInvalidServerURL) Unwrap() error {
	return e.Cause
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

// ErrAssignDeviceHasNoEKCert is returned when --device derivation is
// requested but the registered device record carries no EK certificate.
type ErrAssignDeviceHasNoEKCert struct {
	DeviceID uint64
}

func (e ErrAssignDeviceHasNoEKCert) Error() string {
	return fmt.Sprintf("device profile: device %d has no EK certificate to derive an identity from; supply --ek-serial or --mac", e.DeviceID)
}
