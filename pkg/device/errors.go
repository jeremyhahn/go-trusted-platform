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
	"strings"
)

// ErrProfileNotAssigned indicates the profile is not assigned to a device.
type ErrProfileNotAssigned struct {
	ID uint64
}

// Error returns the error message.
func (e ErrProfileNotAssigned) Error() string {
	return fmt.Sprintf("device: profile %d is not assigned to a device", e.ID)
}

// ErrDeviceIdentityRequired indicates at least one device identifier is required.
type ErrDeviceIdentityRequired struct{}

// Error returns the error message.
func (e ErrDeviceIdentityRequired) Error() string {
	return "device: at least one of ek_serial or mac_address is required"
}

// ErrDeviceRequired indicates a device record was required and none was given.
type ErrDeviceRequired struct{}

// Error returns the error message.
func (e ErrDeviceRequired) Error() string {
	return "device: a device record is required"
}

// ErrDeviceHasNoEKCert indicates a registered device carries no EK
// certificate, so no EK-serial identity can be derived from it.
type ErrDeviceHasNoEKCert struct {
	DeviceID uint64
}

// Error returns the error message.
func (e ErrDeviceHasNoEKCert) Error() string {
	return fmt.Sprintf("device: device %d has no EK certificate to derive an identity from; supply ek_serial or mac_address", e.DeviceID)
}

// ErrNoProfileForDevice indicates neither a profile bound to the device's EK
// identity nor a profile whose match rules cover it exists.
type ErrNoProfileForDevice struct {
	DeviceID uint64
	Serial   string
	EKSerial string
}

// Error returns the error message.
func (e ErrNoProfileForDevice) Error() string {
	return fmt.Sprintf("device: no profile is bound to device %d (serial %q, ek_serial %q) and none matches it", e.DeviceID, e.Serial, e.EKSerial)
}

// ErrNoMatchingConfig indicates no config was found for the device.
type ErrNoMatchingConfig struct {
	EKSerial string
	MAC      string
}

// Error returns the error message.
func (e ErrNoMatchingConfig) Error() string {
	return fmt.Sprintf("device: no matching config found for ek_serial=%q mac=%q", e.EKSerial, e.MAC)
}

// ErrInvalidTemplateID indicates an invalid or zero template ID was provided.
type ErrInvalidTemplateID struct{}

// Error returns the error message.
func (e ErrInvalidTemplateID) Error() string {
	return "device: invalid template ID"
}

// ErrTemplateNotFound indicates the requested template was not found.
type ErrTemplateNotFound struct {
	ID uint64
}

// Error returns the error message.
func (e ErrTemplateNotFound) Error() string {
	return fmt.Sprintf("device: template not found: %d", e.ID)
}

// ErrTemplateNameRequired indicates a template name is required.
type ErrTemplateNameRequired struct{}

// Error returns the error message.
func (e ErrTemplateNameRequired) Error() string {
	return "device: template name is required"
}

// ErrDuplicateTemplateName indicates a template with this name already exists.
type ErrDuplicateTemplateName struct {
	Name string
}

// Error returns the error message.
func (e ErrDuplicateTemplateName) Error() string {
	return fmt.Sprintf("device: duplicate template name: %s", e.Name)
}

// ErrNilTemplate indicates a nil template was provided.
type ErrNilTemplate struct{}

// Error returns the error message.
func (e ErrNilTemplate) Error() string {
	return "device: nil template"
}

// ErrTemplateConfigRequired indicates a template config is required for conversion.
type ErrTemplateConfigRequired struct{}

// Error returns the error message.
func (e ErrTemplateConfigRequired) Error() string {
	return "device: template config is required for profile conversion"
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

// HeartbeatDeviceNotFoundError is returned when the heartbeat identity
// resolves to no device by serial or hostname. It lets transport
// handlers answer 404 for an unknown identity while a storage failure
// after resolution surfaces as a server error.
type HeartbeatDeviceNotFoundError struct {
	Identity string
	Cause    error
}

// Error implements the error interface.
func (e *HeartbeatDeviceNotFoundError) Error() string {
	return "device: no device matches heartbeat identity " + e.Identity + ": " + e.Cause.Error()
}

// Unwrap exposes the cause for errors.Is / errors.As.
func (e *HeartbeatDeviceNotFoundError) Unwrap() error {
	return e.Cause
}

// ErrAttestCertRecorderDependency indicates the attestation-certificate
// recorder was constructed without a required dependency.
type ErrAttestCertRecorderDependency struct {
	Name string
}

// Error returns the error message.
func (e ErrAttestCertRecorderDependency) Error() string {
	return fmt.Sprintf("device: attestation certificate recorder requires a %s", e.Name)
}

// ErrAttestCertTrustAnchorUnavailable indicates the platform CA root could
// not be obtained, so no attestation certificate can be chained and none is
// recorded.
type ErrAttestCertTrustAnchorUnavailable struct {
	Cause error
}

// Error returns the error message.
func (e ErrAttestCertTrustAnchorUnavailable) Error() string {
	msg := "device: attestation certificate refused: platform CA trust anchor unavailable"
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

// Unwrap returns the underlying error.
func (e ErrAttestCertTrustAnchorUnavailable) Unwrap() error {
	return e.Cause
}

// ErrAttestCertNoAttestPub indicates the device record carries no
// attestation public area, so no certificate can be tied to the device's
// attestation key; the device must re-enroll.
type ErrAttestCertNoAttestPub struct {
	DeviceID uint64
}

// Error returns the error message.
func (e ErrAttestCertNoAttestPub) Error() string {
	return fmt.Sprintf("device: attestation certificate refused: device %d has no enrolled attestation public key to bind a certificate to; re-enroll the device", e.DeviceID)
}

// ErrAttestCertAttestPubInvalid indicates the device's recorded attestation
// public area could not be decoded.
type ErrAttestCertAttestPubInvalid struct {
	DeviceID uint64
	Cause    error
}

// Error returns the error message.
func (e ErrAttestCertAttestPubInvalid) Error() string {
	return fmt.Sprintf("device: attestation certificate refused: device %d attestation public key cannot be decoded: %v", e.DeviceID, e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrAttestCertAttestPubInvalid) Unwrap() error {
	return e.Cause
}

// ErrAttestCertKeyMismatch indicates a candidate certificate certifies a key
// other than the device's enrolled attestation key. Recording it would fail
// every quote signature from the device and quarantine it.
type ErrAttestCertKeyMismatch struct{}

// Error returns the error message.
func (e ErrAttestCertKeyMismatch) Error() string {
	return "device: certificate does not certify the device's enrolled attestation public key"
}

// ErrAttestCertNotInStore indicates the platform CA holds no certificate
// under the name.
type ErrAttestCertNotInStore struct {
	CN    string
	Cause error
}

// Error returns the error message.
func (e ErrAttestCertNotInStore) Error() string {
	msg := fmt.Sprintf("device: platform CA holds no certificate under %q", e.CN)
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

// Unwrap returns the underlying error.
func (e ErrAttestCertNotInStore) Unwrap() error {
	return e.Cause
}

// ErrAttestCertPublicAreaNotRestricted indicates re-issuance was refused
// before asking the CA because the device's enrolled attestation public area
// does not describe a TPM-resident Restricted signing key.
type ErrAttestCertPublicAreaNotRestricted struct {
	DeviceID uint64
	Cause    error
}

// Error returns the error message.
func (e ErrAttestCertPublicAreaNotRestricted) Error() string {
	return fmt.Sprintf("device: attestation certificate re-issuance refused for device %d: %v", e.DeviceID, e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrAttestCertPublicAreaNotRestricted) Unwrap() error {
	return e.Cause
}

// ErrAttestCertReissueFailed indicates the platform CA could not issue an
// attestation certificate over the device's enrolled attestation key.
type ErrAttestCertReissueFailed struct {
	DeviceID uint64
	Cause    error
}

// Error returns the error message.
func (e ErrAttestCertReissueFailed) Error() string {
	return fmt.Sprintf("device: attestation certificate re-issuance failed for device %d: %v", e.DeviceID, e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrAttestCertReissueFailed) Unwrap() error {
	return e.Cause
}

// ErrAttestCertWriteFailed indicates the certificate passed the preflight
// but the device record could not be written.
type ErrAttestCertWriteFailed struct {
	DeviceID uint64
	Cause    error
}

// Error returns the error message.
func (e ErrAttestCertWriteFailed) Error() string {
	return fmt.Sprintf("device: attestation certificate for device %d verified but could not be recorded: %v", e.DeviceID, e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrAttestCertWriteFailed) Unwrap() error {
	return e.Cause
}

// ErrAttestCertRefused indicates no candidate certificate passed the
// fail-closed preflight, so nothing was recorded. Attempts lists every
// candidate evaluated and why it was refused; Unwrap exposes their errors so
// errors.As finds the specific refusal (for example
// vm.ErrAKCertificateNotRestricted).
type ErrAttestCertRefused struct {
	DeviceID uint64
	Reissued bool
	Attempts []AttestCertAttempt
}

// Error returns the error message.
func (e ErrAttestCertRefused) Error() string {
	if len(e.Attempts) == 0 {
		return fmt.Sprintf("device: attestation certificate refused for device %d: no certificate is on the record and the platform CA holds none for it; pass reissue to have the CA issue one", e.DeviceID)
	}
	parts := make([]string, 0, len(e.Attempts))
	for _, a := range e.Attempts {
		label := string(a.Source)
		if a.Detail != "" {
			label = fmt.Sprintf("%s[%s]", label, a.Detail)
		}
		parts = append(parts, fmt.Sprintf("%s: %v", label, a.Err))
	}
	return fmt.Sprintf("device: attestation certificate refused for device %d; nothing recorded: %s", e.DeviceID, strings.Join(parts, "; "))
}

// Unwrap returns the refusal of every attempt.
func (e ErrAttestCertRefused) Unwrap() []error {
	errs := make([]error, 0, len(e.Attempts))
	for _, a := range e.Attempts {
		if a.Err != nil {
			errs = append(errs, a.Err)
		}
	}
	return errs
}

// ErrAttestCertReissuedRevokeFailed indicates the CA re-issued an attestation
// certificate the preflight then refused, and the CA could not revoke it: a
// certificate the platform will never trust now sits in the CA store under
// Subject with serial Serial. Refusal carries why it was refused; Unwrap
// exposes both so errors.As finds the specific refusal and the CA error.
type ErrAttestCertReissuedRevokeFailed struct {
	DeviceID uint64
	Serial   string
	Subject  string
	Refusal  error
	Cause    error
}

// Error returns the error message.
func (e ErrAttestCertReissuedRevokeFailed) Error() string {
	return fmt.Sprintf("device: attestation certificate re-issued for device %d was refused (%v) and the CA could not revoke it (serial %s, %s): %v; revoke it by hand", e.DeviceID, e.Refusal, e.Serial, e.Subject, e.Cause)
}

// Unwrap returns the refusal and the CA error.
func (e ErrAttestCertReissuedRevokeFailed) Unwrap() []error {
	errs := make([]error, 0, 2)
	if e.Refusal != nil {
		errs = append(errs, e.Refusal)
	}
	if e.Cause != nil {
		errs = append(errs, e.Cause)
	}
	return errs
}
