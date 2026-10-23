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

// ErrTemplateProfileDependency indicates creating a profile from a template
// was attempted without the template or profile service it needs.
type ErrTemplateProfileDependency struct {
	Name string
}

// Error returns the error message.
func (e ErrTemplateProfileDependency) Error() string {
	return fmt.Sprintf("device: creating a profile from a template requires the %s", e.Name)
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

// IdentityNotFoundError is returned when a certificate identity (a
// heartbeat's, or a diskless node's at boot) resolves to no device by
// serial or hostname. It lets transport handlers answer 404 for an
// unknown identity while a storage failure after resolution surfaces as
// a server error.
type IdentityNotFoundError struct {
	Identity string
	Cause    error
}

// Error implements the error interface.
func (e *IdentityNotFoundError) Error() string {
	return "device: no device matches identity " + e.Identity + ": " + e.Cause.Error()
}

// Unwrap exposes the cause for errors.Is / errors.As.
func (e *IdentityNotFoundError) Unwrap() error {
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

// ErrAttestCertClearUnsupported indicates the recorder's device service has
// no compare-and-clear write for the attestation certificate, so a refused
// certificate cannot be removed. device.Service implements it.
type ErrAttestCertClearUnsupported struct{}

// Error returns the error message.
func (e ErrAttestCertClearUnsupported) Error() string {
	return "device: the device service cannot clear an attestation certificate"
}

// ErrAttestCertClearConflict indicates the certificate on the device record
// changed between the refusal and the clear, so nothing was cleared: a
// concurrent write is never undone by a clear.
type ErrAttestCertClearConflict struct {
	DeviceID uint64
}

// Error returns the error message.
func (e ErrAttestCertClearConflict) Error() string {
	return fmt.Sprintf("device: attestation certificate of device %d changed since it was refused; nothing cleared", e.DeviceID)
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

// ErrRegistrationNoRegistrar reports a registration attempted with no
// device registry to write to.
type ErrRegistrationNoRegistrar struct{}

// Error returns the error message.
func (ErrRegistrationNoRegistrar) Error() string {
	return "device registration: no device registry was supplied"
}

// ErrRegistrationNoSerial reports a registration with no product serial.
// The serial is the registry's identity for find-or-create; without one a
// registration would allocate a new record on every enrollment.
type ErrRegistrationNoSerial struct{}

// Error returns the error message.
func (ErrRegistrationNoSerial) Error() string {
	return "device registration: the enrollment carries no product serial"
}

// ErrRegistrationEKIdentityUnbound reports an enrollment whose serial or
// Common Name claims an EK-derived node identity (entities.IsEKNodeIdentity)
// that is not the identity of the EK certificate the enrollment carries. A
// diskless node is found by that name on every boot (#690), so recording an
// unbound claim would hand one node's record to another.
type ErrRegistrationEKIdentityUnbound struct {
	Claimed string
	Reason  string
	Cause   error
}

// Error returns the error message.
func (e ErrRegistrationEKIdentityUnbound) Error() string {
	msg := fmt.Sprintf("device registration: %q is not bound to the enrollment's EK: %s", e.Claimed, e.Reason)
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying cause.
func (e ErrRegistrationEKIdentityUnbound) Unwrap() error { return e.Cause }

// ErrDeviceSerialRequired reports a device create request without a serial.
// Every REST listener refuses it with HTTP 400 (#484).
type ErrDeviceSerialRequired struct{}

// Error returns the error message.
func (ErrDeviceSerialRequired) Error() string {
	return "device serial is required"
}

// ErrDeviceSerialExists is returned when a create names a serial another
// device already holds. The serial is the identity enrollment matches a TPM
// against, so two rows holding it would make that match ambiguous.
type ErrDeviceSerialExists struct {
	Serial string
}

// Error returns the error message.
func (e ErrDeviceSerialExists) Error() string {
	return fmt.Sprintf("device already exists with serial: %s", e.Serial)
}

// ErrDeviceRequestConflict reports a device request that sets the same field
// flat and inside the {device:{...}} envelope to different values.
type ErrDeviceRequestConflict struct {
	Field string
}

// Error returns the error message.
func (e ErrDeviceRequestConflict) Error() string {
	return fmt.Sprintf("device request sets %q flat and in the device envelope to different values", e.Field)
}

// ErrDeviceRequestBody reports a device request body that is not valid JSON
// for the device request shape.
type ErrDeviceRequestBody struct {
	Cause error
}

// Error returns the error message.
func (e ErrDeviceRequestBody) Error() string {
	return fmt.Sprintf("invalid device request body: %v", e.Cause)
}

// Unwrap returns the decoding error.
func (e ErrDeviceRequestBody) Unwrap() error { return e.Cause }

// ErrRegistrationSaveFailed reports a new device record that could not be
// written.
type ErrRegistrationSaveFailed struct {
	Serial string
	Cause  error
}

// Error returns the error message.
func (e ErrRegistrationSaveFailed) Error() string {
	return fmt.Sprintf("device registration: failed to save device %q: %v", e.Serial, e.Cause)
}

// Unwrap returns the storage error.
func (e ErrRegistrationSaveFailed) Unwrap() error { return e.Cause }

// ErrRegistrationUpdateFailed reports an existing device record that could
// not be updated.
type ErrRegistrationUpdateFailed struct {
	Serial string
	Cause  error
}

// Error returns the error message.
func (e ErrRegistrationUpdateFailed) Error() string {
	return fmt.Sprintf("device registration: failed to update existing device %q: %v", e.Serial, e.Cause)
}

// Unwrap returns the storage error.
func (e ErrRegistrationUpdateFailed) Unwrap() error { return e.Cause }

// ErrControlPlaneNoTPM reports a control-plane self-registration with no
// TPM to read its identity from.
type ErrControlPlaneNoTPM struct{}

// Error returns the error message.
func (ErrControlPlaneNoTPM) Error() string {
	return "device registration: the control plane has no TPM to read its own identity from"
}

// ErrControlPlaneIdentityUnavailable reports a piece of the control plane's
// own TPM identity that could not be read. Name is the material.
type ErrControlPlaneIdentityUnavailable struct {
	Name  string
	Cause error
}

// Error returns the error message.
func (e ErrControlPlaneIdentityUnavailable) Error() string {
	return fmt.Sprintf("device registration: the control plane's own %s is unavailable: %v", e.Name, e.Cause)
}

// Unwrap returns the underlying TPM error.
func (e ErrControlPlaneIdentityUnavailable) Unwrap() error { return e.Cause }

// ErrControlPlaneNoAttestationKey reports a control plane whose TPM holds no
// attestation key public area. Without it there is no anchor to verify a
// quote against, so registering the record would produce a device the
// collector dials and can never verdict.
type ErrControlPlaneNoAttestationKey struct{}

// Error returns the error message.
func (ErrControlPlaneNoAttestationKey) Error() string {
	return "device registration: the control plane's TPM holds no attestation key public area; provision the IAK before registering the control plane as a device"
}

// ErrLifecycleUnenforced is returned for an operator Enable or Disable on a
// control plane with no SDN policy engine: nothing could cut or re-admit the
// device's port, so recording a state change would claim enforcement that
// does not exist.
type ErrLifecycleUnenforced struct{}

// Error returns the error message.
func (ErrLifecycleUnenforced) Error() string {
	return "device lifecycle: this control plane has no SDN policy engine to enforce a device disable or enable"
}

// ErrLifecycleDependency is returned by NewLifecycleService when a required
// dependency is missing.
type ErrLifecycleDependency struct {
	Name string
}

// Error returns the error message.
func (e ErrLifecycleDependency) Error() string {
	return fmt.Sprintf("device lifecycle: %s is required", e.Name)
}

// ErrDeviceNotOnFabric is returned when an operator Enable or Disable targets
// a device with no recorded switch port: it was never admitted to the SDN
// fabric, so there is no port to cut or re-admit.
type ErrDeviceNotOnFabric struct {
	DeviceID uint64
}

// Error returns the error message.
func (e ErrDeviceNotOnFabric) Error() string {
	return fmt.Sprintf("device lifecycle: device %d has no switch port on the SDN fabric to enforce", e.DeviceID)
}

// ErrLifecycleReasonTooLong is returned when a disable reason exceeds Max
// bytes.
type ErrLifecycleReasonTooLong struct {
	Max int
}

// Error returns the error message.
func (e ErrLifecycleReasonTooLong) Error() string {
	return fmt.Sprintf("device lifecycle: reason exceeds %d bytes", e.Max)
}
