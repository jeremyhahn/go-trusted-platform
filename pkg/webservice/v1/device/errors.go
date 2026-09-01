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

// ErrDeviceServiceNotInitialized indicates the device service is not initialized.
type ErrDeviceServiceNotInitialized struct{}

func (e ErrDeviceServiceNotInitialized) Error() string {
	return "device service not initialized"
}

// ErrProfileServiceNotInitializedError indicates the profile service is not initialized.
type ErrProfileServiceNotInitializedError struct{}

func (e ErrProfileServiceNotInitializedError) Error() string {
	return "profile service not initialized"
}

// ErrTemplateServiceNotInitialized indicates the template service is not initialized.
type ErrTemplateServiceNotInitialized struct{}

func (e ErrTemplateServiceNotInitialized) Error() string {
	return "template service not initialized"
}

// ErrInvalidRequestBody indicates the request body is invalid.
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	if e.Reason != "" {
		return "invalid request body: " + e.Reason
	}
	return "invalid request body"
}

// ErrMissingDeviceID indicates device ID is required but not provided.
type ErrMissingDeviceID struct{}

func (e ErrMissingDeviceID) Error() string {
	return "device id is required"
}

// ErrMissingProfileID indicates profile ID is required but not provided.
type ErrMissingProfileID struct{}

func (e ErrMissingProfileID) Error() string {
	return "profile id is required"
}

// ErrMissingTemplateID indicates template ID is required but not provided.
type ErrMissingTemplateID struct{}

func (e ErrMissingTemplateID) Error() string {
	return "template id is required"
}

// ErrMissingTemplateName indicates template name is required but not provided.
type ErrMissingTemplateName struct{}

func (e ErrMissingTemplateName) Error() string {
	return "template name is required"
}

// ErrMissingSerialNumber indicates serial number is required but not provided.
type ErrMissingSerialNumber struct{}

func (e ErrMissingSerialNumber) Error() string {
	return "serial number is required"
}

// ErrMissingMACAddress indicates MAC address is required but not provided.
type ErrMissingMACAddress struct{}

func (e ErrMissingMACAddress) Error() string {
	return "mac address is required"
}

// ErrMissingDeviceIdentity indicates at least one device identifier is required.
type ErrMissingDeviceIdentity struct{}

func (e ErrMissingDeviceIdentity) Error() string {
	return "at least one of ek_serial or mac_address is required"
}

// ErrActivationNotConfigured indicates the activation/profile surface
// was requested on a deployment without SDN enrollment wired.
type ErrActivationNotConfigured struct{}

func (e ErrActivationNotConfigured) Error() string {
	return "device activation is not configured on this deployment"
}

// ErrHeartbeatNotConfigured indicates the heartbeat route was
// registered without a HeartbeatRecorder behind it.
type ErrHeartbeatNotConfigured struct{}

func (e ErrHeartbeatNotConfigured) Error() string {
	return "heartbeat recorder is not configured"
}

// ErrDeviceNotFound indicates the device was not found.
type ErrDeviceNotFound struct {
	ID     uint64
	Serial string
}

func (e ErrDeviceNotFound) Error() string {
	if e.Serial != "" {
		return "device not found: serial=" + e.Serial
	}
	return "device not found"
}

// ErrProfileNotFoundError indicates the profile was not found.
type ErrProfileNotFoundError struct {
	ID     uint64
	Serial string
	MAC    string
}

func (e ErrProfileNotFoundError) Error() string {
	if e.Serial != "" {
		return "profile not found: serial=" + e.Serial
	}
	if e.MAC != "" {
		return "profile not found: mac=" + e.MAC
	}
	return "profile not found"
}

// ErrInvalidDeviceID indicates the device ID is invalid.
type ErrInvalidDeviceID struct{}

func (e ErrInvalidDeviceID) Error() string {
	return "invalid device id"
}

// ErrInvalidProfileID indicates the profile ID is invalid.
type ErrInvalidProfileID struct{}

func (e ErrInvalidProfileID) Error() string {
	return "invalid profile id"
}

// ErrInvalidTemplateID indicates the template ID is invalid.
type ErrInvalidTemplateID struct{}

func (e ErrInvalidTemplateID) Error() string {
	return "invalid template id"
}

// ErrInvalidPaginationParams indicates invalid pagination parameters.
type ErrInvalidPaginationParams struct {
	Reason string
}

func (e ErrInvalidPaginationParams) Error() string {
	if e.Reason != "" {
		return "invalid pagination parameters: " + e.Reason
	}
	return "invalid pagination parameters"
}

// ErrSwitchNotConfigured indicates the switch referenced by a device is not configured.
type ErrSwitchNotConfigured struct {
	SwitchName string
}

func (e ErrSwitchNotConfigured) Error() string {
	return "switch not configured: " + e.SwitchName
}

// ErrSwitchVLANTransitionFailed indicates the physical switch port VLAN change failed.
type ErrSwitchVLANTransitionFailed struct {
	SwitchName string
	Port       string
	VLAN       uint16
	Cause      error
}

func (e ErrSwitchVLANTransitionFailed) Error() string {
	msg := "switch vlan transition failed: switch=" + e.SwitchName + " port=" + e.Port
	if e.Cause != nil {
		msg += " cause=" + e.Cause.Error()
	}
	return msg
}

func (e ErrSwitchVLANTransitionFailed) Unwrap() error {
	return e.Cause
}

// ErrSwitchPortIndeterminate indicates the physical switch port's state
// could not be proven closed after a failed VLAN operation: the read-back
// verification failed, or the read-back showed a VLAN other than the
// profile's provisioning VLAN. The port may remain on the trusted VLAN —
// operator action is required.
type ErrSwitchPortIndeterminate struct {
	SwitchName string
	Port       string
	Cause      error
}

func (e ErrSwitchPortIndeterminate) Error() string {
	msg := "physical port state INDETERMINATE — operator action required: switch=" + e.SwitchName + " port=" + e.Port
	if e.Cause != nil {
		msg += " cause=" + e.Cause.Error()
	}
	return msg
}

func (e ErrSwitchPortIndeterminate) Unwrap() error {
	return e.Cause
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
