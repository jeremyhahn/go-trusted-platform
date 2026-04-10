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

package bmc

import "fmt"

// ErrInvalidConfig indicates an invalid BMC configuration field.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("bmc: invalid configuration for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("bmc: invalid configuration: %s", e.Reason)
}

// ErrConnectionFailed indicates a BMC connection failure.
type ErrConnectionFailed struct {
	Address string
	Cause   error
}

func (e ErrConnectionFailed) Error() string {
	msg := "bmc: connection failed"
	if e.Address != "" {
		msg = fmt.Sprintf("%s to %s", msg, e.Address)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrClientClosed indicates the BMC client has been closed.
type ErrClientClosed struct{}

func (e ErrClientClosed) Error() string {
	return "bmc: client is closed"
}

// ErrPowerOperation indicates a power management operation failure.
type ErrPowerOperation struct {
	Operation string
	Cause     error
}

func (e ErrPowerOperation) Error() string {
	msg := "bmc: power operation failed"
	if e.Operation != "" {
		msg = fmt.Sprintf("bmc: power %s failed", e.Operation)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrPowerOperation) Unwrap() error {
	return e.Cause
}

// ErrBootDevice indicates a boot device operation failure.
type ErrBootDevice struct {
	Device string
	Cause  error
}

func (e ErrBootDevice) Error() string {
	msg := "bmc: boot device operation failed"
	if e.Device != "" {
		msg = fmt.Sprintf("bmc: boot device %s failed", e.Device)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrBootDevice) Unwrap() error {
	return e.Cause
}

// ErrVirtualMedia indicates a virtual media operation failure.
type ErrVirtualMedia struct {
	Operation string
	Cause     error
}

func (e ErrVirtualMedia) Error() string {
	msg := "bmc: virtual media operation failed"
	if e.Operation != "" {
		msg = fmt.Sprintf("bmc: virtual media %s failed", e.Operation)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrVirtualMedia) Unwrap() error {
	return e.Cause
}

// ErrInventory indicates a failure retrieving BMC inventory data.
type ErrInventory struct {
	Cause error
}

func (e ErrInventory) Error() string {
	msg := "bmc: inventory retrieval failed"
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrInventory) Unwrap() error {
	return e.Cause
}

// ErrProfileNotFound indicates a device profile was not found.
type ErrProfileNotFound struct {
	ProfileID uint64
}

func (e ErrProfileNotFound) Error() string {
	return fmt.Sprintf("bmc: profile not found: %d", e.ProfileID)
}

// ErrInvalidBootDevice indicates an unrecognized boot device value.
type ErrInvalidBootDevice struct {
	Device string
}

func (e ErrInvalidBootDevice) Error() string {
	return fmt.Sprintf("bmc: invalid boot device: %s", e.Device)
}

// ErrInvalidPowerState indicates an unrecognized power state value.
type ErrInvalidPowerState struct {
	State string
}

func (e ErrInvalidPowerState) Error() string {
	return fmt.Sprintf("bmc: invalid power state: %s", e.State)
}

// ErrNilConfig indicates a nil configuration was provided.
type ErrNilConfig struct{}

func (e ErrNilConfig) Error() string {
	return "bmc: configuration is nil"
}

// ErrUnsupportedOperation indicates the requested operation is not supported
// by the current BMC protocol.
type ErrUnsupportedOperation struct {
	Operation string
}

func (e ErrUnsupportedOperation) Error() string {
	return fmt.Sprintf("bmc: unsupported operation: %s", e.Operation)
}

// ErrSensorRead indicates a failure reading sensor data from the BMC.
type ErrSensorRead struct {
	Cause error
}

func (e ErrSensorRead) Error() string {
	msg := "bmc: sensor read failed"
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrSensorRead) Unwrap() error {
	return e.Cause
}

// ErrFRURead indicates a failure reading or parsing FRU data.
type ErrFRURead struct {
	Reason string
	Cause  error
}

func (e ErrFRURead) Error() string {
	msg := "bmc: FRU read failed"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrFRURead) Unwrap() error {
	return e.Cause
}

// ErrSDRParse indicates a failure parsing an SDR record.
type ErrSDRParse struct {
	Reason string
}

func (e ErrSDRParse) Error() string {
	return fmt.Sprintf("bmc: SDR parse failed: %s", e.Reason)
}
