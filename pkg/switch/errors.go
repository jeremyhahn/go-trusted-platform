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

package switchmgmt

import "fmt"

// ErrSSHConnectionFailed is returned when the SSH connection to the switch fails.
type ErrSSHConnectionFailed struct {
	Host  string
	Cause error
}

func (e ErrSSHConnectionFailed) Error() string {
	return fmt.Sprintf("switchmgmt: ssh connection failed to %s: %v", e.Host, e.Cause)
}

func (e ErrSSHConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrCommandFailed is returned when a CLI command fails on the switch.
type ErrCommandFailed struct {
	Command string
	Output  string
	Cause   error
}

func (e ErrCommandFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("switchmgmt: command failed %q (output: %s): %v", e.Command, e.Output, e.Cause)
	}
	return fmt.Sprintf("switchmgmt: command failed %q (output: %s)", e.Command, e.Output)
}

func (e ErrCommandFailed) Unwrap() error {
	return e.Cause
}

// ErrVLANConfigFailed is returned when VLAN configuration fails.
type ErrVLANConfigFailed struct {
	VLANID int
	Cause  error
}

func (e ErrVLANConfigFailed) Error() string {
	return fmt.Sprintf("switchmgmt: vlan %d configuration failed: %v", e.VLANID, e.Cause)
}

func (e ErrVLANConfigFailed) Unwrap() error {
	return e.Cause
}

// ErrPortConfigFailed is returned when port configuration fails.
type ErrPortConfigFailed struct {
	Port  string
	Cause error
}

func (e ErrPortConfigFailed) Error() string {
	return fmt.Sprintf("switchmgmt: port %s configuration failed: %v", e.Port, e.Cause)
}

func (e ErrPortConfigFailed) Unwrap() error {
	return e.Cause
}

// ErrUnsupportedVendor is returned when the switch vendor is not supported.
type ErrUnsupportedVendor struct {
	Vendor SwitchVendor
}

func (e ErrUnsupportedVendor) Error() string {
	return fmt.Sprintf("switchmgmt: unsupported vendor: %s", e.Vendor)
}

// ErrVerificationFailed is returned when switch configuration verification fails.
type ErrVerificationFailed struct {
	Details string
}

func (e ErrVerificationFailed) Error() string {
	return fmt.Sprintf("switchmgmt: verification failed: %s", e.Details)
}

// ErrInvalidConfig is returned when the switch configuration is invalid.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("switchmgmt: invalid config: field %s: %s", e.Field, e.Reason)
}

// ErrInvalidPortRange is returned when a port range specification is malformed.
type ErrInvalidPortRange struct {
	Port   string
	Reason string
}

func (e ErrInvalidPortRange) Error() string {
	return fmt.Sprintf("switchmgmt: invalid port range %q: %s", e.Port, e.Reason)
}

// ErrNilConfig is returned when a nil configuration is provided.
type ErrNilConfig struct{}

func (e ErrNilConfig) Error() string {
	return "switchmgmt: configuration cannot be nil"
}

// ErrPortNotFound is returned when a requested port does not exist on the switch.
type ErrPortNotFound struct {
	Port string
}

func (e ErrPortNotFound) Error() string {
	return fmt.Sprintf("switchmgmt: port %s not found", e.Port)
}

// ErrVLANNotFound is returned when a requested VLAN does not exist on the switch.
type ErrVLANNotFound struct {
	VLANID uint16
}

func (e ErrVLANNotFound) Error() string {
	return fmt.Sprintf("switchmgmt: vlan %d not found", e.VLANID)
}

// ErrSwitchConnectionFailed is returned when a connection to the switch cannot be established.
type ErrSwitchConnectionFailed struct {
	Host  string
	Cause error
}

func (e ErrSwitchConnectionFailed) Error() string {
	return fmt.Sprintf("switchmgmt: switch connection failed to %s: %v", e.Host, e.Cause)
}

func (e ErrSwitchConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrPortVLANSetFailed is returned when setting a port's VLAN fails.
type ErrPortVLANSetFailed struct {
	Port   string
	VLANID uint16
	Cause  error
}

func (e ErrPortVLANSetFailed) Error() string {
	return fmt.Sprintf("switchmgmt: failed to set port %s to vlan %d: %v",
		e.Port, e.VLANID, e.Cause)
}

func (e ErrPortVLANSetFailed) Unwrap() error {
	return e.Cause
}

// ErrManagerNotFound is returned when a Manager for the given switch name is not registered.
type ErrManagerNotFound struct {
	Name string
}

func (e ErrManagerNotFound) Error() string {
	return fmt.Sprintf("switchmgmt: manager not found for switch %q", e.Name)
}

// ErrSSHCommandFailed is returned when an SSH CLI command execution fails.
type ErrSSHCommandFailed struct {
	Command string
	Output  string
	Cause   error
}

func (e ErrSSHCommandFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("switchmgmt: ssh command failed %q (output: %s): %v",
			e.Command, e.Output, e.Cause)
	}
	return fmt.Sprintf("switchmgmt: ssh command failed %q (output: %s)",
		e.Command, e.Output)
}

func (e ErrSSHCommandFailed) Unwrap() error {
	return e.Cause
}

// ErrSSHParseOutputFailed is returned when parsing SSH command output fails.
type ErrSSHParseOutputFailed struct {
	Command string
	Output  string
	Reason  string
}

func (e ErrSSHParseOutputFailed) Error() string {
	return fmt.Sprintf("switchmgmt: failed to parse output for %q: %s",
		e.Command, e.Reason)
}
