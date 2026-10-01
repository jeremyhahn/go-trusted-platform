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

// Package fabric manages physical switch fabric for VLAN/VNI provisioning
// and port lifecycle on Cisco Nexus and compatible switches.
package fabric

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ErrUnknownSwitch is returned when a switch ID cannot be found.
type ErrUnknownSwitch struct {
	ID string
}

func (e ErrUnknownSwitch) Error() string {
	return fmt.Sprintf("fabric: unknown switch %q", e.ID)
}

// ErrInvalidPortRef is returned when a port reference is malformed.
type ErrInvalidPortRef struct {
	Reason string
}

func (e ErrInvalidPortRef) Error() string {
	return fmt.Sprintf("fabric: invalid port reference: %s", e.Reason)
}

// ErrDriverConnect is returned when a switch driver fails to connect.
type ErrDriverConnect struct {
	SwitchID string
	Cause    error
}

func (e ErrDriverConnect) Error() string {
	return fmt.Sprintf("fabric: driver connect failed for switch %q: %s", e.SwitchID, e.Cause)
}

func (e ErrDriverConnect) Unwrap() error {
	return e.Cause
}

// ErrInvalidFabricConfig is returned when the fabric configuration is invalid.
type ErrInvalidFabricConfig struct {
	Reason string
}

func (e ErrInvalidFabricConfig) Error() string {
	return fmt.Sprintf("fabric: invalid config: %s", e.Reason)
}

// ErrDriverNotFound is returned when no driver factory is registered for a vendor.
type ErrDriverNotFound struct {
	Vendor string
}

func (e ErrDriverNotFound) Error() string {
	return fmt.Sprintf("fabric: no driver registered for vendor %q", e.Vendor)
}

// ErrDriverOperation is returned when a driver operation fails.
type ErrDriverOperation struct {
	SwitchID  string
	Operation string
	Cause     error
}

func (e ErrDriverOperation) Error() string {
	return fmt.Sprintf("fabric: %s failed on switch %q: %s", e.Operation, e.SwitchID, e.Cause)
}

func (e ErrDriverOperation) Unwrap() error {
	return e.Cause
}

// ErrNilConfig is returned when a nil configuration is provided.
type ErrNilConfig struct{}

func (e ErrNilConfig) Error() string {
	return "fabric: nil config"
}

// ErrUnknownPortClass is returned for a port assignment whose class is not
// one of the port classes (gateway, hypervisor, bmc, mgmt-uplink,
// peer-link).
type ErrUnknownPortClass struct {
	// Class is the unknown class.
	Class zone.PortClass
}

// Error implements the error interface.
func (e ErrUnknownPortClass) Error() string {
	return fmt.Sprintf("fabric: unknown port class %q", e.Class)
}

// ErrDuplicatePort is returned when one switch port is assigned twice.
type ErrDuplicatePort struct {
	// SwitchID is the switch.
	SwitchID string
	// Port is the port assigned twice.
	Port string
}

// Error implements the error interface.
func (e ErrDuplicatePort) Error() string {
	return fmt.Sprintf("fabric: port %q on switch %q is assigned more than once", e.Port, e.SwitchID)
}

// ErrNilPlan is returned when a manager is built without a network plan.
type ErrNilPlan struct{}

// Error implements the error interface.
func (ErrNilPlan) Error() string {
	return "fabric: a network plan is required"
}

// ErrPortClassPlan is returned when the network plan cannot say what a port
// class carries (an unknown class, or a class with no zone in the plan).
type ErrPortClassPlan struct {
	// Class is the port class.
	Class zone.PortClass
	// Cause is the plan's error.
	Cause error
}

// Error implements the error interface.
func (e ErrPortClassPlan) Error() string {
	return fmt.Sprintf("fabric: port class %q: %s", e.Class, e.Cause)
}

// Unwrap returns the plan's error.
func (e ErrPortClassPlan) Unwrap() error { return e.Cause }
