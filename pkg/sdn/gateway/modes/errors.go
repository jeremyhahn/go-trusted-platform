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

package modes

import (
	"fmt"
	"net"
	"net/netip"
)

// Sentinel errors for mode operations.
var (
	// ErrConfigNil is returned when a nil configuration is provided.
	ErrConfigNil = &errConfigNil{}

	// ErrAlreadyRunning is returned when attempting to start an already running handler.
	ErrAlreadyRunning = &errAlreadyRunning{}

	// ErrNotRunning is returned when operations are attempted on a stopped handler.
	ErrNotRunning = &errNotRunning{}

	// ErrVTEPConfigNil is returned when VTEP configuration is nil.
	ErrVTEPConfigNil = &errVTEPConfigNil{}

	// ErrBridgeNameEmpty is returned when bridge name is empty.
	ErrBridgeNameEmpty = &errBridgeNameEmpty{}

	// ErrLoggerNil is returned when logger is nil.
	ErrLoggerNil = &errLoggerNil{}

	// ErrOVSClientNil is returned when OVS client is nil.
	ErrOVSClientNil = &errOVSClientNil{}

	// ErrOpenFlowClientNil is returned when OpenFlow client is nil.
	ErrOpenFlowClientNil = &errOpenFlowClientNil{}

	// ErrVNIOutOfRange is returned when VNI is outside valid range.
	ErrVNIOutOfRange = &errVNIOutOfRange{}

	// ErrVLANOutOfRange is returned when VLAN ID is outside valid range.
	ErrVLANOutOfRange = &errVLANOutOfRange{}

	// ErrVNIAlreadyExists is returned when VNI is already configured.
	ErrVNIAlreadyExists = &errVNIAlreadyExists{}

	// ErrVNINotFound is returned when VNI is not found.
	ErrVNINotFound = &errVNINotFound{}

	// ErrMACNil is returned when MAC address is nil.
	ErrMACNil = &errMACNil{}

	// ErrMACInvalid is returned when MAC address is invalid.
	ErrMACInvalid = &errMACInvalid{}

	// ErrMACNotFound is returned when MAC address is not found.
	ErrMACNotFound = &errMACNotFound{}

	// ErrInvalidVTEPIP is returned when VTEP IP is invalid.
	ErrInvalidVTEPIP = &errInvalidVTEPIP{}

	// ErrAccessPortEmpty is returned when the overlay has no access port.
	ErrAccessPortEmpty = &errAccessPortEmpty{}

	// ErrAccessPortUnresolved is returned when the access port has no
	// OpenFlow port number on the bridge.
	ErrAccessPortUnresolved = &errAccessPortUnresolved{}

	// ErrVLANInUse is returned when a VLAN already carries another VNI.
	ErrVLANInUse = &errVLANInUse{}

	// ErrAnycastGatewayIncomplete is returned when the anycast gateway
	// has only one of its IPv4 address and MAC.
	ErrAnycastGatewayIncomplete = &errAnycastGatewayIncomplete{}

	// ErrAnycastGatewayRequired is returned when an L3VNI is configured
	// without the anycast gateway that routes into it.
	ErrAnycastGatewayRequired = &errAnycastGatewayRequired{}

	// ErrRoutedSubnetInvalid is returned when a routed subnet is not an
	// IPv4 network holding its VNI's anycast gateway, or repeats another.
	ErrRoutedSubnetInvalid = &errRoutedSubnetInvalid{}

	// ErrRouterMACRequired is returned when an L3VNI is configured
	// without the EVPN router MAC symmetric IRB addresses.
	ErrRouterMACRequired = &errRouterMACRequired{}

	// ErrAdmitterNil is returned when the overlay runs EVPN without a
	// VTEP admitter.
	ErrAdmitterNil = &errAdmitterNil{}

	// ErrVTEPRevoked is returned when a VTEP is revoked while one of its
	// routes is being admitted; the route is not installed.
	ErrVTEPRevoked = &errVTEPRevoked{}

	// ErrFlowNotTracked is returned when the overlay releases a flow it
	// never installed.
	ErrFlowNotTracked = &errFlowNotTracked{}

	// ErrSwitchNotRestored is returned for an overlay change while the
	// switch has reconnected but the OpenFlow numbers of the overlay's
	// ports, which a restart can change, have not been read again.
	ErrSwitchNotRestored = &errSwitchNotRestored{}
)

// Lifecycle sentinel error types.

type errConfigNil struct{}

func (e *errConfigNil) Error() string { return "configuration is nil" }

type errAlreadyRunning struct{}

func (e *errAlreadyRunning) Error() string { return "handler already running" }

type errNotRunning struct{}

func (e *errNotRunning) Error() string { return "handler not running" }

// Overlay mode sentinel error types.

type errVTEPConfigNil struct{}

func (e *errVTEPConfigNil) Error() string { return "VTEP configuration is nil" }

type errBridgeNameEmpty struct{}

func (e *errBridgeNameEmpty) Error() string { return "bridge name is empty" }

type errLoggerNil struct{}

func (e *errLoggerNil) Error() string { return "logger is nil" }

type errOVSClientNil struct{}

func (e *errOVSClientNil) Error() string { return "OVS client is nil" }

type errOpenFlowClientNil struct{}

func (e *errOpenFlowClientNil) Error() string { return "OpenFlow client is nil" }

type errVNIOutOfRange struct{}

func (e *errVNIOutOfRange) Error() string { return "VNI must be between 1 and 16777215" }

type errVLANOutOfRange struct{}

func (e *errVLANOutOfRange) Error() string { return "VLAN ID must be between 1 and 4094" }

type errVNIAlreadyExists struct{}

func (e *errVNIAlreadyExists) Error() string { return "VNI already exists" }

type errVNINotFound struct{}

func (e *errVNINotFound) Error() string { return "VNI not found" }

type errMACNil struct{}

func (e *errMACNil) Error() string { return "MAC address is nil" }

type errMACInvalid struct{}

func (e *errMACInvalid) Error() string { return "MAC address must be 6 bytes" }

type errMACNotFound struct{}

func (e *errMACNotFound) Error() string { return "MAC address not found" }

type errInvalidVTEPIP struct{}

func (e *errInvalidVTEPIP) Error() string { return "invalid VTEP IP address" }

type errAccessPortEmpty struct{}

func (e *errAccessPortEmpty) Error() string { return "access port is empty" }

type errAccessPortUnresolved struct{}

func (e *errAccessPortUnresolved) Error() string { return "access port has no OpenFlow port number" }

type errVLANInUse struct{}

func (e *errVLANInUse) Error() string { return "VLAN already carries another VNI" }

type errAnycastGatewayIncomplete struct{}

func (e *errAnycastGatewayIncomplete) Error() string {
	return "anycast gateway needs both an IPv4 address and a MAC"
}

type errRoutedSubnetInvalid struct{}

func (e *errRoutedSubnetInvalid) Error() string {
	return "a routed subnet must be a distinct IPv4 network holding its VNI's anycast gateway"
}

type errAnycastGatewayRequired struct{}

func (e *errAnycastGatewayRequired) Error() string {
	return "an L3VNI needs the anycast gateway to route into it"
}

type errRouterMACRequired struct{}

func (e *errRouterMACRequired) Error() string {
	return "an L3VNI needs the EVPN router MAC for symmetric IRB"
}

type errAdmitterNil struct{}

func (e *errAdmitterNil) Error() string {
	return "EVPN needs a VTEP admitter to vet the VTEPs its routes name"
}

type errVTEPRevoked struct{}

func (e *errVTEPRevoked) Error() string {
	return "the VTEP was revoked while its route was being admitted"
}

type errFlowNotTracked struct{}

func (e *errFlowNotTracked) Error() string { return "overlay flow is not installed" }

type errSwitchNotRestored struct{}

func (e *errSwitchNotRestored) Error() string {
	return "overlay ports not resolved since the switch reconnected"
}

// Contextual error types.

// ErrStopFailed is returned when a component fails to stop.
type ErrStopFailed struct {
	Component string
	Cause     error
}

func (e *ErrStopFailed) Error() string {
	return fmt.Sprintf("failed to stop %s: %v", e.Component, e.Cause)
}

func (e *ErrStopFailed) Unwrap() error {
	return e.Cause
}

// ErrOverlayInitFailed represents an overlay initialization failure.
type ErrOverlayInitFailed struct {
	Component string
	Cause     error
}

func (e *ErrOverlayInitFailed) Error() string {
	return fmt.Sprintf("overlay initialization failed for %s: %v", e.Component, e.Cause)
}

func (e *ErrOverlayInitFailed) Unwrap() error {
	return e.Cause
}

// ErrOverlayStartFailed represents an overlay start failure.
type ErrOverlayStartFailed struct {
	Component string
	Cause     error
}

func (e *ErrOverlayStartFailed) Error() string {
	return fmt.Sprintf("overlay start failed for %s: %v", e.Component, e.Cause)
}

func (e *ErrOverlayStartFailed) Unwrap() error {
	return e.Cause
}

// ErrOverlayPortUnresolved reports that the OpenFlow number of one of the
// overlay's ports, VXLANPort or AccessPort, could not be read.
type ErrOverlayPortUnresolved struct {
	Port  string
	Cause error
}

func (e *ErrOverlayPortUnresolved) Error() string {
	return fmt.Sprintf("resolving the overlay %s: %v", e.Port, e.Cause)
}

func (e *ErrOverlayPortUnresolved) Unwrap() error {
	return e.Cause
}

// ErrVNIOperationFailed represents a VNI operation failure.
type ErrVNIOperationFailed struct {
	VNI       uint32
	Operation string
	Cause     error
}

func (e *ErrVNIOperationFailed) Error() string {
	return fmt.Sprintf("VNI %d %s failed: %v", e.VNI, e.Operation, e.Cause)
}

func (e *ErrVNIOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrMACOperationFailed represents a MAC operation failure.
type ErrMACOperationFailed struct {
	MAC       net.HardwareAddr
	Operation string
	Cause     error
}

func (e *ErrMACOperationFailed) Error() string {
	return fmt.Sprintf("MAC %s %s failed: %v", e.MAC.String(), e.Operation, e.Cause)
}

func (e *ErrMACOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrVTEPOperationFailed represents a VTEP operation failure.
type ErrVTEPOperationFailed struct {
	VTEPIP    netip.Addr
	Operation string
	Cause     error
}

func (e *ErrVTEPOperationFailed) Error() string {
	return fmt.Sprintf("VTEP %s %s failed: %v", e.VTEPIP.String(), e.Operation, e.Cause)
}

func (e *ErrVTEPOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrFlowOperationFailed represents an OpenFlow operation failure.
type ErrFlowOperationFailed struct {
	Table     uint8
	Operation string
	Cause     error
}

func (e *ErrFlowOperationFailed) Error() string {
	return fmt.Sprintf("flow %s on table %d failed: %v", e.Operation, e.Table, e.Cause)
}

func (e *ErrFlowOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrFlowResyncFailed reports that the switch refused the flow mods that
// undo a failed change, so it may hold flows the overlay does not track,
// or refused the flush-and-rebuild that replaces them on the next change.
type ErrFlowResyncFailed struct {
	Cause error
}

func (e *ErrFlowResyncFailed) Error() string {
	return fmt.Sprintf("restoring the overlay flows after a failed change failed: %v", e.Cause)
}

func (e *ErrFlowResyncFailed) Unwrap() error {
	return e.Cause
}

// ErrBindingConflict reports a remote MAC/IP binding refused because it
// claims an address this VTEP answers for: the anycast gateway's or a
// local host's. Owner names which.
type ErrBindingConflict struct {
	VNI   uint32
	MAC   net.HardwareAddr
	IP    netip.Addr
	Owner string
}

func (e *ErrBindingConflict) Error() string {
	return fmt.Sprintf("remote binding %s %s on VNI %d conflicts with the %s", e.MAC, e.IP, e.VNI, e.Owner)
}

// ErrInvalidNDMessage reports a neighbor discovery message the overlay
// will not act on: one RFC 4861 §7.1.1 has a node discard, or one it
// cannot build an answer for. Reason names the check that failed.
type ErrInvalidNDMessage struct {
	Reason string
}

func (e *ErrInvalidNDMessage) Error() string {
	return "overlay: invalid neighbor discovery message: " + e.Reason
}

// ErrUnsupportedNDMessage reports a neighbor discovery message the overlay
// cannot read although RFC 4861 does not have a node discard it: one behind
// an IPv6 extension header. The overlay passes it on unread. Reason names
// what it could not read.
type ErrUnsupportedNDMessage struct {
	Reason string
}

func (e *ErrUnsupportedNDMessage) Error() string {
	return "overlay: unsupported neighbor discovery message: " + e.Reason
}
