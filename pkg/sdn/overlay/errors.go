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

package overlay

import (
	"fmt"
	"net"
	"net/netip"
)

// Sentinel errors for overlay controller operations.
var (
	// ErrControllerNotRunning is returned when operations require a running controller.
	ErrControllerNotRunning = &errControllerNotRunning{}

	// ErrControllerAlreadyRunning is returned when Start is called on a running controller.
	ErrControllerAlreadyRunning = &errControllerAlreadyRunning{}

	// ErrConfigNil is returned when a nil configuration is provided.
	ErrConfigNil = &errConfigNil{}

	// ErrNodeIDEmpty is returned when node ID is empty.
	ErrNodeIDEmpty = &errNodeIDEmpty{}

	// ErrInvalidVTEPIP is returned when VTEP IP is invalid.
	ErrInvalidVTEPIP = &errInvalidVTEPIP{}

	// ErrUnderlayInterfaceEmpty is returned when underlay interface is empty.
	ErrUnderlayInterfaceEmpty = &errUnderlayInterfaceEmpty{}

	// ErrMTUTooSmall is returned when MTU is too small for VXLAN.
	ErrMTUTooSmall = &errMTUTooSmall{}

	// ErrInvalidVXLANPort is returned when VXLAN port is invalid.
	ErrInvalidVXLANPort = &errInvalidVXLANPort{}

	// ErrBridgeNameEmpty is returned when bridge name is empty.
	ErrBridgeNameEmpty = &errBridgeNameEmpty{}

	// ErrVTEPNotFound is returned when a VTEP is not found.
	ErrVTEPNotFound = &errVTEPNotFound{}

	// ErrVTEPAlreadyExists is returned when a VTEP already exists.
	ErrVTEPAlreadyExists = &errVTEPAlreadyExists{}

	// ErrTunnelNotFound is returned when a tunnel is not found.
	ErrTunnelNotFound = &errTunnelNotFound{}

	// ErrTunnelAlreadyExists is returned when a tunnel already exists.
	ErrTunnelAlreadyExists = &errTunnelAlreadyExists{}

	// ErrVNINotFound is returned when a VNI is not found.
	ErrVNINotFound = &errVNINotFound{}

	// ErrVNIAlreadyExists is returned when a VNI already exists.
	ErrVNIAlreadyExists = &errVNIAlreadyExists{}

	// ErrVNIOutOfRange is returned when a VNI is out of valid range.
	ErrVNIOutOfRange = &errVNIOutOfRange{}

	// ErrVLANOutOfRange is returned when a VLAN is out of valid range.
	ErrVLANOutOfRange = &errVLANOutOfRange{}

	// ErrMACNotFound is returned when a MAC entry is not found.
	ErrMACNotFound = &errMACNotFound{}

	// ErrMACAlreadyExists is returned when a MAC entry already exists.
	ErrMACAlreadyExists = &errMACAlreadyExists{}

	// ErrOVSClientNil is returned when OVS client is nil.
	ErrOVSClientNil = &errOVSClientNil{}

	// ErrVTEPManagerNil is returned when VTEP manager is nil.
	ErrVTEPManagerNil = &errVTEPManagerNil{}

	// ErrBGPServiceNil is returned when BGP service is nil.
	ErrBGPServiceNil = &errBGPServiceNil{}

	// ErrIPAMNil is returned when IPAM allocator is nil.
	ErrIPAMNil = &errIPAMNil{}

	// ErrLoggerNil is returned when logger is nil.
	ErrLoggerNil = &errLoggerNil{}

	// ErrShutdownTimeout is returned when graceful shutdown times out.
	ErrShutdownTimeout = &errShutdownTimeout{}

	// ErrStateBackendUnsupported is returned when state backend is not supported.
	ErrStateBackendUnsupported = &errStateBackendUnsupported{}
)

type errControllerNotRunning struct{}

func (e *errControllerNotRunning) Error() string { return "overlay controller not running" }

type errControllerAlreadyRunning struct{}

func (e *errControllerAlreadyRunning) Error() string { return "overlay controller already running" }

type errConfigNil struct{}

func (e *errConfigNil) Error() string { return "configuration is nil" }

type errNodeIDEmpty struct{}

func (e *errNodeIDEmpty) Error() string { return "node ID is empty" }

type errInvalidVTEPIP struct{}

func (e *errInvalidVTEPIP) Error() string { return "invalid VTEP IP address" }

type errUnderlayInterfaceEmpty struct{}

func (e *errUnderlayInterfaceEmpty) Error() string { return "underlay interface name is empty" }

type errMTUTooSmall struct{}

func (e *errMTUTooSmall) Error() string { return "MTU too small for VXLAN encapsulation" }

type errInvalidVXLANPort struct{}

func (e *errInvalidVXLANPort) Error() string { return "invalid VXLAN port" }

type errBridgeNameEmpty struct{}

func (e *errBridgeNameEmpty) Error() string { return "bridge name is empty" }

type errVTEPNotFound struct{}

func (e *errVTEPNotFound) Error() string { return "VTEP not found" }

type errVTEPAlreadyExists struct{}

func (e *errVTEPAlreadyExists) Error() string { return "VTEP already exists" }

type errTunnelNotFound struct{}

func (e *errTunnelNotFound) Error() string { return "tunnel not found" }

type errTunnelAlreadyExists struct{}

func (e *errTunnelAlreadyExists) Error() string { return "tunnel already exists" }

type errVNINotFound struct{}

func (e *errVNINotFound) Error() string { return "VNI not found" }

type errVNIAlreadyExists struct{}

func (e *errVNIAlreadyExists) Error() string { return "VNI already exists" }

type errVNIOutOfRange struct{}

func (e *errVNIOutOfRange) Error() string { return "VNI out of valid range (1-16777215)" }

type errVLANOutOfRange struct{}

func (e *errVLANOutOfRange) Error() string { return "VLAN out of valid range (0-4094)" }

type errMACNotFound struct{}

func (e *errMACNotFound) Error() string { return "MAC entry not found" }

type errMACAlreadyExists struct{}

func (e *errMACAlreadyExists) Error() string { return "MAC entry already exists" }

type errOVSClientNil struct{}

func (e *errOVSClientNil) Error() string { return "OVS client is nil" }

type errVTEPManagerNil struct{}

func (e *errVTEPManagerNil) Error() string { return "VTEP manager is nil" }

type errBGPServiceNil struct{}

func (e *errBGPServiceNil) Error() string { return "BGP service is nil" }

type errIPAMNil struct{}

func (e *errIPAMNil) Error() string { return "IPAM allocator is nil" }

type errLoggerNil struct{}

func (e *errLoggerNil) Error() string { return "logger is nil" }

type errShutdownTimeout struct{}

func (e *errShutdownTimeout) Error() string { return "shutdown timeout exceeded" }

type errStateBackendUnsupported struct{}

func (e *errStateBackendUnsupported) Error() string { return "state backend not supported" }

// ErrStartupFailed is returned when controller startup fails.
type ErrStartupFailed struct {
	NodeID string
	Phase  string
	Cause  error
}

func (e *ErrStartupFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("overlay controller %s startup failed during %s: %v",
			e.NodeID, e.Phase, e.Cause)
	}
	return fmt.Sprintf("overlay controller %s startup failed during %s", e.NodeID, e.Phase)
}

func (e *ErrStartupFailed) Unwrap() error {
	return e.Cause
}

// ErrShutdownFailed is returned when controller shutdown fails.
type ErrShutdownFailed struct {
	NodeID string
	Phase  string
	Cause  error
}

func (e *ErrShutdownFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("overlay controller %s shutdown failed during %s: %v",
			e.NodeID, e.Phase, e.Cause)
	}
	return fmt.Sprintf("overlay controller %s shutdown failed during %s", e.NodeID, e.Phase)
}

func (e *ErrShutdownFailed) Unwrap() error {
	return e.Cause
}

// ErrVNIOperationFailed is returned when a VNI operation fails.
type ErrVNIOperationFailed struct {
	VNI       uint32
	Operation string
	Cause     error
}

func (e *ErrVNIOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("VNI %d operation %q failed: %v", e.VNI, e.Operation, e.Cause)
	}
	return fmt.Sprintf("VNI %d operation %q failed", e.VNI, e.Operation)
}

func (e *ErrVNIOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrTunnelOperationFailed is returned when a tunnel operation fails.
type ErrTunnelOperationFailed struct {
	RemoteVTEP netip.Addr
	VNI        uint32
	Operation  string
	Cause      error
}

func (e *ErrTunnelOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("tunnel to %s VNI %d operation %q failed: %v",
			e.RemoteVTEP, e.VNI, e.Operation, e.Cause)
	}
	return fmt.Sprintf("tunnel to %s VNI %d operation %q failed",
		e.RemoteVTEP, e.VNI, e.Operation)
}

func (e *ErrTunnelOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrMACOperationFailed is returned when a MAC operation fails.
type ErrMACOperationFailed struct {
	MAC       net.HardwareAddr
	VNI       uint32
	Operation string
	Cause     error
}

func (e *ErrMACOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("MAC %s VNI %d operation %q failed: %v",
			e.MAC, e.VNI, e.Operation, e.Cause)
	}
	return fmt.Sprintf("MAC %s VNI %d operation %q failed", e.MAC, e.VNI, e.Operation)
}

func (e *ErrMACOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrBGPOperationFailed is returned when a BGP operation fails.
type ErrBGPOperationFailed struct {
	Operation string
	Cause     error
}

func (e *ErrBGPOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("BGP operation %q failed: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("BGP operation %q failed", e.Operation)
}

func (e *ErrBGPOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrOVSOperationFailed is returned when an OVS operation fails.
type ErrOVSOperationFailed struct {
	Bridge    string
	Operation string
	Cause     error
}

func (e *ErrOVSOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("OVS bridge %s operation %q failed: %v", e.Bridge, e.Operation, e.Cause)
	}
	return fmt.Sprintf("OVS bridge %s operation %q failed", e.Bridge, e.Operation)
}

func (e *ErrOVSOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidState is returned when the controller is in an invalid state.
type ErrInvalidState struct {
	Expected ControllerState
	Actual   ControllerState
}

func (e *ErrInvalidState) Error() string {
	return fmt.Sprintf("invalid controller state: expected %s, got %s", e.Expected, e.Actual)
}

// ErrInvalidMAC is returned when a MAC address is invalid.
type ErrInvalidMAC struct {
	MAC    net.HardwareAddr
	Reason string
}

func (e *ErrInvalidMAC) Error() string {
	if e.MAC == nil {
		return fmt.Sprintf("invalid MAC address: %s", e.Reason)
	}
	return fmt.Sprintf("invalid MAC address %s: %s", e.MAC, e.Reason)
}

// ErrInvalidIP is returned when an IP address is invalid.
type ErrInvalidIP struct {
	IP     netip.Addr
	Reason string
}

func (e *ErrInvalidIP) Error() string {
	if !e.IP.IsValid() {
		return fmt.Sprintf("invalid IP address: %s", e.Reason)
	}
	return fmt.Sprintf("invalid IP address %s: %s", e.IP, e.Reason)
}

// ErrInvalidVNI is returned when a VNI is invalid.
type ErrInvalidVNI struct {
	VNI    uint32
	Reason string
}

func (e *ErrInvalidVNI) Error() string {
	return fmt.Sprintf("invalid VNI %d: %s", e.VNI, e.Reason)
}

// ErrComponentNotInitialized is returned when a component is not initialized.
type ErrComponentNotInitialized struct {
	Component string
}

func (e *ErrComponentNotInitialized) Error() string {
	return fmt.Sprintf("component not initialized: %s", e.Component)
}

// ErrHealthCheckFailed is returned when a health check fails.
type ErrHealthCheckFailed struct {
	Component string
	Reason    string
	Cause     error
}

func (e *ErrHealthCheckFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("health check failed for %s: %s: %v", e.Component, e.Reason, e.Cause)
	}
	if e.Reason != "" {
		return fmt.Sprintf("health check failed for %s: %s", e.Component, e.Reason)
	}
	return fmt.Sprintf("health check failed for %s", e.Component)
}

func (e *ErrHealthCheckFailed) Unwrap() error {
	return e.Cause
}

// ErrEVPNOperationFailed is returned when an EVPN operation fails.
type ErrEVPNOperationFailed struct {
	RouteType string
	Operation string
	Cause     error
}

func (e *ErrEVPNOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("EVPN %s %s failed: %v", e.RouteType, e.Operation, e.Cause)
	}
	return fmt.Sprintf("EVPN %s %s failed", e.RouteType, e.Operation)
}

func (e *ErrEVPNOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrVTEPOperationFailed is returned when a VTEP operation fails.
type ErrVTEPOperationFailed struct {
	VTEP      netip.Addr
	Operation string
	Cause     error
}

func (e *ErrVTEPOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("VTEP %s operation %q failed: %v", e.VTEP, e.Operation, e.Cause)
	}
	return fmt.Sprintf("VTEP %s operation %q failed", e.VTEP, e.Operation)
}

func (e *ErrVTEPOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidOverlayKind is returned for an overlay kind other than platform,
// tenant or public.
type ErrInvalidOverlayKind struct {
	// Kind is the offending kind.
	Kind OverlayKind
}

// Error implements the error interface.
func (e ErrInvalidOverlayKind) Error() string {
	return fmt.Sprintf("overlay: kind %q is not platform, tenant or public", e.Kind)
}

// ErrEnvironmentRequired is returned when a VNI must be derived but the
// controller has no environment number to derive it from.
type ErrEnvironmentRequired struct{}

// Error implements the error interface.
func (ErrEnvironmentRequired) Error() string {
	return "overlay: deriving a VNI needs the environment number (sdn.environment.id)"
}

// ErrVNIOutsideEnvironment is returned when an explicit VNI does not belong
// to the controller's environment block (E·100000+1 to E·100000+99999).
type ErrVNIOutsideEnvironment struct {
	// VNI is the offending VNI.
	VNI uint32
	// Environment is the controller's environment number.
	Environment uint16
}

// Error implements the error interface.
func (e ErrVNIOutsideEnvironment) Error() string {
	return fmt.Sprintf("overlay: VNI %d is outside environment %d's VNI block", e.VNI, e.Environment)
}

// ErrVNIBlockExhausted is returned when every overlay network number of the
// environment is taken.
type ErrVNIBlockExhausted struct {
	// Environment is the exhausted environment.
	Environment uint16
}

// Error implements the error interface.
func (e ErrVNIBlockExhausted) Error() string {
	return fmt.Sprintf("overlay: environment %d has no free overlay network number", e.Environment)
}
