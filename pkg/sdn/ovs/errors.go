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

package ovs

import (
	"errors"
	"strconv"
)

var (
	// ErrNotConnected is returned when attempting operations on a disconnected client
	ErrNotConnected = errors.New("not connected to OVSDB")

	// ErrInvalidSocket is returned when the socket path is invalid
	ErrInvalidSocket = errors.New("invalid OVSDB socket path")

	// ErrBridgeNotFound is returned when a bridge does not exist
	ErrBridgeNotFound = errors.New("bridge not found")

	// ErrBridgeExists is returned when attempting to create a bridge that already exists
	ErrBridgeExists = errors.New("bridge already exists")

	// ErrPortNotFound is returned when a port does not exist
	ErrPortNotFound = errors.New("port not found")

	// ErrPortExists is returned when attempting to create a port that already exists
	ErrPortExists = errors.New("port already exists")

	// ErrFlowNotFound is returned when a flow does not exist
	ErrFlowNotFound = errors.New("flow not found")

	// ErrInvalidFlow is returned when a flow specification is invalid
	ErrInvalidFlow = errors.New("invalid flow specification")

	// ErrInvalidCookieMask is returned when a cookie-scoped flow delete is
	// requested with a zero cookie mask, which would wildcard the cookie
	// and delete every flow on the bridge
	ErrInvalidCookieMask = errors.New("cookie mask must be non-zero")

	// ErrInvalidBridgeName is returned when the bridge name is invalid
	ErrInvalidBridgeName = errors.New("invalid bridge name")

	// ErrInvalidPortName is returned when the port name is invalid
	ErrInvalidPortName = errors.New("invalid port name")

	// ErrInvalidProtocol is returned when the OpenFlow protocol version is invalid
	ErrInvalidProtocol = errors.New("invalid OpenFlow protocol version")

	// ErrTransactionFailed is returned when an OVSDB transaction fails
	ErrTransactionFailed = errors.New("OVSDB transaction failed")

	// ErrOperationTimeout is returned when an operation times out
	ErrOperationTimeout = errors.New("operation timeout")

	// ErrInvalidResponse is returned when the OVSDB response is invalid
	ErrInvalidResponse = errors.New("invalid OVSDB response")

	// ErrProtocolViolation is returned when the OVSDB protocol is violated
	ErrProtocolViolation = errors.New("OVSDB protocol violation")

	// ErrTableNotFound is returned when a database table does not exist
	ErrTableNotFound = errors.New("database table not found")

	// ErrColumnNotFound is returned when a column does not exist
	ErrColumnNotFound = errors.New("column not found")

	// ErrUUIDRequired is returned when a UUID is required but not provided
	ErrUUIDRequired = errors.New("UUID is required")

	// ErrInvalidUUID is returned when a UUID is invalid
	ErrInvalidUUID = errors.New("invalid UUID format")

	// ErrConnectionFailed is returned when connection to OVSDB fails
	ErrConnectionFailed = errors.New("failed to connect to OVSDB")

	// ErrConnectionClosed is returned when the connection is closed
	ErrConnectionClosed = errors.New("connection closed")

	// ErrNoResult is returned when a query returns no results
	ErrNoResult = errors.New("no results returned")

	// VXLAN-specific errors

	// ErrInvalidRemoteIP is returned when the remote VTEP IP address is invalid
	ErrInvalidRemoteIP = errors.New("invalid remote VTEP IP address")

	// ErrVXLANPortExists is returned when a VXLAN port already exists
	ErrVXLANPortExists = errors.New("VXLAN port already exists")

	// ErrVXLANPortNotFound is returned when a VXLAN port does not exist
	ErrVXLANPortNotFound = errors.New("VXLAN port not found")

	// ErrInvalidVXLANConfig is returned when the VXLAN configuration is invalid
	ErrInvalidVXLANConfig = errors.New("invalid VXLAN configuration")

	// ErrInvalidVNI is returned when the VXLAN Network Identifier is invalid
	ErrInvalidVNI = errors.New("invalid VXLAN Network Identifier (must be 0-16777215)")

	// ErrIPFamilyMismatch is returned when local and remote IPs have different address families
	ErrIPFamilyMismatch = errors.New("local and remote IP address family mismatch")

	// ErrConfigSequenceUnreadable is returned when the Open_vSwitch row
	// carries no next_cfg/cur_cfg sequence to wait on.
	ErrConfigSequenceUnreadable = errors.New("ovs: the Open_vSwitch row reports no configuration sequence")
)

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

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}

// ErrInvalidCookie is returned for a flow cookie that does not parse. A
// cookie scopes deletion, so a flow installed with cookie 0 in its place
// is one its owner can never remove by cookie.
type ErrInvalidCookie struct {
	Cookie string
	Err    error
}

// Error implements the error interface.
func (e *ErrInvalidCookie) Error() string {
	return "ovs: invalid flow cookie " + strconv.Quote(e.Cookie) + ": " + e.Err.Error()
}

// Unwrap returns the parse error.
func (e *ErrInvalidCookie) Unwrap() error { return e.Err }

// ErrConfigNotApplied is returned when ovs-vswitchd does not apply a
// committed configuration before the context ends: the change is stored in
// OVSDB but not in force.
type ErrConfigNotApplied struct {
	Target int64
	Err    error
}

// Error implements the error interface.
func (e *ErrConfigNotApplied) Error() string {
	return "ovs: ovs-vswitchd did not apply configuration " + strconv.FormatInt(e.Target, 10) + ": " + e.Err.Error()
}

// Unwrap returns the context error.
func (e *ErrConfigNotApplied) Unwrap() error { return e.Err }

// ErrInvalidPolicing is returned for an ingress policing rate (bps) or burst
// (bits) Open vSwitch cannot apply: it polices in kbps and kb, so each value
// must be 0 or a whole multiple of 1000, and a burst needs a rate.
// ErrInvalidFailMode is returned for a bridge fail mode other than
// "standalone", "secure" or empty.
// ErrInvalidPortType is returned when a port is requested with an interface
// type Open vSwitch does not implement.
type ErrInvalidPortType struct {
	Type string
}

func (e *ErrInvalidPortType) Error() string {
	return "invalid port type: " + e.Type
}

type ErrInvalidFailMode struct {
	FailMode string
}

// Error implements the error interface.
func (e *ErrInvalidFailMode) Error() string {
	return "invalid fail mode: " + e.FailMode + " (must be 'standalone', 'secure', or empty)"
}

type ErrInvalidPolicing struct {
	RateBps   uint64
	BurstBits uint64
}

// Error implements the error interface.
func (e *ErrInvalidPolicing) Error() string {
	return "ovs: invalid ingress policing: rate " + strconv.FormatUint(e.RateBps, 10) +
		" bps, burst " + strconv.FormatUint(e.BurstBits, 10) +
		" bits (each must be 0 or a whole multiple of 1000, and a burst needs a rate)"
}

// ErrInvalidShaping is returned for an egress shaping rate (bps) and burst
// (bits) Open vSwitch cannot apply: a burst needs a rate.
type ErrInvalidShaping struct {
	RateBps   uint64
	BurstBits uint64
}

// Error implements the error interface.
func (e *ErrInvalidShaping) Error() string {
	return "ovs: invalid egress shaping: rate " + strconv.FormatUint(e.RateBps, 10) +
		" bps, burst " + strconv.FormatUint(e.BurstBits, 10) + " bits (a burst needs a rate)"
}
