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

package ipxe

import (
	"errors"
	"fmt"
)

// Sentinel errors for the ipxe package.
var (
	// ErrNoServerIP indicates the server IP could not be determined.
	ErrNoServerIP = errors.New("unable to determine server IP address")

	// ErrNoAvailableIPs indicates no available IP addresses in the DHCP range.
	ErrNoAvailableIPs = errors.New("no available IP addresses in DHCP range")

	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = errors.New("invalid configuration")

	// ErrFirmwareNotFound indicates the requested firmware file was not found.
	ErrFirmwareNotFound = errors.New("firmware file not found")

	// ErrInvalidInterface indicates the network interface is invalid or not found.
	ErrInvalidInterface = errors.New("invalid or non-existent network interface")

	// ErrInvalidIPRange indicates an invalid IP address range.
	ErrInvalidIPRange = errors.New("invalid IP address range")

	// ErrInvalidPort indicates an invalid port number.
	ErrInvalidPort = errors.New("invalid port number")

	// ErrNoBootEntries indicates no boot entries are configured.
	ErrNoBootEntries = errors.New("no boot entries configured")

	// ErrInvalidBootEntry indicates a boot entry is invalid.
	ErrInvalidBootEntry = errors.New("invalid boot entry")

	// ErrLeaseNotFound indicates no lease exists for the given MAC address.
	ErrLeaseNotFound = errors.New("lease not found")

	// ErrLeaseExpired indicates the lease has expired.
	ErrLeaseExpired = errors.New("lease expired")
)

// ErrIPAMAllocationFailed indicates an IPAM allocation operation failed.
type ErrIPAMAllocationFailed struct {
	PoolID string
	MAC    string
	Cause  error
}

// Error returns the error message.
func (e *ErrIPAMAllocationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("IPAM allocation failed for pool %s, MAC %s: %v", e.PoolID, e.MAC, e.Cause)
	}
	return fmt.Sprintf("IPAM allocation failed for pool %s, MAC %s", e.PoolID, e.MAC)
}

// Unwrap returns the underlying error.
func (e *ErrIPAMAllocationFailed) Unwrap() error {
	return e.Cause
}

// ErrIPAMInvalidIP indicates an invalid IP address was returned or provided.
type ErrIPAMInvalidIP struct {
	IP     string
	Reason string
}

// Error returns the error message.
func (e *ErrIPAMInvalidIP) Error() string {
	return fmt.Sprintf("invalid IP %s: %s", e.IP, e.Reason)
}

// ErrIPAMReleaseFailed indicates an IPAM release operation failed.
type ErrIPAMReleaseFailed struct {
	IP    string
	MAC   string
	Cause error
}

// Error returns the error message.
func (e *ErrIPAMReleaseFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("IPAM release failed for IP %s, MAC %s: %v", e.IP, e.MAC, e.Cause)
	}
	return fmt.Sprintf("IPAM release failed for IP %s, MAC %s", e.IP, e.MAC)
}

// Unwrap returns the underlying error.
func (e *ErrIPAMReleaseFailed) Unwrap() error {
	return e.Cause
}

// ErrIPAMRenewFailed indicates an IPAM renewal operation failed.
type ErrIPAMRenewFailed struct {
	IP    string
	MAC   string
	Cause error
}

// Error returns the error message.
func (e *ErrIPAMRenewFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("IPAM renewal failed for IP %s, MAC %s: %v", e.IP, e.MAC, e.Cause)
	}
	return fmt.Sprintf("IPAM renewal failed for IP %s, MAC %s", e.IP, e.MAC)
}

// Unwrap returns the underlying error.
func (e *ErrIPAMRenewFailed) Unwrap() error {
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

// ErrMediaScanFailed is returned by the /media/status scan when procfs
// itself cannot be read; individual processes or descriptors that vanish
// mid-scan are skipped, not reported.
type ErrMediaScanFailed struct {
	ProcRoot string
	Cause    error
}

func (e ErrMediaScanFailed) Error() string {
	return fmt.Sprintf("ipxe: media status scan of %s failed: %v", e.ProcRoot, e.Cause)
}

func (e ErrMediaScanFailed) Unwrap() error { return e.Cause }

// ErrMediaWatcherUnhealthy is returned by /media/status (as 503) when the
// media watcher has no fresh record to serve: its procfs scans have not
// succeeded yet, or not recently enough.
type ErrMediaWatcherUnhealthy struct {
	Reason string
	Cause  error
}

func (e ErrMediaWatcherUnhealthy) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("ipxe: media watcher unhealthy: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("ipxe: media watcher unhealthy: %s", e.Reason)
}

func (e ErrMediaWatcherUnhealthy) Unwrap() error { return e.Cause }
