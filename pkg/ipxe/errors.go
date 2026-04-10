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
