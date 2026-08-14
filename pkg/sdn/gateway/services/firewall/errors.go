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

package firewall

import "errors"

// Sentinel errors returned by the firewall and NAT services.
var (
	// ErrNilController is returned when Deps lacks a flow controller.
	ErrNilController = errors.New("firewall: flow controller is nil")

	// ErrNilOVSClient is returned when Deps lacks an OVS client.
	ErrNilOVSClient = errors.New("firewall: ovs client is nil")

	// ErrNilAllocator is returned when Deps lacks a conntrack zone allocator.
	ErrNilAllocator = errors.New("firewall: conntrack zone allocator is nil")

	// ErrNilZones is returned when Deps lacks a zone provider.
	ErrNilZones = errors.New("firewall: zone provider is nil")

	// ErrNilNetworks is returned when Deps lacks a network summary provider.
	ErrNilNetworks = errors.New("firewall: network provider is nil")

	// ErrEmptyBridge is returned when no bridge name is configured.
	ErrEmptyBridge = errors.New("firewall: bridge name must be non-empty")

	// ErrInvalidDefaultPolicy is returned when DefaultPolicy is neither
	// "allow" nor "deny".
	ErrInvalidDefaultPolicy = errors.New("firewall: default policy must be \"allow\" or \"deny\"")

	// ErrAlreadyStarted is returned when Start is called on a running service.
	ErrAlreadyStarted = errors.New("firewall: service already started")

	// ErrNotStarted is returned when an operation requires a running service.
	ErrNotStarted = errors.New("firewall: service not started")

	// ErrInvalidExternalIP is returned when the NAT external IP is missing
	// or not a valid IPv4 address.
	ErrInvalidExternalIP = errors.New("firewall: NAT external IP must be a valid IPv4 address")

	// ErrInvalidPortRange is returned when the NAT port range is inverted
	// or empty.
	ErrInvalidPortRange = errors.New("firewall: NAT port range start must be below end")

	// ErrInvalidInternalCIDR is returned when the NAT internal CIDR is not
	// a valid IPv4 prefix.
	ErrInvalidInternalCIDR = errors.New("firewall: NAT internal CIDR must be a valid IPv4 prefix")

	// ErrInvalidProtocol is returned when a DNAT protocol is neither "tcp"
	// nor "udp".
	ErrInvalidProtocol = errors.New("firewall: DNAT protocol must be \"tcp\" or \"udp\"")

	// ErrEmptyUplink is returned when a DNAT rule is requested without a
	// configured uplink port.
	ErrEmptyUplink = errors.New("firewall: DNAT requires a configured uplink port")

	// ErrSNATNotEnabled is returned when DisableSNAT is called while SNAT
	// is not active.
	ErrSNATNotEnabled = errors.New("firewall: SNAT is not enabled")

	// ErrSNATAlreadyEnabled is returned when EnableSNAT is called while
	// SNAT is already active.
	ErrSNATAlreadyEnabled = errors.New("firewall: SNAT is already enabled")

	// ErrDNATNotFound is returned when removing a DNAT rule that does not
	// exist.
	ErrDNATNotFound = errors.New("firewall: DNAT rule not found")

	// ErrDNATExists is returned when adding a DNAT rule that already exists.
	ErrDNATExists = errors.New("firewall: DNAT rule already exists")

	// ErrInvalidAddrPort is returned when a DNAT endpoint is not a valid
	// IPv4 address/port pair.
	ErrInvalidAddrPort = errors.New("firewall: DNAT endpoint must be a valid IPv4 address and port")
)

// OpError wraps a transport or controller failure with the firewall
// operation that produced it, preserving errors.Is/errors.As matching.
type OpError struct {
	// Op is the operation that failed ("install", "delete", "allocate",
	// "resolve-uplink", "reconcile").
	Op string

	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *OpError) Error() string {
	return "firewall: " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *OpError) Unwrap() error {
	return e.Err
}
