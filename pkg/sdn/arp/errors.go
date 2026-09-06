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

package arp

import (
	"errors"
	"fmt"
	"net"
)

var (
	// ErrOpenARPTable indicates failure to open the ARP table file
	ErrOpenARPTable = errors.New("failed to open ARP table")

	// ErrReadARPTable indicates failure to read from the ARP table
	ErrReadARPTable = errors.New("failed to read ARP table")

	// ErrEmptyARPTable indicates the ARP table is empty
	ErrEmptyARPTable = errors.New("ARP table is empty")

	// ErrNotFound indicates the requested entry was not found
	ErrNotFound = errors.New("ARP entry not found")

	// ErrInvalidIP indicates an invalid IP address was provided
	ErrInvalidIP = errors.New("invalid IP address")

	// ErrInvalidMAC indicates an invalid MAC address was provided
	ErrInvalidMAC = errors.New("invalid MAC address")

	// ErrMalformedEntry indicates a malformed ARP table entry
	ErrMalformedEntry = errors.New("malformed ARP entry")
)

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

// Duplicate-address detection errors (RFC 5227 probing).
var (
	// ErrNoProbeTransport indicates a detector was built without a transport.
	ErrNoProbeTransport = errors.New("arp: no probe transport configured")

	// ErrInvalidInterface indicates an empty or unusable interface name.
	ErrInvalidInterface = errors.New("arp: invalid interface name")

	// ErrInterfaceUnavailable indicates the probe interface could not be
	// opened: it does not exist, it has no usable hardware address, or the
	// process lacks the privilege to open a raw socket on it.
	ErrInterfaceUnavailable = errors.New("arp: probe interface unavailable")

	// ErrProbeUnsupported indicates raw ARP probing is not implemented on
	// this platform.
	ErrProbeUnsupported = errors.New("arp: raw ARP probing is only supported on Linux")

	// ErrNotIPv4 indicates a non-IPv4 address was supplied. ARP is IPv4-only;
	// IPv6 uses Neighbor Discovery, which this detector does not speak.
	ErrNotIPv4 = errors.New("arp: duplicate-address detection requires an IPv4 address")

	// ErrNilPacketConn indicates a probe session was built without a socket.
	ErrNilPacketConn = errors.New("arp: nil packet connection")

	// ErrProbeSend indicates the probe frame could not be transmitted.
	ErrProbeSend = errors.New("arp: failed to send probe")

	// ErrProbeReceive indicates the probe socket could not be read.
	ErrProbeReceive = errors.New("arp: failed to receive on probe socket")

	// ErrProbeTimeout indicates the listen window closed with no answer. It
	// is the quiet, expected outcome of probing a free address.
	ErrProbeTimeout = errors.New("arp: probe window expired")

	// ErrShortFrame indicates a frame too short to carry an ARP payload.
	ErrShortFrame = errors.New("arp: frame too short for an ARP payload")

	// ErrNotARP indicates a frame whose EtherType is not ARP.
	ErrNotARP = errors.New("arp: frame is not ARP")

	// ErrUnsupportedHardwareType indicates an ARP hardware type other than
	// Ethernet.
	ErrUnsupportedHardwareType = errors.New("arp: unsupported hardware type")

	// ErrUnsupportedProtocolType indicates an ARP protocol type other than
	// IPv4.
	ErrUnsupportedProtocolType = errors.New("arp: unsupported protocol type")

	// ErrUnsupportedAddressLength indicates ARP address lengths other than
	// 6-byte hardware / 4-byte protocol.
	ErrUnsupportedAddressLength = errors.New("arp: unsupported address lengths")
)

// ConflictError reports that another station on the segment already answers
// for the address the platform was about to assign. It carries both hardware
// addresses so an operator can identify the other station from the log line
// alone.
type ConflictError struct {
	// Interface is the interface the probe was sent on.
	Interface string

	// Address is the IPv4 address that is already claimed.
	Address net.IP

	// LocalHardwareAddr is the MAC of the probing interface.
	LocalHardwareAddr net.HardwareAddr

	// ResponderHardwareAddr is the MAC of the station that answered.
	ResponderHardwareAddr net.HardwareAddr
}

// Error implements the error interface.
func (e *ConflictError) Error() string {
	return fmt.Sprintf(
		"arp: duplicate address %s on %s: answered by %s (local %s)",
		e.Address, e.Interface, e.ResponderHardwareAddr, e.LocalHardwareAddr,
	)
}

// ErrProbeSocket indicates the raw ARP socket could not be opened, most
// often because the process lacks CAP_NET_RAW.
var ErrProbeSocket = errors.New("arp: failed to open raw ARP socket")
