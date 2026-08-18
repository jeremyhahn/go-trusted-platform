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

// ErrMACNotFound indicates that the BMC did not expose a MAC address for the system.
type ErrMACNotFound struct {
	Address string
}

func (e ErrMACNotFound) Error() string {
	return fmt.Sprintf("bmc: MAC address not found for %s", e.Address)
}

// ErrProtocolDetectionFailed indicates that no supported BMC protocol could be
// detected at the given address.
type ErrProtocolDetectionFailed struct {
	Address string
}

func (e ErrProtocolDetectionFailed) Error() string {
	return fmt.Sprintf("bmc: protocol detection failed for %s", e.Address)
}

// ErrMACDiscoveryUnsupported indicates that MAC discovery is not supported for
// the given protocol. The administrator must provide the MAC address manually.
type ErrMACDiscoveryUnsupported struct {
	Protocol Protocol
}

func (e ErrMACDiscoveryUnsupported) Error() string {
	return fmt.Sprintf("bmc: MAC discovery not supported via %s, provide MAC manually", e.Protocol)
}

// ErrOEMMACParse indicates the Supermicro OEM host-MAC IPMI response could
// not be parsed as a plausible unicast MAC address. Bytes carries the raw
// response data length so operators can distinguish a truncated response
// from a well-sized one carrying an implausible value.
type ErrOEMMACParse struct {
	Bytes int
}

func (e ErrOEMMACParse) Error() string {
	return fmt.Sprintf("bmc: OEM host MAC response unparsable (%d bytes)", e.Bytes)
}

// ErrOEMMACCommand indicates the Supermicro OEM host-MAC IPMI command
// (NetFn 0x30 / Cmd 0x21) failed on the wire.
type ErrOEMMACCommand struct {
	Cause error
}

func (e ErrOEMMACCommand) Error() string {
	return fmt.Sprintf("bmc: OEM host MAC command failed: %v", e.Cause)
}

// Unwrap returns the underlying wire error.
func (e ErrOEMMACCommand) Unwrap() error { return e.Cause }
