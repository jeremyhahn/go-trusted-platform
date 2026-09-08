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

//go:build !linux

package fhrp

import (
	"net"
	"net/netip"
)

// ErrUnsupportedPlatform is returned by the raw transport and the netlink
// programmer on platforms other than Linux.
type ErrUnsupportedPlatform struct{ What string }

// Error implements the error interface.
func (e ErrUnsupportedPlatform) Error() string {
	return "fhrp: " + e.What + " is only available on Linux"
}

// NewRawTransport returns a transport whose Open always fails.
func NewRawTransport() Transport { return unsupportedTransport{} }

type unsupportedTransport struct{}

func (unsupportedTransport) Open(string, Family, netip.Addr) (Conn, error) {
	return nil, ErrUnsupportedPlatform{What: "the raw VRRP transport"}
}

// NewNetlinkProgrammer returns a programmer whose every call fails.
func NewNetlinkProgrammer() Programmer { return unsupportedProgrammer{} }

type unsupportedProgrammer struct{}

func (unsupportedProgrammer) AddAddress(string, netip.Prefix, net.HardwareAddr) error {
	return ErrUnsupportedPlatform{What: "the netlink programmer"}
}

func (unsupportedProgrammer) DeleteAddress(string, netip.Prefix, net.HardwareAddr) error {
	return ErrUnsupportedPlatform{What: "the netlink programmer"}
}

func (unsupportedProgrammer) Announce(string, netip.Addr, net.HardwareAddr) error {
	return ErrUnsupportedPlatform{What: "the netlink programmer"}
}
