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

package dns

import "strconv"

// ErrNoResolverServers is returned when no resolver servers are configured.
type ErrNoResolverServers struct{}

// Error implements the error interface.
func (e ErrNoResolverServers) Error() string {
	return "resolver: no servers configured"
}

// ErrInvalidResolverPort is returned when a resolver server port is invalid.
type ErrInvalidResolverPort struct {
	Address string
	Port    int
}

// Error implements the error interface.
func (e ErrInvalidResolverPort) Error() string {
	return "resolver: invalid port " + strconv.Itoa(e.Port) + " for server " + e.Address
}

// ErrInvalidResolverAddress is returned when a resolver server address is empty.
type ErrInvalidResolverAddress struct {
	Index int
}

// Error implements the error interface.
func (e ErrInvalidResolverAddress) Error() string {
	return "resolver: empty address for server at index " + strconv.Itoa(e.Index)
}
