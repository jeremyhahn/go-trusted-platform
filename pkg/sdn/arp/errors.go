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

import "errors"

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
