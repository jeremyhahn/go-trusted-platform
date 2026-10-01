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

package rpinetboot

import (
	"errors"
	"strings"
	"time"
)

// UnknownModelError is returned for a model name the protocol table does
// not carry.
type UnknownModelError struct {
	Model  string
	Models []string
}

func (e *UnknownModelError) Error() string {
	return "rpinetboot: unknown model " + e.Model + " (supported: " + strings.Join(e.Models, ", ") + ")"
}

// InvalidIdentityError is returned when an identity field cannot produce
// what the protocol needs from it.
type InvalidIdentityError struct {
	Field string
	Value string
}

func (e *InvalidIdentityError) Error() string {
	return "rpinetboot: invalid " + e.Field + " " + e.Value
}

// DHCPError is a failure of the DHCP exchange at the named stage
// (socket, discover, offer, request, ack).
type DHCPError struct {
	Stage string
	Err   error
}

func (e *DHCPError) Error() string { return "rpinetboot: dhcp " + e.Stage + ": " + e.Err.Error() }
func (e *DHCPError) Unwrap() error { return e.Err }

// TFTPError is a failure fetching one file.
type TFTPError struct {
	File string
	Err  error
}

func (e *TFTPError) Error() string { return "rpinetboot: tftp " + e.File + ": " + e.Err.Error() }
func (e *TFTPError) Unwrap() error { return e.Err }

// TimeoutError is a bootloader timeout: no acceptable reply within the
// configured time.
type TimeoutError struct {
	What  string
	After time.Duration
}

func (e *TimeoutError) Error() string {
	return "rpinetboot: no reply to " + e.What + " within " + e.After.String()
}

// SocketError is a failure to set up the DHCP client socket.
type SocketError struct {
	Option string
	Err    error
}

func (e *SocketError) Error() string { return "rpinetboot: socket " + e.Option + ": " + e.Err.Error() }
func (e *SocketError) Unwrap() error { return e.Err }

var (
	errNoTFTPServer = errors.New("the offer names no TFTP server (no siaddr, option 66 or server identifier)")
	errFileNotFound = errors.New("not found under the device prefix or the root")
)
