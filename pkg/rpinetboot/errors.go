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
	"strconv"
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

// HTTPBootConfigError is an HTTPBootOptions field the bootloader could not run
// with.
type HTTPBootConfigError struct {
	Field string
	Err   error
}

func (e *HTTPBootConfigError) Error() string {
	if e.Err == nil {
		return "rpinetboot: http boot: " + e.Field + " is required"
	}
	return "rpinetboot: http boot: invalid " + e.Field + ": " + e.Err.Error()
}
func (e *HTTPBootConfigError) Unwrap() error { return e.Err }

// HTTPFetchError is a failure fetching one HTTP boot file.
type HTTPFetchError struct {
	URL string
	Err error
}

func (e *HTTPFetchError) Error() string { return "rpinetboot: http " + e.URL + ": " + e.Err.Error() }
func (e *HTTPFetchError) Unwrap() error { return e.Err }

// HTTPStatusError is a server answer other than 200 OK.
type HTTPStatusError struct {
	Status int
}

func (e *HTTPStatusError) Error() string { return "the server answered " + strconv.Itoa(e.Status) }

// HTTPSizeError is a file larger than the bootloader will take.
type HTTPSizeError struct {
	Limit int64
}

func (e *HTTPSizeError) Error() string {
	return "the file is larger than the limit of " + strconv.FormatInt(e.Limit, 10) + " bytes"
}

// HTTPBootRefusedError is a boot.img the bootloader would not run because its
// signature does not verify against the key in OTP; Err is the rpibootsig error
// that says why.
type HTTPBootRefusedError struct {
	URL string
	Err error
}

func (e *HTTPBootRefusedError) Error() string {
	return "rpinetboot: the bootloader refuses " + e.URL + ": " + e.Err.Error()
}
func (e *HTTPBootRefusedError) Unwrap() error { return e.Err }

// RamdiskError is a boot.img that verifies but is not a FAT ramdisk the
// bootloader can mount.
type RamdiskError struct {
	Err error
}

func (e *RamdiskError) Error() string {
	return "rpinetboot: boot.img is not a mountable ramdisk: " + e.Err.Error()
}
func (e *RamdiskError) Unwrap() error { return e.Err }

var (
	errNoTFTPServer = errors.New("the offer names no TFTP server (no siaddr, option 66 or server identifier)")
	errFileNotFound = errors.New("not found under the device prefix or the root")
)
