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

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ErrServerURLRequired is returned when the server URL flag is not provided.
type ErrServerURLRequired struct{}

func (e ErrServerURLRequired) Error() string {
	return "bmc: --server-url is required"
}

// ErrProfileIDRequired is returned when the profile ID flag is not provided.
type ErrProfileIDRequired struct{}

func (e ErrProfileIDRequired) Error() string {
	return "bmc: --profile-id is required"
}

// ErrISOURLRequired is returned when the ISO URL flag is not provided.
type ErrISOURLRequired struct{}

func (e ErrISOURLRequired) Error() string {
	return "bmc: --iso-url is required"
}

// ErrDeviceRequired is returned when the boot device flag is not provided.
type ErrDeviceRequired struct{}

func (e ErrDeviceRequired) Error() string {
	return "bmc: --device is required"
}

// ErrRequestFailed is returned when an HTTP request to the BMC API fails.
type ErrRequestFailed struct {
	URL   string
	Cause error
}

func (e ErrRequestFailed) Error() string {
	return fmt.Sprintf("bmc: request to %s failed: %v", e.URL, e.Cause)
}

func (e ErrRequestFailed) Unwrap() error {
	return e.Cause
}

// ErrUnexpectedStatus is returned when the server returns an unexpected HTTP status.
type ErrUnexpectedStatus struct {
	StatusCode int
	Body       string
}

func (e ErrUnexpectedStatus) Error() string {
	return fmt.Sprintf("bmc: unexpected HTTP status %d: %s", e.StatusCode, e.Body)
}

// ErrResponseDecodeFailed is returned when decoding a server response fails.
type ErrResponseDecodeFailed struct {
	Cause error
}

func (e ErrResponseDecodeFailed) Error() string {
	return fmt.Sprintf("bmc: failed to decode server response: %v", e.Cause)
}

func (e ErrResponseDecodeFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidPowerAction is returned when an invalid power action is specified.
type ErrInvalidPowerAction struct {
	Action string
}

func (e ErrInvalidPowerAction) Error() string {
	return fmt.Sprintf("bmc: invalid power action %q (valid: on, off, reset, cycle)", e.Action)
}

// ErrInvalidBootDevice is returned when an invalid boot device is specified.
type ErrInvalidBootDevice struct {
	Device string
}

func (e ErrInvalidBootDevice) Error() string {
	return fmt.Sprintf("bmc: invalid boot device %q (valid: pxe, disk, cdrom, bios)", e.Device)
}

// ErrRequestBuildFailed is returned when building an HTTP request fails.
type ErrRequestBuildFailed struct {
	Cause error
}

func (e ErrRequestBuildFailed) Error() string {
	return fmt.Sprintf("bmc: failed to build request: %v", e.Cause)
}

func (e ErrRequestBuildFailed) Unwrap() error {
	return e.Cause
}

// ErrRequestEncodeFailed is returned when encoding the request body fails.
type ErrRequestEncodeFailed struct {
	Cause error
}

func (e ErrRequestEncodeFailed) Error() string {
	return fmt.Sprintf("bmc: failed to encode request body: %v", e.Cause)
}

func (e ErrRequestEncodeFailed) Unwrap() error {
	return e.Cause
}

// ErrHostRequired is returned when the --host flag is not provided.
type ErrHostRequired struct{}

func (e ErrHostRequired) Error() string {
	return "bmc: --host is required"
}

// ErrUserRequired is returned when the --user flag is not provided.
type ErrUserRequired struct{}

func (e ErrUserRequired) Error() string {
	return "bmc: --user is required"
}

// ErrPasswordRequired is returned when the --password flag is not provided.
type ErrPasswordRequired struct{}

func (e ErrPasswordRequired) Error() string {
	return "bmc: --password is required"
}

// ErrConsoleConnectionFailed is returned when the SOL console connection fails.
type ErrConsoleConnectionFailed struct {
	Cause error
}

func (e ErrConsoleConnectionFailed) Error() string {
	msg := "bmc: console connection failed"
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrConsoleConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrConsoleTerminalFailed is returned when terminal raw mode setup fails.
type ErrConsoleTerminalFailed struct {
	Cause error
}

func (e ErrConsoleTerminalFailed) Error() string {
	msg := "bmc: failed to configure terminal"
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrConsoleTerminalFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Standalone-mode errors (Gap 4)
// =============================================================================

// ErrBMCFlagConflict is returned when mutually exclusive flag sets are both set.
type ErrBMCFlagConflict struct {
	Fields []string
}

func (e ErrBMCFlagConflict) Error() string {
	return "bmc: mutually exclusive flags: " + strings.Join(e.Fields, ", ")
}

// ErrBMCNoMode is returned when neither --bmc-host nor --server-url/--profile-id was set.
type ErrBMCNoMode struct{}

func (e ErrBMCNoMode) Error() string {
	return "bmc: must set either --bmc-host (standalone) or --server-url and --profile-id (daemon)"
}

// ErrBMCMissingCredential is returned when a required credential flag is missing.
type ErrBMCMissingCredential struct {
	Field string
}

func (e ErrBMCMissingCredential) Error() string {
	return "bmc: missing required credential: " + e.Field
}

// ErrBMCPasswordFileUnreadable is returned when the password file cannot be read.
type ErrBMCPasswordFileUnreadable struct {
	Path  string
	Cause error
}

func (e ErrBMCPasswordFileUnreadable) Error() string {
	return "bmc: password file " + e.Path + " unreadable: " + e.Cause.Error()
}

func (e ErrBMCPasswordFileUnreadable) Unwrap() error { return e.Cause }

// ErrBMCInsecurePasswordFile is returned when the password file mode is too permissive.
type ErrBMCInsecurePasswordFile struct {
	Path string
	Mode os.FileMode
}

func (e ErrBMCInsecurePasswordFile) Error() string {
	return "bmc: password file " + e.Path + " has insecure mode " + e.Mode.String() + " (require 0600 or stricter)"
}

// ErrBMCStandaloneNotReachable is returned when protocol auto-detection finds no BMC.
type ErrBMCStandaloneNotReachable struct {
	Host string
}

func (e ErrBMCStandaloneNotReachable) Error() string {
	return "bmc: standalone host " + e.Host + " not reachable on either redfish (443/tcp) or ipmi (623/udp); set --bmc-protocol explicitly"
}

// ErrBMCInvalidProtocol is returned when --bmc-protocol is set to an unknown value.
type ErrBMCInvalidProtocol struct {
	Value string
}

func (e ErrBMCInvalidProtocol) Error() string {
	return "bmc: invalid --bmc-protocol " + e.Value + " (valid: redfish, ipmi, auto)"
}

// ErrBMCRequiresDaemon is returned when a subcommand only works in daemon mode.
type ErrBMCRequiresDaemon struct {
	Subcommand string
	Reason     string
}

func (e ErrBMCRequiresDaemon) Error() string {
	return "bmc: " + e.Subcommand + " requires --server-url/--profile-id (daemon mode): " + e.Reason
}

// ErrBMCConsoleNotSupported is returned when the selected protocol cannot host a SOL session.
type ErrBMCConsoleNotSupported struct {
	Protocol string
}

func (e ErrBMCConsoleNotSupported) Error() string {
	return "bmc: protocol " + e.Protocol + " does not support SOL console (use --bmc-protocol ipmi)"
}

// ErrBMCConsoleActivate wraps a SOL activation failure.
type ErrBMCConsoleActivate struct {
	Cause error
}

func (e ErrBMCConsoleActivate) Error() string {
	return "bmc: failed to activate SOL console: " + e.Cause.Error()
}

func (e ErrBMCConsoleActivate) Unwrap() error { return e.Cause }

// ErrBMCTTYRaw wraps a terminal raw-mode setup failure.
type ErrBMCTTYRaw struct {
	Cause error
}

func (e ErrBMCTTYRaw) Error() string {
	return "bmc: failed to put terminal into raw mode: " + e.Cause.Error()
}

func (e ErrBMCTTYRaw) Unwrap() error { return e.Cause }

// ErrBMCConsoleSendDecode is returned when the bmc console --send escape
// grammar can't decode the supplied input string.
type ErrBMCConsoleSendDecode struct {
	Input string
	Cause error
}

func (e ErrBMCConsoleSendDecode) Error() string {
	return "bmc: console: failed to decode --send input " + strconv.Quote(e.Input) + ": " + e.Cause.Error()
}

func (e ErrBMCConsoleSendDecode) Unwrap() error { return e.Cause }

// ErrBMCConsoleSendDecodeReason carries the bare reason produced by the
// escape decoder. Embedded as the Cause inside ErrBMCConsoleSendDecode.
type ErrBMCConsoleSendDecodeReason struct {
	Reason string
}

func (e ErrBMCConsoleSendDecodeReason) Error() string {
	return e.Reason
}

// ErrBMCConsoleSendWrite wraps a SOL write failure when --send was used.
type ErrBMCConsoleSendWrite struct {
	Index int
	Cause error
}

func (e ErrBMCConsoleSendWrite) Error() string {
	return "bmc: console: SOL write failed for --send #" + strconv.Itoa(e.Index+1) + ": " + e.Cause.Error()
}

func (e ErrBMCConsoleSendWrite) Unwrap() error { return e.Cause }
