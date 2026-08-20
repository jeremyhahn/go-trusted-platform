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

// ErrRAKPAuthFailed indicates the RAKP authentication exchange failed.
type ErrRAKPAuthFailed struct {
	Stage  string
	Code   uint8
	Reason string
}

func (e ErrRAKPAuthFailed) Error() string {
	msg := "bmc: RAKP authentication failed"
	if e.Stage != "" {
		msg = fmt.Sprintf("%s at %s", msg, e.Stage)
	}
	if e.Code != 0 {
		msg = fmt.Sprintf("%s (status 0x%02x)", msg, e.Code)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	return msg
}

// ErrSessionClosed indicates the RMCP+ session is closed.
type ErrSessionClosed struct{}

func (e ErrSessionClosed) Error() string {
	return "bmc: RMCP+ session is closed"
}

// ErrPacketTooShort indicates a received RMCP packet was too short.
type ErrPacketTooShort struct {
	Expected int
	Actual   int
}

func (e ErrPacketTooShort) Error() string {
	return fmt.Sprintf("bmc: packet too short: expected at least %d bytes, got %d", e.Expected, e.Actual)
}

// ErrIntegrityCheckFailed indicates an HMAC integrity check failed on a received message.
type ErrIntegrityCheckFailed struct{}

func (e ErrIntegrityCheckFailed) Error() string {
	return "bmc: integrity check failed on received message"
}

// ErrCompletionCode indicates the BMC returned a non-zero IPMI completion code.
type ErrCompletionCode struct {
	Code    uint8
	Command uint8
	NetFn   uint8
}

func (e ErrCompletionCode) Error() string {
	return fmt.Sprintf("bmc: IPMI command 0x%02x (netfn 0x%02x) failed with completion code 0x%02x",
		e.Command, e.NetFn, e.Code)
}

// ErrUDPSend indicates a failure sending a UDP packet.
type ErrUDPSend struct {
	Cause error
}

func (e ErrUDPSend) Error() string {
	return fmt.Sprintf("bmc: UDP send failed: %v", e.Cause)
}

func (e ErrUDPSend) Unwrap() error {
	return e.Cause
}

// ErrUDPRecv indicates a failure receiving a UDP packet.
type ErrUDPRecv struct {
	Cause error
}

func (e ErrUDPRecv) Error() string {
	return fmt.Sprintf("bmc: UDP receive failed: %v", e.Cause)
}

func (e ErrUDPRecv) Unwrap() error {
	return e.Cause
}

// ErrDecryptFailed indicates a failure decrypting an RMCP+ payload.
type ErrDecryptFailed struct {
	Reason string
}

func (e ErrDecryptFailed) Error() string {
	return fmt.Sprintf("bmc: decryption failed: %s", e.Reason)
}

// ErrEncryptFailed indicates a failure encrypting an RMCP+ payload.
type ErrEncryptFailed struct {
	Reason string
}

func (e ErrEncryptFailed) Error() string {
	return fmt.Sprintf("bmc: encryption failed: %s", e.Reason)
}

// rakpStatusCodes maps RMCP+ status codes to human-readable descriptions.
// Per IPMI 2.0 spec, Table 13-15.
var rakpStatusCodes = map[uint8]string{
	0x00: "no errors",
	0x01: "insufficient resources to create a session",
	0x02: "invalid session ID",
	0x03: "invalid payload type",
	0x04: "invalid authentication algorithm",
	0x05: "invalid integrity algorithm",
	0x06: "no matching authentication payload",
	0x07: "no matching integrity payload",
	0x09: "invalid role",
	0x0D: "invalid name length",
	0x0E: "unauthorized role or privilege level requested",
	0x0F: "insufficient resources to create a session at the requested time",
	0x10: "invalid name",
	0x11: "unauthorized name",
	0x12: "unauthorized GUID",
	0x13: "invalid integrity check value",
	0x14: "invalid confidentiality algorithm",
	0x15: "no cipher suite match with proposed security algorithms",
	0x16: "illegal or unrecognized parameter",
}

// rakpStatusString returns a human-readable description for a RAKP status code.
func rakpStatusString(code uint8) string {
	if s, ok := rakpStatusCodes[code]; ok {
		return s
	}
	return fmt.Sprintf("unknown status code 0x%02x", code)
}

// ErrFIPSAlgorithmNotApproved reports that a BMC agreed to an RMCP+ algorithm
// that is not FIPS-approved. It can only be returned by a build carrying the
// `fips` tag, where the offer contains HMAC-SHA256 alone — so receiving it
// means the controller echoed something that was never offered, and the
// session is refused rather than downgraded.
type ErrFIPSAlgorithmNotApproved struct {
	// Field is "authentication" or "integrity".
	Field string
	// Algorithm is the value the BMC selected.
	Algorithm uint8
	// Approved is the only value this build accepts for Field.
	Approved uint8
}

func (e ErrFIPSAlgorithmNotApproved) Error() string {
	return fmt.Sprintf(
		"bmc: BMC selected non-approved RMCP+ %s algorithm 0x%02x; this FIPS build accepts 0x%02x only",
		e.Field, e.Algorithm, e.Approved)
}
