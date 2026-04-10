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

// ErrSOLActivateFailed indicates the SOL payload activation command failed.
type ErrSOLActivateFailed struct {
	Cause error
}

func (e ErrSOLActivateFailed) Error() string {
	msg := "bmc: SOL activate payload failed"
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrSOLActivateFailed) Unwrap() error {
	return e.Cause
}

// ErrSOLDeactivateFailed indicates the SOL payload deactivation command failed.
type ErrSOLDeactivateFailed struct {
	Cause error
}

func (e ErrSOLDeactivateFailed) Error() string {
	msg := "bmc: SOL deactivate payload failed"
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrSOLDeactivateFailed) Unwrap() error {
	return e.Cause
}

// ErrSOLSessionClosed indicates the SOL session has been closed.
type ErrSOLSessionClosed struct{}

func (e ErrSOLSessionClosed) Error() string {
	return "bmc: SOL session is closed"
}

// ErrSOLTimeout indicates a SOL operation timed out.
type ErrSOLTimeout struct{}

func (e ErrSOLTimeout) Error() string {
	return "bmc: SOL operation timed out"
}
