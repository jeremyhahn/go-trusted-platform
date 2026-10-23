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

package quotebind

import "fmt"

// ErrQuoteNotBound is returned when a quote was not produced for the
// connection the caller asked over: the node quoted another connection's
// binding (the request was relayed), echoed a binding other than the
// caller's, or the call never derived a binding.
type ErrQuoteNotBound struct {
	Reason string
}

func (e *ErrQuoteNotBound) Error() string {
	return "quote is not bound to this connection: " + e.Reason
}

// ErrQuoteMalformed is returned when a quote is not a marshaled
// TPMS_ATTEST quote structure.
type ErrQuoteMalformed struct {
	Reason string
	Cause  error
}

func (e *ErrQuoteMalformed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("malformed quote: %s: %v", e.Reason, e.Cause)
	}
	return "malformed quote: " + e.Reason
}

func (e *ErrQuoteMalformed) Unwrap() error { return e.Cause }
