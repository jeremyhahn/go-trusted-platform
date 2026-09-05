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

package device

import (
	"strconv"
)

// ID is a platform identifier as it appears on the device REST surface.
//
// It MARSHALS as a JSON string, always. The platform mints ids above 2^53, and
// a JSON number at that magnitude loses precision in any JavaScript client —
// the console truncates the value and can then no longer navigate to the record
// it just listed.
//
// It UNMARSHALS from a JSON string OR a JSON number. That asymmetry is the
// whole point of the type. Before it, responses carried `json:"id,string"` and
// requests carried a bare uint64, so a client that read an object and wrote it
// back had no correct move above 2^53: echoing the string it was given failed
// to unmarshal and produced HTTP 400, and converting it to a JavaScript number
// first lost precision and made the server accept a DIFFERENT id without
// complaint. The second is the worse of the two — an update applied to the
// wrong record, or a 404 nobody can explain.
//
// The obvious repair, adding `,string` to the request types, does not work:
// encoding/json's `,string` accepts a quoted value and REJECTS a bare number
// with "invalid use of ,string struct tag". That would have broken every
// existing client, all of which send numeric ids today. Accepting both
// encodings while emitting one widens the contract instead: no caller that
// works today stops working, and a caller that echoes what it received starts
// working.
type ID uint64

// MarshalJSON emits the id as a JSON string so its precision survives a
// JavaScript client.
func (id ID) MarshalJSON() ([]byte, error) {
	return strconv.AppendQuote(nil, strconv.FormatUint(uint64(id), 10)), nil
}

// UnmarshalJSON accepts a JSON string or a JSON number holding an unsigned
// integer. A JSON null, and the empty string, decode to zero — the same value
// an absent field would leave in place, so a caller that omits the id and one
// that sends null are treated alike.
func (id *ID) UnmarshalJSON(data []byte) error {
	s := string(data)
	if s == "null" {
		return nil
	}

	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		unquoted, err := strconv.Unquote(s)
		if err != nil {
			return ErrInvalidID{Value: s}
		}
		if unquoted == "" {
			*id = 0
			return nil
		}
		s = unquoted
	}

	// ParseUint rejects a sign, a decimal point and an exponent, so a negative,
	// a float and 1e9 are all refused rather than silently truncated.
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return ErrInvalidID{Value: string(data)}
	}
	*id = ID(v)
	return nil
}

// Uint64 returns the id as a plain uint64 for the service layer, which does not
// know about wire encodings.
func (id ID) Uint64() uint64 { return uint64(id) }

// String renders the id in the same decimal form it takes on the wire.
func (id ID) String() string { return strconv.FormatUint(uint64(id), 10) }

// ErrInvalidID reports an id that is neither a JSON string nor a JSON number
// holding an unsigned integer.
type ErrInvalidID struct {
	// Value is the offending JSON token, as received.
	Value string
}

// Error implements the error interface.
func (e ErrInvalidID) Error() string {
	return "device: id must be a JSON string or number holding an unsigned integer, got " + e.Value
}
